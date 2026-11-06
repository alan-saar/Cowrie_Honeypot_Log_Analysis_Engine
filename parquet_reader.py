"""
Módulo de Leitura e Enriquecimento de Logs do Cowrie a partir de Arquivos Apache Parquet
Compatível com a estrutura de logs do projeto dpipot-analytics (data/dpipot-pods-*.parquet e data/dpipot-proxy-*.parquet).
"""

import os
import glob
import re
from typing import List, Optional, Tuple
import duckdb
import pandas as pd


def parse_date_filter(
    date: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None
) -> Tuple[Optional[str], Optional[str]]:
    """
    Normaliza os parâmetros de data recebidos.
    Suporta:
      - date='2026.07.27' ou date='2026-07-27'
      - date='2026.07.27:2026.07.28' (intervalo)
      - start_date / end_date separados
    Retorna: (start_date_iso, end_date_iso) no formato 'YYYY-MM-DD'
    """
    if date:
        if ":" in date:
            parts = date.split(":", 1)
            s_date = parts[0].strip().replace(".", "-")
            e_date = parts[1].strip().replace(".", "-")
            return s_date, e_date
        single = date.strip().replace(".", "-")
        return single, single

    s_date = start_date.strip().replace(".", "-") if start_date else None
    e_date = end_date.strip().replace(".", "-") if end_date else None
    return s_date, e_date


def list_available_parquet_dates(data_dir: str = "data") -> List[str]:
    """
    Lista todas as datas disponíveis nos arquivos Parquet de pods (dpipot-pods-*.parquet).
    Exemplo de retorno: ['2026.07.27', '2026.07.28']
    """
    pattern = os.path.join(data_dir, "dpipot-pods-*.parquet")
    files = glob.glob(pattern)
    dates = []
    date_regex = re.compile(r"dpipot-pods-(\d{4}[.-]\d{2}[.-]\d{2})\.parquet")

    for f in sorted(files):
        match = date_regex.search(os.path.basename(f))
        if match:
            dates.append(match.group(1))
    return dates


def _filter_files_by_date(files: List[str], prefix: str, start_iso: Optional[str], end_iso: Optional[str]) -> List[str]:
    """Filtra lista de arquivos Parquet pelo intervalo de datas no nome do arquivo."""
    if not start_iso and not end_iso:
        return sorted(files)

    selected = []
    date_regex = re.compile(rf"{prefix}-(\d{{4}})[.-](\d{{2}})[.-](\d{{2}})\.parquet")
    for f in sorted(files):
        match = date_regex.search(os.path.basename(f))
        if match:
            file_date_iso = f"{match.group(1)}-{match.group(2)}-{match.group(3)}"
            if start_iso and file_date_iso < start_iso:
                continue
            if end_iso and file_date_iso > end_iso:
                continue
            selected.append(f)
    return selected


def read_cowrie_sessions(
    data_dir: str = "data",
    date: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    enrich_proxy: bool = True
) -> pd.DataFrame:
    """
    Lê os comandos das sessões Cowrie dos arquivos Parquet de pods e opcionalmente
    enriquece com IP real, país e organização ASN a partir dos arquivos de proxy.

    Retorna um DataFrame agrupado por sessão contendo:
      ['session', 'src_ip', 'country', 'asn_org', 'commands', 'start_time', 'command_count']
    """
    start_iso, end_iso = parse_date_filter(date, start_date, end_date)

    all_pod_files = glob.glob(os.path.join(data_dir, "dpipot-pods-*.parquet"))
    pod_files = _filter_files_by_date(all_pod_files, "dpipot-pods", start_iso, end_iso)

    if not pod_files:
        print(f"[AVISO] Nenhum arquivo Parquet de pods encontrado no intervalo [{start_iso} até {end_iso}].")
        return pd.DataFrame(columns=["session", "src_ip", "country", "asn_org", "commands", "start_time", "command_count"])

    print(f"[PARQUET] Processando {len(pod_files)} arquivo(s) de pods Cowrie:")
    for f in pod_files:
        print(f"  • {os.path.basename(f)}")

    con = duckdb.connect()
    con.execute("PRAGMA threads=8;")
    pod_files_str = ", ".join([f"'{f}'" for f in pod_files])

    # Verificar se temos arquivos do proxy para enriquecer
    proxy_files = []
    if enrich_proxy:
        all_proxy_files = glob.glob(os.path.join(data_dir, "dpipot-proxy-*.parquet"))
        proxy_files = _filter_files_by_date(all_proxy_files, "dpipot-proxy", start_iso, end_iso)

    if enrich_proxy and proxy_files:
        print(f"[PARQUET] Enriquecendo com {len(proxy_files)} arquivo(s) de Proxy DPIpot:")
        for f in proxy_files:
            print(f"  • {os.path.basename(f)}")

        proxy_files_str = ", ".join([f"'{f}'" for f in proxy_files])

        query = f"""
        WITH raw_commands AS (
            SELECT 
                session,
                FIRST(src_ip) AS pod_ip,
                MIN("@timestamp") AS start_time,
                REGEXP_EXTRACT("event.original", 'CMD: (.*)', 1) AS cmd,
                MAX(REGEXP_EXTRACT("event.original", 'login attempt \\[(.*)/(.*)\\] succeeded', 2)) AS password_used
            FROM read_parquet([{pod_files_str}], union_by_name=true)
            WHERE session IS NOT NULL
              AND (
                COALESCE("kubernetes.labels.app", '') = 'cowrie'
                OR COALESCE(eventid, '') LIKE 'cowrie%'
              )
            GROUP BY session, "event.original", "@timestamp"
        ),
        session_cmds AS (
            SELECT 
                session,
                FIRST(pod_ip) AS pod_ip,
                MIN(start_time) AS start_time,
                MAX(password_used) AS password_used,
                LIST(cmd) FILTER (WHERE cmd IS NOT NULL AND cmd != '') AS commands,
                COUNT(cmd) FILTER (WHERE cmd IS NOT NULL AND cmd != '') AS command_count
            FROM raw_commands
            GROUP BY session
            HAVING command_count > 0
        ),
        proxy_auth AS (
            SELECT 
                src_ip AS real_ip,
                "src_geo.country_name" AS country,
                "src_asn.organization_name" AS asn_org,
                attack_type AS password,
                "@timestamp" AS proxy_time
            FROM read_parquet([{proxy_files_str}], union_by_name=true)
            WHERE honeypot = 'cowrie-svc:22' 
              AND ndpi_app = 'password'
              AND attack_type IS NOT NULL
        )
        SELECT 
            sc.session,
            COALESCE(pa.real_ip, sc.pod_ip) AS src_ip,
            COALESCE(pa.country, 'Unknown') AS country,
            COALESCE(pa.asn_org, 'Unknown') AS asn_org,
            sc.commands,
            sc.start_time,
            sc.command_count
        FROM session_cmds sc
        LEFT JOIN (
            -- Obter o match mais próximo no tempo se houver múltiplos
            SELECT 
                password,
                real_ip,
                country,
                asn_org,
                proxy_time,
                ROW_NUMBER() OVER (PARTITION BY password ORDER BY proxy_time) as rn
            FROM proxy_auth
        ) pa ON sc.password_used = pa.password AND pa.rn = 1
        ORDER BY sc.start_time
        """
    else:
        # Sem enriquecimento com proxy
        query = f"""
        WITH raw_commands AS (
            SELECT 
                session,
                FIRST(src_ip) AS pod_ip,
                MIN("@timestamp") AS start_time,
                REGEXP_EXTRACT("event.original", 'CMD: (.*)', 1) AS cmd
            FROM read_parquet([{pod_files_str}], union_by_name=true)
            WHERE session IS NOT NULL
              AND (
                COALESCE("kubernetes.labels.app", '') = 'cowrie'
                OR COALESCE(eventid, '') LIKE 'cowrie%'
              )
            GROUP BY session, "event.original", "@timestamp"
        )
        SELECT 
            session,
            FIRST(pod_ip) AS src_ip,
            'Unknown' AS country,
            'Unknown' AS asn_org,
            LIST(cmd) FILTER (WHERE cmd IS NOT NULL AND cmd != '') AS commands,
            MIN(start_time) AS start_time,
            COUNT(cmd) FILTER (WHERE cmd IS NOT NULL AND cmd != '') AS command_count
        FROM raw_commands
        GROUP BY session
        HAVING command_count > 0
        ORDER BY start_time
        """

    print("[PARQUET] Executando agregação e cruzamento de sessões com DuckDB...")
    df = con.sql(query).df()
    print(f"[PARQUET] Total de sessões ativas extraídas: {len(df):,}")
    return df


if __name__ == "__main__":
    import sys
    print("=== Teste do Leitor de Sessões Cowrie (Parquet + Proxy) ===")
    arg_date = sys.argv[1] if len(sys.argv) > 1 else None
    
    sessions_df = read_cowrie_sessions(date=arg_date)
    print("\nInformações das sessões:")
    print(sessions_df.info())
    print("\nTop 5 Sessões Extraídas:")
    print(sessions_df[["session", "src_ip", "country", "asn_org", "command_count"]].head())
    
    print("\nDistribuição por País:")
    print(sessions_df["country"].value_counts().head(10))
