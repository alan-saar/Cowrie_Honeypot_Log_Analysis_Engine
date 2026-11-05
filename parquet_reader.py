"""
Módulo de Leitura Otimizada de Logs do Cowrie a partir de Arquivos Apache Parquet
Compatível com a estrutura de logs do projeto dpipot-analytics (data/dpipot-pods-*.parquet).
"""

import os
import glob
import re
from typing import List, Optional
import duckdb
import pandas as pd


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


def read_cowrie_from_parquet(
    data_dir: str = "data",
    date: Optional[str] = None,
    only_commands: bool = True
) -> pd.DataFrame:
    """
    Lê os logs do Cowrie diretamente dos arquivos Apache Parquet em data_dir usando DuckDB.

    Aplica filtros via push-down predicates para evitar carregar gigabytes desnecessários
    em memória RAM.

    Args:
        data_dir: Diretório onde estão os arquivos Parquet (padrão: 'data').
        date: Data específica no formato 'YYYY.MM.DD' ou 'YYYY-MM-DD'. Se None, lê todos os dias.
        only_commands: Se True, extrai apenas eventos de comando (cowrie.command.input).

    Returns:
        DataFrame do pandas com as colunas relevantes para o pipeline de análise.
    """
    if date:
        normalized_date = date.replace("-", ".")
        pattern = os.path.join(data_dir, f"dpipot-pods-*{normalized_date}*.parquet")
    else:
        pattern = os.path.join(data_dir, "dpipot-pods-*.parquet")

    files = sorted(glob.glob(pattern))
    if not files:
        print(f"[AVISO] Nenhum arquivo Parquet encontrado com o padrão: {pattern}")
        return pd.DataFrame(columns=["session", "src_ip", "input", "timestamp", "eventid"])

    print(f"[PARQUET] Encontrado(s) {len(files)} arquivo(s) Parquet para leitura:")
    for f in files:
        size_mb = os.path.getsize(f) / (1024 * 1024)
        print(f"  • {os.path.basename(f)} ({size_mb:.1f} MB)")

    con = duckdb.connect()
    con.execute("PRAGMA threads=8;")
    files_str = ", ".join([f"'{f}'" for f in files])

    if only_commands:
        query = f"""
        SELECT
            session,
            src_ip,
            REGEXP_EXTRACT("event.original", 'CMD: (.*)', 1) AS input,
            "@timestamp" AS timestamp,
            COALESCE(eventid, 'cowrie.command.input') AS eventid
        FROM read_parquet([{files_str}], union_by_name=true)
        WHERE (
            COALESCE(eventid, '') = 'cowrie.command.input'
            OR "event.original" LIKE 'CMD: %'
        )
        AND "event.original" IS NOT NULL
        """
    else:
        query = f"""
        SELECT
            session,
            src_ip,
            dst_ip,
            protocol,
            REGEXP_EXTRACT("event.original", 'CMD: (.*)', 1) AS input,
            "@timestamp" AS timestamp,
            eventid,
            "event.original" AS raw_log
        FROM read_parquet([{files_str}], union_by_name=true)
        WHERE (
            COALESCE("kubernetes.labels.app", '') = 'cowrie'
            OR COALESCE(eventid, '') LIKE 'cowrie%'
        )
        """

    print("[PARQUET] Executando consulta SQL colunar com DuckDB...")
    df = con.sql(query).df()
    print(f"[PARQUET] Total de eventos extraídos: {len(df):,}")

    return df


if __name__ == "__main__":
    import sys
    target_date = sys.argv[1] if len(sys.argv) > 1 else None
    print("--- Teste do Leitor Parquet Cowrie ---")
    available = list_available_parquet_dates()
    print(f"Datas disponíveis: {available}")

    df_cowrie = read_cowrie_from_parquet(date=target_date)
    print("\nResumo do DataFrame retornado:")
    print(df_cowrie.info())
    print("\nPrimeiros 5 registros:")
    print(df_cowrie.head())
