import os
import glob
import json
import re
import argparse
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from parquet_reader import read_cowrie_sessions, list_available_parquet_dates

# --- CONFIGURATION ---
DEFAULT_LOG_DIRECTORY = 'logs'
DEFAULT_DATA_DIRECTORY = 'data'
DEFAULT_OUTPUT_DIRECTORY = '.'
# --- END CONFIGURATION ---

# --- ANALYSIS KEYWORDS ---
# We define keywords to categorize commands. Using sets for efficient lookups.
KEYWORDS = {
    'recon': {'whoami', 'uname', 'ls', 'pwd', 'ifconfig', 'ip a', 'netstat', 'ps', 'top', 'history', 'cat /etc/passwd'},
    'download': {'wget', 'curl', 'tftp', 'ftpget'},
    'destructive': {'rm', 'mkfs', 'dd'},
    'persistence': {'crontab', 'systemctl enable', '/etc/init.d'}
}
# --- END KEYWORDS ---


def read_log_files(log_path):
    """
    Reads all 'cowrie*.json' files in the specified directory and
    returns the JSON data as a list of dictionaries.
    (Modo legado para arquivos JSON brutos)
    """
    file_pattern = os.path.join(log_path, 'cowrie*.json')
    log_files = glob.glob(file_pattern)
    
    if not log_files:
        print(f"No log files found in directory: {log_path}")
        return []

    print(f"Found {len(log_files)} log file(s).")
    
    all_events = []
    for file_path in log_files:
        print(f"Reading file: {file_path}")
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    all_events.append(event)
                except json.JSONDecodeError:
                    print(f"  - Skipped corrupted JSON line in file: {file_path}")
                    continue
                    
    print(f"Total {len(all_events)} events (log lines) read.")
    return all_events


def group_and_filter_sessions(df):
    """
    Filters for command input events and groups them by session ID.
    (Utilizado quando a fonte de dados é JSON legado)
    """
    command_df = df[df['eventid'] == 'cowrie.command.input'].copy()
    
    if 'input' not in command_df.columns or 'session' not in command_df.columns:
        print("Error: 'input' or 'session' column not found in logs.")
        return None

    sessions = command_df.groupby('session').agg(
        src_ip=('src_ip', 'first'),
        commands=('input', list)
    ).reset_index()
    
    # Preencher metadados padrão para compatibilidade com a nova estrutura
    sessions['country'] = 'N/A'
    sessions['asn_org'] = 'N/A'
    
    print(f"\nFound {len(sessions)} sessions with command inputs.")
    return sessions


def analyze_session_with_rules(session_id, commands):
    """
    Analyzes a session based on a set of predefined rules and keywords, without using an AI API.
    """
    scores = {
        'recon': 0,
        'download': 0,
        'destructive': 0,
        'persistence': 0
    }
    suspicious_items = []
    
    for command in commands:
        if not isinstance(command, str):
            continue
            
        # Check for download tools and extract URLs
        if any(tool in command for tool in KEYWORDS['download']):
            scores['download'] += 1
            urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', command)
            if urls:
                suspicious_items.extend(urls)

        # Check for reconnaissance commands
        if any(tool in command for tool in KEYWORDS['recon']):
            scores['recon'] += 1
            
        # Check for destructive commands
        if any(tool in command for tool in KEYWORDS['destructive']):
            scores['destructive'] += 1
            suspicious_items.append(command)

        # Check for persistence commands
        if any(tool in command for tool in KEYWORDS['persistence']):
            scores['persistence'] += 1
            suspicious_items.append(command)

    # --- Determine Intent and Skill Level based on scores ---
    intent = "Uncategorized"
    if scores['destructive'] > 0:
        intent = "Destructive"
    elif scores['download'] > 0:
        intent = "Malware Deployment"
    elif scores['persistence'] > 0:
        intent = "Persistence Attempt"
    elif scores['recon'] > 0:
        intent = "Reconnaissance"
        
    skill_level = "Low (Script Kiddie)"
    if scores['download'] > 0 and scores['recon'] > 1:
        skill_level = "Medium (Automated Script)"
    elif len(commands) > 10 and scores['recon'] > 5:
        skill_level = "Medium (Manual Exploration)"

    summary = f"Attacker executed {len(commands)} commands, showing signs of {intent}."

    analysis = {
        "intent": intent,
        "skill_level": skill_level,
        "summary": summary,
        "suspicious_items": list(set(suspicious_items))
    }
    
    return analysis


def save_results_to_files(results_df, output_dir='.'):
    """Saves the analysis results to CSV and HTML files."""
    try:
        os.makedirs(output_dir, exist_ok=True)
        csv_path = os.path.join(output_dir, 'ai_analysis_report.csv')
        html_path = os.path.join(output_dir, 'ai_analysis_report.html')

        # Save to CSV
        results_df.to_csv(csv_path, index=False, encoding='utf-8-sig')
        print(f"\n[SUCCESS] Analysis report saved to '{csv_path}'")
        
        # Save to HTML
        results_df.to_html(html_path, escape=False, index=False)
        print(f"[SUCCESS] Analysis report saved to '{html_path}'")

    except Exception as e:
        print(f"\n[ERROR] Failed to save report files: {e}")


def create_visualizations(results_df, output_dir='.'):
    """Creates and saves visualizations based on the analysis results."""
    if results_df.empty:
        print("\nNo data available to create visualizations.")
        return
        
    print("\n--- Creating Visualizations ---")
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        # Set the style for the plots
        sns.set_theme(style="whitegrid")

        # 1. Bar Chart for Attack Intent
        plt.figure(figsize=(10, 6))
        sns.countplot(
            y='intent',
            data=results_df,
            order=results_df['intent'].value_counts().index,
            palette='viridis',
            hue='intent',
            legend=False
        )        
        plt.title('Distribution of Attacker Intents')
        plt.xlabel('Number of Sessions')
        plt.ylabel('Intent')
        plt.tight_layout()
        intent_path = os.path.join(output_dir, 'attack_intent_distribution.png')
        plt.savefig(intent_path)
        print(f"[SUCCESS] Visualization saved to '{intent_path}'")
        plt.close()

        # 2. Pie Chart for Attacker Skill Level
        plt.figure(figsize=(8, 8))
        skill_counts = results_df['skill_level'].value_counts()
        plt.pie(skill_counts, labels=skill_counts.index, autopct='%1.1f%%', startangle=140, colors=sns.color_palette('pastel'))
        plt.title('Distribution of Attacker Skill Levels')
        plt.ylabel('')
        skill_path = os.path.join(output_dir, 'attacker_skill_level.png')
        plt.savefig(skill_path)
        print(f"[SUCCESS] Visualization saved to '{skill_path}'")
        plt.close()

        # 3. Bar Chart for Top Attacking Countries (if country data is available)
        if 'country' in results_df.columns:
            valid_countries = results_df[~results_df['country'].isin(['Unknown', 'N/A', '', None])]
            if not valid_countries.empty:
                top_countries = valid_countries['country'].value_counts().head(10)
                plt.figure(figsize=(10, 6))
                sns.barplot(x=top_countries.values, y=top_countries.index, palette='mako', hue=top_countries.index, legend=False)
                plt.title('Top 10 Source Countries of Attacks')
                plt.xlabel('Number of Sessions')
                plt.ylabel('Country')
                plt.tight_layout()
                country_path = os.path.join(output_dir, 'attack_country_distribution.png')
                plt.savefig(country_path)
                print(f"[SUCCESS] Visualization saved to '{country_path}'")
                plt.close()

    except Exception as e:
        print(f"[ERROR] Failed to create visualizations: {e}")


def parse_arguments():
    """Configura os argumentos de linha de comando."""
    parser = argparse.ArgumentParser(
        description="Cowrie Honeypot Log Analysis Engine - Analisador de Comportamento de Atacantes"
    )
    parser.add_argument(
        '--source',
        choices=['parquet', 'json'],
        default='parquet',
        help="Fonte dos dados: 'parquet' (padrão, logs do dpipot-analytics) ou 'json' (logs legados)."
    )
    parser.add_argument(
        '--data-dir',
        default=DEFAULT_DATA_DIRECTORY,
        help=f"Diretório dos arquivos Parquet (padrão: '{DEFAULT_DATA_DIRECTORY}')."
    )
    parser.add_argument(
        '--log-dir',
        default=DEFAULT_LOG_DIRECTORY,
        help=f"Diretório dos arquivos JSON legados (padrão: '{DEFAULT_LOG_DIRECTORY}')."
    )
    parser.add_argument(
        '--date',
        default=None,
        help="Data específica (ex: 2026.07.27) ou intervalo no formato 'INICIO:FIM' (ex: 2026.07.27:2026.07.28)."
    )
    parser.add_argument(
        '--start-date',
        default=None,
        help="Data de início do intervalo (ex: 2026.07.27)."
    )
    parser.add_argument(
        '--end-date',
        default=None,
        help="Data de fim do intervalo (ex: 2026.07.28)."
    )
    parser.add_argument(
        '--output-dir',
        default=DEFAULT_OUTPUT_DIRECTORY,
        help=f"Diretório de saída para relatórios e gráficos (padrão: '{DEFAULT_OUTPUT_DIRECTORY}')."
    )
    parser.add_argument(
        '--no-enrich',
        action='store_true',
        help="Desativa o enriquecimento automático de IP real, país e ASN com os logs do proxy."
    )
    return parser.parse_args()


# --- Main execution block of the script ---
if __name__ == '__main__':
    args = parse_arguments()

    if args.source == 'parquet':
        print("=== Cowrie Analysis Engine (Modo Apache Parquet / DPIpot) ===")
        enrich = not args.no_enrich
        attacker_sessions = read_cowrie_sessions(
            data_dir=args.data_dir,
            date=args.date,
            start_date=args.start_date,
            end_date=args.end_date,
            enrich_proxy=enrich
        )
    else:
        print("=== Cowrie Analysis Engine (Modo JSON Legado) ===")
        events_list = read_log_files(args.log_dir)
        if events_list:
            df = pd.DataFrame(events_list)
            attacker_sessions = group_and_filter_sessions(df)
        else:
            attacker_sessions = None

    if attacker_sessions is not None and not attacker_sessions.empty:
        analysis_results = []
        total_sessions_to_analyze = len(attacker_sessions)
        
        print(f"\n--- Starting Rule-Based Analysis ({total_sessions_to_analyze} Sessions) ---")
        
        for i, row in attacker_sessions.iterrows():
            session_id = row['session']
            commands = row['commands']
            src_ip = row['src_ip']
            country = row.get('country', 'N/A')
            asn_org = row.get('asn_org', 'N/A')

            analysis = analyze_session_with_rules(session_id, commands)
            
            analysis['session_id'] = session_id
            analysis['src_ip'] = src_ip
            analysis['country'] = country
            analysis['asn_org'] = asn_org
            analysis['command_count'] = len(commands)
            analysis_results.append(analysis)

        if analysis_results:
            results_df = pd.DataFrame(analysis_results)
            
            cols_order = [
                'session_id', 'src_ip', 'country', 'asn_org',
                'intent', 'skill_level', 'command_count', 'summary', 'suspicious_items'
            ]
            for col in cols_order:
                if col not in results_df.columns:
                    results_df[col] = 'N/A'
            results_df = results_df[cols_order]

            save_results_to_files(results_df, output_dir=args.output_dir)
            create_visualizations(results_df, output_dir=args.output_dir)

            print("\n--- Analysis Complete! ---")
        else:
            print("\nNo sessions were successfully analyzed.")
    else:
        print("\nNenhuma sessão encontrada para análise.")
