# Cowrie Honeypot Log Analysis Engine

![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![Libraries](https://img.shields.io/badge/libraries-pandas%20%7C%20seaborn%20%7C%20matplotlib%20%7C%20duckdb-orange.svg)

This project provides a complete, end-to-end pipeline for analyzing SSH/Telnet honeypot logs from Cowrie. It automates the process of ingesting multi-gigabyte Apache Parquet files (or legacy raw JSON log files), processing tens of thousands of events, classifying attacker behavior using a custom rule-based engine, and generating insightful reports and visualizations.

---

## Table of Contents

1. [The Problem](#1-the-problem)
2. [The Solution: An Automated Analysis Pipeline](#2-the-solution-an-automated-analysis-pipeline)
3. [Project Architecture](#3-project-architecture)
4. [Getting Started](#4-getting-started)
   - [Prerequisites](#prerequisites)
   - [Installation](#installation)
5. [Data Sources & Architecture](#5-data-sources--architecture)
   - [DPIpot Apache Parquet Datasets](#dpipot-apache-parquet-datasets)
   - [Legacy Cowrie JSON Logs](#legacy-cowrie-json-logs)
6. [How to Run the Analyzer](#6-how-to-run-the-analyzer)
   - [Default Mode (Parquet)](#default-mode-parquet)
   - [Command Line Options (CLI)](#command-line-options-cli)
7. [Understanding the Output](#7-understanding-the-output)
8. [How the Analysis Engine Works](#8-how-the-analysis-engine-works)
9. [Future Improvements](#9-future-improvements)

---

### 1. The Problem

In the field of cybersecurity, one of the biggest challenges for researchers, students, and enthusiasts is the lack of access to real-world attack data. Large-scale datasets are often proprietary and held by large corporations. Without this data, it's difficult to study attacker tactics, techniques, and procedures (TTPs), understand current threat landscapes, and develop defensive strategies. Honeypots are an excellent solution to this problem, as they are designed to attract and log attack attempts. However, a running honeypot can generate hundreds of thousands of log entries and gigabytes of columnar data, creating a new challenge: how to efficiently sift through this massive amount of data to find meaningful insights.

### 2. The Solution: An Automated Analysis Pipeline

This project presents a solution by providing a complete, automated analysis pipeline written in Python. It takes Apache Parquet datasets or raw log files from the Cowrie honeypot as input and produces high-level, human-readable reports and visualizations as output.

The system processes all log events, groups them into unique attacker sessions, enriches sessions with real attacker IPs and geographic origins via proxy correlations, and uses a custom-built, rule-based analysis engine to classify each session based on the commands executed. This turns raw, noisy data into actionable intelligence.

### 3. Project Architecture

The script operates as a 5-stage data pipeline:

1. **Ingestion (`read_cowrie_sessions` / `read_log_files`):** Discovers and queries columnar Parquet files (`data/dpipot-pods-*.parquet`) using DuckDB push-down predicates, or reads legacy `cowrie*.json` files.
2. **Correlation & Enrichment:** Automatically correlates backend Cowrie sessions with frontend DPIpot Proxy logs (`data/dpipot-proxy-*.parquet`) to retrieve the attacker's public IP, country of origin, and ASN organization.
3. **Processing (`group_and_filter_sessions`):** Extracts executed commands (`CMD: <command>`) and groups them into coherent attacker sessions based on their unique session ID.
4. **Analysis (`analyze_session_with_rules`):** Evaluates the commands in each session against predefined keywords and heuristics to determine the attacker's intent and estimated skill level.
5. **Reporting & Visualization (`save_results_to_files`, `create_visualizations`):** Generates detailed reports in CSV and styled HTML formats, along with high-resolution visual charts.

### 4. Getting Started

Follow these steps to set up and run the analysis engine on your own machine.

#### Prerequisites

- Python 3.9 or higher
- `pip` or `uv` package installer

#### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/EfeEmirYuce/Cowrie-Honeypot-Log-Analysis-Engine
   cd Cowrie-Honeypot-Log-Analysis-Engine
   ```

2. **Install the required libraries:**
   ```bash
   pip install -r requirements.txt
   ```

### 5. Data Sources & Architecture

#### DPIpot Apache Parquet Datasets
The primary data source consists of Apache Parquet files located in `data/` (symlinked or exported from the `dpipot-analytics` pipeline):
- `dpipot-pods-*.parquet`: Logs recorded by Cowrie honeypot containers running inside the Kubernetes cluster.
- `dpipot-proxy-*.parquet`: Logs recorded by the DPIpot L4/L7 transparent proxy (TPROXY), capturing the real public source IP, ASN, and GeoIP metadata.

#### Legacy Cowrie JSON Logs
The analyzer also supports standard Cowrie JSON logs placed in the `logs/` directory in the format `cowrie*.json`.

### 6. How to Run the Analyzer

Ensure your project has the following directory structure:

```
your-project-folder/
├── analysis.py
├── parquet_reader.py
├── requirements.txt
├── data/ -> ../dpipot-analytics/data/ (Apache Parquet files)
└── logs/ (optional legacy Cowrie JSON files)
```

#### Default Mode (Parquet)
By default, the script reads all available days in `data/` using **DuckDB**, automatically extracting Cowrie commands and enriching sessions with proxy metadata:

```bash
python analysis.py
```

#### Command Line Options (CLI)

* **Filter by a specific date:**
  ```bash
  python analysis.py --date 2026.07.27
  ```

* **Filter by a date range:**
  ```bash
  python analysis.py --date 2026.07.27:2026.07.28
  # or equivalently:
  python analysis.py --start-date 2026.07.27 --end-date 2026.07.28
  ```

* **Specify a custom output directory:**
  ```bash
  python analysis.py --output-dir reports/
  ```

* **Disable proxy enrichment:**
  ```bash
  python analysis.py --no-enrich
  ```

* **Run in legacy JSON mode:**
  ```bash
  python analysis.py --source json --log-dir logs
  ```

### 7. Understanding the Output

After the script finishes, you will find five output files:

1. **`ai_analysis_report.csv`:** A CSV file containing a detailed breakdown of every analyzed session, including `session_id`, `src_ip` (real attacker IP), `country`, `asn_org`, `intent`, `skill_level`, `command_count`, `summary`, and `suspicious_items`.
2. **`ai_analysis_report.html`:** A user-friendly HTML version of the report with a styled table that can be opened directly in any browser.
3. **`attack_intent_distribution.png`:** A bar chart visualizing the most common types of attacks observed (e.g., Malware Deployment, Reconnaissance).
4. **`attacker_skill_level.png`:** A pie chart showing the distribution of attacker skill levels (e.g., Script Kiddie, Automated Script, Manual Exploration).
5. **`attack_country_distribution.png`:** A bar chart visualizing the Top 10 source countries of the attacks, enriched via proxy metadata.

### 8. How the Analysis Engine Works

The core of this project is the custom-built, rule-based engine in the `analyze_session_with_rules` function:

- **Keyword Dictionary:** The engine uses a predefined dictionary of `KEYWORDS` containing common commands associated with different attack phases (reconnaissance, download, destruction, persistence).
- **Scoring System:** It iterates through every command in a session and increments a score for each category when a command matches a keyword.
- **Heuristic-Based Classification:** After scoring all commands, a series of `if/elif` rules evaluates the scores to assign a final `intent` and `skill_level` to the session.
- **Evidence Extraction:** The engine also extracts potentially malicious URLs from `wget` or `curl` commands, providing concrete evidence in the final report.

### 9. Future Improvements

- **AI Agent Integration:** Use the rule-based engine as a pre-filter for LLM agents (e.g., Google Gemini) to perform deep-dive analyses on anomalous sessions.
- **Threat Intelligence Enrichment:** Query external threat intelligence APIs (such as AbuseIPDB, VirusTotal, or Shodan) for real-time IP reputation checks.
- **Interactive Dashboards:** Build an interactive Streamlit or Textual TUI dashboard for real-time log monitoring and forensic exploration.
