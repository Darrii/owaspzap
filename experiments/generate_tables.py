#!/usr/bin/env python3
"""
Generate tables for Phase 3 (Q2 Publication)
Creates Excel, CSV, and LaTeX formats for all tables
"""

import json
import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).parent / 'results'
RAW_DATA = BASE_DIR / 'raw_data'
TABLES_DIR = BASE_DIR / 'tables'
TABLES_DIR.mkdir(parents=True, exist_ok=True)

def load_app_data(app_name):
    """Load enhanced and filtered data for an application"""
    enhanced_file = RAW_DATA / app_name / 'enhanced_system.json'
    filtered_file = RAW_DATA / app_name / 'filtered_chains.json'

    with open(enhanced_file) as f:
        enhanced = json.load(f)
    with open(filtered_file) as f:
        filtered = json.load(f)

    return enhanced, filtered

def save_table(df, name, caption):
    """Save table in Excel, CSV, and LaTeX formats"""
    # Excel
    excel_file = TABLES_DIR / f"{name}.xlsx"
    df.to_excel(excel_file, index=False)
    print(f"  ✓ {excel_file.name}")

    # CSV
    csv_file = TABLES_DIR / f"{name}.csv"
    df.to_csv(csv_file, index=False)
    print(f"  ✓ {csv_file.name}")

    # LaTeX (with escape=True for special characters and float_format for precision)
    latex_file = TABLES_DIR / f"{name}.tex"
    latex_content = df.to_latex(index=False, caption=caption, label=f"tab:{name}",
                                 escape=True, column_format=None, float_format="%.1f")
    with open(latex_file, 'w') as f:
        f.write(latex_content)
    print(f"  ✓ {latex_file.name}")

def generate_table_iv():
    """Table IV: Test Applications Overview"""
    print("\n[Table IV] Test Applications Overview")

    apps_data = []
    for app in ['dvwa', 'juiceshop', 'webgoat']:
        enhanced, filtered = load_app_data(app)
        stats = enhanced['statistics']

        apps_data.append({
            'App': app.upper(),
            'Vulns': stats['total_vulnerabilities'],
            'Unique': stats['unique_vulnerabilities'],
            'Nodes': stats['graph_nodes'],
            'Edges': stats['graph_edges']
        })

    df = pd.DataFrame(apps_data)
    save_table(df, 'table_iv_applications', 'Test Applications Overview')

def generate_table_v():
    """Table V: Chain Detection Comparison"""
    print("\n[Table V] Chain Detection Comparison")

    comparison_data = []
    for app in ['dvwa', 'juiceshop', 'webgoat']:
        enhanced, filtered = load_app_data(app)
        stats = enhanced['statistics']

        comparison_data.append({
            'App': app.upper(),
            'Baseline': stats['total_vulnerabilities'],
            'Total Chains': stats['total_chains_found'],
            'Unique': stats['unique_patterns'],
            'Dedup (%)': round((1 - stats['unique_patterns']/stats['total_chains_found'])*100, 2),
            'Time (s)': round(enhanced['processing_time'], 1)
        })

    df = pd.DataFrame(comparison_data)
    save_table(df, 'table_v_comparison', 'Baseline vs Enhanced System Comparison')

def generate_table_vi():
    """Table VI: Performance Metrics"""
    print("\n[Table VI] Performance Metrics")

    perf_data = []
    for app in ['dvwa', 'juiceshop', 'webgoat']:
        enhanced, filtered = load_app_data(app)
        stats = enhanced['statistics']
        chains = filtered['chains']

        # Calculate metrics
        avg_risk = sum(c['risk_score'] for c in chains) / len(chains) if chains else 0
        avg_confidence = sum(c['confidence'] for c in chains) / len(chains) if chains else 0

        perf_data.append({
            'App': app.upper(),
            'Time (s)': round(enhanced['processing_time'], 1),
            'Ch/sec': round(stats['total_chains_found'] / enhanced['processing_time'], 0),
            'Avg Risk': round(avg_risk, 1),
            'Avg Conf': round(avg_confidence, 3)
        })

    df = pd.DataFrame(perf_data)
    save_table(df, 'table_vi_performance', 'System Performance Metrics')

def generate_table_vii():
    """Table VII: Chain Characteristics"""
    print("\n[Table VII] Chain Characteristics")

    char_data = []
    for app in ['dvwa', 'juiceshop', 'webgoat']:
        enhanced, filtered = load_app_data(app)
        chains = filtered['chains']

        # Length distribution
        length_2 = len([c for c in chains if c['length'] == 2])
        length_3 = len([c for c in chains if c['length'] == 3])
        length_4 = len([c for c in chains if c['length'] == 4])
        avg_length = sum(c['length'] for c in chains) / len(chains) if chains else 0

        char_data.append({
            'App': app.upper(),
            'Total': len(chains),
            'Avg Len': round(avg_length, 1),
            'Min Risk': round(min(c['risk_score'] for c in chains), 1) if chains else 0,
            'Max Risk': round(max(c['risk_score'] for c in chains), 1) if chains else 0
        })

    df = pd.DataFrame(char_data)
    save_table(df, 'table_vii_characteristics', 'Vulnerability Chain Characteristics')

if __name__ == '__main__':
    print("=" * 70)
    print("GENERATING TABLES FOR Q2 PUBLICATION")
    print("=" * 70)

    generate_table_iv()
    generate_table_v()
    generate_table_vi()
    generate_table_vii()

    print("\n" + "=" * 70)
    print("✓ All tables generated successfully!")
    print(f"✓ Location: {TABLES_DIR}")
    print("=" * 70)
