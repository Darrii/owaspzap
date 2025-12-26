#!/usr/bin/env python3
"""
Generate graphs for Phase 3 (Q2 Publication)
Creates PNG and PDF formats for all figures
"""

import json
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from pathlib import Path

# Set style
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (10, 6)
plt.rcParams['font.size'] = 11

BASE_DIR = Path(__file__).parent / 'results'
RAW_DATA = BASE_DIR / 'raw_data'
GRAPHS_DIR = BASE_DIR / 'graphs'
GRAPHS_DIR.mkdir(parents=True, exist_ok=True)

def load_app_data(app_name):
    """Load enhanced and filtered data for an application"""
    enhanced_file = RAW_DATA / app_name / 'enhanced_system.json'
    filtered_file = RAW_DATA / app_name / 'filtered_chains.json'

    with open(enhanced_file) as f:
        enhanced = json.load(f)
    with open(filtered_file) as f:
        filtered = json.load(f)

    return enhanced, filtered

def save_figure(fig, name):
    """Save figure in PNG and PDF formats"""
    png_file = GRAPHS_DIR / f"{name}.png"
    pdf_file = GRAPHS_DIR / f"{name}.pdf"

    fig.savefig(png_file, dpi=300, bbox_inches='tight')
    fig.savefig(pdf_file, bbox_inches='tight')

    print(f"  ✓ {png_file.name}")
    print(f"  ✓ {pdf_file.name}")

def generate_figure_4():
    """Figure 4: Chain Detection Performance"""
    print("\n[Figure 4] Chain Detection Performance")

    apps = []
    processing_times = []
    chains_found = []

    for app in ['dvwa', 'juiceshop', 'webgoat']:
        enhanced, filtered = load_app_data(app)
        apps.append(app.upper())
        processing_times.append(enhanced['processing_time'])
        chains_found.append(enhanced['statistics']['total_chains_found'])

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    # Processing time
    bars1 = ax1.bar(apps, processing_times, color=['#3498db', '#e74c3c', '#2ecc71'])
    ax1.set_ylabel('Processing Time (seconds)')
    ax1.set_title('Chain Detection Processing Time')
    ax1.set_ylim(0, max(processing_times) * 1.2)
    for bar, time in zip(bars1, processing_times):
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height,
                f'{time:.1f}s', ha='center', va='bottom')

    # Chains found
    bars2 = ax2.bar(apps, chains_found, color=['#3498db', '#e74c3c', '#2ecc71'])
    ax2.set_ylabel('Total Chains Found')
    ax2.set_title('Total Vulnerability Chains Detected')
    ax2.set_ylim(0, max(chains_found) * 1.2)
    for bar, count in zip(bars2, chains_found):
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height,
                f'{count:,}', ha='center', va='bottom')

    plt.tight_layout()
    save_figure(fig, 'figure_4_performance')
    plt.close()

def generate_figure_5():
    """Figure 5: Deduplication Effectiveness"""
    print("\n[Figure 5] Deduplication Effectiveness")

    apps = []
    total_chains = []
    unique_chains = []
    dedup_rates = []

    for app in ['dvwa', 'juiceshop', 'webgoat']:
        enhanced, filtered = load_app_data(app)
        stats = enhanced['statistics']

        apps.append(app.upper())
        total_chains.append(stats['total_chains_found'])
        unique_chains.append(stats['unique_patterns'])
        dedup_rate = (1 - stats['unique_patterns']/stats['total_chains_found']) * 100
        dedup_rates.append(dedup_rate)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    # Before/After deduplication
    x = np.arange(len(apps))
    width = 0.35

    bars1 = ax1.bar(x - width/2, total_chains, width, label='Before Deduplication',
                    color='#e74c3c', alpha=0.8)
    bars2 = ax1.bar(x + width/2, unique_chains, width, label='After Deduplication',
                    color='#2ecc71', alpha=0.8)

    ax1.set_ylabel('Number of Chains')
    ax1.set_title('Deduplication Impact')
    ax1.set_xticks(x)
    ax1.set_xticklabels(apps)
    ax1.legend()
    ax1.set_yscale('log')  # Log scale for better visualization

    # Deduplication rate
    bars3 = ax2.bar(apps, dedup_rates, color=['#3498db', '#e74c3c', '#2ecc71'])
    ax2.set_ylabel('Deduplication Rate (%)')
    ax2.set_title('Deduplication Effectiveness')
    ax2.set_ylim(0, 105)
    ax2.axhline(y=99, color='gray', linestyle='--', alpha=0.5, label='99% threshold')
    for bar, rate in zip(bars3, dedup_rates):
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height,
                f'{rate:.2f}%', ha='center', va='bottom')
    ax2.legend()

    plt.tight_layout()
    save_figure(fig, 'figure_5_deduplication')
    plt.close()

def generate_figure_6():
    """Figure 6: Risk Score Distribution"""
    print("\n[Figure 6] Risk Score Distribution")

    fig, axes = plt.subplots(1, 3, figsize=(16, 5))

    for i, app in enumerate(['dvwa', 'juiceshop', 'webgoat']):
        enhanced, filtered = load_app_data(app)
        chains = filtered['chains']

        risk_scores = [c['risk_score'] for c in chains]

        # Histogram
        axes[i].hist(risk_scores, bins=20, color=['#3498db', '#e74c3c', '#2ecc71'][i],
                    alpha=0.7, edgecolor='black')
        axes[i].set_xlabel('Risk Score')
        axes[i].set_ylabel('Number of Chains')
        axes[i].set_title(f'{app.upper()}')
        axes[i].axvline(x=np.mean(risk_scores), color='red', linestyle='--',
                       label=f'Mean: {np.mean(risk_scores):.1f}')
        axes[i].legend()

    plt.tight_layout()
    save_figure(fig, 'figure_6_risk_distribution')
    plt.close()

def generate_figure_8():
    """Figure 8: Chain Length Distribution"""
    print("\n[Figure 8] Chain Length Distribution")

    length_data = {2: [], 3: [], 4: []}
    apps = []

    for app in ['dvwa', 'juiceshop', 'webgoat']:
        enhanced, filtered = load_app_data(app)
        chains = filtered['chains']
        apps.append(app.upper())

        for length in [2, 3, 4]:
            count = len([c for c in chains if c['length'] == length])
            length_data[length].append(count)

    fig, ax = plt.subplots(figsize=(10, 6))

    x = np.arange(len(apps))
    width = 0.25

    bars1 = ax.bar(x - width, length_data[2], width, label='Length 2',
                   color='#3498db', alpha=0.8)
    bars2 = ax.bar(x, length_data[3], width, label='Length 3',
                   color='#e74c3c', alpha=0.8)
    bars3 = ax.bar(x + width, length_data[4], width, label='Length 4',
                   color='#2ecc71', alpha=0.8)

    ax.set_ylabel('Number of Chains')
    ax.set_xlabel('Application')
    ax.set_title('Vulnerability Chain Length Distribution')
    ax.set_xticks(x)
    ax.set_xticklabels(apps)
    ax.legend()

    # Add value labels
    for bars in [bars1, bars2, bars3]:
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{int(height)}', ha='center', va='bottom', fontsize=9)

    plt.tight_layout()
    save_figure(fig, 'figure_8_length_distribution')
    plt.close()

if __name__ == '__main__':
    print("=" * 70)
    print("GENERATING GRAPHS FOR Q2 PUBLICATION")
    print("=" * 70)

    generate_figure_4()
    generate_figure_5()
    generate_figure_6()
    generate_figure_8()

    print("\n" + "=" * 70)
    print("✓ All graphs generated successfully!")
    print(f"✓ Location: {GRAPHS_DIR}")
    print("=" * 70)
