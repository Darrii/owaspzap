#!/usr/bin/env python3
"""
PHASE 2: Run Real Experiments
Automated testing script for Q2 paper
"""

import sys
import asyncio
import json
import time
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from vulnerability_chains.utils.zap_parser import ZAPAlertParser
from vulnerability_chains.core.enhanced_detector import EnhancedChainDetector
from vulnerability_chains.core.taxonomy import VulnerabilityTaxonomy
from vulnerability_chains.core.context_analyzer import ContextAnalyzer
from vulnerability_chains.rules.probabilistic_rules import ProbabilisticRuleEngine

# Test targets - reprocess all
TARGETS = {
    'dvwa': 'http://localhost:8080',
    'juiceshop': 'http://localhost:3000',
    'webgoat': 'http://localhost:8081/WebGoat',
}

BASE_DIR = Path(__file__).parent / 'results' / 'raw_data'

async def run_baseline_scan(target_name, target_url):
    """Run baseline ZAP scan (no chain detection)"""
    print(f"[{target_name}] Running baseline ZAP scan...")

    # For baseline, we just parse existing scan results
    scan_file = Path(f'/Users/Dari/Desktop/OWASPpr/scans/{target_name}_scan_dynamic.json')
    if not scan_file.exists():
        scan_file = Path(f'/Users/Dari/Desktop/OWASPpr/scans/{target_name}_scan.json')

    if not scan_file.exists():
        print(f"  ⚠️ Scan file not found: {scan_file}")
        return None

    with open(scan_file) as f:
        scan_data = json.load(f)

    # Save as baseline
    output_file = BASE_DIR / target_name / 'baseline_zap.json'
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, 'w') as f:
        json.dump(scan_data, f, indent=2)

    print(f"  ✓ Baseline saved: {output_file}")
    return scan_data

def run_enhanced_detection(target_name, scan_data):
    """Run enhanced chain detection"""
    print(f"[{target_name}] Running enhanced chain detection...")

    start_time = time.time()

    # Parse vulnerabilities
    parser = ZAPAlertParser()

    # Save temp file
    temp_file = BASE_DIR / target_name / 'temp_scan.json'
    with open(temp_file, 'w') as f:
        json.dump(scan_data, f)

    vulnerabilities = parser.parse_zap_report(str(temp_file))
    temp_file.unlink()  # Delete temp file

    # Initialize detector
    taxonomy = VulnerabilityTaxonomy()
    rule_engine = ProbabilisticRuleEngine(taxonomy)
    context_analyzer = ContextAnalyzer()
    detector = EnhancedChainDetector(taxonomy, rule_engine, context_analyzer, config={
        'min_probability': 0.3,
        'enable_cluster_links': False,
    })

    # Build graph
    detector.build_graph(vulnerabilities)

    # Find chains - get ALL chains before filtering
    all_chains = []
    for start_node in detector.graph.nodes():
        visited = {start_node}
        detector._dfs_chains(
            current=start_node,
            path=[start_node],
            path_probability=1.0,
            visited=visited,
            chains=all_chains,
            min_length=2,
            max_length=4,
            min_prob=0.2,  # Very low threshold to get all possible chains
            max_chains=10000  # High limit
        )

    # Apply only deduplication, NO low-value filtering
    chains = detector._deduplicate_chains(all_chains)
    chains.sort(key=lambda c: c.risk_score, reverse=True)

    elapsed = time.time() - start_time

    # Keep only unique patterns (one representative per pattern)
    unique_patterns = {}
    for chain in chains:
        pattern = tuple([v.name for v in chain.vulnerabilities])
        if pattern not in unique_patterns:
            unique_patterns[pattern] = chain

    # Convert back to list and sort
    unique_chains = list(unique_patterns.values())
    unique_chains.sort(key=lambda c: c.risk_score, reverse=True)

    # Prepare results
    results = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'target': target_name,
        'processing_time': round(elapsed, 3),
        'statistics': {
            'total_vulnerabilities': len(vulnerabilities),
            'unique_vulnerabilities': len(set(v.name for v in vulnerabilities)),
            'graph_nodes': detector.graph.number_of_nodes(),
            'graph_edges': detector.graph.number_of_edges(),
            'total_chains_found': len(chains),
            'unique_patterns': len(unique_chains),
        },
        'chains': [
            {
                'vulnerabilities': [v.name for v in chain.vulnerabilities],
                'risk_score': round(chain.risk_score, 2),
                'confidence': round(chain.confidence, 3),
                'length': len(chain.vulnerabilities),
            }
            for chain in unique_chains  # Save only unique patterns
        ]
    }

    # Save results
    output_file = BASE_DIR / target_name / 'enhanced_system.json'
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"  ✓ Enhanced results saved: {output_file}")
    print(f"  ✓ Found {len(chains)} chains in {elapsed:.2f}s")

    return results

async def run_all_experiments():
    """Run experiments for all targets"""
    print("=" * 60)
    print("PHASE 2: RUNNING REAL EXPERIMENTS")
    print("=" * 60)

    for target_name, target_url in TARGETS.items():
        print(f"\n{'=' * 60}")
        print(f"Testing: {target_name.upper()}")
        print(f"URL: {target_url}")
        print(f"{'=' * 60}\n")

        # Run baseline
        scan_data = await run_baseline_scan(target_name, target_url)

        if scan_data:
            # Run enhanced detection
            run_enhanced_detection(target_name, scan_data)

        print()

    print("=" * 60)
    print("✓ ALL EXPERIMENTS COMPLETED")
    print("=" * 60)

if __name__ == '__main__':
    asyncio.run(run_all_experiments())
