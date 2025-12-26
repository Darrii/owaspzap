#!/usr/bin/env python3
"""
Filter quality chains from raw results
Keep only HIGH/CRITICAL chains, remove duplicates
"""

import json
from pathlib import Path
from collections import defaultdict

def filter_chains(input_file, output_file):
    """Filter and deduplicate chains"""
    with open(input_file) as f:
        data = json.load(f)

    # Group by vulnerability pattern
    unique_patterns = {}

    for chain in data['chains']:
        # Create signature
        pattern = tuple(chain['vulnerabilities'])

        # Keep first occurrence of each pattern
        if pattern not in unique_patterns:
            unique_patterns[pattern] = chain

    # Keep ALL unique patterns (no risk score filtering)
    quality_chains = list(unique_patterns.values())

    # Sort by risk score
    quality_chains.sort(key=lambda x: x['risk_score'], reverse=True)

    # Update data - save ALL unique chains
    data['chains'] = quality_chains
    data['statistics']['filtered_chains'] = len(quality_chains)
    data['statistics']['unique_patterns_only'] = True

    # Save
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)

    print(f"  {input_file.stem}: {data['statistics']['total_chains_found']} → {len(quality_chains)} unique patterns")
    return quality_chains

if __name__ == '__main__':
    base_dir = Path(__file__).parent / 'results' / 'raw_data'

    print("Filtering quality chains...")
    print()

    all_results = {}
    for app in ['dvwa', 'juiceshop', 'webgoat']:
        input_file = base_dir / app / 'enhanced_system.json'
        output_file = base_dir / app / 'filtered_chains.json'

        chains = filter_chains(input_file, output_file)
        all_results[app] = chains

    print()
    print("All unique chains per application:")
    for app, chains in all_results.items():
        print(f"\n{app.upper()} ({len(chains)} unique patterns):")
        for i, chain in enumerate(chains, 1):
            vulns = ' → '.join(chain['vulnerabilities'])
            print(f"  {i}. {vulns} (risk={chain['risk_score']:.1f}, conf={chain['confidence']:.3f})")
