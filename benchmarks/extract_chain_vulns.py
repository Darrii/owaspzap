#!/usr/bin/env python3
"""
Extract Exact Vulnerability Details from ZAP Scans for Chain Validation Testing
===============================================================================

This script extracts exact URLs, payloads, parameters, and evidence from ZAP
scan results for each vulnerability in detected chains. This enables validation
tests to use the EXACT vulnerabilities that ZAP found, rather than generic payloads.

Purpose:
    Improve validation test accuracy from 33.3% to 80%+ by using exact data

Output:
    reports/chain_test_data.json - Exact vulnerability details for testing

Usage:
    ./zapenv/bin/python3 benchmarks/extract_chain_vulns.py \
        --dvwa-scan scans/dvwa_scan_with_replacer.json \
        --juice-scan scans/juiceshop_scan.json \
        --webgoat-scan scans/webgoat_scan.json \
        --output reports/chain_test_data.json
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from vulnerability_chains import ZAPAlertParser, ChainDetector, ChainScoring


def load_scan_results(scan_file):
    """
    Load ZAP scan results from JSON file.

    Args:
        scan_file: Path to ZAP scan JSON file

    Returns:
        List of alert dictionaries
    """
    try:
        with open(scan_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading scan file {scan_file}: {e}")
        return []


def detect_chains_from_scan(scan_file, app_name):
    """
    Detect vulnerability chains from a scan file.

    Args:
        scan_file: Path to ZAP scan JSON file
        app_name: Application name (for display)

    Returns:
        ChainDetectionResult object
    """
    print(f"\n[{app_name}] Analyzing scan results...")

    # Parse vulnerabilities
    parser = ZAPAlertParser()
    vulnerabilities = parser.parse_zap_report(scan_file)
    print(f"  → Parsed {len(vulnerabilities)} vulnerabilities")

    # Detect chains
    detector = ChainDetector()
    result = detector.detect_chains(vulnerabilities)

    # Score chains
    scoring = ChainScoring()
    for chain in result.chains:
        chain.risk_score = scoring.calculate_chain_risk(chain)

    # Sort by risk score
    result.chains.sort(key=lambda c: c.risk_score, reverse=True)

    print(f"  → Detected {result.total_chains} chains")

    return result


def extract_exact_vulnerability_details(vuln, scan_alerts):
    """
    Extract exact details for a vulnerability from ZAP scan alerts.

    Args:
        vuln: Vulnerability object from chain
        scan_alerts: List of ZAP alert dictionaries

    Returns:
        Dictionary with exact vulnerability details or None
    """
    # Try to find exact match first
    for alert in scan_alerts:
        if (alert.get('name') == vuln.name and
            alert.get('url') == vuln.url):
            return {
                'name': alert['name'],
                'url': alert['url'],
                'method': alert.get('method', 'GET'),
                'param': alert.get('param', ''),
                'attack': alert.get('attack', ''),
                'evidence': alert.get('evidence', ''),
                'risk': alert.get('risk', ''),
                'description': alert.get('description', '')[:200] + '...'
            }

    # If no exact match, try fuzzy match on name only
    for alert in scan_alerts:
        if alert.get('name') == vuln.name:
            return {
                'name': alert['name'],
                'url': alert['url'],
                'method': alert.get('method', 'GET'),
                'param': alert.get('param', ''),
                'attack': alert.get('attack', ''),
                'evidence': alert.get('evidence', ''),
                'risk': alert.get('risk', ''),
                'description': alert.get('description', '')[:200] + '...'
            }

    return None


def extract_chain_test_data(chain, scan_alerts, chain_number):
    """
    Extract test data for a specific chain.

    Args:
        chain: VulnerabilityChain object
        scan_alerts: List of ZAP alert dictionaries
        chain_number: Chain number (for identification)

    Returns:
        Dictionary with chain test data
    """
    chain_data = {
        'chain_number': chain_number,
        'chain_type': chain.chain_type.value,  # Convert enum to string
        'risk_score': chain.risk_score,
        'confidence': chain.confidence,
        'vulnerabilities': []
    }

    # Extract exact details for each vulnerability in chain
    for vuln in chain.vulnerabilities:
        exact_details = extract_exact_vulnerability_details(vuln, scan_alerts)
        if exact_details:
            chain_data['vulnerabilities'].append(exact_details)
        else:
            # Fallback: use data from vulnerability object
            chain_data['vulnerabilities'].append({
                'name': vuln.name,
                'url': vuln.url,
                'method': 'GET',
                'param': '',
                'attack': '',
                'evidence': '',
                'risk': vuln.risk.value,
                'description': 'Exact details not found in scan'
            })

    return chain_data


def extract_all_chains(scan_file, app_name, top_n=3):
    """
    Extract test data for top N chains from a scan.

    Args:
        scan_file: Path to ZAP scan JSON file
        app_name: Application name
        top_n: Number of top chains to extract (default: 3)

    Returns:
        Dictionary mapping chain_N to test data
    """
    # Load scan alerts
    scan_alerts = load_scan_results(scan_file)
    if not scan_alerts:
        return {}

    # Detect chains
    result = detect_chains_from_scan(scan_file, app_name)
    if not result.chains:
        print(f"  ! No chains detected for {app_name}")
        return {}

    # Extract data for top N chains
    app_data = {}
    for i, chain in enumerate(result.chains[:top_n], 1):
        chain_key = f"chain_{i}"
        chain_data = extract_chain_test_data(chain, scan_alerts, i)
        app_data[chain_key] = chain_data

        print(f"  ✓ Chain {i}: {chain.chain_type} (Risk: {chain.risk_score:.2f}, Vulns: {len(chain.vulnerabilities)})")

    return app_data


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Extract exact vulnerability details from ZAP scans for validation testing',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '--dvwa-scan',
        help='Path to DVWA ZAP scan JSON file'
    )
    parser.add_argument(
        '--juice-scan',
        help='Path to Juice Shop ZAP scan JSON file'
    )
    parser.add_argument(
        '--webgoat-scan',
        help='Path to WebGoat ZAP scan JSON file'
    )
    parser.add_argument(
        '--output',
        default='reports/chain_test_data.json',
        help='Output JSON file path (default: reports/chain_test_data.json)'
    )
    parser.add_argument(
        '--top-n',
        type=int,
        default=3,
        help='Number of top chains to extract per app (default: 3)'
    )

    args = parser.parse_args()

    # Check at least one scan provided
    if not any([args.dvwa_scan, args.juice_scan, args.webgoat_scan]):
        parser.error("At least one scan file must be provided")

    print("=" * 80)
    print("EXTRACTING EXACT VULNERABILITY DETAILS FOR VALIDATION TESTING")
    print("=" * 80)

    test_data = {
        'metadata': {
            'generated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'purpose': 'Exact vulnerability details for validation testing',
            'source': 'ZAP scan results'
        }
    }

    # Extract DVWA chains
    if args.dvwa_scan:
        print(f"\n[DVWA] Processing scan: {args.dvwa_scan}")
        test_data['DVWA'] = extract_all_chains(args.dvwa_scan, 'DVWA', args.top_n)

    # Extract Juice Shop chains
    if args.juice_scan:
        print(f"\n[Juice Shop] Processing scan: {args.juice_scan}")
        test_data['Juice Shop'] = extract_all_chains(args.juice_scan, 'Juice Shop', args.top_n)

    # Extract WebGoat chains
    if args.webgoat_scan:
        print(f"\n[WebGoat] Processing scan: {args.webgoat_scan}")
        test_data['WebGoat'] = extract_all_chains(args.webgoat_scan, 'WebGoat', args.top_n)

    # Create reports directory if needed
    Path('reports').mkdir(exist_ok=True)

    # Save output
    with open(args.output, 'w') as f:
        json.dump(test_data, f, indent=2)

    print(f"\n{'=' * 80}")
    print(f"✓ Test data saved to: {args.output}")
    print(f"{'=' * 80}\n")

    # Print summary
    total_apps = sum(1 for k in test_data if k != 'metadata')
    total_chains = sum(len(v) for k, v in test_data.items() if k != 'metadata')

    print(f"Summary:")
    print(f"  Applications processed: {total_apps}")
    print(f"  Total chains extracted: {total_chains}")
    print(f"\nNext step: Update manual_vuln_test_final.py to use this test data\n")


if __name__ == "__main__":
    main()
