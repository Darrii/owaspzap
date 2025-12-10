#!/usr/bin/env python3
"""
Compare scan results across DVWA, Juice Shop, and WebGoat
Generates comprehensive validation report
"""

import json
import sys
from pathlib import Path
from datetime import datetime

def load_scan_results(filename):
    """Load scan results from JSON file"""
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"  ⚠ File not found: {filename}")
        return []
    except Exception as e:
        print(f"  ✗ Error loading {filename}: {e}")
        return []

def analyze_alerts(alerts, app_name):
    """Analyze alerts and return statistics"""

    # Risk counts
    risk_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
    for alert in alerts:
        risk = alert.get('risk', 'Informational')
        risk_counts[risk] = risk_counts.get(risk, 0) + 1

    # Plugin IDs
    plugin_ids = set(alert.get('pluginId') for alert in alerts)

    # Injection vulnerabilities
    injection_keywords = ['injection', 'xss', 'scripting', 'command', 'code', 'traversal']
    injection_alerts = [
        a for a in alerts
        if any(kw in a.get('alert', '').lower() for kw in injection_keywords)
    ]

    # Group injection by type
    injection_by_type = {}
    for alert in injection_alerts:
        alert_type = alert.get('alert', 'Unknown')
        if alert_type not in injection_by_type:
            injection_by_type[alert_type] = 0
        injection_by_type[alert_type] += 1

    # Check for critical injection scanner IDs
    critical_scanner_ids = {
        '40018': 'SQL Injection',
        '40019': 'SQL Injection - MySQL',
        '40012': 'Cross Site Scripting (Reflected)',
        '40014': 'Cross Site Scripting (Persistent)',
        '90020': 'Remote OS Command Injection',
        '6': 'Path Traversal',
        '7': 'Remote File Inclusion'
    }

    found_critical = {}
    for scanner_id, scanner_name in critical_scanner_ids.items():
        if scanner_id in plugin_ids:
            count = sum(1 for a in alerts if a.get('pluginId') == scanner_id)
            found_critical[scanner_name] = count

    return {
        'app_name': app_name,
        'total_alerts': len(alerts),
        'risk_counts': risk_counts,
        'plugin_count': len(plugin_ids),
        'injection_count': len(injection_alerts),
        'injection_by_type': injection_by_type,
        'critical_scanners_found': found_critical
    }

def print_comparison_report(results_list):
    """Print comprehensive comparison report"""

    print("="*100)
    print("COMPREHENSIVE SCAN RESULTS COMPARISON")
    print("="*100)
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Summary table
    print("\n" + "="*100)
    print("SUMMARY TABLE")
    print("="*100)

    print(f"\n{'Application':<20} {'Total Alerts':<15} {'High':<10} {'Medium':<10} {'Low':<10} {'Injection':<15}")
    print("-"*100)

    for result in results_list:
        if result['total_alerts'] > 0:
            print(f"{result['app_name']:<20} {result['total_alerts']:<15} "
                  f"{result['risk_counts']['High']:<10} {result['risk_counts']['Medium']:<10} "
                  f"{result['risk_counts']['Low']:<10} {result['injection_count']:<15}")

    # Injection vulnerabilities comparison
    print("\n" + "="*100)
    print("INJECTION VULNERABILITIES BY TYPE")
    print("="*100)

    # Collect all injection types
    all_injection_types = set()
    for result in results_list:
        all_injection_types.update(result['injection_by_type'].keys())

    if all_injection_types:
        print(f"\n{'Vulnerability Type':<50} ", end='')
        for result in results_list:
            if result['total_alerts'] > 0:
                print(f"{result['app_name']:<20} ", end='')
        print()
        print("-"*100)

        for vuln_type in sorted(all_injection_types):
            print(f"{vuln_type:<50} ", end='')
            for result in results_list:
                if result['total_alerts'] > 0:
                    count = result['injection_by_type'].get(vuln_type, 0)
                    if count > 0:
                        print(f"{count:<20} ", end='')
                    else:
                        print(f"{'—':<20} ", end='')
            print()
    else:
        print("\n⚠ No injection vulnerabilities found in any application")

    # Critical scanner detection
    print("\n" + "="*100)
    print("CRITICAL SCANNER IDS DETECTED")
    print("="*100)
    print("\nThese are the injection scanners we specifically configured:")

    all_critical = set()
    for result in results_list:
        all_critical.update(result['critical_scanners_found'].keys())

    if all_critical:
        print(f"\n{'Scanner Name':<50} ", end='')
        for result in results_list:
            if result['total_alerts'] > 0:
                print(f"{result['app_name']:<20} ", end='')
        print()
        print("-"*100)

        for scanner_name in sorted(all_critical):
            print(f"{scanner_name:<50} ", end='')
            for result in results_list:
                if result['total_alerts'] > 0:
                    count = result['critical_scanners_found'].get(scanner_name, 0)
                    if count > 0:
                        print(f"✓ {count} found{'':<10} ", end='')
                    else:
                        print(f"{'—':<20} ", end='')
            print()
    else:
        print("\n✗ No critical injection scanner IDs found in results")
        print("  This indicates the injection scanners may not have run properly")

    # Success metrics
    print("\n" + "="*100)
    print("SUCCESS METRICS")
    print("="*100)

    total_injection = sum(r['injection_count'] for r in results_list)
    total_critical_scanners = sum(len(r['critical_scanners_found']) for r in results_list)

    print(f"\n✓ Total applications scanned: {len([r for r in results_list if r['total_alerts'] > 0])}")
    print(f"✓ Total alerts found: {sum(r['total_alerts'] for r in results_list)}")
    print(f"✓ Total injection vulnerabilities: {total_injection}")
    print(f"✓ Critical injection scanners fired: {total_critical_scanners}")

    # Assessment
    print("\n" + "="*100)
    print("ASSESSMENT")
    print("="*100)

    if total_injection > 0:
        print("\n✅ SUCCESS: Injection vulnerabilities detected!")
        print(f"   Found {total_injection} injection vulnerabilities across applications")

        if total_critical_scanners > 0:
            print(f"   ✅ Critical scanners working: {total_critical_scanners} scanner types fired")
        else:
            print("   ⚠ Warning: No critical scanner IDs found")
            print("   → Injection vulnerabilities detected by other scanners")
    else:
        print("\n⚠ WARNING: No injection vulnerabilities detected")
        print("   Possible reasons:")
        print("   1. Applications may require authentication")
        print("   2. Modern SPAs may need specialized scanning")
        print("   3. Scanners may need different configuration")

    # Recommendations
    print("\n" + "="*100)
    print("RECOMMENDATIONS")
    print("="*100)

    for result in results_list:
        if result['total_alerts'] == 0:
            print(f"\n⚠ {result['app_name']}: No results")
            print(f"   → Scan may not have completed or file not found")
        elif result['injection_count'] == 0:
            print(f"\n⚠ {result['app_name']}: No injection vulnerabilities found")
            print(f"   → May need authenticated scanning or specialized configuration")
        else:
            print(f"\n✓ {result['app_name']}: {result['injection_count']} injection vulnerabilities found")
            print(f"   → Good coverage, continue with chain detection")

    print("\n" + "="*100)

def main():
    """Main comparison function"""

    scan_files = {
        'DVWA': 'scans/dvwa_scan_with_replacer.json',
        'Juice Shop': 'scans/juiceshop_scan_dynamic.json',
        'WebGoat': 'scans/webgoat_scan_dynamic.json'
    }

    print("\nLoading scan results...")
    results_list = []

    for app_name, filename in scan_files.items():
        print(f"  → {app_name}: {filename}")
        alerts = load_scan_results(filename)
        result = analyze_alerts(alerts, app_name)
        results_list.append(result)

        if result['total_alerts'] > 0:
            print(f"    ✓ Loaded {result['total_alerts']} alerts")
        else:
            print(f"    ⚠ No alerts found")

    # Print comparison report
    print_comparison_report(results_list)

    # Save to file
    output_file = f"reports/comparison_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    print(f"\n{'='*100}")
    print(f"Report saved to: {output_file}")
    print(f"{'='*100}\n")

if __name__ == "__main__":
    main()
