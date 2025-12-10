#!/usr/bin/env python3
"""
Validation script for vulnerability chains.

This script:
1. Loads scan results from DVWA, Juice Shop, and WebGoat
2. Runs chain detection on each application
3. Analyzes detected chains for logical soundness
4. Generates a comprehensive validation report

Usage:
    ./zapenv/bin/python3 benchmarks/validate_chains.py
"""

import json
import sys
from pathlib import Path
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from vulnerability_chains import ZAPAlertParser, ChainDetector, ChainScoring


def load_scan_results(scan_file):
    """
    Load and parse ZAP scan results.

    Args:
        scan_file: Path to ZAP scan JSON file

    Returns:
        List of Vulnerability objects
    """
    if not Path(scan_file).exists():
        print(f"  ✗ Scan file not found: {scan_file}")
        return []

    try:
        parser = ZAPAlertParser()
        vulnerabilities = parser.parse_zap_report(scan_file)
        print(f"  ✓ Loaded {len(vulnerabilities)} vulnerabilities from {Path(scan_file).name}")
        return vulnerabilities
    except Exception as e:
        print(f"  ✗ Error loading {scan_file}: {e}")
        return []


def detect_and_analyze_chains(vulns, app_name):
    """
    Run chain detection and analyze results.

    Args:
        vulns: List of vulnerabilities
        app_name: Name of the application

    Returns:
        ChainDetectionResult
    """
    if not vulns:
        print(f"\n  ⚠ No vulnerabilities to analyze for {app_name}")
        return None

    print(f"\n{'='*80}")
    print(f"Analyzing {app_name}")
    print(f"{'='*80}")

    # Run chain detection
    detector = ChainDetector()
    result = detector.detect_chains(vulns)

    # Score chains
    scoring = ChainScoring()
    for chain in result.chains:
        chain.risk_score = scoring.calculate_chain_risk(chain)

    # Sort chains by risk score (highest first)
    result.chains.sort(key=lambda c: c.risk_score, reverse=True)

    # Print summary
    print(f"\n📊 {app_name} Chain Detection Summary:")
    print(f"  Total vulnerabilities analyzed: {result.total_vulnerabilities}")
    print(f"  Total chains detected: {result.total_chains}")
    print(f"  Critical chains (Risk ≥ 30): {sum(1 for c in result.chains if c.risk_score >= 30)}")
    print(f"  High-risk chains (Risk 20-30): {sum(1 for c in result.chains if 20 <= c.risk_score < 30)}")
    print(f"  Medium-risk chains (Risk 10-20): {sum(1 for c in result.chains if 10 <= c.risk_score < 20)}")
    print(f"  Analysis time: {result.analysis_time:.2f}s")

    # Print detailed chain information
    if result.chains:
        print(f"\n🔗 Detected Chains (Top 10):")
        for i, chain in enumerate(result.chains[:10], 1):
            print(f"\n  Chain #{i} (ID: {chain.id})")
            print(f"    Type: {chain.chain_type.value}")
            print(f"    Risk Score: {chain.risk_score:.2f}")
            print(f"    Confidence: {chain.confidence:.2f}")
            print(f"    Length: {len(chain.vulnerabilities)} vulnerabilities")

            # Print vulnerability chain path
            print(f"    Path:")
            for j, vuln in enumerate(chain.vulnerabilities):
                prefix = "      └→" if j == len(chain.vulnerabilities) - 1 else "      ├→"
                print(f"{prefix} {vuln.name} [{vuln.risk.name}]")
                print(f"         URL: {vuln.url}")

            # Print impact
            print(f"    Impact: {chain.impact_description}")

            # Print exploitation steps
            if chain.exploitation_steps:
                print(f"    Exploitation Steps:")
                for step in chain.exploitation_steps:
                    print(f"      - {step}")
    else:
        print(f"\n  ⚠ No chains detected for {app_name}")

    return result


def generate_validation_report(dvwa_result, juice_result, webgoat_result):
    """
    Generate a comprehensive validation report in Markdown format.

    Args:
        dvwa_result: DVWA chain detection result
        juice_result: Juice Shop chain detection result
        webgoat_result: WebGoat chain detection result
    """
    report_file = "reports/chain_validation_report.md"

    with open(report_file, 'w') as f:
        f.write("# Vulnerability Chain Validation Report\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("---\n\n")

        # Overall summary
        total_chains = 0
        if dvwa_result:
            total_chains += dvwa_result.total_chains
        if juice_result:
            total_chains += juice_result.total_chains
        if webgoat_result:
            total_chains += webgoat_result.total_chains

        f.write("## Executive Summary\n\n")
        f.write(f"**Total Chains Detected:** {total_chains}\n\n")
        f.write("| Application | Vulnerabilities | Chains | Critical | High | Medium | Analysis Time |\n")
        f.write("|-------------|-----------------|--------|----------|------|--------|---------------|\n")

        for app_name, result in [("DVWA", dvwa_result), ("Juice Shop", juice_result), ("WebGoat", webgoat_result)]:
            if result:
                critical = sum(1 for c in result.chains if c.risk_score >= 30)
                high = sum(1 for c in result.chains if 20 <= c.risk_score < 30)
                medium = sum(1 for c in result.chains if 10 <= c.risk_score < 20)
                f.write(f"| {app_name} | {result.total_vulnerabilities} | {result.total_chains} | {critical} | {high} | {medium} | {result.analysis_time:.2f}s |\n")
            else:
                f.write(f"| {app_name} | 0 | 0 | 0 | 0 | 0 | 0.00s |\n")

        f.write("\n---\n\n")

        # Detailed reports for each application
        for app_name, result in [("DVWA", dvwa_result), ("Juice Shop", juice_result), ("WebGoat", webgoat_result)]:
            if not result or not result.chains:
                f.write(f"## {app_name}\n\n")
                f.write(f"⚠️ No chains detected for {app_name}\n\n")
                continue

            f.write(f"## {app_name}\n\n")
            f.write(f"**Chains Detected:** {result.total_chains}\n\n")

            # Top 5 chains
            for i, chain in enumerate(result.chains[:5], 1):
                f.write(f"### Chain #{i}: {chain.chain_type.value.replace('_', ' ').title()}\n\n")
                f.write(f"**Risk Score:** {chain.risk_score:.2f} ")
                if chain.risk_score >= 30:
                    f.write("🔴 CRITICAL\n")
                elif chain.risk_score >= 20:
                    f.write("🟠 HIGH\n")
                elif chain.risk_score >= 10:
                    f.write("🟡 MEDIUM\n")
                else:
                    f.write("🟢 LOW\n")
                f.write(f"**Confidence:** {chain.confidence:.2f}\n\n")

                # Chain path
                f.write("**Chain Path:**\n\n")
                f.write("```\n")
                for j, vuln in enumerate(chain.vulnerabilities):
                    arrow = " → " if j < len(chain.vulnerabilities) - 1 else ""
                    f.write(f"{vuln.name}{arrow}")
                f.write("\n```\n\n")

                # Vulnerabilities details
                f.write("**Vulnerabilities:**\n\n")
                for j, vuln in enumerate(chain.vulnerabilities, 1):
                    f.write(f"{j}. **{vuln.name}** [{vuln.risk.name}]\n")
                    f.write(f"   - URL: `{vuln.url}`\n")
                    if vuln.param:
                        f.write(f"   - Parameter: `{vuln.param}`\n")
                    if vuln.evidence:
                        evidence_preview = vuln.evidence[:100] + "..." if len(vuln.evidence) > 100 else vuln.evidence
                        f.write(f"   - Evidence: `{evidence_preview}`\n")
                f.write("\n")

                # Impact
                f.write(f"**Impact:** {chain.impact_description}\n\n")

                # Exploitation steps
                if chain.exploitation_steps:
                    f.write("**Exploitation Steps:**\n\n")
                    for step in chain.exploitation_steps:
                        f.write(f"- {step}\n")
                    f.write("\n")

                # Validation checklist
                f.write("**Validation Checklist:**\n\n")
                f.write("- [ ] Can execute step 1?\n")
                f.write("- [ ] Can execute step 2?\n")
                f.write("- [ ] Can execute step 3?\n")
                f.write("- [ ] Does chain achieve claimed impact?\n")
                f.write("- [ ] Is risk score accurate?\n\n")

                f.write("---\n\n")

    print(f"\n{'='*80}")
    print(f"✅ Validation report generated: {report_file}")
    print(f"{'='*80}\n")


def main():
    """Main validation function."""
    print("\n" + "="*80)
    print("VULNERABILITY CHAIN VALIDATION")
    print("="*80 + "\n")

    # Load scan results
    print("📂 Loading scan results...")

    dvwa_vulns = load_scan_results("scans/dvwa_scan_with_replacer.json")
    juice_vulns = load_scan_results("scans/juiceshop_scan_dynamic.json")
    webgoat_vulns = load_scan_results("scans/webgoat_scan_dynamic.json")

    # Analyze chains for each application
    dvwa_result = detect_and_analyze_chains(dvwa_vulns, "DVWA") if dvwa_vulns else None
    juice_result = detect_and_analyze_chains(juice_vulns, "Juice Shop") if juice_vulns else None
    webgoat_result = detect_and_analyze_chains(webgoat_vulns, "WebGoat") if webgoat_vulns else None

    # Generate validation report
    generate_validation_report(dvwa_result, juice_result, webgoat_result)

    # Summary
    print("\n📋 Validation Summary:")
    print(f"  DVWA: {dvwa_result.total_chains if dvwa_result else 0} chains")
    print(f"  Juice Shop: {juice_result.total_chains if juice_result else 0} chains")
    print(f"  WebGoat: {webgoat_result.total_chains if webgoat_result else 0} chains")

    total = (dvwa_result.total_chains if dvwa_result else 0) + \
            (juice_result.total_chains if juice_result else 0) + \
            (webgoat_result.total_chains if webgoat_result else 0)

    print(f"\n  ✅ TOTAL: {total} chains detected across all applications")
    print(f"\n  📄 Detailed report: reports/chain_validation_report.md")
    print("\n" + "="*80)


if __name__ == "__main__":
    main()
