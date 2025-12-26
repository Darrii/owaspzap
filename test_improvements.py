#!/usr/bin/env python3
"""
Test script for improved risk scoring and filtering.
Re-analyzes testphp.vulnweb.com scan with new algorithms.
"""

import sys
import json
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from vulnerability_chains.utils.zap_parser import ZAPAlertParser
from vulnerability_chains.core.taxonomy import VulnerabilityTaxonomy
from vulnerability_chains.rules.probabilistic_rules import ProbabilisticRuleEngine
from vulnerability_chains.core.context_analyzer import ContextAnalyzer
from vulnerability_chains.core.enhanced_detector import EnhancedChainDetector

def main():
    # Parse testphp scan
    scan_file = "scans/c295482c-dae6-4229-8237-7eae7c5049f7.json"

    print("=" * 80)
    print("IMPROVED RISK SCORING TEST")
    print("=" * 80)
    print(f"\nAnalyzing: {scan_file}\n")

    # Parse vulnerabilities with noise filtering
    parser = ZAPAlertParser(filter_noise=True)
    vulns = parser.parse_zap_report(scan_file)

    print(f"✓ Parsed {len(vulns)} vulnerabilities")
    print(f"  - Skipped {parser.skipped_count} noise/informational alerts\n")

    # Build graph
    taxonomy = VulnerabilityTaxonomy()
    rule_engine = ProbabilisticRuleEngine(taxonomy)
    context_analyzer = ContextAnalyzer()

    detector = EnhancedChainDetector(
        taxonomy=taxonomy,
        rule_engine=rule_engine,
        context_analyzer=context_analyzer,
        config={'enable_cluster_links': False}
    )

    graph = detector.build_graph(vulns)
    print(f"✓ Built graph: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges\n")

    # Find chains
    chains = detector.find_chains(
        min_length=2,
        max_length=5,
        min_chain_probability=0.65
    )

    print(f"✓ Found {len(chains)} chains\n")

    # Categorize by severity
    critical = [c for c in chains if c.risk_score >= 90]
    high = [c for c in chains if 70 <= c.risk_score < 90]
    medium = [c for c in chains if 40 <= c.risk_score < 70]
    low = [c for c in chains if c.risk_score < 40]

    print("SEVERITY DISTRIBUTION:")
    print("=" * 80)
    print(f"  CRITICAL (90-100): {len(critical)} chains")
    print(f"  HIGH (70-89):      {len(high)} chains")
    print(f"  MEDIUM (40-69):    {len(medium)} chains")
    print(f"  LOW (0-39):        {len(low)} chains\n")

    # Show top 10 chains with URLs
    print("TOP 10 CHAINS:")
    print("=" * 80)
    for i, chain in enumerate(chains[:10], 1):
        severity = detector._classify_chain_severity(chain.risk_score)
        print(f"{i}. [{severity}] Score: {chain.risk_score:.1f} | Conf: {chain.confidence:.2f} | Length: {len(chain)}")
        for v in chain.vulnerabilities:
            print(f"     - {v.name} @ {v.url[:60]}...")
        print()

    # Statistics comparison
    print("COMPARISON WITH OLD SYSTEM:")
    print("=" * 80)
    print("OLD: All 31 chains = CRITICAL (risk 420-110)")
    print(f"NEW: {len(critical)} CRITICAL, {len(high)} HIGH, {len(medium)} MEDIUM, {len(low)} LOW")
    print(f"     Normalized scores (0-100)\n")

    # Show score details for first chain
    if chains:
        chain = chains[0]
        print("EXAMPLE CHAIN SCORING BREAKDOWN:")
        print("=" * 80)
        print(f"Chain: {chain.vulnerabilities[0].name} → ... → {chain.vulnerabilities[-1].name}")
        print(f"  - Max Severity: {max(v.risk.value for v in chain.vulnerabilities)} → ~{(max(v.risk.value for v in chain.vulnerabilities)/3.0)*30:.1f} pts")
        print(f"  - Exploitability: ~{chain.confidence*30:.1f} pts (avg link confidence)")
        print(f"  - Chain Length ({len(chain)}): ~{[0,10,15,18,20][min(len(chain)-1,4)]} pts")
        print(f"  - Confidence: {chain.confidence:.2f} → ~{chain.confidence*20:.1f} pts")
        print(f"  TOTAL: {chain.risk_score:.1f}/100 ({detector._classify_chain_severity(chain.risk_score)})\n")

if __name__ == "__main__":
    main()
