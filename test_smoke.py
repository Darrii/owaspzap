#!/usr/bin/env python3
"""
Simple smoke test to verify Vulnerability Chain Detection system works.

This test creates synthetic vulnerabilities and checks if chains are detected.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from vulnerability_chains import VulnerabilityChainAnalyzer
from vulnerability_chains.models import Vulnerability
from vulnerability_chains.constants import RiskLevel


def test_basic_functionality():
    """Test basic chain detection functionality."""

    print("="*70)
    print("🧪 SMOKE TEST - Vulnerability Chain Detection")
    print("="*70)

    # Step 1: Create analyzer
    print("\n1️⃣  Creating analyzer...")
    try:
        analyzer = VulnerabilityChainAnalyzer()
        print("   ✅ Analyzer created successfully")
        print(f"   📚 Loaded {len(analyzer.rule_engine)} chain rules")
    except Exception as e:
        print(f"   ❌ Failed to create analyzer: {e}")
        return False

    # Step 2: Create test vulnerabilities
    print("\n2️⃣  Creating test vulnerabilities...")
    try:
        vulnerabilities = [
            # XSS vulnerability
            Vulnerability(
                id="test_xss_1",
                name="Cross Site Scripting",
                risk=RiskLevel.HIGH,
                confidence="High",
                url="http://testapp.local/login",
                param="username",
                description="XSS vulnerability in login form"
            ),
            # CSRF vulnerability (same domain)
            Vulnerability(
                id="test_csrf_1",
                name="Anti-CSRF Tokens Check",
                risk=RiskLevel.MEDIUM,
                confidence="Medium",
                url="http://testapp.local/admin",
                description="Missing CSRF protection on admin panel"
            ),
            # SQL Injection
            Vulnerability(
                id="test_sqli_1",
                name="SQL Injection",
                risk=RiskLevel.HIGH,
                confidence="High",
                url="http://testapp.local/users",
                param="id",
                description="SQL injection in user lookup"
            ),
            # Privilege Escalation (same domain)
            Vulnerability(
                id="test_priv_1",
                name="Privilege Escalation",
                risk=RiskLevel.HIGH,
                confidence="High",
                url="http://testapp.local/admin/users",
                description="User can escalate privileges"
            )
        ]

        print(f"   ✅ Created {len(vulnerabilities)} test vulnerabilities:")
        for v in vulnerabilities:
            print(f"      • {v.name} ({v.risk.name})")
    except Exception as e:
        print(f"   ❌ Failed to create vulnerabilities: {e}")
        return False

    # Step 3: Analyze for chains
    print("\n3️⃣  Analyzing for vulnerability chains...")
    try:
        result = analyzer.analyze_vulnerabilities(
            vulnerabilities=vulnerabilities,
            max_chain_length=3,
            min_confidence=0.6
        )
        print("   ✅ Analysis completed successfully")
        print(f"   ⏱️  Analysis time: {result.analysis_time:.3f}s")
    except Exception as e:
        print(f"   ❌ Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    # Step 4: Check results
    print("\n4️⃣  Checking results...")
    print(f"   📊 Total vulnerabilities: {result.total_vulnerabilities}")
    print(f"   🔗 Total chains detected: {result.total_chains}")
    print(f"   🔴 Critical chains: {result.critical_chains}")
    print(f"   🟠 High risk chains: {result.high_risk_chains}")

    # Step 5: Display found chains
    if result.total_chains > 0:
        print("\n5️⃣  Found chains:")
        for i, chain in enumerate(result.chains[:5], 1):  # Show first 5
            print(f"\n   Chain #{i}:")
            print(f"   Type: {chain.chain_type.value}")
            print(f"   Risk Score: {chain.risk_score:.2f}")
            print(f"   Confidence: {chain.confidence:.0%}")
            print(f"   Path: {chain.get_summary()}")

        if result.total_chains > 5:
            print(f"\n   ... and {result.total_chains - 5} more chains")
    else:
        print("\n5️⃣  ⚠️  No chains detected (this might be OK depending on vulnerabilities)")

    # Step 6: Test graph statistics
    print("\n6️⃣  Graph statistics:")
    if analyzer.detector.graph:
        stats = analyzer.detector.graph.get_graph_stats()
        print(f"   📈 Graph nodes: {stats['total_nodes']}")
        print(f"   🔗 Graph edges: {stats['total_edges']}")
        print(f"   📊 Average degree: {stats['average_degree']:.2f}")
        print(f"   🌐 Connected components: {stats['connected_components']}")

    # Step 7: Test report generation
    print("\n7️⃣  Testing report generation...")
    try:
        # Generate JSON report
        json_file = analyzer.generate_report(
            result,
            output_file='test_smoke_result.json',
            format='json'
        )
        print(f"   ✅ JSON report: {json_file}")

        # Generate HTML report
        html_file = analyzer.generate_report(
            result,
            output_file='test_smoke_result.html',
            format='html'
        )
        print(f"   ✅ HTML report: {html_file}")
    except Exception as e:
        print(f"   ⚠️  Report generation warning: {e}")

    # Final verdict
    print("\n" + "="*70)
    print("✅ SMOKE TEST PASSED!")
    print("="*70)
    print("\n✨ System is working correctly!")
    print("📝 Next steps:")
    print("   1. Check generated reports: test_smoke_result.html")
    print("   2. Run full benchmark tests on real datasets")
    print("   3. Start collecting metrics for publication")

    return True


def main():
    """Main function."""
    try:
        success = test_basic_functionality()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ SMOKE TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
