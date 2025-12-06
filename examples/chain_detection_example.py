#!/usr/bin/env python3
"""
Example: Vulnerability Chain Detection with OWASP ZAP

This example demonstrates how to use the Vulnerability Chain Detection system
to analyze OWASP ZAP scan results and identify exploit chains.
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from vulnerability_chains import VulnerabilityChainAnalyzer, analyze_zap_scan


def example_1_simple_analysis():
    """Example 1: Simple analysis of a ZAP report."""
    print("\n" + "="*70)
    print("Example 1: Simple ZAP Report Analysis")
    print("="*70)

    # Using convenience function
    # result = analyze_zap_scan('path/to/zap_report.json')

    print("This would analyze a ZAP JSON report and generate an HTML report.")
    print("Usage: analyze_zap_scan('zap_report.json')")


def example_2_detailed_analysis():
    """Example 2: Detailed analysis with custom parameters."""
    print("\n" + "="*70)
    print("Example 2: Detailed Analysis with Custom Parameters")
    print("="*70)

    # Create analyzer
    analyzer = VulnerabilityChainAnalyzer()

    # Analyze with custom parameters
    # result = analyzer.analyze_zap_report(
    #     report_file='path/to/zap_report.json',
    #     max_chain_length=4,
    #     min_confidence=0.7,
    #     min_risk_filter='Medium'
    # )

    print("Analyzer created with default rules.")
    print("Would analyze ZAP report with:")
    print("  - Max chain length: 4")
    print("  - Min confidence: 0.7")
    print("  - Min risk filter: Medium")

    # Print summary
    # analyzer.print_summary(result)


def example_3_multiple_export_formats():
    """Example 3: Export results in multiple formats."""
    print("\n" + "="*70)
    print("Example 3: Export in Multiple Formats")
    print("="*70)

    analyzer = VulnerabilityChainAnalyzer()

    # Analyze
    # result = analyzer.analyze_zap_report('path/to/zap_report.json')

    # Export in multiple formats
    # files = analyzer.export_results(
    #     result,
    #     output_dir='chain_analysis_results',
    #     formats=['html', 'json']
    # )

    print("Would export results in HTML and JSON formats.")
    # print(f"Exported files: {files}")


def example_4_custom_rules():
    """Example 4: Using custom chain rules."""
    print("\n" + "="*70)
    print("Example 4: Custom Chain Rules")
    print("="*70)

    # Create analyzer with custom rules file
    # analyzer = VulnerabilityChainAnalyzer(
    #     rules_file='path/to/custom_rules.json'
    # )

    print("Would create analyzer with custom chain rules.")
    print("Rules file should follow the format in vulnerability_chains/config/chain_rules.json")


def example_5_statistics_and_filtering():
    """Example 5: Get statistics and filter chains."""
    print("\n" + "="*70)
    print("Example 5: Statistics and Filtering")
    print("="*70)

    analyzer = VulnerabilityChainAnalyzer()

    # Analyze
    # result = analyzer.analyze_zap_report('path/to/zap_report.json')

    # Get comprehensive statistics
    # stats = analyzer.get_statistics(result)
    # print(f"Average risk score: {stats['scoring']['average_risk']:.2f}")
    # print(f"Total rules: {stats['rules']['total_rules']}")

    # Get top chains
    # top_chains = analyzer.get_top_chains(result, n=5, min_risk=10.0)
    # for i, chain in enumerate(top_chains, 1):
    #     print(f"\n{i}. {chain.get_summary()}")

    print("Would get detailed statistics and top chains.")


def example_6_programmatic_usage():
    """Example 6: Programmatic usage with custom vulnerabilities."""
    print("\n" + "="*70)
    print("Example 6: Programmatic Usage")
    print("="*70)

    from vulnerability_chains import Vulnerability, RiskLevel

    # Create vulnerabilities manually
    vulns = [
        Vulnerability(
            id="vuln_1",
            name="Cross Site Scripting",
            risk=RiskLevel.HIGH,
            confidence="High",
            url="http://example.com/page",
            param="input",
            description="XSS vulnerability found"
        ),
        Vulnerability(
            id="vuln_2",
            name="Anti-CSRF Tokens Check",
            risk=RiskLevel.MEDIUM,
            confidence="Medium",
            url="http://example.com/admin",
            description="Missing CSRF protection"
        )
    ]

    print(f"Created {len(vulns)} manual vulnerabilities")

    # Analyze
    analyzer = VulnerabilityChainAnalyzer()
    # result = analyzer.analyze_vulnerabilities(vulns)
    # analyzer.print_summary(result)

    print("Would analyze these vulnerabilities for chains.")


def example_7_real_world_scenario():
    """Example 7: Real-world scanning workflow."""
    print("\n" + "="*70)
    print("Example 7: Real-World Workflow")
    print("="*70)

    print("""
Typical workflow:

1. Run OWASP ZAP scan:
   $ zap.sh -cmd -quickurl https://target.com -quickout zap_report.json

2. Analyze with chain detection:
   $ python chain_detection_example.py

3. Review HTML report:
   - Open reports/chains/chain_report_XXXXXX.html
   - Review critical and high-risk chains
   - Prioritize remediation based on risk scores

4. Export for documentation:
   - JSON format for archival
   - HTML format for stakeholder review
    """)


def main():
    """Run all examples."""
    print("\n" + "="*70)
    print("VULNERABILITY CHAIN DETECTION - EXAMPLES")
    print("="*70)

    examples = [
        example_1_simple_analysis,
        example_2_detailed_analysis,
        example_3_multiple_export_formats,
        example_4_custom_rules,
        example_5_statistics_and_filtering,
        example_6_programmatic_usage,
        example_7_real_world_scenario
    ]

    for example in examples:
        try:
            example()
        except Exception as e:
            print(f"Error in {example.__name__}: {e}")

    print("\n" + "="*70)
    print("Examples completed!")
    print("="*70 + "\n")

    print("\nTo run with actual ZAP reports:")
    print("  1. Place your ZAP JSON report in this directory")
    print("  2. Update the file paths in the examples above")
    print("  3. Uncomment the analysis code")
    print("  4. Run: python chain_detection_example.py\n")


if __name__ == "__main__":
    main()
