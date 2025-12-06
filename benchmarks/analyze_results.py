#!/usr/bin/env python3
"""
Vulnerability Chain Analysis Script

Analyzes ZAP scan results using the Vulnerability Chain Detection system
and generates reports with metrics.
"""

import sys
import json
import argparse
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from vulnerability_chains import VulnerabilityChainAnalyzer
except ImportError:
    print("ERROR: vulnerability_chains module not found")
    print("Make sure you're running from the project root directory")
    sys.exit(1)


def analyze_scan(input_file, output_html=None, output_json=None,
                 max_chain_length=5, min_confidence=0.5, min_risk='Low'):
    """
    Analyze ZAP scan results for vulnerability chains.

    Args:
        input_file: Path to ZAP JSON report
        output_html: Path for HTML report (optional)
        output_json: Path for JSON metrics (optional)
        max_chain_length: Maximum chain length to detect
        min_confidence: Minimum confidence threshold (0.0-1.0)
        min_risk: Minimum risk level (Low/Medium/High)

    Returns:
        ChainDetectionResult object
    """
    print("="*70)
    print("Vulnerability Chain Detection Analysis")
    print("="*70)
    print()

    # Check input file exists
    if not Path(input_file).exists():
        print(f"✗ Input file not found: {input_file}")
        sys.exit(1)

    print(f"📂 Input file: {input_file}")
    print(f"⚙️  Configuration:")
    print(f"   - Max chain length: {max_chain_length}")
    print(f"   - Min confidence: {min_confidence}")
    print(f"   - Min risk level: {min_risk}")
    print()

    # Initialize analyzer
    print("🔧 Initializing Vulnerability Chain Analyzer...")
    analyzer = VulnerabilityChainAnalyzer()

    # Analyze ZAP report
    print("🔍 Analyzing ZAP report...")
    result = analyzer.analyze_zap_report(
        report_file=input_file,
        max_chain_length=max_chain_length,
        min_confidence=min_confidence,
        min_risk_filter=min_risk
    )

    # Display summary
    print()
    print("-"*70)
    print("📊 Analysis Results")
    print("-"*70)
    print(f"Vulnerabilities found:    {result.total_vulnerabilities}")
    print(f"Vulnerability chains:     {result.total_chains}")
    print(f"  ├─ Critical chains:     {result.critical_chains}")
    print(f"  └─ High risk chains:    {result.high_risk_chains}")
    print(f"Analysis time:            {result.analysis_time:.3f}s")
    print()

    # Show top chains
    if result.total_chains > 0:
        print("-"*70)
        print("🔗 Top Vulnerability Chains")
        print("-"*70)
        for i, chain in enumerate(result.chains[:5], 1):
            path = ' → '.join([v.name for v in chain.vulnerabilities])
            print(f"{i}. {path}")
            print(f"   Risk Score: {chain.risk_score:.2f}")
            print(f"   Type: {chain.chain_type}")
            print(f"   Confidence: {chain.confidence:.2f}")
            print()
    else:
        print("ℹ️  No vulnerability chains detected")
        print()

    # Generate HTML report
    if output_html:
        print(f"📝 Generating HTML report: {output_html}")
        Path(output_html).parent.mkdir(parents=True, exist_ok=True)
        analyzer.generate_report(result, output_file=output_html, format='html')
        print(f"✓ HTML report saved")

    # Generate JSON metrics
    if output_json:
        print(f"📊 Generating JSON metrics: {output_json}")
        Path(output_json).parent.mkdir(parents=True, exist_ok=True)
        analyzer.generate_report(result, output_file=output_json, format='json')
        print(f"✓ JSON metrics saved")

    print()
    print("="*70)
    print("Analysis Complete!")
    print("="*70)
    print()

    if output_html:
        print(f"Open HTML report:")
        print(f"  macOS:  open {output_html}")
        print(f"  Linux:  xdg-open {output_html}")
        print()

    return result


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Analyze ZAP scan results for vulnerability chains',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic analysis
  python3 analyze_results.py --input scans/dvwa_scan.json

  # With HTML report
  python3 analyze_results.py --input scans/dvwa_scan.json --output-html reports/dvwa.html

  # With both HTML and JSON
  python3 analyze_results.py \\
    --input scans/dvwa_scan.json \\
    --output-html reports/dvwa.html \\
    --output-json reports/dvwa_metrics.json

  # Adjust detection parameters
  python3 analyze_results.py \\
    --input scans/dvwa_scan.json \\
    --max-chain-length 10 \\
    --min-confidence 0.7 \\
    --min-risk High
        """
    )

    parser.add_argument(
        '--input',
        required=True,
        help='Input ZAP JSON report file'
    )
    parser.add_argument(
        '--output-html',
        help='Output HTML report file (optional)'
    )
    parser.add_argument(
        '--output-json',
        help='Output JSON metrics file (optional)'
    )
    parser.add_argument(
        '--max-chain-length',
        type=int,
        default=5,
        help='Maximum chain length to detect (default: 5)'
    )
    parser.add_argument(
        '--min-confidence',
        type=float,
        default=0.5,
        help='Minimum confidence threshold 0.0-1.0 (default: 0.5)'
    )
    parser.add_argument(
        '--min-risk',
        choices=['Low', 'Medium', 'High', 'Critical'],
        default='Low',
        help='Minimum risk level (default: Low)'
    )

    args = parser.parse_args()

    # Set default outputs if not specified
    if not args.output_html and not args.output_json:
        input_path = Path(args.input)
        base_name = input_path.stem
        args.output_html = f"reports/{base_name}_chains.html"
        args.output_json = f"reports/{base_name}_metrics.json"

    # Run analysis
    result = analyze_scan(
        input_file=args.input,
        output_html=args.output_html,
        output_json=args.output_json,
        max_chain_length=args.max_chain_length,
        min_confidence=args.min_confidence,
        min_risk=args.min_risk
    )

    # Exit with code based on chains found
    if result.critical_chains > 0:
        sys.exit(2)  # Critical chains found
    elif result.high_risk_chains > 0:
        sys.exit(1)  # High risk chains found
    else:
        sys.exit(0)  # Success


if __name__ == '__main__':
    main()
