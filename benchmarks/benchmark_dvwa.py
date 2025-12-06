#!/usr/bin/env python3
"""
DVWA Benchmark Script - Vulnerability Chain Detection

This script runs chain detection on DVWA synthetic scan and compares
results against ground truth to calculate benchmark metrics.
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from vulnerability_chains import VulnerabilityChainAnalyzer


class ChainBenchmark:
    """Benchmark evaluation for vulnerability chain detection."""

    def __init__(self, ground_truth_file: str):
        """
        Initialize benchmark with ground truth data.

        Args:
            ground_truth_file: Path to ground truth JSON file
        """
        with open(ground_truth_file, 'r') as f:
            self.ground_truth = json.load(f)

        self.expected_chains = self._parse_expected_chains()

    def _parse_expected_chains(self) -> Set[Tuple[str, ...]]:
        """
        Parse expected chains from ground truth.

        Returns:
            Set of tuples representing expected vulnerability chains
        """
        expected = set()
        for chain in self.ground_truth['expected_chains']:
            path = tuple(chain['vulnerability_path'])
            expected.add(path)

        return expected

    def evaluate(self, detected_chains: List) -> Dict:
        """
        Evaluate detected chains against ground truth.

        Args:
            detected_chains: List of detected VulnerabilityChain objects

        Returns:
            Dictionary with evaluation metrics
        """
        # Convert detected chains to tuples
        detected = set()
        for chain in detected_chains:
            path = tuple([v.name for v in chain.vulnerabilities])
            detected.add(path)

        # Calculate metrics
        true_positives = len(self.expected_chains & detected)
        false_positives = len(detected - self.expected_chains)
        false_negatives = len(self.expected_chains - detected)

        # Precision: Of all detected chains, how many are correct?
        precision = true_positives / len(detected) if detected else 0.0

        # Recall: Of all expected chains, how many were detected?
        recall = true_positives / len(self.expected_chains) if self.expected_chains else 0.0

        # F1 Score: Harmonic mean of precision and recall
        f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        # Detection rate: Percentage of expected chains detected
        detection_rate = recall * 100

        return {
            'true_positives': true_positives,
            'false_positives': false_positives,
            'false_negatives': false_negatives,
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'detection_rate': detection_rate,
            'expected_chains': len(self.expected_chains),
            'detected_chains': len(detected),
            'correct_detections': list(self.expected_chains & detected),
            'missed_chains': list(self.expected_chains - detected),
            'false_detections': list(detected - self.expected_chains)
        }

    def print_report(self, metrics: Dict, analysis_time: float):
        """
        Print formatted benchmark report.

        Args:
            metrics: Evaluation metrics dictionary
            analysis_time: Time taken for analysis
        """
        print("=" * 80)
        print("🎯 DVWA VULNERABILITY CHAIN DETECTION BENCHMARK")
        print("=" * 80)
        print()

        print(f"Dataset: {self.ground_truth['dataset']}")
        print(f"Ground Truth Version: {self.ground_truth['version']}")
        print(f"Scan File: {self.ground_truth['scan_file']}")
        print(f"Analysis Time: {analysis_time:.3f}s")
        print()

        print("-" * 80)
        print("📊 DETECTION METRICS")
        print("-" * 80)
        print(f"Expected Chains:    {metrics['expected_chains']}")
        print(f"Detected Chains:    {metrics['detected_chains']}")
        print(f"True Positives:     {metrics['true_positives']}")
        print(f"False Positives:    {metrics['false_positives']}")
        print(f"False Negatives:    {metrics['false_negatives']}")
        print()

        print("-" * 80)
        print("📈 PERFORMANCE METRICS")
        print("-" * 80)
        print(f"Detection Rate:     {metrics['detection_rate']:.1f}%")
        print(f"Precision:          {metrics['precision']:.3f} ({metrics['precision']*100:.1f}%)")
        print(f"Recall:             {metrics['recall']:.3f} ({metrics['recall']*100:.1f}%)")
        print(f"F1 Score:           {metrics['f1_score']:.3f}")
        print()

        if metrics['correct_detections']:
            print("-" * 80)
            print("✅ CORRECTLY DETECTED CHAINS")
            print("-" * 80)
            for i, chain in enumerate(metrics['correct_detections'], 1):
                print(f"{i}. {' → '.join(chain)}")
            print()

        if metrics['missed_chains']:
            print("-" * 80)
            print("❌ MISSED CHAINS (False Negatives)")
            print("-" * 80)
            for i, chain in enumerate(metrics['missed_chains'], 1):
                print(f"{i}. {' → '.join(chain)}")
            print()

        if metrics['false_detections']:
            print("-" * 80)
            print("⚠️  FALSE DETECTIONS (False Positives)")
            print("-" * 80)
            for i, chain in enumerate(metrics['false_detections'], 1):
                print(f"{i}. {' → '.join(chain)}")
            print()

        print("=" * 80)

        # Overall assessment
        if metrics['f1_score'] >= 0.9:
            print("🏆 EXCELLENT: High-quality chain detection!")
        elif metrics['f1_score'] >= 0.7:
            print("✅ GOOD: Reliable chain detection performance")
        elif metrics['f1_score'] >= 0.5:
            print("⚠️  MODERATE: Chain detection needs improvement")
        else:
            print("❌ POOR: Significant improvement needed")

        print("=" * 80)


def main():
    """Run DVWA benchmark."""
    print("\n🚀 Starting DVWA Vulnerability Chain Detection Benchmark...\n")

    # Paths
    scan_file = 'benchmarks/dvwa_scan_synthetic.json'
    ground_truth_file = 'benchmarks/ground_truth/dvwa_chains.json'
    report_file = 'benchmarks/dvwa_result.html'

    # Initialize analyzer
    print("📊 Initializing Vulnerability Chain Analyzer...")
    analyzer = VulnerabilityChainAnalyzer()

    # Run chain detection
    print(f"🔍 Analyzing ZAP scan: {scan_file}")
    result = analyzer.analyze_zap_report(
        report_file=scan_file,
        max_chain_length=5,
        min_confidence=0.5,
        min_risk_filter='Low'
    )

    print(f"✅ Analysis complete: {result.total_chains} chains detected\n")

    # Generate HTML report
    print(f"📝 Generating HTML report: {report_file}")
    analyzer.generate_report(result, output_file=report_file, format='html')
    print(f"✅ Report saved\n")

    # Load benchmark and evaluate
    print(f"📋 Loading ground truth: {ground_truth_file}")
    benchmark = ChainBenchmark(ground_truth_file)

    print("🔬 Evaluating detection results...")
    metrics = benchmark.evaluate(result.chains)

    # Print benchmark report
    print()
    benchmark.print_report(metrics, result.analysis_time)

    # Save metrics to JSON
    metrics_file = 'benchmarks/dvwa_metrics.json'
    metrics_output = {
        'timestamp': datetime.now().isoformat(),
        'dataset': 'DVWA',
        'scan_file': scan_file,
        'ground_truth_file': ground_truth_file,
        'analysis_time': result.analysis_time,
        'total_vulnerabilities': result.total_vulnerabilities,
        'metrics': {
            'expected_chains': metrics['expected_chains'],
            'detected_chains': metrics['detected_chains'],
            'true_positives': metrics['true_positives'],
            'false_positives': metrics['false_positives'],
            'false_negatives': metrics['false_negatives'],
            'detection_rate': metrics['detection_rate'],
            'precision': metrics['precision'],
            'recall': metrics['recall'],
            'f1_score': metrics['f1_score']
        },
        'correct_detections': [' → '.join(c) for c in metrics['correct_detections']],
        'missed_chains': [' → '.join(c) for c in metrics['missed_chains']],
        'false_detections': [' → '.join(c) for c in metrics['false_detections']]
    }

    with open(metrics_file, 'w') as f:
        json.dump(metrics_output, f, indent=2)

    print(f"\n💾 Metrics saved to: {metrics_file}\n")

    return metrics['f1_score']


if __name__ == '__main__':
    f1_score = main()

    # Exit with code based on F1 score
    if f1_score >= 0.9:
        sys.exit(0)  # Excellent
    elif f1_score >= 0.7:
        sys.exit(0)  # Good
    else:
        sys.exit(1)  # Needs improvement
