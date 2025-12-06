#!/usr/bin/env python3
"""
ZAP Scanner for DVWA

This script runs an automated OWASP ZAP scan against DVWA
and saves the results in ZAP JSON format.
"""

import time
import json
import sys
import argparse
from pathlib import Path

try:
    from zapv2 import ZAPv2
except ImportError:
    print("ERROR: python-owasp-zap-v2.4 not installed")
    print("Run: pip install python-owasp-zap-v2.4")
    sys.exit(1)


class ZAPScanner:
    """OWASP ZAP Scanner wrapper."""

    def __init__(self, api_key='changeme', zap_host='localhost', zap_port=8090):
        """
        Initialize ZAP scanner.

        Args:
            api_key: ZAP API key
            zap_host: ZAP host address
            zap_port: ZAP API port
        """
        self.zap = ZAPv2(
            apikey=api_key,
            proxies={
                'http': f'http://{zap_host}:{zap_port}',
                'https': f'http://{zap_host}:{zap_port}'
            }
        )
        self.api_key = api_key

    def check_connection(self):
        """Check if ZAP is running and accessible."""
        try:
            version = self.zap.core.version
            print(f"✓ Connected to ZAP version: {version}")
            return True
        except Exception as e:
            print(f"✗ Cannot connect to ZAP: {e}")
            return False

    def spider_scan(self, target, max_duration=10):
        """
        Run spider scan.

        Args:
            target: Target URL to scan
            max_duration: Maximum duration in minutes

        Returns:
            Number of URLs found
        """
        print(f"\n🕷️  Starting Spider scan on {target}")
        scan_id = self.zap.spider.scan(target)

        start_time = time.time()
        max_time = max_duration * 60

        while int(self.zap.spider.status(scan_id)) < 100:
            if time.time() - start_time > max_time:
                self.zap.spider.stop(scan_id)
                print(f"\n⚠️  Spider scan stopped after {max_duration} minutes")
                break

            progress = self.zap.spider.status(scan_id)
            urls_found = len(self.zap.spider.results(scan_id))
            print(f"\r  Progress: {progress}% | URLs found: {urls_found}", end='')
            time.sleep(2)

        urls_found = len(self.zap.spider.results(scan_id))
        print(f"\n✓ Spider scan complete | Total URLs: {urls_found}")
        return urls_found

    def active_scan(self, target, max_duration=30):
        """
        Run active scan.

        Args:
            target: Target URL to scan
            max_duration: Maximum duration in minutes

        Returns:
            Number of alerts found
        """
        print(f"\n🔍 Starting Active scan on {target}")
        scan_id = self.zap.ascan.scan(target)

        start_time = time.time()
        max_time = max_duration * 60

        while int(self.zap.ascan.status(scan_id)) < 100:
            if time.time() - start_time > max_time:
                self.zap.ascan.stop(scan_id)
                print(f"\n⚠️  Active scan stopped after {max_duration} minutes")
                break

            progress = self.zap.ascan.status(scan_id)
            alerts = len(self.zap.core.alerts())
            print(f"\r  Progress: {progress}% | Alerts: {alerts}", end='')
            time.sleep(5)

        alerts = len(self.zap.core.alerts())
        print(f"\n✓ Active scan complete | Total alerts: {alerts}")
        return alerts

    def get_alerts(self, baseurl=None):
        """
        Get all alerts from ZAP.

        Args:
            baseurl: Filter alerts by base URL (optional)

        Returns:
            List of alerts
        """
        if baseurl:
            return self.zap.core.alerts(baseurl=baseurl)
        return self.zap.core.alerts()

    def save_results(self, output_file, baseurl=None):
        """
        Save scan results to JSON file.

        Args:
            output_file: Path to output file
            baseurl: Filter alerts by base URL (optional)
        """
        print(f"\n💾 Saving results to {output_file}")
        alerts = self.get_alerts(baseurl)

        # Create output directory if needed
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)

        # Save to JSON
        with open(output_file, 'w') as f:
            json.dump(alerts, f, indent=2)

        print(f"✓ Saved {len(alerts)} alerts")


def main():
    """Run DVWA scan."""
    parser = argparse.ArgumentParser(
        description='Run OWASP ZAP scan against DVWA'
    )
    parser.add_argument(
        '--target',
        default='http://dvwa:80',
        help='Target URL (default: http://dvwa:80)'
    )
    parser.add_argument(
        '--output',
        default='scans/dvwa_scan.json',
        help='Output file (default: scans/dvwa_scan.json)'
    )
    parser.add_argument(
        '--api-key',
        default='changeme',
        help='ZAP API key (default: changeme)'
    )
    parser.add_argument(
        '--zap-host',
        default='localhost',
        help='ZAP host (default: localhost)'
    )
    parser.add_argument(
        '--zap-port',
        type=int,
        default=8090,
        help='ZAP port (default: 8090)'
    )
    parser.add_argument(
        '--spider-duration',
        type=int,
        default=10,
        help='Max spider duration in minutes (default: 10)'
    )
    parser.add_argument(
        '--scan-duration',
        type=int,
        default=30,
        help='Max active scan duration in minutes (default: 30)'
    )
    parser.add_argument(
        '--skip-spider',
        action='store_true',
        help='Skip spider scan'
    )
    parser.add_argument(
        '--skip-active',
        action='store_true',
        help='Skip active scan'
    )

    args = parser.parse_args()

    print("="*60)
    print("OWASP ZAP Scanner for DVWA")
    print("="*60)

    # Initialize scanner
    scanner = ZAPScanner(
        api_key=args.api_key,
        zap_host=args.zap_host,
        zap_port=args.zap_port
    )

    # Check connection
    if not scanner.check_connection():
        print("\n✗ Please ensure ZAP is running:")
        print("  docker-compose up -d zap")
        sys.exit(1)

    # Run scans
    if not args.skip_spider:
        scanner.spider_scan(args.target, max_duration=args.spider_duration)

    if not args.skip_active:
        scanner.active_scan(args.target, max_duration=args.scan_duration)

    # Save results
    scanner.save_results(args.output, baseurl=args.target)

    print("\n" + "="*60)
    print("Scan Complete!")
    print("="*60)
    print(f"Results saved to: {args.output}")
    print("\nNext step: Analyze with Vulnerability Chain Detection")
    print(f"  python3 benchmarks/analyze_results.py --input {args.output}")
    print()


if __name__ == '__main__':
    main()
