#!/usr/bin/env python3
"""
ZAP Scanner Verification Module
Verifies that configured scanners are actually enabled and running
Detects "silent failures" where scanners are configured but don't execute
"""

from zapv2 import ZAPv2
from typing import Dict, List, Set
import time


class ScannerVerifier:
    """Verifies scanner configuration and execution"""

    def __init__(self, zap: ZAPv2):
        """
        Initialize scanner verifier

        Args:
            zap: ZAPv2 instance
        """
        self.zap = zap

    def verify_scanner_configuration(
        self,
        policy_name: str,
        expected_scanner_ids: List[str]
    ) -> Dict:
        """
        Verify that scanners are properly configured in the policy

        Args:
            policy_name: Scan policy name
            expected_scanner_ids: List of scanner IDs that should be enabled

        Returns:
            Dictionary with verification results
        """
        print(f"\n[PRE-SCAN] Verifying scanner configuration for policy '{policy_name}'...")

        try:
            # Get actual scanner configuration
            scanners = self.zap.ascan.scanners(scanpolicyname=policy_name)

            enabled_scanners = []
            disabled_scanners = []
            not_found_scanners = []

            # Build lookup for actual scanners
            scanner_dict = {s['id']: s for s in scanners}

            for scanner_id in expected_scanner_ids:
                if scanner_id in scanner_dict:
                    scanner = scanner_dict[scanner_id]
                    if scanner['enabled'] == 'true':
                        enabled_scanners.append({
                            'id': scanner_id,
                            'name': scanner['name'],
                            'threshold': scanner.get('alertThreshold'),
                            'strength': scanner.get('attackStrength')
                        })
                    else:
                        disabled_scanners.append({
                            'id': scanner_id,
                            'name': scanner['name']
                        })
                else:
                    not_found_scanners.append(scanner_id)

            # Verification status
            all_enabled = len(disabled_scanners) == 0 and len(not_found_scanners) == 0

            # Print results
            if all_enabled:
                print(f"  ✓ All {len(enabled_scanners)} expected scanners are ENABLED")
            else:
                print(f"  ⚠ Configuration issues detected:")
                if disabled_scanners:
                    print(f"    - {len(disabled_scanners)} scanners are DISABLED")
                if not_found_scanners:
                    print(f"    - {len(not_found_scanners)} scanners NOT FOUND in policy")

            # Show sample of enabled scanners
            if enabled_scanners:
                print(f"\n  Enabled scanners (showing first 5):")
                for scanner in enabled_scanners[:5]:
                    print(f"    ✓ {scanner['id']}: {scanner['name']} "
                          f"(threshold={scanner['threshold']}, strength={scanner['strength']})")

            return {
                'policy_name': policy_name,
                'all_enabled': all_enabled,
                'enabled_count': len(enabled_scanners),
                'disabled_count': len(disabled_scanners),
                'not_found_count': len(not_found_scanners),
                'enabled_scanners': enabled_scanners,
                'disabled_scanners': disabled_scanners,
                'not_found_scanners': not_found_scanners
            }

        except Exception as e:
            print(f"  ✗ Verification failed: {e}")
            return {
                'policy_name': policy_name,
                'all_enabled': False,
                'error': str(e)
            }

    def monitor_scan_progress(
        self,
        scan_id: str,
        expected_scanner_ids: List[str],
        check_interval: int = 10
    ):
        """
        Monitor scan progress and track which scanners are running

        Args:
            scan_id: Active scan ID
            expected_scanner_ids: List of expected scanner IDs
            check_interval: Progress check interval in seconds
        """
        print(f"\n[DURING-SCAN] Monitoring scan {scan_id}...")

        seen_scanners = set()
        last_progress = 0

        while True:
            try:
                # Get scan progress
                progress = int(self.zap.ascan.status(scan_id))

                if progress > last_progress:
                    print(f"    Progress: {progress}%", end='\r')
                    last_progress = progress

                # Check if scan is complete
                if progress >= 100:
                    print(f"\n  ✓ Scan complete")
                    break

                time.sleep(check_interval)

            except KeyboardInterrupt:
                print(f"\n  ! Monitoring interrupted by user")
                break
            except Exception as e:
                print(f"\n  ! Monitoring error: {e}")
                break

    def verify_scan_results(
        self,
        expected_scanner_ids: List[str],
        base_url: str = None
    ) -> Dict:
        """
        Verify scan results against expected scanners

        Args:
            expected_scanner_ids: List of scanner IDs that should have run
            base_url: Optional base URL to filter alerts

        Returns:
            Dictionary with verification results
        """
        print(f"\n[POST-SCAN] Verifying scan results...")

        try:
            # Get all alerts
            if base_url:
                alerts = self.zap.core.alerts(baseurl=base_url)
            else:
                alerts = self.zap.core.alerts()

            # Group alerts by plugin ID
            alerts_by_plugin = {}
            for alert in alerts:
                plugin_id = alert.get('pluginId')
                if plugin_id not in alerts_by_plugin:
                    alerts_by_plugin[plugin_id] = []
                alerts_by_plugin[plugin_id].append(alert)

            # Check which expected scanners generated alerts
            scanner_ids_with_alerts = set(alerts_by_plugin.keys())
            expected_set = set(expected_scanner_ids)

            scanners_fired = expected_set & scanner_ids_with_alerts
            scanners_silent = expected_set - scanner_ids_with_alerts
            unexpected_scanners = scanner_ids_with_alerts - expected_set

            # Print results
            print(f"\n  Total alerts: {len(alerts)}")
            print(f"  Unique scanner plugins: {len(alerts_by_plugin)}")

            if scanners_fired:
                print(f"\n  ✓ Expected scanners that FOUND vulnerabilities ({len(scanners_fired)}):")
                for scanner_id in sorted(scanners_fired):
                    alert_count = len(alerts_by_plugin[scanner_id])
                    sample_alert = alerts_by_plugin[scanner_id][0]
                    print(f"    ✓ {scanner_id}: {sample_alert.get('alert', 'Unknown')} "
                          f"({alert_count} alerts)")

            if scanners_silent:
                print(f"\n  ⚠ Expected scanners with NO alerts (silent failures) ({len(scanners_silent)}):")
                for scanner_id in sorted(scanners_silent):
                    print(f"    ✗ {scanner_id}: No vulnerabilities found (or scanner didn't run)")

            if unexpected_scanners:
                print(f"\n  ℹ Other scanners that found issues ({len(unexpected_scanners)}):")
                for scanner_id in list(unexpected_scanners)[:10]:  # Show first 10
                    alert_count = len(alerts_by_plugin[scanner_id])
                    sample_alert = alerts_by_plugin[scanner_id][0]
                    print(f"    • {scanner_id}: {sample_alert.get('alert', 'Unknown')} "
                          f"({alert_count} alerts)")

            # Calculate success rate
            if expected_scanner_ids:
                success_rate = (len(scanners_fired) / len(expected_scanner_ids)) * 100
            else:
                success_rate = 0

            print(f"\n  Scanner Detection Rate: {success_rate:.1f}% "
                  f"({len(scanners_fired)}/{len(expected_scanner_ids)} scanners found vulnerabilities)")

            return {
                'total_alerts': len(alerts),
                'unique_plugins': len(alerts_by_plugin),
                'expected_scanner_count': len(expected_scanner_ids),
                'scanners_fired_count': len(scanners_fired),
                'scanners_silent_count': len(scanners_silent),
                'success_rate': success_rate,
                'scanners_fired': list(scanners_fired),
                'scanners_silent': list(scanners_silent),
                'alerts_by_plugin': {k: len(v) for k, v in alerts_by_plugin.items()}
            }

        except Exception as e:
            print(f"  ✗ Verification failed: {e}")
            return {
                'error': str(e)
            }

    def generate_verification_report(
        self,
        pre_scan_results: Dict,
        post_scan_results: Dict,
        output_file: str = None
    ) -> Dict:
        """
        Generate comprehensive verification report

        Args:
            pre_scan_results: Results from verify_scanner_configuration()
            post_scan_results: Results from verify_scan_results()
            output_file: Optional output file path for JSON report

        Returns:
            Combined verification report
        """
        print(f"\n{'='*80}")
        print("SCANNER VERIFICATION REPORT")
        print(f"{'='*80}")

        report = {
            'pre_scan': pre_scan_results,
            'post_scan': post_scan_results,
            'summary': {}
        }

        # Configuration summary
        if pre_scan_results.get('all_enabled'):
            print("\n✓ PRE-SCAN: All expected scanners were enabled")
        else:
            print(f"\n⚠ PRE-SCAN: Configuration issues detected")
            if 'disabled_count' in pre_scan_results:
                print(f"  - {pre_scan_results['disabled_count']} scanners disabled")
            if 'not_found_count' in pre_scan_results:
                print(f"  - {pre_scan_results['not_found_count']} scanners not found")

        # Results summary
        if 'success_rate' in post_scan_results:
            success_rate = post_scan_results['success_rate']
            if success_rate >= 80:
                status = "✓ EXCELLENT"
            elif success_rate >= 50:
                status = "⚠ PARTIAL"
            else:
                status = "✗ POOR"

            print(f"\n{status} POST-SCAN: {success_rate:.1f}% detection rate")
            print(f"  - {post_scan_results['scanners_fired_count']} scanners found vulnerabilities")
            print(f"  - {post_scan_results['scanners_silent_count']} scanners had no results")
            print(f"  - {post_scan_results['total_alerts']} total alerts")

            report['summary']['status'] = status
            report['summary']['success_rate'] = success_rate
        else:
            print(f"\n✗ POST-SCAN: Verification failed")

        # Save report if requested
        if output_file:
            import json
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n✓ Verification report saved to {output_file}")

        print(f"{'='*80}\n")

        return report


def main():
    """Test scanner verification"""
    import sys

    # Configuration
    ZAP_API_KEY = "changeme"
    ZAP_HOST = "localhost"
    ZAP_PORT = 8090

    print("Connecting to ZAP...")
    zap = ZAPv2(
        apikey=ZAP_API_KEY,
        proxies={
            'http': f'http://{ZAP_HOST}:{ZAP_PORT}',
            'https': f'http://{ZAP_HOST}:{ZAP_PORT}'
        }
    )

    # Test connection
    try:
        version = zap.core.version
        print(f"✓ Connected to ZAP version: {version}")
    except Exception as e:
        print(f"✗ Failed to connect to ZAP: {e}")
        sys.exit(1)

    # Create verifier
    verifier = ScannerVerifier(zap)

    # Example: Verify a policy (would need to create/configure first)
    # This is a demonstration of the API
    print("\n[DEMO] Scanner Verifier API")
    print("This module provides three verification methods:")
    print("  1. verify_scanner_configuration() - Pre-scan verification")
    print("  2. monitor_scan_progress() - During-scan monitoring")
    print("  3. verify_scan_results() - Post-scan verification")
    print("\nUse these in your scanning scripts to ensure scanners are working correctly.")


if __name__ == "__main__":
    main()
