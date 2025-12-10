#!/usr/bin/env python3
"""
ZAP Scanner Discovery Module
Dynamically discovers available scanner IDs from the current ZAP instance
Eliminates hardcoded plugin ID dependencies
"""

from zapv2 import ZAPv2
import json
from typing import Dict, List, Optional


class ScannerDiscovery:
    """Discovers and categorizes available ZAP scanners"""

    # Keywords for categorizing scanners by vulnerability type
    VULNERABILITY_KEYWORDS = {
        'sql_injection': ['sql', 'injection', 'sqlite', 'mysql', 'postgresql', 'oracle', 'mssql'],
        'xss': ['xss', 'cross site scripting', 'cross-site scripting', 'reflected', 'persistent', 'stored'],
        'command_injection': ['command injection', 'os command', 'remote command', 'shell injection'],
        'path_traversal': ['path traversal', 'directory traversal', 'file inclusion'],
        'file_inclusion': ['file inclusion', 'rfi', 'lfi', 'remote file', 'local file'],
        'code_injection': ['code injection', 'server side code', 'eval injection'],
        'xpath_injection': ['xpath', 'xml injection'],
        'ldap_injection': ['ldap'],
        'crlf_injection': ['crlf'],
        'xxe': ['xxe', 'xml external entity'],
    }

    def __init__(self, zap: ZAPv2, policy_name: Optional[str] = None):
        """
        Initialize scanner discovery

        Args:
            zap: ZAPv2 instance
            policy_name: Optional scan policy name (uses default if None)
        """
        self.zap = zap
        self.policy_name = policy_name
        self._scanners_cache = None

    def get_all_scanners(self, force_refresh: bool = False) -> List[Dict]:
        """
        Get all available scanners from ZAP

        Args:
            force_refresh: Force refresh cache

        Returns:
            List of scanner dictionaries with id, name, enabled status
        """
        if self._scanners_cache is None or force_refresh:
            try:
                if self.policy_name:
                    scanners = self.zap.ascan.scanners(scanpolicyname=self.policy_name)
                else:
                    scanners = self.zap.ascan.scanners()

                self._scanners_cache = scanners
            except Exception as e:
                print(f"! Error fetching scanners: {e}")
                return []

        return self._scanners_cache

    def categorize_scanners(self) -> Dict[str, List[Dict]]:
        """
        Categorize scanners by vulnerability type based on name/keywords

        Returns:
            Dictionary mapping vulnerability_type -> list of scanner dicts
        """
        all_scanners = self.get_all_scanners()
        categorized = {key: [] for key in self.VULNERABILITY_KEYWORDS.keys()}
        categorized['other'] = []

        for scanner in all_scanners:
            scanner_name = scanner.get('name', '').lower()
            scanner_id = scanner.get('id')

            # Try to categorize by keywords
            matched = False
            for vuln_type, keywords in self.VULNERABILITY_KEYWORDS.items():
                if any(keyword in scanner_name for keyword in keywords):
                    categorized[vuln_type].append({
                        'id': scanner_id,
                        'name': scanner.get('name', 'Unknown'),
                        'enabled': scanner.get('enabled'),
                        'alertThreshold': scanner.get('alertThreshold'),
                        'attackStrength': scanner.get('attackStrength')
                    })
                    matched = True
                    break

            if not matched:
                categorized['other'].append({
                    'id': scanner_id,
                    'name': scanner.get('name', 'Unknown'),
                    'enabled': scanner.get('enabled'),
                    'alertThreshold': scanner.get('alertThreshold'),
                    'attackStrength': scanner.get('attackStrength')
                })

        return categorized

    def get_injection_scanners(self) -> List[Dict]:
        """
        Get all injection-related scanners (SQL, XSS, Command, Code, etc.)

        Returns:
            List of injection scanner dictionaries
        """
        categorized = self.categorize_scanners()

        injection_types = [
            'sql_injection',
            'xss',
            'command_injection',
            'code_injection',
            'xpath_injection',
            'ldap_injection',
            'crlf_injection'
        ]

        injection_scanners = []
        for vuln_type in injection_types:
            injection_scanners.extend(categorized.get(vuln_type, []))

        return injection_scanners

    def get_scanner_ids_by_type(self, vuln_type: str) -> List[str]:
        """
        Get scanner IDs for a specific vulnerability type

        Args:
            vuln_type: Vulnerability type key (e.g., 'sql_injection', 'xss')

        Returns:
            List of scanner ID strings
        """
        categorized = self.categorize_scanners()
        scanners = categorized.get(vuln_type, [])
        return [s['id'] for s in scanners]

    def print_scanner_summary(self):
        """Print a summary of discovered scanners"""
        categorized = self.categorize_scanners()

        print("\n" + "="*80)
        print("ZAP SCANNER DISCOVERY SUMMARY")
        print("="*80)

        total_scanners = sum(len(scanners) for scanners in categorized.values())
        print(f"\nTotal Scanners Available: {total_scanners}")

        for vuln_type, scanners in categorized.items():
            if scanners:
                print(f"\n{vuln_type.upper().replace('_', ' ')} ({len(scanners)} scanners):")
                for scanner in scanners[:5]:  # Show first 5
                    enabled_str = "✓" if scanner['enabled'] == 'true' else "✗"
                    print(f"  {enabled_str} ID {scanner['id']}: {scanner['name']}")

                if len(scanners) > 5:
                    print(f"  ... and {len(scanners) - 5} more")

        print("\n" + "="*80)

    def save_to_json(self, output_file: str):
        """
        Save discovered scanners to JSON file

        Args:
            output_file: Output JSON file path
        """
        categorized = self.categorize_scanners()

        with open(output_file, 'w') as f:
            json.dump(categorized, f, indent=2)

        print(f"✓ Scanner discovery saved to {output_file}")


def main():
    """Test scanner discovery"""
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
        print("  Make sure ZAP is running on http://localhost:8090")
        sys.exit(1)

    # Discover scanners
    discovery = ScannerDiscovery(zap)
    discovery.print_scanner_summary()

    # Get injection scanners
    injection_scanners = discovery.get_injection_scanners()
    print(f"\n✓ Found {len(injection_scanners)} injection-related scanners")

    # Save to file
    discovery.save_to_json("scans/discovered_scanners.json")

    # Show specific types
    sql_ids = discovery.get_scanner_ids_by_type('sql_injection')
    xss_ids = discovery.get_scanner_ids_by_type('xss')
    cmd_ids = discovery.get_scanner_ids_by_type('command_injection')

    print(f"\nSQL Injection Scanner IDs: {sql_ids}")
    print(f"XSS Scanner IDs: {xss_ids}")
    print(f"Command Injection Scanner IDs: {cmd_ids}")


if __name__ == "__main__":
    main()
