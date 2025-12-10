#!/usr/bin/env python3
"""
Scan Validation Framework
Validates that vulnerabilities exist and were detected by scanners
Provides baseline expectations and pass/fail metrics
"""

import requests
from bs4 import BeautifulSoup
import re
import json
from typing import Dict, List


# Expected detection baselines
EXPECTED_DETECTIONS = {
    'dvwa_security_low': {
        'SQL Injection': {'min': 1, 'max': 15, 'critical': True},
        'Cross Site Scripting': {'min': 2, 'max': 20, 'critical': True},
        'Command Injection': {'min': 1, 'max': 8, 'critical': True},
        'Path Traversal': {'min': 1, 'max': 8, 'critical': False},
        'File Inclusion': {'min': 1, 'max': 8, 'critical': False},
        'CSRF': {'min': 1, 'max': 10, 'critical': False}
    },
    'juiceshop': {
        'SQL Injection': {'min': 3, 'max': 25, 'critical': True},
        'Cross Site Scripting': {'min': 5, 'max': 30, 'critical': True},
        'Authentication': {'min': 2, 'max': 15, 'critical': True},
        'Broken Access Control': {'min': 3, 'max': 20, 'critical': True}
    }
}


class ScanValidator:
    """Validates scan results and vulnerability existence"""

    def __init__(self, dvwa_url: str = "http://localhost:8080"):
        """
        Initialize scan validator

        Args:
            dvwa_url: DVWA base URL
        """
        self.dvwa_url = dvwa_url
        self.session = requests.Session()

    def authenticate_dvwa(self) -> bool:
        """
        Authenticate to DVWA with CSRF token

        Returns:
            True if authentication successful
        """
        try:
            # Get login page
            response = self.session.get(f"{self.dvwa_url}/login.php")
            soup = BeautifulSoup(response.text, 'html.parser')
            user_token_input = soup.find('input', {'name': 'user_token'})

            login_data = {
                'username': 'admin',
                'password': 'password',
                'Login': 'Login'
            }

            if user_token_input and user_token_input.get('value'):
                login_data['user_token'] = user_token_input['value']

            # Login
            response = self.session.post(f"{self.dvwa_url}/login.php", data=login_data, allow_redirects=True)

            # Verify authentication
            response = self.session.get(f"{self.dvwa_url}/index.php")
            return 'logout.php' in response.text

        except Exception as e:
            print(f"  ✗ Authentication failed: {e}")
            return False

    def set_security_low(self) -> bool:
        """
        Set DVWA security level to low

        Returns:
            True if successful
        """
        try:
            # Get security page for CSRF token
            response = self.session.get(f"{self.dvwa_url}/security.php")
            soup = BeautifulSoup(response.text, 'html.parser')
            security_token_input = soup.find('input', {'name': 'user_token'})

            security_data = {
                'security': 'low',
                'seclev_submit': 'Submit'
            }

            if security_token_input and security_token_input.get('value'):
                security_data['user_token'] = security_token_input['value']

            # Set security
            self.session.post(f"{self.dvwa_url}/security.php", data=security_data)
            return True

        except Exception as e:
            print(f"  ✗ Failed to set security level: {e}")
            return False

    def test_sql_injection(self) -> Dict:
        """
        Test for SQL injection vulnerability

        Returns:
            Test results dictionary
        """
        print("\n  Testing SQL Injection...")

        payloads = [
            ("1' OR '1'='1", "Should return multiple users"),
            ("1' UNION SELECT user,password FROM users--", "Should extract credentials"),
        ]

        results = []

        for payload, description in payloads:
            try:
                response = self.session.get(
                    f"{self.dvwa_url}/vulnerabilities/sqli/",
                    params={'id': payload, 'Submit': 'Submit'}
                )

                # Check for multiple user rows
                user_rows = response.text.count('Surname')

                vulnerable = user_rows > 1 or 'admin' in response.text.lower()

                results.append({
                    'payload': payload,
                    'description': description,
                    'vulnerable': vulnerable,
                    'user_rows_found': user_rows
                })

                if vulnerable:
                    print(f"    ✓ {description}: VULNERABLE")
                else:
                    print(f"    ✗ {description}: Not detected")

            except Exception as e:
                results.append({
                    'payload': payload,
                    'description': description,
                    'error': str(e)
                })

        return {
            'vulnerability_type': 'SQL Injection',
            'exists': any(r.get('vulnerable', False) for r in results),
            'tests': results
        }

    def test_xss_reflected(self) -> Dict:
        """
        Test for reflected XSS vulnerability

        Returns:
            Test results dictionary
        """
        print("\n  Testing Reflected XSS...")

        payloads = [
            ("<script>alert(1)</script>", "Basic script tag"),
            ("<img src=x onerror=alert(1)>", "Image event handler"),
        ]

        results = []

        for payload, description in payloads:
            try:
                response = self.session.get(
                    f"{self.dvwa_url}/vulnerabilities/xss_r/",
                    params={'name': payload}
                )

                # Check if payload is reflected unencoded
                vulnerable = payload in response.text

                results.append({
                    'payload': payload,
                    'description': description,
                    'vulnerable': vulnerable
                })

                if vulnerable:
                    print(f"    ✓ {description}: VULNERABLE")
                else:
                    print(f"    ✗ {description}: Not detected")

            except Exception as e:
                results.append({
                    'payload': payload,
                    'description': description,
                    'error': str(e)
                })

        return {
            'vulnerability_type': 'Cross Site Scripting (Reflected)',
            'exists': any(r.get('vulnerable', False) for r in results),
            'tests': results
        }

    def test_command_injection(self) -> Dict:
        """
        Test for command injection vulnerability

        Returns:
            Test results dictionary
        """
        print("\n  Testing Command Injection...")

        payloads = [
            ("127.0.0.1; whoami", "Execute whoami command"),
            ("127.0.0.1 && id", "Execute id command"),
        ]

        results = []

        for payload, description in payloads:
            try:
                response = self.session.get(
                    f"{self.dvwa_url}/vulnerabilities/exec/",
                    params={'ip': payload, 'Submit': 'Submit'}
                )

                # Check for command output
                vulnerable = bool(re.search(r'www-data|root|uid=', response.text))

                results.append({
                    'payload': payload,
                    'description': description,
                    'vulnerable': vulnerable
                })

                if vulnerable:
                    print(f"    ✓ {description}: VULNERABLE")
                else:
                    print(f"    ✗ {description}: Not detected")

            except Exception as e:
                results.append({
                    'payload': payload,
                    'description': description,
                    'error': str(e)
                })

        return {
            'vulnerability_type': 'Command Injection',
            'exists': any(r.get('vulnerable', False) for r in results),
            'tests': results
        }

    def validate_dvwa_vulnerabilities(self) -> Dict:
        """
        Validate that DVWA vulnerabilities exist

        Returns:
            Validation results dictionary
        """
        print("="*80)
        print("MANUAL VULNERABILITY VALIDATION")
        print("="*80)

        # Authenticate
        print("\n[1/4] Authenticating to DVWA...")
        if not self.authenticate_dvwa():
            return {'error': 'Authentication failed'}

        print("  ✓ Authenticated successfully")

        # Set security to low
        print("\n[2/4] Setting security level to LOW...")
        self.set_security_low()

        # Test vulnerabilities
        print("\n[3/4] Testing for vulnerabilities...")
        sql_results = self.test_sql_injection()
        xss_results = self.test_xss_reflected()
        cmd_results = self.test_command_injection()

        # Summary
        print("\n[4/4] Validation Summary...")
        vulnerabilities_exist = []
        if sql_results['exists']:
            vulnerabilities_exist.append('SQL Injection')
            print("  ✓ SQL Injection: CONFIRMED")
        else:
            print("  ✗ SQL Injection: NOT FOUND")

        if xss_results['exists']:
            vulnerabilities_exist.append('XSS')
            print("  ✓ Cross-Site Scripting: CONFIRMED")
        else:
            print("  ✗ Cross-Site Scripting: NOT FOUND")

        if cmd_results['exists']:
            vulnerabilities_exist.append('Command Injection')
            print("  ✓ Command Injection: CONFIRMED")
        else:
            print("  ✗ Command Injection: NOT FOUND")

        print(f"\n✓ Validated {len(vulnerabilities_exist)}/3 critical vulnerabilities exist")
        print("="*80 + "\n")

        return {
            'sql_injection': sql_results,
            'xss_reflected': xss_results,
            'command_injection': cmd_results,
            'vulnerabilities_confirmed': vulnerabilities_exist,
            'total_confirmed': len(vulnerabilities_exist)
        }

    def validate_scan_results(self, scan_alerts: List[Dict], target_app: str = 'dvwa_security_low') -> Dict:
        """
        Validate scan results against expected baselines

        Args:
            scan_alerts: List of ZAP alert dictionaries
            target_app: Target application key (dvwa_security_low or juiceshop)

        Returns:
            Validation report dictionary
        """
        print("="*80)
        print("SCAN RESULTS VALIDATION")
        print("="*80)

        expected = EXPECTED_DETECTIONS.get(target_app, {})

        # Categorize alerts by type
        alerts_by_type = {}
        for alert in scan_alerts:
            alert_name = alert.get('alert', 'Unknown')

            # Map to expected categories
            for expected_type in expected.keys():
                if any(keyword in alert_name for keyword in expected_type.lower().split()):
                    if expected_type not in alerts_by_type:
                        alerts_by_type[expected_type] = []
                    alerts_by_type[expected_type].append(alert)
                    break

        # Validate against expectations
        report = {
            'target_app': target_app,
            'total_alerts': len(scan_alerts),
            'expected_types': len(expected),
            'detected_types': len(alerts_by_type),
            'details': {},
            'pass_count': 0,
            'fail_count': 0,
            'critical_pass': 0,
            'critical_fail': 0
        }

        print(f"\nTarget: {target_app}")
        print(f"Total Alerts: {len(scan_alerts)}\n")

        for vuln_type, expectations in expected.items():
            count = len(alerts_by_type.get(vuln_type, []))
            min_expected = expectations['min']
            max_expected = expectations['max']
            is_critical = expectations['critical']

            # Determine pass/fail
            if min_expected <= count <= max_expected:
                status = 'PASS'
                report['pass_count'] += 1
                if is_critical:
                    report['critical_pass'] += 1
                symbol = "✓"
            else:
                status = 'FAIL'
                report['fail_count'] += 1
                if is_critical:
                    report['critical_fail'] += 1
                symbol = "✗"

            criticality = " [CRITICAL]" if is_critical else ""
            print(f"  {symbol} {vuln_type}{criticality}")
            print(f"     Expected: {min_expected}-{max_expected} | Detected: {count} | Status: {status}")

            report['details'][vuln_type] = {
                'expected_range': f"{min_expected}-{max_expected}",
                'detected': count,
                'status': status,
                'critical': is_critical
            }

        # Overall assessment
        print(f"\n{'='*80}")
        if report['critical_fail'] == 0 and report['fail_count'] <= 2:
            overall = "✓ PASS"
        elif report['critical_fail'] == 0:
            overall = "⚠ PARTIAL PASS"
        else:
            overall = "✗ FAIL"

        print(f"\nOverall Assessment: {overall}")
        print(f"  Passed: {report['pass_count']}/{len(expected)}")
        print(f"  Failed: {report['fail_count']}/{len(expected)}")
        print(f"  Critical Passed: {report['critical_pass']}")
        print(f"  Critical Failed: {report['critical_fail']}")
        print(f"{'='*80}\n")

        report['overall_status'] = overall

        return report


def main():
    """Run validation tests"""
    import sys

    validator = ScanValidator()

    # Validate that vulnerabilities exist
    validation_results = validator.validate_dvwa_vulnerabilities()

    if validation_results.get('total_confirmed', 0) >= 2:
        print("\n✓ Validation PASSED: Vulnerabilities confirmed to exist")
        sys.exit(0)
    else:
        print("\n✗ Validation FAILED: Vulnerabilities not found")
        print("  Ensure DVWA database is initialized and security is set to LOW")
        sys.exit(1)


if __name__ == "__main__":
    main()
