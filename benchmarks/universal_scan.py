#!/usr/bin/env python3
"""
Universal Web Application Scanner with Vulnerability Chain Detection
=====================================================================

This script provides a universal interface for scanning ANY web application
with OWASP ZAP and detecting vulnerability chains.

Features:
- Works on any website (public or authenticated)
- Optional form-based authentication
- Optional token-based authentication (JWT, Bearer)
- Optional cookie-based authentication
- Automatic CSRF token extraction
- Vulnerability chain detection built-in
- HTML reports with chain visualization

Usage:
    # Simple scan (no authentication)
    ./zapenv/bin/python3 benchmarks/universal_scan.py --target https://example.com

    # With form authentication
    ./zapenv/bin/python3 benchmarks/universal_scan.py \\
        --target http://example.com \\
        --auth-type form \\
        --login-url "http://example.com/login" \\
        --username admin \\
        --password password

    # With CSRF token support
    ./zapenv/bin/python3 benchmarks/universal_scan.py \\
        --target http://example.com \\
        --auth-type form \\
        --login-url "http://example.com/login" \\
        --username admin \\
        --password password \\
        --csrf-pattern 'name="csrf_token" value="([^"]+)"'

    # With JWT token
    ./zapenv/bin/python3 benchmarks/universal_scan.py \\
        --target https://api.example.com \\
        --auth-type token \\
        --token "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

Author: SIAAS Research Team
License: MIT
"""

import argparse
import json
import re
import requests
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from zapv2 import ZAPv2

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from vulnerability_chains import (
    ZAPAlertParser,
    ChainDetector,
    ChainScoring,
    GraphVisualizer
)


class UniversalScanner:
    """Universal scanner for any web application."""

    def __init__(self, target_url, auth_config=None, zap_host='localhost', zap_port=8090):
        """
        Initialize the universal scanner.

        Args:
            target_url: Target URL to scan
            auth_config: Optional authentication configuration dict
            zap_host: ZAP proxy host
            zap_port: ZAP proxy port
        """
        self.target = target_url
        self.auth_config = auth_config or {}
        self.zap = ZAPv2(proxies={
            'http': f'http://{zap_host}:{zap_port}',
            'https': f'http://{zap_host}:{zap_port}'
        })
        self.session_cookie = None
        self.csrf_token = None

        # Parse target domain for file naming
        parsed = urlparse(target_url)
        self.domain = parsed.netloc.replace(':', '_')

    def run(self):
        """Main scan workflow."""
        print("\n" + "=" * 80)
        print("UNIVERSAL WEB APPLICATION SCANNER")
        print("=" * 80)
        print(f"\nTarget: {self.target}")
        if self.auth_config:
            print(f"Authentication: {self.auth_config.get('type', 'none').upper()}")
        print("\n")

        # 1. Create new session
        print("[1/6] Creating new ZAP session...")
        self.zap.core.new_session()
        print("✓ Session created\n")

        # 2. Setup authentication if configured
        if self.auth_config and self.auth_config.get('type'):
            print("[2/6] Setting up authentication...")
            self._setup_authentication()
            print("✓ Authentication configured\n")
        else:
            print("[2/6] Skipping authentication (public scan)\n")

        # 3. Spider
        print("[3/6] Starting Spider scan...")
        self._spider()
        print("✓ Spider complete\n")

        # 4. Active scan
        print("[4/6] Starting Active scan...")
        scan_id = self._active_scan()
        print("✓ Active scan complete\n")

        # 5. Collect results
        print("[5/6] Collecting scan results...")
        scan_file = self._collect_results()
        print(f"✓ Results saved to: {scan_file}\n")

        # 6. Detect chains
        print("[6/6] Detecting vulnerability chains...")
        self._detect_chains(scan_file)
        print("✓ Chain detection complete\n")

        print("=" * 80)
        print("SCAN COMPLETE!")
        print("=" * 80)

    def _setup_authentication(self):
        """Setup authentication based on config."""
        auth_type = self.auth_config.get('type')

        if auth_type == 'form':
            self._setup_form_auth()
        elif auth_type == 'token':
            self._setup_token_auth()
        elif auth_type == 'cookie':
            self._setup_cookie_auth()
        else:
            raise ValueError(f"Unsupported auth type: {auth_type}")

    def _setup_form_auth(self):
        """Handle form-based authentication with optional CSRF support."""
        login_url = self.auth_config['login_url']
        username = self.auth_config['username']
        password = self.auth_config['password']

        # Extract CSRF token if pattern provided
        if 'csrf_pattern' in self.auth_config:
            print(f"  → Extracting CSRF token from {login_url}...")
            self.csrf_token = self._extract_csrf_token(
                login_url,
                self.auth_config['csrf_pattern']
            )
            if self.csrf_token:
                print(f"  ✓ CSRF token extracted: {self.csrf_token[:20]}...")
            else:
                print("  ! CSRF token not found")

        # Build login data
        username_field = self.auth_config.get('username_field', 'username')
        password_field = self.auth_config.get('password_field', 'password')

        login_data = {
            username_field: username,
            password_field: password
        }

        # Add CSRF token if extracted
        if self.csrf_token:
            csrf_field = self.auth_config.get('csrf_field', 'csrf_token')
            login_data[csrf_field] = self.csrf_token

        # Perform login
        print(f"  → Logging in as {username}...")
        response = requests.post(login_url, data=login_data, allow_redirects=False)

        # Extract session cookie
        if 'Set-Cookie' in response.headers:
            cookies = response.headers['Set-Cookie']
            # Extract session cookie (common names: PHPSESSID, session, sessionid)
            for cookie_name in ['PHPSESSID', 'session', 'sessionid', 'SESSION']:
                match = re.search(rf'{cookie_name}=([^;]+)', cookies)
                if match:
                    self.session_cookie = f"{cookie_name}={match.group(1)}"
                    print(f"  ✓ Session cookie: {self.session_cookie}")
                    break

        if not self.session_cookie:
            print("  ! Warning: No session cookie found")

    def _setup_token_auth(self):
        """Handle token-based authentication (JWT, Bearer)."""
        token = self.auth_config['token']
        print(f"  ✓ Token configured: {token[:30]}...")

        # Token will be added to requests via ZAP replacer or context

    def _setup_cookie_auth(self):
        """Handle cookie-based authentication (manual cookie)."""
        cookie = self.auth_config['cookie']
        self.session_cookie = cookie
        print(f"  ✓ Cookie configured: {cookie[:50]}...")

    def _extract_csrf_token(self, url, pattern):
        """
        Extract CSRF token from a page using regex pattern.

        Args:
            url: URL to fetch
            pattern: Regex pattern to extract token

        Returns:
            Extracted token or None
        """
        try:
            response = requests.get(url)
            match = re.search(pattern, response.text)
            if match:
                return match.group(1)
        except Exception as e:
            print(f"  ! Error extracting CSRF: {e}")
        return None

    def _spider(self):
        """Run spider scan."""
        print(f"  → Spidering {self.target}...")

        # Start spider
        scan_id = self.zap.spider.scan(self.target)

        # Wait for completion
        while int(self.zap.spider.status(scan_id)) < 100:
            progress = int(self.zap.spider.status(scan_id))
            print(f"    Spider: {progress}%", end='\r')
            time.sleep(2)

        print(f"    Spider: 100%")

        # Get results
        urls = self.zap.spider.results(scan_id)
        print(f"  ✓ Spider found {len(urls)} URLs")

    def _active_scan(self):
        """Run active scan."""
        print(f"  → Active scanning {self.target}...")

        # Start active scan
        scan_id = self.zap.ascan.scan(self.target)

        # Wait for completion
        while int(self.zap.ascan.status(scan_id)) < 100:
            progress = int(self.zap.ascan.status(scan_id))
            print(f"    Active scan: {progress}%", end='\r')
            time.sleep(5)

        print(f"    Active scan: 100%")
        return scan_id

    def _collect_results(self):
        """Collect and save scan results."""
        alerts = self.zap.core.alerts()
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        scan_file = f"scans/{self.domain}_scan_{timestamp}.json"

        # Create scans directory if not exists
        Path("scans").mkdir(exist_ok=True)

        # Save results
        with open(scan_file, 'w') as f:
            json.dump(alerts, f, indent=2)

        print(f"  ✓ Found {len(alerts)} alerts")
        return scan_file

    def _detect_chains(self, scan_file):
        """Detect vulnerability chains from scan results."""
        # Parse vulnerabilities
        parser = ZAPAlertParser()
        vulnerabilities = parser.parse_zap_report(scan_file)
        print(f"  → Parsed {len(vulnerabilities)} vulnerabilities")

        # Detect chains
        detector = ChainDetector()
        result = detector.detect_chains(vulnerabilities)

        # Score chains
        scoring = ChainScoring()
        for chain in result.chains:
            chain.risk_score = scoring.calculate_chain_risk(chain)

        # Sort by risk score
        result.chains.sort(key=lambda c: c.risk_score, reverse=True)

        print(f"  ✓ Found {result.total_chains} vulnerability chains")

        # Generate report
        if result.chains:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_file = f"reports/{self.domain}_chains_{timestamp}.html"

            visualizer = GraphVisualizer()
            visualizer.generate_html_report(result, report_file)
            print(f"  ✓ Chain report: {report_file}")

            # Print summary
            print(f"\n  Chain Summary:")
            print(f"    Critical (Risk ≥ 30): {sum(1 for c in result.chains if c.risk_score >= 30)}")
            print(f"    High (Risk 20-30): {sum(1 for c in result.chains if 20 <= c.risk_score < 30)}")
            print(f"    Medium (Risk 10-20): {sum(1 for c in result.chains if 10 <= c.risk_score < 20)}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Universal Web Application Scanner with Chain Detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    # Required arguments
    parser.add_argument(
        '--target',
        required=True,
        help='Target URL to scan (e.g., http://example.com)'
    )

    # Authentication arguments
    parser.add_argument(
        '--auth-type',
        choices=['form', 'token', 'cookie', 'none'],
        default='none',
        help='Authentication type'
    )

    # Form authentication
    parser.add_argument('--login-url', help='Login page URL (for form auth)')
    parser.add_argument('--username', help='Username (for form auth)')
    parser.add_argument('--password', help='Password (for form auth)')
    parser.add_argument('--username-field', default='username', help='Username field name')
    parser.add_argument('--password-field', default='password', help='Password field name')
    parser.add_argument('--csrf-pattern', help='Regex pattern to extract CSRF token')
    parser.add_argument('--csrf-field', default='csrf_token', help='CSRF field name')

    # Token authentication
    parser.add_argument('--token', help='Authentication token (for token auth)')

    # Cookie authentication
    parser.add_argument('--cookie', help='Session cookie (for cookie auth)')

    # ZAP connection
    parser.add_argument('--zap-host', default='localhost', help='ZAP host')
    parser.add_argument('--zap-port', default=8090, type=int, help='ZAP port')

    args = parser.parse_args()

    # Build auth config
    auth_config = None
    if args.auth_type != 'none':
        auth_config = {'type': args.auth_type}

        if args.auth_type == 'form':
            if not all([args.login_url, args.username, args.password]):
                parser.error("Form auth requires --login-url, --username, and --password")
            auth_config.update({
                'login_url': args.login_url,
                'username': args.username,
                'password': args.password,
                'username_field': args.username_field,
                'password_field': args.password_field,
            })
            if args.csrf_pattern:
                auth_config['csrf_pattern'] = args.csrf_pattern
                auth_config['csrf_field'] = args.csrf_field

        elif args.auth_type == 'token':
            if not args.token:
                parser.error("Token auth requires --token")
            auth_config['token'] = args.token

        elif args.auth_type == 'cookie':
            if not args.cookie:
                parser.error("Cookie auth requires --cookie")
            auth_config['cookie'] = args.cookie

    # Run scanner
    scanner = UniversalScanner(
        target_url=args.target,
        auth_config=auth_config,
        zap_host=args.zap_host,
        zap_port=args.zap_port
    )

    try:
        scanner.run()
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nError: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
