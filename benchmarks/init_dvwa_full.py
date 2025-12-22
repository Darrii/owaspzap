#!/usr/bin/env python3
"""
Complete DVWA Initialization Script

This script performs full DVWA initialization:
1. Checks if database is initialized
2. Extracts CSRF token from setup page
3. Creates database with CSRF protection
4. Logs in with default credentials
5. Sets security level to 'low'
6. Verifies everything is ready for testing

Usage:
    ./zapenv/bin/python3 benchmarks/init_dvwa_full.py
"""

import requests
import re
import sys
import time
from bs4 import BeautifulSoup

DVWA_URL = "http://localhost:8080"
USERNAME = "admin"
PASSWORD = "password"

def print_step(step_num, total_steps, message):
    """Print formatted step message."""
    print(f"\n[{step_num}/{total_steps}] {message}")

def print_result(success, message):
    """Print result with status indicator."""
    status = "✓" if success else "✗"
    print(f"    {status} {message}")

def wait_for_dvwa(max_retries=10):
    """Wait for DVWA to be accessible."""
    print("="*80)
    print("DVWA INITIALIZATION")
    print("="*80)

    print_step(1, 6, "Waiting for DVWA to be accessible...")

    for i in range(max_retries):
        try:
            response = requests.get(f"{DVWA_URL}/login.php", timeout=5, allow_redirects=False)
            if response.status_code in [200, 302]:
                print_result(True, "DVWA is accessible")
                return True
        except requests.exceptions.RequestException:
            if i < max_retries - 1:
                print(f"    Waiting... ({i+1}/{max_retries})")
                time.sleep(2)

    print_result(False, "Cannot connect to DVWA")
    return False

def check_and_initialize_database(session):
    """Check if database is initialized, and initialize if needed."""
    print_step(2, 6, "Checking database status...")

    try:
        # Check if redirected to setup.php
        response = session.get(f"{DVWA_URL}/login.php", allow_redirects=False)

        if response.status_code == 302 and 'setup.php' in response.headers.get('Location', ''):
            print_result(False, "Database not initialized - creating now...")

            # Get setup page to extract CSRF token
            setup_response = session.get(f"{DVWA_URL}/setup.php")

            # Extract CSRF token
            soup = BeautifulSoup(setup_response.text, 'html.parser')
            user_token_input = soup.find('input', {'name': 'user_token'})

            if not user_token_input or 'value' not in user_token_input.attrs:
                print_result(False, "Could not extract CSRF token from setup page")
                return False

            user_token = user_token_input['value']
            print(f"    ✓ CSRF token extracted: {user_token[:20]}...")

            # Create database with CSRF token
            db_response = session.post(f"{DVWA_URL}/setup.php", data={
                'create_db': 'Create / Reset Database',
                'user_token': user_token
            }, allow_redirects=True)

            # Check for success indicators
            success_indicators = [
                'setup successful',
                'database has been created',
                'created successfully',
                'setup has been completed',
                "'users' table"
            ]

            response_lower = db_response.text.lower()
            setup_successful = any(indicator in response_lower for indicator in success_indicators)

            if setup_successful:
                print_result(True, "Database created successfully")
                return True
            else:
                print_result(False, "Database creation failed or unclear")
                print("\n    Response preview (first 500 chars):")
                print(f"    {db_response.text[:500]}")
                return False
        else:
            print_result(True, "Database already initialized")
            return True

    except Exception as e:
        print_result(False, f"Error checking database: {e}")
        return False

def login_to_dvwa(session):
    """Login to DVWA with default credentials."""
    print_step(3, 6, "Logging in to DVWA...")

    try:
        # Get login page to extract CSRF token
        login_page = session.get(f"{DVWA_URL}/login.php")

        # Extract CSRF token
        csrf_match = re.search(r'name=["\']user_token["\'] value=["\'](.*?)["\']', login_page.text)

        if not csrf_match:
            print_result(False, "Could not extract CSRF token from login page")
            return False

        user_token = csrf_match.group(1)
        print(f"    ✓ CSRF token extracted: {user_token[:20]}...")

        # Perform login
        login_data = {
            'username': USERNAME,
            'password': PASSWORD,
            'Login': 'Login',
            'user_token': user_token
        }

        login_response = session.post(f"{DVWA_URL}/login.php", data=login_data, allow_redirects=True)

        # Check if login was successful (should redirect to index.php)
        if 'index.php' in login_response.url or 'Welcome to' in login_response.text:
            print_result(True, f"Login successful as '{USERNAME}'")
            return True
        else:
            print_result(False, "Login failed")
            return False

    except Exception as e:
        print_result(False, f"Error during login: {e}")
        return False

def set_security_level(session, level='low'):
    """Set DVWA security level."""
    print_step(4, 6, f"Setting security level to '{level}'...")

    try:
        # Set security level
        security_response = session.post(f"{DVWA_URL}/security.php", data={
            'security': level,
            'seclev_submit': 'Submit'
        }, allow_redirects=True)

        # Verify security level was set
        if 'security' in session.cookies.get_dict():
            actual_level = session.cookies.get('security')
            if actual_level == level:
                print_result(True, f"Security level set to '{level}'")
                return True
            else:
                print_result(False, f"Security level is '{actual_level}' (expected '{level}')")
                return False
        else:
            print_result(False, "Security cookie not found")
            return False

    except Exception as e:
        print_result(False, f"Error setting security level: {e}")
        return False

def verify_ready(session):
    """Verify DVWA is ready for testing."""
    print_step(5, 6, "Verifying DVWA is ready for testing...")

    try:
        # Try to access a vulnerability page
        response = session.get(f"{DVWA_URL}/vulnerabilities/xss_r/")

        if response.status_code == 200 and 'dvwa' in response.text.lower():
            print_result(True, "XSS page accessible")

            # Check security headers
            has_csp = 'Content-Security-Policy' in response.headers
            has_xframe = 'X-Frame-Options' in response.headers

            print(f"    - CSP Header: {'Present' if has_csp else 'Missing (vulnerable)'}")
            print(f"    - X-Frame-Options: {'Present' if has_xframe else 'Missing (vulnerable)'}")

            return True
        else:
            print_result(False, "Cannot access vulnerability pages")
            return False

    except Exception as e:
        print_result(False, f"Error verifying: {e}")
        return False

def main():
    """Run full DVWA initialization."""

    # Step 1: Wait for DVWA
    if not wait_for_dvwa():
        sys.exit(1)

    # Create session
    session = requests.Session()

    # Step 2: Check and initialize database
    if not check_and_initialize_database(session):
        sys.exit(1)

    # Step 3: Login
    if not login_to_dvwa(session):
        sys.exit(1)

    # Step 4: Set security level
    if not set_security_level(session, 'low'):
        sys.exit(1)

    # Step 5: Verify ready
    if not verify_ready(session):
        sys.exit(1)

    # Step 6: Success
    print_step(6, 6, "Initialization complete!")
    print("\n" + "="*80)
    print("DVWA IS READY FOR TESTING")
    print("="*80)
    print(f"\nURL: {DVWA_URL}")
    print(f"Username: {USERNAME}")
    print(f"Password: {PASSWORD}")
    print(f"Security Level: low")
    print("\nYou can now run vulnerability chain tests:")
    print("  ./zapenv/bin/python3 manual_vuln_test_final.py")
    print("\n" + "="*80 + "\n")

    sys.exit(0)

if __name__ == "__main__":
    main()
