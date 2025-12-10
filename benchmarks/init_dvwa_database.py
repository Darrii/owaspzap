#!/usr/bin/env python3
"""
Properly initialize DVWA database with CSRF token handling.
This script extracts the CSRF token from setup.php and creates the database tables.
"""
import requests
from bs4 import BeautifulSoup
import sys
import time

DVWA_URL = "http://localhost:8080"

print("="*80)
print("DVWA DATABASE INITIALIZATION")
print("="*80)

print("\n[1/4] Connecting to DVWA...")
session = requests.Session()

# Wait for DVWA to be ready
max_retries = 10
for i in range(max_retries):
    try:
        response = session.get(f"{DVWA_URL}/setup.php", timeout=5)
        if response.status_code == 200:
            print("✓ DVWA is accessible")
            break
    except requests.exceptions.RequestException:
        if i < max_retries - 1:
            print(f"  Waiting for DVWA... ({i+1}/{max_retries})")
            time.sleep(2)
        else:
            print("✗ Cannot connect to DVWA")
            sys.exit(1)

print("\n[2/4] Extracting CSRF token from setup page...")
response = session.get(f"{DVWA_URL}/setup.php")

# Parse HTML to find user_token
soup = BeautifulSoup(response.text, 'html.parser')
user_token_input = soup.find('input', {'name': 'user_token'})

if user_token_input and 'value' in user_token_input.attrs:
    user_token = user_token_input['value']
    print(f"✓ CSRF token extracted: {user_token[:20]}...")
else:
    print("✗ Could not extract CSRF token from setup page")
    print("\nSetup page content (first 500 chars):")
    print(response.text[:500])
    sys.exit(1)

print("\n[3/4] Creating database with CSRF token...")
response = session.post(f"{DVWA_URL}/setup.php", data={
    'create_db': 'Create / Reset Database',
    'user_token': user_token
}, allow_redirects=True)

# Check for success indicators
success_indicators = [
    'setup successful',
    'database has been created',
    'created successfully',
    'tables created',
    "'users' table",
    'setup has been completed'
]

response_lower = response.text.lower()
setup_successful = any(indicator in response_lower for indicator in success_indicators)

if setup_successful:
    print("✓ Database creation request successful")
else:
    print("! Database creation response unclear")
    print("\nResponse content (first 800 chars):")
    print(response.text[:800])

print("\n[4/4] Verifying DVWA is ready...")
response = session.get(f"{DVWA_URL}/login.php", allow_redirects=False)

# If it redirects to setup.php, database is not ready
if response.status_code == 302 and 'setup.php' in response.headers.get('Location', ''):
    print("✗ DVWA still redirecting to setup.php - database not initialized")
    sys.exit(1)
elif response.status_code == 200:
    print("✓ DVWA login page accessible (no redirect to setup)")
    print("\n" + "="*80)
    print("DATABASE INITIALIZATION COMPLETE")
    print("="*80)
    sys.exit(0)
else:
    print(f"! Unexpected response: {response.status_code}")
    sys.exit(1)
