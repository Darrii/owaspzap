#!/usr/bin/env python3
"""
ZAP scan with Replacer rule to force our authenticated PHPSESSID cookie.
"""

from zapv2 import ZAPv2
import json
import time
import sys

# Configuration
ZAP_API_KEY = "changeme"
ZAP_HOST = "localhost"
ZAP_PORT = "8090"
DVWA_URL = "http://dvwa:80"
SCAN_OUTPUT = "scans/dvwa_scan_with_replacer.json"

print("="*80)
print("ZAP SCAN WITH REPLACER RULE (FORCED COOKIE)")
print("="*80)

# Connect to ZAP
zap = ZAPv2(
    apikey=ZAP_API_KEY,
    proxies={
        'http': f'http://{ZAP_HOST}:{ZAP_PORT}',
        'https': f'http://{ZAP_HOST}:{ZAP_PORT}'
    }
)

print("\n[1/11] Creating new ZAP session...")
try:
    zap.core.new_session(name='dvwa_replacer', overwrite=True)
    print("✓ Session created")
except Exception as e:
    print(f"! Warning: {e}")

print("\n[2/11] Accessing DVWA and logging in via host with CSRF token...")
# Login via host with proper CSRF token extraction
import subprocess
import requests
from bs4 import BeautifulSoup

# Create session for CSRF token extraction
session = requests.Session()

try:
    # Step 1: GET login page to extract CSRF token
    print("  → Getting login page to extract CSRF token...")
    response = session.get('http://localhost:8080/login.php')

    soup = BeautifulSoup(response.text, 'html.parser')
    user_token_input = soup.find('input', {'name': 'user_token'})

    if user_token_input and user_token_input.get('value'):
        user_token = user_token_input['value']
        print(f"  ✓ Extracted CSRF token: {user_token[:20]}...")

        # Step 2: POST login with CSRF token
        login_data = {
            'username': 'admin',
            'password': 'password',
            'Login': 'Login',
            'user_token': user_token
        }
        response = session.post('http://localhost:8080/login.php', data=login_data, allow_redirects=True)

        # Extract PHPSESSID from session cookies
        phpsessid = session.cookies.get('PHPSESSID')

        if phpsessid:
            print(f"  ✓ Authenticated with CSRF token, got PHPSESSID: {phpsessid}")
        else:
            print("  ⚠ No PHPSESSID in response, trying without token...")
            raise Exception("No PHPSESSID")
    else:
        print("  ⚠ No CSRF token found, trying login without token...")
        raise Exception("No CSRF token")

except Exception as e:
    # Fallback: Try login without CSRF token (may work in some DVWA versions)
    print(f"  → Fallback: Logging in without CSRF token...")
    result = subprocess.run([
        'curl', '-s', '-c', '-',
        '-d', 'username=admin&password=password&Login=Login',
        'http://localhost:8080/login.php'
    ], capture_output=True, text=True)

    # Extract PHPSESSID from curl output
    phpsessid = None
    for line in result.stdout.split('\n'):
        if 'PHPSESSID' in line:
            parts = line.split()
            if len(parts) >= 7:
                phpsessid = parts[6]
                break

if not phpsessid:
    print("✗ Failed to get PHPSESSID from host login")
    sys.exit(1)

print(f"✓ Got authenticated PHPSESSID: {phpsessid}")

# Set security to low (extract CSRF token first)
try:
    response = session.get('http://localhost:8080/security.php')
    soup = BeautifulSoup(response.text, 'html.parser')
    security_token_input = soup.find('input', {'name': 'user_token'})

    if security_token_input and security_token_input.get('value'):
        security_token = security_token_input['value']
        security_data = {
            'security': 'low',
            'seclev_submit': 'Submit',
            'user_token': security_token
        }
        session.post('http://localhost:8080/security.php', data=security_data)
        print("✓ Set security=low (with CSRF token)")
    else:
        # Fallback without token
        subprocess.run([
            'curl', '-s',
            '-b', f'PHPSESSID={phpsessid}',
            '-d', 'security=low&seclev_submit=Submit',
            'http://localhost:8080/security.php'
        ], capture_output=True)
        print("✓ Set security=low (fallback)")
except:
    subprocess.run([
        'curl', '-s',
        '-b', f'PHPSESSID={phpsessid}',
        '-d', 'security=low&seclev_submit=Submit',
        'http://localhost:8080/security.php'
    ], capture_output=True)
    print("✓ Set security=low (fallback)")

print(f"\n[3/11] Creating Replacer rule to force PHPSESSID={phpsessid}...")

# Create replacer rule to REPLACE any PHPSESSID cookie with our authenticated one
# Using Replacer API
try:
    # Add a replacer rule that replaces Cookie header
    # Rule: Replace PHPSESSID=.* with PHPSESSID={our_cookie}
    rule_desc = f"Force authenticated PHPSESSID cookie"

    # Remove old replacer rules first
    try:
        rules = zap.replacer.rules()
        for rule in rules:
            zap.replacer.remove_rule(description=rule.get('description', ''))
    except:
        pass

    # Add new rule:
    # - Match: Cookie.*PHPSESSID=([^;]+)
    # - Replace with: Cookie: PHPSESSID={phpsessid}; security=low
    # - Type: Request Header
    zap.replacer.add_rule(
        description=rule_desc,
        enabled='true',
        matchtype='REQ_HEADER',
        matchregex='true',
        matchstring='Cookie.*',
        replacement=f'Cookie: PHPSESSID={phpsessid}; security=low'
    )
    print(f"✓ Replacer rule added")

except Exception as e:
    print(f"! Replacer rule error: {e}")
    print("  Continuing without replacer...")

print("\n[4/11] Manually sending requests with correct cookie to populate ZAP history...")
# Pre-seed ZAP with authenticated requests
vulnerable_paths = [
    '/vulnerabilities/sqli/',
    '/vulnerabilities/sqli/?id=1&Submit=Submit',
    '/vulnerabilities/sqli/?id=1%27%20OR%20%271%27=%271&Submit=Submit',
    '/vulnerabilities/xss_r/',
    '/vulnerabilities/xss_r/?name=<script>alert(1)</script>',
    '/vulnerabilities/xss_s/',
    '/vulnerabilities/csrf/',
    '/vulnerabilities/fi/',
    '/vulnerabilities/fi/?page=../../hackable/flags/fi.php',
    '/vulnerabilities/upload/',
    '/vulnerabilities/exec/',
    '/vulnerabilities/exec/?ip=127.0.0.1;whoami&Submit=Submit',
    '/vulnerabilities/brute/',
    '/vulnerabilities/captcha/',
    '/vulnerabilities/weak_id/',
]

for path in vulnerable_paths:
    try:
        req = f'''GET {path} HTTP/1.1
Host: dvwa
Cookie: PHPSESSID={phpsessid}; security=low
Connection: keep-alive'''
        zap.core.send_request(request=req, followredirects=True)
        time.sleep(0.2)
    except:
        pass

print(f"✓ Seeded {len(vulnerable_paths)} authenticated URLs")

print("\n[5/11] Verifying authentication works...")
test_req = f'''GET /vulnerabilities/sqli/ HTTP/1.1
Host: dvwa
Cookie: PHPSESSID={phpsessid}; security=low'''

test_response = zap.core.send_request(request=test_req, followredirects=False)

if '200 OK' in test_response and 'SQL Injection' in test_response:
    print("✓ Authentication verified - can access protected pages")
elif '302' in test_response or 'login.php' in test_response:
    print("✗ Authentication failed - redirecting to login")
    print(f"  PHPSESSID may have expired: {phpsessid}")
    sys.exit(1)
else:
    print("! Unexpected response, continuing anyway...")

print("\n[6/11] Starting Spider scan...")
print(f"  Note: All requests will use Cookie: PHPSESSID={phpsessid}")

spider_id = zap.spider.scan(url=DVWA_URL, maxchildren=None, recurse=True, subtreeonly=False)

while int(zap.spider.status(spider_id)) < 100:
    progress = zap.spider.status(spider_id)
    print(f"    Spider: {progress}%", end='\r')
    sys.stdout.flush()
    time.sleep(2)

urls_found = zap.spider.results(spider_id)
print(f"\n  ✓ Spider found {len(urls_found)} URLs")

vuln_urls = [url for url in urls_found if 'vulnerabilities' in url]
if vuln_urls:
    print(f"  ✓ Found {len(vuln_urls)} vulnerable URLs")
    for url in vuln_urls[:5]:
        print(f"      • {url}")
else:
    print("  ✗ No /vulnerabilities/* URLs found")

print("\n[7/11] Checking if Replacer is working...")
# Check last few requests to see if they have our cookie
messages = zap.core.messages()
correct_cookie_count = 0
wrong_cookie_count = 0

for msg in messages[-20:]:
    req_header = msg.get('requestHeader', '')
    if f'PHPSESSID={phpsessid}' in req_header:
        correct_cookie_count += 1
    elif 'PHPSESSID=' in req_header:
        wrong_cookie_count += 1

print(f"  Correct cookie (ours): {correct_cookie_count}/20")
print(f"  Wrong cookie: {wrong_cookie_count}/20")

if correct_cookie_count > wrong_cookie_count:
    print("  ✓ Replacer seems to be working!")
else:
    print("  ! Replacer may not be working properly")

print("\n[8/11] Starting Active scan with aggressive policy...")

# Use more aggressive scan policy
try:
    # Enable all scanners
    zap.ascan.enable_all_scanners()
    print("  ✓ Enabled all active scanners")
except:
    pass

ascan_id = zap.ascan.scan(
    url=DVWA_URL,
    recurse=True,
    scanpolicyname='Default Policy'
)

max_wait = 1200
start_time = time.time()
last_progress = 0

while True:
    try:
        status = zap.ascan.status(ascan_id)
        progress = int(status)

        if progress >= 100:
            print(f"    Active scan: 100%")
            break

        if progress != last_progress:
            print(f"    Active scan: {progress}%", end='\r')
            sys.stdout.flush()
            last_progress = progress

        if time.time() - start_time > max_wait:
            print(f"\n  ! Timeout after {max_wait}s")
            break

        time.sleep(5)
    except Exception as e:
        if time.time() - start_time > 120:
            print(f"\n  ! Warning: {e}")
            break
        time.sleep(5)

print("\n  ✓ Active scan complete")

print("\n[9/11] Verifying cookie usage in scan requests...")
# Check what cookies were used during active scan
messages = zap.core.messages()
scan_requests_with_correct_cookie = 0
scan_requests_with_wrong_cookie = 0
scan_requests_total = 0

for msg in messages:
    url = msg.get('requestHeader', '').split('\n')[0]
    if '/vulnerabilities/' in url:
        scan_requests_total += 1
        req_header = msg.get('requestHeader', '')
        if f'PHPSESSID={phpsessid}' in req_header:
            scan_requests_with_correct_cookie += 1
        elif 'PHPSESSID=' in req_header:
            scan_requests_with_wrong_cookie += 1

print(f"  Total scan requests to /vulnerabilities/: {scan_requests_total}")
print(f"  With correct cookie: {scan_requests_with_correct_cookie}")
print(f"  With wrong cookie: {scan_requests_with_wrong_cookie}")

print("\n[10/11] Collecting results...")
alerts = zap.core.alerts(baseurl='')
print(f"✓ Found {len(alerts)} total alerts")

# Save results
with open(SCAN_OUTPUT, 'w') as f:
    json.dump(alerts, f, indent=2)
print(f"✓ Saved to: {SCAN_OUTPUT}")

print("\n[11/11] Analysis...")
print("\n" + "="*80)
print("RESULTS SUMMARY")
print("="*80)

risk_counts = {}
for alert in alerts:
    risk = alert.get('risk', 'Unknown')
    risk_counts[risk] = risk_counts.get(risk, 0) + 1

for risk in ['High', 'Medium', 'Low', 'Informational']:
    if risk in risk_counts:
        print(f"  {risk}: {risk_counts[risk]}")

print("\n" + "="*80)
print("CRITICAL VULNERABILITIES")
print("="*80)

critical_types = {
    'SQL Injection': [],
    'Cross Site Scripting': [],
    'XSS': [],
    'Command Injection': [],
    'Path Traversal': [],
    'File Inclusion': []
}

for alert in alerts:
    name = alert.get('name', '')
    url = alert.get('url', '')

    for crit_type in critical_types.keys():
        if crit_type.lower() in name.lower():
            critical_types[crit_type].append((name, url))

found_any = False
for vuln_type, findings in critical_types.items():
    if findings:
        found_any = True
        unique_names = {}
        for name, url in findings:
            if name not in unique_names:
                unique_names[name] = []
            unique_names[name].append(url)

        print(f"\n✓ {vuln_type}:")
        for name, urls in unique_names.items():
            print(f"    • {name}: {len(urls)} instances")
            for url in urls[:2]:
                print(f"        {url}")

if not found_any:
    print("\n✗ No critical vulnerabilities found")
    print("  Even with Replacer rule forcing authentication")
    print("  ZAP may not be detecting DVWA vulnerabilities properly")

print("\n" + "="*80)
print(f"Scan complete! Results: {SCAN_OUTPUT}")
print("="*80)
