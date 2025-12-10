#!/usr/bin/env python3
"""
Session-based authenticated ZAP scan using HTTP Sessions API.
This approach manually manages a single PHPSESSID cookie.
"""

from zapv2 import ZAPv2
import json
import time
import sys
import re

# Configuration
ZAP_API_KEY = "changeme"
ZAP_HOST = "localhost"
ZAP_PORT = "8090"
DVWA_URL = "http://dvwa:80"
SCAN_OUTPUT = "scans/dvwa_scan_with_auth.json"

print("="*80)
print("SESSION-BASED AUTHENTICATED ZAP SCAN")
print("="*80)

# Connect to ZAP
zap = ZAPv2(
    apikey=ZAP_API_KEY,
    proxies={
        'http': f'http://{ZAP_HOST}:{ZAP_PORT}',
        'https': f'http://{ZAP_HOST}:{ZAP_PORT}'
    }
)

print("\n[1/9] Creating new ZAP session...")
try:
    zap.core.new_session(name='dvwa_http_session', overwrite=True)
    print("✓ Session created")
except Exception as e:
    print(f"! Warning: {e}")

print("\n[2/9] Creating HTTP session for DVWA...")

# Create a named HTTP session
site = DVWA_URL
session_name = "AuthenticatedSession"

# Remove old sessions
existing_sessions = zap.httpsessions.sessions(site=site)
for session in existing_sessions:
    session_id = session.get('session', [''])[0]
    try:
        zap.httpsessions.remove_session(site=site, session=session_id)
    except:
        pass

# Create new session
zap.httpsessions.create_empty_session(site=site, session=session_name)
print(f"✓ Created session: {session_name}")

# Set it as active
zap.httpsessions.set_active_session(site=site, session=session_name)
print(f"✓ Set as active session")

print("\n[3/9] Accessing DVWA to get PHPSESSID...")

# Access main page to get initial PHPSESSID
zap.core.access_url(url=DVWA_URL, followredirects=True)
time.sleep(1)

# Get the PHPSESSID from active session
sessions_data = zap.httpsessions.sessions(site=site)
active_session = None
for session in sessions_data:
    if session['session'][0] == session_name:
        active_session = session
        break

if active_session:
    cookies = active_session['session'][1]
    if 'PHPSESSID' in cookies:
        phpsessid = cookies['PHPSESSID']['value']
        print(f"✓ Got PHPSESSID: {phpsessid}")
    else:
        print("✗ No PHPSESSID in session")
        sys.exit(1)
else:
    print("✗ Could not find active session")
    sys.exit(1)

print("\n[4/9] Logging in to DVWA...")

# Send login POST request
login_request = f'''POST /login.php HTTP/1.1
Host: dvwa
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID={phpsessid}; security=low
Content-Length: 42

username=admin&password=password&Login=Login'''

response = zap.core.send_request(request=login_request, followredirects=False)
print("✓ Login request sent")

# Check if login was successful (should redirect to index.php)
if '302' in response or 'Location: index.php' in response:
    print("✓ Login successful (got redirect)")
else:
    print("! Warning: Unexpected response")
    print(response[:200])

# Update session cookie after login
time.sleep(1)

# Set security level to low
security_request = f'''POST /security.php HTTP/1.1
Host: dvwa
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID={phpsessid}; security=low
Content-Length: 33

security=low&seclev_submit=Submit'''

zap.core.send_request(request=security_request, followredirects=False)
print("✓ Set security level to Low")

print("\n[5/9] Verifying authentication...")

# Test access to protected page
test_request = f'''GET /vulnerabilities/sqli/ HTTP/1.1
Host: dvwa
Cookie: PHPSESSID={phpsessid}; security=low'''

test_response = zap.core.send_request(request=test_request, followredirects=False)

if '200 OK' in test_response and 'SQL Injection' in test_response:
    print("✓ Can access protected pages!")
elif '302' in test_response or 'login.php' in test_response:
    print("✗ Still redirecting to login")
    print("Authentication failed!")
    sys.exit(1)
else:
    print("! Unexpected response:")
    print(test_response[:300])

print("\n[6/9] Seeding vulnerable URLs with authenticated session...")

# Access vulnerable pages with authenticated cookie
vulnerable_pages = [
    '/vulnerabilities/sqli/',
    '/vulnerabilities/sqli/?id=1&Submit=Submit',
    '/vulnerabilities/xss_r/',
    '/vulnerabilities/xss_r/?name=test',
    '/vulnerabilities/xss_s/',
    '/vulnerabilities/csrf/',
    '/vulnerabilities/fi/',
    '/vulnerabilities/fi/?page=include.php',
    '/vulnerabilities/upload/',
    '/vulnerabilities/exec/',
    '/vulnerabilities/brute/',
    '/vulnerabilities/captcha/',
    '/vulnerabilities/weak_id/',
]

for page in vulnerable_pages:
    try:
        req = f'''GET {page} HTTP/1.1
Host: dvwa
Cookie: PHPSESSID={phpsessid}; security=low'''
        zap.core.send_request(request=req, followredirects=True)
        time.sleep(0.2)
    except:
        pass

print(f"✓ Seeded {len(vulnerable_pages)} vulnerable pages")

print("\n[7/9] Starting Spider scan with authenticated session...")

# Spider with the authenticated session
scan_id = zap.spider.scan(url=DVWA_URL, maxchildren=None, recurse=True, subtreeonly=False)

while int(zap.spider.status(scan_id)) < 100:
    progress = zap.spider.status(scan_id)
    print(f"  Spider progress: {progress}%", end='\r')
    sys.stdout.flush()
    time.sleep(2)

urls_found = zap.spider.results(scan_id)
print(f"\n✓ Spider found {len(urls_found)} URLs")

# Show vulnerable URLs found
vuln_urls = [url for url in urls_found if 'vulnerabilities' in url]
if vuln_urls:
    print(f"  ✓ Found {len(vuln_urls)} vulnerable URLs:")
    for url in vuln_urls[:5]:
        print(f"    • {url}")
else:
    print("  ✗ No vulnerable URLs found by spider")

print("\n[8/9] Starting Active scan...")

ascan_id = zap.ascan.scan(url=DVWA_URL, recurse=True, scanpolicyname='Default Policy')

max_wait = 1200  # 20 minutes
start_time = time.time()
last_progress = 0

while True:
    try:
        status = zap.ascan.status(ascan_id)
        progress = int(status)

        if progress >= 100:
            print(f"  Active scan progress: 100%")
            break

        if progress != last_progress:
            print(f"  Active scan progress: {progress}%", end='\r')
            sys.stdout.flush()
            last_progress = progress

        if time.time() - start_time > max_wait:
            print(f"\n! Timeout after {max_wait}s")
            break

        time.sleep(5)
    except Exception as e:
        if time.time() - start_time > 120:
            print(f"\n! Warning: {e}")
            break
        time.sleep(5)

print("\n✓ Active scan complete")

print("\n[9/9] Collecting results...")

# Get all alerts
alerts = zap.core.alerts(baseurl='')
print(f"✓ Found {len(alerts)} total alerts")

# Filter for alerts on vulnerable URLs
vuln_alerts = [a for a in alerts if 'vulnerabilities' in a.get('url', '')]
print(f"✓ {len(vuln_alerts)} alerts on /vulnerabilities/* pages")

# Save results
with open(SCAN_OUTPUT, 'w') as f:
    json.dump(alerts, f, indent=2)
print(f"✓ Saved to: {SCAN_OUTPUT}")

# Show summary
print("\n" + "="*80)
print("SCAN RESULTS SUMMARY")
print("="*80)

risk_counts = {}
for alert in alerts:
    risk = alert.get('risk', 'Unknown')
    risk_counts[risk] = risk_counts.get(risk, 0) + 1

for risk in ['High', 'Medium', 'Low', 'Informational']:
    if risk in risk_counts:
        print(f"  {risk}: {risk_counts[risk]}")

# Check for critical vulnerabilities
print("\n" + "="*80)
print("CRITICAL VULNERABILITIES FOUND:")
print("="*80)

critical_types = ['SQL Injection', 'Cross Site Scripting', 'Command Injection', 'Path Traversal', 'CSRF']
critical_found = {}

for alert in alerts:
    name = alert.get('name', '')
    url = alert.get('url', '')

    for crit_type in critical_types:
        if crit_type.lower() in name.lower():
            if crit_type not in critical_found:
                critical_found[crit_type] = []
            critical_found[crit_type].append(url)

if critical_found:
    for vuln_type, urls in critical_found.items():
        print(f"\n✓ {vuln_type}: {len(urls)} instances")
        for url in urls[:3]:
            print(f"    • {url}")
else:
    print("\n✗ No critical vulnerabilities found (SQLi, XSS, etc.)")
    print("  Authentication may not have worked properly")

print("\n" + "="*80)
print(f"Session-based authenticated scan complete!")
print(f"Results: {SCAN_OUTPUT}")
print("="*80)
