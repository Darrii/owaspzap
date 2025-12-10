#!/usr/bin/env python3
"""
ZAP scan with proper session management - uses single PHPSESSID throughout.
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
SCAN_OUTPUT = "scans/dvwa_scan_fixed.json"

print("="*80)
print("ZAP SCAN WITH FIXED SESSION MANAGEMENT")
print("="*80)

# Connect to ZAP
zap = ZAPv2(
    apikey=ZAP_API_KEY,
    proxies={
        'http': f'http://{ZAP_HOST}:{ZAP_PORT}',
        'https': f'http://{ZAP_HOST}:{ZAP_PORT}'
    }
)

print("\n[1/10] Creating new ZAP session...")
try:
    zap.core.new_session(name='dvwa_fixed_session', overwrite=True)
    print("✓ ZAP session created")
except Exception as e:
    print(f"! Warning: {e}")

print("\n[2/10] Creating single HTTP session...")
site = DVWA_URL
session_name = "DVWA_Auth_Session"

# Remove all existing sessions
try:
    existing = zap.httpsessions.sessions(site=site)
    print(f"  Found {len(existing)} existing sessions, removing...")
    for session in existing:
        try:
            session_id = session['session'][0]
            zap.httpsessions.remove_session(site=site, session=session_id)
        except:
            pass
except:
    pass

# Create ONE new session
zap.httpsessions.create_empty_session(site=site, session=session_name)
zap.httpsessions.set_active_session(site=site, session=session_name)
print(f"✓ Created and activated session: {session_name}")

print("\n[3/10] Getting PHPSESSID cookie...")
# Access DVWA to get PHPSESSID
zap.core.access_url(url=f"{DVWA_URL}/login.php", followredirects=True)
time.sleep(2)

# Get the PHPSESSID from our session
sessions = zap.httpsessions.sessions(site=site)
phpsessid = None

for session in sessions:
    if session['session'][0] == session_name:
        cookies = session['session'][1]
        if 'PHPSESSID' in cookies:
            phpsessid = cookies['PHPSESSID']['value']
            print(f"✓ Got PHPSESSID: {phpsessid}")
            break

if not phpsessid:
    print("✗ Failed to get PHPSESSID")
    sys.exit(1)

print("\n[4/10] Setting session cookie permanently...")
# Set the cookie in ZAP's session
zap.httpsessions.set_session_token_value(
    site=site,
    session=session_name,
    sessiontoken='PHPSESSID',
    tokenvalue=phpsessid
)
print(f"✓ PHPSESSID set in session")

print("\n[5/10] Logging in to DVWA...")
# Login using the PHPSESSID
login_request = f'''POST /login.php HTTP/1.1
Host: dvwa
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID={phpsessid}
Content-Length: 42

username=admin&password=password&Login=Login'''

response = zap.core.send_request(request=login_request, followredirects=False)

if '302' in response or 'index.php' in response:
    print("✓ Login successful (got redirect)")
else:
    print("! Warning: Unexpected login response")

time.sleep(1)

print("\n[6/10] Setting security level to Low...")
security_request = f'''POST /security.php HTTP/1.1
Host: dvwa
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID={phpsessid}; security=low
Content-Length: 33

security=low&seclev_submit=Submit'''

zap.core.send_request(request=security_request, followredirects=False)
print("✓ Security level set")

print("\n[7/10] Verifying authentication...")
# Test access to protected page
test_request = f'''GET /vulnerabilities/sqli/ HTTP/1.1
Host: dvwa
Cookie: PHPSESSID={phpsessid}; security=low'''

test_response = zap.core.send_request(request=test_request, followredirects=False)

if '200 OK' in test_response and 'SQL Injection' in test_response:
    print("✓ Authentication verified - can access /vulnerabilities/sqli/")
elif '302' in test_response or 'login.php' in test_response:
    print("✗ Authentication failed - still redirecting to login")
    sys.exit(1)
else:
    print("! Unexpected response")

print("\n[8/10] Pre-seeding vulnerable pages...")
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
Cookie: PHPSESSID={phpsessid}; security=low'''
        zap.core.send_request(request=req, followredirects=True)
        time.sleep(0.3)
    except:
        pass

print(f"✓ Seeded {len(vulnerable_paths)} URLs with authenticated session")

print("\n[9/10] Starting Spider and Active scans...")
print("  Note: Spider and Active scan will use the authenticated session")

# Make sure session is still active
zap.httpsessions.set_active_session(site=site, session=session_name)

# Spider scan
print("\n  Starting Spider...")
spider_id = zap.spider.scan(url=DVWA_URL, maxchildren=None, recurse=True, subtreeonly=False)

while int(zap.spider.status(spider_id)) < 100:
    progress = zap.spider.status(spider_id)
    print(f"    Spider: {progress}%", end='\r')
    sys.stdout.flush()
    time.sleep(2)

urls_found = zap.spider.results(spider_id)
print(f"\n  ✓ Spider found {len(urls_found)} URLs")

# Check if vulnerable URLs were found
vuln_urls = [url for url in urls_found if 'vulnerabilities' in url]
if vuln_urls:
    print(f"  ✓ Found {len(vuln_urls)} vulnerable URLs (authentication worked!)")
    for url in vuln_urls[:5]:
        print(f"      • {url}")
else:
    print("  ✗ No /vulnerabilities/* URLs found (authentication may have failed)")

# Active scan
print("\n  Starting Active scan...")
ascan_id = zap.ascan.scan(url=DVWA_URL, recurse=True, scanpolicyname='Default Policy')

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

print("\n  ✓ Scans complete")

print("\n[10/10] Collecting results...")
alerts = zap.core.alerts(baseurl='')
print(f"✓ Found {len(alerts)} total alerts")

# Save results
with open(SCAN_OUTPUT, 'w') as f:
    json.dump(alerts, f, indent=2)
print(f"✓ Saved to: {SCAN_OUTPUT}")

# Summary
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

# Check for critical vulnerabilities
print("\n" + "="*80)
print("CRITICAL VULNERABILITIES")
print("="*80)

critical_types = {
    'SQL Injection': [],
    'Cross Site Scripting': [],
    'Command Injection': [],
    'Path Traversal': [],
    'CSRF': []
}

for alert in alerts:
    name = alert.get('name', '')
    url = alert.get('url', '')

    for crit_type in critical_types.keys():
        if crit_type.lower() in name.lower():
            critical_types[crit_type].append(url)

found_any = False
for vuln_type, urls in critical_types.items():
    if urls:
        found_any = True
        print(f"\n✓ {vuln_type}: {len(urls)} instances")
        for url in list(set(urls))[:3]:
            print(f"    • {url}")

if not found_any:
    print("\n✗ No critical vulnerabilities found (SQLi, XSS, Command Injection)")
    print("  This suggests authentication may not have worked properly")

print("\n" + "="*80)
print(f"Scan complete! Results: {SCAN_OUTPUT}")
print("="*80)
