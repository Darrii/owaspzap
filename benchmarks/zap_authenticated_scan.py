#!/usr/bin/env python3
"""
Authenticated ZAP scan for DVWA using proper context and authentication.
This ensures ZAP can access protected pages and find real vulnerabilities.
"""

from zapv2 import ZAPv2
import json
import time
import sys

# Configuration
ZAP_API_KEY = "changeme"
ZAP_HOST = "localhost"
ZAP_PORT = "8090"
DVWA_URL = "http://dvwa:80"  # Internal Docker network
USERNAME = "admin"
PASSWORD = "password"
SCAN_OUTPUT = "scans/dvwa_scan_authenticated.json"

print("="*80)
print("AUTHENTICATED ZAP SCAN FOR DVWA")
print("="*80)

# Connect to ZAP
zap = ZAPv2(
    apikey=ZAP_API_KEY,
    proxies={
        'http': f'http://{ZAP_HOST}:{ZAP_PORT}',
        'https': f'http://{ZAP_HOST}:{ZAP_PORT}'
    }
)

print("\n[1/8] Creating new ZAP session...")
try:
    zap.core.new_session(name='dvwa_authenticated', overwrite=True)
    print("✓ Session created")
except Exception as e:
    print(f"! Warning: {e}")

print("\n[2/8] Setting up authentication context...")

# Create context for DVWA
context_name = "DVWA"
context_id = zap.context.new_context(contextname=context_name)
print(f"✓ Context created: {context_name} (ID: {context_id})")

# Include DVWA URLs in context
zap.context.include_in_context(
    contextname=context_name,
    regex=f"{DVWA_URL}.*"
)
print(f"✓ Context includes: {DVWA_URL}.*")

# Exclude logout URL
zap.context.exclude_from_context(
    contextname=context_name,
    regex=f"{DVWA_URL}/logout.php.*"
)
print("✓ Excluded logout.php")

print("\n[3/8] Configuring form-based authentication...")

# Set authentication method to form-based
login_url = f"{DVWA_URL}/login.php"
login_request_data = "username={%username%}&password={%password%}&Login=Login"

zap.authentication.set_authentication_method(
    contextid=context_id,
    authmethodname='formBasedAuthentication',
    authmethodconfigparams=f'loginUrl={login_url}&loginRequestData={login_request_data}'
)
print(f"✓ Login URL: {login_url}")
print(f"✓ Login data: {login_request_data}")

# Set logged in indicator (text that appears only when logged in)
zap.authentication.set_logged_in_indicator(
    contextid=context_id,
    loggedinindicatorregex='.*Logout.*'  # "Logout" link appears when logged in
)
print("✓ Logged-in indicator: 'Logout'")

# Set logged out indicator
zap.authentication.set_logged_out_indicator(
    contextid=context_id,
    loggedoutindicatorregex='.*Login.*'
)
print("✓ Logged-out indicator: 'Login'")

print("\n[4/8] Creating user for scanning...")

# Create user
user_name = "admin"
user_id = zap.users.new_user(contextid=context_id, name=user_name)
print(f"✓ User created: {user_name} (ID: {user_id})")

# Set user credentials
zap.users.set_authentication_credentials(
    contextid=context_id,
    userid=user_id,
    authcredentialsconfigparams=f'username={USERNAME}&password={PASSWORD}'
)
print(f"✓ Credentials set: {USERNAME}/{PASSWORD}")

# Enable user
zap.users.set_user_enabled(contextid=context_id, userid=user_id, enabled=True)
print("✓ User enabled")

# Enable forced user mode (scan as this user)
zap.forcedUser.set_forced_user(contextid=context_id, userid=user_id)
zap.forcedUser.set_forced_user_mode_enabled(boolean=True)
print("✓ Forced user mode enabled")

print("\n[5/8] Accessing DVWA and establishing session...")

# Access the target to establish session
zap.core.access_url(url=DVWA_URL, followredirects=True)
time.sleep(2)

# Access login page
zap.core.access_url(url=login_url, followredirects=True)
time.sleep(1)

# Manually seed vulnerable pages
vulnerable_pages = [
    '/vulnerabilities/sqli/',
    '/vulnerabilities/sqli/?id=1&Submit=Submit',
    '/vulnerabilities/xss_r/',
    '/vulnerabilities/xss_s/',
    '/vulnerabilities/csrf/',
    '/vulnerabilities/fi/?page=../../hackable/flags/fi.php',
    '/vulnerabilities/upload/',
    '/vulnerabilities/exec/',
    '/vulnerabilities/brute/',
    '/vulnerabilities/captcha/',
    '/vulnerabilities/weak_id/',
]

print("Seeding vulnerable URLs...")
for page in vulnerable_pages:
    try:
        url = f"{DVWA_URL}{page}"
        zap.core.access_url(url=url, followredirects=True)
        time.sleep(0.3)
    except:
        pass

print(f"✓ Seeded {len(vulnerable_pages)} vulnerable pages")

print("\n[6/8] Starting Spider scan (authenticated)...")
scan_id = zap.spider.scan_as_user(
    contextid=context_id,
    userid=user_id,
    url=DVWA_URL,
    maxchildren=None,
    recurse=True,
    subtreeonly=False
)

# Wait for spider
while int(zap.spider.status(scan_id)) < 100:
    progress = zap.spider.status(scan_id)
    print(f"  Spider progress: {progress}%", end='\r')
    sys.stdout.flush()
    time.sleep(2)

urls_found = zap.spider.results(scan_id)
print(f"\n✓ Spider found {len(urls_found)} URLs")

# Show some URLs to verify authentication worked
print("\nSample URLs found:")
for url in urls_found[:10]:
    print(f"  • {url}")

print("\n[7/8] Starting Active scan (authenticated)...")
ascan_id = zap.ascan.scan_as_user(
    url=DVWA_URL,
    contextid=context_id,
    userid=user_id,
    recurse=True,
    scanpolicyname='Default Policy',
    method=None,
    postdata=None
)

# Wait for active scan
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

print("\n[8/8] Collecting results...")

# Get all alerts
alerts = zap.core.alerts(baseurl='')
print(f"✓ Found {len(alerts)} alerts")

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
critical_found = []
critical_types = ['SQL Injection', 'Cross Site Scripting', 'Command Injection', 'Path Traversal']

for alert in alerts:
    name = alert.get('name', '')
    for crit_type in critical_types:
        if crit_type.lower() in name.lower():
            if name not in critical_found:
                critical_found.append(name)

if critical_found:
    print(f"\n✓ CRITICAL VULNERABILITIES FOUND:")
    for vuln in critical_found:
        print(f"  • {vuln}")
else:
    print(f"\n✗ No critical vulnerabilities found (SQLi, XSS, etc.)")

print("\n" + "="*80)
print(f"Authenticated scan complete!")
print(f"Results: {SCAN_OUTPUT}")
print("="*80)
