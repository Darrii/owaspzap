#!/usr/bin/env python3
"""
Aggressive authenticated ZAP scan with maximum scanner configuration.
Enables all injection scanners at HIGH strength and LOW threshold.
"""

from zapv2 import ZAPv2
import json
import time
import sys
import subprocess

# Configuration
ZAP_API_KEY = "changeme"
ZAP_HOST = "localhost"
ZAP_PORT = "8090"
DVWA_URL = "http://dvwa:80"
SCAN_OUTPUT = "scans/dvwa_scan_aggressive.json"

print("="*80)
print("AGGRESSIVE AUTHENTICATED ZAP SCAN")
print("="*80)

# Connect to ZAP
zap = ZAPv2(
    apikey=ZAP_API_KEY,
    proxies={
        'http': f'http://{ZAP_HOST}:{ZAP_PORT}',
        'https': f'http://{ZAP_HOST}:{ZAP_PORT}'
    }
)

print("\n[1/12] Creating new ZAP session...")
try:
    zap.core.new_session(name='dvwa_aggressive', overwrite=True)
    print("✓ Session created")
except Exception as e:
    print(f"! Warning: {e}")

print("\n[2/12] Getting authenticated PHPSESSID from host...")
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
    print("✗ Failed to get PHPSESSID from host login")
    sys.exit(1)

print(f"✓ Got authenticated PHPSESSID: {phpsessid}")

# Set security to low
subprocess.run([
    'curl', '-s',
    '-b', f'PHPSESSID={phpsessid}',
    '-d', 'security=low&seclev_submit=Submit',
    'http://localhost:8080/security.php'
], capture_output=True)
print("✓ Set security=low")

print(f"\n[3/12] Creating Replacer rule to force authentication...")
try:
    # Remove old rules
    rules = zap.replacer.rules()
    for rule in rules:
        zap.replacer.remove_rule(description=rule.get('description', ''))
except:
    pass

zap.replacer.add_rule(
    description="Force authenticated PHPSESSID",
    enabled='true',
    matchtype='REQ_HEADER',
    matchregex='true',
    matchstring='Cookie.*',
    replacement=f'Cookie: PHPSESSID={phpsessid}; security=low'
)
print("✓ Replacer rule configured")

print("\n[4/12] Pre-seeding vulnerable URLs...")
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

print("\n[5/12] Configuring aggressive scan policy...")

# Create custom scan policy
policy_name = "Aggressive"

try:
    # Try to create new policy (may fail if exists)
    zap.ascan.add_scan_policy(scanpolicyname=policy_name)
except:
    pass

print(f"✓ Using policy: {policy_name}")

print("\n[6/12] Enabling critical vulnerability scanners...")

# Get all available scanners
scanners = zap.ascan.scanners()

# Critical scanner IDs for injection vulnerabilities
critical_scanners = {
    '40018': 'SQL Injection',
    '40019': 'SQL Injection - MySQL',
    '40020': 'SQL Injection - Hypersonic SQL',
    '40021': 'SQL Injection - Oracle',
    '40022': 'SQL Injection - PostgreSQL',
    '40023': 'SQL Injection - SQLite',
    '40024': 'SQL Injection - MS SQL Server',
    '90018': 'SQL Injection - Authentication Bypass',
    '40012': 'Cross Site Scripting (Reflected)',
    '40014': 'Cross Site Scripting (Persistent)',
    '40016': 'Cross Site Scripting (Persistent) - Prime',
    '40017': 'Cross Site Scripting (Persistent) - Spider',
    '90019': 'Server Side Code Injection',
    '90020': 'Remote OS Command Injection',
    '7': 'Remote File Inclusion',
    '6': 'Path Traversal',
}

print("  Configuring scanners:")
enabled_count = 0

for scanner in scanners:
    scanner_id = scanner.get('id')
    scanner_name = scanner.get('name', 'Unknown')

    # Check if this is a critical scanner
    if scanner_id in critical_scanners or any(
        keyword in scanner_name.lower()
        for keyword in ['sql', 'injection', 'xss', 'scripting', 'command', 'traversal', 'inclusion']
    ):
        try:
            # Enable scanner
            zap.ascan.set_scanner_alert_threshold(
                id=scanner_id,
                alertthreshold='LOW',  # Detect even low-confidence issues
                scanpolicyname=policy_name
            )
            zap.ascan.set_scanner_attack_strength(
                id=scanner_id,
                attackstrength='INSANE',  # Maximum strength
                scanpolicyname=policy_name
            )
            zap.ascan.enable_scanners(
                ids=scanner_id,
                scanpolicyname=policy_name
            )
            print(f"    ✓ {scanner_name} (ID: {scanner_id}) - INSANE/LOW")
            enabled_count += 1
        except Exception as e:
            print(f"    ! {scanner_name}: {e}")

print(f"✓ Enabled {enabled_count} critical scanners")

print("\n[7/12] Starting Spider scan...")
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

print("\n[8/12] Starting AGGRESSIVE Active scan...")
print(f"  Policy: {policy_name}")
print(f"  Scanners: {enabled_count} at INSANE strength")
print(f"  Threshold: LOW (maximum sensitivity)")

ascan_id = zap.ascan.scan(
    url=DVWA_URL,
    recurse=True,
    scanpolicyname=policy_name
)

max_wait = 1800  # 30 minutes for aggressive scan
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

print("\n[9/12] Verifying Replacer worked...")
messages = zap.core.messages()
correct_cookie = sum(1 for msg in messages if f'PHPSESSID={phpsessid}' in msg.get('requestHeader', ''))
total_messages = len(messages)
print(f"  Requests with correct cookie: {correct_cookie}/{total_messages}")

print("\n[10/12] Collecting results...")
alerts = zap.core.alerts(baseurl='')
print(f"✓ Found {len(alerts)} total alerts")

# Save results
with open(SCAN_OUTPUT, 'w') as f:
    json.dump(alerts, f, indent=2)
print(f"✓ Saved to: {SCAN_OUTPUT}")

print("\n[11/12] Analyzing results...")
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
print("INJECTION VULNERABILITIES")
print("="*80)

injection_types = {
    'SQL Injection': [],
    'Cross Site Scripting': [],
    'XSS': [],
    'Command Injection': [],
    'OS Command': [],
    'Path Traversal': [],
    'File Inclusion': [],
    'Code Injection': [],
}

for alert in alerts:
    name = alert.get('name', '')
    url = alert.get('url', '')
    risk = alert.get('risk', '')

    for inj_type in injection_types.keys():
        if inj_type.lower() in name.lower():
            injection_types[inj_type].append({
                'name': name,
                'url': url,
                'risk': risk,
                'param': alert.get('param', ''),
                'attack': alert.get('attack', '')
            })

found_any = False
for vuln_type, findings in injection_types.items():
    if findings:
        found_any = True
        print(f"\n✓ {vuln_type}: {len(findings)} instances")

        # Group by unique names
        unique = {}
        for f in findings:
            if f['name'] not in unique:
                unique[f['name']] = []
            unique[f['name']].append(f)

        for name, instances in unique.items():
            print(f"    • {name} ({instances[0]['risk']}): {len(instances)} URLs")
            for inst in instances[:2]:
                if inst['param']:
                    print(f"        Parameter: {inst['param']}")
                if inst['attack']:
                    print(f"        Attack: {inst['attack'][:80]}")
                print(f"        URL: {inst['url']}")

if not found_any:
    print("\n✗ NO INJECTION VULNERABILITIES FOUND")
    print("  Even with AGGRESSIVE scan policy and INSANE strength")
    print("\n  This suggests one of:")
    print("    1. ZAP Active Scanner not compatible with DVWA's vulnerability patterns")
    print("    2. DVWA security=low not actually vulnerable")
    print("    3. ZAP requires manual configuration beyond API")
    print("\n  Recommendation: Manually inject test vulnerabilities for chain detection")

print("\n[12/12] Scan policy details...")
print(f"\nPolicy: {policy_name}")
print(f"Enabled scanners: {enabled_count}")
print("Strength: INSANE")
print("Threshold: LOW")
print(f"Results: {SCAN_OUTPUT}")

print("\n" + "="*80)
print("AGGRESSIVE SCAN COMPLETE")
print("="*80)
