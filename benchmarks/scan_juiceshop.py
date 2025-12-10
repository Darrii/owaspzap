#!/usr/bin/env python3
"""
ZAP Aggressive Scan for OWASP Juice Shop
Modern vulnerable web application with REST API
"""
import time
import json
from zapv2 import ZAPv2

JUICESHOP_URL = "http://juiceshop:3000"
ZAP_API_KEY = "changeme"
ZAP_HOST = "localhost"
ZAP_PORT = 8090

print("="*80)
print("ZAP AGGRESSIVE SCAN - OWASP JUICE SHOP")
print("="*80)

# Connect to ZAP
zap = ZAPv2(
    apikey=ZAP_API_KEY,
    proxies={
        'http': f'http://{ZAP_HOST}:{ZAP_PORT}',
        'https': f'http://{ZAP_HOST}:{ZAP_PORT}'
    }
)

# [1/10] New session
print("\n[1/10] Creating new ZAP session...")
zap.core.new_session(name="juiceshop_scan", overwrite=True)
print("✓ Session created")

# [2/10] Access target
print("\n[2/10] Accessing Juice Shop...")
zap.core.access_url(url=JUICESHOP_URL, followredirects=True)
time.sleep(2)
print(f"✓ Accessed {JUICESHOP_URL}")

# [3/10] Create aggressive policy
print("\n[3/10] Creating aggressive scan policy...")
policy_name = "JuiceShop-Aggressive"

try:
    zap.ascan.remove_scan_policy(scanpolicyname=policy_name)
except:
    pass

zap.ascan.add_scan_policy(scanpolicyname=policy_name)
print(f"✓ Created policy: {policy_name}")

# [4/10] Configure critical scanners
print("\n[4/10] Configuring injection scanners...")

critical_scanners = {
    '40018': 'SQL Injection',
    '40019': 'SQL Injection - MySQL (Time Based)',
    '40012': 'Cross Site Scripting (Reflected)',
    '40014': 'Cross Site Scripting (Persistent)',
    '90020': 'Remote OS Command Injection',
    '6': 'Path Traversal',
    '7': 'Remote File Inclusion',
    '40003': 'CRLF Injection',
    '90019': 'Server Side Code Injection',
    '90021': 'XPath Injection',
}

configured_count = 0
for scanner_id, scanner_name in critical_scanners.items():
    try:
        # Set threshold to LOW
        zap.ascan.set_scanner_alert_threshold(
            id=scanner_id,
            alertthreshold='LOW',
            scanpolicyname=policy_name
        )
        # Set strength to INSANE
        zap.ascan.set_scanner_attack_strength(
            id=scanner_id,
            attackstrength='INSANE',
            scanpolicyname=policy_name
        )
        # Enable scanner
        zap.ascan.enable_scanners(
            ids=scanner_id,
            scanpolicyname=policy_name
        )
        configured_count += 1
        print(f"  ✓ {scanner_name} (ID: {scanner_id}) - INSANE/LOW")
    except Exception as e:
        print(f"  ! {scanner_name}: {e}")

print(f"✓ Configured {configured_count} scanners")

# [5/10] Spider scan
print("\n[5/10] Starting Spider scan...")
spider_id = zap.spider.scan(url=JUICESHOP_URL, maxchildren=None, recurse=True)

while int(zap.spider.status(spider_id)) < 100:
    status = int(zap.spider.status(spider_id))
    print(f"    Spider: {status}%", end='\r')
    time.sleep(2)

spider_results = zap.spider.results(spider_id)
print(f"\n  ✓ Spider found {len(spider_results)} URLs")

# Show some interesting URLs
interesting_urls = [url for url in spider_results if any(
    path in url for path in ['/api/', '/rest/', '/products/', '/users/']
)]
print(f"  ✓ Found {len(interesting_urls)} API/interesting endpoints:")
for url in interesting_urls[:10]:
    print(f"      • {url}")

# [6/10] Passive scan
print("\n[6/10] Waiting for passive scan...")
time.sleep(5)
while int(zap.pscan.records_to_scan) > 0:
    remaining = int(zap.pscan.records_to_scan)
    print(f"    Passive scan: {remaining} records remaining", end='\r')
    time.sleep(2)
print("\n  ✓ Passive scan complete")

# [7/10] Active scan
print(f"\n[7/10] Starting AGGRESSIVE Active scan...")
print(f"  Policy: {policy_name}")
print(f"  Scanners: {configured_count} at INSANE strength")
print(f"  Threshold: LOW (maximum sensitivity)")

ascan_id = zap.ascan.scan(
    url=JUICESHOP_URL,
    recurse=True,
    inscopeonly=False,
    scanpolicyname=policy_name,
    method=None,
    postdata=None
)

while int(zap.ascan.status(ascan_id)) < 100:
    status = int(zap.ascan.status(ascan_id))
    print(f"    Active scan: {status}%", end='\r')
    time.sleep(5)

print("\n  ✓ Active scan complete")

# [8/10] Collect results
print("\n[8/10] Collecting results...")
alerts = zap.core.alerts(baseurl=JUICESHOP_URL)
print(f"✓ Found {len(alerts)} total alerts")

# Save to file
output_file = "scans/juiceshop_scan.json"
with open(output_file, 'w') as f:
    json.dump(alerts, f, indent=2)
print(f"✓ Saved to: {output_file}")

# [9/10] Analyze results
print("\n[9/10] Analyzing results...")

# Count by risk
risk_counts = {}
for alert in alerts:
    risk = alert.get('risk', 'Unknown')
    risk_counts[risk] = risk_counts.get(risk, 0) + 1

# Count injection plugins
injection_plugins = {'40018', '40019', '40012', '40014', '90020', '6', '7'}
found_plugins = set(str(alert.get('pluginId')) for alert in alerts)
found_injection = injection_plugins & found_plugins

print("\n" + "="*80)
print("RESULTS SUMMARY")
print("="*80)

for risk, count in sorted(risk_counts.items(), reverse=True):
    if risk in ['High', 'Critical', 'Medium']:
        print(f"  {risk}: {count}")

if found_injection:
    print("\n" + "="*80)
    print("INJECTION VULNERABILITIES FOUND")
    print("="*80)

    for plugin_id in sorted(found_injection):
        plugin_alerts = [a for a in alerts if str(a.get('pluginId')) == plugin_id]
        if plugin_alerts:
            name = plugin_alerts[0].get('alert', 'Unknown')
            print(f"\n✓ {name} (Plugin {plugin_id})")
            print(f"  Found in {len(plugin_alerts)} locations:")
            for alert in plugin_alerts[:3]:
                print(f"    • {alert.get('url', 'N/A')}")
else:
    print("\n" + "="*80)
    print("⚠️ NO INJECTION VULNERABILITIES FOUND")
    print("="*80)

# [10/10] Summary
print("\n[10/10] Scan complete!")
print(f"\nResults saved to: {output_file}")
print(f"Total alerts: {len(alerts)}")
print(f"Injection plugins found: {len(found_injection)}/{len(injection_plugins)}")

print("\n" + "="*80)
print("JUICE SHOP SCAN COMPLETE")
print("="*80)
