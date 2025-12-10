#!/usr/bin/env python3
"""
OWASP WebGoat Scanner with Dynamic Discovery
Uses the new dynamic scanner discovery system
"""

import sys
import time
import json
from zapv2 import ZAPv2

# Add benchmarks to path
sys.path.insert(0, '/Users/Dari/Desktop/OWASPpr/benchmarks')

from zap_scanner_discovery import ScannerDiscovery
from zap_scanner_verifier import ScannerVerifier

# Configuration
WEBGOAT_URL = "http://webgoat:8080/WebGoat"
ZAP_API_KEY = "changeme"
ZAP_HOST = "localhost"
ZAP_PORT = 8090
SCAN_OUTPUT = "scans/webgoat_scan_dynamic.json"

print("="*80)
print("WEBGOAT SCAN WITH DYNAMIC SCANNER DISCOVERY")
print("="*80)

# Connect to ZAP
print("\n[1/9] Connecting to ZAP...")
zap = ZAPv2(
    apikey=ZAP_API_KEY,
    proxies={
        'http': f'http://{ZAP_HOST}:{ZAP_PORT}',
        'https': f'http://{ZAP_HOST}:{ZAP_PORT}'
    }
)

try:
    version = zap.core.version
    print(f"  ✓ Connected to ZAP version: {version}")
except Exception as e:
    print(f"  ✗ Failed to connect to ZAP: {e}")
    sys.exit(1)

# New session
print("\n[2/9] Creating new ZAP session...")
zap.core.new_session(name="webgoat_dynamic", overwrite=True)
print("  ✓ Session created")

# Discover scanners
print("\n[3/9] Discovering available scanners...")
discovery = ScannerDiscovery(zap)
injection_scanners = discovery.get_injection_scanners()

print(f"  ✓ Found {len(injection_scanners)} injection scanners")

# Create aggressive policy
print("\n[4/9] Creating aggressive scan policy...")
policy_name = "WebGoat-Dynamic-Aggressive"

try:
    zap.ascan.remove_scan_policy(scanpolicyname=policy_name)
except:
    pass

zap.ascan.add_scan_policy(scanpolicyname=policy_name)

# Configure discovered injection scanners
configured_count = 0
expected_scanner_ids = []

for scanner in injection_scanners:
    scanner_id = scanner['id']
    try:
        zap.ascan.set_scanner_alert_threshold(
            id=scanner_id,
            alertthreshold='LOW',
            scanpolicyname=policy_name
        )
        zap.ascan.set_scanner_attack_strength(
            id=scanner_id,
            attackstrength='INSANE',
            scanpolicyname=policy_name
        )
        zap.ascan.enable_scanners(
            ids=scanner_id,
            scanpolicyname=policy_name
        )
        configured_count += 1
        expected_scanner_ids.append(scanner_id)
    except Exception as e:
        pass

print(f"  ✓ Configured {configured_count} scanners")

# Verify configuration
print("\n[5/9] Verifying scanner configuration...")
verifier = ScannerVerifier(zap)
pre_results = verifier.verify_scanner_configuration(policy_name, expected_scanner_ids[:10])
print(f"  ✓ Verified {pre_results['enabled_count']} scanners")

# Access target
print(f"\n[6/9] Accessing WebGoat...")
zap.core.access_url(url=WEBGOAT_URL, followredirects=True)
time.sleep(3)
print(f"  ✓ Accessed {WEBGOAT_URL}")

# Spider scan
print("\n[7/9] Starting Spider scan...")
spider_id = zap.spider.scan(url=WEBGOAT_URL, maxchildren=None, recurse=True)

while int(zap.spider.status(spider_id)) < 100:
    status = int(zap.spider.status(spider_id))
    print(f"    Spider: {status}%", end='\r')
    time.sleep(2)

spider_results = zap.spider.results(spider_id)
print(f"\n  ✓ Spider found {len(spider_results)} URLs")

# Active scan
print("\n[8/9] Starting Active scan with aggressive policy...")
print(f"  Note: This will take 15-30 minutes with INSANE strength")

ascan_id = zap.ascan.scan(
    url=WEBGOAT_URL,
    recurse=True,
    inscopeonly=False,
    scanpolicyname=policy_name
)

print(f"  ✓ Active scan started (ID: {ascan_id})")

# Monitor progress
last_progress = 0
while int(zap.ascan.status(ascan_id)) < 100:
    progress = int(zap.ascan.status(ascan_id))
    if progress > last_progress:
        print(f"    Active scan: {progress}%", end='\r')
        last_progress = progress
    time.sleep(5)

print(f"\n  ✓ Active scan complete")

# Collect results
print("\n[9/9] Collecting results...")

alerts = zap.core.alerts(baseurl=WEBGOAT_URL)
print(f"  ✓ Found {len(alerts)} total alerts")

# Save to file
with open(SCAN_OUTPUT, 'w') as f:
    json.dump(alerts, f, indent=2)

print(f"  ✓ Saved to: {SCAN_OUTPUT}")

# Analysis
print("\n" + "="*80)
print("RESULTS ANALYSIS")
print("="*80)

# Count by risk
risk_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
for alert in alerts:
    risk = alert.get('risk', 'Informational')
    risk_counts[risk] = risk_counts.get(risk, 0) + 1

print(f"\nAlerts by risk level:")
for risk, count in risk_counts.items():
    print(f"  {risk}: {count}")

# Find injection vulnerabilities
injection_keywords = ['injection', 'xss', 'scripting', 'command', 'code']
injection_alerts = [a for a in alerts if any(kw in a.get('alert', '').lower() for kw in injection_keywords)]

print(f"\n" + "="*80)
print(f"INJECTION VULNERABILITIES FOUND: {len(injection_alerts)}")
print("="*80)

if injection_alerts:
    by_type = {}
    for alert in injection_alerts:
        alert_type = alert.get('alert', 'Unknown')
        if alert_type not in by_type:
            by_type[alert_type] = []
        by_type[alert_type].append(alert)

    for alert_type, alerts_of_type in sorted(by_type.items()):
        print(f"\n✓ {alert_type}:")
        print(f"    • {len(alerts_of_type)} instances")
        sample = alerts_of_type[0]
        print(f"        {sample.get('url', 'N/A')}")
else:
    print("\n⚠ No injection vulnerabilities detected")

print("\n" + "="*80)
print(f"Scan complete! Results saved to: {SCAN_OUTPUT}")
print("="*80)

# Post-scan verification
post_results = verifier.verify_scan_results(expected_scanner_ids[:10], WEBGOAT_URL)
if post_results.get('success_rate'):
    print(f"\nScanner Detection Rate: {post_results['success_rate']:.1f}%")
