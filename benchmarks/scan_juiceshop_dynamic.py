#!/usr/bin/env python3
"""
OWASP Juice Shop Scanner with Dynamic Discovery
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
JUICESHOP_URL = "http://juiceshop:3000"
ZAP_API_KEY = "changeme"
ZAP_HOST = "localhost"
ZAP_PORT = 8090
SCAN_OUTPUT = "scans/juiceshop_scan_dynamic.json"

print("="*80)
print("JUICE SHOP SCAN WITH DYNAMIC SCANNER DISCOVERY")
print("="*80)

# Connect to ZAP
print("\n[1/10] Connecting to ZAP...")
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
print("\n[2/10] Creating new ZAP session...")
zap.core.new_session(name="juiceshop_dynamic", overwrite=True)
print("  ✓ Session created")

# Discover scanners
print("\n[3/10] Discovering available scanners...")
discovery = ScannerDiscovery(zap)
injection_scanners = discovery.get_injection_scanners()

print(f"  ✓ Found {len(injection_scanners)} injection scanners")

# Show breakdown
sql_ids = discovery.get_scanner_ids_by_type('sql_injection')
xss_ids = discovery.get_scanner_ids_by_type('xss')
code_ids = discovery.get_scanner_ids_by_type('code_injection')

print(f"  → SQL Injection: {len(sql_ids)} scanners")
print(f"  → XSS: {len(xss_ids)} scanners")
print(f"  → Code Injection: {len(code_ids)} scanners")

# Create aggressive policy
print("\n[4/10] Creating aggressive scan policy with discovered scanners...")
policy_name = "JuiceShop-Dynamic-Aggressive"

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
    scanner_name = scanner['name']

    try:
        # Set threshold to LOW (detect even low-confidence issues)
        zap.ascan.set_scanner_alert_threshold(
            id=scanner_id,
            alertthreshold='LOW',
            scanpolicyname=policy_name
        )

        # Set strength to INSANE (maximum attack intensity)
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
        expected_scanner_ids.append(scanner_id)
        print(f"  ✓ {scanner_name} (ID: {scanner_id}) - INSANE/LOW")

    except Exception as e:
        print(f"  ! {scanner_name}: {e}")

print(f"\n  ✓ Configured {configured_count} scanners")

# Verify scanner configuration
print("\n[5/10] Verifying scanner configuration...")
verifier = ScannerVerifier(zap)
pre_results = verifier.verify_scanner_configuration(policy_name, expected_scanner_ids[:10])

if not pre_results.get('all_enabled'):
    print(f"  ⚠ Some scanners not properly enabled:")
    print(f"    - Enabled: {pre_results['enabled_count']}")
    print(f"    - Disabled: {pre_results['disabled_count']}")
    print(f"    - Not found: {pre_results['not_found_count']}")
    print(f"  → Continuing anyway...")
else:
    print(f"  ✓ All {pre_results['enabled_count']} scanners verified")

# Access target
print(f"\n[6/10] Accessing Juice Shop...")
zap.core.access_url(url=JUICESHOP_URL, followredirects=True)
time.sleep(3)
print(f"  ✓ Accessed {JUICESHOP_URL}")

# Spider scan
print("\n[7/10] Starting Spider scan...")
print("  Note: Juice Shop is a modern SPA (Single Page Application)")
print("  Traditional spider may have limited effectiveness")

spider_id = zap.spider.scan(url=JUICESHOP_URL, maxchildren=None, recurse=True)

while int(zap.spider.status(spider_id)) < 100:
    status = int(zap.spider.status(spider_id))
    print(f"    Spider: {status}%", end='\r')
    time.sleep(2)

spider_results = zap.spider.results(spider_id)
print(f"\n  ✓ Spider found {len(spider_results)} URLs")

# Show sample URLs
if spider_results:
    print(f"\n  Sample discovered URLs:")
    for url in spider_results[:10]:
        print(f"    • {url}")

# Ajax Spider (better for SPAs)
print("\n[8/10] Starting AJAX Spider (for SPA support)...")
zap.ajaxSpider.scan(url=JUICESHOP_URL)

time.sleep(5)  # Give it time to start

ajax_running = True
ajax_timeout = 300  # 5 minutes max
ajax_start = time.time()

while ajax_running and (time.time() - ajax_start) < ajax_timeout:
    status = zap.ajaxSpider.status
    if status == "stopped":
        ajax_running = False
    print(f"    AJAX Spider: {status}", end='\r')
    time.sleep(3)

ajax_results = zap.ajaxSpider.results()
print(f"\n  ✓ AJAX Spider found {len(ajax_results)} additional URLs")

# Active scan
print("\n[9/10] Starting Active scan with aggressive policy...")
print(f"  Policy: {policy_name}")
print(f"  Scanners: {configured_count} injection scanners")
print(f"  Note: This will take 15-30 minutes with INSANE strength")

ascan_id = zap.ascan.scan(
    url=JUICESHOP_URL,
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
print("\n[10/10] Collecting results...")

alerts = zap.core.alerts(baseurl=JUICESHOP_URL)
print(f"  ✓ Found {len(alerts)} total alerts")

# Save to file
with open(SCAN_OUTPUT, 'w') as f:
    json.dump(alerts, f, indent=2)

print(f"  ✓ Saved to: {SCAN_OUTPUT}")

# Post-scan verification
print("\n" + "="*80)
print("POST-SCAN VERIFICATION")
print("="*80)

post_results = verifier.verify_scan_results(expected_scanner_ids[:10], JUICESHOP_URL)

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
injection_alerts = []

for alert in alerts:
    alert_name = alert.get('alert', '').lower()
    if any(keyword in alert_name for keyword in injection_keywords):
        injection_alerts.append(alert)

print(f"\n" + "="*80)
print(f"INJECTION VULNERABILITIES FOUND: {len(injection_alerts)}")
print("="*80)

if injection_alerts:
    # Group by type
    by_type = {}
    for alert in injection_alerts:
        alert_type = alert.get('alert', 'Unknown')
        if alert_type not in by_type:
            by_type[alert_type] = []
        by_type[alert_type].append(alert)

    for alert_type, alerts_of_type in sorted(by_type.items()):
        print(f"\n✓ {alert_type}:")
        print(f"    • {len(alerts_of_type)} instances")

        # Show first instance
        sample = alerts_of_type[0]
        print(f"        {sample.get('url', 'N/A')}")
else:
    print("\n⚠ No injection vulnerabilities detected")
    print("\nPossible reasons:")
    print("  1. Juice Shop may require authenticated scanning")
    print("  2. SPA architecture limits traditional scanning")
    print("  3. May need specialized REST API scanning")

# Show top alerts by type
print(f"\n" + "="*80)
print("TOP VULNERABILITY TYPES")
print("="*80)

alert_types = {}
for alert in alerts:
    alert_type = alert.get('alert', 'Unknown')
    alert_types[alert_type] = alert_types.get(alert_type, 0) + 1

for alert_type, count in sorted(alert_types.items(), key=lambda x: x[1], reverse=True)[:15]:
    print(f"  • {alert_type}: {count} instances")

print("\n" + "="*80)
print(f"Scan complete! Results saved to: {SCAN_OUTPUT}")
print("="*80)

# Success rate
if post_results.get('success_rate'):
    print(f"\nScanner Detection Rate: {post_results['success_rate']:.1f}%")
    print(f"  Scanners that found vulnerabilities: {post_results['scanners_fired_count']}/{post_results['expected_scanner_count']}")
