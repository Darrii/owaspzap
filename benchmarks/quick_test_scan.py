#!/usr/bin/env python3
"""
Quick Test Scan - Uses dynamic scanner discovery
Tests the complete fix: DB init → Discovery → Auth → Scan → Validation
"""

import sys
import time
from zapv2 import ZAPv2

# Add benchmarks to path
sys.path.insert(0, '/Users/Dari/Desktop/OWASPpr/benchmarks')

from zap_scanner_discovery import ScannerDiscovery
from zap_scanner_verifier import ScannerVerifier
from dvwa_database_initializer import DVWADatabaseInitializer
from scan_validator import ScanValidator

# Configuration
ZAP_API_KEY = "changeme"
ZAP_HOST = "localhost"
ZAP_PORT = 8090
DVWA_URL = "http://dvwa:80"
DVWA_HOST_URL = "http://localhost:8080"

print("="*80)
print("QUICK TEST SCAN WITH DYNAMIC DISCOVERY")
print("="*80)

# Step 1: Initialize DVWA database
print("\n[1/7] Initializing DVWA database...")
initializer = DVWADatabaseInitializer(DVWA_HOST_URL)
if not initializer.verify_database_initialized():
    print("  → Database not initialized, initializing now...")
    initializer.initialize(methods=['http'])
else:
    print("  ✓ Database already initialized")

# Step 2: Validate vulnerabilities exist
print("\n[2/7] Validating vulnerabilities exist...")
validator = ScanValidator(DVWA_HOST_URL)
validation_results = validator.validate_dvwa_vulnerabilities()

if validation_results.get('total_confirmed', 0) < 2:
    print("  ✗ Insufficient vulnerabilities found, cannot proceed")
    sys.exit(1)

print(f"  ✓ Confirmed {validation_results['total_confirmed']} vulnerabilities exist")

# Step 3: Connect to ZAP
print("\n[3/7] Connecting to ZAP...")
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

# Step 4: Discover scanners
print("\n[4/7] Discovering available scanners...")
discovery = ScannerDiscovery(zap)
injection_scanners = discovery.get_injection_scanners()
print(f"  ✓ Found {len(injection_scanners)} injection scanners")

# Show sample
sql_ids = discovery.get_scanner_ids_by_type('sql_injection')
xss_ids = discovery.get_scanner_ids_by_type('xss')
print(f"  → SQL Injection scanners: {len(sql_ids)} (IDs: {sql_ids[:5]}...)")
print(f"  → XSS scanners: {len(xss_ids)} (IDs: {xss_ids})")

# Step 5: Create and configure scan policy
print("\n[5/7] Creating aggressive scan policy with discovered scanners...")
policy_name = "DynamicDiscovery-Test"

try:
    zap.ascan.remove_scan_policy(scanpolicyname=policy_name)
except:
    pass

zap.ascan.add_scan_policy(scanpolicyname=policy_name)

# Configure discovered scanners
configured_count = 0
for scanner in injection_scanners[:10]:  # Use first 10 for quick test
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
    except Exception as e:
        print(f"  ! Failed to configure scanner {scanner_id}: {e}")

print(f"  ✓ Configured {configured_count} scanners")

# Step 6: Verify scanner configuration
print("\n[6/7] Verifying scanner configuration...")
verifier = ScannerVerifier(zap)
expected_ids = [s['id'] for s in injection_scanners[:10]]
pre_results = verifier.verify_scanner_configuration(policy_name, expected_ids)

if not pre_results.get('all_enabled'):
    print(f"  ⚠ Some scanners not enabled properly:")
    print(f"    - Enabled: {pre_results['enabled_count']}")
    print(f"    - Disabled: {pre_results['disabled_count']}")
    print(f"    - Not found: {pre_results['not_found_count']}")
else:
    print(f"  ✓ All {pre_results['enabled_count']} scanners properly configured")

# Step 7: Quick access scan (no spider/active for speed)
print("\n[7/7] Accessing vulnerable endpoints...")
print("  (Skipping full spider/active scan for quick test)")

# Just access some vulnerable pages
test_urls = [
    f"{DVWA_URL}/vulnerabilities/sqli/?id=1&Submit=Submit",
    f"{DVWA_URL}/vulnerabilities/xss_r/?name=test",
]

for url in test_urls:
    try:
        zap.core.access_url(url=url, followredirects=True)
        print(f"  ✓ Accessed: {url}")
    except Exception as e:
        print(f"  ! Failed to access {url}: {e}")

# Wait a bit for passive scanners
time.sleep(5)

# Check alerts
print("\n" + "="*80)
print("RESULTS SUMMARY")
print("="*80)

alerts = zap.core.alerts(baseurl=DVWA_URL)
print(f"\nTotal alerts found: {len(alerts)}")

# Group by plugin ID
plugin_counts = {}
for alert in alerts:
    plugin_id = alert.get('pluginId')
    plugin_name = alert.get('alert', 'Unknown')
    if plugin_id not in plugin_counts:
        plugin_counts[plugin_id] = {'name': plugin_name, 'count': 0}
    plugin_counts[plugin_id]['count'] += 1

print(f"\nAlerts by scanner (top 10):")
for plugin_id in sorted(plugin_counts.keys(), key=lambda x: plugin_counts[x]['count'], reverse=True)[:10]:
    info = plugin_counts[plugin_id]
    print(f"  • Plugin {plugin_id}: {info['name']} ({info['count']} alerts)")

# Check if injection scanners fired
expected_ids_set = set(expected_ids)
found_ids_set = set(plugin_counts.keys())
injection_found = expected_ids_set & found_ids_set

print(f"\nInjection scanners that found vulnerabilities: {len(injection_found)}/{len(expected_ids)}")
if injection_found:
    print(f"  Scanner IDs: {sorted(injection_found)}")
else:
    print("  ⚠ No injection scanners generated alerts")
    print("  → This was a quick test without full active scan")
    print("  → Run full scan with spider + active scan for complete results")

print("\n" + "="*80)
print("Quick test complete! For full test, run:")
print("  ./zapenv/bin/python3 benchmarks/zap_with_replacer.py")
print("="*80)
