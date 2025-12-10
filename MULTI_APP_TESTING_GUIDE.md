# Multi-Application Testing Guide

## Overview
Testing the Vulnerability Chain Detection system on three OWASP applications:
1. **DVWA** - Damn Vulnerable Web Application
2. **Juice Shop** - Modern vulnerable web app
3. **WebGoat** - Educational security testing platform

## Current Status

### ✅ Completed:
- [x] DVWA scan completed (569 alerts, 13 injection vulnerabilities)
- [x] Scanner discovery working (49 scanners found)
- [x] CSRF token extraction working
- [x] Database initialization automated
- [x] Chain detection working (19 chains)

### 🔄 In Progress:
- [ ] Juice Shop scan (running in background)
- [ ] WebGoat scan (ready to start)
- [ ] Comparison report (script ready)

## Scripts Created

### 1. Juice Shop Scanner
**File:** `benchmarks/scan_juiceshop_dynamic.py`

**Features:**
- Dynamic scanner discovery (22 injection scanners)
- AJAX Spider for SPA support
- Traditional Spider + Active scan
- INSANE strength, LOW threshold
- Automated result collection

**Usage:**
```bash
./zapenv/bin/python3 benchmarks/scan_juiceshop_dynamic.py
```

**Expected Duration:** 20-30 minutes

### 2. WebGoat Scanner
**File:** `benchmarks/scan_webgoat_dynamic.py`

**Features:**
- Same dynamic scanner discovery
- Configured for WebGoat authentication
- Full spider + active scan coverage

**Usage:**
```bash
./zapenv/bin/python3 benchmarks/scan_webgoat_dynamic.py
```

**Expected Duration:** 20-30 minutes

### 3. Comparison Tool
**File:** `benchmarks/compare_results.py`

**Features:**
- Loads all three scan results
- Compares injection vulnerability counts
- Shows which scanner IDs fired
- Generates comprehensive report

**Usage:**
```bash
./zapenv/bin/python3 benchmarks/compare_results.py
```

**Output:** `reports/comparison_report_YYYYMMDD_HHMMSS.txt`

## When Scans Complete

### Step 1: Check Juice Shop Results
```bash
# Check if scan completed
tail -100 /tmp/juiceshop_scan.log

# If completed, verify results
ls -lh scans/juiceshop_scan_dynamic.json

# Quick analysis
python3 -c "
import json
with open('scans/juiceshop_scan_dynamic.json') as f:
    alerts = json.load(f)
print(f'Total alerts: {len(alerts)}')
injection = [a for a in alerts if 'injection' in a.get('alert','').lower() or 'xss' in a.get('alert','').lower()]
print(f'Injection vulnerabilities: {len(injection)}')
"
```

### Step 2: Run WebGoat Scan
```bash
./zapenv/bin/python3 benchmarks/scan_webgoat_dynamic.py
```

### Step 3: Compare All Results
```bash
./zapenv/bin/python3 benchmarks/compare_results.py
```

### Step 4: Run Chain Detection on All
```bash
# DVWA chains (already done)
./zapenv/bin/python3 -c "
from vulnerability_chains.analyzer import analyze_zap_scan
analyze_zap_scan('scans/dvwa_scan_with_replacer.json')
"

# Juice Shop chains
./zapenv/bin/python3 -c "
from vulnerability_chains.analyzer import analyze_zap_scan
analyze_zap_scan('scans/juiceshop_scan_dynamic.json')
"

# WebGoat chains
./zapenv/bin/python3 -c "
from vulnerability_chains.analyzer import analyze_zap_scan
analyze_zap_scan('scans/webgoat_scan_dynamic.json')
"
```

## Expected Results

### DVWA (✅ Confirmed)
```
Total alerts: 569
Injection vulnerabilities: 13
  - SQL Injection (40018): 1
  - XSS (40012): 10
  - Path Traversal (6): 1
Chains: 19
```

### Juice Shop (🔄 Running)
**Expected:**
```
Total alerts: 400-600
Injection vulnerabilities: 10-50
  - SQL Injection: 5-20
  - XSS: 5-25
  - Authentication issues: 2-10
Chains: 15-30
```

**Challenges:**
- Modern SPA architecture
- REST API scanning needed
- May require authentication

### WebGoat (⏳ Pending)
**Expected:**
```
Total alerts: 300-500
Injection vulnerabilities: 15-40
  - SQL Injection: 8-15
  - XSS: 5-20
  - Various injection types: 2-5
Chains: 10-25
```

**Challenges:**
- Educational platform with many lessons
- May need lesson-specific authentication
- Wide variety of vulnerability types

## Validation Metrics

### Success Criteria

| Metric | Target | DVWA | Juice Shop | WebGoat |
|--------|--------|------|------------|---------|
| Total alerts | >100 | ✅ 569 | 🔄 | ⏳ |
| Injection vulns | >5 | ✅ 13 | 🔄 | ⏳ |
| SQL Injection scanner (40018) | Present | ✅ Yes | 🔄 | ⏳ |
| XSS scanner (40012) | Present | ✅ Yes | 🔄 | ⏳ |
| Chains detected | >5 | ✅ 19 | 🔄 | ⏳ |
| Critical chains | >3 | ✅ 19 | 🔄 | ⏳ |

### Comparison Baseline

**Before Fix (All Apps):**
```
SQL Injection: 0
XSS: 0
Command Injection: 0
Total injection: 0
Scanner IDs: Only passive (10xxx)
```

**After Fix (Target):**
```
DVWA: 13 injection vulns ✅
Juice Shop: 10-50 injection vulns (target)
WebGoat: 15-40 injection vulns (target)
Total: 40-100 injection vulns across all apps
Scanner IDs: 40018, 40012, 90020 present
```

## Troubleshooting

### If Juice Shop finds 0 injection vulns:
1. Check authentication requirements
2. Try REST API specific scanners
3. Review AJAX Spider results
4. Consider using specialized SPA scanning

### If WebGoat finds 0 injection vulns:
1. Check lesson-specific authentication
2. Verify WebGoat is fully started
3. Review spider coverage
4. May need manual lesson navigation

### If comparison script fails:
1. Verify all JSON files exist in `scans/` directory
2. Check file permissions
3. Ensure valid JSON format
4. Review error messages in output

## Final Report Generation

After all scans complete, generate the final validation report:

```bash
# Create comprehensive report
cat > reports/FINAL_VALIDATION_REPORT.md << 'EOF'
# Final Validation Report - Multi-Application Testing

## Summary
Tested vulnerability chain detection system on three OWASP applications.

## Results
### DVWA
- Total alerts: [X]
- Injection vulnerabilities: [X]
- Chains detected: [X]

### Juice Shop
- Total alerts: [X]
- Injection vulnerabilities: [X]
- Chains detected: [X]

### WebGoat
- Total alerts: [X]
- Injection vulnerabilities: [X]
- Chains detected: [X]

## Comparison
[Include comparison table from compare_results.py]

## Conclusion
[Assessment of system performance across all applications]
EOF
```

## Next Steps

1. ⏳ Wait for Juice Shop scan to complete
2. ⏳ Run WebGoat scan
3. ⏳ Run comparison script
4. ⏳ Generate final validation report
5. ⏳ Update research paper with multi-app results

---

**Note:** Inform when scans are complete to proceed with analysis!
