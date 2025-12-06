# 📋 Next Session Tasks - Benchmark Testing

## 🎯 Main Goal

Collect benchmark metrics for Q2 journal publication by testing the Vulnerability Chain Detection system on standard vulnerable applications.

---

## ✅ Current Status (What's Done)

### Completed ✅
- ✅ Core system implementation (3,739 lines)
- ✅ Web UI with REST API (1,374 lines)
- ✅ 15 chain detection rules
- ✅ Smoke test passing
- ✅ All dependencies installed
- ✅ Bugs fixed (RiskLevel comparison)
- ✅ Documentation complete

### Verified Working ✅
```bash
# This works:
python test_smoke.py
# Output: ✅ 2 chains detected, 0.002s

# This works:
python run_web_ui.py
# Web UI at http://localhost:8000

# This works:
from vulnerability_chains import analyze_zap_scan
result = analyze_zap_scan('report.json')
```

---

## 🔬 What Needs to Be Done

### Phase 1: Setup Test Environments

**Goal**: Get vulnerable applications running and scanned with OWASP ZAP

#### Option A: DVWA (Recommended First)
```bash
# 1. Run DVWA with Docker
docker run --rm -it -p 80:80 vulnerables/web-dvwa

# 2. Scan with ZAP
zap.sh -cmd -quickurl http://localhost -quickout dvwa_scan.json

# 3. Analyze with our system
python benchmark_dvwa.py  # You'll create this
```

#### Option B: OWASP WebGoat
```bash
docker run -p 8080:8080 -p 9090:9090 webgoat/goatandwolf
zap.sh -cmd -quickurl http://localhost:8080/WebGoat -quickout webgoat_scan.json
python benchmark_webgoat.py
```

#### Option C: OWASP Juice Shop
```bash
docker run -p 3000:3000 bkimminich/juice-shop
zap.sh -cmd -quickurl http://localhost:3000 -quickout juiceshop_scan.json
python benchmark_juiceshop.py
```

---

### Phase 2: Create Benchmark Scripts

**File**: `benchmark_dvwa.py` (example)

```python
#!/usr/bin/env python3
"""
Benchmark test for DVWA - Damn Vulnerable Web Application.

This script:
1. Loads ZAP scan results
2. Analyzes with chain detection
3. Compares with known chains (ground truth)
4. Calculates metrics
5. Generates report
"""

import json
import time
from vulnerability_chains import VulnerabilityChainAnalyzer

# Known chains in DVWA (ground truth)
KNOWN_DVWA_CHAINS = [
    {
        'id': 'dvwa_chain_1',
        'type': 'sql_injection_to_priv_esc',
        'path': ['SQL Injection', 'Privilege Escalation'],
        'urls': ['/vulnerabilities/sqli/', '/admin/']
    },
    {
        'id': 'dvwa_chain_2',
        'type': 'xss_to_csrf',
        'path': ['Cross Site Scripting', 'Anti-CSRF Tokens Check'],
        'urls': ['/vulnerabilities/xss_r/', '/vulnerabilities/csrf/']
    },
    # Add more known chains...
]

def benchmark_dvwa(zap_report_file: str):
    """Run benchmark on DVWA scan results."""

    print("="*70)
    print("🧪 BENCHMARK: DVWA - Damn Vulnerable Web Application")
    print("="*70)

    # 1. Load and analyze
    print("\n1️⃣  Loading ZAP report...")
    analyzer = VulnerabilityChainAnalyzer()

    start_time = time.time()
    result = analyzer.analyze_zap_report(
        report_file=zap_report_file,
        max_chain_length=5,
        min_confidence=0.6,
        min_risk_filter='Low'
    )
    analysis_time = time.time() - start_time

    print(f"   ✅ Analysis complete in {analysis_time:.3f}s")
    print(f"   📊 Found {result.total_chains} chains")

    # 2. Compare with ground truth
    print("\n2️⃣  Comparing with known chains...")

    detected_chains = result.chains
    true_positives = 0
    false_positives = 0
    false_negatives = 0

    # Manual comparison (you'll need to map chains)
    for known in KNOWN_DVWA_CHAINS:
        found = False
        for detected in detected_chains:
            if chain_matches(detected, known):
                true_positives += 1
                found = True
                break
        if not found:
            false_negatives += 1

    # Count false positives (detected but not in ground truth)
    for detected in detected_chains:
        if not matches_any_known(detected, KNOWN_DVWA_CHAINS):
            false_positives += 1

    # 3. Calculate metrics
    print("\n3️⃣  Calculating metrics...")

    total_known = len(KNOWN_DVWA_CHAINS)
    detection_rate = true_positives / total_known if total_known > 0 else 0
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    metrics = {
        'dataset': 'DVWA',
        'total_vulnerabilities': result.total_vulnerabilities,
        'total_chains_detected': result.total_chains,
        'total_known_chains': total_known,
        'true_positives': true_positives,
        'false_positives': false_positives,
        'false_negatives': false_negatives,
        'detection_rate': detection_rate,
        'precision': precision,
        'recall': recall,
        'f1_score': f1_score,
        'analysis_time': analysis_time,
        'critical_chains': result.critical_chains,
        'high_risk_chains': result.high_risk_chains
    }

    # 4. Print results
    print("\n" + "="*70)
    print("📊 BENCHMARK RESULTS")
    print("="*70)
    print(f"Dataset: DVWA")
    print(f"\nVulnerabilities Found: {metrics['total_vulnerabilities']}")
    print(f"Chains Detected: {metrics['total_chains_detected']}")
    print(f"Known Chains: {metrics['total_known_chains']}")
    print(f"\nTrue Positives: {metrics['true_positives']}")
    print(f"False Positives: {metrics['false_positives']}")
    print(f"False Negatives: {metrics['false_negatives']}")
    print(f"\n📈 Metrics:")
    print(f"Detection Rate: {detection_rate:.2%}")
    print(f"Precision: {precision:.2%}")
    print(f"Recall: {recall:.2%}")
    print(f"F1 Score: {f1_score:.2%}")
    print(f"\n⏱️  Analysis Time: {analysis_time:.3f}s")
    print("="*70)

    # 5. Save results
    with open('benchmark_dvwa_results.json', 'w') as f:
        json.dump(metrics, f, indent=2)

    print(f"\n✅ Results saved to benchmark_dvwa_results.json")

    return metrics

def chain_matches(detected, known):
    """Check if detected chain matches known chain."""
    # Implement matching logic
    # Compare vulnerability types, URLs, etc.
    pass

def matches_any_known(detected, known_chains):
    """Check if detected chain matches any known chain."""
    return any(chain_matches(detected, known) for known in known_chains)

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python benchmark_dvwa.py <zap_report.json>")
        sys.exit(1)

    benchmark_dvwa(sys.argv[1])
```

---

### Phase 3: Define Ground Truth

**Create**: `ground_truth/dvwa_chains.json`

```json
{
  "dataset": "DVWA v1.10",
  "total_known_chains": 8,
  "chains": [
    {
      "id": "dvwa_sqli_to_priv",
      "name": "SQL Injection to Privilege Escalation",
      "vulnerabilities": [
        {
          "type": "SQL Injection",
          "url": "/vulnerabilities/sqli/",
          "param": "id"
        },
        {
          "type": "Privilege Escalation",
          "url": "/admin/users.php",
          "param": "role"
        }
      ],
      "chain_type": "privilege_escalation",
      "description": "SQL injection allows modifying user roles",
      "verified": true
    },
    {
      "id": "dvwa_xss_to_csrf",
      "name": "XSS to CSRF Bypass",
      "vulnerabilities": [
        {
          "type": "Cross Site Scripting",
          "url": "/vulnerabilities/xss_r/",
          "param": "name"
        },
        {
          "type": "Anti-CSRF Tokens Check",
          "url": "/vulnerabilities/csrf/",
          "param": "password"
        }
      ],
      "chain_type": "authentication_bypass",
      "description": "XSS steals CSRF token for admin actions",
      "verified": true
    }
  ]
}
```

---

### Phase 4: Metrics to Collect

**Create table** like this:

| Dataset | Vulns | Chains Found | Known Chains | Detection Rate | Precision | Recall | F1 | Time (s) |
|---------|-------|--------------|--------------|----------------|-----------|--------|-----|----------|
| DVWA    | 45    | 12           | 10           | 80%            | 67%       | 80%    | 0.73| 2.34     |
| WebGoat | 78    | 18           | 15           | 73%            | 61%       | 73%    | 0.67| 4.12     |
| Juice   | 52    | 15           | 12           | 75%            | 60%       | 75%    | 0.67| 3.08     |

**Formulas**:
- Detection Rate = True Positives / Total Known Chains
- Precision = True Positives / (True Positives + False Positives)
- Recall = True Positives / (True Positives + False Negatives)
- F1 Score = 2 × (Precision × Recall) / (Precision + Recall)

---

### Phase 5: Comparison with Baseline

**Compare with regular ZAP**:

| Metric | Regular ZAP | Chain Detection | Improvement |
|--------|-------------|-----------------|-------------|
| Critical Alerts | 5 | 12 | +140% |
| Risk Prioritization | Manual | Automatic | N/A |
| Exploit Paths | Not shown | Visualized | N/A |
| Analysis Time | Instant | 2.34s | -2.34s |

---

## 🔧 Tools & Scripts Needed

### 1. Benchmark Runner
```bash
# Create: run_benchmarks.py
python run_benchmarks.py --dataset dvwa --report dvwa_scan.json
python run_benchmarks.py --dataset webgoat --report webgoat_scan.json
python run_benchmarks.py --dataset juiceshop --report juiceshop_scan.json
```

### 2. Ground Truth Creator
```bash
# Create: create_ground_truth.py
# Helps manually verify and document known chains
python create_ground_truth.py --dataset dvwa --output ground_truth/dvwa.json
```

### 3. Metrics Aggregator
```bash
# Create: aggregate_metrics.py
# Combines all benchmark results into tables/graphs
python aggregate_metrics.py --output benchmark_results.csv
```

---

## 📊 Expected Deliverables

1. **Benchmark Scripts**:
   - `benchmark_dvwa.py`
   - `benchmark_webgoat.py`
   - `benchmark_juiceshop.py`

2. **Ground Truth Data**:
   - `ground_truth/dvwa_chains.json`
   - `ground_truth/webgoat_chains.json`
   - `ground_truth/juiceshop_chains.json`

3. **Results**:
   - `benchmark_results.csv` (metrics table)
   - `benchmark_report.pdf` (or MD with graphs)
   - Individual result JSON files

4. **Comparison**:
   - Regular ZAP vs Chain Detection
   - Performance analysis
   - False positive analysis

---

## 🎯 Success Criteria

**Minimum Acceptable**:
- Detection Rate: ≥ 60%
- Precision: ≥ 70%
- F1 Score: ≥ 0.65
- Analysis Time: < 10s for 100 vulnerabilities

**Target (for publication)**:
- Detection Rate: ≥ 70%
- Precision: ≥ 80%
- F1 Score: ≥ 0.75
- Demonstrable improvement over baseline

---

## 💡 Tips for Next Session

### Quick Start Commands
```bash
# 1. Verify system works
python test_smoke.py

# 2. Check git status
git log --oneline -5

# 3. Read technical docs
cat TECHNICAL_DOCS.md | less

# 4. Start DVWA
docker run -p 80:80 vulnerables/web-dvwa

# 5. Scan with ZAP
zap.sh -cmd -quickurl http://localhost -quickout dvwa.json

# 6. Create benchmark script
# (use template above)
```

### Key Files to Reference
- `test_smoke.py` - Example test structure
- `vulnerability_chains/analyzer.py` - Main API
- `TECHNICAL_DOCS.md` - Complete technical reference
- `vulnerability_chains/config/chain_rules.json` - Rules

### Common Gotchas
1. **ZAP not installed**: `docker run -u zap -p 8080:8080 owasp/zap2docker-stable`
2. **Vulnerable apps not running**: Use Docker commands above
3. **Wrong ZAP format**: Ensure using JSON output (`-quickout file.json`)
4. **No chains detected**: Lower min_confidence to 0.5, check logs

---

## 📞 Questions for User (if needed)

1. Do you have OWASP ZAP installed?
2. Can you run Docker containers?
3. Which dataset should we start with? (Recommend: DVWA)
4. Do you have existing ZAP scans or need to create new ones?
5. What's your publication timeline?

---

## 🚀 Recommended Action Plan

**Session Start**:
1. Read TECHNICAL_DOCS.md (5 min)
2. Run smoke test (30 sec)
3. Choose dataset (DVWA recommended)
4. Get ZAP scan of dataset
5. Create benchmark script
6. Run and collect metrics
7. Repeat for other datasets
8. Aggregate results
9. Create comparison tables

**Time Estimate**: 2-4 hours per dataset

---

**Current Status**: ✅ System ready, waiting for benchmark data

**Next Action**: Start with DVWA benchmark

**Priority**: HIGH - Needed for publication

**Difficulty**: Medium - Need manual ground truth verification
