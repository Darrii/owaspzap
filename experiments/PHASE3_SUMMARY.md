# Phase 3 Results Summary - Q2 Publication

**Generated:** 2025-12-25
**Applications Tested:** DVWA, OWASP Juice Shop, OWASP WebGoat

---

## Executive Summary

Successfully completed Phase 3 data processing and visualization for Q2 academic publication. Generated 12 table files (4 tables × 3 formats) and 8 graph files (4 figures × 2 formats).

---

## Experimental Results

### DVWA (Damn Vulnerable Web Application)
- **Vulnerabilities:** 194 total, 9 unique types
- **Graph:** 136 nodes, 18,392 edges
- **Chains:** 9,828 total → **8 unique patterns**
- **Deduplication:** 99.92% reduction
- **Processing Time:** 30.11s
- **Risk Distribution:** 4 HIGH/MEDIUM (60-69), 4 MEDIUM (50-59)

**Top Chains:**
1. Missing Security Headers → Missing Security Headers → Path Traversal (risk=63.3)
2. Missing Security Headers → Missing Security Headers → Cross Site Scripting (risk=63.3)
3. Missing Security Headers → Missing Security Headers → SQL Injection (risk=63.3)

### OWASP Juice Shop
- **Vulnerabilities:** 623 total, 6 unique types
- **Graph:** 564 nodes, 317,591 edges
- **Chains:** 9,936 total → **50 unique patterns**
- **Deduplication:** 99.50% reduction
- **Processing Time:** 950.31s (15.8 min)
- **Risk Distribution:** 2 MEDIUM (60-69)

**Top Chains:**
1. Cross-Domain Misconfiguration → Command Injection → SQL Injection (risk=65.7)
2. Cross-Domain Misconfiguration × 4 (risk=60.1)

### OWASP WebGoat
- **Vulnerabilities:** 25 total, 5 unique types
- **Graph:** 21 nodes, 424 edges
- **Chains:** 9,080 total → **27 unique patterns**
- **Deduplication:** 99.70% reduction
- **Processing Time:** 13.44s
- **Risk Distribution:** 7 MEDIUM (60-69), 18 MEDIUM (50-59), 2 LOW (<50)

**Top Chains:**
1. Session Fixation → SQL Injection → SQL Injection (risk=65.7)
2. Missing Security Headers → SQL Injection → SQL Injection (risk=65.7)
3. Anti-CSRF Tokens Check → SQL Injection → SQL Injection (risk=65.7)

---

## Overall Statistics

- **Total Vulnerabilities Scanned:** 842
- **Total Unique Chains Discovered:** 85
- **Average Deduplication Rate:** 99.71%
- **Total Graph Nodes:** 721
- **Total Graph Edges:** 336,407

---

## Generated Deliverables

### Tables (experiments/results/tables/)

#### Table IV: Test Applications Overview
- Formats: Excel (.xlsx), CSV (.csv), LaTeX (.tex)
- Content: Application descriptions, vulnerability counts, graph statistics

#### Table V: Baseline vs Enhanced System Comparison
- Formats: Excel (.xlsx), CSV (.csv), LaTeX (.tex)
- Content: Chain detection performance, deduplication metrics, processing times

#### Table VI: System Performance Metrics
- Formats: Excel (.xlsx), CSV (.csv), LaTeX (.tex)
- Content: Graph build time, detection time, throughput, risk analysis

#### Table VII: Vulnerability Chain Characteristics
- Formats: Excel (.xlsx), CSV (.csv), LaTeX (.tex)
- Content: Chain length distribution, risk score ranges, averages

### Graphs (experiments/results/graphs/)

#### Figure 4: Chain Detection Performance
- Formats: PNG (300 DPI), PDF (vector)
- Content: Processing time comparison, total chains found per application

#### Figure 5: Deduplication Effectiveness
- Formats: PNG (300 DPI), PDF (vector)
- Content: Before/after deduplication comparison, deduplication rates

#### Figure 6: Risk Score Distribution
- Formats: PNG (300 DPI), PDF (vector)
- Content: Histograms showing risk score distribution for each application

#### Figure 8: Chain Length Distribution
- Formats: PNG (300 DPI), PDF (vector)
- Content: Bar chart showing distribution of chain lengths (2, 3, 4) per application

---

## Key Findings

1. **High Deduplication Efficiency:** Average 99.71% reduction in duplicate chains across all applications
2. **Scalability:** System handles graphs with 300K+ edges (JuiceShop) in reasonable time (~16 min)
3. **Real Vulnerability Detection:** Successfully detected critical chains including SQL Injection, XSS, Path Traversal, Command Injection
4. **Consistent Performance:** Deduplication rate remains high (99.5-99.9%) across applications of varying sizes

---

## Technical Details

### System Configuration
- Min link probability: 0.3
- Max boost multiplier: 2.5
- Min chain probability: 0.2
- Max chain length: 4
- Cluster links: Disabled

### Chain Detection Algorithm
- Method: Depth-First Search (DFS) with bounded boosting
- Deduplication: Pattern-based (tuple signatures)
- Risk Scoring: Component-based (0-100 scale)
  - Base Severity: 30%
  - Exploitability: 30%
  - Chain Length: 20%
  - Confidence: 20%

---

## Files Structure

```
experiments/results/
├── tables/
│   ├── table_iv_applications.{xlsx,csv,tex}
│   ├── table_v_comparison.{xlsx,csv,tex}
│   ├── table_vi_performance.{xlsx,csv,tex}
│   └── table_vii_characteristics.{xlsx,csv,tex}
├── graphs/
│   ├── figure_4_performance.{png,pdf}
│   ├── figure_5_deduplication.{png,pdf}
│   ├── figure_6_risk_distribution.{png,pdf}
│   └── figure_8_length_distribution.{png,pdf}
└── raw_data/
    ├── dvwa/
    │   ├── baseline_zap.json
    │   ├── enhanced_system.json
    │   └── filtered_chains.json (8 unique)
    ├── juiceshop/
    │   ├── baseline_zap.json
    │   ├── enhanced_system.json
    │   └── filtered_chains.json (50 unique)
    └── webgoat/
        ├── baseline_zap.json
        ├── enhanced_system.json
        └── filtered_chains.json (27 unique)
```

---

## Status: ✅ PHASE 3 COMPLETED

All deliverables for Q2 publication have been generated successfully. Ready for integration into research paper.

---

**Next Steps (if needed):**
- Review tables and graphs for publication quality
- Integrate into LaTeX manuscript
- Add analysis and discussion sections
- Prepare supplementary materials
