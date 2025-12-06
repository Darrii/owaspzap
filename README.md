# 🔗 Vulnerability Chain Detection for OWASP ZAP

> **Graph-based analysis of compound exploits in web applications**

[![Status](https://img.shields.io/badge/status-ready%20for%20benchmarking-success)]()
[![Python](https://img.shields.io/badge/python-3.11+-blue)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()

## 🎯 What is This?

Traditional security scanners report vulnerabilities **in isolation**. This system detects **exploit chains** where multiple vulnerabilities combine to create critical attacks.

**Example**:
```
XSS (Medium) + CSRF (Medium) → Admin Takeover (CRITICAL)
```

## ⚡ Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Smoke Test
```bash
python test_smoke.py
```

**Expected**: ✅ 2 chains detected in 0.002s

### 3. Analyze ZAP Report
```bash
python -c "from vulnerability_chains import analyze_zap_scan; analyze_zap_scan('zap_report.json')"
```

### 4. Or Use Web UI
```bash
python run_web_ui.py
# Open http://localhost:8000
```

## 📊 Project Status

### ✅ Completed
- **Core System**: 3,739 lines of Python
- **Web Interface**: 1,374 lines (FastAPI + HTML/CSS/JS)
- **Chain Rules**: 15 pre-defined patterns
- **Documentation**: Complete
- **Smoke Test**: Passing

### 🔄 Next Steps (For New Session)
- [ ] Benchmark on DVWA
- [ ] Benchmark on WebGoat
- [ ] Benchmark on Juice Shop
- [ ] Collect metrics for publication
- [ ] Write research paper

## 📁 Project Structure

```
vulnerability_chains/          # Main package (3,739 lines)
├── analyzer.py               # Main interface ⭐
├── core/
│   ├── vulnerability_graph.py   # NetworkX graph
│   ├── chain_detector.py        # Path finding algorithm
│   └── chain_scoring.py         # Risk assessment
├── rules/
│   └── chain_rules.py           # Rule engine
├── utils/
│   └── zap_parser.py            # ZAP JSON parser
├── visualization/
│   └── graph_visualizer.py      # HTML reports
├── config/
│   └── chain_rules.json         # 15 rules ⭐
└── web/                      # Web UI (FastAPI)
    ├── app.py
    ├── templates/
    └── static/

test_smoke.py                 # Working test ⭐
run_web_ui.py                # Web server launcher
```

## 🚀 Usage Examples

### Python API
```python
from vulnerability_chains import VulnerabilityChainAnalyzer

# Create analyzer
analyzer = VulnerabilityChainAnalyzer()

# Analyze ZAP report
result = analyzer.analyze_zap_report(
    report_file='zap_report.json',
    max_chain_length=5,
    min_confidence=0.6,
    min_risk_filter='Medium'
)

# Print summary
analyzer.print_summary(result)

# Generate HTML report
analyzer.generate_report(result, 'chains.html')
```

### Command Line
```bash
# One-line analysis
python -c "from vulnerability_chains import analyze_zap_scan; analyze_zap_scan('report.json')"
```

### Web Interface
```bash
# Start server
python run_web_ui.py --port 8000

# Use dashboard at http://localhost:8000
# - Upload ZAP report
# - View results
# - Download HTML/JSON
```

## 🔬 How It Works

### 1. Build Graph
```python
# Vulnerabilities = nodes
# Chain rules = edges
graph = VulnerabilityGraph()
for vuln in vulnerabilities:
    graph.add_vulnerability(vuln)
for source, target in pairs:
    if rule_matches(source, target):
        graph.add_link(source, target)
```

### 2. Find Chains
```python
# DFS to find all paths
for source in source_nodes:
    paths = find_all_paths_from(source, max_length=5)
    for path in paths:
        chain = create_chain(path)
        if chain.confidence >= min_confidence:
            chains.append(chain)
```

### 3. Score Chains
```python
# Multi-factor risk scoring
risk_score = (
    base_severity × 1.0 +
    chain_length × 0.5 +
    exploitability × 1.5 +
    impact × 2.0 +
    confidence × 0.8
) × chain_type_multiplier
```

## 📊 15 Chain Rules

1. XSS → CSRF Bypass
2. Info Disclosure → Auth Bypass
3. Path Traversal → Source Code Disclosure
4. SQL Injection → Privilege Escalation
5. XSS → Session Hijacking
6. Weak Auth → Brute Force
7. Directory Listing → Info Disclosure
8. SSRF → Internal Network Access
9. File Upload → RCE
10. XXE → SSRF
11. Insecure Deserialization → RCE
12. Missing Headers → XSS
13. Weak Crypto → Data Breach
14. IDOR → Privilege Escalation
15. Command Injection → Data Exfiltration

*See `vulnerability_chains/config/chain_rules.json` for details*

## 🧪 Testing

### Smoke Test (Current)
```bash
python test_smoke.py
```
- Creates 4 test vulnerabilities
- Expects 2 chains detected
- Verifies all 15 rules load
- Generates reports

### Benchmark Testing (Next Step)
```bash
# 1. Scan target with ZAP
zap.sh -quickurl http://dvwa.local -quickout dvwa.json

# 2. Analyze with chain detection
python benchmark_dvwa.py

# 3. Collect metrics
- Chain detection rate
- False positive rate
- Analysis time
- Risk prioritization accuracy
```

## 📚 Documentation

- **[TECHNICAL_DOCS.md](TECHNICAL_DOCS.md)** ⭐ - Complete technical reference (READ THIS FIRST for new session)
- **[QUICKSTART.md](QUICKSTART.md)** - User quick start guide
- **[VULNERABILITY_CHAINS.md](VULNERABILITY_CHAINS.md)** - Project overview
- **[vulnerability_chains/README.md](vulnerability_chains/README.md)** - Full API docs
- **[vulnerability_chains/web/README.md](vulnerability_chains/web/README.md)** - Web UI docs

## 🎯 For Next Claude Code Session

### 🚀 Quick Onboarding

1. **Read**: [TECHNICAL_DOCS.md](TECHNICAL_DOCS.md) (comprehensive technical guide)
2. **Run**: `python test_smoke.py` (verify system works)
3. **Check**: `git status` and `git log` (understand current state)
4. **Start**: Benchmark testing on datasets

### 📋 What to Do Next

**Goal**: Collect benchmark metrics for Q2 publication

**Steps**:
1. Set up test environments (DVWA/WebGoat/Juice Shop)
2. Scan with OWASP ZAP
3. Analyze with chain detection
4. Compare with ground truth
5. Calculate metrics:
   - Chain Detection Rate (target: 70-80%)
   - False Chain Rate (target: <10%)
   - Risk Prioritization Accuracy
   - Performance metrics
6. Generate comparison tables
7. Create visualizations

### 🔑 Key Files for Benchmarking

- `vulnerability_chains/analyzer.py` - Main API
- `vulnerability_chains/config/chain_rules.json` - Rules config
- `test_smoke.py` - Example test structure
- Create: `benchmark_dvwa.py`, `benchmark_webgoat.py`, etc.

### 💡 Important Notes

- ✅ System is fully functional
- ✅ Smoke test passing
- ✅ Web UI working
- ✅ All dependencies installed
- ✅ RiskLevel comparison bug FIXED (commit 735972b)
- ⚠️ Need real ZAP scans of vulnerable apps
- ⚠️ Need ground truth data for comparison

## 🐛 Known Issues

### Fixed ✅
- RiskLevel enum comparison (commit 735972b)
- get_max_risk() method (commit 735972b)

### None Currently 🎉
All smoke tests passing!

## 📊 Performance

- **Smoke test**: 0.002s for 4 vulnerabilities
- **Expected**: 2-10s for 50-100 vulnerabilities
- **Memory**: ~200MB base + (report size × 3)

## 🤝 Contributing

For new features or benchmark scripts:
1. Follow existing code structure
2. Add tests
3. Update documentation
4. Run smoke test before committing

## 📄 License

MIT License - See LICENSE file

## 📞 Support

- **Technical Docs**: Read TECHNICAL_DOCS.md
- **API Docs**: http://localhost:8000/docs (when server running)
- **Examples**: See `examples/` directory
- **Tests**: See `test_smoke.py`

---

## 🎓 Research Information

**Title**: Graph-based Vulnerability Chain Analysis for Compound Exploit Detection in Web Applications

**Target**: Q2 Security Journal

**Status**: Implementation complete, ready for benchmarking

**Expected Results**:
- 70-80% chain detection rate
- <10% false positive rate
- Significant improvement over traditional scanners

---

**Current Version**: 1.0.0
**Last Updated**: 2025-12-06
**Status**: ✅ Ready for Benchmarking

**Start Here for New Session**: [TECHNICAL_DOCS.md](TECHNICAL_DOCS.md) ⭐
