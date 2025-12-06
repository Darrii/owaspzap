# 🚀 Quick Start Guide - Vulnerability Chain Detection

## ⚡ Fastest Way to Get Started

### Step 1: Start the Web Interface

```bash
python run_web_ui.py
```

### Step 2: Open Your Browser

Navigate to: **http://localhost:8000/**

### Step 3: Upload & Analyze

1. **Drag & drop** your OWASP ZAP JSON report onto the upload area
2. **Wait** for automatic analysis (usually 2-10 seconds)
3. **View results** in the interactive dashboard

That's it! 🎉

---

## 🎨 Web Interface Features

### 📤 Upload
- Drag & drop ZAP JSON reports
- Or click "Browse Files"
- Configurable analysis options

### 📊 Dashboard
- Real-time statistics
- Top vulnerability chains
- Risk-based color coding
- Download HTML/JSON reports

### 🕒 History
- Browse previous analyses
- Re-view old reports
- Delete old analyses

### 📚 Rules
- View all 15 chain rules
- See chain types and patterns
- Understand detection logic

---

## 🐍 Python API (Alternative)

If you prefer command-line:

```python
from vulnerability_chains import analyze_zap_scan

# One-line analysis
result = analyze_zap_scan('path/to/zap_report.json')
```

Or for more control:

```python
from vulnerability_chains import VulnerabilityChainAnalyzer

analyzer = VulnerabilityChainAnalyzer()
result = analyzer.analyze_zap_report(
    report_file='zap_report.json',
    max_chain_length=5,
    min_confidence=0.7,
    min_risk_filter='Medium'
)

# Generate reports
analyzer.generate_report(result, 'output.html')
analyzer.print_summary(result)
```

---

## 🔧 Configuration Options

### Web UI Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| Max Chain Length | 5 | Maximum vulnerabilities in a chain (2-10) |
| Min Confidence | 0.6 | Minimum detection confidence (0-1) |
| Min Risk Filter | All | Filter by risk level (Low/Medium/High/Critical) |

### Server Options

```bash
# Custom port
python run_web_ui.py --port 8080

# Specific host
python run_web_ui.py --host 127.0.0.1 --port 9000

# Help
python run_web_ui.py --help
```

---

## 📖 Documentation Links

- **Web UI Details**: `vulnerability_chains/web/README.md`
- **Full Documentation**: `vulnerability_chains/README.md`
- **Project Overview**: `VULNERABILITY_CHAINS.md`
- **Examples**: `examples/chain_detection_example.py`

---

## 🆘 Troubleshooting

### Port Already in Use?
```bash
python run_web_ui.py --port 8080
```

### Can't Upload File?
- Ensure file is `.json` format
- Check file size (< 50MB recommended)
- Verify it's a valid OWASP ZAP report

### Analysis Fails?
- Check ZAP report format
- Try lower max_chain_length
- Use min_risk_filter to reduce scope

---

## 🎯 What Gets Detected?

### Chain Types
1. **Remote Code Execution** (File Upload → RCE)
2. **Privilege Escalation** (SQL Injection → Admin)
3. **Authentication Bypass** (XSS → CSRF → Admin Access)
4. **Session Hijacking** (XSS → Cookie Theft)
5. **Data Exfiltration** (XXE → SSRF → Internal Data)
6. **Information Gathering** (Directory Listing → Source Code)

### 15 Pre-defined Rules
- XSS → CSRF Bypass
- SQL Injection → Privilege Escalation
- File Upload → Remote Code Execution
- Path Traversal → Source Code Disclosure
- XXE → SSRF
- And 10 more...

---

## 📊 Example Output

```
======================================================================
🔗 VULNERABILITY CHAIN DETECTION SUMMARY
======================================================================

📊 Statistics:
   Total Vulnerabilities: 45
   Total Chains Detected: 12
   Critical Chains: 3
   High Risk Chains: 5
   Analysis Time: 2.34s

🔝 Top Chain:
   [REMOTE_CODE_EXECUTION] File Upload → Command Injection
   Risk Score: 22.5
   Confidence: 88%
```

---

## 🚀 Next Steps

1. **Explore the Dashboard**: Check out all tabs and features
2. **Review Chain Rules**: Understand detection patterns
3. **Test with Examples**: Use DVWA, WebGoat, or Juice Shop
4. **Read Full Docs**: `vulnerability_chains/README.md`
5. **Customize Rules**: Create custom chain rules if needed

---

## 🤝 Need Help?

- **API Docs**: http://localhost:8000/docs (when server running)
- **Interactive API**: http://localhost:8000/redoc
- **GitHub Issues**: Report bugs or request features
- **Documentation**: Check the README files

---

**Happy Chain Hunting! 🔗🔍**

*SIAAS Research Team - Vulnerability Chain Detection v1.0.0*
