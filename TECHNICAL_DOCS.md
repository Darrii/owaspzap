# 📘 Technical Documentation - Vulnerability Chain Detection System

## 🎯 Project Overview

**Full Name**: Graph-based Vulnerability Chain Analysis for Compound Exploit Detection in Web Applications

**Purpose**: Automatically detect exploitation chains in OWASP ZAP scan results by building a graph of vulnerabilities and finding paths between them.

**Scientific Goal**: Q2 journal publication with reproducible benchmark results.

---

## 📊 Project Status

### ✅ Completed (100%)
- Core system implementation (3,739 lines of Python)
- Web UI with REST API (1,374 lines)
- 15 pre-defined chain rules
- Complete documentation
- Smoke test (passing)

### 🔄 Next Steps
- Benchmark testing on datasets (DVWA, WebGoat, Juice Shop)
- Metrics collection for publication
- Performance optimization

---

## 🏗️ Architecture

### High-Level Flow
```
ZAP Report (JSON)
    ↓
ZAPAlertParser → Vulnerability objects
    ↓
ChainDetector.build_graph() → VulnerabilityGraph (NetworkX)
    ↓
ChainRuleEngine.create_links() → Add edges based on 15 rules
    ↓
ChainDetector.find_all_chains() → Path finding (DFS)
    ↓
ChainScoring.score_all_chains() → Risk calculation
    ↓
GraphVisualizer.generate_html_report() → HTML/JSON output
```

### Directory Structure
```
vulnerability_chains/
├── __init__.py                 # Main exports
├── analyzer.py                 # VulnerabilityChainAnalyzer (main interface)
├── models.py                   # Data classes (Vulnerability, Chain, Link)
├── constants.py                # Enums (RiskLevel, ChainType, etc.)
├── core/
│   ├── vulnerability_graph.py  # NetworkX graph wrapper
│   ├── chain_detector.py       # Path finding algorithm
│   └── chain_scoring.py        # Risk scoring with CVSS
├── rules/
│   └── chain_rules.py          # Rule engine + condition checking
├── utils/
│   └── zap_parser.py           # ZAP JSON parser
├── visualization/
│   └── graph_visualizer.py     # HTML/JSON report generator
├── config/
│   └── chain_rules.json        # 15 chain rules (JSON)
└── web/
    ├── app.py                  # FastAPI application
    ├── templates/index.html    # Dashboard UI
    └── static/                 # CSS/JS
```

---

## 🔧 Core Components

### 1. VulnerabilityChainAnalyzer
**File**: `vulnerability_chains/analyzer.py`

**Main Interface** - Use this for all analysis tasks.

```python
from vulnerability_chains import VulnerabilityChainAnalyzer

analyzer = VulnerabilityChainAnalyzer()

# Analyze ZAP report
result = analyzer.analyze_zap_report(
    report_file='zap_report.json',
    max_chain_length=5,          # 2-10
    min_confidence=0.6,          # 0-1
    min_risk_filter='Medium'     # Low/Medium/High/Critical
)

# Generate reports
analyzer.generate_report(result, 'output.html')
analyzer.print_summary(result)

# Get statistics
stats = analyzer.get_statistics(result)
```

**Key Methods**:
- `analyze_zap_report()` - Main analysis entry point
- `analyze_vulnerabilities()` - Analyze Vulnerability objects directly
- `generate_report()` - Create HTML/JSON reports
- `get_statistics()` - Get comprehensive stats
- `get_top_chains()` - Get highest risk chains

---

### 2. VulnerabilityGraph
**File**: `vulnerability_chains/core/vulnerability_graph.py`

**Graph Data Structure** - Uses NetworkX DiGraph.

```python
from vulnerability_chains.core import VulnerabilityGraph

graph = VulnerabilityGraph()

# Add vulnerabilities as nodes
graph.add_vulnerability(vuln)  # Vulnerability object

# Add links as edges
graph.add_link(chain_link)     # ChainLink object

# Find paths
paths = graph.find_paths(source_id, target_id, max_length=5)
all_paths = graph.find_all_paths_from(source_id, max_length=5)

# Get statistics
stats = graph.get_graph_stats()
```

**Graph Structure**:
- **Nodes**: Vulnerability objects with attributes (id, name, risk, url, etc.)
- **Edges**: ChainLink objects with weights (exploitability, confidence)
- **Directed**: Edges represent exploit flow direction

---

### 3. ChainDetector
**File**: `vulnerability_chains/core/chain_detector.py`

**Chain Finding Algorithm** - Detects exploitation paths.

```python
from vulnerability_chains.core import ChainDetector

detector = ChainDetector(rule_engine)

# Build graph and detect chains
result = detector.detect_chains(
    vulnerabilities=vulns,
    max_length=5,
    min_confidence=0.6
)
```

**Algorithm**:
1. Build graph from vulnerabilities
2. Apply rules to create edges
3. Find all source nodes (no incoming edges)
4. DFS to find all paths from each source
5. Filter by min_confidence
6. Remove duplicate and subchains
7. Return ChainDetectionResult

**Important**: Uses `networkx.all_simple_paths()` for path finding.

---

### 4. ChainRuleEngine
**File**: `vulnerability_chains/rules/chain_rules.py`

**Rule-Based Linking** - Connects vulnerabilities based on predefined rules.

```python
from vulnerability_chains.rules import ChainRuleEngine

engine = ChainRuleEngine()  # Loads config/chain_rules.json

# Find applicable rules
rules = engine.find_applicable_rules(source_vuln, target_vuln)

# Create links
links = engine.create_links(source_vuln, target_vuln)

# Get statistics
stats = engine.get_statistics()
```

**Rule Structure** (15 rules in `config/chain_rules.json`):
```json
{
  "rule_id": "XSS_TO_CSRF",
  "source_type": "Cross Site Scripting",
  "target_type": "Anti-CSRF Tokens Check",
  "chain_type": "authentication_bypass",
  "conditions": {
    "same_domain": true,
    "min_confidence": 0.7
  },
  "exploitability": 0.85,
  "impact_multiplier": 2.5
}
```

**Condition Checking**:
- `same_domain`: URLs must have same netloc
- `min_confidence`: Average confidence threshold
- `contains_credentials`: Evidence/param has password/token/etc.
- `cookie_accessible`: XSS without HttpOnly protection
- `no_rate_limiting`: No rate limiting detected

---

### 5. ChainScoring
**File**: `vulnerability_chains/core/chain_scoring.py`

**Risk Assessment** - Multi-factor risk scoring.

```python
from vulnerability_chains.core import ChainScoring

scoring = ChainScoring()

# Calculate risk for a chain
risk_score = scoring.calculate_chain_risk(chain)

# Score all chains
scored_chains = scoring.score_all_chains(chains)

# Get distribution
distribution = scoring.get_risk_distribution(chains)
```

**Scoring Formula**:
```python
risk_score = (
    base_severity × 1.0 +      # Max + avg severity
    chain_length × 0.5 +       # Length penalty
    exploitability × 1.5 +     # Weakest link
    impact × 2.0 +             # Chain type impact
    confidence × 0.8           # Detection confidence
) × chain_type_multiplier

# Scale: 0-100
# Categories: <5=Low, 5-10=Medium, 10-15=High, 15+=Critical
```

**CVSS Approximation**:
- `calculate_cvss_base_score()` - Returns approximate CVSS v3 score (0-10)

---

### 6. ZAPAlertParser
**File**: `vulnerability_chains/utils/zap_parser.py`

**ZAP Report Parser** - Converts ZAP JSON to Vulnerability objects.

```python
from vulnerability_chains.utils import ZAPAlertParser

parser = ZAPAlertParser()

# Parse ZAP report
vulns = parser.parse_zap_report('zap_report.json')

# Filter
high_risk = parser.filter_by_risk(vulns, RiskLevel.HIGH)
high_conf = parser.filter_by_confidence(vulns, 'Medium')

# Deduplicate
unique = parser.deduplicate_vulnerabilities(vulns)
```

**Supported Formats**:
- Standard ZAP JSON report (`site` → `alerts`)
- Direct alerts array
- API response format

---

### 7. GraphVisualizer
**File**: `vulnerability_chains/visualization/graph_visualizer.py`

**Report Generation** - Creates HTML/JSON reports.

```python
from vulnerability_chains.visualization import GraphVisualizer

viz = GraphVisualizer()

# Generate HTML
html_file = viz.generate_html_report(result, 'report.html')

# Generate JSON
json_file = viz.export_to_json(result, 'report.json')
```

**HTML Features**:
- Summary statistics cards
- Top 10 chains with details
- Complete chain listing
- Exploitation steps
- Color-coded risk levels
- Responsive design

---

## 📦 Data Models

### Vulnerability
**File**: `vulnerability_chains/models.py`

```python
@dataclass
class Vulnerability:
    id: str                      # Unique ID
    name: str                    # Vulnerability type
    risk: RiskLevel              # INFORMATIONAL/LOW/MEDIUM/HIGH/CRITICAL
    confidence: str              # Low/Medium/High
    url: str                     # Affected URL
    param: Optional[str]         # Vulnerable parameter
    attack: Optional[str]        # Attack payload
    evidence: Optional[str]      # Evidence found
    description: Optional[str]   # Description
    solution: Optional[str]      # Remediation
    cwe_id: Optional[int]        # CWE ID
    plugin_id: Optional[str]     # ZAP plugin ID
```

**Creation**:
```python
# From ZAP alert
vuln = Vulnerability.from_zap_alert(alert_dict)

# Manual
vuln = Vulnerability(
    id="vuln_1",
    name="Cross Site Scripting",
    risk=RiskLevel.HIGH,
    confidence="High",
    url="http://example.com/page"
)
```

---

### ChainLink
**File**: `vulnerability_chains/models.py`

```python
@dataclass
class ChainLink:
    source: Vulnerability        # Source vulnerability
    target: Vulnerability        # Target vulnerability
    rule_name: str              # Rule that created link
    confidence: float           # Link confidence (0-1)
    exploitability: float       # How exploitable (0-1)
    description: str            # Link description
    conditions_met: List[str]   # Which conditions passed
```

---

### VulnerabilityChain
**File**: `vulnerability_chains/models.py`

```python
@dataclass
class VulnerabilityChain:
    id: str                     # Unique chain ID
    vulnerabilities: List[Vulnerability]
    links: List[ChainLink]
    chain_type: ChainType       # RCE/PRIV_ESC/AUTH_BYPASS/etc.
    risk_score: float           # 0-100
    confidence: float           # Average link confidence
    impact_description: str     # Human-readable impact
    exploitation_steps: List[str]
    detected_at: datetime
```

**Methods**:
- `get_max_risk()` - Highest vulnerability risk in chain
- `get_summary()` - Human-readable summary
- `to_dict()` - Convert to dictionary

---

### ChainDetectionResult
**File**: `vulnerability_chains/models.py`

```python
@dataclass
class ChainDetectionResult:
    chains: List[VulnerabilityChain]
    total_vulnerabilities: int
    total_chains: int
    critical_chains: int        # risk >= 15
    high_risk_chains: int       # risk >= 10
    analysis_time: float
    timestamp: datetime
```

---

## 🔢 Enums & Constants

### RiskLevel
**File**: `vulnerability_chains/constants.py`

```python
class RiskLevel(Enum):
    INFORMATIONAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_string(cls, risk_str: str) -> 'RiskLevel'

    def to_numeric(self) -> int
```

### ChainType
```python
class ChainType(Enum):
    AUTHENTICATION_BYPASS = "authentication_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    REMOTE_CODE_EXECUTION = "remote_code_execution"
    SESSION_HIJACKING = "session_hijacking"
    INFORMATION_GATHERING = "information_gathering"
    COMPOUND_EXPLOIT = "compound_exploit"
```

### Default Parameters
```python
MAX_CHAIN_LENGTH = 5            # Maximum vulnerabilities in chain
MIN_CHAIN_CONFIDENCE = 0.6      # Minimum confidence threshold
MIN_CHAIN_RISK_SCORE = 5.0      # Minimum risk to report

DEFAULT_CHAIN_WEIGHTS = {
    'base_severity': 1.0,
    'chain_length': 0.5,
    'exploitability': 1.5,
    'impact': 2.0,
    'confidence': 0.8
}
```

---

## 🌐 Web Interface

### FastAPI Application
**File**: `vulnerability_chains/web/app.py`

**Start Server**:
```bash
python run_web_ui.py --port 8000
```

**API Endpoints**:
```
GET  /                          - Dashboard
POST /api/upload                - Upload ZAP report
POST /api/analyze/{id}          - Start analysis
GET  /api/results/{id}          - Get results
GET  /api/report/{id}/html      - View HTML
GET  /api/report/{id}/json      - View JSON
GET  /api/download/{id}/{fmt}   - Download report
GET  /api/analyses              - List all analyses
DELETE /api/analysis/{id}       - Delete analysis
GET  /api/rules                 - Get chain rules
```

**Example Usage**:
```python
import requests

# Upload
files = {'file': open('zap_report.json', 'rb')}
r = requests.post('http://localhost:8000/api/upload', files=files)
analysis_id = r.json()['analysis_id']

# Analyze
r = requests.post(f'http://localhost:8000/api/analyze/{analysis_id}')
result = r.json()

print(f"Found {result['statistics']['total_chains']} chains")
```

---

## 🧪 Testing

### Smoke Test
**File**: `test_smoke.py`

**Run**:
```bash
python test_smoke.py
```

**What it tests**:
- ✅ Analyzer initialization
- ✅ 15 chain rules loading
- ✅ Vulnerability creation
- ✅ Chain detection (expects 2 chains from 4 test vulns)
- ✅ Graph statistics
- ✅ Report generation

**Expected Output**:
```
✅ SMOKE TEST PASSED!
Found 2 chains:
- Chain #1: SQL Injection → Privilege Escalation (Risk: 61.28)
- Chain #2: XSS → CSRF (Risk: 41.11)
```

---

## 📊 Benchmark Testing (TO DO)

### Required Datasets
1. **OWASP WebGoat** - Educational vulnerable app
2. **DVWA** - Damn Vulnerable Web Application
3. **OWASP Juice Shop** - Modern vulnerable app

### Metrics to Collect
```python
{
    'chain_detection_rate': 0.75,     # % of known chains found
    'false_chain_rate': 0.08,         # % of invalid chains
    'risk_prioritization_accuracy': 0.82,
    'analysis_time': 2.34,            # seconds
    'total_vulnerabilities': 45,
    'total_chains': 12,
    'chains_by_type': {
        'rce': 2,
        'privilege_escalation': 3,
        'auth_bypass': 4,
        ...
    }
}
```

### Benchmark Script Template
```python
from vulnerability_chains import VulnerabilityChainAnalyzer

# Scan with ZAP first
# zap.sh -quickurl http://dvwa.local -quickout dvwa_scan.json

# Analyze
analyzer = VulnerabilityChainAnalyzer()
result = analyzer.analyze_zap_report('dvwa_scan.json')

# Collect metrics
print(f"Chains: {result.total_chains}")
print(f"Critical: {result.critical_chains}")
print(f"Time: {result.analysis_time}s")

# Compare with known chains (manual verification)
known_chains = load_known_chains('dvwa_ground_truth.json')
detected_ids = set(chain.id for chain in result.chains)
known_ids = set(chain['id'] for chain in known_chains)

detection_rate = len(detected_ids & known_ids) / len(known_ids)
print(f"Detection Rate: {detection_rate:.2%}")
```

---

## 🔍 Debugging & Troubleshooting

### Common Issues

**1. Import errors**
```bash
# Install dependencies
pip install -r requirements.txt
```

**2. No chains detected**
- Check min_confidence (try 0.5 instead of 0.7)
- Check min_risk_filter (use 'Low' or None)
- Verify vulnerabilities are on same domain
- Check logs: `logging.basicConfig(level=logging.DEBUG)`

**3. Graph errors**
```python
# Check graph stats
stats = analyzer.detector.graph.get_graph_stats()
print(stats)

# Verify edges were created
print(f"Edges: {stats['total_edges']}")
```

**4. RiskLevel comparison errors**
- **FIXED** in commit 735972b
- Use `.value` for comparisons
- `max(vulnerabilities, key=lambda v: v.risk.value).risk`

---

## 🚀 Performance

### Current Performance
- **Smoke test**: 0.002s for 4 vulnerabilities
- **Expected**: ~2-10s for 50-100 vulnerabilities
- **Memory**: ~200MB + (report size × 3)

### Optimization Tips
1. Reduce `max_chain_length` (5 → 3)
2. Increase `min_confidence` (0.6 → 0.7)
3. Filter by risk before analysis
4. Use caching for repeated analyses

---

## 📝 Known Limitations

1. **No machine learning** - Rules are hand-coded
2. **Same domain requirement** - Many rules need same_domain=true
3. **No interactive graph viz** - Only HTML reports (D3.js planned)
4. **No real-time scanning** - Requires ZAP JSON report first
5. **Limited rule conditions** - Only 5 condition types supported

---

## 📚 Additional Files

### Documentation
- `VULNERABILITY_CHAINS.md` - Project overview
- `QUICKSTART.md` - Quick start guide
- `vulnerability_chains/README.md` - Full API documentation
- `vulnerability_chains/web/README.md` - Web UI documentation

### Examples
- `examples/chain_detection_example.py` - 7 usage examples
- `test_smoke.py` - Basic functionality test

### Configuration
- `requirements.txt` - Python dependencies
- `vulnerability_chains/config/chain_rules.json` - 15 chain rules
- `.gitignore` - Ignore patterns

---

## 🎯 Quick Reference

### One-Line Analysis
```bash
python -c "from vulnerability_chains import analyze_zap_scan; analyze_zap_scan('report.json')"
```

### Programmatic Usage
```python
from vulnerability_chains import VulnerabilityChainAnalyzer

analyzer = VulnerabilityChainAnalyzer()
result = analyzer.analyze_zap_report('zap_report.json')
analyzer.print_summary(result)
```

### Web UI
```bash
python run_web_ui.py
# Open http://localhost:8000
```

### Run Tests
```bash
python test_smoke.py
```

---

## 📞 For Next Session

### Starting Point
1. Read this document (TECHNICAL_DOCS.md)
2. Run smoke test: `python test_smoke.py`
3. Verify Web UI: `python run_web_ui.py`
4. Start benchmark testing on datasets

### Key Files to Know
- `vulnerability_chains/analyzer.py` - Main interface
- `vulnerability_chains/core/chain_detector.py` - Detection algorithm
- `vulnerability_chains/config/chain_rules.json` - Rules configuration
- `test_smoke.py` - Working test example

### Important Notes
- All 15 chain rules are in JSON config (easily editable)
- RiskLevel enum comparison bug is **FIXED**
- System is tested and working
- Ready for benchmark data collection

---

**Last Updated**: 2025-12-06
**Version**: 1.0.0
**Status**: ✅ Core Complete, Ready for Benchmarking
