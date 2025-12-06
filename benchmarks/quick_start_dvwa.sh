#!/bin/bash

###############################################################################
# Quick Start DVWA Benchmark
#
# This script automates the entire benchmark process:
# 1. Starts DVWA and ZAP containers
# 2. Performs ZAP scanning
# 3. Analyzes results with Vulnerability Chain Detection
# 4. Generates reports and metrics
# 5. Cleans up containers
###############################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DVWA_URL="http://dvwa:80"
ZAP_API_KEY="changeme"
ZAP_HOST="localhost"
ZAP_PORT="8090"
SCAN_OUTPUT="scans/dvwa_scan.json"
REPORT_OUTPUT="reports/dvwa_chains.html"
METRICS_OUTPUT="reports/dvwa_metrics.json"

echo -e "${BLUE}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  DVWA Vulnerability Chain Detection Benchmark        ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════╝${NC}"
echo ""

# Step 1: Check Docker
echo -e "${YELLOW}[1/8]${NC} Checking Docker..."
if ! command -v docker &> /dev/null; then
    echo -e "${RED}✗ Docker not found. Please install Docker first.${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Docker found${NC}"

# Step 2: Check Python dependencies
echo -e "${YELLOW}[2/8]${NC} Checking Python dependencies..."
if ! python3 -c "import zapv2" 2>/dev/null; then
    echo -e "${YELLOW}! Installing python-owasp-zap-v2.4...${NC}"
    pip3 install python-owasp-zap-v2.4 -q
fi
echo -e "${GREEN}✓ Python dependencies ready${NC}"

# Step 3: Start containers
echo -e "${YELLOW}[3/8]${NC} Starting DVWA and ZAP containers..."
docker-compose up -d dvwa zap

# Wait for services to be ready
echo -e "${YELLOW}[3/8]${NC} Waiting for services to start..."
echo -n "  Waiting for DVWA"
for i in {1..30}; do
    if curl -s http://localhost:8080 > /dev/null 2>&1; then
        echo -e " ${GREEN}✓${NC}"
        break
    fi
    echo -n "."
    sleep 2
done

echo -n "  Waiting for ZAP"
for i in {1..30}; do
    if curl -s "http://localhost:8090/JSON/core/view/version/?apikey=$ZAP_API_KEY" > /dev/null 2>&1; then
        echo -e " ${GREEN}✓${NC}"
        break
    fi
    echo -n "."
    sleep 2
done

# Step 4: Configure DVWA
echo -e "${YELLOW}[4/8]${NC} Configuring DVWA (setting security to Low)..."
# Note: In real scenario, you'd automate DVWA setup here
echo -e "${YELLOW}  ! Please manually configure DVWA:${NC}"
echo -e "    1. Open http://localhost:8080/setup.php"
echo -e "    2. Click 'Create / Reset Database'"
echo -e "    3. Login with admin/password"
echo -e "    4. Set Security Level to 'Low'"
echo -e "  ${BLUE}Press Enter when ready to continue...${NC}"
read -r

# Step 5: Run ZAP scan
echo -e "${YELLOW}[5/8]${NC} Running ZAP scan (this may take 5-10 minutes)..."
mkdir -p scans reports

python3 - <<EOF
from zapv2 import ZAPv2
import json
import time
import sys

# Connect to ZAP
zap = ZAPv2(apikey='$ZAP_API_KEY', proxies={'http': 'http://$ZAP_HOST:$ZAP_PORT', 'https': 'http://$ZAP_HOST:$ZAP_PORT'})

target = '$DVWA_URL'

print("  Starting Spider scan...")
scan_id = zap.spider.scan(target)

# Wait for spider to complete
while int(zap.spider.status(scan_id)) < 100:
    progress = zap.spider.status(scan_id)
    print(f"  Spider progress: {progress}%", end='\r')
    time.sleep(2)
print(f"  Spider progress: 100% ✓")

print("  Starting Active scan...")
scan_id = zap.ascan.scan(target)

# Wait for active scan to complete
while int(zap.ascan.status(scan_id)) < 100:
    progress = zap.ascan.status(scan_id)
    print(f"  Active scan progress: {progress}%", end='\r')
    time.sleep(5)
print(f"  Active scan progress: 100% ✓")

# Get alerts
print("  Fetching alerts...")
alerts = zap.core.alerts(baseurl=target)

# Save to JSON
output_file = '$SCAN_OUTPUT'
with open(output_file, 'w') as f:
    json.dump(alerts, f, indent=2)

print(f"  Scan results saved to {output_file}")
print(f"  Found {len(alerts)} alerts")
EOF

echo -e "${GREEN}✓ ZAP scan complete${NC}"

# Step 6: Analyze with Vulnerability Chain Detection
echo -e "${YELLOW}[6/8]${NC} Analyzing vulnerability chains..."

python3 - <<EOF
from vulnerability_chains import VulnerabilityChainAnalyzer

analyzer = VulnerabilityChainAnalyzer()

# Analyze ZAP report
result = analyzer.analyze_zap_report(
    report_file='$SCAN_OUTPUT',
    max_chain_length=5,
    min_confidence=0.5,
    min_risk_filter='Low'
)

print(f"  Vulnerabilities: {result.total_vulnerabilities}")
print(f"  Chains detected: {result.total_chains}")
print(f"  Critical chains: {result.critical_chains}")
print(f"  High risk chains: {result.high_risk_chains}")

# Generate HTML report
analyzer.generate_report(result, output_file='$REPORT_OUTPUT', format='html')
print(f"  HTML report: $REPORT_OUTPUT")

# Generate JSON report
analyzer.generate_report(result, output_file='$METRICS_OUTPUT', format='json')
print(f"  JSON metrics: $METRICS_OUTPUT")
EOF

echo -e "${GREEN}✓ Analysis complete${NC}"

# Step 7: Display results
echo -e "${YELLOW}[7/8]${NC} Results:"
echo ""
cat "$METRICS_OUTPUT" | python3 -m json.tool | head -20
echo ""

# Step 8: Cleanup
echo -e "${YELLOW}[8/8]${NC} Cleanup options:"
echo -e "  ${BLUE}k)${NC} Keep containers running"
echo -e "  ${BLUE}s)${NC} Stop containers"
echo -e "  ${BLUE}r)${NC} Remove containers"
read -p "Choose [k/s/r] (default: s): " choice
choice=${choice:-s}

case $choice in
    k|K)
        echo -e "${GREEN}Containers left running${NC}"
        ;;
    s|S)
        echo -e "${YELLOW}Stopping containers...${NC}"
        docker-compose stop dvwa zap
        echo -e "${GREEN}✓ Containers stopped${NC}"
        ;;
    r|R)
        echo -e "${YELLOW}Removing containers...${NC}"
        docker-compose down
        echo -e "${GREEN}✓ Containers removed${NC}"
        ;;
esac

echo ""
echo -e "${BLUE}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Benchmark Complete!                                  ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}Results:${NC}"
echo -e "  📊 HTML Report: ${BLUE}$REPORT_OUTPUT${NC}"
echo -e "  📈 JSON Metrics: ${BLUE}$METRICS_OUTPUT${NC}"
echo -e "  🔍 Raw ZAP Scan: ${BLUE}$SCAN_OUTPUT${NC}"
echo ""
echo -e "Open the HTML report in your browser:"
echo -e "  ${YELLOW}open $REPORT_OUTPUT${NC}  # macOS"
echo -e "  ${YELLOW}xdg-open $REPORT_OUTPUT${NC}  # Linux"
echo ""
