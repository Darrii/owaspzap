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
DVWA_URL_EXTERNAL="http://localhost:8080"  # For setup from host
DVWA_URL_INTERNAL="http://dvwa:80"          # For ZAP scanning from Docker
DVWA_USERNAME="admin"
DVWA_PASSWORD="password"
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
# Determine Python executable (prefer venv)
if [ -f "./zapenv/bin/python" ]; then
    PYTHON="./zapenv/bin/python"
    PIP="./zapenv/bin/pip"
elif [ -n "$VIRTUAL_ENV" ] && command -v python &> /dev/null; then
    PYTHON="python"
    PIP="pip"
else
    PYTHON="python3"
    PIP="pip3"
fi

if ! $PYTHON -c "import zapv2" 2>/dev/null; then
    echo -e "${YELLOW}! Installing python-owasp-zap-v2.4...${NC}"
    $PIP install python-owasp-zap-v2.4 -q
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

# Step 4: Configure DVWA automatically
echo -e "${YELLOW}[4/8]${NC} Configuring DVWA (setting security to Low)..."
echo "  Setting up DVWA database..."

# Create/reset database
curl -s "http://localhost:8080/setup.php" > /dev/null
sleep 2

# Get PHPSESSID cookie
PHPSESSID=$(curl -s -c - "http://localhost:8080/login.php" | grep PHPSESSID | awk '{print $7}')

# Login to DVWA
curl -s -b "PHPSESSID=$PHPSESSID" \
  -d "username=admin&password=password&Login=Login" \
  "http://localhost:8080/login.php" > /dev/null

# Set security level to low
curl -s -b "PHPSESSID=$PHPSESSID" \
  -d "security=low&seclev_submit=Submit" \
  "http://localhost:8080/security.php" > /dev/null

echo -e "${GREEN}✓ DVWA configured (security level: Low)${NC}"

# Step 5: Run ZAP scan
echo -e "${YELLOW}[5/8]${NC} Running ZAP scan (this may take 15-20 minutes)..."
mkdir -p scans reports

$PYTHON - <<EOF
from zapv2 import ZAPv2
import json
import time
import sys

# Connect to ZAP
zap = ZAPv2(apikey='$ZAP_API_KEY', proxies={'http': 'http://$ZAP_HOST:$ZAP_PORT', 'https': 'http://$ZAP_HOST:$ZAP_PORT'})

# Use internal Docker network URL for ZAP to access DVWA
target = '$DVWA_URL_INTERNAL'
username = '$DVWA_USERNAME'
password = '$DVWA_PASSWORD'

print("  Initializing ZAP session...")
try:
    zap.core.new_session(name='dvwa_session', overwrite=True)
except:
    pass

# Access the target first
print("  Accessing DVWA...")
zap.core.access_url(target, followredirects=True)
time.sleep(2)

# Perform manual login via ZAP to establish authenticated session
print("  Logging into DVWA...")
login_url = f'{target}/login.php'

# Send POST request to login
try:
    import urllib.parse
    login_data = urllib.parse.urlencode({
        'username': username,
        'password': password,
        'Login': 'Login'
    })

    # Use ZAP's sendRequest to login
    zap.core.send_request(
        request=f'POST {login_url} HTTP/1.1\r\n'
               f'Host: dvwa\r\n'
               f'Content-Type: application/x-www-form-urlencoded\r\n'
               f'Content-Length: {len(login_data)}\r\n'
               f'\r\n'
               f'{login_data}',
        followredirects=True
    )
    print("  Login request sent")
    time.sleep(2)
except Exception as e:
    print(f"  Warning: Login via sendRequest failed: {e}")
    # Fallback: just access the login page
    zap.core.access_url(login_url, followredirects=True)
    time.sleep(1)

# Manually add vulnerable URLs - ZAP will discover them
vulnerable_paths = [
    '/vulnerabilities/sqli/',
    '/vulnerabilities/sqli/?id=1&Submit=Submit',
    '/vulnerabilities/xss_r/',
    '/vulnerabilities/xss_s/',
    '/vulnerabilities/csrf/',
    '/vulnerabilities/fi/',
    '/vulnerabilities/upload/',
    '/vulnerabilities/exec/',
    '/vulnerabilities/brute/',
    '/vulnerabilities/captcha/',
    '/vulnerabilities/weak_id/',
]

print("  Pre-seeding vulnerable URLs...")
for path in vulnerable_paths:
    try:
        url = f'{target}{path}'
        zap.core.access_url(url, followredirects=True)
        time.sleep(0.5)
    except Exception as e:
        pass

print("  Starting Spider scan...")
scan_id = zap.spider.scan(target, recurse=True, subtreeonly=False)

# Wait for spider to complete
while int(zap.spider.status(scan_id)) < 100:
    progress = zap.spider.status(scan_id)
    print(f"  Spider progress: {progress}%", end='\r')
    sys.stdout.flush()
    time.sleep(2)
print(f"  Spider progress: 100% ✓")

# Get spider results
urls_found = zap.spider.results(scan_id)
print(f"  Spider found {len(urls_found)} URLs")

print("  Starting Active scan...")
scan_id = zap.ascan.scan(target, recurse=True, scanpolicyname='Default Policy')

# Wait for active scan to complete
max_wait = 1200  # 20 minutes max for thorough scanning
start_time = time.time()
last_progress = 0

while True:
    try:
        status = zap.ascan.status(scan_id)
        progress = int(status)

        if progress >= 100:
            print(f"  Active scan progress: 100% ✓")
            break

        if progress != last_progress:
            print(f"  Active scan progress: {progress}%", end='\r')
            sys.stdout.flush()
            last_progress = progress

        if time.time() - start_time > max_wait:
            print(f"\n  Active scan timeout after {max_wait}s")
            break

        time.sleep(5)

    except (ValueError, KeyError) as e:
        # Scan ID might be invalid, wait a bit more
        if time.time() - start_time > 120:
            print(f"\n  Warning: Could not track scan progress: {e}")
            print("  Waiting 60 more seconds...")
            time.sleep(60)
            break
        time.sleep(5)

# Get alerts
print("\n  Fetching alerts...")
alerts = zap.core.alerts(baseurl='')

# Save to JSON
output_file = '$SCAN_OUTPUT'
with open(output_file, 'w') as f:
    json.dump(alerts, f, indent=2)

print(f"  Scan results saved to {output_file}")
print(f"  Found {len(alerts)} alerts")

# Print summary by risk level
risk_counts = {}
for alert in alerts:
    risk = alert.get('risk', 'Unknown')
    risk_counts[risk] = risk_counts.get(risk, 0) + 1

print("  Alert summary by risk:")
for risk in ['High', 'Medium', 'Low', 'Informational']:
    if risk in risk_counts:
        print(f"    {risk}: {risk_counts[risk]}")
EOF

echo -e "${GREEN}✓ ZAP scan complete${NC}"

# Step 6: Analyze with Vulnerability Chain Detection
echo -e "${YELLOW}[6/8]${NC} Analyzing vulnerability chains..."

$PYTHON - <<EOF
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
cat "$METRICS_OUTPUT" | $PYTHON -m json.tool | head -20
echo ""

# Step 8: Cleanup
echo -e "${YELLOW}[8/8]${NC} Cleanup options:"
echo -e "  ${BLUE}k)${NC} Keep containers running"
echo -e "  ${BLUE}s)${NC} Stop containers"
echo -e "  ${BLUE}r)${NC} Remove containers"

# Auto-mode: keep containers running by default
if [ -n "$AUTO_MODE" ]; then
    choice="k"
    echo "  Auto-mode: keeping containers running"
else
    read -p "Choose [k/s/r] (default: k): " choice
    choice=${choice:-k}
fi

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
