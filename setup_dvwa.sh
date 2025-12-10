#!/bin/bash

echo "Setting up DVWA database..."

# Get session
PHPSESSID=$(curl -s -c - -d 'username=admin&password=password&Login=Login' http://localhost:8080/login.php | grep PHPSESSID | awk '{print $7}')
echo "PHPSESSID: $PHPSESSID"

# Create database
echo "Creating database..."
curl -s -b "PHPSESSID=$PHPSESSID" -d "create_db=Create" http://localhost:8080/setup.php | grep -E "created|error|success|Setup successful" | head -5

echo ""
echo "Setting security to low..."
curl -s -b "PHPSESSID=$PHPSESSID" -d 'security=low&seclev_submit=Submit' http://localhost:8080/security.php > /dev/null

echo ""
echo "Testing SQLi..."
curl -s -b "PHPSESSID=$PHPSESSID; security=low" "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" | grep "First name:" | head -3
