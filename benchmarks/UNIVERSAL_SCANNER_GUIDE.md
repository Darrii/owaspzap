# Universal Scanner Guide

## Overview

`universal_scan.py` is a **universal web application scanner** that works on **ANY website** with minimal configuration. It combines OWASP ZAP scanning with automatic vulnerability chain detection.

## Key Features

✅ **Universal**: Works on any website (legacy PHP, modern SPA, APIs)
✅ **Authentication Support**: Form-based, token-based, or cookie-based auth
✅ **CSRF Handling**: Automatic CSRF token extraction
✅ **Chain Detection**: Built-in vulnerability chain analysis
✅ **Easy to Use**: Simple command-line interface

---

## Quick Start

### 1. Simple Scan (No Authentication)

```bash
./zapenv/bin/python3 benchmarks/universal_scan.py --target https://example.com
```

**Use case:** Public websites, landing pages, blogs

**Output:**
- Scan results: `scans/example.com_scan_<timestamp>.json`
- Chain report: `reports/example.com_chains_<timestamp>.html`

---

### 2. Form-Based Authentication (Most Common)

```bash
./zapenv/bin/python3 benchmarks/universal_scan.py \
  --target http://example.com \
  --auth-type form \
  --login-url "http://example.com/login" \
  --username admin \
  --password password
```

**Use case:** WordPress, Joomla, custom PHP apps, Django, Laravel

**What it does:**
1. Fetches login page
2. Submits username/password
3. Extracts session cookie
4. Scans authenticated pages

---

### 3. Form Auth + CSRF Token

```bash
./zapenv/bin/python3 benchmarks/universal_scan.py \
  --target http://dvwa \
  --auth-type form \
  --login-url "http://dvwa/login.php" \
  --username admin \
  --password password \
  --csrf-pattern 'name="user_token" value="([^"]+)"'
```

**Use case:** DVWA, modern frameworks with CSRF protection

**What it does:**
1. Extracts CSRF token using regex pattern
2. Includes token in login request
3. Maintains authenticated session

**Common CSRF patterns:**
- `'name="csrf_token" value="([^"]+)"'` (Django, Flask)
- `'name="_token" value="([^"]+)"'` (Laravel)
- `'<input.*?name="authenticity_token".*?value="([^"]+)"'` (Rails)

---

### 4. Token-Based Authentication (APIs, SPAs)

```bash
# Get token first
TOKEN=$(curl -X POST https://api.example.com/login \
  -d '{"user":"admin","pass":"secret"}' | jq -r .token)

# Scan with token
./zapenv/bin/python3 benchmarks/universal_scan.py \
  --target https://api.example.com \
  --auth-type token \
  --token "Bearer $TOKEN"
```

**Use case:** REST APIs, GraphQL, modern SPAs

---

### 5. Cookie-Based Authentication (Manual Login)

```bash
# 1. Login manually in browser
# 2. Copy session cookie from browser DevTools

./zapenv/bin/python3 benchmarks/universal_scan.py \
  --target http://example.com \
  --auth-type cookie \
  --cookie "PHPSESSID=abc123def456; security=low"
```

**Use case:** Complex auth flows (OAuth, SAML, 2FA)

---

## Real-World Examples

### Example 1: WordPress Site

```bash
./zapenv/bin/python3 benchmarks/universal_scan.py \
  --target http://myblog.com \
  --auth-type form \
  --login-url "http://myblog.com/wp-login.php" \
  --username admin \
  --password mypassword \
  --username-field log \
  --password-field pwd
```

### Example 2: Django Application

```bash
./zapenv/bin/python3 benchmarks/universal_scan.py \
  --target http://myapp.com \
  --auth-type form \
  --login-url "http://myapp.com/accounts/login/" \
  --username testuser \
  --password testpass \
  --csrf-pattern 'name="csrfmiddlewaretoken" value="([^"]+)"' \
  --csrf-field csrfmiddlewaretoken
```

### Example 3: Laravel Application

```bash
./zapenv/bin/python3 benchmarks/universal_scan.py \
  --target http://mylaravel.com \
  --auth-type form \
  --login-url "http://mylaravel.com/login" \
  --username admin \
  --password secret \
  --csrf-pattern 'name="_token" value="([^"]+)"' \
  --csrf-field _token
```

### Example 4: React SPA with JWT

```bash
# Login via API
TOKEN=$(curl -X POST http://myapp.com/api/auth \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"pass"}' | jq -r .access_token)

# Scan with JWT
./zapenv/bin/python3 benchmarks/universal_scan.py \
  --target http://myapp.com \
  --auth-type token \
  --token "Bearer $TOKEN"
```

---

## Command-Line Arguments

### Required

| Argument | Description | Example |
|----------|-------------|---------|
| `--target` | Target URL to scan | `http://example.com` |

### Authentication

| Argument | Description | Default |
|----------|-------------|---------|
| `--auth-type` | Auth type: `form`, `token`, `cookie`, `none` | `none` |

### Form Authentication

| Argument | Description | Default |
|----------|-------------|---------|
| `--login-url` | Login page URL | Required for form auth |
| `--username` | Username | Required for form auth |
| `--password` | Password | Required for form auth |
| `--username-field` | Username field name | `username` |
| `--password-field` | Password field name | `password` |
| `--csrf-pattern` | Regex to extract CSRF token | Optional |
| `--csrf-field` | CSRF field name | `csrf_token` |

### Token Authentication

| Argument | Description | Default |
|----------|-------------|---------|
| `--token` | Auth token (JWT, Bearer, etc.) | Required for token auth |

### Cookie Authentication

| Argument | Description | Default |
|----------|-------------|---------|
| `--cookie` | Session cookie string | Required for cookie auth |

### ZAP Connection

| Argument | Description | Default |
|----------|-------------|---------|
| `--zap-host` | ZAP proxy host | `localhost` |
| `--zap-port` | ZAP proxy port | `8090` |

---

## Scan Workflow

The scanner performs 6 steps:

1. **Create ZAP Session**: Initialize new scanning session
2. **Setup Authentication**: Login and extract session cookie (if configured)
3. **Spider Scan**: Discover all URLs in the application
4. **Active Scan**: Test discovered URLs for vulnerabilities
5. **Collect Results**: Save vulnerabilities to JSON file
6. **Detect Chains**: Analyze vulnerabilities and find exploit chains

---

## Output Files

### Scan Results

**Location:** `scans/<domain>_scan_<timestamp>.json`

Contains all vulnerabilities found by ZAP in JSON format.

### Chain Report

**Location:** `reports/<domain>_chains_<timestamp>.html`

Interactive HTML report showing:
- Vulnerability chain graph
- Risk scores
- Exploitation steps
- Affected URLs

---

## Comparison with App-Specific Scanners

| Feature | Universal Scanner | App-Specific (DVWA, Juice Shop) |
|---------|------------------|----------------------------------|
| **Setup Time** | 30 seconds | 5-10 minutes |
| **Code to Write** | 0 lines (CLI only) | 50-100 lines Python |
| **Works on New Sites** | ✅ Yes | ❌ No (requires customization) |
| **CSRF Support** | ✅ Automatic (via regex) | Manual implementation |
| **Auth Support** | ✅ Form, Token, Cookie | Only form (hardcoded) |
| **Chain Detection** | ✅ Built-in | ✅ Built-in |
| **Flexibility** | Medium (80% of cases) | High (100% control) |

---

## Troubleshooting

### Problem: No session cookie found

**Solution:** Check if login was successful. Try manual cookie auth instead:
```bash
# Login in browser, copy cookie
--auth-type cookie --cookie "SESSION=abc123"
```

### Problem: CSRF token not extracted

**Solution:** Inspect login page HTML and adjust regex pattern:
```bash
# View page source
curl http://example.com/login | grep csrf

# Adjust pattern to match your HTML
--csrf-pattern 'name="your_csrf_field" value="([^"]+)"'
```

### Problem: Scan finds no authenticated pages

**Solution:** Verify authentication works:
```bash
# Test login manually first
curl -X POST http://example.com/login \
  -d "username=admin&password=pass" \
  -v

# Check for Set-Cookie in response headers
```

---

## Advanced Usage

### Custom Field Names

Some applications use non-standard field names:

```bash
# Drupal example
--username-field name \
--password-field pass

# WordPress example
--username-field log \
--password-field pwd
```

### Multiple Cookies

Combine multiple cookies with semicolons:

```bash
--cookie "session=abc123; security=low; PHPSESSID=xyz789"
```

### Remote ZAP Instance

Scan using ZAP running on another machine:

```bash
--zap-host 192.168.1.100 \
--zap-port 8090
```

---

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Security Scan

on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Start ZAP
        run: docker run -d -p 8090:8090 owasp/zap2docker-stable zap.sh -daemon

      - name: Run Universal Scanner
        run: |
          python3 benchmarks/universal_scan.py \
            --target ${{ secrets.APP_URL }} \
            --auth-type form \
            --login-url ${{ secrets.LOGIN_URL }} \
            --username ${{ secrets.TEST_USER }} \
            --password ${{ secrets.TEST_PASS }}

      - name: Check for Critical Chains
        run: |
          # Fail build if critical chains found (Risk > 30)
          python3 -c "import json; \
            report = json.load(open('scans/*.json')); \
            critical = [c for c in report['chains'] if c['risk_score'] > 30]; \
            exit(len(critical))"
```

---

## Next Steps

1. **Run your first scan** on a test application
2. **Review the chain report** in your browser
3. **Customize auth config** for your specific application
4. **Integrate into CI/CD** for continuous security testing

---

**Questions?** Check the main [README.md](../README.md) or [TECHNICAL_DOCS.md](../TECHNICAL_DOCS.md)
