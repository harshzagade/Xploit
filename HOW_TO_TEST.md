# How to Test Xploit

## Testing with Vulnerable App

### Start the Test App:
```bash
python3 vulnerable_test_app.py
```

This starts a deliberately vulnerable Flask app on http://127.0.0.1:5000

### Run Xploit:
```bash
xploit http://127.0.0.1:5000/ --mode full --depth 3
```

### Expected Results:
- 11 findings: 5 HIGH, 4 MEDIUM, 1 LOW, 1 INFO
  - HIGH: SQL Injection, XSS, and authentication/transport issues
  - MEDIUM: missing security headers, misconfigurations
  - LOW / INFO: informational disclosures

### Manual Testing:

**SQL Injection:**
```bash
curl "http://127.0.0.1:5000/sqli?id=1' OR '1'='1"
```

**XSS:**
```bash
curl "http://127.0.0.1:5000/xss?q=<script>alert(1)</script>"
```

## Testing with DVWA

1. Download DVWA: https://github.com/digininja/DVWA
2. Set security level to LOW
3. Run: `xploit http://localhost/dvwa/ --mode full`

## Important Notes

- The vulnerable_test_app.py is INTENTIONALLY INSECURE
- NEVER deploy it to production
- Only use on localhost for testing
- Stop the app after testing: `pkill -f vulnerable_test_app`
