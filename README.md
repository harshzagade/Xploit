# Xploit

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.7.0-blue.svg?style=flat-square">
  <img src="https://img.shields.io/badge/Python-3.10%2B-yellow.svg?style=flat-square">
  <img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat-square">
  <img src="https://img.shields.io/badge/Detections-25%2B-brightgreen.svg?style=flat-square">
</p>

**Xploit** is a CLI-based web vulnerability scanner designed for authorized security assessments. It performs intelligent crawling, tests for OWASP Top 10 vulnerabilities, and generates professional security reports with CWE classifications.

> ⚠️ **Legal Notice:** Use Xploit only on applications you own or are explicitly authorized to test. Unauthorized scanning is illegal.

---

## 🚀 Features

- **Comprehensive Vulnerability Detection (25+ Types)**
  - **Injection Attacks:** SQL, XSS, Command, LDAP, XML/XXE, NoSQL, SSTI
  - **Authentication Issues:** Username enumeration, weak policies, session management
  - **Sensitive Data Exposure:** Credit cards, SSNs, API keys, private keys, cloud credentials
  - **Security Misconfigurations:** Missing headers, risky methods, directory listing
  - **CSRF, IDOR, Open Redirect, Clickjacking, CORS**

- **Intelligent Crawling**
  - Same-origin enforcement with configurable depth
  - Sitemap and robots.txt discovery
  - Form extraction and parameter analysis
  - Up to 500 pages per scan

- **Professional Reporting**
  - Detailed findings with severity ratings (HIGH/MEDIUM/LOW)
  - CWE classifications for all vulnerabilities
  - Evidence, impact assessment, and remediation guidance
  - Text and JSON output formats

- **Advanced Scanning Controls**
  - Three scan modes: `passive`, `active`, `full`
  - Custom headers and cookies for authenticated scanning
  - Rate limiting to avoid detection
  - Path scoping for targeted assessments

- **CI/CD Integration**
  - GitHub Actions workflow for automated testing
  - JSON output for pipeline integration
  - Quiet mode for scripting

---

## 📦 Installation

### Using pipx (Recommended)
```bash
git clone https://github.com/harshzagade/Xploit.git
cd Xploit
pipx install .
```

### Using pip
```bash
pip install --user .
```

### Development Install
```bash
python3 -m pip install -e .
```

---

## 🎯 Quick Start

### Basic Scan
```bash
xploit https://target.example
```

### Full Scan with Custom Settings
```bash
xploit https://target.example \
  --mode full \
  --depth 4 \
  --max-pages 500 \
  --timeout 8
```

### Authenticated Scan
```bash
xploit https://target.example/dashboard \
  --header "Authorization: Bearer YOUR_TOKEN" \
  --cookie "session=YOUR_SESSION"
```

### JSON Output for Automation
```bash
xploit https://target.example \
  --format json \
  --quiet > results.json
```

### Passive Scan (Non-Intrusive)
```bash
xploit https://target.example \
  --mode passive \
  --scope-prefix /app
```

---

## 📖 Usage Examples

### Scan with Rate Limiting
```bash
xploit https://target.example --rate-limit 0.5
```

### Scope Scan to Specific Path
```bash
xploit https://target.example/api --scope-prefix /api
```

### Run Without Installing
```bash
python3 xploit.py https://target.example
python3 -m xploit https://target.example
```

---

## 🧪 Testing

### Test on Vulnerable Application
```bash
# Start the deliberately vulnerable test app
python3 vulnerable_test_app.py

# Run Xploit against it
xploit http://127.0.0.1:5000/ --mode full
```

**Expected Results:** 18 findings including SQL Injection and XSS

See [HOW_TO_TEST.md](./HOW_TO_TEST.md) for detailed testing instructions.

### Run Unit Tests
```bash
python3 -m pytest tests/
```

---

## 🛡️ Vulnerability Coverage

Xploit detects **25+ vulnerability types** across OWASP Top 10 categories:

| Category | Vulnerabilities | Detection Method |
|----------|----------------|------------------|
| **Injection** | SQL Injection (Error, Time, Union, Boolean, Stacked) | 5 SQLi techniques + response analysis |
| | Cross-Site Scripting (XSS) | 20 payload variations + reflection check |
| | Command Injection | Time-delay and output-based detection |
| | Directory Traversal | Path traversal payloads |
| | **LDAP Injection** | Error-based detection with LDAP payloads |
| | **XML Injection / XXE** | External entity payloads + file disclosure |
| | **NoSQL Injection** | MongoDB/CouchDB error patterns |
| | **Server-Side Template Injection (SSTI)** | Template expression evaluation |
| **Broken Authentication** | Credentials over HTTP | Form analysis |
| | **Username Enumeration** | Response timing/size differences |
| | **Weak Password Policy** | Policy indicator analysis |
| | **Session Token in URL** | Parameter analysis |
| | **Insecure Session Cookies** | Cookie flag validation |
| | **Default Credentials (Heuristic)** | Common credential patterns |
| **Sensitive Data** | API keys in comments | Regex pattern matching |
| | Config file exposure | Known file probing |
| | Technology disclosure | Header analysis |
| | **Credit Card Numbers** | Luhn-validated card patterns |
| | **Social Security Numbers** | SSN pattern detection |
| | **Private Keys** | RSA/EC/PGP key patterns |
| | **Database Connection Strings** | Connection string patterns |
| | **Cloud API Credentials** | AWS/Google/Stripe key patterns |
| | **Email Addresses (PII)** | Bulk email exposure detection |
| **Security Misconfiguration** | Missing CSP, HSTS, X-Frame-Options | Header validation |
| | Risky HTTP methods | OPTIONS request testing |
| | Directory listing | Response pattern matching |
| **CSRF** | Missing anti-CSRF tokens | POST form analysis |
| **Access Control** | IDOR indicators | Predictable ID detection |
| | Open Redirect | Redirect parameter testing |
| **Other** | CORS misconfiguration | CORS header analysis |
| | Clickjacking | Frame options check |
| | File upload surfaces | Input type detection |

---

## 📊 Sample Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                        XPLOIT ASSESSMENT REPORT                            
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[1] ASSESSMENT OVERVIEW
    Target URL        : https://target.example
    Scan Status       : COMPLETED
    Scan Mode         : FULL
    Duration          : 12.5s
    Pages Crawled     : 15
    Forms Discovered  : 8
    Total Findings    : 23

[2] FINDINGS SUMMARY
    CRITICAL/HIGH     : 8
    MEDIUM            : 10
    LOW               : 5

[3] DETAILED VULNERABILITY ANALYSIS

    ID: SQLi-001 | SQL Injection
    ────────────────────────────────────────────────────────────────────
    Severity    : HIGH
    Category    : SQL Injection
    CWE         : CWE-89
    Target      : GET https://target.example/user?id=1
    Parameter   : id
    Evidence    : MySQL error: You have an error in your SQL syntax
    Impact      : Attacker can read, modify, or delete database records
    Remediation : Use parameterized queries or prepared statements
```

---

## 🔧 CLI Options

```bash
usage: xploit <url> [options]

positional arguments:
  url                   target URL (e.g., https://example.com)

options:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  --depth DEPTH         crawl depth (default: 4)
  --max-pages MAX_PAGES maximum pages to crawl (default: 500)
  --timeout TIMEOUT     HTTP timeout per request in seconds (default: 6)
  --mode {passive,active,full}
                        scan mode
  --rate-limit RATE_LIMIT
                        minimum delay between requests in seconds
  --scope-prefix SCOPE_PREFIX
                        restrict crawling to a path prefix
  --format {text,json}  output format
  --header NAME: VALUE  add a custom HTTP header (repeatable)
  --cookie NAME=VALUE   add a cookie (repeatable)
  --insecure            disable SSL certificate verification
  --no-color            disable ANSI colors
  --quiet               suppress banner and progress output
```

---

## 🏗️ Architecture

```
xploit/
├── cli.py              # Command-line interface
├── scanner.py          # Core scanning engine
├── reporting.py        # Report generation
└── modules/            # Vulnerability detection modules
    ├── sqli.py        # SQL Injection
    ├── xss.py         # Cross-Site Scripting
    ├── injection_advanced.py  # Command Injection, Traversal
    ├── logic_vulnerabilities.py  # CSRF, Open Redirect
    ├── exposure.py    # Information Disclosure, IDOR
    └── general.py     # Headers, Auth, CORS
```

---

## 🧬 Scan Modes

### Passive Mode
- Analyzes observed responses only
- No payload injection
- Checks headers, comments, tech disclosure
- Safe for production environments

### Active Mode
- Injects payloads into parameters
- Tests for SQLi, XSS, Command Injection
- Probes for sensitive files
- More intrusive

### Full Mode (Default)
- Combines passive + active checks
- Comprehensive vulnerability coverage
- Recommended for security assessments

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🔒 Security

For security concerns or responsible disclosure, see [SECURITY.md](./SECURITY.md).

---

## 👨‍💻 Author

**Harsh Zagade**
- GitHub: [@harshzagade](https://github.com/harshzagade)
- LinkedIn: [harsh-zagade](https://linkedin.com/in/harsh-zagade)

---

## 📚 Additional Resources

- [Testing Guide](./HOW_TO_TEST.md) - How to test Xploit
- [Testing Report](./TESTING_REPORT.md) - Verification results
- [Changelog](./CHANGELOG.md) - Version history

---

## ⚖️ Disclaimer

This tool is provided for educational and authorized security testing purposes only. Users are responsible for complying with applicable laws and obtaining proper authorization before scanning any systems. The author assumes no liability for misuse or damage caused by this tool.

---

**Built with ❤️ for the cybersecurity community**
