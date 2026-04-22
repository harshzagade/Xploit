# Xploit

Xploit is a CLI-based web vulnerability scanner for authorized security assessments. It performs bounded crawling, tests high-risk input surfaces, and prints clear findings directly in the terminal.

> Use Xploit only on applications you own or are explicitly authorized to test.

## Features

- Terminal-first workflow with no output files required.
- Same-origin crawling with configurable depth and page limits.
- Detailed findings with severity, confidence, CWE, evidence, impact, remediation, and validation guidance.
- Clean handling for unreachable targets.
- Universal `xploit` command via Python package entry point.

## Vulnerability Coverage

Xploit checks for:

- SQL Injection
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Command Injection
- Directory Traversal
- Insecure HTTP Headers
- Broken Authentication
- Sensitive Data Exposure
- Open Redirect
- Security Misconfiguration

## Installation

Clone the repository:

```bash
git clone https://github.com/<your-username>/Xploit.git
cd Xploit
```

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Install as a global CLI command:

```bash
python3 -m pip install -e .
```

Verify:

```bash
xploit --help
```

## Usage

Scan a target:

```bash
xploit https://target.example
```

Tune crawl depth, page count, and timeout:

```bash
xploit https://target.example --depth 2 --max-pages 40 --timeout 8
```

Run without installing:

```bash
python3 xploit.py https://target.example
python3 -m xploit https://target.example
```

Interactive prompt:

```bash
xploit
```

## CLI Options

```text
usage: xploit <url> [options]

options:
  --depth DEPTH         crawl depth inside the same origin
  --max-pages N         maximum pages to crawl
  --timeout SECONDS     HTTP timeout per request
  --no-color            disable ANSI colors
  --quiet               print compact terminal output
  -v, --version         show version
  -h, --help            show help
```

## Example Output

```text
Scan Overview
------------------------------------------------------------------------
Target URL        : https://target.example/
Scan status       : COMPLETED
Duration          : 5.84s
Pages crawled     : 2
Forms discovered  : 1
Total findings    : 8
High severity     : 4
Medium severity   : 4
Low severity      : 0

Detailed Findings
------------------------------------------------------------------------
[01] HIGH Missing Content-Security-Policy
     Finding ID     : HDR-001
     Category       : Insecure HTTP Headers
     Confidence     : High
     Affected URL   : https://target.example/
     CWE            : CWE-693
     Evidence       : Response does not include `content-security-policy`.
     Remediation    : Set a strict `content-security-policy` header.
```

## Development

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m pip install -e .
```

Validate:

```bash
python3 -m compileall xploit xploit.py
xploit --help
```

## Safety Notes

Xploit uses visible, non-stealth probes and does not attempt persistence, evasion, credential theft, exploit chaining, or destructive actions. Findings should be manually validated before being reported as confirmed vulnerabilities.

## License

MIT License. See [LICENSE](LICENSE).
