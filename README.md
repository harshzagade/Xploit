# Xploit

![Python](https://img.shields.io/badge/python-3.x-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Version](https://img.shields.io/badge/version-1.0.0-orange.svg)

**Xploit** is a high-performance web vulnerability scanner designed for security professionals and bug bounty hunters. It crawls targets to identify common misconfigurations and security vulnerabilities with speed and precision.

---

## ⚡ Features
- **High-Performance Scanning:** Efficient multi-threaded crawling.
- **Coverage:** SQLi, XSS, CSRF, Command Injection, Directory Traversal, and more.
- **Color-Coded Output:** Easy-to-read terminal interface for quick triage.
- **Customizable:** Adjust scan depth, speed, and timeout settings.

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/harshzagade/Xploit.git
cd Xploit

# Install dependencies
pip install -r requirements.txt
```

---

## 📖 Usage

Simple scan:
```bash
python3 xploit.py https://example.com
```

Tuned scan:
```bash
python3 xploit.py https://example.com --depth 2 --max-pages 50
```

---

## 🖥️ Output Preview
```text
  [01] [HIGH] SQL Injection
       Finding ID     : SQL-01
       Affected URL   : https://example.com/login.php?id=1
       Evidence       : ' UNION SELECT null, null --
       Remediation    : Use parameterized queries/prepared statements.
```

---

## 📜 Disclaimer
This tool is for **authorized security assessments only**. Using this tool against targets without prior authorization is illegal. The author assumes no responsibility for any misuse or damage caused.

## ⚖️ License
This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.
