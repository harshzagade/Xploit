# Contributing

Contributions are welcome if they keep Xploit focused on authorized, defensive security testing.

## Development Setup

```bash
git clone https://github.com/<your-username>/Xploit.git
cd Xploit
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m pip install -e .
```

## Validation

Before submitting changes, run:

```bash
python3 -m compileall xploit xploit.py
xploit --help
```

## Pull Request Guidelines

- Keep scanner checks bounded and non-destructive.
- Avoid stealth, evasion, persistence, credential theft, or exploit chaining features.
- Include clear evidence and remediation text for new findings.
- Prefer terminal-readable output over generated files.
