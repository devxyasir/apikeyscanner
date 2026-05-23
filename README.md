# 🔍 apikeyscanner

**A local secret leak detection tool for developers and DevOps teams.**

Detect leaked API keys, tokens, passwords, and secrets inside your files and projects — before they reach production or get pushed to GitHub.

---

## ✨ What It Does

`apikeyscanner` scans local files and directories for hardcoded secrets like:

- OpenAI, Anthropic, HuggingFace API keys
- AWS, Google Cloud, Azure credentials
- GitHub, GitLab personal access tokens
- Stripe, PayPal payment keys
- Slack, Discord, Telegram bot tokens
- Database connection strings (PostgreSQL, MySQL, MongoDB, Redis)
- Hardcoded passwords, secrets, and tokens
- JWT tokens and Bearer tokens
- Private key blocks (RSA, EC, OpenSSH, PGP)
- `.env` file sensitive values

---

## 📦 Installation

```bash
# Install from PyPI
pip install apikeyscanner

# Clone the repository
git clone https://github.com/devxyasir/apikeyscanner.git
cd apikeyscanner

# Install in development mode
pip install -e .

# Or install with dev tools
pip install -e ".[dev]"
```

---

## ⚡ Quick Start

### CLI

```bash
# Scan the current project
apikeyscanner scan .

# Scan a specific file
apikeyscanner scan ./config.py

# Scan a directory
apikeyscanner scan ./src

# Only show HIGH severity findings
apikeyscanner scan . --severity HIGH

# Save a JSON report
apikeyscanner scan . --output reports/report.json

# Ignore specific directories
apikeyscanner scan . --ignore node_modules --ignore venv

# Print raw JSON output (great for CI/CD)
apikeyscanner scan . --json
```

### Python Library

```python
import apikeyscanner as aks

# Scan a file
result = aks.scan("./config.py")

# Scan a directory
result = aks.scan("./src")

# Scan the full project
result = aks.scan(".")

# Check for high-risk secrets
if result.has_high_risk:
    print(f"❌ {result.high_count} HIGH-risk secrets found!")
else:
    print("✅ No high-risk secrets found.")

# Access findings
for finding in result.findings:
    print(f"[{finding.severity}] {finding.type} in {finding.file}:{finding.line}")

# Save a JSON report
result.save_json("reports/report.json")
```

---

## 🖥️ CLI Examples

```bash
# Full project scan with verbose output
apikeyscanner scan . --verbose

# Scan and fail CI if HIGH secrets found (exit code 1)
apikeyscanner scan . --severity HIGH --json && echo "Safe" || echo "SECRETS FOUND"

# Scan a .env file
apikeyscanner scan .env

# Check version
apikeyscanner version
```

---

## 📊 Example Terminal Output

```
╭──────────────────────────────────────────╮
│            API Key Scanner               │
│    Local Secret Leak Detection Tool      │
╰──────────────────────────────────────────╯

  Target:  ./myproject

  Found 4 possible secret(s)

 Severity   Type                File                  Line   Match
 ─────────  ──────────────────  ────────────────────  ─────  ─────────────────
 HIGH       OpenAI API Key      config.py             12     sk-a********890
 HIGH       AWS Access Key ID   .env                  4      AKIA********XMP
 MEDIUM     Hardcoded Token     backend/auth.py       33     tok-a********456
 MEDIUM     Database URL        docker-compose.yml    18     post********3/db

╭────────────────────── Summary ────────────────────────╮
│  Scanned files:   58                                  │
│  Skipped files:   12                                  │
│  High findings:   2                                   │
│  Medium findings: 2                                   │
│  Low findings:    0                                   │
│                                                       │
│  Security Status: FAILED ❌                           │
│  Fix the detected secrets before pushing or deploying.│
╰───────────────────────────────────────────────────────╯
```

---

## 🐍 Python Library API

```python
import apikeyscanner as aks

result = aks.scan(
    path=".",
    severity=["HIGH", "MEDIUM"],   # filter by severity
    ignore=["node_modules", "venv"],
    recursive=True,
)

# Properties
result.total_findings    # int: total number of secrets found
result.high_count        # int: count of HIGH severity findings
result.medium_count      # int: count of MEDIUM severity findings
result.low_count         # int: count of LOW severity findings
result.has_findings      # bool: True if any secrets found
result.has_high_risk     # bool: True if any HIGH findings
result.is_clean          # bool: True if no secrets found
result.scan_mode         # str: "file", "directory", or "project"
result.scanned_files     # int: number of files scanned
result.skipped_files     # int: number of files skipped

# Methods
result.summary           # dict: compact summary
result.to_dict()         # dict: full result as dictionary
result.to_json()         # str: full result as JSON string
result.save_json("path") # save report to disk
```

---

## 🔗 FastAPI Integration

```python
from fastapi import FastAPI, HTTPException
import apikeyscanner as aks

app = FastAPI()

@app.post("/security/scan")
def scan_project():
    result = aks.scan(
        path="/srv/backend-app",
        severity=["HIGH"],
        ignore=["venv", "node_modules"],
    )

    if result.has_high_risk:
        raise HTTPException(
            status_code=403,
            detail={
                "message": "Deployment blocked. Secrets detected.",
                "findings": [f.to_dict() for f in result.findings],
            }
        )

    return {"message": "Safe to deploy.", "summary": result.summary}
```

---

## 🧪 Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# Run with coverage
pytest --cov=apikeyscanner

# Run a specific test class
pytest tests/test_scanner.py::TestOpenAIKeyDetection -v
```

---

## 📁 Project Structure

```
apikeyscanner/
├── apikeyscanner/
│   ├── __init__.py      # Public API: exposes scan()
│   ├── scanner.py       # Core scanning engine
│   ├── patterns.py      # All detection patterns (regex + metadata)
│   ├── result.py        # ScanResult and Finding classes
│   ├── reporter.py      # JSON report generation
│   ├── cli.py           # Typer CLI + Rich terminal UI
│   ├── logger.py        # Structured logging
│   └── utils.py         # File filtering, masking, path helpers
├── tests/
│   ├── test_scanner.py  # Pytest test suite
│   └── sample_files/    # Test fixtures
├── examples/
│   ├── basic_usage.py   # Library usage examples
│   └── fastapi_usage.py # FastAPI integration
├── reports/             # Generated reports (gitignored)
├── README.md
├── DOCUMENTATION.md
├── pyproject.toml
└── requirements.txt
```

---

## 🛡️ Severity Levels

| Level  | Color  | Meaning                                                                      |
|--------|--------|------------------------------------------------------------------------------|
| HIGH   | 🔴 Red | Critical secrets: API keys, passwords, private keys. Rotate immediately.     |
| MEDIUM | 🟡 Yellow | Tokens, URLs with credentials, JWT tokens. Review and move to env vars.   |
| LOW    | 🔵 Cyan | Informational patterns that may indicate sensitive configuration.            |

---

## ⚠️ Ethical Note

This tool is **defensive only**. It is designed to protect your own projects.

- It only scans **local files on your own machine**.
- It does **not** send data to any server.
- It does **not** exploit or exfiltrate secrets.
- It **masks** secret values in all output.
- It is intended for use by developers, DevOps teams, and security teams to protect their own codebases.

**Never use this tool on files or systems you do not own or have explicit permission to scan.**

---

## 👤 Author

- **Author:** devxyasir
- **Email:** jamyasir0534@gmail.com
- **GitHub:** https://github.com/devxyasir
- **LinkedIn:** https://www.linkedin.com/in/devxyasir/
- **X:** https://x.com/devxyasir
- **Instagram:** https://www.instagram.com/devxyasir/

---

## 📄 License

MIT © devxyasir
