# apikeyscanner — Complete Documentation

---

## Table of Contents

1. [What is apikeyscanner?](#1-what-is-apikeyscanner)
2. [What problem does it solve?](#2-what-problem-does-it-solve)
3. [Why secret leaks are dangerous](#3-why-secret-leaks-are-dangerous)
4. [How the scanner works internally](#4-how-the-scanner-works-internally)
5. [CLI usage](#5-cli-usage)
6. [Python library usage](#6-python-library-usage)
7. [Single file scan](#7-single-file-scan)
8. [Directory scan](#8-directory-scan)
9. [Full project recursive scan](#9-full-project-recursive-scan)
10. [Ignore rules](#10-ignore-rules)
11. [Severity levels](#11-severity-levels)
12. [JSON reports](#12-json-reports)
13. [FastAPI integration](#13-fastapi-integration)
14. [ScanResult object](#14-scanresult-object)
15. [How regex patterns work](#15-how-regex-patterns-work)
16. [How secrets are masked](#16-how-secrets-are-masked)
17. [How logging works](#17-how-logging-works)
18. [How to add a new detection pattern](#18-how-to-add-a-new-detection-pattern)
19. [How to run tests](#19-how-to-run-tests)
20. [How to publish to PyPI](#20-how-to-publish-to-pypi)
21. [How to publish to GitHub](#21-how-to-publish-to-github)
22. [Future improvements](#22-future-improvements)

---

## 1. What is apikeyscanner?

`apikeyscanner` is a Python security tool that scans local files and directories for hardcoded secrets.

It looks for:
- API keys (OpenAI, Google, AWS, Stripe, etc.)
- Access tokens (GitHub, GitLab, HuggingFace, etc.)
- Database connection strings with embedded credentials
- Hardcoded passwords and secrets
- Private key blocks (RSA, EC, OpenSSH, PGP)
- `.env` file sensitive values
- JWT tokens and Bearer tokens

It works both as a **CLI tool** and as a **Python library**, making it useful for:
- Developers checking their own projects before pushing to GitHub
- DevOps teams running pre-deployment security checks
- Security teams auditing codebases
- CI/CD pipelines as an automated security gate

---

## 2. What problem does it solve?

Developers frequently make mistakes like:

```python
# BAD — never do this
OPENAI_API_KEY = "sk-real-key-here-1234567890ABCDEF"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_URL = "postgresql://admin:password123@prod-db:5432/mydb"
```

These secrets often end up in:
- Version control (Git, GitHub, GitLab)
- Docker images pushed to Docker Hub
- Log files stored in S3 buckets
- Deployment scripts shared between team members

`apikeyscanner` catches these mistakes **before** they reach production or version control.

---

## 3. Why secret leaks are dangerous

Leaked secrets allow attackers to:

- **Drain cloud resources** — AWS, GCP, Azure accounts can be abused to spin up thousands of servers for crypto mining, costing tens of thousands of dollars overnight.
- **Access private data** — Database credentials give full access to all customer data.
- **Send malicious emails** — SendGrid/Mailgun keys allow spamming millions of users from your domain.
- **Make unauthorized payments** — Stripe live keys allow attackers to process refunds, create charges, or extract your Stripe balance.
- **Impersonate your service** — OpenAI keys rack up massive API bills on your account.

Real incidents:
- Uber: 57 million user records exposed due to AWS credentials in a private GitHub repo.
- Toyota: Vehicle location data for 2 million customers exposed due to a key leaked in a public GitHub repo for 5 years.
- Twitch: $125 million in creator payouts leaked due to misconfigured access credentials.

---

## 4. How the scanner works internally

### Module architecture

```
apikeyscanner/
├── __init__.py     → Public API (exposes scan())
├── scanner.py      → Core engine: file collection + pattern matching
├── patterns.py     → All detection patterns (regex + metadata)
├── result.py       → ScanResult + Finding data classes
├── reporter.py     → JSON report saving/loading
├── cli.py          → Typer CLI + Rich terminal UI
├── logger.py       → Structured logging
└── utils.py        → File filtering, masking, path helpers
```

### Scan flow

```
scan(path) called
    ↓
resolve_path() → absolute Path object
    ↓
detect_scan_mode() → "file", "directory", or "project"
    ↓
_collect_files()
    - If file: return [path]
    - If directory: walk recursively, apply ignore rules
    ↓
For each file:
    is_binary_file() → skip if binary
    read_text() → get content
    For each Pattern:
        re.compile(regex) → compiled pattern
        finditer() → iterate over matches
        mask_secret() → mask the matched value
        create Finding(severity, type, file, line, match, ...)
    ↓
Build ScanResult(findings, scanned_count, skipped_count, ...)
    ↓
Apply severity filter if requested
    ↓
Return ScanResult
```

---

## 5. CLI usage

### Install

```bash
pip install -e .
```

### Commands

#### `scan` — main command

```bash
apikeyscanner scan PATH [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `PATH` | File or directory to scan (default: `.`) |
| `--recursive / -r` | Recursively scan subdirectories (default: True) |
| `--output / -o FILE` | Save JSON report to a file |
| `--json` | Print raw JSON output (useful for CI/CD) |
| `--severity / -s TEXT` | Filter by severity: HIGH, MEDIUM, LOW (comma-separated) |
| `--ignore / -i TEXT` | Extra directory names to ignore (repeatable) |
| `--verbose / -v` | Show detailed debug output |

#### `version` — show version

```bash
apikeyscanner version
```

### CLI examples

```bash
# Scan current directory
apikeyscanner scan .

# Scan a specific file
apikeyscanner scan ./config.py

# Scan a directory
apikeyscanner scan ./backend

# Only show HIGH severity findings
apikeyscanner scan . --severity HIGH

# Show HIGH and MEDIUM
apikeyscanner scan . --severity HIGH,MEDIUM

# Save report
apikeyscanner scan . --output reports/report.json

# Ignore directories
apikeyscanner scan . --ignore node_modules --ignore venv --ignore dist

# Raw JSON output (for piping or CI/CD)
apikeyscanner scan . --json

# Verbose mode (shows skipped files and debug logs)
apikeyscanner scan . --verbose

# Exit code: 0 = clean, 1 = secrets found
apikeyscanner scan . && echo "All clear!"
```

---

## 6. Python library usage

```python
import apikeyscanner as aks

# Simplest usage — scan current directory
result = aks.scan(".")

# All options
result = aks.scan(
    path=".",
    severity=["HIGH", "MEDIUM"],  # Only return these severity levels
    ignore=["node_modules", "venv", ".git"],  # Skip these directories
    recursive=True,  # Scan subdirectories
    verbose=False,   # Set True for debug logging
)

# Check results
print(result.total_findings)   # 4
print(result.has_high_risk)    # True
print(result.is_clean)         # False

# Loop through findings
for finding in result.findings:
    print(f"[{finding.severity}] {finding.type}")
    print(f"  File: {finding.file}, Line: {finding.line}")
    print(f"  Match: {finding.match}")
    print(f"  Fix: {finding.fix}")

# Save report
result.save_json("reports/report.json")
```

---

## 7. Single file scan

Scans exactly one file. Useful for quick checks.

```bash
# CLI
apikeyscanner scan ./config.py
apikeyscanner scan ./.env
apikeyscanner scan ./backend/auth.py
```

```python
# Library
result = aks.scan("./config.py")
print(result.scan_mode)  # "file"
print(result.scanned_files)  # 1
```

---

## 8. Directory scan

Scans all valid files in a directory and its subdirectories.

```bash
# CLI
apikeyscanner scan ./src
apikeyscanner scan ./backend
```

```python
# Library
result = aks.scan("./src")
print(result.scan_mode)  # "directory"
```

---

## 9. Full project recursive scan

Scanning `.` is treated as a **project scan** — it scans everything from the root, applying all ignore rules automatically.

```bash
# CLI
apikeyscanner scan .
```

```python
# Library
result = aks.scan(".")
print(result.scan_mode)  # "project"
```

The scanner will recurse into all subdirectories:

```
myproject/           ← scanned
├── app.py           ← scanned
├── config.py        ← scanned
├── .env             ← scanned
├── backend/
│   ├── settings.py  ← scanned
│   └── auth/
│       └── tokens.py  ← scanned (nested!)
├── frontend/
│   └── config.js    ← scanned
├── node_modules/    ← IGNORED
├── venv/            ← IGNORED
└── .git/            ← IGNORED
```

---

## 10. Ignore rules

### Default ignored directories

These are always ignored:

```
.git, venv, env, .venv, node_modules, __pycache__,
dist, build, .next, .cache, coverage, target,
.tox, .mypy_cache, .pytest_cache, .ruff_cache,
htmlcov, .eggs
```

### Custom ignore

```bash
apikeyscanner scan . --ignore my_custom_dir --ignore another_dir
```

```python
result = aks.scan(".", ignore=["my_custom_dir", "vendor", "third_party"])
```

### Scannable file types

The scanner only reads these file types:

```
.py, .js, .ts, .jsx, .tsx, .json, .env, .yaml, .yml,
.txt, .md, .toml, .ini, .cfg, .conf, .xml, .html,
.css, .sh, .bash, .zsh, .rb, .go, .rs, .java,
.php, .cs, .swift, .kt, .properties
```

Special filenames always scanned: `Dockerfile`, `docker-compose.yml`, `.env`, `.env.*`, `.npmrc`, `Makefile`, `Procfile`.

Binary files are detected and skipped automatically.

---

## 11. Severity levels

| Level | Color | When to use |
|-------|-------|-------------|
| `HIGH` | Red | Critical — rotate immediately. Live API keys, passwords, private keys. |
| `MEDIUM` | Yellow | Important — move to env vars. Tokens, JWT, database URLs. |
| `LOW` | Cyan | Informational — review manually. |

Filter by severity:

```python
# Only HIGH findings
result = aks.scan(".", severity=["HIGH"])

# HIGH and MEDIUM
result = aks.scan(".", severity=["HIGH", "MEDIUM"])
```

---

## 12. JSON reports

### Save a report

```bash
# CLI
apikeyscanner scan . --output reports/report.json
```

```python
# Library
result = aks.scan(".")
result.save_json("reports/report.json")
```

### Report format

```json
{
  "target": ".",
  "scan_mode": "project",
  "scanned_files": 58,
  "skipped_files": 12,
  "summary": {
    "total_findings": 4,
    "high": 2,
    "medium": 2,
    "low": 0
  },
  "findings": [
    {
      "severity": "HIGH",
      "type": "OpenAI API Key",
      "file": "config.py",
      "line": 12,
      "match": "sk-a********890",
      "description": "An OpenAI API key was found hardcoded in the source code.",
      "fix": "Remove the key from code. Store it in an environment variable (OPENAI_API_KEY)."
    }
  ]
}
```

---

## 13. FastAPI integration

See `examples/fastapi_usage.py` for the full example.

```python
from fastapi import FastAPI, HTTPException
import apikeyscanner as aks

app = FastAPI()

@app.post("/security/scan")
def scan_before_deploy():
    result = aks.scan(
        path="/srv/my-app",
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

This pattern is useful in:
- **Pre-deployment hooks** — run before `git push` or before a CI/CD deploy step
- **Internal security dashboards** — show security status in your admin panel
- **GitOps workflows** — scan repositories before applying changes

---

## 14. ScanResult object

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `target` | str | Path that was scanned |
| `scan_mode` | str | "file", "directory", or "project" |
| `findings` | list[Finding] | All detected secrets |
| `scanned_files` | int | Number of files scanned |
| `skipped_files` | int | Number of files skipped |
| `total_findings` | int | Total number of secrets found |
| `high_count` | int | Number of HIGH severity findings |
| `medium_count` | int | Number of MEDIUM severity findings |
| `low_count` | int | Number of LOW severity findings |
| `has_findings` | bool | True if any secrets found |
| `has_high_risk` | bool | True if any HIGH findings |
| `is_clean` | bool | True if zero findings |
| `summary` | dict | Compact summary dictionary |

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `to_dict()` | dict | Full result as Python dictionary |
| `to_json()` | str | Full result as JSON string |
| `save_json(path)` | None | Save JSON report to disk |
| `filter_by_severity(levels)` | ScanResult | New result with filtered findings |

### Finding object

| Property | Type | Description |
|----------|------|-------------|
| `severity` | str | HIGH, MEDIUM, or LOW |
| `type` | str | Pattern name (e.g., "OpenAI API Key") |
| `file` | str | Relative file path |
| `line` | int | Line number (1-indexed) |
| `match` | str | Masked secret value |
| `description` | str | What was detected |
| `fix` | str | How to fix it |

---

## 15. How regex patterns work

Each pattern in `patterns.py` is a `Pattern` dataclass:

```python
@dataclass
class Pattern:
    name: str        # Human-readable name
    regex: str       # Python regex string
    severity: str    # HIGH, MEDIUM, LOW
    description: str # What this pattern detects
    fix: str         # How to remediate
```

Example:

```python
Pattern(
    name="OpenAI API Key",
    regex=r"sk-[A-Za-z0-9]{20,}",
    severity="HIGH",
    description="An OpenAI API key was found hardcoded in the source code.",
    fix="Remove the key from code. Store it in an environment variable.",
)
```

The regex `sk-[A-Za-z0-9]{20,}` means:
- `sk-` — literal prefix of all OpenAI keys
- `[A-Za-z0-9]{20,}` — 20 or more alphanumeric characters

Patterns are compiled with `re.MULTILINE | re.IGNORECASE` for maximum coverage.

---

## 16. How secrets are masked

The `mask_secret()` function in `utils.py` ensures full secret values are never printed:

```
sk-abcdef1234567890ABCDEF
     ↓
sk-a********EF
```

Rules:
- First 4 characters preserved (prefix identification)
- Last 3 characters preserved (suffix identification)
- Everything in between replaced with `********`
- Very short values: first 2 + `****` + last 2

This means a security reviewer can:
- Identify *which* key it might be from the prefix
- Confirm it's the same key they have in their records from the suffix
- But cannot reconstruct the full secret from the masked value

---

## 17. How logging works

`logger.py` provides a module-level logger using Python's built-in `logging`.

Default behavior:
- Log level: `WARNING` (silent unless there are errors)
- Output: `stderr` (doesn't interfere with JSON output on `stdout`)

Verbose mode (`--verbose`):
- Log level: `DEBUG`
- Shows: each file scanned, each file skipped, each finding, report saves

```python
# Enable verbose logging from library
result = aks.scan(".", verbose=True)
```

Full secrets are **never** logged — only masked values and pattern names.

---

## 18. How to add a new detection pattern

1. Open `apikeyscanner/patterns.py`
2. Add a new `Pattern` to the `PATTERNS` list:

```python
Pattern(
    name="Notion API Key",
    regex=r"secret_[A-Za-z0-9]{43}",
    severity="HIGH",
    description="A Notion integration secret was found in the source code.",
    fix="Revoke this key in Notion integrations and store it as an environment variable.",
),
```

3. Test it:

```python
# Quick test
import apikeyscanner as aks

# Create a temp file with a fake Notion key
result = aks.scan("./test_file.py")
notion_findings = [f for f in result.findings if f.type == "Notion API Key"]
print(notion_findings)
```

4. Add a test in `tests/test_scanner.py` for the new pattern.

Tips for writing good regex:
- Be specific enough to avoid false positives
- Use `(?i)` for case-insensitive matching when appropriate
- Test against real key format documentation
- Consider using anchors like `(?<![A-Z0-9])` to avoid mid-word matches

---

## 19. How to run tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# Run with verbose output
pytest -v

# Run with coverage report
pytest --cov=apikeyscanner --cov-report=term-missing

# Run a specific test file
pytest tests/test_scanner.py

# Run a specific test class
pytest tests/test_scanner.py::TestOpenAIKeyDetection

# Run a specific test function
pytest tests/test_scanner.py::TestOpenAIKeyDetection::test_detects_openai_key_in_file
```

---

## 20. How to publish to PyPI

Build and upload the package with the official Python packaging tools:

```bash
# Install packaging tools
python -m pip install --upgrade build twine

# Build source and wheel distributions
python -m build

# Validate package metadata and README rendering
python -m twine check dist/*

# Upload to PyPI
python -m twine upload dist/*
```

Use `__token__` as the username and a PyPI API token as the password when prompted.

Package owner/contact metadata:

- Author: devxyasir
- Email: jamyasir0534@gmail.com
- GitHub: https://github.com/devxyasir
- LinkedIn: https://www.linkedin.com/in/devxyasir/
- X: https://x.com/devxyasir
- Instagram: https://www.instagram.com/devxyasir/

---

## 21. How to publish to GitHub

```bash
# Initialize git
cd apikeyscanner
git init
git add .
git commit -m "Initial release: apikeyscanner v1.0.0"

# Create repo on GitHub, then:
git remote add origin https://github.com/devxyasir/apikeyscanner.git
git branch -M main
git push -u origin main
```

### Recommended GitHub repo settings

1. **Topics**: `security`, `api-keys`, `secret-detection`, `devops`, `python`, `cli`
2. **Description**: "A local secret leak detection tool for developers and DevOps teams"
3. **Add a license**: MIT
4. **GitHub Actions CI**: Add a workflow to run `pytest` on every push

Example `.github/workflows/ci.yml`:

```yaml
name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -e ".[dev]"
      - run: pytest --cov=apikeyscanner
```

---

## 22. Future improvements

Ideas for v2.0 and beyond:

### Detection
- [ ] Add more patterns: Anthropic, Cohere, Replicate, Pinecone, Supabase, PlanetScale
- [ ] Entropy-based detection (detect high-entropy strings that may be secrets even without known prefixes)
- [ ] Context-aware scanning (detect secrets based on variable names, not just values)
- [ ] Custom pattern files (load additional patterns from a YAML/JSON file)
- [ ] `.apikeyscannerignore` file support (similar to `.gitignore`)

### Output
- [ ] HTML report with interactive findings table
- [ ] SARIF output format (for GitHub Advanced Security integration)
- [ ] Markdown report format
- [ ] CSV export

### Performance
- [ ] Parallel file scanning using `concurrent.futures`
- [ ] Incremental scanning (only scan files changed since last scan)
- [ ] File size limits with configurable threshold

### Integrations
- [ ] Pre-commit hook (detect secrets before `git commit`)
- [ ] GitHub Actions integration
- [ ] VS Code extension
- [ ] Docker image for CI/CD pipelines

### Safety
- [ ] Allowlist / whitelist for known false positives
- [ ] Minimum confidence threshold per pattern
- [ ] Machine learning classifier for reducing false positives
