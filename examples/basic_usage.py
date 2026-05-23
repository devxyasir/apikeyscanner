"""
examples/basic_usage.py
=======================

Shows the most common ways to use apikeyscanner as a Python library.
Run this file from the project root:

    python examples/basic_usage.py
"""

import apikeyscanner as aks

# ──────────────────────────────────────────────
# 1. Scan a single file
# ──────────────────────────────────────────────
print("=" * 50)
print("1. Scanning a single file")
print("=" * 50)

result = aks.scan("tests/sample_files/unsafe_config.py")

print(f"Scan mode: {result.scan_mode}")
print(f"Total findings: {result.total_findings}")
print(f"High risk: {result.has_high_risk}")

for finding in result.findings:
    print(f"  [{finding.severity}] {finding.type} — line {finding.line} — {finding.match}")


# ──────────────────────────────────────────────
# 2. Scan a directory
# ──────────────────────────────────────────────
print("\n" + "=" * 50)
print("2. Scanning a directory")
print("=" * 50)

result = aks.scan("tests/sample_files")

print(f"Scan mode: {result.scan_mode}")
print(f"Files scanned: {result.scanned_files}")
print(f"Total findings: {result.total_findings}")


# ──────────────────────────────────────────────
# 3. Scan with severity filter
# ──────────────────────────────────────────────
print("\n" + "=" * 50)
print("3. Scanning with severity filter (HIGH only)")
print("=" * 50)

result = aks.scan("tests/sample_files", severity=["HIGH"])

print(f"HIGH findings: {result.high_count}")
print(f"MEDIUM findings: {result.medium_count}  ← should be 0 (filtered out)")


# ──────────────────────────────────────────────
# 4. Scan with ignore list
# ──────────────────────────────────────────────
print("\n" + "=" * 50)
print("4. Scanning with ignore list")
print("=" * 50)

result = aks.scan(".", ignore=["node_modules", "venv", ".git", "reports"])

print(f"Scan mode: {result.scan_mode}")
print(f"Files scanned: {result.scanned_files}")
print(f"Files skipped: {result.skipped_files}")
print(f"Total findings: {result.total_findings}")


# ──────────────────────────────────────────────
# 5. Check if project is safe to deploy
# ──────────────────────────────────────────────
print("\n" + "=" * 50)
print("5. Deployment readiness check")
print("=" * 50)

result = aks.scan("tests/sample_files", severity=["HIGH"])

if result.has_high_risk:
    print(f"❌ Deployment BLOCKED — {result.high_count} HIGH-risk secret(s) found!")
    for f in result.findings:
        print(f"   {f.file}:{f.line} — {f.type}")
else:
    print("✅ No HIGH-risk secrets found. Safe to deploy.")


# ──────────────────────────────────────────────
# 6. Save a JSON report
# ──────────────────────────────────────────────
print("\n" + "=" * 50)
print("6. Saving JSON report")
print("=" * 50)

result = aks.scan("tests/sample_files")
result.save_json("reports/example_report.json")
print("✅ Report saved to reports/example_report.json")


# ──────────────────────────────────────────────
# 7. Access the full summary
# ──────────────────────────────────────────────
print("\n" + "=" * 50)
print("7. Summary dict")
print("=" * 50)

import json
print(json.dumps(result.summary, indent=2))
