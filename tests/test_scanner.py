"""
Tests for apikeyscanner.

Covers:
- Single file scanning
- Directory scanning
- Recursive folder scanning
- Ignore rules
- Secret masking
- Severity filtering
- JSON report saving
- Scan mode detection
- Edge cases (clean files, binary files)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import apikeyscanner as aks
from apikeyscanner.utils import mask_secret, is_ignored_dir, is_scannable_file
from apikeyscanner.result import ScanResult, Finding

# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

SAMPLE_DIR = Path(__file__).parent / "sample_files"
UNSAFE_CONFIG = SAMPLE_DIR / "unsafe_config.py"
UNSAFE_ENV = SAMPLE_DIR / "unsafe_env.env"
CLEAN_FILE = SAMPLE_DIR / "clean_file.py"


# ──────────────────────────────────────────────
# 1. OpenAI Key Detection
# ──────────────────────────────────────────────

class TestOpenAIKeyDetection:
    def test_detects_openai_key_in_file(self):
        """Scanner should detect the fake OpenAI key in unsafe_config.py."""
        result = aks.scan(UNSAFE_CONFIG)
        openai_findings = [f for f in result.findings if f.type == "OpenAI API Key"]
        assert len(openai_findings) >= 1, "Expected to find at least one OpenAI API key"

    def test_openai_finding_has_correct_severity(self):
        result = aks.scan(UNSAFE_CONFIG)
        openai_findings = [f for f in result.findings if f.type == "OpenAI API Key"]
        assert all(f.severity == "HIGH" for f in openai_findings)

    def test_openai_finding_has_masked_value(self):
        result = aks.scan(UNSAFE_CONFIG)
        openai_findings = [f for f in result.findings if f.type == "OpenAI API Key"]
        for finding in openai_findings:
            # Masked value should NOT contain the full original key
            assert "fakeOpenAIkey1234567890ABCDEFG" not in finding.match
            # Should contain asterisks
            assert "*" in finding.match

    def test_openai_finding_has_line_number(self):
        result = aks.scan(UNSAFE_CONFIG)
        openai_findings = [f for f in result.findings if f.type == "OpenAI API Key"]
        for finding in openai_findings:
            assert finding.line > 0


# ──────────────────────────────────────────────
# 2. Hardcoded Password Detection
# ──────────────────────────────────────────────

class TestHardcodedPasswordDetection:
    def test_detects_hardcoded_password(self):
        result = aks.scan(UNSAFE_CONFIG)
        password_findings = [f for f in result.findings if "Password" in f.type or "password" in f.type.lower()]
        assert len(password_findings) >= 1, "Expected to detect a hardcoded password"

    def test_password_finding_has_fix(self):
        result = aks.scan(UNSAFE_CONFIG)
        for finding in result.findings:
            assert len(finding.fix) > 0, "Every finding should include a fix suggestion"


# ──────────────────────────────────────────────
# 3. .env Secret Detection
# ──────────────────────────────────────────────

class TestEnvFileDetection:
    def test_detects_secrets_in_env_file(self):
        result = aks.scan(UNSAFE_ENV)
        assert result.total_findings >= 1, "Expected at least one secret in .env file"

    def test_env_scan_mode_is_file(self):
        result = aks.scan(UNSAFE_ENV)
        assert result.scan_mode == "file"

    def test_env_scanned_files_is_one(self):
        result = aks.scan(UNSAFE_ENV)
        assert result.scanned_files == 1


# ──────────────────────────────────────────────
# 4. Clean File — No False Positives
# ──────────────────────────────────────────────

class TestCleanFile:
    def test_clean_file_has_no_findings(self):
        result = aks.scan(CLEAN_FILE)
        assert result.total_findings == 0, (
            f"Clean file should have zero findings but got: "
            f"{[f.type for f in result.findings]}"
        )

    def test_clean_file_is_not_high_risk(self):
        result = aks.scan(CLEAN_FILE)
        assert not result.has_high_risk

    def test_clean_file_result_is_clean(self):
        result = aks.scan(CLEAN_FILE)
        assert result.is_clean


# ──────────────────────────────────────────────
# 5. Directory Scan
# ──────────────────────────────────────────────

class TestDirectoryScan:
    def test_scans_directory(self):
        result = aks.scan(SAMPLE_DIR)
        assert result.scan_mode == "directory"
        assert result.scanned_files >= 2

    def test_directory_scan_finds_secrets(self):
        result = aks.scan(SAMPLE_DIR)
        assert result.total_findings >= 1


# ──────────────────────────────────────────────
# 6. Nested Folder Scan
# ──────────────────────────────────────────────

class TestNestedFolderScan:
    def test_recursive_scan_finds_nested_files(self, tmp_path):
        """Scanner should find secrets in deeply nested subdirectories."""
        nested = tmp_path / "src" / "auth" / "tokens"
        nested.mkdir(parents=True)

        secret_file = nested / "config.py"
        secret_file.write_text(
            'OPENAI_KEY = "sk-FakeNestedKey1234567890ABCDEFtest"\n',
            encoding="utf-8",
        )

        result = aks.scan(tmp_path, recursive=True)
        assert result.total_findings >= 1
        assert any("config.py" in f.file for f in result.findings)


# ──────────────────────────────────────────────
# 7. Ignore Rules
# ──────────────────────────────────────────────

class TestIgnoreRules:
    def test_ignores_node_modules(self, tmp_path):
        """Secrets inside node_modules should be skipped."""
        nm = tmp_path / "node_modules" / "some_package"
        nm.mkdir(parents=True)

        secret_file = nm / "index.js"
        secret_file.write_text(
            'const key = "sk-FakeNodeModulesKey1234567890ABCDEF";\n',
            encoding="utf-8",
        )

        result = aks.scan(tmp_path, recursive=True)
        # node_modules is in default ignore list — no findings expected
        assert result.total_findings == 0

    def test_ignores_venv(self, tmp_path):
        """Secrets inside venv should be skipped."""
        venv_dir = tmp_path / "venv" / "lib"
        venv_dir.mkdir(parents=True)

        secret_file = venv_dir / "settings.py"
        secret_file.write_text(
            'SECRET = "password=FakeVenvPassword123"\n',
            encoding="utf-8",
        )

        result = aks.scan(tmp_path, recursive=True)
        assert result.total_findings == 0

    def test_custom_ignore_dir(self, tmp_path):
        """A custom ignore directory should be skipped."""
        custom_dir = tmp_path / "my_custom_ignore"
        custom_dir.mkdir()

        secret_file = custom_dir / "secrets.py"
        secret_file.write_text(
            'API_KEY = "sk-FakeCustomIgnoreKey1234567890ABC"\n',
            encoding="utf-8",
        )

        result = aks.scan(tmp_path, ignore=["my_custom_ignore"])
        assert result.total_findings == 0

    def test_is_ignored_dir_defaults(self):
        assert is_ignored_dir(".git") is True
        assert is_ignored_dir("node_modules") is True
        assert is_ignored_dir("venv") is True
        assert is_ignored_dir("src") is False
        assert is_ignored_dir("myapp") is False


# ──────────────────────────────────────────────
# 8. Secret Masking
# ──────────────────────────────────────────────

class TestSecretMasking:
    def test_mask_long_secret(self):
        secret = "sk-abcdef1234567890ABCDEF"
        masked = mask_secret(secret)
        assert "*" in masked
        # Original secret should not appear fully
        assert secret not in masked
        # Prefix preserved
        assert masked.startswith(secret[:4])
        # Suffix preserved
        assert masked.endswith(secret[-3:])

    def test_mask_short_secret(self):
        secret = "abc123"
        masked = mask_secret(secret)
        assert "*" in masked
        assert len(masked) >= len(secret)

    def test_mask_does_not_return_empty(self):
        for s in ["x", "ab", "abc", "abcd", "abcde1234567890"]:
            assert len(mask_secret(s)) > 0

    def test_findings_are_masked(self):
        """All findings returned by the scanner must have masked values."""
        result = aks.scan(UNSAFE_CONFIG)
        for finding in result.findings:
            # Should not contain a long uninterrupted alphanum string without masking
            assert len(finding.match) > 0
            # Masked value should contain asterisks for non-trivial matches
            if len(finding.match) > 8:
                assert "*" in finding.match, f"Finding match not masked: {finding.match}"


# ──────────────────────────────────────────────
# 9. JSON Report Saving
# ──────────────────────────────────────────────

class TestJSONReport:
    def test_save_json_report(self, tmp_path):
        result = aks.scan(UNSAFE_CONFIG)
        report_path = tmp_path / "reports" / "test_report.json"
        result.save_json(report_path)

        assert report_path.exists()
        data = json.loads(report_path.read_text())

        assert "target" in data
        assert "findings" in data
        assert "summary" in data
        assert isinstance(data["findings"], list)

    def test_report_structure(self, tmp_path):
        result = aks.scan(UNSAFE_CONFIG)
        report_path = tmp_path / "report.json"
        result.save_json(report_path)

        data = json.loads(report_path.read_text())

        assert "scan_mode" in data
        assert "scanned_files" in data
        assert "skipped_files" in data
        assert data["summary"]["total_findings"] == result.total_findings

    def test_to_json_string(self):
        result = aks.scan(UNSAFE_CONFIG)
        json_str = result.to_json()
        parsed = json.loads(json_str)
        assert parsed["target"] is not None

    def test_to_dict(self):
        result = aks.scan(CLEAN_FILE)
        d = result.to_dict()
        assert d["findings"] == []
        assert d["summary"]["total_findings"] == 0


# ──────────────────────────────────────────────
# 10. Scan Mode Detection
# ──────────────────────────────────────────────

class TestScanModeDetection:
    def test_file_mode(self):
        result = aks.scan(UNSAFE_CONFIG)
        assert result.scan_mode == "file"

    def test_directory_mode(self):
        result = aks.scan(SAMPLE_DIR)
        assert result.scan_mode == "directory"

    def test_project_mode(self, tmp_path, monkeypatch):
        """Scanning "." (current working directory) should use project mode."""
        monkeypatch.chdir(tmp_path)

        # Create a file so the scan has something to look at
        (tmp_path / "app.py").write_text(
            'SECRET_KEY = "FakeProjectModeSecret123456789ABC"\n',
            encoding="utf-8",
        )

        result = aks.scan(".")
        assert result.scan_mode == "project"


# ──────────────────────────────────────────────
# 11. Severity Filtering
# ──────────────────────────────────────────────

class TestSeverityFiltering:
    def test_filter_to_high_only(self):
        result = aks.scan(UNSAFE_CONFIG, severity=["HIGH"])
        for finding in result.findings:
            assert finding.severity == "HIGH"

    def test_filter_to_medium_only(self, tmp_path):
        """Only MEDIUM findings should be returned when filtered."""
        result = aks.scan(SAMPLE_DIR, severity=["MEDIUM"])
        for finding in result.findings:
            assert finding.severity == "MEDIUM"

    def test_no_filter_returns_all_severities(self):
        result = aks.scan(SAMPLE_DIR)
        severities = {f.severity for f in result.findings}
        # Sample directory should have at least HIGH findings
        assert "HIGH" in severities


# ──────────────────────────────────────────────
# 12. ScanResult API
# ──────────────────────────────────────────────

class TestScanResultAPI:
    def test_has_findings_true(self):
        result = aks.scan(UNSAFE_CONFIG)
        assert result.has_findings is True

    def test_has_findings_false(self):
        result = aks.scan(CLEAN_FILE)
        assert result.has_findings is False

    def test_has_high_risk(self):
        result = aks.scan(UNSAFE_CONFIG)
        assert result.has_high_risk is True

    def test_summary_dict(self):
        result = aks.scan(UNSAFE_CONFIG)
        s = result.summary
        assert "total_findings" in s
        assert "high" in s
        assert "medium" in s
        assert "low" in s
        assert "status" in s
        assert s["status"] in ("PASSED", "FAILED")

    def test_repr(self):
        result = aks.scan(CLEAN_FILE)
        r = repr(result)
        assert "ScanResult" in r


# ──────────────────────────────────────────────
# 13. is_scannable_file utility
# ──────────────────────────────────────────────

class TestScannableFile:
    def test_py_files_are_scannable(self):
        assert is_scannable_file(Path("config.py")) is True

    def test_env_files_are_scannable(self):
        assert is_scannable_file(Path(".env")) is True
        assert is_scannable_file(Path(".env.local")) is True

    def test_dockerfile_is_scannable(self):
        assert is_scannable_file(Path("Dockerfile")) is True

    def test_image_files_are_not_scannable(self):
        assert is_scannable_file(Path("photo.png")) is False
        assert is_scannable_file(Path("data.zip")) is False
        assert is_scannable_file(Path("binary.exe")) is False
