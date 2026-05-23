"""
ScanResult — the object returned by every scan.
Contains all findings, metadata, and helper methods.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


# ──────────────────────────────────────────────
# Finding — one detected secret
# ──────────────────────────────────────────────

@dataclass
class Finding:
    """Represents a single detected secret or credential."""

    severity: str       # HIGH, MEDIUM, LOW
    type: str           # Human-readable pattern name
    file: str           # Relative file path
    line: int           # Line number (1-indexed)
    match: str          # Masked secret value
    description: str    # What was detected
    fix: str            # How to fix it

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "type": self.type,
            "file": self.file,
            "line": self.line,
            "match": self.match,
            "description": self.description,
            "fix": self.fix,
        }


# ──────────────────────────────────────────────
# ScanResult — the main result object
# ──────────────────────────────────────────────

@dataclass
class ScanResult:
    """
    The result of a scan operation.

    Attributes
    ----------
    target : str
        The path that was scanned.
    scan_mode : str
        One of "file", "directory", or "project".
    findings : list[Finding]
        All detected secrets/credentials.
    scanned_files : int
        Number of files that were successfully scanned.
    skipped_files : int
        Number of files that were skipped (binary, unreadable, ignored).
    """

    target: str
    scan_mode: str
    findings: list[Finding] = field(default_factory=list)
    scanned_files: int = 0
    skipped_files: int = 0

    # ── Computed Counts ───────────────────────

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "MEDIUM")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "LOW")

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    # ── Status Properties ─────────────────────

    @property
    def has_findings(self) -> bool:
        """True if any secrets were found."""
        return self.total_findings > 0

    @property
    def has_high_risk(self) -> bool:
        """True if any HIGH severity secrets were found."""
        return self.high_count > 0

    @property
    def is_clean(self) -> bool:
        """True if no secrets were found at all."""
        return not self.has_findings

    # ── Summary ───────────────────────────────

    @property
    def summary(self) -> dict:
        """A compact summary dict of the scan result."""
        return {
            "target": self.target,
            "scan_mode": self.scan_mode,
            "scanned_files": self.scanned_files,
            "skipped_files": self.skipped_files,
            "total_findings": self.total_findings,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "status": "FAILED" if self.has_findings else "PASSED",
        }

    # ── Serialization ─────────────────────────

    def to_dict(self) -> dict:
        """Convert the full result to a dictionary."""
        return {
            "target": self.target,
            "scan_mode": self.scan_mode,
            "scanned_files": self.scanned_files,
            "skipped_files": self.skipped_files,
            "summary": {
                "total_findings": self.total_findings,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert the full result to a formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def save_json(self, path: str | Path) -> None:
        """
        Save the full result as a JSON report to disk.

        Parameters
        ----------
        path : str or Path
            File path for the JSON report.
            Parent directories are created automatically.
        """
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.to_json(), encoding="utf-8")

    # ── Filter Helpers ────────────────────────

    def filter_by_severity(self, severities: list[str]) -> "ScanResult":
        """
        Return a new ScanResult containing only findings that match
        the specified severity levels.

        Parameters
        ----------
        severities : list[str]
            e.g. ["HIGH", "MEDIUM"]
        """
        upper = [s.upper() for s in severities]
        filtered_findings = [f for f in self.findings if f.severity in upper]
        return ScanResult(
            target=self.target,
            scan_mode=self.scan_mode,
            findings=filtered_findings,
            scanned_files=self.scanned_files,
            skipped_files=self.skipped_files,
        )

    def __repr__(self) -> str:
        return (
            f"ScanResult(target={self.target!r}, mode={self.scan_mode!r}, "
            f"findings={self.total_findings}, high={self.high_count})"
        )
