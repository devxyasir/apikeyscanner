"""
Core scanning engine for apikeyscanner.

This module is the heart of the tool. It:
1. Resolves the scan target (file, directory, or project)
2. Collects all scannable files recursively
3. Applies regex patterns to each file
4. Returns a ScanResult with all findings
"""

from __future__ import annotations

import re
from pathlib import Path

from .logger import (
    log_file_error,
    log_file_scanned,
    log_file_skipped,
    log_finding,
    log_scan_complete,
    log_scan_start,
)
from .patterns import PATTERNS, Pattern
from .result import Finding, ScanResult
from .utils import (
    detect_scan_mode,
    is_binary_file,
    is_ignored_dir,
    is_scannable_file,
    mask_secret,
    relative_display_path,
    resolve_path,
)


# ──────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────

def scan(
    path: str | Path,
    severity: list[str] | None = None,
    ignore: list[str] | None = None,
    recursive: bool = True,
    verbose: bool = False,
) -> ScanResult:
    """
    Scan a file, directory, or full project for leaked secrets.

    Parameters
    ----------
    path : str or Path
        Path to the file or directory to scan.
    severity : list[str] or None
        Filter findings to these severity levels.
        e.g. ["HIGH", "MEDIUM"] — None means include all levels.
    ignore : list[str] or None
        Extra directory names to ignore (added to the default ignore list).
    recursive : bool
        If True (default), scan subdirectories recursively.
    verbose : bool
        If True, emit debug-level log messages.

    Returns
    -------
    ScanResult
        A result object containing all findings and scan metadata.
    """
    target_path = resolve_path(str(path))
    scan_mode = detect_scan_mode(target_path)
    base_path = target_path if target_path.is_dir() else target_path.parent

    log_scan_start(str(path), scan_mode, verbose)

    # Collect all files to scan
    files = _collect_files(
        target_path,
        scan_mode=scan_mode,
        recursive=recursive,
        custom_ignores=ignore,
        verbose=verbose,
    )

    # Run the detection engine
    findings: list[Finding] = []
    scanned_count = 0
    skipped_count = 0

    for file_path in files:
        result = _scan_file(
            file_path=file_path,
            base_path=base_path,
            patterns=PATTERNS,
            verbose=verbose,
        )

        if result is None:
            skipped_count += 1
        else:
            scanned_count += 1
            findings.extend(result)

    log_scan_complete(scanned_count, skipped_count, len(findings), verbose)

    scan_result = ScanResult(
        target=str(path),
        scan_mode=scan_mode,
        findings=findings,
        scanned_files=scanned_count,
        skipped_files=skipped_count,
    )

    # Apply severity filter if requested
    if severity:
        scan_result = scan_result.filter_by_severity(severity)

    return scan_result


# ──────────────────────────────────────────────
# File Collection
# ──────────────────────────────────────────────

def _collect_files(
    target: Path,
    scan_mode: str,
    recursive: bool,
    custom_ignores: list[str] | None,
    verbose: bool,
) -> list[Path]:
    """
    Build a list of file paths to scan based on the target and options.
    """
    if scan_mode == "file":
        return [target]

    files: list[Path] = []
    _walk_directory(target, files, recursive, custom_ignores, verbose)
    return files


def _walk_directory(
    directory: Path,
    files: list[Path],
    recursive: bool,
    custom_ignores: list[str] | None,
    verbose: bool,
) -> None:
    """
    Recursively walk a directory tree and collect scannable files.
    Skips directories in the ignore list.
    """
    try:
        entries = sorted(directory.iterdir())
    except PermissionError as e:
        log_file_error(str(directory), e, verbose)
        return

    for entry in entries:
        if entry.is_dir():
            if is_ignored_dir(entry.name, custom_ignores):
                log_file_skipped(str(entry), "ignored directory", verbose)
                continue
            if recursive:
                _walk_directory(entry, files, recursive, custom_ignores, verbose)
        elif entry.is_file():
            if is_scannable_file(entry):
                files.append(entry)
            else:
                log_file_skipped(str(entry), "unscannable extension", verbose)


# ──────────────────────────────────────────────
# File Scanning
# ──────────────────────────────────────────────

def _scan_file(
    file_path: Path,
    base_path: Path,
    patterns: list[Pattern],
    verbose: bool,
) -> list[Finding] | None:
    """
    Scan a single file against all detection patterns.

    Returns
    -------
    list[Finding] or None
        A list of findings (possibly empty) if the file was scanned.
        None if the file was skipped (binary, unreadable).
    """
    # Skip binary files
    if is_binary_file(file_path):
        log_file_skipped(str(file_path), "binary file", verbose)
        return None

    # Read file content
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        log_file_error(str(file_path), e, verbose)
        return None

    log_file_scanned(str(file_path), verbose)

    display_path = relative_display_path(file_path, base_path)
    findings: list[Finding] = []
    lines = content.splitlines()

    for pattern in patterns:
        try:
            compiled = re.compile(pattern.regex, re.MULTILINE | re.IGNORECASE)
        except re.error:
            continue

        for line_number, line in enumerate(lines, start=1):
            for match in compiled.finditer(line):
                matched_text = match.group(0)
                masked = mask_secret(matched_text)

                finding = Finding(
                    severity=pattern.severity,
                    type=pattern.name,
                    file=display_path,
                    line=line_number,
                    match=masked,
                    description=pattern.description,
                    fix=pattern.fix,
                )
                findings.append(finding)

                log_finding(pattern.name, display_path, line_number, verbose)

    return findings
