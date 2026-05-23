"""
Report generation utilities for apikeyscanner.
Handles saving and loading JSON scan reports.
"""

from __future__ import annotations

import json
from pathlib import Path

from .logger import log_report_saved
from .result import ScanResult


def save_json_report(result: ScanResult, output_path: str | Path, verbose: bool = False) -> Path:
    """
    Save a ScanResult as a formatted JSON report file.

    Parameters
    ----------
    result : ScanResult
        The scan result to serialize.
    output_path : str or Path
        Destination file path. Parent directories are created automatically.
    verbose : bool
        Log the save action if True.

    Returns
    -------
    Path
        The resolved path where the report was saved.
    """
    dest = Path(output_path).resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(result.to_json(), encoding="utf-8")
    log_report_saved(str(dest), verbose)
    return dest


def load_json_report(input_path: str | Path) -> dict:
    """
    Load a previously saved JSON report from disk.

    Parameters
    ----------
    input_path : str or Path
        Path to the JSON report file.

    Returns
    -------
    dict
        The deserialized report data.
    """
    source = Path(input_path)
    if not source.exists():
        raise FileNotFoundError(f"Report file not found: {source}")
    return json.loads(source.read_text(encoding="utf-8"))
