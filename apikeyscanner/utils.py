"""
Utility helpers for the apikeyscanner package.
"""

import re
from pathlib import Path


# ──────────────────────────────────────────────
# Files & Directories to Ignore
# ──────────────────────────────────────────────

DEFAULT_IGNORE_DIRS: set[str] = {
    ".git",
    "venv",
    "env",
    ".venv",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    ".next",
    ".cache",
    "coverage",
    "target",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "htmlcov",
    ".eggs",
    "*.egg-info",
}

# File extensions we scan
SCANNABLE_EXTENSIONS: set[str] = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".json", ".env", ".yaml", ".yml",
    ".txt", ".md", ".toml", ".ini",
    ".cfg", ".conf", ".xml", ".html",
    ".css", ".sh", ".bash", ".zsh",
    ".rb", ".go", ".rs", ".java",
    ".php", ".cs", ".swift", ".kt",
    ".properties",
}

# Filenames without extensions to scan
SCANNABLE_FILENAMES: set[str] = {
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".env.staging",
    ".env.test",
    "Makefile",
    "Procfile",
    ".npmrc",
    ".htpasswd",
}


# ──────────────────────────────────────────────
# Secret Masking
# ──────────────────────────────────────────────

def mask_secret(value: str) -> str:
    """
    Mask a secret value so it cannot be read but can be identified.

    Rules:
    - Keep the first 4 characters visible.
    - Keep the last 3 characters visible.
    - Replace everything in between with asterisks.
    - Minimum masked length is 8 characters to avoid trivial brute-force.

    Example:
        sk-abcdef1234567890  →  sk-a********890
        ghp_ABCDEFGHIJ12345  →  ghp_********345
    """
    length = len(value)

    if length <= 8:
        # Very short value: mask the middle
        return value[:2] + "****" + value[-2:]

    if length <= 12:
        return value[:3] + "****" + value[-3:]

    # Standard masking: show prefix + 8 asterisks + last 3
    prefix = value[:4]
    suffix = value[-3:]
    stars = "*" * 8
    return f"{prefix}{stars}{suffix}"


def mask_line(line: str, matched_text: str) -> str:
    """
    Replace the matched secret in a full line with a masked version.
    Returns the line with the secret obscured.
    """
    if not matched_text:
        return line
    masked = mask_secret(matched_text)
    return line.replace(matched_text, masked, 1)


# ──────────────────────────────────────────────
# File Filtering
# ──────────────────────────────────────────────

def is_scannable_file(path: Path) -> bool:
    """
    Return True if the file should be scanned.

    A file is scannable if:
    - Its extension is in the allowed list, OR
    - Its filename (with or without path) is in the allowed filenames set.
    """
    if path.name in SCANNABLE_FILENAMES:
        return True

    # Also catch dotenv variants like .env.local
    if path.name.startswith(".env"):
        return True

    return path.suffix.lower() in SCANNABLE_EXTENSIONS


def is_ignored_dir(dir_name: str, custom_ignores: list[str] | None = None) -> bool:
    """
    Return True if a directory should be skipped during scanning.
    """
    if dir_name in DEFAULT_IGNORE_DIRS:
        return True
    if custom_ignores and dir_name in custom_ignores:
        return True
    return False


# ──────────────────────────────────────────────
# Path Utilities
# ──────────────────────────────────────────────

def resolve_path(path: str) -> Path:
    """Resolve a string path to an absolute Path object."""
    return Path(path).resolve()


def relative_display_path(file_path: Path, base: Path) -> str:
    """
    Return a short relative path for display purposes.
    Falls back to the absolute path string if relative fails.
    """
    try:
        return str(file_path.relative_to(base))
    except ValueError:
        return str(file_path)


def detect_scan_mode(path: Path) -> str:
    """
    Automatically determine the scan mode based on the path type.

    - "file"      → path points to a single file
    - "project"   → path is the current working directory (".")
    - "directory" → path is any other directory
    """
    if path.is_file():
        return "file"

    if path == Path.cwd():
        return "project"

    return "directory"


# ──────────────────────────────────────────────
# Binary Detection
# ──────────────────────────────────────────────

def is_binary_file(path: Path, sample_size: int = 8192) -> bool:
    """
    Quick heuristic check to determine if a file is binary.
    Reads the first `sample_size` bytes and checks for null bytes
    or a high ratio of non-printable characters.
    """
    try:
        with open(path, "rb") as f:
            chunk = f.read(sample_size)

        if b"\x00" in chunk:
            return True

        # Check ratio of non-text bytes
        non_text = sum(1 for byte in chunk if byte > 127 or (byte < 32 and byte not in (9, 10, 13)))
        return len(chunk) > 0 and (non_text / len(chunk)) > 0.30

    except OSError:
        return True
