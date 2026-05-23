"""
Logging configuration for apikeyscanner.
Provides a simple, structured logger used throughout the package.
"""

import logging
import sys


# Module-level logger — all submodules use getLogger(__name__)
_LOGGER_NAME = "apikeyscanner"

# Prevent adding duplicate handlers if the module is re-imported
_handler_attached = False


def get_logger(verbose: bool = False) -> logging.Logger:
    """
    Return the apikeyscanner logger, configuring it on first call.

    Parameters
    ----------
    verbose : bool
        If True, set the log level to DEBUG (show all messages).
        If False, set to INFO (hide debug-level messages).

    Returns
    -------
    logging.Logger
    """
    global _handler_attached

    logger = logging.getLogger(_LOGGER_NAME)

    if not _handler_attached:
        handler = logging.StreamHandler(sys.stderr)
        formatter = logging.Formatter(
            fmt="[%(asctime)s] [%(levelname)s] %(message)s",
            datefmt="%H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        _handler_attached = True

    level = logging.DEBUG if verbose else logging.WARNING
    logger.setLevel(level)

    return logger


def log_scan_start(target: str, mode: str, verbose: bool = False) -> None:
    logger = get_logger(verbose)
    logger.info("Scan started")
    logger.info("Target: %s", target)
    logger.info("Scan mode: %s", mode)


def log_scan_complete(
    scanned: int,
    skipped: int,
    findings: int,
    verbose: bool = False,
) -> None:
    logger = get_logger(verbose)
    logger.info("Scan complete")
    logger.info("Files scanned: %d", scanned)
    logger.info("Files skipped: %d", skipped)
    logger.info("Total findings: %d", findings)


def log_file_error(path: str, error: Exception, verbose: bool = False) -> None:
    logger = get_logger(verbose)
    logger.debug("Could not read file: %s — %s", path, error)


def log_file_skipped(path: str, reason: str, verbose: bool = False) -> None:
    logger = get_logger(verbose)
    logger.debug("Skipped: %s (%s)", path, reason)


def log_file_scanned(path: str, verbose: bool = False) -> None:
    logger = get_logger(verbose)
    logger.debug("Scanning: %s", path)


def log_report_saved(path: str, verbose: bool = False) -> None:
    logger = get_logger(verbose)
    logger.info("Report saved: %s", path)


def log_finding(pattern_name: str, file_path: str, line: int, verbose: bool = False) -> None:
    """Log a finding WITHOUT printing the actual secret value."""
    logger = get_logger(verbose)
    logger.info("Found: [%s] in %s at line %d", pattern_name, file_path, line)
