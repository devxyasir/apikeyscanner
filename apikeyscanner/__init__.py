"""
apikeyscanner — Local Secret Leak Detection Tool
================================================

A simple, professional security tool to detect leaked API keys,
tokens, passwords, and secrets inside local files and projects.

Quick start
-----------

    import apikeyscanner as aks

    result = aks.scan(".")

    print(result.total_findings)
    print(result.has_high_risk)
    result.save_json("reports/report.json")

"""

__version__ = "1.0.0"
__author__ = "devxyasir"
__email__ = "jamyasir0534@gmail.com"
__license__ = "MIT"

from .scanner import scan
from .result import ScanResult, Finding

__all__ = [
    "scan",
    "ScanResult",
    "Finding",
    "__version__",
    "__author__",
    "__email__",
]
