"""
examples/fastapi_usage.py
=========================

Shows how to integrate apikeyscanner into a FastAPI application.

This example demonstrates two endpoints:
1. A pre-deployment security scan endpoint.
2. A detailed findings endpoint for security dashboards.

To run this example:

    pip install fastapi uvicorn
    uvicorn examples.fastapi_usage:app --reload

Or run the file directly:

    python examples/fastapi_usage.py
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

import apikeyscanner as aks

app = FastAPI(
    title="API Key Scanner — FastAPI Integration",
    description="Example of using apikeyscanner inside a FastAPI backend.",
    version="1.0.0",
)

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────

# In production: set this to your actual project directory.
# Example: PROJECT_PATH = "/srv/backend-app"
PROJECT_PATH = "."

IGNORED_DIRS = ["venv", "node_modules", ".git", "dist", "build", ".next", "reports"]


# ──────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────

@app.get("/")
def root():
    """Health check endpoint."""
    return {"status": "ok", "tool": "apikeyscanner", "version": aks.__version__}


@app.post("/security/scan")
def scan_project():
    """
    Run a full security scan of the project directory.

    Blocks deployment if HIGH-severity secrets are detected.
    Use this endpoint as a pre-deployment gate in your CI/CD pipeline.
    """
    result = aks.scan(
        path=PROJECT_PATH,
        severity=["HIGH"],
        ignore=IGNORED_DIRS,
        recursive=True,
    )

    if result.has_high_risk:
        raise HTTPException(
            status_code=403,
            detail={
                "message": "🚨 Deployment blocked. High-risk secrets detected.",
                "summary": result.summary,
                "findings": [f.to_dict() for f in result.findings],
            },
        )

    return {
        "message": "✅ No high-risk secrets found. Project is safe to deploy.",
        "summary": result.summary,
    }


@app.post("/security/scan/full")
def scan_project_full():
    """
    Run a full security scan including all severity levels.

    Returns all findings — HIGH, MEDIUM, and LOW — without blocking.
    Useful for security dashboards, audit logs, and internal tooling.
    """
    result = aks.scan(
        path=PROJECT_PATH,
        ignore=IGNORED_DIRS,
        recursive=True,
    )

    return {
        "status": "FAILED" if result.has_findings else "PASSED",
        "summary": result.summary,
        "findings": [f.to_dict() for f in result.findings],
    }


@app.post("/security/scan/file")
def scan_single_file(file_path: str):
    """
    Scan a single file for leaked secrets.

    Parameters
    ----------
    file_path : str
        Path to the file to scan (query parameter).

    Example:
        POST /security/scan/file?file_path=./config.py
    """
    result = aks.scan(
        path=file_path,
        recursive=False,
    )

    return {
        "file": file_path,
        "scan_mode": result.scan_mode,
        "total_findings": result.total_findings,
        "findings": [f.to_dict() for f in result.findings],
    }


@app.post("/security/scan/report")
def scan_and_save_report(output_path: str = "reports/security_report.json"):
    """
    Scan the project and save a full JSON report to disk.

    Parameters
    ----------
    output_path : str
        Where to save the JSON report (default: reports/security_report.json).
    """
    result = aks.scan(
        path=PROJECT_PATH,
        ignore=IGNORED_DIRS,
        recursive=True,
    )

    result.save_json(output_path)

    return {
        "message": f"Report saved to {output_path}",
        "summary": result.summary,
    }


# ──────────────────────────────────────────────
# Run directly for testing
# ──────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("examples.fastapi_usage:app", host="127.0.0.1", port=8000, reload=True)
