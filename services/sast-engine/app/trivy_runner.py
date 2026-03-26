import json
import subprocess
from pathlib import Path


def run_trivy_scan(project_path: Path) -> dict:
    command = [
        "trivy",
        "fs",
        "--format",
        "json",
        "--scanners",
        "vuln,misconfig",
        "--skip-dirs",
        "node_modules",
        "--skip-dirs",
        ".git",
        "--skip-dirs",
        "venv",
        "--skip-dirs",
        ".venv",
        "--skip-dirs",
        "dist",
        "--skip-dirs",
        "build",
        str(project_path),
    ]

    process = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if process.stdout:
        try:
            return json.loads(process.stdout)
        except json.JSONDecodeError:
            pass

    raise RuntimeError(
        f"Trivy scan failed. stderr={process.stderr.strip()}"
    )