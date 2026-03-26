import json
import subprocess
from pathlib import Path


def run_semgrep_scan(project_path: Path) -> dict:
    command = [
        "semgrep",
        "scan",
        "--config=auto",
        "--json",
        "--exclude=node_modules",
        "--exclude=.git",
        "--exclude=venv",
        "--exclude=.venv",
        "--exclude=dist",
        "--exclude=build",
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
        f"Semgrep scan failed. stderr={process.stderr.strip()}"
    )