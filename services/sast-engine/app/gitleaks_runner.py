import json
import subprocess
from pathlib import Path


def run_gitleaks_scan(project_path: Path) -> list:
    command = [
        "gitleaks",
        "detect",
        "--no-git",
        "--source",
        str(project_path),
        "--report-format",
        "json",
        "--report-path",
        "-",
    ]

    process = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if process.stdout:
        try:
            data = json.loads(process.stdout)
            if isinstance(data, list):
                return data
            return []
        except json.JSONDecodeError:
            pass

    stderr = process.stderr.strip()
    if stderr:
        raise RuntimeError(f"Gitleaks scan failed. stderr={stderr}")

    return []