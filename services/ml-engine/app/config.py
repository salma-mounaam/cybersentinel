from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent.parent.parent

DATA_DIR = PROJECT_ROOT / "data" / "cicids2018"
PROCESSED_DATA = PROJECT_ROOT / "data" / "cicids2018_processed.parquet"

MODELS_DIR = BASE_DIR.parent / "models"
MODELS_DIR.mkdir(exist_ok=True, parents=True)

LOGS_DIR = BASE_DIR.parent / "logs"
LOGS_DIR.mkdir(exist_ok=True, parents=True)