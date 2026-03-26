import pandas as pd
from pathlib import Path
from app.config import DATA_DIR

def load_all_parquet():

    files = list(DATA_DIR.glob("*.parquet"))
    dfs = []

    for file in files:
        print(f"Loading {file.name}")
        df = pd.read_parquet(file)
        dfs.append(df)

    dataset = pd.concat(dfs, ignore_index=True)

    print("\nDataset shape:", dataset.shape)

    return dataset


if __name__ == "__main__":
    df = load_all_parquet()
    print(df.head())