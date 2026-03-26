import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from joblib import dump

from app.config import PROCESSED_DATA, MODELS_DIR
from app.preprocessing.load_dataset import load_all_parquet


DROP_COLUMNS = [
    "Flow ID",
    "Src IP",
    "Dst IP",
    "Timestamp"
]


def run_feature_engineering():
    df = load_all_parquet()

    for col in DROP_COLUMNS:
        if col in df.columns:
            df = df.drop(columns=col)

    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()

    df["Label"] = df["Label"].astype(str).str.strip().str.lower()
    df["Label"] = df["Label"].apply(lambda x: 0 if x == "benign" else 1)

    print("\nLabel distribution after encoding:")
    print(df["Label"].value_counts())

    X = df.drop("Label", axis=1)
    y = df["Label"]

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    dump(scaler, MODELS_DIR / "scaler.pkl")

    processed = pd.DataFrame(X_scaled, columns=X.columns)
    processed["Label"] = y.values

    processed.to_parquet(PROCESSED_DATA, index=False)

    print(f"Dataset saved: {PROCESSED_DATA}")


if __name__ == "__main__":
    run_feature_engineering()