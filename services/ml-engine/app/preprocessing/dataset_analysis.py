import pandas as pd
from app.preprocessing.load_dataset import load_all_parquet

def analyze():

    df = load_all_parquet()

    print("\nColumns:")
    print(df.columns)

    print("\nMissing values:")
    print(df.isnull().sum().sort_values(ascending=False).head(20))

    if "Label" in df.columns:
        print("\nLabel distribution:")
        print(df["Label"].value_counts())

if __name__ == "__main__":
    analyze()