import json

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM
from tensorflow.keras.layers import Dense, Input
from tensorflow.keras.models import Model

from app.config import DATA_DIR, MODELS_DIR
from app.utils.metrics import compute_metrics


RESULTS_PATH = MODELS_DIR / "loao_results.json"


def to_python_types(obj):
    if isinstance(obj, dict):
        return {k: to_python_types(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [to_python_types(v) for v in obj]
    if isinstance(obj, np.integer):
        return int(obj)
    if isinstance(obj, np.floating):
        return float(obj)
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    return obj


def load_raw_dataset():
    files = list(DATA_DIR.glob("*.parquet"))
    dfs = []

    for file in files:
        print(f"Loading {file.name}")
        df = pd.read_parquet(file)
        dfs.append(df)

    dataset = pd.concat(dfs, ignore_index=True)
    return dataset


def clean_dataset(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    drop_columns = ["Flow ID", "Src IP", "Dst IP", "Timestamp"]
    for col in drop_columns:
        if col in df.columns:
            df = df.drop(columns=col)

    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()

    df["Label"] = df["Label"].astype(str).str.strip()
    return df


def build_loao_split(
    df: pd.DataFrame,
    left_out_attack: str,
    normal_train_size: int = 50000,
    normal_test_size: int = 10000,
    attack_test_size: int = 10000,
    random_state: int = 42,
):
    benign_df = df[df["Label"].str.lower() == "benign"].copy()
    attack_df = df[df["Label"] == left_out_attack].copy()

    if attack_df.empty:
        raise ValueError(f"Aucune ligne trouvée pour l'attaque: {left_out_attack}")

    if len(benign_df) < normal_train_size + normal_test_size:
        raise ValueError("Pas assez de trafic normal pour train/test.")

    benign_train = benign_df.sample(n=normal_train_size, random_state=random_state)
    benign_remaining = benign_df.drop(benign_train.index)
    benign_test = benign_remaining.sample(n=normal_test_size, random_state=random_state)

    if len(attack_df) > attack_test_size:
        attack_test = attack_df.sample(n=attack_test_size, random_state=random_state)
    else:
        attack_test = attack_df

    train_df = benign_train.copy()
    test_df = pd.concat([benign_test, attack_test], ignore_index=True)

    y_test = test_df["Label"].apply(lambda x: 0 if x.lower() == "benign" else 1).values

    X_train = train_df.drop(columns=["Label"])
    X_test = test_df.drop(columns=["Label"])

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    return X_train_scaled, X_test_scaled, y_test, scaler, len(attack_test)


def train_isolation_forest(X_train):
    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train)
    return model


def predict_isolation_forest(model, X_test):
    pred = model.predict(X_test)
    return np.where(pred == -1, 1, 0)


def train_ocsvm(X_train, sample_size: int = 20000):
    if len(X_train) > sample_size:
        idx = np.random.RandomState(42).choice(len(X_train), size=sample_size, replace=False)
        X_train_small = X_train[idx]
    else:
        X_train_small = X_train

    model = OneClassSVM(
        kernel="rbf",
        gamma="scale",
        nu=0.05,
    )
    model.fit(X_train_small)
    return model


def predict_ocsvm(model, X_test):
    pred = model.predict(X_test)
    return np.where(pred == -1, 1, 0)


def train_autoencoder(X_train, epochs: int = 10, batch_size: int = 256):
    input_dim = X_train.shape[1]

    input_layer = Input(shape=(input_dim,))
    encoded = Dense(16, activation="relu")(input_layer)
    encoded = Dense(8, activation="relu")(encoded)

    decoded = Dense(16, activation="relu")(encoded)
    decoded = Dense(input_dim, activation="linear")(decoded)

    autoencoder = Model(inputs=input_layer, outputs=decoded)
    autoencoder.compile(optimizer="adam", loss="mse")

    autoencoder.fit(
        X_train,
        X_train,
        epochs=epochs,
        batch_size=batch_size,
        verbose=1,
    )

    return autoencoder


def predict_autoencoder(model, X_train, X_test, threshold_percentile: float = 95.0):
    train_recon = model.predict(X_train, verbose=0)
    train_mse = np.mean(np.power(X_train - train_recon, 2), axis=1)

    threshold = np.percentile(train_mse, threshold_percentile)

    test_recon = model.predict(X_test, verbose=0)
    test_mse = np.mean(np.power(X_test - test_recon, 2), axis=1)

    y_pred = (test_mse > threshold).astype(int)
    return y_pred, float(threshold)


def run_loao():
    df = load_raw_dataset()
    df = clean_dataset(df)

    attack_labels = sorted(
        [label for label in df["Label"].unique() if label.lower() != "benign"]
    )

    print("\nAttaques trouvées:")
    for attack in attack_labels:
        print("-", attack)

    results = []

    selected_attacks = [a for a in attack_labels if len(df[df["Label"] == a]) >= 1000]

    print("\nAttaques retenues pour LOAO:")
    for attack in selected_attacks:
        print("-", attack)

    for attack in selected_attacks:
        print(f"\n{'=' * 70}")
        print(f"LOAO - Attaque laissée de côté : {attack}")
        print(f"{'=' * 70}")

        X_train, X_test, y_test, scaler, attack_count = build_loao_split(
            df=df,
            left_out_attack=attack,
            normal_train_size=50000,
            normal_test_size=10000,
            attack_test_size=10000,
            random_state=42,
        )

        iso_model = train_isolation_forest(X_train)
        iso_pred = predict_isolation_forest(iso_model, X_test)
        iso_metrics = compute_metrics(y_test, iso_pred)

        ocsvm_model = train_ocsvm(X_train, sample_size=20000)
        ocsvm_pred = predict_ocsvm(ocsvm_model, X_test)
        ocsvm_metrics = compute_metrics(y_test, ocsvm_pred)

        auto_model = train_autoencoder(X_train, epochs=10, batch_size=256)
        auto_pred, threshold = predict_autoencoder(
            auto_model,
            X_train,
            X_test,
            threshold_percentile=95.0,
        )
        auto_metrics = compute_metrics(y_test, auto_pred)

        result = {
            "left_out_attack": attack,
            "attack_test_count": int(attack_count),
            "isolation_forest": iso_metrics,
            "ocsvm": ocsvm_metrics,
            "autoencoder": {
                **auto_metrics,
                "threshold": float(threshold),
            },
        }

        results.append(result)

        print("\nIsolation Forest:", iso_metrics)
        print("One-Class SVM:", ocsvm_metrics)
        print("Autoencoder:", auto_metrics)

    results_clean = to_python_types(results)

    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump(results_clean, f, indent=2, ensure_ascii=False)

    print(f"\nRésultats sauvegardés dans : {RESULTS_PATH}")

    return results_clean


if __name__ == "__main__":
    run_loao()