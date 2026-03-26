import numpy as np
import pandas as pd
from joblib import load
from tensorflow.keras.models import load_model

from app.config import MODELS_DIR


class AutoencoderPredictor:
    def __init__(self):
        self.scaler = load(MODELS_DIR / "scaler.pkl")
        self.model = load_model(MODELS_DIR / "autoencoder.keras")

        # Colonnes attendues, dans le même ordre que pendant l'entraînement
        self.feature_names = list(self.scaler.feature_names_in_)

        # Seuil par défaut provisoire
        # Tu pourras ensuite le remplacer par un seuil calculé depuis train_mse
        self.threshold = 0.1

    def preprocess(self, features: dict):
        row = {}

        for col in self.feature_names:
            row[col] = float(features.get(col, 0.0))

        df = pd.DataFrame([row], columns=self.feature_names)
        x_scaled = self.scaler.transform(df)
        return x_scaled

    def predict(self, features: dict):
        x_scaled = self.preprocess(features)

        reconstruction = self.model.predict(x_scaled, verbose=0)
        mse = float(np.mean(np.power(x_scaled - reconstruction, 2), axis=1)[0])

        is_anomaly = mse > self.threshold

        if mse < self.threshold:
            risk_level = "low"
        elif mse < self.threshold * 2:
            risk_level = "medium"
        else:
            risk_level = "high"

        return {
            "model": "autoencoder",
            "anomaly_score": mse,
            "threshold": float(self.threshold),
            "is_anomaly": bool(is_anomaly),
            "risk_level": risk_level,
            "details": {
                "feature_count": len(self.feature_names)
            }
        }