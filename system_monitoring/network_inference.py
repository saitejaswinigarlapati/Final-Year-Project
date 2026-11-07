import joblib
import pandas as pd
from pathlib import Path

MODEL_PATH = (
    Path(__file__).resolve().parent.parent
    / "models"
    / "edge_network_decision_tree.joblib"
)

artifact = joblib.load(MODEL_PATH)
model = artifact["model"]
feature_columns = artifact["feature_columns"]


def predict_network(features):
    missing = set(feature_columns) - set(features.columns)

    if missing:
        raise ValueError(f"Missing network features: {sorted(missing)}")

    X = features[feature_columns]

    predictions = model.predict(X)
    probabilities = model.predict_proba(X)

    results = []

    for prediction, probability in zip(predictions, probabilities):
        results.append({
            "prediction": str(prediction),
            "probabilities": {
                str(label): float(value)
                for label, value in zip(
                    artifact["target_classes"], probability
                )
            }
        })

    return results
