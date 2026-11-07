import joblib
import pandas as pd
from pathlib import Path

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "edge_host_decision_tree.joblib"

artifact = joblib.load(MODEL_PATH)
model = artifact["model"]
feature_columns = artifact["feature_columns"]


def predict_host(features):
    X = pd.DataFrame(
        [[features.get(col) for col in feature_columns]],
        columns=feature_columns
    )

    prediction = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]

    return {
        "prediction": str(prediction),
        "probabilities": {
            str(label): float(probability)
            for label, probability in zip(
                artifact["target_classes"], probabilities
            )
        },
        "source_timestamp": features["timestamp"]
    }
