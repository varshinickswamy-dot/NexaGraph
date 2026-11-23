import json
import joblib
import pandas as pd
import urllib.request
import numpy as np

from pathlib import Path

BASE = Path(__file__).resolve().parents[2]

MODEL_PATH = BASE / "backend/ml/artifacts/nexagraph_binary_model.joblib"
DATA_PATH = BASE / "data/processed/cic_ids2017_features.csv"

# Load trained model bundle
bundle = joblib.load(MODEL_PATH)

features = bundle["features"]
imputer = bundle["imputer"]

# Read one actual dataset record
data = pd.read_csv(DATA_PATH, nrows=1)

# Build input using the exact training feature names
row = data[features].iloc[0]

# Replace missing or infinite values using training medians
values = row.to_numpy(dtype=float, copy=True)

missing_mask = ~np.isfinite(values)

values[missing_mask] = imputer.statistics_[missing_mask]

payload = {
    "features": {
        name: float(value)
        for name, value in zip(features, values)
    }
}

# Send prediction request
request = urllib.request.Request(
    "http://127.0.0.1:8000/api/ml/predict",
    data=json.dumps(payload).encode("utf-8"),
    headers={"Content-Type": "application/json"},
    method="POST"
)

try:
    with urllib.request.urlopen(request) as response:
        result = json.loads(response.read().decode())

    print("\n========== NEXAGRAPH-AI PREDICTION ==========")
    print(json.dumps(result, indent=4))

except Exception as error:
    print("Prediction failed:", error)