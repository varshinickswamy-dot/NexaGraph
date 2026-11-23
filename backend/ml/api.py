import json
import joblib
import numpy as np

from pathlib import Path
from functools import lru_cache

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, ConfigDict


router = APIRouter(prefix="/api/ml", tags=["Machine Learning"])

BASE_DIR = Path(__file__).resolve().parents[2]
ARTIFACT_DIR = BASE_DIR / "backend" / "ml" / "artifacts"

MODEL_PATH = ARTIFACT_DIR / "nexagraph_binary_model.joblib"
METRICS_PATH = ARTIFACT_DIR / "training_metrics.json"


@lru_cache(maxsize=1)
def load_model_bundle():
    if not MODEL_PATH.exists():
        raise FileNotFoundError("Trained ML model artifact not found.")

    return joblib.load(MODEL_PATH)


def load_metrics():
    if not METRICS_PATH.exists():
        raise FileNotFoundError("Training metrics report not found.")

    with METRICS_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


class PredictionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    features: dict[str, float] = Field(
        description="Network-flow feature values using CIC-IDS-2017 feature names."
    )


@router.get("/status")
def ml_status():
    return {
        "available": MODEL_PATH.exists(),
        "metrics_available": METRICS_PATH.exists(),
        "model": "HistGradientBoostingClassifier",
        "dataset": "CIC-IDS-2017"
    }


@router.get("/metrics")
def ml_metrics():
    try:
        return load_metrics()
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@router.post("/predict")
def predict_network_traffic(payload: PredictionInput):
    try:
        bundle = load_model_bundle()

        model = bundle["model"]
        imputer = bundle["imputer"]
        feature_names = bundle["features"]
        target_mapping = bundle["target_mapping"]

        missing_features = [
            name for name in feature_names
            if name not in payload.features
        ]

        if missing_features:
            raise HTTPException(
                status_code=422,
                detail={
                    "message": "Required features are missing.",
                    "missing_features": missing_features
                }
            )

        values = []

        for name in feature_names:
            value = payload.features[name]

            if not np.isfinite(value):
                raise HTTPException(
                    status_code=422,
                    detail=f"Feature '{name}' must be a finite number."
                )

            values.append(float(value))

        input_array = np.array(
            values,
            dtype=np.float64
        ).reshape(1, -1)

        transformed = imputer.transform(input_array)

        prediction = int(model.predict(transformed)[0])

        probabilities = model.predict_proba(transformed)[0]

        confidence = float(probabilities[prediction])

        return {
            "prediction": prediction,
            "classification": target_mapping[str(prediction)],
            "confidence": round(confidence, 4),
            "confidence_percentage": round(confidence * 100, 2),
            "probabilities": {
                target_mapping[str(index)]: round(float(probability), 4)
                for index, probability in enumerate(probabilities)
            },
            "model": "HistGradientBoostingClassifier",
            "dataset": "CIC-IDS-2017"
        }

    except HTTPException:
        raise

    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Network traffic prediction failed."
        ) from exc