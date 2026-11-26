import json
import os
import time
import joblib
import numpy as np
import pandas as pd

from pathlib import Path

from sklearn.model_selection import train_test_split
from sklearn.impute import SimpleImputer
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.dummy import DummyClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix
)
from sklearn.utils.class_weight import compute_sample_weight


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_PATH = Path(
    os.getenv(
        "NEXAGRAPH_TRAINING_DATA",
        str(PROJECT_ROOT / "data" / "processed" / "cic_ids2017_features.csv"),
    )
).expanduser().resolve()
ARTIFACT_DIR = PROJECT_ROOT / "backend" / "ml" / "artifacts"

MODEL_PATH = ARTIFACT_DIR / "nexagraph_binary_model.joblib"
REPORT_PATH = ARTIFACT_DIR / "training_metrics.json"

CHUNK_SIZE = 100000
SAMPLE_PER_CHUNK = 5000
RANDOM_STATE = 42


def evaluate(model, X, y):

    predictions = model.predict(X)
    probabilities = model.predict_proba(X)[:, 1]

    return {
        "accuracy": round(float(accuracy_score(y, predictions)), 4),
        "precision": round(float(precision_score(
            y, predictions, zero_division=0
        )), 4),
        "recall": round(float(recall_score(
            y, predictions, zero_division=0
        )), 4),
        "f1_score": round(float(f1_score(
            y, predictions, zero_division=0
        )), 4),
        "roc_auc": round(float(roc_auc_score(
            y, probabilities
        )), 4),
        "confusion_matrix": confusion_matrix(y, predictions).tolist()
    }


def main():

    start = time.time()

    print("\n===================================")
    print("NEXAGRAPH-AI MODEL TRAINING")
    print("===================================")

    if not DATA_PATH.exists():
        raise FileNotFoundError(DATA_PATH)

    if MODEL_PATH.exists() or REPORT_PATH.exists():
        raise FileExistsError(
            "Model artifacts already exist. "
            "Preserving existing results."
        )

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Load reproducible sample
    print("\n[1/5] Loading dataset...")

    samples = []

    for chunk in pd.read_csv(DATA_PATH, chunksize=CHUNK_SIZE):

        chunk["Label"] = chunk["Label"].astype(str).str.strip()

        sample = chunk.sample(
            n=min(SAMPLE_PER_CHUNK, len(chunk)),
            random_state=RANDOM_STATE
        )

        samples.append(sample)

        print(f"Loaded: {sum(len(x) for x in samples):,}")

    data = pd.concat(samples, ignore_index=True)

    # 2. Prepare binary target
    print("\n[2/5] Preparing features...")

    y = (data["Label"].str.upper() != "BENIGN").astype(int)

    X = data.drop(columns=["Label"])

    X = X.apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)

    valid_columns = X.columns[X.notna().any()].tolist()
    X = X[valid_columns]

    print("Records:", len(X))
    print("Features:", len(valid_columns))
    print("Benign:", int((y == 0).sum()))
    print("Malicious:", int((y == 1).sum()))

    # 3. Split before imputation
    print("\n[3/5] Splitting dataset...")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        stratify=y,
        random_state=RANDOM_STATE
    )

    # Fit imputer only on training data
    imputer = SimpleImputer(strategy="median")

    X_train = imputer.fit_transform(X_train)
    X_test = imputer.transform(X_test)

    # 4. Baseline
    print("\n[4/5] Evaluating baseline...")

    baseline = DummyClassifier(strategy="most_frequent")
    baseline.fit(X_train, y_train)

    baseline_metrics = evaluate(
        baseline, X_test, y_test
    )

    # 5. Train model
    print("\n[5/5] Training ML model...")

    model = HistGradientBoostingClassifier(
        max_iter=80,
        learning_rate=0.1,
        max_leaf_nodes=31,
        l2_regularization=1.0,
        early_stopping=True,
        random_state=RANDOM_STATE
    )

    weights = compute_sample_weight(
        class_weight="balanced",
        y=y_train
    )

    model.fit(
        X_train,
        y_train,
        sample_weight=weights
    )

    model_metrics = evaluate(
        model, X_test, y_test
    )

    # Save preprocessing and model together
    joblib.dump(
        {
            "model": model,
            "imputer": imputer,
            "features": valid_columns,
            "target_mapping": {
                "0": "BENIGN",
                "1": "MALICIOUS"
            }
        },
        MODEL_PATH
    )

    report = {
        "project": "NexaGraph-AI",
        "task": "Binary Network Attack Detection",
        "dataset": "CIC-IDS-2017",
        "sample_size": len(data),
        "training_records": len(X_train),
        "testing_records": len(X_test),
        "feature_count": len(valid_columns),
        "baseline": baseline_metrics,
        "ml_model": model_metrics,
        "improvement": {
            "accuracy": round(
                model_metrics["accuracy"] -
                baseline_metrics["accuracy"], 4
            ),
            "f1_score": round(
                model_metrics["f1_score"] -
                baseline_metrics["f1_score"], 4
            )
        },
        "training_seconds": round(time.time() - start, 2)
    }

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    print("\n===================================")
    print("TRAINING RESULTS")
    print("===================================")

    print("\nBASELINE:")
    print(json.dumps(baseline_metrics, indent=4))

    print("\nTRAINED MODEL:")
    print(json.dumps(model_metrics, indent=4))

    print("\nIMPROVEMENT:")
    print(json.dumps(report["improvement"], indent=4))

    print("\nMODEL:", MODEL_PATH)
    print("REPORT:", REPORT_PATH)


if __name__ == "__main__":
    main()