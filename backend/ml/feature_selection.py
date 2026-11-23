from pathlib import Path
import pandas as pd
import numpy as np
import json

ROOT = Path(__file__).resolve().parents[2]

DATASET = ROOT / "data/processed/cic_ids2017_ready.csv"

OUTPUT = ROOT / "data/processed/feature_selection_report.json"

CHUNK_SIZE = 100_000

CONSTANT_FEATURES = [
    "Bwd PSH Flags",
    "Bwd URG Flags",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate"
]

REDUNDANT_FEATURES = [
    "Fwd Header Length.1"
]


def analyze():

    print("\n====================================")
    print("NEXAGRAPH-AI FEATURE SELECTION")
    print("====================================")

    feature_data = []
    total_rows = 0

    # Collect reproducible sample.
    for chunk in pd.read_csv(
        DATASET,
        chunksize=CHUNK_SIZE,
        low_memory=False
    ):

        sample = chunk.sample(
            n=min(5000, len(chunk)),
            random_state=42
        )

        feature_data.append(sample)

        total_rows += len(chunk)

        print("Processed:", total_rows)

    data = pd.concat(
        feature_data,
        ignore_index=True
    )

    features = data.drop(columns=["Label"])

    # Remove known constant and duplicate candidates.
    candidates = features.drop(
        columns=CONSTANT_FEATURES + REDUNDANT_FEATURES,
        errors="ignore"
    )

    # Correlation matrix.
    correlation = candidates.corr()

    correlated_pairs = []

    for i in range(len(correlation.columns)):

        for j in range(i + 1, len(correlation.columns)):

            value = correlation.iloc[i, j]

            if pd.notna(value) and abs(value) >= 0.98:

                correlated_pairs.append({
                    "feature_1": correlation.columns[i],
                    "feature_2": correlation.columns[j],
                    "correlation": round(float(value), 6)
                })

    report = {
        "total_dataset_records": total_rows,
        "sample_records": len(data),
        "original_feature_count": len(features.columns),
        "constant_features": CONSTANT_FEATURES,
        "redundant_feature_candidates": REDUNDANT_FEATURES,
        "remaining_feature_count": len(candidates.columns),
        "high_correlation_pairs": correlated_pairs,
        "correlation_threshold": 0.98,
        "note": (
            "Correlation results are exploratory and must be "
            "validated before final feature exclusion."
        )
    }

    OUTPUT.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8"
    )

    print("\nORIGINAL FEATURES:", len(features.columns))
    print("CONSTANT FEATURES:", len(CONSTANT_FEATURES))
    print("REDUNDANT CANDIDATES:", len(REDUNDANT_FEATURES))
    print("REMAINING FEATURES:", len(candidates.columns))

    print("\nHIGH CORRELATION PAIRS:", len(correlated_pairs))

    print("\nREPORT:", OUTPUT)


if __name__ == "__main__":
    analyze()