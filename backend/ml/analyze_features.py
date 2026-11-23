from pathlib import Path
import pandas as pd
import numpy as np
import json

ROOT = Path(__file__).resolve().parents[2]

DATASET = ROOT / "data" / "processed" / "cic_ids2017_ready.csv"
REPORT = ROOT / "data" / "processed" / "feature_analysis.json"


def analyze_features():

    print("\n====================================")
    print("NEXAGRAPH-AI FEATURE ANALYSIS")
    print("====================================")

    if not DATASET.exists():
        raise FileNotFoundError(DATASET)

    feature_names = None
    minimum = {}
    maximum = {}
    unique_values = {}
    missing_values = {}
    total_rows = 0
    duplicate_rows = 0
    label_counts = {}

    for chunk in pd.read_csv(
        DATASET,
        chunksize=100_000,
        low_memory=False
    ):

        total_rows += len(chunk)

        if feature_names is None:
            feature_names = [
                col for col in chunk.columns
                if col != "Label"
            ]

        features = chunk[feature_names]

        duplicate_rows += int(chunk.duplicated().sum())

        for col in feature_names:

            series = pd.to_numeric(
                features[col],
                errors="coerce"
            )

            missing_values[col] = (
                missing_values.get(col, 0)
                + int(series.isna().sum())
            )

            current_min = series.min()
            current_max = series.max()

            if pd.notna(current_min):
                minimum[col] = min(
                    minimum.get(col, float("inf")),
                    float(current_min)
                )

            if pd.notna(current_max):
                maximum[col] = max(
                    maximum.get(col, float("-inf")),
                    float(current_max)
                )

            values = set(series.dropna().unique())

            if col not in unique_values:
                unique_values[col] = values
            else:
                unique_values[col].update(values)

        for label, count in chunk["Label"].value_counts().items():
            label_counts[str(label)] = (
                label_counts.get(str(label), 0) + int(count)
            )

        print(f"Analyzed: {total_rows:,}")

    constant_features = [
        col for col in feature_names
        if len(unique_values[col]) <= 1
    ]

    report = {
        "total_records": total_rows,
        "feature_count": len(feature_names),
        "duplicate_rows_within_chunks": duplicate_rows,
        "constant_features": constant_features,
        "missing_values": missing_values,
        "minimum": minimum,
        "maximum": maximum,
        "labels": label_counts
    }

    REPORT.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8"
    )

    print("\nFEATURE COUNT:", len(feature_names))
    print("CONSTANT FEATURES:", constant_features)
    print("DUPLICATE ROWS WITHIN CHUNKS:", duplicate_rows)

    print("\nFEATURE RANGES:")

    for col in feature_names:
        print(
            f"{col}: "
            f"min={minimum.get(col)}, "
            f"max={maximum.get(col)}"
        )

    print("\nREPORT SAVED:", REPORT)


if __name__ == "__main__":
    analyze_features()