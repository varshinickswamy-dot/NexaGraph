import json
from pathlib import Path

import numpy as np
import pandas as pd

DATA_PATH = Path("data/processed/cic_ids2017_features.csv")
REPORT_PATH = Path("data/processed/final_dataset_validation.json")

CHUNK_SIZE = 100000

def main():

    print("\n====================================")
    print("NEXAGRAPH-AI FINAL DATASET VALIDATION")
    print("====================================")

    if not DATA_PATH.exists():
        raise FileNotFoundError(DATA_PATH)

    total_rows = 0
    missing_counts = {}
    infinite_counts = {}
    negative_counts = {}
    label_counts = {}
    constant_values = {}
    numeric_columns = None
    columns = None

    for chunk in pd.read_csv(DATA_PATH, chunksize=CHUNK_SIZE):

        total_rows += len(chunk)

        if columns is None:
            columns = chunk.columns.tolist()

            if "Label" not in columns:
                raise ValueError("Target column Label is missing.")

            numeric_columns = [
                col for col in columns if col != "Label"
            ]

            constant_values = {
                col: None for col in numeric_columns
            }

        features = chunk[numeric_columns].apply(
            pd.to_numeric, errors="coerce"
        )

        missing = features.isna().sum()
        for col, count in missing.items():
            missing_counts[col] = (
                missing_counts.get(col, 0) + int(count)
            )

        infinite = np.isinf(features).sum()
        for col, count in infinite.items():
            infinite_counts[col] = (
                infinite_counts.get(col, 0) + int(count)
            )

        negative = (features < 0).sum()
        for col, count in negative.items():
            negative_counts[col] = (
                negative_counts.get(col, 0) + int(count)
            )

        for col in numeric_columns:
            if constant_values[col] is None:
                if not features[col].dropna().empty:
                    constant_values[col] = features[col].dropna().iloc[0]

        for label, count in chunk["Label"].value_counts(
            dropna=False
        ).items():
            label = str(label)
            label_counts[label] = (
                label_counts.get(label, 0) + int(count)
            )

        print(f"Validated: {total_rows:,}")

    report = {
        "total_records": total_rows,
        "total_columns": len(columns),
        "numeric_features": len(numeric_columns),
        "target_column": "Label",
        "missing_values": {
            k: v for k, v in missing_counts.items() if v > 0
        },
        "infinite_values": {
            k: v for k, v in infinite_counts.items() if v > 0
        },
        "negative_values": {
            k: v for k, v in negative_counts.items() if v > 0
        },
        "label_distribution": label_counts,
        "unique_labels": len(label_counts),
    }

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    print("\n========== VALIDATION SUMMARY ==========")
    print("Records:", total_rows)
    print("Columns:", len(columns))
    print("Numeric features:", len(numeric_columns))
    print("Unique labels:", len(label_counts))
    print("Missing values:", sum(missing_counts.values()))
    print("Infinite values:", sum(infinite_counts.values()))
    print("Negative-value columns:", sum(
        1 for v in negative_counts.values() if v > 0
    ))

    print("\nLABEL DISTRIBUTION:")
    for label, count in sorted(
        label_counts.items(), key=lambda x: x[1], reverse=True
    ):
        print(f"{label}: {count:,}")

    print("\nREPORT:", REPORT_PATH)

if __name__ == "__main__":
    main()