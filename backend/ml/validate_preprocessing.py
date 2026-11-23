from pathlib import Path
import json
import pandas as pd
import numpy as np

ROOT = Path(__file__).resolve().parents[2]

DATASET_PATH = ROOT / "data" / "processed" / "cic_ids2017_cleaned.csv"
REPORT_PATH = ROOT / "data" / "processed" / "preprocessing_validation.json"


def validate_dataset():

    print("\n======================================")
    print("NEXAGRAPH-AI PREPROCESSING VALIDATION")
    print("======================================")

    if not DATASET_PATH.exists():
        raise FileNotFoundError(DATASET_PATH)

    total_rows = 0
    missing_values = 0
    infinite_values = 0
    invalid_labels = 0
    label_counts = {}
    columns = None

    for chunk in pd.read_csv(
        DATASET_PATH,
        chunksize=100_000,
        low_memory=False
    ):

        total_rows += len(chunk)

        if columns is None:
            columns = list(chunk.columns)

        missing_values += int(chunk.isna().sum().sum())

        features = chunk.drop(columns=["Label"])

        numeric = features.select_dtypes(include=[np.number])

        infinite_values += int(
            np.isinf(numeric.to_numpy()).sum()
        )

        invalid_labels += int(
            chunk["Label"].isna().sum()
        )

        counts = chunk["Label"].value_counts()

        for label, count in counts.items():
            label_counts[str(label)] = (
                label_counts.get(str(label), 0) + int(count)
            )

    report = {
        "dataset": DATASET_PATH.name,
        "total_records": total_rows,
        "total_columns": len(columns),
        "feature_columns": len(columns) - 1,
        "missing_values": missing_values,
        "infinite_values": infinite_values,
        "invalid_labels": invalid_labels,
        "labels": label_counts,
        "validation_passed": (
            total_rows > 0
            and len(columns) == 79
            and missing_values == 0
            and infinite_values == 0
            and invalid_labels == 0
        )
    }

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)

    REPORT_PATH.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8"
    )

    print("\nTOTAL RECORDS:", total_rows)
    print("TOTAL COLUMNS:", len(columns))
    print("FEATURE COLUMNS:", len(columns) - 1)
    print("MISSING VALUES:", missing_values)
    print("INFINITE VALUES:", infinite_values)
    print("INVALID LABELS:", invalid_labels)

    print("\nLABEL DISTRIBUTION:")

    for label, count in sorted(
        label_counts.items(),
        key=lambda item: item[1],
        reverse=True
    ):
        print(f"{label}: {count}")

    print("\nVALIDATION:", report["validation_passed"])
    print("REPORT:", REPORT_PATH)


if __name__ == "__main__":
    validate_dataset()