import json
from pathlib import Path

import pandas as pd

INPUT_PATH = Path("data/processed/cic_ids2017_ready.csv")
OUTPUT_PATH = Path("data/processed/cic_ids2017_features.csv")
REPORT_PATH = Path("data/processed/final_feature_report.json")

CHUNK_SIZE = 100000

CONSTANT_FEATURES = [
    "Bwd PSH Flags",
    "Bwd URG Flags",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
]

DUPLICATE_FEATURES = [
    "Fwd Header Length.1"
]

def main():

    print("\n====================================")
    print("NEXAGRAPH-AI FINAL FEATURE PREPARATION")
    print("====================================")

    if not INPUT_PATH.exists():
        raise FileNotFoundError(INPUT_PATH)

    if OUTPUT_PATH.exists():
        raise FileExistsError(
            f"{OUTPUT_PATH} already exists. "
            "Preserving existing output."
        )

    first_chunk = True
    total_rows = 0
    final_columns = None

    for chunk in pd.read_csv(INPUT_PATH, chunksize=CHUNK_SIZE):

        missing = [
            col for col in CONSTANT_FEATURES + DUPLICATE_FEATURES
            if col not in chunk.columns
        ]

        if missing:
            raise ValueError(f"Missing expected columns: {missing}")

        chunk = chunk.drop(
            columns=CONSTANT_FEATURES + DUPLICATE_FEATURES
        )

        if first_chunk:
            final_columns = chunk.columns.tolist()

            chunk.to_csv(
                OUTPUT_PATH,
                index=False,
                mode="w"
            )

            first_chunk = False

        else:
            chunk.to_csv(
                OUTPUT_PATH,
                index=False,
                mode="a",
                header=False
            )

        total_rows += len(chunk)

        print(f"Prepared: {total_rows:,}")

    report = {
        "input_file": str(INPUT_PATH),
        "output_file": str(OUTPUT_PATH),
        "records": total_rows,
        "original_features": 78,
        "constant_features_removed": len(CONSTANT_FEATURES),
        "duplicate_features_removed": len(DUPLICATE_FEATURES),
        "remaining_columns": len(final_columns),
        "target_column": "Label",
        "model_input_features": len(final_columns) - 1,
        "removed_constant_features": CONSTANT_FEATURES,
        "removed_duplicate_features": DUPLICATE_FEATURES,
    }

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with open(REPORT_PATH, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("\nFEATURE PREPARATION COMPLETE")
    print("Records:", total_rows)
    print("Remaining columns:", len(final_columns))
    print("Model input features:", len(final_columns) - 1)
    print("Target: Label")
    print("Output:", OUTPUT_PATH)
    print("Report:", REPORT_PATH)


if __name__ == "__main__":
    main()