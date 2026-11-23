from pathlib import Path
import pandas as pd
import json

ROOT = Path(__file__).resolve().parents[2]

INPUT_FILE = (
    ROOT / "data" / "processed" / "cic_ids2017_cleaned.csv"
)

OUTPUT_FILE = (
    ROOT / "data" / "processed" / "cic_ids2017_ready.csv"
)

REPORT_FILE = (
    ROOT / "data" / "processed" / "missing_value_report.json"
)

CHUNK_SIZE = 100_000


def clean_dataset():

    if not INPUT_FILE.exists():
        raise FileNotFoundError(INPUT_FILE)

    if OUTPUT_FILE.exists():
        raise FileExistsError(
            f"{OUTPUT_FILE} already exists. "
            "Rename it before generating another copy."
        )

    print("\n====================================")
    print("NEXAGRAPH-AI DATASET CLEANING")
    print("====================================")

    total_rows = 0
    missing_before = {}
    missing_after = {}
    first_chunk = True

    try:
        for chunk in pd.read_csv(
            INPUT_FILE,
            chunksize=CHUNK_SIZE,
            low_memory=False
        ):

            total_rows += len(chunk)

            for column in ["Flow Bytes/s", "Flow Packets/s"]:

                if column not in chunk.columns:
                    raise ValueError(
                        f"Required feature missing: {column}"
                    )

                missing_before[column] = (
                    missing_before.get(column, 0)
                    + int(chunk[column].isna().sum())
                )

                # Preserve missing values for train-only imputation.
                chunk[column] = pd.to_numeric(
                    chunk[column],
                    errors="coerce"
                )

                missing_after[column] = (
                    missing_after.get(column, 0)
                    + int(chunk[column].isna().sum())
                )

            chunk.to_csv(
                OUTPUT_FILE,
                mode="w" if first_chunk else "a",
                header=first_chunk,
                index=False
            )

            first_chunk = False

            print(f"Processed: {total_rows:,}")

    except Exception:
        if OUTPUT_FILE.exists():
            OUTPUT_FILE.unlink()
        raise

    report = {
        "total_records": total_rows,
        "missing_before": missing_before,
        "missing_after": missing_after,
        "strategy": (
            "Retain missing values for median imputation "
            "using training data only."
        )
    }

    REPORT_FILE.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8"
    )

    print("\nCLEANING STAGE COMPLETED")
    print("Total records:", total_rows)
    print("Missing values:", sum(missing_after.values()))
    print("Output:", OUTPUT_FILE)
    print("Report:", REPORT_FILE)


if __name__ == "__main__":
    clean_dataset()