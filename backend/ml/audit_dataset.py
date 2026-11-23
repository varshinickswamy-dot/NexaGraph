import json
from collections import Counter
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = ROOT / "data" / "raw"
OUTPUT_DIR = ROOT / "data" / "processed"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

CHUNK_SIZE = 100_000


def audit_dataset():

    files = sorted(DATA_DIR.glob("*.csv"))

    if not files:
        raise FileNotFoundError(
            f"No CSV files found in {DATA_DIR}"
        )

    report = {
        "dataset": "CIC-IDS-2017",
        "total_files": len(files),
        "files": [],
        "total_records": 0,
        "total_missing_values": 0,
        "label_distribution": {}
    }

    overall_labels = Counter()
    reference_columns = None

    print("\n================================")
    print("NEXAGRAPH-AI DATASET AUDIT")
    print("================================")

    for file in files:

        print(f"\nProcessing: {file.name}")

        file_labels = Counter()
        rows = 0
        missing_values = 0

        try:

            reader = pd.read_csv(
                file,
                chunksize=CHUNK_SIZE,
                encoding="utf-8-sig",
                low_memory=False,
                on_bad_lines="error"
            )

            for chunk in reader:

                chunk.columns = [
                    str(column).strip()
                    for column in chunk.columns
                ]

                if "Label" not in chunk.columns:
                    raise ValueError(
                        f"Label column missing in {file.name}"
                    )

                columns = list(chunk.columns)

                if reference_columns is None:
                    reference_columns = columns

                elif columns != reference_columns:
                    raise ValueError(
                        f"Column mismatch in {file.name}"
                    )

                rows += len(chunk)

                missing_values += int(
                    chunk.isna().sum().sum()
                )

                labels = (
                    chunk["Label"]
                    .astype("string")
                    .str.strip()
                    .fillna("MISSING")
                )

                counts = labels.value_counts(
                    dropna=False
                )

                for label, count in counts.items():

                    file_labels[str(label)] += int(count)

                    overall_labels[str(label)] += int(count)

                print(
                    f"  Processed {rows:,} records",
                    end="\r"
                )

        except Exception as error:

            print(f"\nERROR: {error}")
            raise

        file_report = {
            "filename": file.name,
            "records": rows,
            "missing_values": missing_values,
            "labels": dict(file_labels)
        }

        report["files"].append(file_report)

        report["total_records"] += rows

        report["total_missing_values"] += missing_values

        print(f"\nCompleted: {file.name}")
        print(f"Records: {rows:,}")
        print(f"Labels: {dict(file_labels)}")

    report["label_distribution"] = dict(overall_labels)

    report["total_classes"] = len(overall_labels)

    output_file = OUTPUT_DIR / "dataset_audit.json"

    with open(output_file, "w", encoding="utf-8") as f:

        json.dump(
            report,
            f,
            indent=4
        )

    print("\n================================")
    print("DATASET AUDIT COMPLETED")
    print("================================")

    print("Files:", len(files))

    print("Total records:", f"{report['total_records']:,}")

    print("Total classes:", report["total_classes"])

    print("Missing values:", report["total_missing_values"])

    print("\nOVERALL LABEL DISTRIBUTION")

    for label, count in sorted(
        overall_labels.items(),
        key=lambda item: item[1],
        reverse=True
    ):

        print(f"{label}: {count:,}")

    print("\nAudit report saved to:")
    print(output_file)


if __name__ == "__main__":

    audit_dataset()