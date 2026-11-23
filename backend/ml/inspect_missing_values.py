from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]

DATASET_PATH = (
    ROOT / "data" / "processed" / "cic_ids2017_cleaned.csv"
)


def inspect_missing_values():

    print("\n====================================")
    print("MISSING VALUE INVESTIGATION")
    print("====================================")

    missing_counts = {}
    total_rows = 0

    for chunk in pd.read_csv(
        DATASET_PATH,
        chunksize=100_000,
        low_memory=False
    ):

        total_rows += len(chunk)

        missing = chunk.isna().sum()

        for column, count in missing.items():
            missing_counts[column] = (
                missing_counts.get(column, 0) + int(count)
            )

    print("\nTOTAL ROWS:", total_rows)

    print("\nCOLUMNS WITH MISSING VALUES:")

    affected = {
        column: count
        for column, count in missing_counts.items()
        if count > 0
    }

    for column, count in sorted(
        affected.items(),
        key=lambda item: item[1],
        reverse=True
    ):

        print(f"{column}: {count}")

    print("\nTOTAL MISSING CELLS:", sum(affected.values()))
    print("AFFECTED COLUMNS:", len(affected))


if __name__ == "__main__":
    inspect_missing_values()