import re
from pathlib import Path

import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = ROOT / "data" / "raw"

OUTPUT_DIR = ROOT / "data" / "processed"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

CHUNK_SIZE = 100_000


def normalize_label(label):

    label = str(label).strip()

    label = re.sub(r"\s+", " ", label)

    return label


def clean_chunk(df):

    df.columns = [
        str(col).strip()
        for col in df.columns
    ]

    df = df.replace(
        [np.inf, -np.inf],
        np.nan
    )

    df["Label"] = (
        df["Label"]
        .astype("string")
        .str.strip()
        .str.replace(r"\s+", " ", regex=True)
    )

    df = df.dropna(subset=["Label"])

    for column in df.columns:

        if column == "Label":
            continue

        df[column] = pd.to_numeric(
            df[column],
            errors="coerce"
        )

    return df


def preprocess_dataset():

    files = sorted(DATA_DIR.glob("*.csv"))

    if not files:

        raise FileNotFoundError(
            "CIC-IDS-2017 CSV files not found."
        )

    output_file = OUTPUT_DIR / "cic_ids2017_cleaned.csv"

    if output_file.exists():

        raise FileExistsError(
            f"{output_file} already exists. "
            "Move or rename it before running again."
        )

    total_rows = 0

    for index, file in enumerate(files):

        print(f"\nProcessing {file.name}")

        reader = pd.read_csv(
            file,
            chunksize=CHUNK_SIZE,
            encoding="utf-8-sig",
            low_memory=False
        )

        for chunk in reader:

            chunk = clean_chunk(chunk)

            chunk.to_csv(
                output_file,
                mode="w" if total_rows == 0 else "a",
                header=(total_rows == 0),
                index=False
            )

            total_rows += len(chunk)

            print(
                f"Processed records: {total_rows:,}",
                end="\r"
            )

    print("\n\nPreprocessing completed.")

    print("Total processed records:", total_rows)

    print("Output:", output_file)


if __name__ == "__main__":

    preprocess_dataset()