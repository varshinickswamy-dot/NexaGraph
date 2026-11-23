import pandas as pd
import numpy as np

DATA_PATH = "data/processed/cic_ids2017_ready.csv"

print("\n====================================")
print("NEXAGRAPH-AI DUPLICATE FEATURE CHECK")
print("====================================")

target_columns = [
    "Fwd Header Length",
    "Fwd Header Length.1"
]

total_rows = 0
equal_rows = 0
different_rows = 0
both_nan_rows = 0

for chunk in pd.read_csv(DATA_PATH, chunksize=100000):

    if not all(col in chunk.columns for col in target_columns):
        raise ValueError("Required columns not found.")

    first = pd.to_numeric(
        chunk["Fwd Header Length"], errors="coerce"
    )

    second = pd.to_numeric(
        chunk["Fwd Header Length.1"], errors="coerce"
    )

    both_nan = first.isna() & second.isna()

    equal = (
        first.eq(second) | both_nan
    )

    total_rows += len(chunk)
    equal_rows += int(equal.sum())
    different_rows += int((~equal).sum())
    both_nan_rows += int(both_nan.sum())

print("\nTOTAL ROWS:", total_rows)
print("IDENTICAL ROWS:", equal_rows)
print("DIFFERENT ROWS:", different_rows)
print("BOTH NAN ROWS:", both_nan_rows)

if different_rows == 0:
    print("\nRESULT: Columns are identical.")
else:
    print("\nRESULT: Columns are NOT identical.")