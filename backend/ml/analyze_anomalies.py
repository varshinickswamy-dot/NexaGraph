from pathlib import Path
import pandas as pd
import numpy as np
import json

ROOT = Path(__file__).resolve().parents[2]

DATASET = ROOT / "data/processed/cic_ids2017_ready.csv"

REPORT = ROOT / "data/processed/anomaly_analysis.json"

CHUNK_SIZE = 100_000

SUSPICIOUS_FEATURES = [
    "Flow Duration",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Min",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Header Length.1",
    "min_seg_size_forward"
]


def analyze_anomalies():

    print("\n====================================")
    print("NEXAGRAPH-AI ANOMALY INVESTIGATION")
    print("====================================")

    statistics = {
        col: {
            "negative_count": 0,
            "zero_count": 0,
            "positive_count": 0,
            "minimum": float("inf"),
            "maximum": float("-inf")
        }
        for col in SUSPICIOUS_FEATURES
    }

    total_rows = 0

    for chunk in pd.read_csv(
        DATASET,
        chunksize=CHUNK_SIZE,
        low_memory=False
    ):

        total_rows += len(chunk)

        for col in SUSPICIOUS_FEATURES:

            if col not in chunk.columns:
                continue

            values = pd.to_numeric(
                chunk[col],
                errors="coerce"
            )

            stats = statistics[col]

            stats["negative_count"] += int(
                (values < 0).sum()
            )

            stats["zero_count"] += int(
                (values == 0).sum()
            )

            stats["positive_count"] += int(
                (values > 0).sum()
            )

            minimum = values.min()
            maximum = values.max()

            if pd.notna(minimum):
                stats["minimum"] = min(
                    stats["minimum"],
                    float(minimum)
                )

            if pd.notna(maximum):
                stats["maximum"] = max(
                    stats["maximum"],
                    float(maximum)
                )

        print(f"Analyzed: {total_rows:,}")

    for col, stats in statistics.items():

        if stats["minimum"] == float("inf"):
            stats["minimum"] = None

        if stats["maximum"] == float("-inf"):
            stats["maximum"] = None

    report = {
        "total_records": total_rows,
        "features": statistics
    }

    REPORT.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8"
    )

    print("\nANOMALY SUMMARY")

    for col, stats in statistics.items():

        print(f"\n{col}")
        print("Negative:", stats["negative_count"])
        print("Zero:", stats["zero_count"])
        print("Positive:", stats["positive_count"])
        print("Minimum:", stats["minimum"])
        print("Maximum:", stats["maximum"])

    print("\nREPORT:", REPORT)


if __name__ == "__main__":
    analyze_anomalies()