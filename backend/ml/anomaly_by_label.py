from pathlib import Path
import pandas as pd
import json

ROOT = Path(__file__).resolve().parents[2]

DATASET = ROOT / "data/processed/cic_ids2017_ready.csv"

REPORT = ROOT / "data/processed/anomaly_by_label.json"

CHUNK_SIZE = 100_000

FEATURES = [
    "Flow Duration",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Min",
    "Fwd Header Length",
    "Bwd Header Length",
    "min_seg_size_forward"
]


def analyze():

    print("\n======================================")
    print("ANOMALIES BY ATTACK CLASS")
    print("======================================")

    results = {}

    total_rows = 0

    for chunk in pd.read_csv(
        DATASET,
        chunksize=CHUNK_SIZE,
        low_memory=False
    ):

        total_rows += len(chunk)

        for feature in FEATURES:

            if feature not in chunk.columns:
                continue

            negative_rows = chunk[feature] < 0

            grouped = chunk.loc[
                negative_rows, ["Label", feature]
            ].groupby("Label")[feature].agg(
                ["count", "min", "max"]
            )

            for label, row in grouped.iterrows():

                label = str(label)

                if label not in results:
                    results[label] = {}

                if feature not in results[label]:
                    results[label][feature] = {
                        "negative_count": 0,
                        "minimum": None,
                        "maximum": None
                    }

                entry = results[label][feature]

                entry["negative_count"] += int(row["count"])

                minimum = float(row["min"])
                maximum = float(row["max"])

                if entry["minimum"] is None:
                    entry["minimum"] = minimum
                    entry["maximum"] = maximum
                else:
                    entry["minimum"] = min(
                        entry["minimum"], minimum
                    )

                    entry["maximum"] = max(
                        entry["maximum"], maximum
                    )

        print(f"Processed: {total_rows:,}")

    REPORT.write_text(
        json.dumps(results, indent=4),
        encoding="utf-8"
    )

    print("\nANOMALIES BY LABEL")

    for label, features in results.items():

        print(f"\nLABEL: {label}")

        for feature, stats in features.items():

            print(
                f"  {feature}: "
                f"{stats['negative_count']} "
                f"(min={stats['minimum']}, "
                f"max={stats['maximum']})"
            )

    print("\nREPORT SAVED:", REPORT)


if __name__ == "__main__":
    analyze()