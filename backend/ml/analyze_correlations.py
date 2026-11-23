from pathlib import Path
import pandas as pd
import json

ROOT = Path(__file__).resolve().parents[2]

DATASET = ROOT / "data/processed/cic_ids2017_ready.csv"

REPORT = ROOT / "data/processed/correlation_analysis.json"

CHUNK_SIZE = 100_000

DROP_CANDIDATES = [
    "Bwd PSH Flags",
    "Bwd URG Flags",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Fwd Header Length.1"
]


def analyze_correlations():

    print("\n====================================")
    print("FEATURE CORRELATION ANALYSIS")
    print("====================================")

    # Use a reproducible sample for efficient correlation analysis.
    samples = []

    for chunk in pd.read_csv(
        DATASET,
        chunksize=CHUNK_SIZE,
        low_memory=False
    ):

        features = chunk.drop(
            columns=["Label"] + DROP_CANDIDATES,
            errors="ignore"
        )

        sample = features.sample(
            n=min(2000, len(features)),
            random_state=42
        )

        samples.append(sample)

        print("Sample collected:", len(samples))

    data = pd.concat(samples, ignore_index=True)

    correlation = data.corr(method="pearson")

    pairs = []

    for i in range(len(correlation.columns)):

        for j in range(i + 1, len(correlation.columns)):

            value = correlation.iloc[i, j]

            if pd.notna(value) and abs(value) >= 0.98:

                pairs.append({
                    "feature_1": correlation.columns[i],
                    "feature_2": correlation.columns[j],
                    "correlation": float(value)
                })

    report = {
        "sample_records": len(data),
        "correlation_threshold": 0.98,
        "high_correlation_pairs": pairs
    }

    REPORT.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8"
    )

    print("\nHIGH CORRELATION PAIRS:")

    if not pairs:
        print("No highly correlated pairs found.")

    for pair in pairs:

        print(
            pair["feature_1"],
            "<->",
            pair["feature_2"],
            ":",
            round(pair["correlation"], 5)
        )

    print("\nTOTAL HIGH CORRELATION PAIRS:", len(pairs))
    print("REPORT:", REPORT)


if __name__ == "__main__":
    analyze_correlations()