# NexaGraph dataset and ML artifact layout

## CIC-IDS-2017 training data

Place the original downloaded CIC-IDS-2017 CSV files under:

```text
data/raw/
```

The training pipeline expects the prepared feature table at:

```text
data/processed/cic_ids2017_features.csv
```

Run training from the repository root:

```powershell
python -m backend.ml.train_model
```

If the processed CSV is stored elsewhere, set `NEXAGRAPH_TRAINING_DATA` to its full path before running the command.

The training script writes the model bundle and metrics report to:

```text
backend/ml/artifacts/nexagraph_binary_model.joblib
backend/ml/artifacts/training_metrics.json
```

The API loads those exact artifact paths. The processed CSV must contain a `Label` column and numeric network-flow feature columns; `BENIGN` is treated as benign and all other labels are mapped to malicious.

## Repository data files

- `assets.csv` and `connections.csv` are small sample network-graph files used by the local fallback graph.
- `raw/` and `processed/` contain large training datasets and are intentionally ignored by Git to avoid committing hundreds of megabytes.
- Do not put credentials, tokens, or private customer traffic captures in this directory.

## Deployment note

Render does not receive ignored local dataset directories. The deployed prediction API needs the trained model bundle under `backend/ml/artifacts/`; it does not need the original CIC-IDS-2017 CSVs to serve predictions.
