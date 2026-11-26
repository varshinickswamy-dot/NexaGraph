# NexaGraph AI

**AI-assisted Security Operations Centre (SOC) and network attack-path analysis**

NexaGraph AI combines network asset visibility, security-event monitoring, vulnerability intelligence, incident workflows and machine-learning-based network traffic classification in one security operations workspace.

> **Project status:** Academic / demonstrator project. The application includes integrated SOC modules and a CIC-IDS-2017-trained binary classifier. Production SOC use requires organization-specific validation, operational monitoring, security review and controlled deployment.

## Core capabilities

- **Security Operations Overview:** consolidated incident, event, vulnerability, asset and ML availability signals.
- **Enterprise Network Graph:** visualize assets and network relationships with organization-aware graph access.
- **Attack Path Analysis:** identify directed paths from exposed assets toward critical assets using explainable heuristic risk scoring.
- **Remediation Simulation:** model asset isolation and connection removal without modifying the live graph.
- **Security Event Monitoring:** review security events and severity summaries.
- **Incident Management:** manage incident status, investigation notes and related assets.
- **Vulnerability Intelligence:** inspect findings, severity, CVSS and remediation status.
- **ML Traffic Detection:** classify network-flow feature vectors as BENIGN or MALICIOUS.
- **Security Intelligence and Team Management:** supporting SOC workflows and organization collaboration.

## Technology stack

| Layer | Technologies |
|---|---|
| Frontend | React 19, TypeScript, Vite, Cytoscape.js |
| Backend | Python 3.12, FastAPI, Pydantic |
| Relational data | PostgreSQL, SQLAlchemy |
| Graph data | Neo4j |
| Machine learning | pandas, NumPy, scikit-learn, joblib |
| Deployment | Render |
| Quality checks | GitHub Actions, TypeScript build, Python compilation, pytest |

## Repository layout

```text
NexaGraph/
├── backend/
│   ├── main.py
│   ├── auth_routes.py
│   ├── incident_routes.py
│   ├── security_event_routes.py
│   ├── vulnerability_routes.py
│   ├── intelligence_routes.py
│   ├── network_routes.py
│   └── ml/
│       ├── api.py
│       ├── train_model.py
│       └── artifacts/
│           ├── nexagraph_binary_model.joblib
│           └── training_metrics.json
├── database/postgres/migrations/
├── data/
│   ├── raw/                 # Local CIC-IDS-2017 source files (not committed)
│   ├── processed/           # Local prepared feature table (not committed)
│   ├── assets.csv           # Small fallback graph fixture
│   ├── connections.csv      # Small fallback graph fixture
│   └── README.md
├── frontend/src/
├── .github/workflows/ci.yml
└── requirements.txt
```

## Local setup

### Backend

From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
uvicorn backend.main:app --reload
```

The API runs at `http://127.0.0.1:8000`. Interactive API documentation is available at `/docs` when enabled by the application.

Configure database and authentication settings through environment variables. Never commit `.env`, database passwords, API keys or private traffic captures.

### Frontend

```powershell
cd frontend
npm ci
npm run dev
```

For a production build, run `npm run build`. Configure the frontend API base URL using the project's supported frontend environment setting. On the backend, set `FRONTEND_ORIGINS` to the exact deployed frontend origin(s), comma-separated.

## CIC-IDS-2017 dataset and model

The training pipeline expects the prepared feature table at:

```text
data/processed/cic_ids2017_features.csv
```

Original dataset files belong under `data/raw/`. The large raw and processed data directories are intentionally excluded from Git; do not commit the full dataset.

Train locally from the repository root:

```powershell
python -m backend.ml.train_model
```

Alternatively, set `NEXAGRAPH_TRAINING_DATA` to the full path of the prepared feature CSV. The CSV must contain a `Label` column and numeric network-flow feature columns.

The training script writes:

- `backend/ml/artifacts/nexagraph_binary_model.joblib`
- `backend/ml/artifacts/training_metrics.json`

The deployed prediction API needs the trained model artifact, not the original training CSVs. Keep the model and metrics report from the same training run.

### Reported evaluation snapshot

The checked-in metrics report records 145,000 sampled records, 116,000 training records, 29,000 test records and 69 features. On that report's random holdout split, the model reports accuracy 0.9982, precision 0.9922, recall 0.9984, F1 0.9953 and ROC-AUC 0.9999.

These are dataset-split results, not a guarantee of real-world SOC detection performance. Validate against temporally separated and organization-specific traffic before operational use.

## Tests and continuous integration

Run the backend unit tests from the repository root:

```powershell
python -m pytest backend/test_attack_paths.py backend/test_remediation_api.py -q
```

Run frontend checks:

```powershell
cd frontend
npm ci
npm run build
npm run lint
npm test
```

GitHub Actions runs backend syntax checks and the frontend TypeScript/production build on relevant changes.

## Deployment checklist

- Deploy backend and frontend from the same intended commit.
- Configure PostgreSQL and Neo4j connection variables in the backend service.
- Set `FRONTEND_ORIGINS` to the deployed frontend URL.
- Set the frontend API base URL to the deployed backend.
- Include `backend/ml/artifacts/nexagraph_binary_model.joblib` and its matching `training_metrics.json` in the backend deployment.
- Verify health, authentication, organization-scoped graph access, event/incident APIs and authenticated ML prediction.
- Keep secrets in deployment environment settings, never in Git.

## Security and operational notes

- Keep authenticated routes behind authentication and role checks.
- Keep organization data scoped to the authenticated organization.
- Treat attack-path and asset-risk scores as project heuristics, not certified risk measurements.
- Remediation simulation is non-destructive; it does not execute network isolation or firewall changes.
- Review audit events, backups, access controls, dependency updates and incident-response procedures before production use.

## License

No open-source license has been declared in this repository. Contact the project owner before reusing or redistributing the code.
