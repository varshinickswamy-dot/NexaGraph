import { useEffect, useState } from "react";
import "./MLDetectionDashboard.css";

const API_URL =
  import.meta.env.VITE_API_URL ||
  import.meta.env.VITE_API_BASE_URL ||
  "http://127.0.0.1:8000";

const TOKEN_KEY = "nexagraph-access-token";

type Metrics = {
  project: string;
  task: string;
  dataset: string;
  sample_size: number;
  training_records: number;
  testing_records: number;
  feature_count: number;
  training_seconds: number;
  baseline: {
    accuracy: number;
    precision: number;
    recall: number;
    f1_score: number;
    roc_auc: number;
    confusion_matrix: number[][];
  };
  ml_model: {
    accuracy: number;
    precision: number;
    recall: number;
    f1_score: number;
    roc_auc: number;
    confusion_matrix: number[][];
  };
};

function MLDetectionDashboard() {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadMetrics() {
      try {
        const token = localStorage.getItem(TOKEN_KEY);

        const response = await fetch(
          `${API_URL}/api/ml/metrics`,
          {
            headers: token
              ? { Authorization: `Bearer ${token}` }
              : {},
          }
        );

        if (!response.ok) {
          throw new Error("Unable to load ML metrics.");
        }

        const data = await response.json();
        setMetrics(data);
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : "ML dashboard unavailable."
        );
      } finally {
        setLoading(false);
      }
    }

    void loadMetrics();
  }, []);

  if (loading) {
    return (
      <section className="ml-dashboard">
        <p>Loading ML performance...</p>
      </section>
    );
  }

  if (error || !metrics) {
    return (
      <section className="ml-dashboard">
        <h2>AI Threat Detection</h2>
        <p className="ml-error">
          {error || "Metrics unavailable"}
        </p>
      </section>
    );
  }

  const performance = [
    {
      label: "Accuracy",
      baseline: metrics.baseline.accuracy,
      model: metrics.ml_model.accuracy,
    },
    {
      label: "Precision",
      baseline: metrics.baseline.precision,
      model: metrics.ml_model.precision,
    },
    {
      label: "Recall",
      baseline: metrics.baseline.recall,
      model: metrics.ml_model.recall,
    },
    {
      label: "F1 Score",
      baseline: metrics.baseline.f1_score,
      model: metrics.ml_model.f1_score,
    },
    {
      label: "ROC-AUC",
      baseline: metrics.baseline.roc_auc,
      model: metrics.ml_model.roc_auc,
    },
  ];

  const matrix = metrics.ml_model.confusion_matrix;

  return (
    <section className="ml-dashboard">

      <div className="ml-heading">
        <div>
          <span className="ml-eyebrow">
            MACHINE LEARNING MODULE
          </span>
          <h2>AI Threat Detection Dashboard</h2>
          <p>
            Network attack detection using CIC-IDS-2017
          </p>
        </div>

        <span className="ml-status">
          MODEL AVAILABLE
        </span>
      </div>

      <div className="ml-summary-grid">

        <div className="ml-card">
          <span>Model Accuracy</span>
          <strong>
            {(metrics.ml_model.accuracy * 100).toFixed(2)}%
          </strong>
          <small>Current benchmark</small>
        </div>

        <div className="ml-card">
          <span>Precision</span>
          <strong>
            {(metrics.ml_model.precision * 100).toFixed(2)}%
          </strong>
          <small>Malicious classification</small>
        </div>

        <div className="ml-card">
          <span>Recall</span>
          <strong>
            {(metrics.ml_model.recall * 100).toFixed(2)}%
          </strong>
          <small>Malicious detection</small>
        </div>

        <div className="ml-card">
          <span>F1 Score</span>
          <strong>
            {(metrics.ml_model.f1_score * 100).toFixed(2)}%
          </strong>
          <small>Combined performance</small>
        </div>

      </div>

      <div className="ml-panel">
        <h3>Baseline vs Trained ML Model</h3>

        <div className="ml-legend">
          <span className="baseline-dot" />
          Baseline

          <span className="model-dot" />
          Trained ML Model
        </div>

        {performance.map((item) => (
          <div className="ml-performance-row" key={item.label}>
            <div className="ml-performance-title">
              <strong>{item.label}</strong>
              <span>
                {(item.model * 100).toFixed(2)}%
              </span>
            </div>

            <div className="ml-bar-track">
              <div
                className="ml-bar baseline-bar"
                style={{
                  width: `${item.baseline * 100}%`,
                }}
              />
            </div>

            <div className="ml-bar-track">
              <div
                className="ml-bar model-bar"
                style={{
                  width: `${item.model * 100}%`,
                }}
              />
            </div>
          </div>
        ))}
      </div>

      <div className="ml-panel">
        <h3>Confusion Matrix</h3>

        <p className="ml-description">
          Trained model classification results on the test set.
        </p>

        <div className="ml-matrix">
          <div className="ml-matrix-cell ml-matrix-heading">
            Actual / Predicted
          </div>

          <div className="ml-matrix-cell ml-matrix-heading">
            BENIGN
          </div>

          <div className="ml-matrix-cell ml-matrix-heading">
            MALICIOUS
          </div>

          <div className="ml-matrix-cell ml-matrix-heading">
            BENIGN
          </div>

          <div className="ml-matrix-cell ml-correct">
            {matrix[0][0]}
          </div>

          <div className="ml-matrix-cell ml-incorrect">
            {matrix[0][1]}
          </div>

          <div className="ml-matrix-cell ml-matrix-heading">
            MALICIOUS
          </div>

          <div className="ml-matrix-cell ml-incorrect">
            {matrix[1][0]}
          </div>

          <div className="ml-matrix-cell ml-correct">
            {matrix[1][1]}
          </div>
        </div>
      </div>

      <div className="ml-panel">
        <h3>Training Information</h3>

        <div className="ml-info-grid">
          <div>
            <span>Dataset</span>
            <strong>{metrics.dataset}</strong>
          </div>

          <div>
            <span>Training records</span>
            <strong>
              {metrics.training_records.toLocaleString()}
            </strong>
          </div>

          <div>
            <span>Testing records</span>
            <strong>
              {metrics.testing_records.toLocaleString()}
            </strong>
          </div>

          <div>
            <span>Features</span>
            <strong>{metrics.feature_count}</strong>
          </div>

          <div>
            <span>Training duration</span>
            <strong>{metrics.training_seconds}s</strong>
          </div>

          <div>
            <span>Algorithm</span>
            <strong>HistGradientBoosting</strong>
          </div>
        </div>
      </div>

      <div className="ml-disclaimer">
        Performance figures represent the current sampled random
        train/test benchmark. Independent validation is required
        before interpreting them as real-world detection performance.
      </div>

    </section>
  );
}

export default MLDetectionDashboard;