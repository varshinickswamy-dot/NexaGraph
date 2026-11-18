import { useCallback, useState } from "react";
import "./SecurityIntelligence.css";

const API =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

type Finding = {
  title: string;
  category: string;
  severity: string;
  description: string;
  recommendation: string;
  event_ids: string[];
  asset_id?: string | null;
  source_ip?: string | null;
  evidence_count: number;
};

type Analysis = {
  organization_id: string;
  analysis_period_hours: number;
  analyzed_at: string;
  total_events_analyzed: number;
  high_risk_events: number;
  total_findings: number;
  severity_summary: Record<string, number>;
  findings: Finding[];
};

const severityLevels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export default function SecurityIntelligence() {
  const [organizationId, setOrganizationId] = useState(
    () => localStorage.getItem("nexagraph-organization-id") || ""
  );

  const [hours, setHours] = useState("24");
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [filter, setFilter] = useState("ALL");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);

  // Incident creation states
  const [creatingIncident, setCreatingIncident] = useState<string | null>(
    null
  );

  const [incidentMessage, setIncidentMessage] = useState("");

  // ==========================================
  // SECURITY INTELLIGENCE ANALYSIS
  // ==========================================

  const runAnalysis = useCallback(async () => {
    if (!organizationId.trim()) {
      setError("Enter a valid organization UUID.");
      return;
    }

    setLoading(true);
    setError("");
    setIncidentMessage("");
    setAnalysis(null);

    try {
      const params = new URLSearchParams({
        organization_id: organizationId.trim(),
        hours,
      });

      const response = await fetch(
        `${API}/security-intelligence/analyze?${params.toString()}`
      );

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(
          typeof data.detail === "string"
            ? data.detail
            : "Security analysis failed."
        );
      }

      setAnalysis(data);

      localStorage.setItem(
        "nexagraph-organization-id",
        organizationId.trim()
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to execute analysis."
      );
    } finally {
      setLoading(false);
    }
  }, [organizationId, hours]);

  // ==========================================
  // CREATE INCIDENT FROM SECURITY FINDING
  // ==========================================

  async function createIncidentFromFinding(finding: Finding) {
    if (!organizationId.trim()) {
      setError("Organization ID is required.");
      return;
    }

    if (creatingIncident !== null) {
      return;
    }

    const confirmed = window.confirm(
      `Create a security incident for "${finding.title}"?`
    );

    if (!confirmed) {
      return;
    }

    setCreatingIncident(finding.title);
    setIncidentMessage("");
    setError("");

    try {
      const response = await fetch(`${API}/incidents`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          organization_id: organizationId.trim(),
          title: finding.title,
          description: [
            finding.description,
            "",
            "SECURITY INTELLIGENCE FINDING",
            `Detection category: ${finding.category}`,
            `Severity: ${finding.severity}`,
            `Evidence count: ${finding.evidence_count}`,
            `Evidence event IDs: ${finding.event_ids.join(", ")}`,
            `Affected asset: ${finding.asset_id || "Not specified"}`,
            `Source IP: ${finding.source_ip || "Not specified"}`,
            "",
            `Recommended action: ${finding.recommendation}`,
          ].join("\n"),
          severity: finding.severity,
        }),
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(
          typeof data.detail === "string"
            ? data.detail
            : "Incident creation failed."
        );
      }

      setIncidentMessage(
        `Incident created successfully! Reference: ${
          data.id || "Created"
        }`
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to create incident."
      );
    } finally {
      setCreatingIncident(null);
    }
  }

  // ==========================================
  // ORGANIZATION CONNECTION
  // ==========================================

  function saveOrganization() {
    if (!organizationId.trim()) {
      setError("Please enter an organization UUID.");
      return;
    }

    localStorage.setItem(
      "nexagraph-organization-id",
      organizationId.trim()
    );

    runAnalysis();
  }

  // ==========================================
  // FILTER FINDINGS
  // ==========================================

  const filteredFindings =
    analysis?.findings.filter(
      (finding) =>
        filter === "ALL" || finding.severity === filter
    ) ?? [];

  // ==========================================
  // DETECTION CATEGORY STATISTICS
  // ==========================================

  const categories =
    analysis?.findings.reduce<Record<string, number>>(
      (result, finding) => {
        result[finding.category] =
          (result[finding.category] || 0) + 1;

        return result;
      },
      {}
    ) ?? {};

  // ==========================================
  // RENDER
  // ==========================================

  return (
    <section className="si-module">

      {/* HEADER */}

      <div className="si-header">
        <div>
          <span className="si-eyebrow">
            ADVANCED SECURITY ANALYTICS
          </span>

          <h2>Security Intelligence Center</h2>

          <p>
            Analyze security events and identify suspicious activity
            using explainable detection rules.
          </p>
        </div>

        <button
          className="si-primary"
          onClick={runAnalysis}
          disabled={loading || !organizationId.trim()}
        >
          {loading ? "Analyzing..." : "Run Analysis"}
        </button>
      </div>

      {/* ORGANIZATION AND ANALYSIS CONTROLS */}

      <div className="si-controls">
        <label>
          Organization UUID

          <input
            value={organizationId}
            onChange={(e) => setOrganizationId(e.target.value)}
            placeholder="Enter organization UUID"
          />
        </label>

        <label>
          Analysis Period

          <select
            value={hours}
            onChange={(e) => setHours(e.target.value)}
          >
            <option value="1">Last 1 hour</option>
            <option value="6">Last 6 hours</option>
            <option value="12">Last 12 hours</option>
            <option value="24">Last 24 hours</option>
            <option value="48">Last 48 hours</option>
            <option value="72">Last 3 days</option>
            <option value="168">Last 7 days</option>
          </select>
        </label>

        <button onClick={saveOrganization}>
          Connect
        </button>
      </div>

      {/* ERROR MESSAGE */}

      {error && (
        <div className="si-error" role="alert">
          {error}
        </div>
      )}

      {/* INCIDENT SUCCESS MESSAGE */}

      {incidentMessage && (
        <div className="si-incident-success" role="status">
          {incidentMessage}
        </div>
      )}

      {/* LOADING */}

      {loading && (
        <div className="si-empty">
          Analyzing security events...
        </div>
      )}

      {/* ANALYSIS RESULTS */}

      {analysis && !loading && (
        <>

          {/* ANALYSIS STATUS */}

          <div className="si-status">
            <span>Analysis completed</span>

            <span>
              {new Date(analysis.analyzed_at).toLocaleString()}
            </span>
          </div>

          {/* METRICS */}

          <div className="si-metrics">

            <article>
              <span>Events Analyzed</span>
              <strong>{analysis.total_events_analyzed}</strong>
            </article>

            <article>
              <span>Total Findings</span>
              <strong>{analysis.total_findings}</strong>
            </article>

            <article className="si-critical">
              <span>Critical Findings</span>

              <strong>
                {analysis.severity_summary.CRITICAL ?? 0}
              </strong>
            </article>

            <article className="si-high">
              <span>High Findings</span>

              <strong>
                {analysis.severity_summary.HIGH ?? 0}
              </strong>
            </article>

            <article className="si-medium">
              <span>Medium Findings</span>

              <strong>
                {analysis.severity_summary.MEDIUM ?? 0}
              </strong>
            </article>

            <article className="si-low">
              <span>Low Findings</span>

              <strong>
                {analysis.severity_summary.LOW ?? 0}
              </strong>
            </article>

          </div>

          {/* DETECTION CATEGORIES */}

          <div className="si-panel">

            <h3>Detection Categories</h3>

            {Object.keys(categories).length === 0 ? (
              <p className="si-empty">
                No detection findings in this analysis period.
              </p>
            ) : (
              <div className="si-category-grid">

                {Object.entries(categories).map(
                  ([category, count]) => (
                    <div className="si-category" key={category}>
                      <span>
                        {category.replaceAll("_", " ")}
                      </span>

                      <strong>{count}</strong>
                    </div>
                  )
                )}

              </div>
            )}

          </div>

          {/* SECURITY FINDINGS */}

          <div className="si-panel">

            <div className="si-findings-heading">

              <div>
                <h3>Security Findings</h3>

                <p>
                  Findings generated from the analyzed event records.
                </p>
              </div>

              <select
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
              >
                <option value="ALL">All Severities</option>

                {severityLevels.map((level) => (
                  <option key={level}>{level}</option>
                ))}
              </select>

            </div>

            {filteredFindings.length === 0 ? (
              <div className="si-empty">
                No findings match this filter.
              </div>
            ) : (

              <div className="si-findings">

                {filteredFindings.map((finding, index) => {

                  const key = `${finding.title}-${index}`;

                  const isExpanded = expanded === key;

                  return (

                    <article
                      className="si-finding"
                      key={key}
                    >

                      {/* FINDING HEADER */}

                      <div className="si-finding-top">

                        <div>

                          <span
                            className={`si-badge ${finding.severity.toLowerCase()}`}
                          >
                            {finding.severity}
                          </span>

                          <span className="si-category-label">
                            {finding.category.replaceAll("_", " ")}
                          </span>

                          <h4>{finding.title}</h4>

                        </div>

                        <button
                          onClick={() =>
                            setExpanded(isExpanded ? null : key)
                          }
                        >
                          {isExpanded
                            ? "Hide Details"
                            : "View Details"}
                        </button>

                      </div>

                      {/* DESCRIPTION */}

                      <p>{finding.description}</p>

                      {/* EVIDENCE SUMMARY */}

                      <div className="si-evidence-summary">

                        <span>
                          Evidence events: {finding.evidence_count}
                        </span>

                        {finding.source_ip && (
                          <span>
                            Source IP: {finding.source_ip}
                          </span>
                        )}

                        {finding.asset_id && (
                          <span>
                            Asset: {finding.asset_id}
                          </span>
                        )}

                      </div>

                      {/* EXPANDED DETAILS */}

                      {isExpanded && (

                        <div className="si-expanded">

                          <h5>Investigation Recommendation</h5>

                          <p>{finding.recommendation}</p>

                          <h5>Evidence Event IDs</h5>

                          {finding.event_ids.length > 0 ? (

                            finding.event_ids.map((id) => (
                              <code key={id}>{id}</code>
                            ))

                          ) : (

                            <p>No evidence IDs available.</p>

                          )}

                          {/* CREATE INCIDENT */}

                          <div className="si-incident-action">

                            <button
                              className="si-primary"
                              disabled={creatingIncident !== null}
                              onClick={() =>
                                createIncidentFromFinding(finding)
                              }
                            >
                              {creatingIncident === finding.title
                                ? "Creating Incident..."
                                : "Create Incident from Finding"}
                            </button>

                          </div>

                        </div>

                      )}

                    </article>

                  );

                })}

              </div>

            )}

          </div>

          {/* DISCLAIMER */}

          <div className="si-disclaimer">
            Detection results are generated using rule-based analysis.
            Findings are investigation indicators, not proof of a
            confirmed cyberattack. Validate evidence before taking
            security actions.
          </div>

        </>
      )}

      {/* INITIAL STATE */}

      {!analysis && !loading && !error && (
        <div className="si-empty">
          Connect an organization and run security analysis.
        </div>
      )}

    </section>
  );
}