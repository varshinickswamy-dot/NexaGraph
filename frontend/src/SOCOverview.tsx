import { useCallback, useEffect, useMemo, useState } from "react";
import { API_BASE_URL, authenticatedFetch } from "./api";
import "./SOCOverview.css";

type Props = { organizationId: string | null };

type IncidentSummary = {
  total?: number;
  breakdown?: { status?: string; severity?: string; count?: number }[];
};
type EventSummary = {
  total?: number;
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  last_24_hours?: number;
};
type GraphData = { nodes?: unknown[]; edges?: unknown[] };
type Finding = { severity?: string; status?: string };

async function getJson<T>(path: string): Promise<T> {
  const response = await authenticatedFetch(path);
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json() as Promise<T>;
}

function isActiveStatus(status?: string) {
  return !["RESOLVED", "CLOSED"].includes(String(status || "").toUpperCase());
}

function countActiveIncidents(rows: { status?: string; count?: number }[]) {
  return rows.filter((row) => isActiveStatus(row.status))
    .reduce((total, row) => total + (Number(row.count) || 0), 0);
}

function countActiveIncidentSeverity(
  rows: { status?: string; severity?: string; count?: number }[],
  severity: string,
) {
  return rows.filter((row) =>
    isActiveStatus(row.status) && String(row.severity || "").toUpperCase() === severity
  ).reduce((total, row) => total + (Number(row.count) || 0), 0);
}

export default function SOCOverview({ organizationId }: Props) {
  const [incident, setIncident] = useState<IncidentSummary | null>(null);
  const [events, setEvents] = useState<EventSummary | null>(null);
  const [graph, setGraph] = useState<GraphData | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [mlAvailable, setMlAvailable] = useState<boolean | null>(null);
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);
  const [loading, setLoading] = useState(true);
  const [errors, setErrors] = useState<string[]>([]);

  const refresh = useCallback(async () => {
    setLoading(true);
    const nextErrors: string[] = [];
    const jobs: Promise<void>[] = [];

    if (organizationId) {
      jobs.push(getJson<IncidentSummary>(`/incidents/summary?organization_id=${encodeURIComponent(organizationId)}`)
        .then(setIncident).catch(() => { nextErrors.push("Incident summary unavailable"); }));
      jobs.push(getJson<EventSummary>(`/security-events/summary?organization_id=${encodeURIComponent(organizationId)}`)
        .then(setEvents).catch(() => { nextErrors.push("Security-event summary unavailable"); }));
    } else {
      setIncident(null);
      setEvents(null);
      nextErrors.push("Organization context is unavailable");
    }

    jobs.push(getJson<GraphData>("/graph")
      .then(setGraph).catch(() => { nextErrors.push("Asset graph unavailable"); }));
    jobs.push(getJson<{success?: boolean; findings?: Finding[]}>("/vulnerabilities?limit=500&offset=0")
      .then((data) => setFindings(Array.isArray(data.findings) ? data.findings : []))
      .catch(() => { nextErrors.push("Vulnerability summary unavailable"); }));
    jobs.push(fetch(`${API_BASE_URL}/api/ml/status`)
      .then(async (response) => {
        if (!response.ok) throw new Error("ML status unavailable");
        const data = await response.json();
        setMlAvailable(data.available === true);
      }).catch(() => { setMlAvailable(false); nextErrors.push("AI model status unavailable"); }));

    await Promise.all(jobs);
    setErrors(nextErrors);
    setUpdatedAt(new Date());
    setLoading(false);
  }, [organizationId]);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 60000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const activeFindings = useMemo(() => findings.filter((item) =>
    ["OPEN", "IN_PROGRESS"].includes(String(item.status).toUpperCase())
  ), [findings]);
  const criticalFindings = activeFindings.filter((item) => String(item.severity).toUpperCase() === "CRITICAL").length;
  const criticalIncidents = incident?.breakdown
    ? countActiveIncidentSeverity(incident.breakdown, "CRITICAL")
    : 0;
  const highIncidents = incident?.breakdown
    ? countActiveIncidentSeverity(incident.breakdown, "HIGH")
    : 0;
  const activeIncidentCount = incident?.breakdown
    ? countActiveIncidents(incident.breakdown)
    : incident ? Number(incident.total) || 0 : "—";
  const criticalEvents = Number(events?.critical) || 0;
  const highEvents = Number(events?.high) || 0;
  const priorityCount = criticalFindings + criticalIncidents + criticalEvents + highIncidents + highEvents;

  return (
    <section className="soc-overview nx-nav-section" id="soc-overview">
      <div className="soc-heading">
        <div>
          <span className="soc-eyebrow">SECURITY OPERATIONS CENTRE</span>
          <h2>Operations Overview</h2>
          <p>Consolidated operational signals from your connected NexaGraph modules.</p>
        </div>
        <button type="button" onClick={() => void refresh()} disabled={loading}>
          {loading ? "Refreshing…" : "↻ Refresh"}
        </button>
      </div>

      <div className="soc-statusline">
        <span className={mlAvailable ? "soc-dot is-live" : "soc-dot"} />
        AI model {mlAvailable === null ? "Checking" : mlAvailable ? "Available" : "Unavailable"}
        <span className="soc-updated">{updatedAt ? `Updated ${updatedAt.toLocaleTimeString()}` : "Waiting for data"}</span>
      </div>

      <div className="soc-kpi-grid">
        <article className="soc-kpi"><span>Registered assets</span><strong>{graph?.nodes?.length ?? "—"}</strong><small>From network graph</small></article>
        <article className="soc-kpi"><span>Active incidents</span><strong>{activeIncidentCount}</strong><small>{criticalIncidents} critical · {highIncidents} high (active)</small></article>
        <article className="soc-kpi"><span>Security events · 24h</span><strong>{events?.last_24_hours ?? "—"}</strong><small>{events?.total ?? 0} recorded events · all time</small></article>
        <article className="soc-kpi soc-kpi-risk"><span>Active vulnerabilities</span><strong>{activeFindings.length}</strong><small>{criticalFindings} critical findings</small></article>
      </div>

      <div className="soc-lower-grid">
        <article className="soc-panel">
          <div className="soc-panel-title"><h3>Priority signals</h3><span>{priorityCount} high-priority items</span></div>
          <div className="soc-signal-list">
            <div><span className="soc-severity critical">Critical vulnerabilities</span><strong>{criticalFindings}</strong></div>
            <div><span className="soc-severity critical">Critical incidents</span><strong>{criticalIncidents}</strong></div>
            <div><span className="soc-severity high">High incidents</span><strong>{highIncidents}</strong></div>
            <div><span className="soc-severity critical">Critical security events</span><strong>{criticalEvents}</strong></div>
            <div><span className="soc-severity high">High security events</span><strong>{highEvents}</strong></div>
          </div>
          <p className="soc-footnote">Counts are sourced from existing module APIs; the same underlying issue may appear in more than one category.</p>
        </article>
        <article className="soc-panel">
          <div className="soc-panel-title"><h3>Workspace health</h3><span>Live service checks</span></div>
          <div className="soc-health-list">
            <div><span>Network asset graph</span><b className={graph ? "ok" : "unknown"}>{graph ? "Connected" : "Unavailable"}</b></div>
            <div><span>Incident management</span><b className={incident ? "ok" : "unknown"}>{incident ? "Connected" : "Unavailable"}</b></div>
            <div><span>Security event monitoring</span><b className={events ? "ok" : "unknown"}>{events ? "Connected" : "Unavailable"}</b></div>
            <div><span>Vulnerability intelligence</span><b className={findings.length || !errors.some((e) => e.includes("Vulnerability")) ? "ok" : "unknown"}>{errors.some((e) => e.includes("Vulnerability")) ? "Unavailable" : "Connected"}</b></div>
            <div><span>ML detection service</span><b className={mlAvailable ? "ok" : "unknown"}>{mlAvailable ? "Available" : mlAvailable === null ? "Checking" : "Unavailable"}</b></div>
          </div>
        </article>
      </div>
      {errors.length > 0 && <p className="soc-warning" role="status">Some modules could not be reached: {errors.join(" · ")}. Other available metrics are still displayed.</p>}
      {!organizationId && <p className="soc-warning">Sign in to an organization account to load incident and event summaries.</p>}
    </section>
  );
}
