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
  event_types?: { event_type?: string; count?: number }[];
};
type GraphData = { nodes?: unknown[]; edges?: unknown[] };
type SecurityEvent = { id?: string; event_type?: string; severity?: string; occurred_at?: string; created_at?: string };
type Finding = {
  finding_id?: string;
  graph_asset_id?: string;
  asset_name?: string;
  asset_type?: string | null;
  ip_address?: string | null;
  asset_criticality?: string | null;
  severity?: string;
  status?: string;
  cvss_score?: number | null;
};
type VulnerabilitySummary = {
  total_findings?: number;
  by_status?: Record<string, number>;
};

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
  const [recentEvents, setRecentEvents] = useState<SecurityEvent[]>([]);
  const [graph, setGraph] = useState<GraphData | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [vulnerabilitySummary, setVulnerabilitySummary] = useState<VulnerabilitySummary | null>(null);
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
      jobs.push(getJson<SecurityEvent[]>(`/security-events?organization_id=${encodeURIComponent(organizationId)}&limit=500&offset=0`)
        .then((data) => setRecentEvents(Array.isArray(data) ? data : []))
        .catch(() => { setRecentEvents([]); nextErrors.push("Recent security activity unavailable"); }));
    } else {
      setIncident(null);
      setEvents(null);
      setRecentEvents([]);
      nextErrors.push("Organization context is unavailable");
    }

    jobs.push(getJson<GraphData>("/graph")
      .then(setGraph).catch(() => { nextErrors.push("Asset graph unavailable"); }));
    jobs.push(getJson<{success?: boolean; findings?: Finding[]}>("/vulnerabilities?limit=500&offset=0")
      .then((data) => setFindings(Array.isArray(data.findings) ? data.findings : []))
      .catch(() => { nextErrors.push("Vulnerability findings unavailable"); }));
    jobs.push(getJson<VulnerabilitySummary>("/vulnerabilities/summary")
      .then(setVulnerabilitySummary)
      .catch(() => { setVulnerabilitySummary(null); nextErrors.push("Vulnerability summary unavailable"); }));
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
    ["OPEN", "IN_PROGRESS"].includes(String(item.status || "").toUpperCase())
  ), [findings]);
  const criticalFindings = activeFindings.filter((item) => String(item.severity || "").toUpperCase() === "CRITICAL").length;
  const assetRiskLeaders = useMemo(() => {
    const severityPoints: Record<string, number> = { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1 };
    const criticalityMultiplier: Record<string, number> = { LOW: 1, MEDIUM: 1.15, HIGH: 1.3, CRITICAL: 1.5 };
    const grouped = new Map<string, {
      id: string; name: string; type: string; ip: string; criticality: string;
      findings: number; critical: number; high: number; maxCvss: number; score: number;
    }>();
    activeFindings.forEach((finding) => {
      const id = finding.graph_asset_id || finding.asset_name || "unknown";
      const existing = grouped.get(id) || {
        id, name: finding.asset_name || "Unnamed asset", type: finding.asset_type || "Asset",
        ip: finding.ip_address || "", criticality: String(finding.asset_criticality || "LOW").toUpperCase(),
        findings: 0, critical: 0, high: 0, maxCvss: 0, score: 0,
      };
      const severity = String(finding.severity || "").toUpperCase();
      existing.findings += 1;
      if (severity === "CRITICAL") existing.critical += 1;
      if (severity === "HIGH") existing.high += 1;
      existing.maxCvss = Math.max(existing.maxCvss, Number(finding.cvss_score) || 0);
      existing.score += severityPoints[severity] || 0;
      grouped.set(id, existing);
    });
    return [...grouped.values()].map((asset) => ({
      ...asset,
      score: Math.min(100, Math.round(asset.score * (criticalityMultiplier[asset.criticality] || 1))),
    })).sort((a, b) => b.score - a.score || b.maxCvss - a.maxCvss || b.findings - a.findings).slice(0, 5);
  }, [activeFindings]);
  const activeVulnerabilityCount = vulnerabilitySummary?.by_status
    ? (Number(vulnerabilitySummary.by_status.OPEN) || 0) + (Number(vulnerabilitySummary.by_status.IN_PROGRESS) || 0)
    : activeFindings.length;
  const criticalIncidents = incident?.breakdown
    ? countActiveIncidentSeverity(incident.breakdown, "CRITICAL")
    : 0;
  const highIncidents = incident?.breakdown
    ? countActiveIncidentSeverity(incident.breakdown, "HIGH")
    : 0;
  const activeIncidentCount = incident?.breakdown
    ? countActiveIncidents(incident.breakdown)
    : incident ? Number(incident.total) || 0 : "—";
  const incidentAnalysis = useMemo(() => {
    const rows = incident?.breakdown ?? [];
    const statusCounts = new Map<string, number>();
    const severityCounts = new Map<string, number>();
    rows.forEach((row) => {
      const status = String(row.status || "UNKNOWN").toUpperCase();
      const severity = String(row.severity || "UNKNOWN").toUpperCase();
      const count = Number(row.count) || 0;
      statusCounts.set(status, (statusCounts.get(status) || 0) + count);
      severityCounts.set(severity, (severityCounts.get(severity) || 0) + count);
    });
    const total = rows.reduce((sum, row) => sum + (Number(row.count) || 0), 0);
    const resolved = [...statusCounts.entries()]
      .filter(([status]) => ["RESOLVED", "CLOSED"].includes(status))
      .reduce((sum, [, count]) => sum + count, 0);
    const statuses = [...statusCounts.entries()].sort((a, b) => b[1] - a[1]);
    const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((severity) => ({
      label: severity,
      count: severityCounts.get(severity) || 0,
    }));
    return { total, resolved, resolutionRate: total ? Math.round((resolved / total) * 100) : 0, statuses, severities };
  }, [incident]);
  const criticalEvents = Number(events?.critical) || 0;
  const highEvents = Number(events?.high) || 0;
  const priorityCount = criticalFindings + criticalIncidents + criticalEvents + highIncidents + highEvents;
  const activityTimeline = useMemo(() => {
    const days = Array.from({ length: 7 }, (_, index) => {
      const date = new Date();
      date.setHours(0, 0, 0, 0);
      date.setDate(date.getDate() - (6 - index));
      const key = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
      return { key, label: date.toLocaleDateString(undefined, { weekday: "short" }), count: 0, critical: 0 };
    });
    const byDate = new Map(days.map((day) => [day.key, day]));
    recentEvents.forEach((event) => {
      const rawDate = event.occurred_at || event.created_at;
      if (!rawDate) return;
      const date = new Date(rawDate);
      if (Number.isNaN(date.getTime())) return;
      const key = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
      const day = byDate.get(key);
      if (!day) return;
      day.count += 1;
      if (String(event.severity || "").toUpperCase() === "CRITICAL") day.critical += 1;
    });
    return days;
  }, [recentEvents]);

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
        <article className="soc-kpi soc-kpi-risk"><span>Active vulnerabilities</span><strong>{activeVulnerabilityCount}</strong><small>{criticalFindings} critical findings in latest 500 records</small></article>
      </div>

      <div className="soc-lower-grid">
        <article className="soc-panel">
          <div className="soc-panel-title"><h3>Priority signals</h3><span>{priorityCount} high-priority items</span></div>
          <div className="soc-signal-list">
            <div><span className="soc-severity critical">Critical vulnerabilities</span><strong>{criticalFindings}</strong></div>
            <div><span className="soc-severity critical">Critical incidents</span><strong>{criticalIncidents}</strong></div>
            <div><span className="soc-severity high">High incidents</span><strong>{highIncidents}</strong></div>
            <div><span className="soc-severity critical">Critical security events · all time</span><strong>{criticalEvents}</strong></div>
            <div><span className="soc-severity high">High security events · all time</span><strong>{highEvents}</strong></div>
          </div>
          <p className="soc-footnote">Counts are sourced from existing module APIs; the same underlying issue may appear in more than one category.</p>
        </article>
        <article className="soc-panel soc-asset-risk">
          <div className="soc-panel-title"><h3>Asset risk intelligence</h3><span>Top affected assets · latest 500 findings</span></div>
          {assetRiskLeaders.length ? (
            <div className="soc-risk-assets">
              {assetRiskLeaders.map((asset, index) => (
                <div className="soc-risk-asset" key={asset.id}>
                  <div className="soc-risk-rank">{index + 1}</div>
                  <div className="soc-risk-main">
                    <strong>{asset.name}</strong>
                    <span>{asset.type} · {asset.criticality} criticality{asset.ip ? ` · ${asset.ip}` : ""}</span>
                    <small>{asset.critical} critical · {asset.high} high · {asset.findings} active findings{asset.maxCvss ? ` · CVSS ${asset.maxCvss.toFixed(1)} max` : ""}</small>
                  </div>
                  <div className="soc-risk-score" aria-label={`Heuristic risk score ${asset.score} out of 100`}>
                    <strong>{asset.score}</strong><span>/100</span>
                  </div>
                </div>
              ))}
            </div>
          ) : <p className="soc-footnote">No active asset findings are available in the latest results.</p>}
          <p className="soc-footnote">Triage score uses the same heuristic as Asset Vulnerability: severity points multiplied by asset criticality. It is a prioritization aid, not a CVSS score or certified risk rating.</p>
        </article>
        <article className="soc-panel soc-incident-analysis">
          <div className="soc-panel-title"><h3>Incident analysis</h3><span>Live status and severity distribution</span></div>
          {incident ? (
            <>
              <div className="soc-resolution-summary">
                <div><strong>{incidentAnalysis.resolutionRate}%</strong><span>Resolved / closed</span></div>
                <div><strong>{incidentAnalysis.resolved}</strong><span>Of {incidentAnalysis.total} total incidents</span></div>
              </div>
              <div className="soc-analysis-columns">
                <div className="soc-analysis-group">
                  <h4>By status</h4>
                  {incidentAnalysis.statuses.length ? incidentAnalysis.statuses.map(([status, count]) => (
                    <div className="soc-analysis-row" key={status}>
                      <span>{status.replaceAll("_", " ")}</span><strong>{count}</strong>
                      <div className="soc-analysis-track"><i style={{ width: `${incidentAnalysis.total ? (count / incidentAnalysis.total) * 100 : 0}%` }} /></div>
                    </div>
                  )) : <p className="soc-footnote">No incidents recorded.</p>}
                </div>
                <div className="soc-analysis-group">
                  <h4>By severity</h4>
                  {incidentAnalysis.severities.map((item) => (
                    <div className="soc-analysis-row" key={item.label}>
                      <span>{item.label}</span><strong>{item.count}</strong>
                      <div className="soc-analysis-track"><i className={item.label.toLowerCase()} style={{ width: `${incidentAnalysis.total ? (item.count / incidentAnalysis.total) * 100 : 0}%` }} /></div>
                    </div>
                  ))}
                </div>
              </div>
              <p className="soc-footnote">Resolution rate is based on incidents currently marked RESOLVED or CLOSED. This is a current-state snapshot, not a time-based trend.</p>
            </>
          ) : <p className="soc-footnote">Incident analysis is unavailable until the incident summary loads.</p>}
        </article>
        <article className="soc-panel">
          <div className="soc-panel-title"><h3>Security event types</h3><span>All recorded events</span></div>
          {events?.event_types?.length ? (
            <div className="soc-event-types">
              {events.event_types.slice(0, 5).map((item) => {
                const count = Number(item.count) || 0;
                const maximum = Math.max(...events.event_types!.map((entry) => Number(entry.count) || 0), 1);
                return (
                  <div className="soc-event-type" key={item.event_type || "unknown"}>
                    <div><span>{(item.event_type || "Unknown").replaceAll("_", " ")}</span><strong>{count}</strong></div>
                    <div className="soc-event-track"><span style={{ width: `${Math.max(0, Math.min(100, (count / maximum) * 100))}%` }} /></div>
                  </div>
                );
              })}
            </div>
          ) : <p className="soc-footnote">No event-type breakdown is available yet.</p>}
        </article>
        <article className="soc-panel soc-timeline-panel">
          <div className="soc-panel-title"><h3>Threat activity timeline</h3><span>Last 7 days · latest 500 events</span></div>
          <div className="soc-timeline" role="img" aria-label="Security events recorded each day over the last seven days">
            {activityTimeline.map((day) => {
              const peak = Math.max(...activityTimeline.map((item) => item.count), 1);
              return (
                <div className="soc-timeline-day" key={day.key}>
                  <div className="soc-timeline-bar-wrap">
                    <span className="soc-timeline-bar" style={{ height: `${Math.max(day.count ? 8 : 2, (day.count / peak) * 100)}%` }} />
                    {day.critical > 0 && <i title={`${day.critical} critical events`} />}
                  </div>
                  <strong>{day.count}</strong>
                  <small>{day.label}</small>
                </div>
              );
            })}
          </div>
          <p className="soc-footnote">Daily counts are calculated from the existing security-event records returned by your organization API. This is activity volume, not a detection-rate score.</p>
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
