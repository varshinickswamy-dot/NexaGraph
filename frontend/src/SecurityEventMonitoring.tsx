import { useCallback, useEffect, useState } from "react";
import "./SecurityEventMonitoring.css";

const API =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

type SecurityEvent = {
  id: string;
  organization_id: string;
  asset_id?: string | null;
  asset_name?: string | null;
  event_type: string;
  severity: string;
  description?: string;
  source_ip?: string;
  destination_ip?: string;
  event_data?: Record<string, unknown>;
  occurred_at: string;
};

type Summary = {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  last_24_hours: number;
  event_types: {
    event_type: string;
    count: number;
  }[];
};

const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

const eventTypes = [
  "UNAUTHORIZED_ACCESS",
  "SUSPICIOUS_LOGIN",
  "NETWORK_ANOMALY",
  "VULNERABILITY_DETECTED",
  "POLICY_VIOLATION",
];

export default function SecurityEventMonitoring() {
  const [organizationId, setOrganizationId] = useState(
    () => localStorage.getItem("nexagraph-organization-id") || ""
  );

  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [selected, setSelected] = useState<SecurityEvent | null>(null);

  const [severityFilter, setSeverityFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [search, setSearch] = useState("");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const [showCreate, setShowCreate] = useState(false);

  const [form, setForm] = useState({
    asset_id: "",
    event_type: "SUSPICIOUS_LOGIN",
    severity: "MEDIUM",
    description: "",
    source_ip: "",
    destination_ip: "",
  });

  async function request(path: string, options: RequestInit = {}) {
    const response = await fetch(`${API}${path}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
      },
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new Error(
        typeof data.detail === "string"
          ? data.detail
          : `Request failed (${response.status})`
      );
    }

    return data;
  }

  const loadEvents = useCallback(async () => {
    if (!organizationId.trim()) return;

    setLoading(true);
    setError("");

    try {
      const params = new URLSearchParams({
        organization_id: organizationId.trim(),
        limit: "500",
        offset: "0",
      });

      if (severityFilter) {
        params.set("severity", severityFilter);
      }

      if (typeFilter) {
        params.set("event_type", typeFilter);
      }

      if (search.trim()) {
        params.set("search", search.trim());
      }

      const [eventData, summaryData] = await Promise.all([
        request(`/security-events?${params.toString()}`),
        request(
          `/security-events/summary?organization_id=${encodeURIComponent(
            organizationId.trim()
          )}`
        ),
      ]);

      setEvents(eventData);
      setSummary(summaryData);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to load security events."
      );
    } finally {
      setLoading(false);
    }
  }, [organizationId, severityFilter, typeFilter, search]);

  useEffect(() => {
    const timer = window.setTimeout(loadEvents, 300);
    return () => window.clearTimeout(timer);
  }, [loadEvents]);

  async function openEvent(id: string) {
    try {
      const data = await request(
        `/security-events/${id}?organization_id=${encodeURIComponent(
          organizationId.trim()
        )}`
      );

      setSelected(data);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Could not load event."
      );
    }
  }

  async function ingestEvent(e: React.FormEvent) {
    e.preventDefault();

    try {
      await request("/security-events", {
        method: "POST",
        body: JSON.stringify({
          organization_id: organizationId.trim(),
          asset_id: form.asset_id.trim() || null,
          event_type: form.event_type,
          severity: form.severity,
          description: form.description,
          source_ip: form.source_ip.trim() || null,
          destination_ip: form.destination_ip.trim() || null,
          event_data: {
            source: "NEXAGRAPH_DASHBOARD",
            ingestion_type: "MANUAL",
          },
        }),
      });

      setMessage("Security event ingested successfully.");

      setForm({
        asset_id: "",
        event_type: "SUSPICIOUS_LOGIN",
        severity: "MEDIUM",
        description: "",
        source_ip: "",
        destination_ip: "",
      });

      setShowCreate(false);
      await loadEvents();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Event ingestion failed."
      );
    }
  }

  function saveOrganization() {
    localStorage.setItem(
      "nexagraph-organization-id",
      organizationId.trim()
    );

    setMessage("Organization ID saved.");
    loadEvents();
  }

  return (
    <section className="security-events-module">
      <div className="sem-header">
        <div>
          <span className="sem-eyebrow">SECURITY OPERATIONS CENTER</span>
          <h2>Security Event Monitoring</h2>
          <p>
            Monitor, analyze and investigate organizational security events.
          </p>
        </div>

        <button
          className="sem-primary"
          onClick={() => setShowCreate(!showCreate)}
          disabled={!organizationId.trim()}
        >
          + Ingest Event
        </button>
      </div>

      <div className="sem-org">
        <label htmlFor="sem-org-id">Organization ID</label>

        <input
          id="sem-org-id"
          value={organizationId}
          onChange={(e) => setOrganizationId(e.target.value)}
          placeholder="Enter organization UUID"
        />

        <button onClick={saveOrganization}>Connect</button>
      </div>

      {error && (
        <div className="sem-alert sem-error" role="alert">
          {error}
          <button onClick={() => setError("")}>Dismiss</button>
        </div>
      )}

      {message && (
        <div className="sem-alert sem-success" role="status">
          {message}
          <button onClick={() => setMessage("")}>Dismiss</button>
        </div>
      )}

      {organizationId.trim() && (
        <>
          <div className="sem-metrics">
            <div className="sem-metric">
              <span>Total Events</span>
              <strong>{summary?.total ?? 0}</strong>
            </div>

            <div className="sem-metric critical">
              <span>Critical</span>
              <strong>{summary?.critical ?? 0}</strong>
            </div>

            <div className="sem-metric high">
              <span>High</span>
              <strong>{summary?.high ?? 0}</strong>
            </div>

            <div className="sem-metric medium">
              <span>Medium</span>
              <strong>{summary?.medium ?? 0}</strong>
            </div>

            <div className="sem-metric low">
              <span>Low</span>
              <strong>{summary?.low ?? 0}</strong>
            </div>

            <div className="sem-metric recent">
              <span>Last 24 Hours</span>
              <strong>{summary?.last_24_hours ?? 0}</strong>
            </div>
          </div>

          <div className="sem-panel">
            <div className="sem-panel-heading">
              <div>
                <h3>Event Distribution</h3>
                <p>Events grouped by detected event type.</p>
              </div>
            </div>

            <div className="sem-distribution">
              {summary?.event_types.map((item) => {
                const percentage =
                  summary.total > 0
                    ? (Number(item.count) / Number(summary.total)) * 100
                    : 0;

                return (
                  <div className="sem-distribution-item" key={item.event_type}>
                    <div className="sem-distribution-label">
                      <span>{item.event_type.replaceAll("_", " ")}</span>
                      <strong>{item.count}</strong>
                    </div>

                    <div className="sem-progress">
                      <div style={{ width: `${percentage}%` }} />
                    </div>
                  </div>
                );
              })}

              {summary?.event_types.length === 0 && (
                <p className="sem-empty">No event distribution available.</p>
              )}
            </div>
          </div>

          {showCreate && (
            <form className="sem-create-form" onSubmit={ingestEvent}>
              <h3>Ingest Security Event</h3>

              <label>
                Event Type
                <select
                  value={form.event_type}
                  onChange={(e) =>
                    setForm({ ...form, event_type: e.target.value })
                  }
                >
                  {eventTypes.map((type) => (
                    <option key={type} value={type}>
                      {type.replaceAll("_", " ")}
                    </option>
                  ))}
                </select>
              </label>

              <label>
                Severity
                <select
                  value={form.severity}
                  onChange={(e) =>
                    setForm({ ...form, severity: e.target.value })
                  }
                >
                  {severities.map((value) => (
                    <option key={value}>{value}</option>
                  ))}
                </select>
              </label>

              <label>
                Asset UUID (optional)
                <input
                  value={form.asset_id}
                  onChange={(e) =>
                    setForm({ ...form, asset_id: e.target.value })
                  }
                  placeholder="Existing asset UUID"
                />
              </label>

              <label>
                Source IP
                <input
                  value={form.source_ip}
                  onChange={(e) =>
                    setForm({ ...form, source_ip: e.target.value })
                  }
                  placeholder="192.168.1.10"
                />
              </label>

              <label>
                Destination IP
                <input
                  value={form.destination_ip}
                  onChange={(e) =>
                    setForm({ ...form, destination_ip: e.target.value })
                  }
                  placeholder="10.0.0.10"
                />
              </label>

              <label className="sem-full">
                Event Description
                <textarea
                  required
                  value={form.description}
                  onChange={(e) =>
                    setForm({ ...form, description: e.target.value })
                  }
                  placeholder="Describe the detected security event..."
                />
              </label>

              <div className="sem-actions">
                <button type="submit" className="sem-primary">
                  Submit Event
                </button>

                <button
                  type="button"
                  onClick={() => setShowCreate(false)}
                >
                  Cancel
                </button>
              </div>
            </form>
          )}

          <div className="sem-panel">
            <div className="sem-panel-heading">
              <div>
                <h3>Security Event Timeline</h3>
                <p>Latest recorded organizational security events.</p>
              </div>

              <button onClick={loadEvents}>↻ Refresh</button>
            </div>

            <div className="sem-filters">
              <input
                placeholder="Search event, description or IP..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />

              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
              >
                <option value="">All Severities</option>
                {severities.map((value) => (
                  <option key={value}>{value}</option>
                ))}
              </select>

              <select
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
              >
                <option value="">All Event Types</option>
                {eventTypes.map((value) => (
                  <option key={value}>{value}</option>
                ))}
              </select>
            </div>

            {loading ? (
              <p className="sem-empty">Loading security events...</p>
            ) : events.length === 0 ? (
              <p className="sem-empty">
                No security events found for these filters.
              </p>
            ) : (
              <div className="sem-table-wrap">
                <table className="sem-table">
                  <thead>
                    <tr>
                      <th>Event</th>
                      <th>Severity</th>
                      <th>Asset</th>
                      <th>Source IP</th>
                      <th>Time</th>
                    </tr>
                  </thead>

                  <tbody>
                    {events.map((event) => (
                      <tr
                        key={event.id}
                        className={
                          selected?.id === event.id ? "selected" : ""
                        }
                        onClick={() => openEvent(event.id)}
                      >
                        <td>
                          <strong>
                            {event.event_type.replaceAll("_", " ")}
                          </strong>
                          <small>{event.description || "No description"}</small>
                        </td>

                        <td>
                          <span
                            className={`sem-badge ${event.severity.toLowerCase()}`}
                          >
                            {event.severity}
                          </span>
                        </td>

                        <td>{event.asset_name || "Unlinked"}</td>
                        <td>{event.source_ip || "—"}</td>

                        <td>
                          {new Date(event.occurred_at).toLocaleString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {selected && (
            <div className="sem-panel sem-details">
              <div className="sem-panel-heading">
                <h3>Event Investigation Details</h3>
                <button onClick={() => setSelected(null)}>Close</button>
              </div>

              <p><strong>Event ID:</strong> {selected.id}</p>
              <p><strong>Type:</strong> {selected.event_type}</p>
              <p><strong>Severity:</strong> {selected.severity}</p>
              <p><strong>Description:</strong> {selected.description || "N/A"}</p>
              <p><strong>Asset:</strong> {selected.asset_name || selected.asset_id || "Unlinked"}</p>
              <p><strong>Source IP:</strong> {selected.source_ip || "N/A"}</p>
              <p><strong>Destination IP:</strong> {selected.destination_ip || "N/A"}</p>
              <p>
                <strong>Occurred:</strong>{" "}
                {new Date(selected.occurred_at).toLocaleString()}
              </p>

              <h4>Event Metadata</h4>
              <pre>{JSON.stringify(selected.event_data || {}, null, 2)}</pre>
            </div>
          )}
        </>
      )}

      {!organizationId.trim() && (
        <div className="sem-empty">
          Enter your organization UUID and click Connect to view security events.
        </div>
      )}
    </section>
  );
}