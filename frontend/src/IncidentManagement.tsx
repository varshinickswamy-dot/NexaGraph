import { useCallback, useEffect, useState } from "react";
import "./IncidentManagement.css";

const API =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

type Incident = {
  id: string;
  organization_id: string;
  title: string;
  description?: string;
  severity: string;
  status: string;
  created_at: string;
  updated_at?: string;
  assignments?: {
    id: string;
    full_name: string;
    email: string;
    assigned_at: string;
  }[];
  notes?: {
    id: string;
    user_id?: string;
    note: string;
    created_at: string;
  }[];
};

type Summary = {
  total: number;
  breakdown: {
    status: string;
    severity: string;
    count: number;
  }[];
};

const statuses = [
  "NEW",
  "INVESTIGATING",
  "CONTAINED",
  "RESOLVED",
  "CLOSED",
];

const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export default function IncidentManagement() {
  const [organizationId, setOrganizationId] = useState(
    () => localStorage.getItem("nexagraph-organization-id") || ""
  );

  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [selected, setSelected] = useState<Incident | null>(null);

  const [statusFilter, setStatusFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [search, setSearch] = useState("");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const [showCreate, setShowCreate] = useState(false);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState("MEDIUM");

  const [note, setNote] = useState("");
  const [noteUserId, setNoteUserId] = useState("");
  const [assignUserId, setAssignUserId] = useState("");

  const request = async (
    path: string,
    options: RequestInit = {}
  ) => {
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
  };

  const loadData = useCallback(async () => {
    if (!organizationId.trim()) return;

    setLoading(true);
    setError("");

    try {
      const params = new URLSearchParams({
        organization_id: organizationId.trim(),
      });

      if (statusFilter) params.set("status", statusFilter);
      if (severityFilter) params.set("severity", severityFilter);
      if (search.trim()) params.set("search", search.trim());

      const [list, totals] = await Promise.all([
        request(`/incidents?${params.toString()}`),
        request(
          `/incidents/summary?organization_id=${encodeURIComponent(
            organizationId.trim()
          )}`
        ),
      ]);

      setIncidents(list);
      setSummary(totals);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Unable to load incidents."
      );
    } finally {
      setLoading(false);
    }
  }, [organizationId, statusFilter, severityFilter, search]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      loadData();
    }, 300);

    return () => window.clearTimeout(timer);
  }, [loadData]);

  async function openIncident(id: string) {
    try {
      const data = await request(
        `/incidents/${id}?organization_id=${encodeURIComponent(
          organizationId.trim()
        )}`
      );
      setSelected(data);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Could not load incident."
      );
    }
  }

  async function createIncident(e: React.FormEvent) {
    e.preventDefault();

    try {
      await request("/incidents", {
        method: "POST",
        body: JSON.stringify({
          organization_id: organizationId.trim(),
          title,
          description,
          severity,
        }),
      });

      setMessage("Incident created successfully.");
      setTitle("");
      setDescription("");
      setSeverity("MEDIUM");
      setShowCreate(false);
      await loadData();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Incident creation failed."
      );
    }
  }

  async function updateIncident(
    field: "status" | "severity",
    value: string
  ) {
    if (!selected) return;

    try {
      await request(
        `/incidents/${selected.id}?organization_id=${encodeURIComponent(
          organizationId.trim()
        )}`,
        {
          method: "PATCH",
          body: JSON.stringify({ [field]: value }),
        }
      );

      setMessage("Incident updated successfully.");
      await openIncident(selected.id);
      await loadData();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Incident update failed."
      );
    }
  }

  async function assignIncident() {
    if (!selected || !assignUserId.trim()) return;

    try {
      await request(
        `/incidents/${selected.id}/assign?organization_id=${encodeURIComponent(
          organizationId.trim()
        )}`,
        {
          method: "POST",
          body: JSON.stringify({
            user_id: assignUserId.trim(),
          }),
        }
      );

      setAssignUserId("");
      setMessage("User assigned successfully.");
      await openIncident(selected.id);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Assignment failed."
      );
    }
  }

  async function removeAssignment(userId: string) {
    if (!selected) return;

    try {
      await request(
        `/incidents/${selected.id}/assign/${userId}?organization_id=${encodeURIComponent(
          organizationId.trim()
        )}`,
        { method: "DELETE" }
      );

      setMessage("Assignment removed.");
      await openIncident(selected.id);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Could not remove assignment."
      );
    }
  }

  async function addNote(e: React.FormEvent) {
    e.preventDefault();
    if (!selected || !note.trim()) return;

    try {
      await request(
        `/incidents/${selected.id}/notes?organization_id=${encodeURIComponent(
          organizationId.trim()
        )}`,
        {
          method: "POST",
          body: JSON.stringify({
            note,
            user_id: noteUserId.trim() || null,
          }),
        }
      );

      setNote("");
      setMessage("Investigation note added.");
      await openIncident(selected.id);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Could not add note."
      );
    }
  }

  const countByStatus = (status: string) =>
    summary?.breakdown
      .filter((item) => item.status === status)
      .reduce((total, item) => total + item.count, 0) ?? 0;

  const countBySeverity = (value: string) =>
    summary?.breakdown
      .filter((item) => item.severity === value)
      .reduce((total, item) => total + item.count, 0) ?? 0;

  function saveOrganization() {
    localStorage.setItem(
      "nexagraph-organization-id",
      organizationId.trim()
    );
    setMessage("Organization ID saved.");
    loadData();
  }

  return (
    <section className="incident-module">
      <div className="incident-heading">
        <div>
          <span className="incident-eyebrow">SECURITY OPERATIONS</span>
          <h2>Incident Management</h2>
          <p>Monitor, investigate and manage security incidents.</p>
        </div>

        <button
          className="incident-primary"
          onClick={() => setShowCreate(!showCreate)}
          disabled={!organizationId.trim()}
        >
          + Create Incident
        </button>
      </div>

      <div className="incident-org">
        <label htmlFor="incident-org-id">Organization ID</label>
        <input
          id="incident-org-id"
          value={organizationId}
          onChange={(e) => setOrganizationId(e.target.value)}
          placeholder="Enter your PostgreSQL organization UUID"
        />
        <button onClick={saveOrganization}>Connect</button>
      </div>

      {error && (
        <div className="incident-alert incident-error" role="alert">
          {error}
          <button onClick={() => setError("")}>Dismiss</button>
        </div>
      )}

      {message && (
        <div className="incident-alert incident-success" role="status">
          {message}
          <button onClick={() => setMessage("")}>Dismiss</button>
        </div>
      )}

      {organizationId.trim() && (
        <>
          <div className="incident-metrics">
            <div className="incident-metric">
              <span>Total Incidents</span>
              <strong>{summary?.total ?? 0}</strong>
            </div>

            <div className="incident-metric critical">
              <span>Critical</span>
              <strong>{countBySeverity("CRITICAL")}</strong>
            </div>

            <div className="incident-metric high">
              <span>High</span>
              <strong>{countBySeverity("HIGH")}</strong>
            </div>

            <div className="incident-metric open">
              <span>Open</span>
              <strong>
                {countByStatus("NEW") +
                  countByStatus("INVESTIGATING") +
                  countByStatus("CONTAINED")}
              </strong>
            </div>

            <div className="incident-metric resolved">
              <span>Resolved</span>
              <strong>
                {countByStatus("RESOLVED") +
                  countByStatus("CLOSED")}
              </strong>
            </div>
          </div>

          {showCreate && (
            <form
              className="incident-create-form"
              onSubmit={createIncident}
            >
              <h3>Create Security Incident</h3>

              <label>
                Incident Title
                <input
                  required
                  minLength={3}
                  maxLength={250}
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder="Enter incident title"
                />
              </label>

              <label>
                Description
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Describe the security incident"
                />
              </label>

              <label>
                Severity
                <select
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value)}
                >
                  {severities.map((value) => (
                    <option key={value}>{value}</option>
                  ))}
                </select>
              </label>

              <div className="incident-actions">
                <button type="submit" className="incident-primary">
                  Create Incident
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

          <div className="incident-content">
            <div className="incident-list-panel">
              <div className="incident-list-heading">
                <h3>Security Incidents</h3>
                <button onClick={loadData}>↻ Refresh</button>
              </div>

              <div className="incident-filters">
                <input
                  placeholder="Search incidents..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />

                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                >
                  <option value="">All Statuses</option>
                  {statuses.map((value) => (
                    <option key={value}>{value}</option>
                  ))}
                </select>

                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                >
                  <option value="">All Severities</option>
                  {severities.map((value) => (
                    <option key={value}>{value}</option>
                  ))}
                </select>
              </div>

              {loading ? (
                <p className="incident-empty">Loading incidents...</p>
              ) : incidents.length === 0 ? (
                <p className="incident-empty">
                  No incidents found for these filters.
                </p>
              ) : (
                <div className="incident-table-wrap">
                  <table className="incident-table">
                    <thead>
                      <tr>
                        <th>Incident</th>
                        <th>Severity</th>
                        <th>Status</th>
                        <th>Created</th>
                      </tr>
                    </thead>

                    <tbody>
                      {incidents.map((item) => (
                        <tr
                          key={item.id}
                          className={
                            selected?.id === item.id ? "selected" : ""
                          }
                          onClick={() => openIncident(item.id)}
                        >
                          <td>
                            <strong>{item.title}</strong>
                            <small>{item.id}</small>
                          </td>
                          <td>
                            <span
                              className={`incident-badge ${item.severity.toLowerCase()}`}
                            >
                              {item.severity}
                            </span>
                          </td>
                          <td>{item.status}</td>
                          <td>
                            {new Date(item.created_at).toLocaleDateString()}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="incident-detail-panel">
              {!selected ? (
                <div className="incident-empty">
                  <h3>Incident Investigation</h3>
                  <p>Select an incident to view its details.</p>
                </div>
              ) : (
                <>
                  <span className="incident-eyebrow">
                    INCIDENT DETAILS
                  </span>

                  <h3>{selected.title}</h3>
                  <small className="incident-id">{selected.id}</small>

                  <p>
                    {selected.description || "No description provided."}
                  </p>

                  <div className="incident-edit-fields">
                    <label>
                      Severity
                      <select
                        value={selected.severity}
                        onChange={(e) =>
                          updateIncident("severity", e.target.value)
                        }
                      >
                        {severities.map((value) => (
                          <option key={value}>{value}</option>
                        ))}
                      </select>
                    </label>

                    <label>
                      Status
                      <select
                        value={selected.status}
                        onChange={(e) =>
                          updateIncident("status", e.target.value)
                        }
                      >
                        {statuses.map((value) => (
                          <option key={value}>{value}</option>
                        ))}
                      </select>
                    </label>
                  </div>

                  <h4>Assigned Responders</h4>

                  <div className="incident-assignment">
                    <input
                      placeholder="Enter active user UUID"
                      value={assignUserId}
                      onChange={(e) => setAssignUserId(e.target.value)}
                    />
                    <button onClick={assignIncident}>Assign</button>
                  </div>

                  {selected.assignments?.map((person) => (
                    <div
                      className="incident-person"
                      key={person.id}
                    >
                      <div>
                        <strong>{person.full_name}</strong>
                        <small>{person.email}</small>
                      </div>
                      <button
                        onClick={() => removeAssignment(person.id)}
                      >
                        Remove
                      </button>
                    </div>
                  ))}

                  <h4>Investigation Notes</h4>

                  <form className="incident-note-form" onSubmit={addNote}>
                    <textarea
                      required
                      value={note}
                      onChange={(e) => setNote(e.target.value)}
                      placeholder="Record investigation findings..."
                    />

                    <input
                      placeholder="Responder UUID (optional)"
                      value={noteUserId}
                      onChange={(e) => setNoteUserId(e.target.value)}
                    />

                    <button type="submit" className="incident-primary">
                      Add Investigation Note
                    </button>
                  </form>

                  <div className="incident-notes">
                    {selected.notes?.map((item) => (
                      <article key={item.id}>
                        <p>{item.note}</p>
                        <small>
                          {new Date(item.created_at).toLocaleString()}
                        </small>
                      </article>
                    ))}

                    {selected.notes?.length === 0 && (
                      <p className="incident-empty">
                        No investigation notes yet.
                      </p>
                    )}
                  </div>
                </>
              )}
            </div>
          </div>
        </>
      )}

      {!organizationId.trim() && (
        <div className="incident-empty">
          Enter your organization UUID and select Connect to load incidents.
        </div>
      )}
    </section>
  );
}