import NetworkTopology from "./NetworkTopology";
import VulnerabilityIntelligence from "./VulnerabilityIntelligence";
import AssetVulnerabilityPanel from "./AssetVulnerabilityPanel";
import { useCallback, useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import cytoscape from "cytoscape";
import "./App.css";
import "./theme-overrides.css";
import IncidentManagement from "./IncidentManagement";
import SecurityEventMonitoring from "./SecurityEventMonitoring";
import SecurityIntelligence from "./SecurityIntelligence";
import TeamManagement from "./TeamManagement";
const API_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";
const AUTH_TOKEN_KEY = "nexagraph-access-token";
import "./AuthScreen.css";
import AuthScreen from "./AuthScreen";
import MLDetectionDashboard from "./MLDetectionDashboard";

type AuthUser = {
  id: string;
  full_name: string;
  email: string;
  organization_id: string | null;
  role: string;
};

type NodeData = {
  id: string;
  name: string;
  type: string;
  ip: string;
  criticality: string;
  exposed: string;
  compromised: string;
  environment?: string;
};

type EdgeData = {
  source: string;
  target: string;
  relationship: string;
  protocol: string | null;
};

type GraphResponse = {
  nodes: NodeData[];
  edges: EdgeData[];
};


type AttackPath = {
  path: NodeData[];
  connections: EdgeData[];
  risk_score: number;
  risk_level: "Low" | "Medium" | "High" | "Critical";
};

type AttackPathResponse = {
  paths: AttackPath[];
  total_paths: number;
  max_paths_reached: boolean;
  scoring_note?: string;
};
type RemediationType = "isolate-asset" | "remove-connection";


type FullSimulationResponse = {
  action_type: RemediationType;
  simulated_only: boolean;
  database_modified: boolean;
  before: AttackPathResponse;
  after: AttackPathResponse;
  paths_eliminated: number;
  highest_risk_before: number;
  highest_risk_after: number;
  risk_score_reduction: number;
  scoring_note: string;
};


type AssetForm = Omit<NodeData, never>;

type ConnectionForm = {
  source: string;
  target: string;
  relationship: string;
  protocol: string;
};

const emptyAssetForm: AssetForm = {
  id: "",
  name: "",
  type: "Server",
  ip: "",
  criticality: "Medium",
  exposed: "No",
  compromised: "No",
};

const emptyConnectionForm: ConnectionForm = {
  source: "",
  target: "",
  relationship: "CONNECTS",
  protocol: "TCP",
};

async function apiRequest(path: string, options: RequestInit = {}) {
  const headers = new Headers(options.headers);
  const token = window.localStorage.getItem(AUTH_TOKEN_KEY);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const response = await fetch(`${API_URL}${path}`, { ...options, headers });
  const result = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      typeof result.detail === "string"
        ? result.detail
        : `Request failed (${response.status})`
    );
  }

  return result;
}

type AppTheme = "dark" | "light";

function App() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [commandOpen, setCommandOpen] = useState(false);
  const [commandQuery, setCommandQuery] = useState("");
  const [theme, setTheme] = useState<AppTheme>(() => {
    const saved = window.localStorage.getItem("nexagraph-theme");
    return saved === "light" ? "light" : "dark";
  });

  useEffect(() => {
    function handleGlobalShortcut(event: KeyboardEvent) {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setCommandOpen((open) => !open);
        setCommandQuery("");
      }
      if (event.key === "Escape") {
        setCommandOpen(false);
        setSidebarOpen(false);
      }
    }
    window.addEventListener("keydown", handleGlobalShortcut);
    return () => window.removeEventListener("keydown", handleGlobalShortcut);
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    window.localStorage.setItem("nexagraph-theme", theme);
  }, [theme]);

  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [authUser, setAuthUser] = useState<AuthUser | null>(null);
  const [authChecking, setAuthChecking] = useState(true);

  useEffect(() => {
    let active = true;
    async function restoreSession() {
      const savedToken = window.localStorage.getItem(AUTH_TOKEN_KEY);
      if (!savedToken) { if (active) setAuthChecking(false); return; }
      try {
        const response = await fetch(`${API_URL}/auth/me`, { headers: { Authorization: `Bearer ${savedToken}` } });
        const result = await response.json().catch(() => ({}));
        if (!response.ok || !result.id || !result.email) throw new Error("Session is invalid");
        if (active) { setAccessToken(savedToken); setAuthUser(result as AuthUser); }
      } catch {
        window.localStorage.removeItem(AUTH_TOKEN_KEY);
        if (active) { setAccessToken(null); setAuthUser(null); }
      } finally { if (active) setAuthChecking(false); }
    }
    void restoreSession();
    return () => { active = false; };
  }, []);

  function handleAuthenticated(token: string, user: AuthUser) {
    window.localStorage.setItem(AUTH_TOKEN_KEY, token);
    setAccessToken(token);
    setAuthUser(user);
  }

  async function handleLogout() {
    const token = accessToken;
    try {
      if (token) await fetch(`${API_URL}/auth/logout`, { method: "POST", headers: { Authorization: `Bearer ${token}` } });
    } catch (err) { console.warn("Logout request failed; clearing local session.", err); }
    finally {
      window.localStorage.removeItem(AUTH_TOKEN_KEY);
      setAccessToken(null); setAuthUser(null); setGraph(null); setSelectedNode(null);
      setAttackData(null); setSimulationResult(null); setLoading(true); setError("");
    }
  }

  const graphRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  const [graph, setGraph] = useState<GraphResponse | null>(null);
  const [selectedNode, setSelectedNode] = useState<NodeData | null>(null);
  const [search, setSearch] = useState("");
  const [criticalityFilter, setCriticalityFilter] = useState("All");
  const [typeFilter, setTypeFilter] = useState("All");
  const [environmentFilter, setEnvironmentFilter] = useState("All");
  const [relationshipFilter, setRelationshipFilter] = useState("All");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [assetForm, setAssetForm] = useState<AssetForm>(emptyAssetForm);
  const [connectionForm, setConnectionForm] =
    useState<ConnectionForm>(emptyConnectionForm);

  const [editing, setEditing] = useState(false);
  const [editForm, setEditForm] = useState<AssetForm>(emptyAssetForm);
  const [saving, setSaving] = useState(false);
  const [formMessage, setFormMessage] = useState("");
  const [formError, setFormError] = useState("");

  
  const [attackData, setAttackData] =
    useState<AttackPathResponse | null>(null);

  const [analyzing, setAnalyzing] = useState(false);
  const [attackError, setAttackError] = useState("");
  const [selectedPathIndex, setSelectedPathIndex] =
    useState<number | null>(null);

  const [remediationType, setRemediationType] =
    useState<RemediationType>("isolate-asset");
  const [remediationTarget, setRemediationTarget] = useState("");
  const [simulationResult, setSimulationResult] =
    useState<FullSimulationResponse | null>(null);
  const [simulationLoading, setSimulationLoading] = useState(false);
  const [simulationError, setSimulationError] = useState("");


  const refreshGraph = useCallback(async (showSpinner = false) => {
  try {
    if (showSpinner) setLoading(true);
    setError("");

    const data = (await apiRequest("/graph")) as GraphResponse;

    if (!Array.isArray(data.nodes) || !Array.isArray(data.edges)) {
      throw new Error("Invalid graph response");
    }

    setGraph(data);

    // Discard old analysis results when the underlying graph is refreshed.
    setAttackData(null);
    setSelectedPathIndex(null);

    setSelectedNode((previous) => {
      if (!previous) return null;
      return data.nodes.find((node) => node.id === previous.id) ?? null;
    });
  } catch (err) {
    console.error(err);

    setError(
      err instanceof Error
        ? err.message
        : "Could not load graph. Check FastAPI and Neo4j."
    );
  } finally {
    setLoading(false);
  }
}, [
  setLoading,
  setError,
  setGraph,
  setAttackData,
  setSelectedPathIndex,
  setSelectedNode,
]);

  useEffect(() => {
    if (!accessToken) { setLoading(false); return; }
    let isActive = true;

    const loadInitialGraph = async () => {
      try {
        const data = (await apiRequest("/graph")) as GraphResponse;

        if (!Array.isArray(data.nodes) || !Array.isArray(data.edges)) {
          throw new Error("Invalid graph response");
        }

        if (!isActive) return;

        setGraph(data);
        setAttackData(null);
        setSelectedPathIndex(null);
        setSelectedNode(null);
        setError("");
      } catch (err) {
        if (!isActive) return;

        console.error(err);
        setError(
          err instanceof Error
            ? err.message
            : "Could not load graph. Check FastAPI and Neo4j."
        );
      } finally {
        if (isActive) {
          setLoading(false);
        }
      }
    };

    void loadInitialGraph();

    return () => {
      isActive = false;
    };
  }, [accessToken]);

  // Rebuild the visualization whenever the database graph changes.
  useEffect(() => {
    if (!graph || !graphRef.current) return;

    const elements: cytoscape.ElementDefinition[] = [
      ...graph.nodes.map((node) => ({
        data: {
          id: node.id,
          label: node.name,
          type: node.type,
          ip: node.ip,
          criticality: node.criticality,
          exposed: node.exposed,
          compromised: node.compromised,
          environment: node.environment ?? "Unknown",
        },
      })),
      ...graph.edges
        .filter(
          (edge) =>
            graph.nodes.some((node) => node.id === edge.source) &&
            graph.nodes.some((node) => node.id === edge.target)
        )
        .map((edge, index) => ({
          data: {
            id: `edge-${index}`,
            source: edge.source,
            target: edge.target,
            label: edge.relationship,
            protocol: edge.protocol ?? "",
          },
        })),
    ];

    const cy = cytoscape({
      container: graphRef.current,
      elements,
      minZoom: 0.3,
      maxZoom: 3,
      wheelSensitivity: 0.2,
      style: [
        {
          selector: "node",
          style: {
            "background-color": theme === "dark" ? "#2563eb" : "#3156a6",
            label: "data(label)",
            color: "#ffffff",
            "text-valign": "center",
            "text-halign": "center",
            "font-size": 11,
            width: 48,
            height: 48,
            "border-width": 2,
            "border-color": theme === "dark" ? "#93c5fd" : "#5476b8",
            "text-wrap": "wrap",
            "text-max-width": "75px",
            "overlay-opacity": 0,
          },
        },
        {
          selector: 'node[criticality = "Critical"]',
          style: {
            "background-color": "#991b1b",
            "border-color": "#f87171",
          },
        },
        {
          selector: 'node[exposed = "Yes"]',
          style: {
            "border-width": 4,
            "border-color": "#f59e0b",
          },
        },
        {
          selector: 'node[compromised = "Yes"]',
          style: {
            "background-color": "#7f1d1d",
            "border-color": "#ef4444",
            "border-width": 5,
          },
        },
        {
          selector: "edge",
          style: {
            width: 2,
            "line-color": theme === "dark" ? "#64748b" : "#8794a8",
            "target-arrow-color": theme === "dark" ? "#64748b" : "#8794a8",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(label)",
            color: "#94a3b8",
            "font-size": 8,
            "text-background-color": theme === "dark" ? "#0f172a" : "#ffffff",
            "text-background-opacity": 0.85,
            "text-background-padding": "2px",
          },
        },
        {
          selector: "node:selected",
          style: {
            "border-color": "#fbbf24",
            "border-width": 5,
          },
        },
        {
          selector: ".search-match",
          style: {
            "border-color": "#22c55e",
            "border-width": 5,
          },
        },
        {
          selector: ".search-dim",
          style: { opacity: 0.2 },
        },
        {
          selector: ".filter-dim",
          style: { opacity: 0.08 },
        },
        {
          selector: ".path-highlight",
          style: {
            opacity: 1,
            "overlay-opacity": 0,
          },
        },
        {
          selector: "node.path-highlight",
          style: {
            "background-color": "#d97706",
            "border-color": "#fef3c7",
            "border-width": 5,
            opacity: 1,
          },
        },
        {
          selector: "edge.path-highlight",
          style: {
            "line-color": "#fbbf24",
            "target-arrow-color": "#fbbf24",
            width: 5,
            opacity: 1,
          },
        },
        {
          selector: ".path-dim",
          style: { opacity: 0.15 },
        },
      ],
      layout: {
        name: "cose",
        animate: false,
        fit: true,
        padding: 70,
        nodeRepulsion: () => 9000,
        idealEdgeLength: () => 150,
        componentSpacing: 100,
        gravity: 0.25,
      },
    });

    cyRef.current = cy;

    cy.on("tap", "node", (event) => {
      const node = graph.nodes.find(
        (item) => item.id === event.target.id()
      );

      if (node) {
        setSelectedNode(node);
        setEditing(false);
        setFormMessage("");
        setFormError("");
      }
    });

    cy.on("tap", (event) => {
      if (event.target === cy) {
        setSelectedNode(null);
        setEditing(false);
      }
    });

    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [graph, theme]);

  // Search graph assets.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    const query = search.trim().toLowerCase();
    cy.elements().removeClass("search-match search-dim");

    if (!query) return;

    const matches = cy.nodes().filter((node) =>
      [
        node.data("id"),
        node.data("label"),
        node.data("type"),
        node.data("ip"),
      ].some((value) =>
        String(value ?? "").toLowerCase().includes(query)
      )
    );

    cy.elements().addClass("search-dim");
    matches.removeClass("search-dim").addClass("search-match");
    matches.connectedEdges().removeClass("search-dim");

    if (matches.length) {
      cy.animate({ fit: { eles: matches, padding: 70 }, duration: 250 });
    }
  }, [search, graph]);

  // Apply the selected graph filters without removing data from the graph.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    // Cytoscape collections expose forEach in the browser. Guard the call so
    // lightweight graph mocks used by tests (which may only implement filter)
    // do not throw during React's effect lifecycle.
    const nodes = cy.nodes();
    if (typeof nodes.forEach === "function") {
      nodes.forEach((node) => {
        const criticalityMatches = criticalityFilter === "All" ||
          String(node.data("criticality") ?? "").toLowerCase() === criticalityFilter.toLowerCase();
        const typeMatches = typeFilter === "All" ||
          String(node.data("type") ?? "").toLowerCase() === typeFilter.toLowerCase();
        const environmentMatches = environmentFilter === "All" ||
          String(node.data("environment") ?? "Unknown").toLowerCase() === environmentFilter.toLowerCase();
        node.toggleClass("filter-dim", !(criticalityMatches && typeMatches && environmentMatches));
      });
    }

    const edges = cy.edges();
    if (typeof edges.forEach === "function") {
      edges.forEach((edge) => {
        const relationshipMatches = relationshipFilter === "All" ||
          String(edge.data("label") ?? "").toLowerCase() === relationshipFilter.toLowerCase();
        edge.toggleClass("filter-dim", !relationshipMatches);
      });
    }
  }, [criticalityFilter, typeFilter, environmentFilter, relationshipFilter, graph]);

  const assetTypes = Array.from(new Set((graph?.nodes ?? []).map((node) => node.type).filter(Boolean))).sort();
  const environments = Array.from(new Set((graph?.nodes ?? []).map((node) => node.environment || "Unknown"))).sort();
  const relationships = Array.from(new Set((graph?.edges ?? []).map((edge) => edge.relationship).filter(Boolean))).sort();
  const filteredAssetCount = (graph?.nodes ?? []).filter((node) =>
    (criticalityFilter === "All" || node.criticality.toLowerCase() === criticalityFilter.toLowerCase()) &&
    (typeFilter === "All" || node.type.toLowerCase() === typeFilter.toLowerCase()) &&
    (environmentFilter === "All" || (node.environment || "Unknown").toLowerCase() === environmentFilter.toLowerCase())
  ).length;

  function zoomGraph(factor: number) {
    const cy = cyRef.current;
    if (!cy) return;
    const nextZoom = Math.max(cy.minZoom(), Math.min(cy.maxZoom(), cy.zoom() * factor));
    cy.zoom({ level: nextZoom, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  }

  async function analyzeAttackPaths() {
    setAnalyzing(true);
    setAttackError("");
    setSelectedPathIndex(null);

    try {
      const result = (await apiRequest("/attack-paths")) as AttackPathResponse;

      if (!Array.isArray(result.paths)) {
        throw new Error("The attack-path endpoint returned an unexpected response.");
      }

      setAttackData(result);

      const cy = cyRef.current;
      if (cy) {
        cy.elements().removeClass("path-highlight path-dim");
      }
    } catch (err) {
      setAttackError(
        err instanceof Error ? err.message : "Could not analyze attack paths."
      );
      setAttackData(null);
    } finally {
      setAnalyzing(false);
    }
  }

  async function runFullSimulation() {
    setSimulationError("");
    setSimulationResult(null);

    if (!remediationTarget) {
      setSimulationError(
        remediationType === "isolate-asset"
          ? "Select an asset to isolate."
          : "Select a connection to remove."
      );
      return;
    }

    setSimulationLoading(true);
    try {
      let payload: {
        action_type: RemediationType;
        target_id?: string;
        source_id?: string;
        destination_id?: string;
        relationship?: string;
      };

      if (remediationType === "isolate-asset") {
        payload = {
          action_type: "isolate-asset",
          target_id: remediationTarget,
        };
      } else {
        const edgeIndex = Number(remediationTarget);
        const edge = graph?.edges[edgeIndex];
        if (!edge) {
          throw new Error("The selected connection no longer exists. Refresh the graph and try again.");
        }
        payload = {
          action_type: "remove-connection",
          source_id: edge.source,
          destination_id: edge.target,
          relationship: edge.relationship,
        };
      }

      const result = (await apiRequest("/simulate-remediation", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      })) as FullSimulationResponse;

      if (!result.before || !result.after) {
        throw new Error("The simulation endpoint returned an unexpected response. Check the backend response schema.");
      }
      setSimulationResult(result);
    } catch (err) {
      setSimulationError(
        err instanceof Error ? err.message : "Full-graph simulation failed."
      );
    } finally {
      setSimulationLoading(false);
    }
  }

  function highlightAttackPath(item: AttackPath, index: number) {
    setSelectedPathIndex(index);

    const cy = cyRef.current;
    if (!cy) return;

    cy.elements().removeClass("path-highlight path-dim");
    cy.elements().addClass("path-dim");

    item.path.forEach((node) => {
      cy.getElementById(node.id)
        .removeClass("path-dim")
        .addClass("path-highlight");
    });

    item.connections.forEach((edge) => {
      cy.edges()
        .filter(
          (candidate) =>
            candidate.data("source") === edge.source &&
            candidate.data("target") === edge.target &&
            candidate.data("label") === edge.relationship
        )
        .forEach((candidate) => {
          candidate.removeClass("path-dim").addClass("path-highlight");
        });
    });

    const highlighted = cy.elements(".path-highlight");
    if (highlighted.length) {
      cy.animate({
        fit: { eles: highlighted, padding: 70 },
        duration: 300,
      });
    }
  }

  function resetGraph() {
    const cy = cyRef.current;
    if (!cy) return;

    cy.elements().removeClass(
      "search-match search-dim path-highlight path-dim"
    );
    setSelectedPathIndex(null);
    cy.layout({
      name: "cose",
      animate: false,
      fit: true,
      padding: 70,
      nodeRepulsion: () => 9000,
      idealEdgeLength: () => 150,
      componentSpacing: 100,
      gravity: 0.25,
    }).run();

    cy.fit(undefined, 45);
    setSearch("");
    setCriticalityFilter("All");
    setTypeFilter("All");
    setEnvironmentFilter("All");
    setRelationshipFilter("All");
    setSelectedNode(null);
    setEditing(false);
  }

  async function submitAsset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    setFormMessage("");
    setFormError("");

    try {
      await apiRequest("/assets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...assetForm,
          id: assetForm.id.trim(),
          name: assetForm.name.trim(),
          type: assetForm.type.trim(),
          ip: assetForm.ip.trim(),
        }),
      });

      await refreshGraph();
      setAssetForm({ ...emptyAssetForm });
      setFormMessage("Asset added successfully.");
    } catch (err) {
      setFormError(
        err instanceof Error ? err.message : "Could not add asset."
      );
    } finally {
      setSaving(false);
    }
  }

  async function submitConnection(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    setFormMessage("");
    setFormError("");

    try {
      await apiRequest("/connections", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(connectionForm),
      });

      await refreshGraph();
      setConnectionForm({ ...emptyConnectionForm });
      setFormMessage("Connection added successfully.");
    } catch (err) {
      setFormError(
        err instanceof Error ? err.message : "Could not add connection."
      );
    } finally {
      setSaving(false);
    }
  }

  function startEditing() {
    if (!selectedNode) return;

    setEditForm({ ...selectedNode });
    setEditing(true);
    setFormMessage("");
    setFormError("");
  }

  async function submitEdit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedNode) return;

    setSaving(true);
    setFormMessage("");
    setFormError("");

    try {
      await apiRequest(
        `/assets/${encodeURIComponent(selectedNode.id)}`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            ...editForm,
            id: selectedNode.id,
            name: editForm.name.trim(),
            type: editForm.type.trim(),
            ip: editForm.ip.trim(),
          }),
        }
      );

      await refreshGraph();
      setEditing(false);
      setFormMessage("Asset updated successfully.");
    } catch (err) {
      setFormError(
        err instanceof Error ? err.message : "Could not update asset."
      );
    } finally {
      setSaving(false);
    }
  }

  async function removeAsset() {
    if (!selectedNode) return;

    const confirmed = window.confirm(
      `Delete "${selectedNode.name}" and ALL its connected relationships? This cannot be undone.`
    );

    if (!confirmed) return;

    setSaving(true);
    setFormMessage("");
    setFormError("");

    try {
      await apiRequest(
        `/assets/${encodeURIComponent(selectedNode.id)}`,
        { method: "DELETE" }
      );

      setSelectedNode(null);
      setEditing(false);
      await refreshGraph();
      setFormMessage("Asset and its relationships deleted.");
    } catch (err) {
      setFormError(
        err instanceof Error ? err.message : "Could not delete asset."
      );
    } finally {
      setSaving(false);
    }
  }

  async function removeConnection(edge: EdgeData) {
    const sourceName =
      graph?.nodes.find((node) => node.id === edge.source)?.name ??
      edge.source;
    const targetName =
      graph?.nodes.find((node) => node.id === edge.target)?.name ??
      edge.target;

    const confirmed = window.confirm(
      `Delete connection ${sourceName} → ${targetName} (${edge.relationship})?`
    );

    if (!confirmed) return;

    setSaving(true);
    setFormMessage("");
    setFormError("");

    try {
      await apiRequest("/connections", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          source: edge.source,
          target: edge.target,
          relationship: edge.relationship,
        }),
      });

      await refreshGraph();
      setFormMessage("Connection deleted successfully.");
    } catch (err) {
      setFormError(
        err instanceof Error ? err.message : "Could not delete connection."
      );
    } finally {
      setSaving(false);
    }
  }

  const criticalCount =
    graph?.nodes.filter(
      (node) => node.criticality.toLowerCase() === "critical"
    ).length ?? 0;

  const compromisedCount =
    graph?.nodes.filter(
      (node) => String(node.compromised).toLowerCase() === "yes"
    ).length ?? 0;

  const selectedConnections =
    graph?.edges.filter(
      (edge) =>
        selectedNode &&
        (edge.source === selectedNode.id || edge.target === selectedNode.id)
    ) ?? [];

  if (authChecking) return <div className="nx-auth-loading">Checking your secure session...</div>;
  if (!accessToken || !authUser) return <AuthScreen theme={theme} onToggleTheme={() => setTheme(current => current === "dark" ? "light" : "dark")} onAuthenticated={handleAuthenticated} />;

  return (
    <div className="app">
      <header className="header">
        <div>
          <h1>NEXAGRAPH AI</h1>
          <p>Enterprise Attack Path Analysis &amp; Threat Intelligence</p>
        </div>

        <div className="header-actions">
          <button
            type="button"
            className="theme-toggle"
            onClick={() => setTheme((current) => current === "dark" ? "light" : "dark")}
            aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
            aria-pressed={theme === "light"}
          >
            <span aria-hidden="true">{theme === "dark" ? "☀" : "☾"}</span>
            {theme === "dark" ? "Light mode" : "Dark mode"}
          </button>
          <div className="nx-session-user"><strong>{authUser.full_name}</strong><span>{authUser.role}</span></div>
          <button type="button" className="nx-logout-button" onClick={() => void handleLogout()}>Sign out</button>
          <div className="status">
          <span className="status-dot" />
          {error ? "BACKEND UNAVAILABLE" : loading ? "CONNECTING..." : "SYSTEM ONLINE"}
          </div>
        </div>
      </header>

      <div className="nx-app-shell">
        <aside id="nexagraph-main-navigation" className={`nx-sidebar ${sidebarOpen ? "is-open" : ""}`} aria-label="Main navigation">
          <div className="nx-sidebar-brand">
            <span className="nx-brand-mark">N</span>
            <div><strong>NexaGraph</strong><small>Security workspace</small></div>
          </div>
          <div className="nx-sidebar-section">WORKSPACE</div>
          <nav className="nx-sidebar-nav">
            {[
              { id: "overview", icon: "▦", label: "Overview" },
              { id: "ml-detection", icon: "◈", label: "AI Threat Detection" },
              { id: "network-topology", icon: "⌘", label: "Network Topology" },
              { id: "vulnerability-intelligence", icon: "◇", label: "Vulnerability Intel" },
              { id: "incidents", icon: "⚑", label: "Incident Management" },
              { id: "security-events", icon: "◉", label: "Security Events" },
              { id: "security-intelligence", icon: "✧", label: "Threat Intelligence" },
              { id: "asset-management", icon: "▣", label: "Asset Management" },
              ...((authUser.role === "ORG_ADMIN" || authUser.role === "SUPER_ADMIN")
                ? [{ id: "team-management", icon: "♙", label: "Team Management" }]
                : []),
            ].map((item) => (
              <a key={item.id} href={`#${item.id}`} onClick={() => setSidebarOpen(false)}>
                <span aria-hidden="true">{item.icon}</span>{item.label}
              </a>
            ))}
          </nav>
          <div className="nx-sidebar-footer">
            <span className="nx-sidebar-live-dot" /> Secure workspace
            <small>Signed in as {authUser.role.replaceAll("_", " ")}</small>
          </div>
        </aside>
        {sidebarOpen && <button className="nx-sidebar-backdrop" aria-label="Close navigation" onClick={() => setSidebarOpen(false)} />}
        <button
          className="nx-floating-menu"
          type="button"
          onClick={() => setSidebarOpen((open) => !open)}
          aria-expanded={sidebarOpen}
          aria-controls="nexagraph-main-navigation"
          aria-label={sidebarOpen ? "Close navigation menu" : "Open navigation menu"}
          title="Open navigation"
        >
          <span aria-hidden="true">{sidebarOpen ? "×" : "☰"}</span>
        </button>
        <button
          className="nx-floating-search"
          type="button"
          onClick={() => { setCommandQuery(""); setCommandOpen(true); }}
          aria-label="Open quick navigation"
          title="Quick navigation (Ctrl+K)"
        >
          <span aria-hidden="true">⌕</span>
        </button>
        <div className="nx-content">
          <main className="main">
        <section className="stats" id="overview">
          <div className="stat-card">
            <span>Assets</span>
            <strong>{graph?.nodes.length ?? 0}</strong>
          </div>
          <div className="stat-card">
            <span>Connections</span>
            <strong>{graph?.edges.length ?? 0}</strong>
          </div>
          <div className="stat-card">
            <span>Critical Assets</span>
            <strong>{criticalCount}</strong>
          </div>
          <div className="stat-card">
            <span>Compromised</span>
            <strong>{compromisedCount}</strong>
          </div>
        </section>
        <section id="ml-detection" className="nx-nav-section"><MLDetectionDashboard /></section>

        {/* Organization team management: visible only to authorized administrators */}
        {(authUser.role === "ORG_ADMIN" || authUser.role === "SUPER_ADMIN") && (
          <section id="team-management" className="nx-nav-section"><TeamManagement /></section>
        )}

        {/* Live PostgreSQL-backed network topology */}
        <section id="network-topology" className="nx-nav-section"><NetworkTopology theme={theme} /></section>

        {/* PostgreSQL-backed vulnerability intelligence */}
        <section id="vulnerability-intelligence" className="nx-nav-section"><VulnerabilityIntelligence /></section>

        <section id="incidents" className="nx-nav-section"><IncidentManagement /></section>
        <section id="security-events" className="nx-nav-section"><SecurityEventMonitoring /></section>
        <section id="security-intelligence" className="nx-nav-section"><SecurityIntelligence /></section>

        {error && <div className="error">{error}</div>}
        {loading && <div className="loading">Loading enterprise graph...</div>}

        <section className="management-panel nx-nav-section" id="asset-management">
          <h2>Manage Enterprise Graph</h2>
          <p>Add assets and define relationships between existing assets.</p>

          {formMessage && (
            <div className="form-success" role="status">{formMessage}</div>
          )}
          {formError && (
            <div className="error" role="alert">{formError}</div>
          )}

          <div className="forms-grid">
            <form className="management-form" onSubmit={submitAsset}>
              <h3>Add Asset</h3>

              <label>
                Asset ID
                <input
                  required
                  maxLength={50}
                  value={assetForm.id}
                  onChange={(e) => setAssetForm({ ...assetForm, id: e.target.value })}
                  placeholder="e.g. A08"
                />
              </label>

              <label>
                Asset Name
                <input
                  required
                  maxLength={100}
                  value={assetForm.name}
                  onChange={(e) => setAssetForm({ ...assetForm, name: e.target.value })}
                  placeholder="e.g. Payment Server"
                />
              </label>

              <label>
                Type
                <select
                  value={assetForm.type}
                  onChange={(e) => setAssetForm({ ...assetForm, type: e.target.value })}
                >
                  {["External", "Server", "Endpoint", "Database", "Application", "Network Device"].map((type) => (
                    <option key={type}>{type}</option>
                  ))}
                </select>
              </label>

              <label>
                IP Address / Identifier
                <input
                  required
                  maxLength={100}
                  value={assetForm.ip}
                  onChange={(e) => setAssetForm({ ...assetForm, ip: e.target.value })}
                  placeholder="e.g. 10.0.0.70"
                />
              </label>

              <label>
                Criticality
                <select
                  value={assetForm.criticality}
                  onChange={(e) => setAssetForm({ ...assetForm, criticality: e.target.value })}
                >
                  {["Low", "Medium", "High", "Critical"].map((level) => (
                    <option key={level}>{level}</option>
                  ))}
                </select>
              </label>

              <label>
                Exposed
                <select
                  value={assetForm.exposed}
                  onChange={(e) => setAssetForm({ ...assetForm, exposed: e.target.value })}
                >
                  <option>No</option>
                  <option>Yes</option>
                </select>
              </label>

              <label>
                Compromised
                <select
                  value={assetForm.compromised}
                  onChange={(e) => setAssetForm({ ...assetForm, compromised: e.target.value })}
                >
                  <option>No</option>
                  <option>Yes</option>
                </select>
              </label>

              <button type="submit" disabled={saving}>
                {saving ? "Saving..." : "Add Asset"}
              </button>
            </form>

            <form className="management-form" onSubmit={submitConnection}>
              <h3>Add Connection</h3>

              <label>
                Source Asset
                <select
                  required
                  value={connectionForm.source}
                  onChange={(e) => setConnectionForm({
                    ...connectionForm,
                    source: e.target.value,
                    target: e.target.value === connectionForm.target ? "" : connectionForm.target,
                  })}
                >
                  <option value="">Select source asset</option>
                  {(graph?.nodes ?? []).map((node) => (
                    <option key={node.id} value={node.id}>{node.name} ({node.id})</option>
                  ))}
                </select>
              </label>

              <label>
                Target Asset
                <select
                  required
                  value={connectionForm.target}
                  onChange={(e) => setConnectionForm({ ...connectionForm, target: e.target.value })}
                >
                  <option value="">Select target asset</option>
                  {(graph?.nodes ?? []).filter((node) => node.id !== connectionForm.source).map((node) => (
                    <option key={node.id} value={node.id}>{node.name} ({node.id})</option>
                  ))}
                </select>
              </label>

              <label>
                Relationship
                <select
                  value={connectionForm.relationship}
                  onChange={(e) => setConnectionForm({ ...connectionForm, relationship: e.target.value })}
                >
                  {["CONNECTS", "ACCESS", "ACCESSES", "ADMIN_ACCESS", "BACKUP", "AUTHENTICATES", "DEPENDS_ON"].map((rel) => (
                    <option key={rel}>{rel}</option>
                  ))}
                </select>
              </label>

              <label>
                Protocol
                <select
                  value={connectionForm.protocol}
                  onChange={(e) => setConnectionForm({ ...connectionForm, protocol: e.target.value })}
                >
                  {["TCP", "UDP", "HTTP", "HTTPS", "SSH", "RDP", "OTHER"].map((protocol) => (
                    <option key={protocol}>{protocol}</option>
                  ))}
                </select>
              </label>

              <button type="submit" disabled={saving || !connectionForm.source || !connectionForm.target}>
                {saving ? "Saving..." : "Add Connection"}
              </button>
            </form>
          </div>
        </section>

        {/* Attack Path Analysis */}
        <section className="management-panel attack-panel">
          <div className="panel-header">
            <div>
              <h2>Attack Path Analysis</h2>
              <p>
                Find potential directed routes from exposed or compromised
                assets to critical assets.
              </p>
            </div>
            <button
              type="button"
              onClick={() => void analyzeAttackPaths()}
              disabled={analyzing || loading || !graph}
            >
              {analyzing ? "Analyzing..." : "Analyze Attack Paths"}
            </button>
          </div>

          {attackError && (
            <div className="error" role="alert">{attackError}</div>
          )}

          {!attackData && !attackError && (
            <p className="attack-note">
              Run an analysis to identify and rank potential attack paths.
            </p>
          )}

          {attackData && (
            <div className="attack-results">
              <div className="attack-summary">
                <div className="stat-card">
                  <span>Paths Found</span>
                  <strong>{attackData.total_paths}</strong>
                </div>
                <div className="stat-card">
                  <span>Highest Risk</span>
                  <strong>
                    {attackData.paths.length > 0
                      ? attackData.paths[0].risk_level
                      : "None"}
                  </strong>
                </div>
              </div>

              {attackData.max_paths_reached && (
                <p className="attack-note">
                  The 100-path limit was reached. Additional paths may exist.
                </p>
              )}

              
{attackData.paths.length === 0 ? (
  <div className="empty">
    No qualifying paths were found. Check that an exposed or
    compromised asset has a directed route to an asset marked Critical.
  </div>
) : (
  <div className="attack-path-list">
    {attackData.paths.map((item, index) => (
      <button
        type="button"
        key={`${item.path.map((node) => node.id).join("-")}-${index}`}
        className={`attack-path-card ${
          selectedPathIndex === index ? "path-selected" : ""
        }`}
        aria-pressed={selectedPathIndex === index}
        onClick={() => highlightAttackPath(item, index)}
      >
        <div className="attack-path-heading">
          <strong>Attack Path {index + 1}</strong>
          <span
            className={`risk-pill risk-${item.risk_level.toLowerCase()}`}
          >
            {item.risk_level} Risk
          </span>
        </div>

        <div className="attack-path-metadata">
          <span>
            <strong>{item.risk_score}</strong>/100 risk score
          </span>
          <span>{item.path.length} assets</span>
          <span>{Math.max(0, item.path.length - 1)} hops</span>
        </div>

        <div
          className="risk-score-track"
          aria-label={`Risk score ${item.risk_score} out of 100`}
        >
          <div
            className={`risk-score-fill risk-fill-${item.risk_level.toLowerCase()}`}
            style={{
              width: `${Math.max(0, Math.min(100, item.risk_score))}%`,
            }}
          />
        </div>

        <div className="path-sequence">
          {item.path.map((node, nodeIndex) => (
            <span
              className="path-node"
              key={`${node.id}-${nodeIndex}`}
            >
              {node.name}
              {nodeIndex < item.path.length - 1 && (
                <span className="path-arrow"> → </span>
              )}
            </span>
          ))}
        </div>

        <span className="path-hint">
          {selectedPathIndex === index
            ? "Currently highlighted in the graph"
            : "Select to highlight this route in the graph"}
        </span>
      </button>
    ))}
  </div>
)}


              <p className="attack-note">{attackData.scoring_note}</p>
            </div>
          )}
        </section>

        <section className="management-panel full-simulation-panel">
          <div className="panel-header">
            <div>
              <h2>Remediation Simulator</h2>
              <p>
                Test a proposed fix against the full graph snapshot. This simulation
                does not modify your Neo4j database.
              </p>
            </div>
            <span className="simulation-safe-badge">SIMULATION ONLY</span>
          </div>

          <div className="simulation-controls">
            <label>
              Remediation action
              <select
                value={remediationType}
                onChange={(event) => {
                  setRemediationType(event.target.value as RemediationType);
                  setRemediationTarget("");
                  setSimulationResult(null);
                  setSimulationError("");
                }}
              >
                <option value="isolate-asset">Isolate an asset</option>
                <option value="remove-connection">Remove a connection</option>
              </select>
            </label>

            {remediationType === "isolate-asset" ? (
              <label>
                Asset to isolate
                <select
                  value={remediationTarget}
                  onChange={(event) => {
                    setRemediationTarget(event.target.value);
                    setSimulationResult(null);
                    setSimulationError("");
                  }}
                >
                  <option value="">Select an asset</option>
                  {(graph?.nodes ?? []).map((node) => (
                    <option key={node.id} value={node.id}>
                      {node.name} ({node.id})
                    </option>
                  ))}
                </select>
              </label>
            ) : (
              <label>
                Connection to remove
                <select
                  value={remediationTarget}
                  onChange={(event) => {
                    setRemediationTarget(event.target.value);
                    setSimulationResult(null);
                    setSimulationError("");
                  }}
                >
                  <option value="">Select a connection</option>
                  {(graph?.edges ?? []).map((edge, index) => {
                    const sourceName =
                      graph?.nodes.find((node) => node.id === edge.source)?.name ?? edge.source;
                    const targetName =
                      graph?.nodes.find((node) => node.id === edge.target)?.name ?? edge.target;
                    return (
                      <option key={`${edge.source}-${edge.target}-${edge.relationship}-${index}`} value={String(index)}>
                        {sourceName} → {targetName} ({edge.relationship})
                      </option>
                    );
                  })}
                </select>
              </label>
            )}

            <button
              type="button"
              onClick={() => void runFullSimulation()}
              disabled={simulationLoading || loading || !graph || !remediationTarget}
            >
              {simulationLoading ? "Recalculating full graph..." : "Run Full-Graph Simulation"}
            </button>
          </div>

          {simulationError && (
            <div className="error" role="alert">{simulationError}</div>
          )}

          {simulationResult && (
            <div className="full-simulation-results" aria-live="polite">
              <div className="panel-header">
                <h3>Simulation Results</h3>
                <span className="simulation-safe-badge">
                  {simulationResult.database_modified ? "DATABASE CHANGED" : "DATABASE UNCHANGED"}
                </span>
              </div>

              
<div className="simulation-metrics">
  <div className="stat-card">
    <span>Paths Before</span>
    <strong>{simulationResult.before.total_paths}</strong>
  </div>

  <div className="stat-card">
    <span>Paths After</span>
    <strong>{simulationResult.after.total_paths}</strong>
  </div>

  <div className="stat-card">
    <span>Paths Eliminated</span>
    <strong>{simulationResult.paths_eliminated}</strong>
  </div>

  <div className="stat-card">
    <span>Path Reduction</span>
    <strong>
      {simulationResult.before.total_paths > 0
        ? `${Math.round(
            (simulationResult.paths_eliminated /
              simulationResult.before.total_paths) * 100
          )}%`
        : "N/A"}
    </strong>
  </div>

  <div className="stat-card">
    <span>Highest Risk After</span>
    <strong>{simulationResult.highest_risk_after}/100</strong>
  </div>
</div>


              <p className="attack-note">
                Highest risk before: {simulationResult.highest_risk_before}/100 ·
                Score reduction: {simulationResult.risk_score_reduction} points
              </p>
              
<div
  className={`simulation-risk-status ${
    simulationResult.after.paths.length === 0
      ? "status-no-paths"
      : simulationResult.highest_risk_after >= 80
        ? "status-critical"
        : simulationResult.highest_risk_after >= 60
          ? "status-high"
          : simulationResult.highest_risk_after >= 35
            ? "status-medium"
            : "status-low"
  }`}
  role="status"
>
  <strong>
    {simulationResult.after.paths.length === 0
      ? "No qualifying attack paths remain"
      : simulationResult.highest_risk_after >= 80
        ? "Critical risk remains"
        : simulationResult.highest_risk_after >= 60
          ? "High risk remains"
          : simulationResult.highest_risk_after >= 35
            ? "Moderate risk remains"
            : "Lower residual risk"}
  </strong>

  <p>
    {simulationResult.after.paths.length === 0
      ? "No qualifying paths were found within the current analysis limits. This does not prove the environment is secure."
      : `${simulationResult.paths_eliminated} of ${simulationResult.before.total_paths} qualifying paths eliminated. ${
          simulationResult.highest_risk_after === simulationResult.highest_risk_before
            ? "The highest risk score has not decreased."
            : simulationResult.risk_score_reduction > 0
              ? `The highest risk score decreased by ${simulationResult.risk_score_reduction} points.`
              : "The highest risk score increased; investigate the remaining routes."
        }`}
  </p>
</div>


              <h4>Remaining Attack Paths</h4>
              {simulationResult.after.paths.length === 0 ? (
                <div className="form-success">
                  No qualifying attack paths were found after this simulated action.
                </div>
              ) : (
                <div className="simulation-path-list">
                  {simulationResult.after.paths.map((path, index) => (
                    <div
                      className="simulation-path-row"
                      key={`${path.path.map((node) => node.id).join("-")}-${index}`}
                    >
                      <span>{path.path.map((node) => node.name).join(" → ")}</span>
                      <strong>{path.risk_score}/100 · {path.risk_level}</strong>
                    </div>
                  ))}
                </div>
              )}

              {(simulationResult.after.max_paths_reached ||
                simulationResult.before.max_paths_reached) && (
                <p className="attack-note">
                  The 100-path limit was reached. Additional qualifying paths may exist.
                </p>
              )}
              <p className="attack-note">
                {simulationResult.scoring_note || "Risk scores are prototype heuristics, not probabilities of a real attack."}
              </p>
              

<div className="remediation-recommendations">
  <h4>Recommended Next Actions</h4>

  {simulationResult.after.paths.length === 0 ? (
    <div className="recommendation-item">
      <strong>All identified paths eliminated in this simulation</strong>
      <p>
        No qualifying attack paths remain in the simulated graph.
        Validate the affected assets and connections in your live
        environment before implementing any changes.
      </p>
      <p>
        Paths eliminated: {simulationResult.paths_eliminated}
      </p>
    </div>
  ) : (
    <>
      {(() => {
        const highestRiskPath = simulationResult.after.paths.reduce(
          (highest, current) =>
            current.risk_score > highest.risk_score ? current : highest
        );

        const pathAssets = highestRiskPath.path;
        const firstAsset = pathAssets[0];
        const lastAsset = pathAssets[pathAssets.length - 1];

        return (
          <>
            <div className="recommendation-item">
              <strong>
                1. Prioritize the highest-risk remaining route
              </strong>

              <div className="recommendation-risk-summary">
                <span>
                  Risk score:{" "}
                  <strong>{highestRiskPath.risk_score}/100</strong>
                </span>
                <span>
                  Risk level:{" "}
                  <strong>{highestRiskPath.risk_level}</strong>
                </span>
                <span>
                  Assets involved: <strong>{pathAssets.length}</strong>
                </span>
              </div>

              <p>
                Review the directed route from{" "}
                <strong>{firstAsset.name}</strong> to{" "}
                <strong>{lastAsset.name}</strong>. Investigate the
                assets and connections along this route to identify
                where additional controls may reduce exposure.
              </p>

              <div className="recommendation-asset-list">
                {pathAssets.map((asset, index) => (
                  <div
                    className="recommendation-asset"
                    key={`${asset.id}-${index}`}
                  >
                    <span className="recommendation-asset-number">
                      {index + 1}
                    </span>
                    <span>{asset.name}</span>
                    {index < pathAssets.length - 1 && (
                      <span className="recommendation-asset-arrow">
                        →
                      </span>
                    )}
                  </div>
                ))}
              </div>

              <button
                type="button"
                className="simulation-path-button"
                onClick={() =>
                  highlightAttackPath(highestRiskPath, 0)
                }
              >
                Highlight this attack path
              </button>
            </div>
          </>
        );
      })()}

      <div className="recommendation-item">
        <strong>2. Review the residual risk</strong>
        <p>
          {simulationResult.highest_risk_after >= 80
            ? "Critical risk remains. Prioritize investigation of the highest-risk route and its reachable critical assets."
            : simulationResult.highest_risk_after >= 60
              ? "High risk remains. Review the assets and connections that preserve the remaining attack routes."
              : simulationResult.highest_risk_after >= 35
                ? "Moderate risk remains. Review the remaining routes for additional exposure-reduction opportunities."
                : "The remaining paths have lower scores under the current heuristic. Validate the results and continue monitoring."}
        </p>
      </div>

      <div className="recommendation-item">
        <strong>3. Verify the simulated change</strong>
        <p>
          {simulationResult.paths_eliminated > 0
            ? `${simulationResult.paths_eliminated} qualifying attack path(s) were eliminated in this simulation. Confirm that the proposed change addresses the intended exposure before applying it.`
            : "No qualifying attack paths were eliminated. Consider evaluating a different asset or connection."}
        </p>
        <p>
          Database modified:{" "}
          <strong>
            {simulationResult.database_modified ? "Yes" : "No"}
          </strong>
        </p>
      </div>
    </>
  )}
</div>



            </div>
          )}
        </section>

        <section className="workspace">
          <div className="graph-panel">
            <div className="panel-header">
              <div>
                <h2>Enterprise Attack Graph</h2>
                <p>Interactive asset and relationship visualization</p>
              </div>
              <span className="live-badge">
                {graph ? "GRAPH LOADED" : "WAITING FOR DATA"}
              </span>
            </div>

            <div className="graph-toolbar">
              <input
                type="search"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search assets by name, ID, type or IP..."
                aria-label="Search graph assets"
              />
              <button type="button" onClick={resetGraph}>Reset graph</button>
              <button type="button" onClick={() => void refreshGraph(true)}>Refresh</button>
              <button type="button" onClick={() => zoomGraph(1.2)} aria-label="Zoom in">＋</button>
              <button type="button" onClick={() => zoomGraph(0.8)} aria-label="Zoom out">−</button>
              <button type="button" onClick={() => cyRef.current?.fit(undefined, 55)}>Fit</button>
            </div>

            <div className="graph-filters" aria-label="Graph filters">
              <label>Criticality
                <select value={criticalityFilter} onChange={(event) => setCriticalityFilter(event.target.value)}>
                  {['All', 'Critical', 'High', 'Medium', 'Low'].map((value) => <option key={value}>{value}</option>)}
                </select>
              </label>
              <label>Asset type
                <select value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)}>
                  <option value="All">All types</option>
                  {assetTypes.map((value) => <option key={value}>{value}</option>)}
                </select>
              </label>
              <label>Environment
                <select value={environmentFilter} onChange={(event) => setEnvironmentFilter(event.target.value)}>
                  <option value="All">All environments</option>
                  {environments.map((value) => <option key={value}>{value}</option>)}
                </select>
              </label>
              <label>Relationship
                <select value={relationshipFilter} onChange={(event) => setRelationshipFilter(event.target.value)}>
                  <option value="All">All relationships</option>
                  {relationships.map((value) => <option key={value}>{value}</option>)}
                </select>
              </label>
              <span className="filter-count">Showing {filteredAssetCount} of {graph?.nodes.length ?? 0} assets</span>
            </div>

            <div ref={graphRef} className="graph-container" />

            <div className="graph-legend">
              <span><i className="legend-normal" /> Normal</span>
              <span><i className="legend-critical" /> Critical</span>
              <span><i className="legend-exposed" /> Exposed</span>
              <span><i className="legend-compromised" /> Compromised</span>
            </div>
          </div>

          <aside className="details-panel">
            <h2>Asset Details</h2>

            {!selectedNode ? (
              <div className="empty">Select a node in the graph to inspect its properties.</div>
            ) : editing ? (
              <form className="management-form" onSubmit={submitEdit}>
                <h3>Edit {selectedNode.name}</h3>

                <label>
                  Asset ID (cannot change)
                  <input value={editForm.id} readOnly />
                </label>

                <label>
                  Name
                  <input required maxLength={100} value={editForm.name}
                    onChange={(e) => setEditForm({ ...editForm, name: e.target.value })} />
                </label>

                <label>
                  Type
                  <select value={editForm.type}
                    onChange={(e) => setEditForm({ ...editForm, type: e.target.value })}>
                    {["External", "Server", "Endpoint", "Database", "Application", "Network Device"].map((type) => (
                      <option key={type}>{type}</option>
                    ))}
                  </select>
                </label>

                <label>
                  IP Address / Identifier
                  <input required maxLength={100} value={editForm.ip}
                    onChange={(e) => setEditForm({ ...editForm, ip: e.target.value })} />
                </label>

                <label>
                  Criticality
                  <select value={editForm.criticality}
                    onChange={(e) => setEditForm({ ...editForm, criticality: e.target.value })}>
                    {["Low", "Medium", "High", "Critical"].map((level) => (
                      <option key={level}>{level}</option>
                    ))}
                  </select>
                </label>

                <label>
                  Exposed
                  <select value={editForm.exposed}
                    onChange={(e) => setEditForm({ ...editForm, exposed: e.target.value })}>
                    <option>No</option><option>Yes</option>
                  </select>
                </label>

                <label>
                  Compromised
                  <select value={editForm.compromised}
                    onChange={(e) => setEditForm({ ...editForm, compromised: e.target.value })}>
                    <option>No</option><option>Yes</option>
                  </select>
                </label>

                <button type="submit" disabled={saving}>
                  {saving ? "Saving..." : "Save Changes"}
                </button>
                <button type="button" disabled={saving} onClick={() => setEditing(false)}>
                  Cancel
                </button>
              </form>
            ) : (
              <>
                <div className="asset-intelligence">
                  <div className="asset-intelligence-heading">
                    <div className="asset-name">{selectedNode.name}</div>
                    <span className={`asset-criticality-badge ${String(selectedNode.criticality).toLowerCase()}`}>
                      {selectedNode.criticality || "Unknown"} criticality
                    </span>
                  </div>

                  <div className="asset-security-flags">
                    <span className={String(selectedNode.exposed).toLowerCase() === "yes" ? "flag warning" : "flag safe"}>
                      {String(selectedNode.exposed).toLowerCase() === "yes" ? "Exposed" : "Not marked exposed"}
                    </span>
                    <span className={String(selectedNode.compromised).toLowerCase() === "yes" ? "flag danger" : "flag safe"}>
                      {String(selectedNode.compromised).toLowerCase() === "yes" ? "Compromised" : "Not marked compromised"}
                    </span>
                  </div>

                  <div className="asset-detail-grid">
                    {[
                      ["Asset ID", selectedNode.id],
                      ["Asset type", selectedNode.type],
                      ["IP / Identifier", selectedNode.ip || "Not provided"],
                      ["Environment", selectedNode.environment || "Not supplied by graph API"],
                    ].map(([label, value]) => (
                      <div className="asset-detail-card" key={label}>
                        <span>{label}</span>
                        <strong>{value}</strong>
                      </div>
                    ))}
                  </div>

                  <section className="asset-intel-section">
                    <div className="asset-intel-section-heading">
                      <h3>Network activity</h3>
                      <span>{selectedConnections.length} recorded</span>
                    </div>
                    <div className="asset-connection-stats">
                      <div><strong>{selectedConnections.filter((edge) => edge.target === selectedNode.id).length}</strong><span>Incoming</span></div>
                      <div><strong>{selectedConnections.filter((edge) => edge.source === selectedNode.id).length}</strong><span>Outgoing</span></div>
                      <div><strong>{selectedConnections.length}</strong><span>Total</span></div>
                    </div>
                  </section>

                  <AssetVulnerabilityPanel
                    graphAssetId={selectedNode.id}
                    assetName={selectedNode.name}
                    criticality={selectedNode.criticality}
                  />
                </div>

                <div className="asset-actions">
                  <button type="button" disabled={saving} onClick={startEditing}>
                    Edit Asset
                  </button>
                  <button type="button" className="danger-button" disabled={saving} onClick={() => void removeAsset()}>
                    Delete Asset
                  </button>
                </div>

                <div className="connection-list">
                  <h3>Connected Relationships ({selectedConnections.length})</h3>

                  {selectedConnections.length === 0 ? (
                    <p className="empty">No connections for this asset.</p>
                  ) : selectedConnections.map((edge, index) => {
                    const sourceName = graph?.nodes.find((node) => node.id === edge.source)?.name ?? edge.source;
                    const targetName = graph?.nodes.find((node) => node.id === edge.target)?.name ?? edge.target;

                    return (
                      <div className="connection-item" key={`${edge.source}-${edge.target}-${edge.relationship}-${index}`}>
                        <p><strong>{sourceName}</strong> → <strong>{targetName}</strong></p>
                        <p>{edge.relationship} · {edge.protocol || "No protocol"}</p>
                        <button
                          type="button"
                          className="danger-button"
                          disabled={saving}
                          onClick={() => void removeConnection(edge)}
                        >
                          Delete Connection
                        </button>
                      </div>
                    );
                  })}
                </div>
              </>
            )}
          </aside>
        </section>
          </main>
        </div>
      </div>
      {commandOpen && (
        <div className="nx-command-backdrop" onMouseDown={(event) => {
          if (event.target === event.currentTarget) setCommandOpen(false);
        }}>
          <section className="nx-command-dialog" role="dialog" aria-modal="true" aria-labelledby="nx-command-title">
            <div className="nx-command-heading">
              <div>
                <span>QUICK NAVIGATION</span>
                <h2 id="nx-command-title">Where would you like to go?</h2>
              </div>
              <button type="button" onClick={() => setCommandOpen(false)} aria-label="Close quick navigation">×</button>
            </div>
            <input
              autoFocus
              type="search"
              value={commandQuery}
              onChange={(event) => setCommandQuery(event.target.value)}
              placeholder="Search dashboard, incidents, assets..."
              aria-label="Search project sections"
            />
            <div className="nx-command-results">
              {[
                { id: "overview", label: "Overview", detail: "Dashboard and security summary" },
                { id: "ml-detection", label: "AI Threat Detection", detail: "Machine-learning detection metrics" },
                { id: "network-topology", label: "Network Topology", detail: "Explore connected assets" },
                { id: "vulnerability-intelligence", label: "Vulnerability Intelligence", detail: "Review asset findings" },
                { id: "incidents", label: "Incident Management", detail: "Track and investigate incidents" },
                { id: "security-events", label: "Security Events", detail: "Monitor security activity" },
                { id: "security-intelligence", label: "Threat Intelligence", detail: "Explore security intelligence" },
                { id: "asset-management", label: "Asset Management", detail: "Manage assets and relationships" },
                ...((authUser.role === "ORG_ADMIN" || authUser.role === "SUPER_ADMIN")
                  ? [{ id: "team-management", label: "Team Management", detail: "Manage organization invitations" }]
                  : []),
              ].filter((item) => `${item.label} ${item.detail}`.toLowerCase().includes(commandQuery.trim().toLowerCase())).map((item) => (
                <button key={item.id} type="button" onClick={() => {
                  document.getElementById(item.id)?.scrollIntoView({ behavior: "smooth", block: "start" });
                  setCommandOpen(false);
                  setCommandQuery("");
                  setSidebarOpen(false);
                }}>
                  <span className="nx-command-result-icon">⌕</span>
                  <span><strong>{item.label}</strong><small>{item.detail}</small></span>
                  <kbd>↵</kbd>
                </button>
              ))}
              {[
                { id: "overview", label: "Overview", detail: "Dashboard and security summary" },
                { id: "ml-detection", label: "AI Threat Detection", detail: "Machine-learning detection metrics" },
                { id: "network-topology", label: "Network Topology", detail: "Explore connected assets" },
                { id: "vulnerability-intelligence", label: "Vulnerability Intelligence", detail: "Review asset findings" },
                { id: "incidents", label: "Incident Management", detail: "Track and investigate incidents" },
                { id: "security-events", label: "Security Events", detail: "Monitor security activity" },
                { id: "security-intelligence", label: "Threat Intelligence", detail: "Explore security intelligence" },
                { id: "asset-management", label: "Asset Management", detail: "Manage assets and relationships" },
                ...((authUser.role === "ORG_ADMIN" || authUser.role === "SUPER_ADMIN")
                  ? [{ id: "team-management", label: "Team Management", detail: "Manage organization invitations" }]
                  : []),
              ].filter((item) => `${item.label} ${item.detail}`.toLowerCase().includes(commandQuery.trim().toLowerCase())).length === 0 && (
                <p className="nx-command-empty">No matching sections. Try another search.</p>
              )}
            </div>
            <footer><span><kbd>Ctrl</kbd> + <kbd>K</kbd> to toggle</span><span><kbd>Esc</kbd> to close</span></footer>
          </section>
        </div>
      )}
    </div>
  );
}

export default App;
