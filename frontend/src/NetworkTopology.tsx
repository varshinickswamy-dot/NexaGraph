import { useCallback, useEffect, useRef, useState } from "react";
import cytoscape from "cytoscape";
import { authenticatedFetch } from "./api";

type TopologyNode = {
  id: string;
  database_id: string;
  name: string;
  type: string | null;
  ip_address: string | null;
  criticality: string | null;
  environment: string | null;
  vulnerability_count?: number;
  active_vulnerability_count?: number;
  vulnerability_risk_score?: number;
  vulnerability_risk_level?: string;
};

type TopologyEdge = {
  id: string;
  source: string;
  target: string;
  relationship_type: string;
  protocol: string | null;
  port: number | null;
  direction: string;
  status: string;
  description: string | null;
};

type TopologyResponse = {
  success: boolean;
  summary: {
    total_assets: number;
    total_relationships: number;
  };
  nodes: TopologyNode[];
  edges: TopologyEdge[];
};

type NetworkTopologyProps = {
  theme?: "dark" | "light";
};

type VulnerabilityRow = {
  graph_asset_id: string;
  severity: string;
  status: string;
};

type VulnerabilityListResponse = {
  success: boolean;
  findings: VulnerabilityRow[];
};

const ACTIVE_VULNERABILITY_STATUSES = new Set(["OPEN", "IN_PROGRESS"]);
const VULNERABILITY_POINTS: Record<string, number> = {
  CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1,
};
const ASSET_CRITICALITY_MULTIPLIER: Record<string, number> = {
  LOW: 1, MEDIUM: 1.15, HIGH: 1.3, CRITICAL: 1.5,
};

async function addVulnerabilityRisk(result: TopologyResponse): Promise<TopologyResponse> {
  try {
    const response = await authenticatedFetch("/vulnerabilities?limit=500&offset=0");
    if (!response.ok) return result;
    const payload = (await response.json()) as VulnerabilityListResponse;
    if (!payload.success || !Array.isArray(payload.findings)) return result;

    const findingsByAsset = new Map<string, VulnerabilityRow[]>();
    payload.findings.forEach((finding) => {
      const key = String(finding.graph_asset_id ?? "");
      if (!key) return;
      const current = findingsByAsset.get(key) ?? [];
      current.push(finding);
      findingsByAsset.set(key, current);
    });

    return {
      ...result,
      nodes: result.nodes.map((node) => {
        const findings = findingsByAsset.get(String(node.id)) ?? [];
        const active = findings.filter((finding) =>
          ACTIVE_VULNERABILITY_STATUSES.has(String(finding.status).toUpperCase())
        );
        const points = active.reduce(
          (sum, finding) =>
            sum + (VULNERABILITY_POINTS[String(finding.severity).toUpperCase()] ?? 0),
          0
        );
        const multiplier =
          ASSET_CRITICALITY_MULTIPLIER[String(node.criticality ?? "").toUpperCase()] ?? 1;
        const score = Math.min(100, Math.round(points * multiplier));
        const level =
          score >= 80 ? "CRITICAL" :
          score >= 60 ? "HIGH" :
          score >= 35 ? "MEDIUM" : "LOW";
        return {
          ...node,
          vulnerability_count: findings.length,
          active_vulnerability_count: active.length,
          vulnerability_risk_score: score,
          vulnerability_risk_level: level,
        };
      }),
    };
  } catch {
    // Keep topology usable if the optional vulnerability summary is unavailable.
    return result;
  }
}

export default function NetworkTopology({ theme = "dark" }: NetworkTopologyProps) {
  const graphRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  const [data, setData] = useState<TopologyResponse | null>(null);
  const [selectedNode, setSelectedNode] =
    useState<TopologyNode | null>(null);

  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // =====================================================
  // LOAD NETWORK TOPOLOGY
  // =====================================================

  const loadTopology = useCallback(async () => {
    try {
      setLoading(true);
      setError("");

      const response = await authenticatedFetch("/network/topology");

      if (!response.ok) {
        throw new Error(
          `Unable to load network topology. Server returned ${response.status}.`
        );
      }

      const result: TopologyResponse = await response.json();

      if (
        !result.success ||
        !Array.isArray(result.nodes) ||
        !Array.isArray(result.edges)
      ) {
        throw new Error("Invalid network topology response.");
      }

      const enrichedResult = await addVulnerabilityRisk(result);
      setData(enrichedResult);
      setSelectedNode(null);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to load network topology."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  // =====================================================
  // INITIAL DATA LOAD
  // =====================================================

  useEffect(() => {
    let cancelled = false;

    const fetchInitialTopology = async () => {
      try {
        const response = await authenticatedFetch("/network/topology");

        if (!response.ok) {
          throw new Error(
            `Unable to load network topology. Server returned ${response.status}.`
          );
        }

        const result: TopologyResponse = await response.json();

        if (
          !result.success ||
          !Array.isArray(result.nodes) ||
          !Array.isArray(result.edges)
        ) {
          throw new Error("Invalid network topology response.");
        }

        const enrichedResult = await addVulnerabilityRisk(result);

        if (!cancelled) {
          setData(enrichedResult);
          setError("");
        }
      } catch (err) {
        if (!cancelled) {
          setError(
            err instanceof Error
              ? err.message
              : "Unable to load network topology."
          );
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    void fetchInitialTopology();

    return () => {
      cancelled = true;
    };
  }, []);

  // =====================================================
  // CREATE CYTOSCAPE NETWORK GRAPH
  // =====================================================

  useEffect(() => {
    if (!data || !graphRef.current) return;

    const validNodeIds = new Set(data.nodes.map((node) => node.id));

    const elements: cytoscape.ElementDefinition[] = [
      ...data.nodes.map((node) => ({
        data: {
          id: node.id,
          label: node.name,
          type: node.type ?? "Unknown",
          criticality: (node.criticality ?? "Unknown").trim().toUpperCase(),
          ip: node.ip_address ?? "Not available",
          environment: node.environment ?? "Unknown",
          vulnerabilityRisk: node.vulnerability_risk_level ?? "UNKNOWN",
          vulnerabilityRiskScore: node.vulnerability_risk_score ?? 0,
          activeVulnerabilities: node.active_vulnerability_count ?? 0,
        },
      })),

      ...data.edges
        .filter(
          (edge) =>
            validNodeIds.has(edge.source) &&
            validNodeIds.has(edge.target)
        )
        .map((edge) => ({
          data: {
            id: edge.id,
            source: edge.source,
            target: edge.target,
            label: `${edge.relationship_type}\n${edge.protocol ?? ""} ${
              edge.port ?? ""
            }`,
            relationship: edge.relationship_type,
            protocol: edge.protocol ?? "",
            port: edge.port ?? "",
            direction: edge.direction,
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
    label: "data(label)",

    "background-color": "#2563eb",

    color: theme === "light" ? "#172b4d" : "#f8fafc",

    "text-valign": "bottom",
    "text-halign": "center",
    "text-margin-y": 9,

    "font-size": 10,
    "font-weight": 700,

    width: 42,
    height: 42,

    "border-width": 2,
    "border-color": theme === "light" ? "#5476b8" : "#60a5fa",

    "text-wrap": "wrap",
    "text-max-width": "100px",

    "text-outline-color": theme === "light" ? "#f0eee8": "#0c1527",
    "text-outline-width": 2,
  },
},
        {
          selector: 'node[criticality = "CRITICAL"]',
          style: {
            "background-color": "#991b1b",
            "border-color": "#ef4444",
            width: 52,
            height: 52,
          },
        },

        {
          selector: 'node[criticality = "HIGH"]',
          style: {
            "background-color": "#b45309",
            "border-color": "#fbbf24",
          },
        },

        {
          selector: 'node[criticality = "MEDIUM"]',
          style: {
            "background-color": "#475569",
            "border-color": "#94a3b8",
          },
        },

        {
          selector: 'node[vulnerabilityRisk = "CRITICAL"][activeVulnerabilities > 0]',
          style: {
            "border-color": "#ff4d5e",
            "border-width": 6,
            "underlay-color": "#ff4d5e",
            "underlay-opacity": 0.22,
            "underlay-padding": 8,
          },
        },
        {
          selector: 'node[vulnerabilityRisk = "HIGH"][activeVulnerabilities > 0]',
          style: {
            "border-color": "#ffad70",
            "border-width": 5,
            "underlay-color": "#ffad70",
            "underlay-opacity": 0.16,
            "underlay-padding": 6,
          },
        },

        {
  selector: "edge",
  style: {
    width: 2,

    "line-color": theme === "light" ? "#64748b" : "#94a3b8",
    "target-arrow-color": theme === "light" ? "#64748b": "#00d4ff",

    "target-arrow-shape": "triangle",
    "target-arrow-fill": "filled",

    "curve-style": "bezier",

    label: "data(label)",

    color: theme === "light" ? "#263449" : "#cbd5e1",

    "font-size": 9,

    "text-background-color": theme === "light" ? "#ffffff" : "#111827",
    "text-background-opacity": 0.95,
    "text-background-padding": "3px",
  },
},

        {
          selector: "node:selected",
          style: {
            "border-color": "#00d4ff",
            "border-width": 5,
          },
        },

        {
          selector: ".topology-dim",
          style: {
            opacity: 0.15,
          },
        },

        {
          selector: ".topology-match",
          style: {
            "border-color": "#00d4ff",
            "border-width": 5,
            opacity: 1,
          },
        },
      ],

      layout: {
  name: "cose",
  animate: false,
  fit: true,
  padding: 35,
  nodeRepulsion: () => 18000,
  idealEdgeLength: () => 180,
  componentSpacing: 160,
  nodeOverlap: 20,
  gravity: 0.15,
  numIter: 1500,
  initialTemp: 200,
  coolingFactor: 0.95,
  minTemp: 1,
},
    });

    cyRef.current = cy;
    // Automatically resize the graph when its container changes.
const resizeObserver = new ResizeObserver(() => {
  if (!cy.destroyed()) {
    cy.resize();
  }
});

resizeObserver.observe(graphRef.current!);

cy.one("layoutstop", () => {
  if (!cy.destroyed()) {
    cy.resize();
    cy.fit(cy.elements(), 45);
  }
});

resizeObserver.observe(graphRef.current!);

    // Select asset
    cy.on("tap", "node", (event) => {
      const node = data.nodes.find(
        (item) => item.id === event.target.id()
      );

      setSelectedNode(node ?? null);
    });

    // Clear selection when clicking empty graph area
    cy.on("tap", (event) => {
      if (event.target === cy) {
        setSelectedNode(null);
      }
    });

    return () => {
  resizeObserver.disconnect();
  cy.destroy();
  cyRef.current = null;
};
  }, [data, theme]);

  // =====================================================
  // SEARCH NETWORK ASSETS
  // =====================================================

  useEffect(() => {
    const cy = cyRef.current;

    if (!cy) return;

    const query = search.trim().toLowerCase();

    cy.elements().removeClass("topology-match topology-dim");

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

    cy.elements().addClass("topology-dim");

    matches
      .removeClass("topology-dim")
      .addClass("topology-match");

    matches.connectedEdges().removeClass("topology-dim");

    if (matches.length > 0) {
      cy.animate({
        fit: {
          eles: matches,
          padding: 80,
        },
        duration: 250,
      });
    }
  }, [search, data]);

  // =====================================================
  // RESET GRAPH VIEW
  // =====================================================

  function resetView() {
    const cy = cyRef.current;

    if (cy) {
      cy.elements().removeClass("topology-match topology-dim");
      cy.fit(undefined, 50);
    }

    setSearch("");
    setSelectedNode(null);
  }

  // =====================================================
  // REFRESH TOPOLOGY
  // =====================================================

  async function handleRefresh() {
    await loadTopology();
  }

  // =====================================================
  // USER INTERFACE
  // =====================================================

  return (
    <section className="topology-panel">

      {/* HEADER */}

      <div className="topology-header">
        <div>
          <h2>Network Topology Intelligence</h2>

          <p>
            Database-backed visualization of enterpriseassets
            and their recorded network relationships.
          </p>
        </div>

        <span className="topology-live">DATABASE SYNC</span>
      </div>

      {/* STATISTICS */}

      {data && (
        <div className="topology-stats">

          <div>
            <span>Total Assets</span>
            <strong>{data.summary.total_assets}</strong>
          </div>

          <div>
            <span>Active Relationships</span>
            <strong>{data.summary.total_relationships}</strong>
          </div>

          <div>
            <span>Critical Assets</span>
            <strong>
              {
                data.nodes.filter(
                  (node) =>
                    node.criticality?.trim().toUpperCase() === "CRITICAL"
                ).length
              }
            </strong>
          </div>

          <div>
            <span>High Vulnerability Risk</span>
            <strong>
              {
                data.nodes.filter(
                  (node) =>
                    (node.active_vulnerability_count ?? 0) > 0 &&
                    ["HIGH", "CRITICAL"].includes(node.vulnerability_risk_level ?? "")
                ).length
              }
            </strong>
          </div>

        </div>
      )}

      {/* TOOLBAR */}

      <div className="topology-toolbar">

        <input
          type="search"
          placeholder="Search assets, IP addresses or types..."
          value={search}
          onChange={(event) => setSearch(event.target.value)}
        />

        <button
          type="button"
          onClick={resetView}
        >
          Reset View
        </button>

        <button
          type="button"
          onClick={handleRefresh}
          disabled={loading}
        >
          {loading ? "Loading..." : "Refresh"}
        </button>

      </div>

      {/* ERROR MESSAGE */}

      {error && (
        <div className="error" role="alert">
          {error}
        </div>
      )}

      {/* LOADING MESSAGE */}

      {loading && (
        <div className="loading">
          Loading enterprise network topology...
        </div>
      )}

      {/* NETWORK GRAPH AND DETAILS */}

      <div className="topology-workspace">

        <div
          ref={graphRef}
          className="topology-graph"
          aria-label="Interactive enterprise network topology"
        />

        {/* ASSET DETAILS */}

        <aside className="topology-details">

          <h3>Asset Intelligence</h3>

          {!selectedNode ? (
            <p className="empty">
              Select an asset in the graph to view its details.
            </p>
          ) : (
            <>
              <h4>{selectedNode.name}</h4>

              {[
                ["Asset ID", selectedNode.id],
                ["Database ID", selectedNode.database_id],
                ["Type", selectedNode.type],
                ["IP Address", selectedNode.ip_address],
                ["Criticality", selectedNode.criticality],
                ["Environment", selectedNode.environment],
                ["Total vulnerabilities", selectedNode.vulnerability_count ?? 0],
                ["Active vulnerabilities", selectedNode.active_vulnerability_count ?? 0],
                ["Vulnerability risk", selectedNode.vulnerability_risk_level ?? "Not assessed"],
                ["Vulnerability risk score", selectedNode.vulnerability_risk_score ?? "—"],
              ].map(([label, value]) => (
                <div
                  className="topology-detail-row"
                  key={label}
                >
                  <span>{label}</span>

                  <strong>
                    {value || "Not available"}
                  </strong>
                </div>
              ))}
            </>
          )}

        </aside>

      </div>

      {/* GRAPH LEGEND */}

      <div className="topology-legend">

        <span>
          <i className="topology-normal" />
          Normal Asset
        </span>

        <span>
          <i className="topology-high" />
          High Criticality
        </span>

        <span>
          <i className="topology-critical" />
          Critical Asset
        </span>

        <span>
          <i className="topology-critical" />
          Critical vulnerability risk
        </span>

        <span>
          <i className="topology-edge" />
          Network Connection
        </span>

      </div>

    </section>
  );
}
