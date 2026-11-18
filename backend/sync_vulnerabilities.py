"""
NexaGraph AI
Organization-Aware Vulnerability Synchronization

PostgreSQL = Source of Truth
Neo4j = Organization-Isolated Graph Representation

Supports:
- Global synchronization
- Organization-specific synchronization
- Tenant-isolated vulnerability nodes
- Accurate unmatched asset reporting
- Idempotent graph synchronization
"""

from sqlalchemy import text

from backend.database import engine
from backend.graph_identity import make_graph_asset_key
from backend.neo4j_connection import get_neo4j_driver


# ==========================================================
# POSTGRESQL QUERY
# ==========================================================

FETCH_VULNERABILITIES = text("""
    SELECT
        av.id AS mapping_id,
        av.status,
        av.detected_at,
        av.resolved_at,

        a.organization_id,
        a.graph_asset_id,

        v.id AS vulnerability_id,
        v.cve_id,
        v.title,
        v.description,
        v.cvss_score,
        v.severity,
        v.source

    FROM asset_vulnerabilities av

    JOIN assets_metadata a
        ON a.id = av.asset_id

    JOIN vulnerabilities v
        ON v.id = av.vulnerability_id

    WHERE (
        CAST(:organization_id AS UUID) IS NULL
        OR a.organization_id = CAST(:organization_id AS UUID)
    )

    ORDER BY av.detected_at
""")


def fetch_vulnerability_data(organization_id=None):
    """Fetch all vulnerability mappings or one organization's mappings."""

    with engine.connect() as connection:

        result = connection.execute(
            FETCH_VULNERABILITIES,
            {
                "organization_id": organization_id
            }
        )

        return [
            dict(row._mapping)
            for row in result
        ]


# ==========================================================
# RECORD PREPARATION
# ==========================================================

def prepare_records(records):
    """Prepare organization-aware vulnerability records."""

    prepared = []

    for record in records:

        organization_id = str(
            record["organization_id"]
        )

        vulnerability_id = str(
            record["vulnerability_id"]
        )

        # Organization-specific graph identity.
        vulnerability_key = (
            f"{organization_id}:{vulnerability_id}"
        )

        prepared.append({

            "mapping_id": str(
                record["mapping_id"]
            ),

            "organization_id": organization_id,

            "asset_key": make_graph_asset_key(
                organization_id,
                record["graph_asset_id"]
            ),

            "vulnerability_id": vulnerability_id,

            "vulnerability_key": vulnerability_key,

            "cve_id": record["cve_id"],

            "title": record["title"],

            "description": record["description"],

            "cvss_score": (
                float(record["cvss_score"])
                if record["cvss_score"] is not None
                else None
            ),

            "severity": record["severity"],

            "source": record["source"],

            "status": (
                str(record["status"]).upper()
                if record["status"]
                else "UNKNOWN"
            ),

            "detected_at": (
                record["detected_at"].isoformat()
                if record["detected_at"]
                else None
            ),

            "resolved_at": (
                record["resolved_at"].isoformat()
                if record["resolved_at"]
                else None
            )
        })

    return prepared


# ==========================================================
# NEO4J SYNCHRONIZATION
# ==========================================================

def synchronize_vulnerabilities(organization_id=None):
    """
    Synchronize PostgreSQL vulnerabilities into Neo4j.

    organization_id=None:
        Synchronize all organizations.

    organization_id=<UUID>:
        Synchronize only the specified organization.
    """

    records = fetch_vulnerability_data(
        organization_id
    )

    if not records:

        return {
            "status": "success",
            "organization_id": organization_id,
            "total_records": 0,
            "synchronized": 0,
            "unmatched_assets": 0,
            "message": "No vulnerability mappings found."
        }

    prepared = prepare_records(records)

    driver = get_neo4j_driver()

    query = """
        UNWIND $records AS item

        OPTIONAL MATCH (a:Asset {
            graph_key: item.asset_key
        })

        FOREACH (_ IN CASE
            WHEN a IS NULL THEN []
            ELSE [1]
        END |

            MERGE (v:Vulnerability {
                graph_key: item.vulnerability_key
            })

            SET
                v.id = item.vulnerability_id,
                v.organization_id = item.organization_id,
                v.cve_id = item.cve_id,
                v.title = item.title,
                v.description = item.description,
                v.cvss_score = item.cvss_score,
                v.severity = item.severity,
                v.source = item.source,
                v.last_synchronized = datetime()

            MERGE (a)-[r:HAS_VULNERABILITY {
                mapping_id: item.mapping_id
            }]->(v)

            SET
                r.organization_id = item.organization_id,
                r.status = item.status,
                r.detected_at = item.detected_at,
                r.resolved_at = item.resolved_at,
                r.last_synchronized = datetime()
        )

        RETURN
            count(item) AS total_records,

            sum(
                CASE
                    WHEN a IS NULL THEN 0
                    ELSE 1
                END
            ) AS synchronized,

            sum(
                CASE
                    WHEN a IS NULL THEN 1
                    ELSE 0
                END
            ) AS unmatched_assets
    """

    try:

        with driver.session() as session:

            result = session.run(
                query,
                records=prepared
            ).single()

            synchronized = (
                result["synchronized"]
                if result else 0
            )

            unmatched_assets = (
                result["unmatched_assets"]
                if result else len(prepared)
            )

        response = {

            "status": (
                "success"
                if unmatched_assets == 0
                else "partial_success"
            ),

            "organization_id": organization_id,

            "total_records": len(prepared),

            "synchronized": synchronized,

            "unmatched_assets": unmatched_assets
        }

        print("Vulnerability synchronization completed.")

        print(
            f"Organization: {organization_id or 'ALL'}"
        )

        print(
            f"Total mappings: {len(prepared)}"
        )

        print(
            f"Synchronized: {synchronized}"
        )

        print(
            f"Unmatched assets: {unmatched_assets}"
        )

        return response

    except Exception as exc:

        print(
            f"Vulnerability synchronization failed: {exc}"
        )

        raise


# ==========================================================
# EXECUTION
# ==========================================================

if __name__ == "__main__":

    result = synchronize_vulnerabilities()

    print(result)