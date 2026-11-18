"""
NexaGraph AI
Organization-Aware Asset Synchronization

PostgreSQL = Source of Truth
Neo4j = Graph Representation
"""

from sqlalchemy import text

from backend.database import engine
from backend.graph_identity import make_graph_asset_key
from backend.neo4j_connection import get_neo4j_driver


FETCH_ASSETS_QUERY = text("""
    SELECT
        id AS postgres_asset_id,
        organization_id,
        graph_asset_id,
        asset_name,
        asset_type,
        ip_address::text AS ip_address,
        operating_system,
        environment,
        criticality
    FROM assets_metadata
    WHERE (
        CAST(:organization_id AS UUID) IS NULL
        OR organization_id = CAST(:organization_id AS UUID)
    )
    ORDER BY organization_id, graph_asset_id
""")


def fetch_postgres_assets(organization_id=None):
    """Fetch all assets or assets belonging to one organization."""

    with engine.connect() as connection:
        result = connection.execute(
            FETCH_ASSETS_QUERY,
            {"organization_id": organization_id}
        )

        return [
            dict(row._mapping)
            for row in result
        ]


def prepare_asset_records(assets):
    """Prepare organization-aware Neo4j asset records."""

    prepared = []

    for asset in assets:

        organization_id = str(asset["organization_id"])
        graph_asset_id = str(asset["graph_asset_id"])

        graph_key = make_graph_asset_key(
            organization_id,
            graph_asset_id
        )

        criticality = (
            str(asset["criticality"]).upper()
            if asset["criticality"]
            else "MEDIUM"
        )

        prepared.append({
            "graph_key": graph_key,
            "id": graph_key,
            "postgres_asset_id": str(
                asset["postgres_asset_id"]
            ),
            "organization_id": organization_id,
            "graph_asset_id": graph_asset_id,
            "name": asset["asset_name"],
            "type": asset["asset_type"],
            "ip": asset["ip_address"] or "",
            "operating_system": asset["operating_system"],
            "environment": asset["environment"],
            "criticality": criticality,
        })

    return prepared


def synchronize_assets(organization_id=None):
    """
    Synchronize PostgreSQL assets into Neo4j.

    organization_id=None:
        Synchronize all organizations.

    organization_id=<UUID>:
        Synchronize only the specified organization.
    """

    assets = fetch_postgres_assets(organization_id)

    if not assets:
        return {
            "status": "success",
            "total_postgres_assets": 0,
            "synchronized": 0,
            "failed": 0,
            "organization_id": organization_id,
            "message": "No assets available."
        }

    records = prepare_asset_records(assets)

    driver = get_neo4j_driver()

    query = """
        UNWIND $assets AS asset

        MERGE (a:Asset {graph_key: asset.graph_key})

        SET
            a.id = asset.id,
            a.postgres_asset_id = asset.postgres_asset_id,
            a.organization_id = asset.organization_id,
            a.graph_asset_id = asset.graph_asset_id,
            a.name = asset.name,
            a.type = asset.type,
            a.ip = asset.ip,
            a.operating_system = asset.operating_system,
            a.environment = asset.environment,
            a.criticality = asset.criticality,
            a.exposed = coalesce(a.exposed, 'No'),
            a.compromised = coalesce(a.compromised, 'No'),
            a.last_synchronized = datetime()

        RETURN count(a) AS synchronized
    """

    with driver.session() as session:

        result = session.run(
            query,
            assets=records
        ).single()

        synchronized = (
            result["synchronized"]
            if result else 0
        )

    return {
        "status": (
            "success"
            if synchronized == len(records)
            else "partial_success"
        ),
        "organization_id": organization_id,
        "total_postgres_assets": len(assets),
        "synchronized": synchronized,
        "failed": len(records) - synchronized
    }


if __name__ == "__main__":

    result = synchronize_assets()

    print(result)