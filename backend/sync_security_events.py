"""
NexaGraph AI
Organization-Aware Security Event Synchronization

PostgreSQL = Source of Truth
Neo4j = Graph Representation

Supports:
- Global synchronization
- Organization-specific synchronization
- Tenant-isolated security events
- Organization-aware asset relationships
- Safe relationship cleanup
- Accurate synchronization reporting
"""

import json

from sqlalchemy import text

from backend.database import engine
from backend.graph_identity import make_graph_asset_key
from backend.neo4j_connection import get_neo4j_driver


# ==========================================================
# POSTGRESQL QUERY
# ==========================================================

FETCH_EVENTS_QUERY = text("""
    SELECT
        se.id AS event_id,
        se.organization_id,
        o.name AS organization_name,
        se.event_type,
        se.severity,
        se.description,
        se.source_ip::text AS source_ip,
        se.destination_ip::text AS destination_ip,
        se.event_data,
        se.occurred_at,

        a.organization_id AS asset_organization_id,
        a.graph_asset_id

    FROM security_events se

    JOIN organizations o
        ON o.id = se.organization_id

    LEFT JOIN assets_metadata a
        ON a.id = se.asset_id

    WHERE (
        CAST(:organization_id AS UUID) IS NULL
        OR se.organization_id = CAST(:organization_id AS UUID)
    )

    ORDER BY se.occurred_at
""")


def fetch_security_events(organization_id=None):
    """Fetch all events or events belonging to one organization."""

    with engine.connect() as connection:

        result = connection.execute(
            FETCH_EVENTS_QUERY,
            {
                "organization_id": organization_id
            }
        )

        return [
            dict(row._mapping)
            for row in result
        ]


# ==========================================================
# EVENT PREPARATION
# ==========================================================

def prepare_event(record):
    """Prepare an organization-aware security event."""

    organization_id = str(
        record["organization_id"]
    )

    asset_key = None

    if record["graph_asset_id"] is not None:

        if (
            record["asset_organization_id"] is None
            or str(record["asset_organization_id"])
            != organization_id
        ):
            raise ValueError(
                "Security event and associated asset "
                "belong to different organizations."
            )

        asset_key = make_graph_asset_key(
            organization_id,
            record["graph_asset_id"]
        )

    event_id = str(record["event_id"])

    return {

        "event_id": event_id,

        "event_key": (
            f"{organization_id}:{event_id}"
        ),

        "organization_id": organization_id,

        "organization_name": record["organization_name"],

        "event_type": record["event_type"],

        "severity": record["severity"],

        "description": record["description"],

        "source_ip": record["source_ip"],

        "destination_ip": record["destination_ip"],

        "event_data": json.dumps(
            record["event_data"] or {},
            default=str
        ),

        "occurred_at": (
            record["occurred_at"].isoformat()
            if record["occurred_at"]
            else None
        ),

        "asset_key": asset_key,

    }


# ==========================================================
# NEO4J SYNCHRONIZATION
# ==========================================================

def synchronize_security_events(organization_id=None):
    """
    Synchronize PostgreSQL security events into Neo4j.

    organization_id=None:
        Synchronize all organizations.

    organization_id=<UUID>:
        Synchronize only the specified organization.
    """

    records = fetch_security_events(
        organization_id
    )

    if not records:

        print("No security events found.")

        return {

            "status": "success",

            "organization_id": organization_id,

            "total_events": 0,

            "synchronized": 0,

            "linked_assets": 0,

            "unlinked_assets": 0,

            "errors": [],

            "message": "No security events available."

        }

    prepared = []

    errors = []

    # ------------------------------------------------------
    # Prepare and validate records.
    # ------------------------------------------------------

    for record in records:

        try:

            prepared.append(
                prepare_event(record)
            )

        except Exception as exc:

            errors.append({

                "event_id": str(record["event_id"]),

                "error": str(exc)

            })

    if not prepared:

        return {

            "status": "failed",

            "organization_id": organization_id,

            "total_events": len(records),

            "synchronized": 0,

            "linked_assets": 0,

            "unlinked_assets": 0,

            "errors": errors

        }

    driver = get_neo4j_driver()

    # ======================================================
    # CYPHER QUERY
    # ======================================================

    query = """

        UNWIND $records AS item

        MERGE (o:Organization {
            id: item.organization_id
        })

        SET
            o.name = item.organization_name

        MERGE (e:SecurityEvent {
            graph_key: item.event_key
        })

        SET
            e.id = item.event_id,
            e.organization_id = item.organization_id,
            e.event_type = item.event_type,
            e.severity = item.severity,
            e.description = item.description,
            e.source_ip = item.source_ip,
            e.destination_ip = item.destination_ip,
            e.event_data = item.event_data,
            e.occurred_at = item.occurred_at,
            e.last_synchronized = datetime()

        MERGE (o)-[:GENERATED_EVENT]->(e)

        WITH e, item

        // Remove only relationships belonging to
        // the same organization.

        OPTIONAL MATCH
            (old:Asset)-[old_rel:HAS_SECURITY_EVENT]->(e)

        WHERE
            old_rel.organization_id = item.organization_id

        DELETE old_rel

        WITH e, item

        // Find an asset belonging to this organization.

        OPTIONAL MATCH (a:Asset {
            graph_key: item.asset_key
        })

        WHERE
            a.organization_id = item.organization_id

        FOREACH (_ IN CASE
            WHEN a IS NULL THEN []
            ELSE [1]
        END |

            MERGE (a)-[r:HAS_SECURITY_EVENT {
                event_key: item.event_key
            }]->(e)

            SET
                r.organization_id = item.organization_id,
                r.last_synchronized = datetime()
        )

        RETURN
            count(e) AS synchronized,

            sum(
                CASE
                    WHEN a IS NOT NULL THEN 1
                    ELSE 0
                END
            ) AS linked_assets,

            sum(
                CASE
                    WHEN item.asset_key IS NOT NULL
                    AND a IS NULL THEN 1
                    ELSE 0
                END
            ) AS unlinked_assets

    """

    # ======================================================
    # EXECUTION
    # ======================================================

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

            linked_assets = (
                result["linked_assets"]
                if result else 0
            )

            unlinked_assets = (
                result["unlinked_assets"]
                if result else 0
            )

        # ==================================================
        # RESULT
        # ==================================================

        response = {

            "status": (
                "success"
                if (
                    not errors
                    and synchronized == len(prepared)
                    and unlinked_assets == 0
                )
                else "partial_success"
            ),

            "organization_id": organization_id,

            "total_events": len(records),

            "synchronized": synchronized,

            "linked_assets": linked_assets,

            "unlinked_assets": unlinked_assets,

            "errors": errors

        }

        print("Security event synchronization completed.")

        print(
            f"Organization: {organization_id or 'ALL'}"
        )

        print(
            f"Total events: {len(records)}"
        )

        print(
            f"Synchronized: {synchronized}"
        )

        print(
            f"Linked assets: {linked_assets}"
        )

        print(
            f"Unlinked assets: {unlinked_assets}"
        )

        print(
            f"Errors: {len(errors)}"
        )

        return response

    except Exception as exc:

        print(
            f"Security event synchronization failed: {exc}"
        )

        raise


# ==========================================================
# EXECUTION
# ==========================================================

if __name__ == "__main__":

    result = synchronize_security_events()

    print(result)