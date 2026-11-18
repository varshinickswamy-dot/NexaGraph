
"""
NexaGraph AI
Organization-Aware Incident Synchronization

PostgreSQL = Source of Truth
Neo4j = Graph Representation

Supports:
- Global synchronization
- Organization-specific synchronization
- Tenant-isolated incidents
- Organization-scoped assignments
- Organization-scoped affected assets
- Organization-scoped investigation notes
"""

from sqlalchemy import text

from backend.database import engine
from backend.graph_identity import make_graph_asset_key
from backend.neo4j_connection import get_neo4j_driver


# ==========================================================
# POSTGRESQL QUERIES
# ==========================================================

FETCH_INCIDENTS_QUERY = text("""
    SELECT
        i.id AS incident_id,
        i.organization_id,
        o.name AS organization_name,
        i.title,
        i.description,
        i.severity,
        i.status,
        i.created_at,
        i.updated_at,
        i.resolved_at,

        creator.id AS creator_id,
        creator.full_name AS creator_name,
        creator.is_active AS creator_active

    FROM incidents i

    JOIN organizations o
        ON o.id = i.organization_id

    LEFT JOIN users creator
        ON creator.id = i.created_by
        AND creator.organization_id = i.organization_id

    WHERE (
        CAST(:organization_id AS UUID) IS NULL
        OR i.organization_id = CAST(:organization_id AS UUID)
    )

    ORDER BY i.created_at
""")


FETCH_ASSIGNMENTS_QUERY = text("""
    SELECT
        ia.id AS assignment_id,
        ia.incident_id,
        ia.user_id,
        u.full_name,
        u.is_active,
        i.organization_id

    FROM incident_assignments ia

    JOIN incidents i
        ON i.id = ia.incident_id

    JOIN users u
        ON u.id = ia.user_id
        AND u.organization_id = i.organization_id

    WHERE (
        CAST(:organization_id AS UUID) IS NULL
        OR i.organization_id = CAST(:organization_id AS UUID)
    )
""")


FETCH_INCIDENT_ASSETS_QUERY = text("""
    SELECT
        ia.incident_id,
        i.organization_id,
        a.graph_asset_id

    FROM incident_assets ia

    JOIN incidents i
        ON i.id = ia.incident_id

    JOIN assets_metadata a
        ON a.id = ia.asset_id
        AND a.organization_id = i.organization_id

    WHERE (
        CAST(:organization_id AS UUID) IS NULL
        OR i.organization_id = CAST(:organization_id AS UUID)
    )
""")


FETCH_INCIDENT_NOTES_QUERY = text("""
    SELECT
        n.id AS note_id,
        n.incident_id,
        n.user_id,
        n.note,
        n.created_at,
        u.full_name AS author_name

    FROM incident_notes n

    JOIN incidents i
        ON i.id = n.incident_id

    LEFT JOIN users u
        ON u.id = n.user_id
        AND u.organization_id = i.organization_id

    WHERE (
        CAST(:organization_id AS UUID) IS NULL
        OR i.organization_id = CAST(:organization_id AS UUID)
    )
""")


# ==========================================================
# DATABASE FETCHING
# ==========================================================

def fetch_query(query, organization_id=None):
    """Execute a parameterized PostgreSQL query."""

    with engine.connect() as connection:

        result = connection.execute(
            query,
            {
                "organization_id": organization_id
            }
        )

        return [
            dict(row._mapping)
            for row in result
        ]


def fetch_incidents(organization_id=None):
    return fetch_query(
        FETCH_INCIDENTS_QUERY,
        organization_id
    )


def fetch_assignments(organization_id=None):
    return fetch_query(
        FETCH_ASSIGNMENTS_QUERY,
        organization_id
    )


def fetch_incident_assets(organization_id=None):
    return fetch_query(
        FETCH_INCIDENT_ASSETS_QUERY,
        organization_id
    )


def fetch_incident_notes(organization_id=None):
    return fetch_query(
        FETCH_INCIDENT_NOTES_QUERY,
        organization_id
    )


# ==========================================================
# DATA PREPARATION
# ==========================================================

def serialize_datetime(value):
    return value.isoformat() if value else None


def prepare_incidents(incidents):

    prepared = []

    for item in incidents:

        organization_id = str(item["organization_id"])
        incident_id = str(item["incident_id"])

        prepared.append({

            "incident_id": incident_id,

            "incident_key": (
                f"{organization_id}:{incident_id}"
            ),

            "organization_id": organization_id,

            "organization_name": item["organization_name"],

            "title": item["title"],

            "description": item["description"],

            "severity": item["severity"],

            "status": item["status"],

            "created_at": serialize_datetime(
                item["created_at"]
            ),

            "updated_at": serialize_datetime(
                item["updated_at"]
            ),

            "resolved_at": serialize_datetime(
                item["resolved_at"]
            ),

            "creator_id": (
                str(item["creator_id"])
                if item["creator_id"] else None
            ),

            "creator_name": item["creator_name"],

            "creator_active": item["creator_active"]

        })

    return prepared


def prepare_assignments(assignments):

    return [

        {
            "assignment_id": str(item["assignment_id"]),

            "incident_id": str(item["incident_id"]),

            "incident_key": (
                f"{item['organization_id']}:{item['incident_id']}"
            ),

            "organization_id": str(item["organization_id"]),

            "user_id": str(item["user_id"]),

            "full_name": item["full_name"],

            "is_active": item["is_active"]
        }

        for item in assignments
    ]


def prepare_incident_assets(incident_assets):

    prepared = []

    for item in incident_assets:

        organization_id = str(item["organization_id"])

        incident_id = str(item["incident_id"])

        prepared.append({

            "incident_id": incident_id,

            "incident_key": (
                f"{organization_id}:{incident_id}"
            ),

            "organization_id": organization_id,

            "asset_key": make_graph_asset_key(
                organization_id,
                item["graph_asset_id"]
            )

        })

    return prepared


def prepare_notes(notes):

    prepared = []

    for item in notes:

        incident_id = str(item["incident_id"])

        # Organization identity is resolved from the
        # parent incident during synchronization.

        prepared.append({

            "note_id": str(item["note_id"]),

            "incident_id": incident_id,

            "user_id": (
                str(item["user_id"])
                if item["user_id"] else None
            ),

            "author_name": item["author_name"],

            "note": item["note"],

            "created_at": serialize_datetime(
                item["created_at"]
            )

        })

    return prepared


# ==========================================================
# NEO4J SYNCHRONIZATION
# ==========================================================

def synchronize_incidents(organization_id=None):
    """
    Synchronize incidents and associated graph relationships.

    organization_id=None:
        Synchronize all organizations.

    organization_id=<UUID>:
        Synchronize one organization's records only.
    """

    incidents = fetch_incidents(organization_id)

    assignments = fetch_assignments(organization_id)

    incident_assets = fetch_incident_assets(
        organization_id
    )

    notes = fetch_incident_notes(organization_id)

    if not incidents:

        return {

            "status": "success",

            "organization_id": organization_id,

            "incidents": 0,

            "assignments": 0,

            "affected_assets": 0,

            "notes": 0,

            "message": "No incidents found."

        }

    prepared_incidents = prepare_incidents(
        incidents
    )

    prepared_assignments = prepare_assignments(
        assignments
    )

    prepared_assets = prepare_incident_assets(
        incident_assets
    )

    prepared_notes = prepare_notes(
        notes
    )

    driver = get_neo4j_driver()

    try:

        with driver.session() as session:

            # --------------------------------------------------
            # 1. ORGANIZATIONS AND INCIDENTS
            # --------------------------------------------------

            incident_result = session.run("""

                UNWIND $records AS item

                MERGE (o:Organization {
                    id: item.organization_id
                })

                SET o.name = item.organization_name

                MERGE (i:Incident {
                    graph_key: item.incident_key
                })

                SET
                    i.id = item.incident_id,
                    i.organization_id = item.organization_id,
                    i.title = item.title,
                    i.description = item.description,
                    i.severity = item.severity,
                    i.status = item.status,
                    i.created_at = item.created_at,
                    i.updated_at = item.updated_at,
                    i.resolved_at = item.resolved_at,
                    i.last_synchronized = datetime()

                MERGE (o)-[:HAS_INCIDENT]->(i)

                WITH i, item

                FOREACH (_ IN CASE
                    WHEN item.creator_id IS NULL THEN []
                    ELSE [1]
                END |

                    MERGE (creator:User {
                        id: item.creator_id
                    })

                    SET
                        creator.full_name = item.creator_name,
                        creator.is_active = item.creator_active

                    MERGE (creator)-[:CREATED]->(i)
                )

                RETURN count(i) AS synchronized

            """, records=prepared_incidents).single()

            synchronized_incidents = (
                incident_result["synchronized"]
                if incident_result else 0
            )

            # --------------------------------------------------
            # 2. INCIDENT ASSIGNMENTS
            # --------------------------------------------------

            if prepared_assignments:

                session.run("""

                    UNWIND $records AS item

                    MATCH (i:Incident {
                        graph_key: item.incident_key
                    })

                    MERGE (u:User {
                        id: item.user_id
                    })

                    SET
                        u.full_name = item.full_name,
                        u.is_active = item.is_active

                    MERGE (i)-[r:ASSIGNED_TO {
                        assignment_id: item.assignment_id
                    }]->(u)

                    SET
                        r.organization_id = item.organization_id,
                        r.last_synchronized = datetime()

                """, records=prepared_assignments).consume()

            # --------------------------------------------------
            # 3. INCIDENT-TO-ASSET RELATIONSHIPS
            # --------------------------------------------------

            if prepared_assets:

                session.run("""

                    UNWIND $records AS item

                    MATCH (i:Incident {
                        graph_key: item.incident_key
                    })

                    MATCH (a:Asset {
                        graph_key: item.asset_key
                    })

                    MERGE (i)-[r:AFFECTS {
                        organization_id: item.organization_id
                    }]->(a)

                    SET
                        r.last_synchronized = datetime()

                """, records=prepared_assets).consume()

            # --------------------------------------------------
            # 4. INVESTIGATION NOTES
            # --------------------------------------------------

            if prepared_notes:

                session.run("""

                    UNWIND $records AS item

                    MATCH (i:Incident {
                        id: item.incident_id
                    })

                    WHERE
                        item.incident_id IS NOT NULL

                    MERGE (n:IncidentNote {
                        id: item.note_id
                    })

                    SET
                        n.note = item.note,
                        n.created_at = item.created_at,
                        n.author_id = item.user_id,
                        n.author_name = item.author_name,
                        n.organization_id = i.organization_id,
                        n.graph_key =
                            i.organization_id + ':' + item.note_id,
                        n.last_synchronized = datetime()

                    MERGE (i)-[:HAS_NOTE]->(n)

                    WITH n, item

                    FOREACH (_ IN CASE
                        WHEN item.user_id IS NULL THEN []
                        ELSE [1]
                    END |

                        MERGE (u:User {
                            id: item.user_id
                        })

                        MERGE (u)-[:AUTHORED]->(n)
                    )

                """, records=prepared_notes).consume()

        # --------------------------------------------------
        # RESULT
        # --------------------------------------------------

        response = {

            "status": (
                "success"
                if synchronized_incidents == len(prepared_incidents)
                else "partial_success"
            ),

            "organization_id": organization_id,

            "incidents": synchronized_incidents,

            "assignments": len(prepared_assignments),

            "affected_assets": len(prepared_assets),

            "notes": len(prepared_notes)

        }

        print("Incident synchronization completed.")

        print(
            f"Organization: {organization_id or 'ALL'}"
        )

        print(
            f"Incidents: {response['incidents']}"
        )

        print(
            f"Assignments: {response['assignments']}"
        )

        print(
            f"Affected assets: {response['affected_assets']}"
        )

        print(
            f"Investigation notes: {response['notes']}"
        )

        return response

    finally:

        # Shared Neo4j driver must remain open.
        pass


# ==========================================================
# EXECUTION
# ==========================================================

if __name__ == "__main__":

    result = synchronize_incidents()

    print(result)