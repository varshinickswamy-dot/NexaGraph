"""
NexaGraph AI
Organization-Aware Network Relationship Synchronization

PostgreSQL = Source of Truth
Neo4j = Graph Representation

Supports:
- Global synchronization
- Organization-specific synchronization
- Tenant isolation
- Bidirectional relationships
- Inactive relationship cleanup
- Detailed error reporting
"""

from sqlalchemy import text

from backend.database import engine
from backend.graph_identity import make_graph_asset_key
from backend.neo4j_connection import get_neo4j_driver


ALLOWED_RELATIONSHIPS = {
    "CONNECTS_TO",
    "ALLOWS_TRAFFIC",
    "HOSTED_ON",
    "DEPENDS_ON",
    "PROTECTED_BY",
}


# ==========================================================
# POSTGRESQL QUERY
# ==========================================================

FETCH_RELATIONSHIPS_QUERY = text("""
    SELECT
        nr.id AS relationship_id,
        nr.organization_id,
        nr.relationship_type,
        nr.protocol,
        nr.port,
        nr.direction,
        nr.status,
        nr.description,

        source.organization_id AS source_organization_id,
        target.organization_id AS target_organization_id,

        source.graph_asset_id AS source_asset_id,
        target.graph_asset_id AS target_asset_id

    FROM asset_network_relationships nr

    JOIN assets_metadata source
        ON source.id = nr.source_asset_id

    JOIN assets_metadata target
        ON target.id = nr.target_asset_id

    WHERE (
        CAST(:organization_id AS UUID) IS NULL
        OR nr.organization_id = CAST(:organization_id AS UUID)
    )

    ORDER BY nr.created_at
""")


def fetch_network_relationships(organization_id=None):
    """
    Fetch all relationships or relationships belonging
    to a specific organization.
    """

    with engine.connect() as connection:

        result = connection.execute(
            FETCH_RELATIONSHIPS_QUERY,
            {
                "organization_id": organization_id
            }
        )

        return [
            dict(row._mapping)
            for row in result
        ]


# ==========================================================
# RELATIONSHIP VALIDATION
# ==========================================================

def prepare_relationship(record):
    """Validate and prepare an organization-aware relationship."""

    relationship_type = str(
        record["relationship_type"] or ""
    ).upper()

    if relationship_type not in ALLOWED_RELATIONSHIPS:
        raise ValueError(
            f"Unsupported relationship type: {relationship_type}"
        )

    organization_id = str(
        record["organization_id"]
    )

    source_organization = str(
        record["source_organization_id"]
    )

    target_organization = str(
        record["target_organization_id"]
    )

    # Strict organization isolation.
    if not (
        organization_id
        == source_organization
        == target_organization
    ):
        raise ValueError(
            "Relationship and both assets must belong "
            "to the same organization."
        )

    source_id = str(
        record["source_asset_id"]
    )

    target_id = str(
        record["target_asset_id"]
    )

    if source_id == target_id:
        raise ValueError(
            "Source and target assets cannot be identical."
        )

    direction = str(
        record["direction"] or "OUTBOUND"
    ).upper()

    if direction not in {
        "INBOUND",
        "OUTBOUND",
        "BIDIRECTIONAL",
    }:
        raise ValueError(
            f"Unsupported direction: {direction}"
        )

    status = str(
        record["status"] or "ACTIVE"
    ).upper()

    if status not in {
        "ACTIVE",
        "INACTIVE",
        "PENDING",
    }:
        raise ValueError(
            f"Unsupported relationship status: {status}"
        )

    port = record["port"]

    if port is not None and not 1 <= int(port) <= 65535:
        raise ValueError(
            f"Invalid network port: {port}"
        )

    return {
        "relationship_id": str(
            record["relationship_id"]
        ),

        "organization_id": organization_id,

        "source_key": make_graph_asset_key(
            organization_id,
            source_id
        ),

        "target_key": make_graph_asset_key(
            organization_id,
            target_id
        ),

        "relationship_type": relationship_type,

        "protocol": record["protocol"],

        "port": port,

        "direction": direction,

        "status": status,

        "description": record["description"],
    }


# ==========================================================
# NEO4J SYNCHRONIZATION
# ==========================================================

def synchronize_network_relationships(organization_id=None):
    """
    Synchronize PostgreSQL relationships into Neo4j.

    organization_id=None:
        Synchronize all organizations.

    organization_id=<UUID>:
        Synchronize only the specified organization.
    """

    records = fetch_network_relationships(
        organization_id
    )

    if not records:

        return {
            "status": "success",
            "organization_id": organization_id,
            "total_records": 0,
            "synchronized": 0,
            "inactive_removed": 0,
            "skipped": 0,
            "errors": [],
            "message": "No network relationships available."
        }

    driver = get_neo4j_driver()

    synchronized = 0
    inactive_removed = 0
    skipped = 0

    errors = []

    try:

        with driver.session() as session:

            for record in records:

                try:

                    relationship = prepare_relationship(
                        record
                    )

                    relationship_type = relationship[
                        "relationship_type"
                    ]

                    # --------------------------------------------------
                    # Remove only the matching relationship belonging
                    # to the same organization.
                    # --------------------------------------------------

                    delete_query = """
                        MATCH (
                            source:Asset {
                                graph_key: $source_key
                            }
                        )-[existing]-(target:Asset {
                            graph_key: $target_key
                        })

                        WHERE
                            existing.relationship_id =
                                $relationship_id

                            AND existing.organization_id =
                                $organization_id

                        DELETE existing
                    """

                    def synchronize_transaction(tx):

                        tx.run(
                            delete_query,

                            source_key=relationship[
                                "source_key"
                            ],

                            target_key=relationship[
                                "target_key"
                            ],

                            relationship_id=relationship[
                                "relationship_id"
                            ],

                            organization_id=relationship[
                                "organization_id"
                            ]

                        ).consume()

                        # Inactive and pending relationships
                        # are not represented as active graph edges.

                        if relationship["status"] != "ACTIVE":
                            return "inactive"

                        # --------------------------------------------------
                        # CREATE PRIMARY RELATIONSHIP
                        # --------------------------------------------------

                        create_query = f"""
                            MATCH (source:Asset {{
                                graph_key: $source_key
                            }})

                            MATCH (target:Asset {{
                                graph_key: $target_key
                            }})

                            MERGE (source)-[r:{relationship_type} {{
                                relationship_id: $relationship_id
                            }}]->(target)

                            SET
                                r.organization_id = $organization_id,
                                r.protocol = $protocol,
                                r.port = $port,
                                r.direction = $direction,
                                r.status = $status,
                                r.description = $description,
                                r.last_synchronized = datetime()

                            RETURN r
                        """

                        result = tx.run(
                            create_query,

                            relationship_id=relationship[
                                "relationship_id"
                            ],

                            organization_id=relationship[
                                "organization_id"
                            ],

                            source_key=relationship[
                                "source_key"
                            ],

                            target_key=relationship[
                                "target_key"
                            ],

                            protocol=relationship["protocol"],

                            port=relationship["port"],

                            direction=relationship["direction"],

                            status=relationship["status"],

                            description=relationship["description"],

                        ).single()

                        if not result:
                            return "missing_asset"

                        # --------------------------------------------------
                        # BIDIRECTIONAL RELATIONSHIPS
                        # --------------------------------------------------

                        if (
                            relationship["direction"]
                            == "BIDIRECTIONAL"

                            and relationship_type in {
                                "CONNECTS_TO",
                                "ALLOWS_TRAFFIC",
                            }
                        ):

                            reverse_query = f"""
                                MATCH (source:Asset {{
                                    graph_key: $source_key
                                }})

                                MATCH (target:Asset {{
                                    graph_key: $target_key
                                }})

                                MERGE (target)-[r:{relationship_type} {{
                                    relationship_id: $relationship_id
                                }}]->(source)

                                SET
                                    r.organization_id = $organization_id,
                                    r.protocol = $protocol,
                                    r.port = $port,
                                    r.direction = 'BIDIRECTIONAL',
                                    r.status = $status,
                                    r.description = $description,
                                    r.last_synchronized = datetime()
                            """

                            tx.run(
                                reverse_query,

                                relationship_id=relationship[
                                    "relationship_id"
                                ],

                                organization_id=relationship[
                                    "organization_id"
                                ],

                                source_key=relationship[
                                    "source_key"
                                ],

                                target_key=relationship[
                                    "target_key"
                                ],

                                protocol=relationship["protocol"],

                                port=relationship["port"],

                                direction=relationship["direction"],

                                status=relationship["status"],

                                description=relationship["description"],

                            ).consume()

                        return "synchronized"

                    # Execute each relationship transactionally.
                    result = session.execute_write(
                        synchronize_transaction
                    )

                    if result == "synchronized":

                        synchronized += 1

                    elif result == "inactive":

                        inactive_removed += 1

                    else:

                        skipped += 1

                        errors.append({
                            "relationship_id": relationship[
                                "relationship_id"
                            ],
                            "error": (
                                "Source or target asset "
                                "was not found in Neo4j."
                            )
                        })

                except Exception as exc:

                    skipped += 1

                    errors.append({
                        "relationship_id": str(
                            record["relationship_id"]
                        ),
                        "error": str(exc)
                    })

        # ======================================================
        # RESULT
        # ======================================================

        response = {
            "status": (
                "success"
                if not errors
                else "partial_success"
            ),

            "organization_id": organization_id,

            "total_records": len(records),

            "synchronized": synchronized,

            "inactive_removed": inactive_removed,

            "skipped": skipped,

            "errors": errors,
        }

        print("Network synchronization completed.")

        print(
            f"Organization: {organization_id or 'ALL'}"
        )

        print(
            f"Total records: {len(records)}"
        )

        print(
            f"Synchronized: {synchronized}"
        )

        print(
            f"Inactive removed: {inactive_removed}"
        )

        print(
            f"Skipped: {skipped}"
        )

        return response

    finally:

        # Do not close the shared Neo4j driver.
        pass


# ==========================================================
# EXECUTION
# ==========================================================

if __name__ == "__main__":

    result = synchronize_network_relationships()

    print(result)