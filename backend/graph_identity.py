"""
NexaGraph AI
Organization-aware Neo4j asset identity utilities.

PostgreSQL remains the source of truth.
Neo4j asset identities are scoped to organizations.
"""


def normalize_identifier(value) -> str:
    """Convert an identifier into a consistent string."""
    if value is None:
        raise ValueError("Identifier cannot be None.")

    return str(value).strip()


def make_graph_asset_key(
    organization_id,
    graph_asset_id
) -> str:
    """
    Generate a globally unique graph identity for an asset.

    The same graph_asset_id can exist in different organizations
    without creating collisions.
    """

    org_id = normalize_identifier(organization_id)
    asset_id = normalize_identifier(graph_asset_id)

    if not org_id or not asset_id:
        raise ValueError(
            "Organization ID and graph asset ID are required."
        )

    return f"{org_id}:{asset_id}"


def validate_asset_identity(
    organization_id,
    graph_asset_id
) -> bool:
    """Validate the organization and graph asset identifiers."""

    try:
        make_graph_asset_key(
            organization_id,
            graph_asset_id
        )
        return True

    except (ValueError, TypeError):
        return False