import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from backend.auth_routes import get_current_user, require_roles
from backend.database import engine

# =========================================================
# NexaGraph AI - Network Relationship Management
# Tenant-safe PostgreSQL network topology API
# =========================================================

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/network",
    tags=["Network Relationships"],
)

ALLOWED_RELATIONSHIPS = {
    "CONNECTS_TO",
    "ALLOWS_TRAFFIC",
    "HOSTED_ON",
    "DEPENDS_ON",
    "PROTECTED_BY",
}
ALLOWED_DIRECTIONS = {"INBOUND", "OUTBOUND", "BIDIRECTIONAL"}
ALLOWED_STATUSES = {"ACTIVE", "INACTIVE", "PENDING"}

NETWORK_WRITE_ROLES = ("SUPER_ADMIN", "ORG_ADMIN", "SECURITY_ANALYST")
NETWORK_ADMIN_ROLES = ("SUPER_ADMIN", "ORG_ADMIN")


class NetworkRelationshipInput(BaseModel):
    organization_id: UUID
    source_asset_id: UUID
    target_asset_id: UUID
    relationship_type: str = Field(min_length=1, max_length=50)
    protocol: str = Field(default="TCP", max_length=30)
    port: int | None = Field(default=None, ge=1, le=65535)
    direction: str = "OUTBOUND"
    status: str = "ACTIVE"
    description: str | None = None


def resolve_organization_scope(
    requested_org_id: UUID | None,
    current_user: dict,
) -> str | None:
    """
    SUPER_ADMIN may request one organization or all organizations.
    Every other role is strictly restricted to its own organization.
    """
    role = str(current_user.get("role", "")).upper()
    own_org_id = current_user.get("organization_id")

    if role == "SUPER_ADMIN":
        return str(requested_org_id) if requested_org_id else None

    if not own_org_id:
        raise HTTPException(
            status_code=403,
            detail="Your account is not assigned to an organization.",
        )

    if requested_org_id and str(requested_org_id) != str(own_org_id):
        # Do not disclose whether another tenant exists.
        raise HTTPException(
            status_code=404,
            detail="Network resource not found.",
        )

    return str(own_org_id)


def validate_relationship_input(data: NetworkRelationshipInput) -> tuple[str, str, str]:
    relationship_type = data.relationship_type.strip().upper()
    direction = data.direction.strip().upper()
    status = data.status.strip().upper()

    if relationship_type not in ALLOWED_RELATIONSHIPS:
        raise HTTPException(status_code=400, detail="Invalid relationship type.")
    if direction not in ALLOWED_DIRECTIONS:
        raise HTTPException(status_code=400, detail="Invalid relationship direction.")
    if status not in ALLOWED_STATUSES:
        raise HTTPException(status_code=400, detail="Invalid relationship status.")
    if data.source_asset_id == data.target_asset_id:
        raise HTTPException(
            status_code=400,
            detail="Source and target assets must differ.",
        )

    return relationship_type, direction, status


# =========================================================
# CREATE NETWORK RELATIONSHIP
# =========================================================

@router.post("/relationships", status_code=201)
def create_network_relationship(
    data: NetworkRelationshipInput,
    current_user: dict = Depends(require_roles(*NETWORK_WRITE_ROLES)),
):
    org_id = resolve_organization_scope(data.organization_id, current_user)
    relationship_type, direction, status = validate_relationship_input(data)

    try:
        with engine.begin() as connection:
            assets = connection.execute(
                text(
                    """
                    SELECT id
                    FROM assets_metadata
                    WHERE id IN (
                        CAST(:source_id AS UUID),
                        CAST(:target_id AS UUID)
                    )
                    AND organization_id = CAST(:organization_id AS UUID)
                    """
                ),
                {
                    "source_id": str(data.source_asset_id),
                    "target_id": str(data.target_asset_id),
                    "organization_id": org_id,
                },
            ).mappings().all()

            if len(assets) != 2:
                raise HTTPException(
                    status_code=404,
                    detail="Source or target asset not found in this organization.",
                )

            result = connection.execute(
                text(
                    """
                    INSERT INTO asset_network_relationships (
                        organization_id,
                        source_asset_id,
                        target_asset_id,
                        relationship_type,
                        protocol,
                        port,
                        direction,
                        status,
                        description
                    )
                    VALUES (
                        CAST(:organization_id AS UUID),
                        CAST(:source_asset_id AS UUID),
                        CAST(:target_asset_id AS UUID),
                        :relationship_type,
                        :protocol,
                        :port,
                        :direction,
                        :status,
                        :description
                    )
                    RETURNING *
                    """
                ),
                {
                    "organization_id": org_id,
                    "source_asset_id": str(data.source_asset_id),
                    "target_asset_id": str(data.target_asset_id),
                    "relationship_type": relationship_type,
                    "protocol": data.protocol.strip().upper(),
                    "port": data.port,
                    "direction": direction,
                    "status": status,
                    "description": data.description,
                },
            ).mappings().one()

            return dict(result)

    except HTTPException:
        raise
    except SQLAlchemyError as exc:
        logger.exception("Database error creating network relationship.")
        raise HTTPException(
            status_code=503,
            detail="Database operation failed while creating the network relationship.",
        ) from exc
    except Exception as exc:
        logger.exception("Unexpected error creating network relationship.")
        raise HTTPException(
            status_code=500,
            detail="Unexpected error while creating network relationship.",
        ) from exc


# =========================================================
# GET NETWORK RELATIONSHIPS
# =========================================================

@router.get("/relationships")
def get_network_relationships(
    organization_id: UUID | None = Query(default=None),
    status: str | None = Query(default=None),
    current_user: dict = Depends(get_current_user),
):
    org_id = resolve_organization_scope(organization_id, current_user)

    if status is not None:
        status = status.strip().upper()
        if status not in ALLOWED_STATUSES:
            raise HTTPException(status_code=400, detail="Invalid relationship status.")

    try:
        with engine.connect() as connection:
            rows = connection.execute(
                text(
                    """
                    SELECT
                        nr.*,
                        source.graph_asset_id AS source_graph_id,
                        source.asset_name AS source_name,
                        target.graph_asset_id AS target_graph_id,
                        target.asset_name AS target_name
                    FROM asset_network_relationships nr
                    JOIN assets_metadata source
                        ON source.id = nr.source_asset_id
                       AND source.organization_id = nr.organization_id
                    JOIN assets_metadata target
                        ON target.id = nr.target_asset_id
                       AND target.organization_id = nr.organization_id
                    WHERE (
                        CAST(:organization_id AS UUID) IS NULL
                        OR nr.organization_id = CAST(:organization_id AS UUID)
                    )
                    AND (
                        CAST(:status AS VARCHAR) IS NULL
                        OR nr.status = CAST(:status AS VARCHAR)
                    )
                    ORDER BY nr.created_at DESC
                    """
                ),
                {"organization_id": org_id, "status": status},
            ).mappings().all()

            return [dict(row) for row in rows]

    except SQLAlchemyError as exc:
        logger.exception("Database error retrieving network relationships.")
        raise HTTPException(
            status_code=503,
            detail="Database operation failed while retrieving network relationships.",
        ) from exc


# =========================================================
# DELETE NETWORK RELATIONSHIP
# =========================================================

@router.delete("/relationships/{relationship_id}")
def delete_network_relationship(
    relationship_id: UUID,
    organization_id: UUID = Query(...),
    current_user: dict = Depends(require_roles(*NETWORK_ADMIN_ROLES)),
):
    org_id = resolve_organization_scope(organization_id, current_user)

    try:
        with engine.begin() as connection:
            result = connection.execute(
                text(
                    """
                    DELETE FROM asset_network_relationships
                    WHERE id = CAST(:relationship_id AS UUID)
                      AND organization_id = CAST(:organization_id AS UUID)
                    RETURNING id
                    """
                ),
                {
                    "relationship_id": str(relationship_id),
                    "organization_id": org_id,
                },
            ).first()

            if result is None:
                raise HTTPException(
                    status_code=404,
                    detail="Network relationship not found.",
                )

            return {
                "message": "Network relationship deleted successfully.",
                "relationship_id": str(result[0]),
            }

    except HTTPException:
        raise
    except SQLAlchemyError as exc:
        logger.exception("Database error deleting network relationship.")
        raise HTTPException(
            status_code=503,
            detail="Database operation failed while deleting network relationship.",
        ) from exc


# =========================================================
# NETWORK TOPOLOGY
# =========================================================

@router.get("/topology")
def get_network_topology(
    organization_id: UUID | None = Query(default=None),
    current_user: dict = Depends(get_current_user),
):
    org_id = resolve_organization_scope(organization_id, current_user)

    try:
        with engine.connect() as connection:
            assets = connection.execute(
                text(
                    """
                    SELECT
                        id,
                        graph_asset_id,
                        asset_name,
                        asset_type,
                        ip_address,
                        criticality,
                        environment
                    FROM assets_metadata
                    WHERE (
                        CAST(:organization_id AS UUID) IS NULL
                        OR organization_id = CAST(:organization_id AS UUID)
                    )
                    ORDER BY asset_name NULLS LAST, id
                    """
                ),
                {"organization_id": org_id},
            ).mappings().all()

            relationships = connection.execute(
                text(
                    """
                    SELECT
                        nr.id,
                        nr.source_asset_id,
                        nr.target_asset_id,
                        nr.relationship_type,
                        nr.protocol,
                        nr.port,
                        nr.direction,
                        nr.status,
                        nr.description,
                        source.graph_asset_id AS source_graph_id,
                        target.graph_asset_id AS target_graph_id
                    FROM asset_network_relationships nr
                    JOIN assets_metadata source
                        ON source.id = nr.source_asset_id
                       AND source.organization_id = nr.organization_id
                    JOIN assets_metadata target
                        ON target.id = nr.target_asset_id
                       AND target.organization_id = nr.organization_id
                    WHERE (
                        CAST(:organization_id AS UUID) IS NULL
                        OR nr.organization_id = CAST(:organization_id AS UUID)
                    )
                    AND nr.status = 'ACTIVE'
                    ORDER BY nr.created_at DESC
                    """
                ),
                {"organization_id": org_id},
            ).mappings().all()

            # Use graph_asset_id when available; fall back to the database UUID.
            # This ensures every edge endpoint matches a node ID in this response.
            nodes = []
            node_ids = set()

            for asset in assets:
                node_id = str(asset["graph_asset_id"] or asset["id"])
                node_ids.add(node_id)
                nodes.append(
                    {
                        "id": node_id,
                        "database_id": str(asset["id"]),
                        "name": asset["asset_name"] or str(asset["id"]),
                        "type": asset["asset_type"],
                        "ip_address": asset["ip_address"],
                        "criticality": asset["criticality"],
                        "environment": asset["environment"],
                    }
                )

            edges = []
            for relationship in relationships:
                source_id = str(
                    relationship["source_graph_id"] or relationship["source_asset_id"]
                )
                target_id = str(
                    relationship["target_graph_id"] or relationship["target_asset_id"]
                )

                # Never return edges whose endpoints are absent from this tenant's nodes.
                if source_id not in node_ids or target_id not in node_ids:
                    continue

                edges.append(
                    {
                        "id": str(relationship["id"]),
                        "source": source_id,
                        "target": target_id,
                        "relationship_type": relationship["relationship_type"],
                        "protocol": relationship["protocol"],
                        "port": relationship["port"],
                        "direction": relationship["direction"],
                        "status": relationship["status"],
                        "description": relationship["description"],
                    }
                )

            critical_assets = sum(
                1
                for node in nodes
                if str(node["criticality"] or "").strip().upper() == "CRITICAL"
            )

            return {
                "success": True,
                "summary": {
                    "total_assets": len(nodes),
                    "total_relationships": len(edges),
                    "critical_assets": critical_assets,
                },
                "nodes": nodes,
                "edges": edges,
                "message": (
                    "Topology loaded successfully."
                    if nodes
                    else "No assets are registered for this organization. Add or import assets to populate the topology."
                ),
            }

    except SQLAlchemyError as exc:
        logger.exception("Database error retrieving network topology.")
        raise HTTPException(
            status_code=503,
            detail="Database operation failed while retrieving network topology.",
        ) from exc
