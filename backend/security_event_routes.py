import json
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import text

from backend.database import engine
from backend.auth_routes import get_current_user, require_roles

router = APIRouter(
    prefix="/security-events",
    tags=["Security Event Monitoring"],
)

VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
SECURITY_EVENT_INGEST_ROLES = (
    "SUPER_ADMIN",
    "ORG_ADMIN",
    "SECURITY_ANALYST",
)


class SecurityEventCreate(BaseModel):
    organization_id: UUID
    asset_id: Optional[UUID] = None
    event_type: str = Field(min_length=2, max_length=100)
    severity: str = "MEDIUM"
    description: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    event_data: dict = Field(default_factory=dict)


def resolve_organization_id(
    requested_org_id: UUID,
    current_user: dict,
) -> str:
    """Allow SUPER_ADMIN cross-tenant access; isolate every other role."""
    role = str(current_user.get("role", "")).upper()
    own_org_id = current_user.get("organization_id")

    if role == "SUPER_ADMIN":
        return str(requested_org_id)

    if not own_org_id or str(own_org_id) != str(requested_org_id):
        # Avoid disclosing whether another organization's records exist.
        raise HTTPException(
            status_code=404,
            detail="Security event not found",
        )

    return str(own_org_id)


@router.get("")
def list_security_events(
    organization_id: UUID,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    current_user: dict = Depends(get_current_user),
):
    org_id = resolve_organization_id(organization_id, current_user)

    query = """
        SELECT
            e.id,
            e.organization_id,
            e.asset_id,
            a.asset_name,
            e.event_type,
            e.severity,
            e.description,
            e.source_ip::text AS source_ip,
            e.destination_ip::text AS destination_ip,
            e.event_data,
            e.occurred_at,
            e.created_at
        FROM security_events e
        LEFT JOIN assets_metadata a
            ON a.id = e.asset_id
        WHERE e.organization_id = :org
    """

    params = {
        "org": org_id,
        "limit": limit,
        "offset": offset,
    }

    if severity:
        if severity.upper() not in VALID_SEVERITIES:
            raise HTTPException(status_code=400, detail="Invalid severity")

        query += " AND e.severity = :severity"
        params["severity"] = severity.upper()

    if event_type:
        query += " AND e.event_type = :event_type"
        params["event_type"] = event_type

    if search:
        query += """
            AND (
                e.description ILIKE :search
                OR e.event_type ILIKE :search
                OR e.source_ip::text ILIKE :search
                OR e.destination_ip::text ILIKE :search
            )
        """
        params["search"] = f"%{search}%"

    query += """
        ORDER BY e.occurred_at DESC
        LIMIT :limit OFFSET :offset
    """

    with engine.connect() as conn:
        rows = conn.execute(text(query), params).mappings().all()

    return [dict(row) for row in rows]


@router.get("/summary")
def security_event_summary(
    organization_id: UUID,
    current_user: dict = Depends(get_current_user),
):
    org_id = resolve_organization_id(organization_id, current_user)

    with engine.connect() as conn:
        totals = conn.execute(
            text("""
                SELECT
                    COUNT(*) AS total,
                    COUNT(*) FILTER (
                        WHERE severity = 'CRITICAL'
                    ) AS critical,
                    COUNT(*) FILTER (
                        WHERE severity = 'HIGH'
                    ) AS high,
                    COUNT(*) FILTER (
                        WHERE severity = 'MEDIUM'
                    ) AS medium,
                    COUNT(*) FILTER (
                        WHERE severity = 'LOW'
                    ) AS low,
                    COUNT(*) FILTER (
                        WHERE occurred_at >= NOW() - INTERVAL '24 hours'
                    ) AS last_24_hours
                FROM security_events
                WHERE organization_id = :org
            """),
            {"org": org_id},
        ).mappings().first()

        types = conn.execute(
            text("""
                SELECT event_type, COUNT(*) AS count
                FROM security_events
                WHERE organization_id = :org
                GROUP BY event_type
                ORDER BY count DESC
            """),
            {"org": org_id},
        ).mappings().all()

    return {
        **dict(totals),
        "event_types": [dict(row) for row in types],
    }


@router.get("/{event_id}")
def get_security_event(
    event_id: UUID,
    organization_id: UUID,
    current_user: dict = Depends(get_current_user),
):
    org_id = resolve_organization_id(organization_id, current_user)

    with engine.connect() as conn:
        row = conn.execute(
            text("""
                SELECT
                    e.id,
                    e.organization_id,
                    e.asset_id,
                    a.asset_name,
                    e.event_type,
                    e.severity,
                    e.description,
                    e.source_ip::text AS source_ip,
                    e.destination_ip::text AS destination_ip,
                    e.event_data,
                    e.occurred_at,
                    e.created_at
                FROM security_events e
                LEFT JOIN assets_metadata a
                    ON a.id = e.asset_id
                WHERE e.id = :id
                AND e.organization_id = :org
            """),
            {
                "id": str(event_id),
                "org": org_id,
            },
        ).mappings().first()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Security event not found",
        )

    return dict(row)


@router.post("", status_code=201)
def ingest_security_event(
    data: SecurityEventCreate,
    current_user: dict = Depends(
        require_roles(*SECURITY_EVENT_INGEST_ROLES)
    ),
):
    org_id = resolve_organization_id(data.organization_id, current_user)

    if data.severity.upper() not in VALID_SEVERITIES:
        raise HTTPException(status_code=400, detail="Invalid severity")

    with engine.begin() as conn:
        organization = conn.execute(
            text("""
                SELECT id
                FROM organizations
                WHERE id = :org
            """),
            {"org": org_id},
        ).first()

        if not organization:
            raise HTTPException(
                status_code=404,
                detail="Organization not found",
            )

        if data.asset_id:
            asset = conn.execute(
                text("""
                    SELECT id
                    FROM assets_metadata
                    WHERE id = :asset
                    AND organization_id = :org
                """),
                {
                    "asset": str(data.asset_id),
                    "org": org_id,
                },
            ).first()

            if not asset:
                raise HTTPException(
                    status_code=404,
                    detail="Asset not found in this organization",
                )

        row = conn.execute(
            text("""
                INSERT INTO security_events (
                    organization_id,
                    asset_id,
                    event_type,
                    severity,
                    description,
                    source_ip,
                    destination_ip,
                    event_data
                )
                VALUES (
                    :org,
                    :asset,
                    :event_type,
                    :severity,
                    :description,
                    CAST(:source_ip AS INET),
                    CAST(:destination_ip AS INET),
                    CAST(:event_data AS JSONB)
                )
                RETURNING
                    id,
                    organization_id,
                    asset_id,
                    event_type,
                    severity,
                    description,
                    source_ip::text AS source_ip,
                    destination_ip::text AS destination_ip,
                    event_data,
                    occurred_at
            """),
            {
                "org": org_id,
                "asset": str(data.asset_id) if data.asset_id else None,
                "event_type": data.event_type,
                "severity": data.severity.upper(),
                "description": data.description,
                "source_ip": data.source_ip,
                "destination_ip": data.destination_ip,
                "event_data": json.dumps(data.event_data),
            },
        ).mappings().first()

    return dict(row)
