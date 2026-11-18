from uuid import UUID
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text

from backend.database import engine
from backend.auth_routes import get_current_user, require_roles

router = APIRouter(prefix="/incidents", tags=["Incident Management"])

# Roles allowed to make operational changes to incidents.
INCIDENT_WRITE_ROLES = ("SUPER_ADMIN", "ORG_ADMIN", "SECURITY_ANALYST")
INCIDENT_ADMIN_ROLES = ("SUPER_ADMIN", "ORG_ADMIN")


class IncidentCreate(BaseModel):
    organization_id: UUID
    title: str = Field(min_length=3, max_length=250)
    description: Optional[str] = None
    severity: str = "MEDIUM"


class IncidentUpdate(BaseModel):
    title: Optional[str] = Field(default=None, max_length=250)
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None


class AssignmentInput(BaseModel):
    user_id: UUID


class NoteInput(BaseModel):
    # The author is always taken from the authenticated session.
    note: str = Field(min_length=1, max_length=5000)


VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

VALID_STATUSES = {
    "NEW",
    "INVESTIGATING",
    "CONTAINED",
    "RESOLVED",
    "CLOSED",
}


def serialize(row):
    return dict(row) if row else None


def resolve_organization_id(requested_org_id: UUID, current_user: dict) -> str:
    """Prevent non-super-admin users from selecting another tenant."""
    role = str(current_user.get("role", "")).upper()
    own_org_id = current_user.get("organization_id")

    if role == "SUPER_ADMIN":
        return str(requested_org_id)

    if not own_org_id or str(own_org_id) != str(requested_org_id):
        # Return 404 to avoid confirming that another tenant exists.
        raise HTTPException(status_code=404, detail="Incident not found")

    return str(own_org_id)


@router.get("")
def list_incidents(
    organization_id: UUID,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    org_id = resolve_organization_id(organization_id, current_user)

    query = """
        SELECT *
        FROM incidents
        WHERE organization_id = :organization_id
    """
    params = {"organization_id": org_id}

    if status:
        query += " AND status = :status"
        params["status"] = status.upper()

    if severity:
        query += " AND severity = :severity"
        params["severity"] = severity.upper()

    if search:
        query += " AND (title ILIKE :search OR description ILIKE :search)"
        params["search"] = f"%{search}%"

    query += " ORDER BY created_at DESC"

    with engine.connect() as conn:
        rows = conn.execute(text(query), params).mappings().all()

    return [serialize(row) for row in rows]


@router.post("", status_code=201)
def create_incident(
    data: IncidentCreate,
    current_user: dict = Depends(require_roles(*INCIDENT_WRITE_ROLES)),
):
    org_id = resolve_organization_id(data.organization_id, current_user)

    if data.severity.upper() not in VALID_SEVERITIES:
        raise HTTPException(status_code=400, detail="Invalid severity")

    with engine.begin() as conn:
        org = conn.execute(
            text("SELECT id FROM organizations WHERE id=:id"),
            {"id": org_id},
        ).first()

        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        row = conn.execute(
            text("""
                INSERT INTO incidents (
                    organization_id,
                    title,
                    description,
                    severity,
                    created_by
                )
                VALUES (
                    :org, :title, :description, :severity, :creator
                )
                RETURNING *
            """),
            {
                "org": org_id,
                "title": data.title,
                "description": data.description,
                "severity": data.severity.upper(),
                "creator": str(current_user["id"]),
            },
        ).mappings().first()

    return serialize(row)


@router.get("/summary")
def incident_summary(
    organization_id: UUID,
    current_user: dict = Depends(get_current_user),
):
    org_id = resolve_organization_id(organization_id, current_user)

    with engine.connect() as conn:
        rows = conn.execute(
            text("""
                SELECT status, severity, COUNT(*) AS count
                FROM incidents
                WHERE organization_id=:org
                GROUP BY status, severity
            """),
            {"org": org_id},
        ).mappings().all()

    return {
        "organization_id": org_id,
        "total": sum(row["count"] for row in rows),
        "breakdown": [serialize(row) for row in rows],
    }


@router.get("/{incident_id}")
def get_incident(
    incident_id: UUID,
    organization_id: UUID,
    current_user: dict = Depends(get_current_user),
):
    org_id = resolve_organization_id(organization_id, current_user)

    with engine.connect() as conn:
        row = conn.execute(
            text("""
                SELECT *
                FROM incidents
                WHERE id=:id AND organization_id=:org
            """),
            {"id": str(incident_id), "org": org_id},
        ).mappings().first()

        if not row:
            raise HTTPException(status_code=404, detail="Incident not found")

        assignments = conn.execute(
            text("""
                SELECT u.id, u.full_name, u.email, ia.assigned_at
                FROM incident_assignments ia
                JOIN incidents i
                    ON i.id = ia.incident_id
                   AND i.organization_id = :org
                JOIN users u
                    ON u.id = ia.user_id
                   AND u.organization_id = :org
                WHERE ia.incident_id = :id
            """),
            {"id": str(incident_id), "org": org_id},
        ).mappings().all()

        notes = conn.execute(
            text("""
                SELECT n.id, n.user_id, n.note, n.created_at
                FROM incident_notes n
                JOIN incidents i
                    ON i.id = n.incident_id
                   AND i.organization_id = :org
                WHERE n.incident_id = :id
                ORDER BY n.created_at DESC
            """),
            {"id": str(incident_id), "org": org_id},
        ).mappings().all()

    result = serialize(row)
    result["assignments"] = [serialize(item) for item in assignments]
    result["notes"] = [serialize(item) for item in notes]
    return result


@router.patch("/{incident_id}")
def update_incident(
    incident_id: UUID,
    organization_id: UUID,
    data: IncidentUpdate,
    current_user: dict = Depends(require_roles(*INCIDENT_WRITE_ROLES)),
):
    org_id = resolve_organization_id(organization_id, current_user)
    updates = data.model_dump(exclude_unset=True)

    if not updates:
        raise HTTPException(status_code=400, detail="No update fields provided")

    if "severity" in updates and updates["severity"] is not None:
        if updates["severity"].upper() not in VALID_SEVERITIES:
            raise HTTPException(status_code=400, detail="Invalid severity")
        updates["severity"] = updates["severity"].upper()

    if "status" in updates and updates["status"] is not None:
        if updates["status"].upper() not in VALID_STATUSES:
            raise HTTPException(status_code=400, detail="Invalid status")
        updates["status"] = updates["status"].upper()

    assignments = []
    params = {"id": str(incident_id), "org": org_id}

    # Only these model fields can reach the SQL SET clause.
    allowed_update_fields = {"title", "description", "severity", "status"}
    for key, value in updates.items():
        if key not in allowed_update_fields:
            raise HTTPException(status_code=400, detail="Invalid update field")
        assignments.append(f"{key} = :{key}")
        params[key] = value

    assignments.append("updated_at = NOW()")

    if updates.get("status") == "RESOLVED":
        assignments.append("resolved_at = NOW()")

    if updates.get("status") in {"NEW", "INVESTIGATING", "CONTAINED"}:
        assignments.append("resolved_at = NULL")

    query = f"""
        UPDATE incidents
        SET {", ".join(assignments)}
        WHERE id=:id AND organization_id=:org
        RETURNING *
    """

    with engine.begin() as conn:
        row = conn.execute(text(query), params).mappings().first()

        if not row:
            raise HTTPException(status_code=404, detail="Incident not found")

    return serialize(row)


@router.post("/{incident_id}/assign", status_code=201)
def assign_incident(
    incident_id: UUID,
    organization_id: UUID,
    data: AssignmentInput,
    current_user: dict = Depends(require_roles(*INCIDENT_WRITE_ROLES)),
):
    org_id = resolve_organization_id(organization_id, current_user)

    with engine.begin() as conn:
        incident = conn.execute(
            text("""
                SELECT id FROM incidents
                WHERE id=:id AND organization_id=:org
            """),
            {"id": str(incident_id), "org": org_id},
        ).first()

        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        user = conn.execute(
            text("""
                SELECT id FROM users
                WHERE id=:id AND organization_id=:org
                AND is_active=TRUE
            """),
            {"id": str(data.user_id), "org": org_id},
        ).first()

        if not user:
            raise HTTPException(status_code=404, detail="Active user not found")

        conn.execute(
            text("""
                INSERT INTO incident_assignments (incident_id, user_id)
                VALUES (:incident, :user)
                ON CONFLICT (incident_id, user_id) DO NOTHING
            """),
            {
                "incident": str(incident_id),
                "user": str(data.user_id),
            },
        )

    return {"message": "Incident assignment saved"}


@router.delete("/{incident_id}/assign/{user_id}")
def remove_assignment(
    incident_id: UUID,
    user_id: UUID,
    organization_id: UUID,
    current_user: dict = Depends(require_roles(*INCIDENT_ADMIN_ROLES)),
):
    org_id = resolve_organization_id(organization_id, current_user)

    with engine.begin() as conn:
        result = conn.execute(
            text("""
                DELETE FROM incident_assignments ia
                USING incidents i
                WHERE ia.incident_id=i.id
                AND i.id=:incident
                AND i.organization_id=:org
                AND ia.user_id=:user
            """),
            {
                "incident": str(incident_id),
                "org": org_id,
                "user": str(user_id),
            },
        )

        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Assignment not found")

    return {"message": "Assignment removed"}


@router.post("/{incident_id}/notes", status_code=201)
def add_incident_note(
    incident_id: UUID,
    organization_id: UUID,
    data: NoteInput,
    current_user: dict = Depends(require_roles(*INCIDENT_WRITE_ROLES)),
):
    org_id = resolve_organization_id(organization_id, current_user)

    with engine.begin() as conn:
        incident = conn.execute(
            text("""
                SELECT id FROM incidents
                WHERE id=:id AND organization_id=:org
            """),
            {"id": str(incident_id), "org": org_id},
        ).first()

        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        row = conn.execute(
            text("""
                INSERT INTO incident_notes (
                    incident_id, user_id, note
                )
                VALUES (:incident, :user, :note)
                RETURNING *
            """),
            {
                "incident": str(incident_id),
                "user": str(current_user["id"]),
                "note": data.note,
            },
        ).mappings().first()

    return serialize(row)
