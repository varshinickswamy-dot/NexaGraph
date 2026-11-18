"""
NexaGraph AI
Organization-specific demo-data provisioning.

IMPORTANT:
- Call this function inside an existing SQLAlchemy transaction.
- This module does not commit or roll back the session.
- Existing records are never overwritten or deleted.
- All generated records belong to exactly one organization.
"""

import json

from uuid import UUID, uuid5, NAMESPACE_URL

from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.demo_data_templates import (
    DEPARTMENTS,
    ASSETS,
    NETWORK_RELATIONSHIPS,
    SECURITY_EVENT_TEMPLATES,
    INCIDENT_TEMPLATES,
    REMEDIATION_TEMPLATES,
    RISK_HISTORY_SNAPSHOTS,
)


def _stable_id(
    organization_id: UUID,
    record_type: str,
    record_key: str,
) -> UUID:
    """Generate a deterministic UUID for an organization record."""

    return uuid5(
        NAMESPACE_URL,
        f"nexagraph:{organization_id}:{record_type}:{record_key}",
    )


def _ensure_department(
    db: Session,
    organization_id: UUID,
    department: dict,
) -> UUID:
    department_id = _stable_id(
        organization_id,
        "department",
        department["key"],
    )

    db.execute(
        text("""
            INSERT INTO departments (
                id,
                organization_id,
                name
            )
            VALUES (
                :id,
                :organization_id,
                :name
            )
            ON CONFLICT (organization_id, name)
            DO NOTHING
        """),
        {
            "id": department_id,
            "organization_id": organization_id,
            "name": department["name"],
        },
    )

    existing = db.execute(
        text("""
            SELECT id
            FROM departments
            WHERE organization_id = :organization_id
              AND name = :name
        """),
        {
            "organization_id": organization_id,
            "name": department["name"],
        },
    ).scalar_one()

    return existing


def _ensure_asset(
    db: Session,
    organization_id: UUID,
    admin_user_id: UUID,
    asset: dict,
    department_ids: dict,
) -> UUID:
    graph_asset_id = (
        f"NG-{organization_id.hex[:8]}-{asset['key']}"
    )

    existing = db.execute(
        text("""
            SELECT id
            FROM assets_metadata
            WHERE organization_id = :organization_id
              AND graph_asset_id = :graph_asset_id
        """),
        {
            "organization_id": organization_id,
            "graph_asset_id": graph_asset_id,
        },
    ).scalar_one_or_none()

    if existing:
        return existing

    asset_id = _stable_id(
        organization_id,
        "asset",
        asset["key"],
    )

    db.execute(
        text("""
            INSERT INTO assets_metadata (
                id,
                organization_id,
                graph_asset_id,
                asset_name,
                asset_type,
                ip_address,
                operating_system,
                environment,
                criticality,
                owner_id,
                department_id
            )
            VALUES (
                :id,
                :organization_id,
                :graph_asset_id,
                :asset_name,
                :asset_type,
                CAST(:ip_address AS INET),
                :operating_system,
                :environment,
                :criticality,
                :owner_id,
                :department_id
            )
            ON CONFLICT (organization_id, graph_asset_id)
            DO NOTHING
        """),
        {
            "id": asset_id,
            "organization_id": organization_id,
            "graph_asset_id": graph_asset_id,
            "asset_name": asset["name"],
            "asset_type": asset["type"],
            "ip_address": asset["ip"],
            "operating_system": asset["os"],
            "environment": asset["environment"],
            "criticality": asset["criticality"],
            "owner_id": admin_user_id,
            "department_id": department_ids[asset["department"]],
        },
    )

    return db.execute(
        text("""
            SELECT id
            FROM assets_metadata
            WHERE organization_id = :organization_id
              AND graph_asset_id = :graph_asset_id
        """),
        {
            "organization_id": organization_id,
            "graph_asset_id": graph_asset_id,
        },
    ).scalar_one()


def _ensure_relationship(
    db: Session,
    organization_id: UUID,
    source_id: UUID,
    target_id: UUID,
    relationship: tuple,
) -> None:
    source_key, target_key, relationship_type, direction, port = relationship

    relationship_key = (
        f"{source_key}:{target_key}:{relationship_type}:{direction}:{port}"
    )

    relationship_id = _stable_id(
        organization_id,
        "relationship",
        relationship_key,
    )

    # Both endpoints must belong to this organization.
    valid_endpoints = db.execute(
        text("""
            SELECT COUNT(*)
            FROM assets_metadata
            WHERE organization_id = :organization_id
              AND id IN (:source_id, :target_id)
        """),
        {
            "organization_id": organization_id,
            "source_id": source_id,
            "target_id": target_id,
        },
    ).scalar_one()

    if valid_endpoints != 2:
        raise ValueError(
            "Cross-organization or missing relationship endpoint detected."
        )

    db.execute(
        text("""
            INSERT INTO asset_network_relationships (
                id,
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
                :id,
                :organization_id,
                :source_id,
                :target_id,
                :relationship_type,
                'TCP',
                :port,
                :direction,
                'ACTIVE',
                :description
            )
            ON CONFLICT (id) DO NOTHING
        """),
        {
            "id": relationship_id,
            "organization_id": organization_id,
            "source_id": source_id,
            "target_id": target_id,
            "relationship_type": relationship_type,
            "port": port,
            "direction": direction,
            "description": (
                f"Demo relationship between {source_key} and {target_key}."
            ),
        },
    )


def _ensure_vulnerability_mappings(
    db: Session,
    organization_id: UUID,
    asset_ids: dict,
) -> int:
    vulnerabilities = db.execute(
        text("""
            SELECT id
            FROM vulnerabilities
            ORDER BY cvss_score DESC NULLS LAST, id
            LIMIT 30
        """)
    ).scalars().all()

    if not vulnerabilities:
        return 0

    asset_keys = list(asset_ids.keys())
    inserted_candidates = 0

    for index, vulnerability_id in enumerate(vulnerabilities):
        asset_key = asset_keys[index % len(asset_keys)]
        asset_id = asset_ids[asset_key]

        result = db.execute(
            text("""
                INSERT INTO asset_vulnerabilities (
                    asset_id,
                    vulnerability_id,
                    status
                )
                VALUES (
                    :asset_id,
                    :vulnerability_id,
                    'OPEN'
                )
                ON CONFLICT (asset_id, vulnerability_id)
                DO NOTHING
            """),
            {
                "asset_id": asset_id,
                "vulnerability_id": vulnerability_id,
            },
        )

        inserted_candidates += result.rowcount or 0

    return inserted_candidates


def _ensure_security_events(
    db: Session,
    organization_id: UUID,
    asset_ids: dict,
) -> int:
    inserted = 0

    for index, event in enumerate(SECURITY_EVENT_TEMPLATES):
        asset_key, event_type, severity, description = event

        event_id = _stable_id(
            organization_id,
            "security_event",
            f"event-{index + 1:03d}",
        )

        result = db.execute(
            text("""
                INSERT INTO security_events (
                    id,
                    organization_id,
                    asset_id,
                    event_type,
                    severity,
                    description,
                    event_data,
                    occurred_at
                )
                VALUES (
                    :id,
                    :organization_id,
                    :asset_id,
                    :event_type,
                    :severity,
                    :description,
                    CAST(:event_data AS JSONB),
                    NOW() - (:hours || ' hours')::INTERVAL
                )
                ON CONFLICT (id) DO NOTHING
            """),
            {
                "id": event_id,
                "organization_id": organization_id,
                "asset_id": asset_ids[asset_key],
                "event_type": event_type,
                "severity": severity,
                "description": description,
                "event_data": json.dumps({
                    "source": "NEXAGRAPH_DEMO",
                    "synthetic": True,
                }),
                "hours": str(index * 3),
            },
        )

        inserted += result.rowcount or 0

    return inserted


def _ensure_incidents(
    db: Session,
    organization_id: UUID,
    admin_user_id: UUID,
    users: list,
    asset_ids: dict,
) -> int:
    inserted = 0

    for incident in INCIDENT_TEMPLATES:
        incident_id = _stable_id(
            organization_id,
            "incident",
            incident["key"],
        )

        result = db.execute(
            text("""
                INSERT INTO incidents (
                    id,
                    organization_id,
                    title,
                    description,
                    severity,
                    status,
                    created_by
                )
                VALUES (
                    :id,
                    :organization_id,
                    :title,
                    :description,
                    :severity,
                    :status,
                    :created_by
                )
                ON CONFLICT (id) DO NOTHING
            """),
            {
                "id": incident_id,
                "organization_id": organization_id,
                "title": incident["title"],
                "description": incident["description"],
                "severity": incident["severity"],
                "status": incident["status"],
                "created_by": admin_user_id,
            },
        )

        inserted += result.rowcount or 0

        for asset_key in incident["assets"]:
            db.execute(
                text("""
                    INSERT INTO incident_assets (
                        incident_id,
                        asset_id
                    )
                    VALUES (
                        :incident_id,
                        :asset_id
                    )
                    ON CONFLICT (incident_id, asset_id)
                    DO NOTHING
                """),
                {
                    "incident_id": incident_id,
                    "asset_id": asset_ids[asset_key],
                },
            )

        assigned_user = users[
            INCIDENT_TEMPLATES.index(incident) % len(users)
        ]

        db.execute(
            text("""
                INSERT INTO incident_assignments (
                    incident_id,
                    user_id
                )
                VALUES (
                    :incident_id,
                    :user_id
                )
                ON CONFLICT (incident_id, user_id)
                DO NOTHING
            """),
            {
                "incident_id": incident_id,
                "user_id": assigned_user,
            },
        )

        note_id = _stable_id(
            organization_id,
            "incident_note",
            incident["key"],
        )

        db.execute(
            text("""
                INSERT INTO incident_notes (
                    id,
                    incident_id,
                    user_id,
                    note
                )
                VALUES (
                    :id,
                    :incident_id,
                    :user_id,
                    :note
                )
                ON CONFLICT (id) DO NOTHING
            """),
            {
                "id": note_id,
                "incident_id": incident_id,
                "user_id": admin_user_id,
                "note": (
                    "Initial synthetic investigation note. "
                    "This record is for demonstration purposes."
                ),
            },
        )

    return inserted


def _ensure_remediation_actions(
    db: Session,
    organization_id: UUID,
    admin_user_id: UUID,
    asset_ids: dict,
) -> int:
    vulnerabilities = db.execute(
        text("""
            SELECT id
            FROM vulnerabilities
            ORDER BY cvss_score DESC NULLS LAST, id
            LIMIT 5
        """)
    ).scalars().all()

    inserted = 0

    for index, template in enumerate(REMEDIATION_TEMPLATES):
        action_id = _stable_id(
            organization_id,
            "remediation",
            template["key"],
        )

        vulnerability_id = (
            vulnerabilities[index]
            if index < len(vulnerabilities)
            else None
        )

        asset_key = list(asset_ids.keys())[index]

        result = db.execute(
            text("""
                INSERT INTO remediation_actions (
                    id,
                    organization_id,
                    asset_id,
                    vulnerability_id,
                    assigned_to,
                    title,
                    description,
                    status,
                    due_date
                )
                VALUES (
                    :id,
                    :organization_id,
                    :asset_id,
                    :vulnerability_id,
                    :assigned_to,
                    :title,
                    :description,
                    'PENDING',
                    NOW() + INTERVAL '7 days'
                )
                ON CONFLICT (id) DO NOTHING
            """),
            {
                "id": action_id,
                "organization_id": organization_id,
                "asset_id": asset_ids[asset_key],
                "vulnerability_id": vulnerability_id,
                "assigned_to": admin_user_id,
                "title": template["title"],
                "description": template["description"],
            },
        )

        inserted += result.rowcount or 0

    return inserted


def _ensure_risk_history(
    db: Session,
    organization_id: UUID,
    asset_ids: dict,
) -> int:
    inserted = 0

    for asset_key, asset_id in asset_ids.items():
        for snapshot in range(RISK_HISTORY_SNAPSHOTS):
            risk_id = _stable_id(
                organization_id,
                "risk_history",
                f"{asset_key}-snapshot-{snapshot + 1}",
            )

            risk_score = max(
                5,
                min(100, 25 + (snapshot * 12) + (len(asset_key) % 25)),
            )

            result = db.execute(
                text("""
                    INSERT INTO risk_history (
                        id,
                        organization_id,
                        asset_id,
                        risk_score,
                        risk_level,
                        calculation_details,
                        recorded_at
                    )
                    VALUES (
                        :id,
                        :organization_id,
                        :asset_id,
                        :risk_score,
                        :risk_level,
                        CAST(:details AS JSONB),
                        NOW() - (:days || ' days')::INTERVAL
                    )
                    ON CONFLICT (id) DO NOTHING
                """),
                {
                    "id": risk_id,
                    "organization_id": organization_id,
                    "asset_id": asset_id,
                    "risk_score": risk_score,
                    "risk_level": (
                        "CRITICAL" if risk_score >= 80
                        else "HIGH" if risk_score >= 60
                        else "MEDIUM" if risk_score >= 35
                        else "LOW"
                    ),
                    "details": json.dumps({
                        "source": "NEXAGRAPH_DEMO",
                        "synthetic": True,
                        "snapshot": snapshot + 1,
                    }),
                    "days": str((RISK_HISTORY_SNAPSHOTS - snapshot) * 7),
                },
            )

            inserted += result.rowcount or 0

    return inserted


def provision_organization_demo_data(
    db: Session,
    organization_id,
    admin_user_id,
) -> dict:
    """
    Provision demonstration records for one organization.

    The caller MUST invoke this function inside an active transaction.

    This function intentionally does not commit.
    """

    organization_id = UUID(str(organization_id))
    admin_user_id = UUID(str(admin_user_id))

    # Lock the organization to serialize concurrent provisioning.
    organization = db.execute(
        text("""
            SELECT id
            FROM organizations
            WHERE id = :organization_id
            FOR UPDATE
        """),
        {"organization_id": organization_id},
    ).scalar_one_or_none()

    if not organization:
        raise ValueError("Organization does not exist.")

    # Validate the administrator belongs to this organization.
    admin = db.execute(
        text("""
            SELECT id
            FROM users
            WHERE id = :admin_user_id
              AND organization_id = :organization_id
              AND is_active = TRUE
        """),
        {
            "admin_user_id": admin_user_id,
            "organization_id": organization_id,
        },
    ).scalar_one_or_none()

    if not admin:
        raise ValueError(
            "Administrator does not belong to this organization."
        )

    # Only organization members may receive assignments.
    users = db.execute(
        text("""
            SELECT id
            FROM users
            WHERE organization_id = :organization_id
              AND is_active = TRUE
            ORDER BY created_at, id
        """),
        {"organization_id": organization_id},
    ).scalars().all()

    if not users:
        raise ValueError("Organization has no active members.")

    # Departments
    department_ids = {}

    for department in DEPARTMENTS:
        department_ids[department["key"]] = _ensure_department(
            db,
            organization_id,
            department,
        )

    # Assets
    asset_ids = {}

    for asset in ASSETS:
        asset_ids[asset["key"]] = _ensure_asset(
            db,
            organization_id,
            admin_user_id,
            asset,
            department_ids,
        )

    # Network relationships
    for relationship in NETWORK_RELATIONSHIPS:
        source_key, target_key = relationship[:2]

        _ensure_relationship(
            db,
            organization_id,
            asset_ids[source_key],
            asset_ids[target_key],
            relationship,
        )

    # Vulnerabilities
    vulnerability_mappings = _ensure_vulnerability_mappings(
        db,
        organization_id,
        asset_ids,
    )

    # Security events
    security_events = _ensure_security_events(
        db,
        organization_id,
        asset_ids,
    )

    # Incidents and investigation data
    incidents = _ensure_incidents(
        db,
        organization_id,
        admin_user_id,
        users,
        asset_ids,
    )

    # Remediation
    remediation_actions = _ensure_remediation_actions(
        db,
        organization_id,
        admin_user_id,
        asset_ids,
    )

    # Risk history
    risk_records = _ensure_risk_history(
        db,
        organization_id,
        asset_ids,
    )

    return {
        "success": True,
        "organization_id": str(organization_id),
        "departments": len(department_ids),
        "assets": len(asset_ids),
        "relationships": len(NETWORK_RELATIONSHIPS),
        "vulnerability_mappings_inserted": vulnerability_mappings,
        "security_events_inserted": security_events,
        "incidents_inserted": incidents,
        "remediation_actions_inserted": remediation_actions,
        "risk_history_inserted": risk_records,
        "message": (
            "Organization demo-data provisioning completed "
            "inside the current transaction."
        ),
    }