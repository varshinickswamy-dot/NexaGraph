from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from backend.database import engine


def analyze_security_events(
    organization_id: str,
    hours: int = 24
):
    """
    Rule-based security intelligence engine.

    Analyzes stored security events and produces
    explainable security findings.
    """

    if hours < 1 or hours > 168:
        raise ValueError("Hours must be between 1 and 168.")

    query = text("""
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
            e.occurred_at
        FROM security_events e
        LEFT JOIN assets_metadata a
            ON a.id = e.asset_id
        WHERE e.organization_id = :org
        AND e.occurred_at >= NOW() - make_interval(hours => :hours)
        ORDER BY e.occurred_at DESC
    """)

    with engine.connect() as connection:
        records = connection.execute(
            query,
            {
                "org": organization_id,
                "hours": hours
            }
        ).mappings().all()

    events = [dict(row) for row in records]

    findings = []

    def add_finding(
        title,
        category,
        severity,
        description,
        recommendation,
        event_ids,
        asset_id=None,
        source_ip=None
    ):
        findings.append({
            "title": title,
            "category": category,
            "severity": severity,
            "description": description,
            "recommendation": recommendation,
            "event_ids": list(set(event_ids)),
            "asset_id": asset_id,
            "source_ip": source_ip,
            "evidence_count": len(set(event_ids))
        })

    # --------------------------------------------
    # 1. REPEATED FAILED LOGIN DETECTION
    # --------------------------------------------

    failed_logins = defaultdict(list)

    for event in events:
        data = event.get("event_data") or {}

        if not isinstance(data, dict):
            continue

        event_type = (event.get("event_type") or "").upper()

        outcome = str(
            data.get("outcome", data.get("status", ""))
        ).lower()

        failed = (
            data.get("success") is False
            or data.get("failed") is True
            or outcome in {
                "failed",
                "failure",
                "denied",
                "unsuccessful"
            }
        )

        authentication_event = (
            "LOGIN" in event_type
            or "AUTH" in event_type
        )

        if failed and authentication_event and event.get("source_ip"):
            failed_logins[event["source_ip"]].append(event)

    for source_ip, matching in failed_logins.items():

        if len(matching) >= 5:
            add_finding(
                title="Repeated Failed Login Attempts",
                category="AUTHENTICATION",
                severity="HIGH",
                description=(
                    f"{len(matching)} failed authentication events "
                    f"were recorded from source IP {source_ip}."
                ),
                recommendation=(
                    "Review authentication logs, validate the source "
                    "and investigate possible credential abuse."
                ),
                event_ids=[str(e["id"]) for e in matching],
                source_ip=source_ip
            )

    # --------------------------------------------
    # 2. SUSPICIOUS LOGIN ACTIVITY
    # --------------------------------------------

    suspicious_logins = defaultdict(list)

    for event in events:

        event_type = (event.get("event_type") or "").upper()

        if "SUSPICIOUS_LOGIN" in event_type:
            ip = event.get("source_ip")

            if ip:
                suspicious_logins[ip].append(event)

    for source_ip, matching in suspicious_logins.items():

        if len(matching) >= 2:
            add_finding(
                title="Repeated Suspicious Login Activity",
                category="AUTHENTICATION",
                severity="HIGH",
                description=(
                    f"{len(matching)} suspicious login events "
                    f"were recorded from {source_ip}."
                ),
                recommendation=(
                    "Investigate the source IP and review affected "
                    "accounts and authentication records."
                ),
                event_ids=[str(e["id"]) for e in matching],
                source_ip=source_ip
            )

    # --------------------------------------------
    # 3. MULTIPLE ASSET IP ACTIVITY
    # --------------------------------------------

    ip_assets = defaultdict(lambda: defaultdict(list))

    for event in events:

        source_ip = event.get("source_ip")
        asset_id = event.get("asset_id")

        if source_ip and asset_id:
            ip_assets[source_ip][str(asset_id)].append(event)

    for source_ip, assets in ip_assets.items():

        if len(assets) >= 3:

            matching = [
                event
                for asset_events in assets.values()
                for event in asset_events
            ]

            add_finding(
                title="Cross-Asset Source IP Activity",
                category="NETWORK",
                severity="MEDIUM",
                description=(
                    f"Source IP {source_ip} generated events "
                    f"associated with {len(assets)} different assets."
                ),
                recommendation=(
                    "Review network access logs and verify whether "
                    "the cross-asset activity is expected."
                ),
                event_ids=[str(e["id"]) for e in matching],
                source_ip=source_ip
            )

    # --------------------------------------------
    # 4. CRITICAL EVENT CORRELATION
    # --------------------------------------------

    asset_events = defaultdict(list)

    for event in events:

        asset_id = event.get("asset_id")
        severity = (event.get("severity") or "").upper()

        if asset_id and severity in {"CRITICAL", "HIGH"}:
            asset_events[str(asset_id)].append(event)

    for asset_id, matching in asset_events.items():

        if len(matching) >= 3:

            critical_count = sum(
                1 for e in matching
                if e["severity"].upper() == "CRITICAL"
            )

            add_finding(
                title="Concentrated High-Risk Security Activity",
                category="ASSET_RISK",
                severity="CRITICAL" if critical_count else "HIGH",
                description=(
                    f"{len(matching)} high-severity events were "
                    f"recorded against asset {asset_id}, including "
                    f"{critical_count} critical events."
                ),
                recommendation=(
                    "Prioritize investigation of this asset, inspect "
                    "related vulnerabilities and assess containment."
                ),
                event_ids=[str(e["id"]) for e in matching],
                asset_id=asset_id
            )

    # --------------------------------------------
    # 5. VULNERABILITY DETECTION EVENTS
    # --------------------------------------------

    vulnerability_events = [
        event for event in events
        if "VULNERABILITY" in (
            event.get("event_type") or ""
        ).upper()
    ]

    for event in vulnerability_events:

        severity = (event.get("severity") or "MEDIUM").upper()

        add_finding(
            title="Vulnerability Detection Event",
            category="VULNERABILITY",
            severity=severity,
            description=(
                event.get("description")
                or "A vulnerability-related security event was recorded."
            ),
            recommendation=(
                "Review the affected asset, validate the vulnerability "
                "and prioritize remediation according to severity."
            ),
            event_ids=[str(event["id"])],
            asset_id=(
                str(event["asset_id"])
                if event.get("asset_id") else None
            )
        )

    # --------------------------------------------
    # 6. HIGH SEVERITY EVENT SUMMARY
    # --------------------------------------------

    high_risk_events = [
        event for event in events
        if (event.get("severity") or "").upper()
        in {"HIGH", "CRITICAL"}
    ]

    # --------------------------------------------
    # FINAL RESULT
    # --------------------------------------------

    severity_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3
    }

    findings.sort(
        key=lambda item: severity_order.get(
            item["severity"], 4
        )
    )

    return {
        "organization_id": organization_id,
        "analysis_period_hours": hours,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "total_events_analyzed": len(events),
        "high_risk_events": len(high_risk_events),
        "total_findings": len(findings),
        "severity_summary": {
            severity: sum(
                1 for finding in findings
                if finding["severity"] == severity
            )
            for severity in [
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW"
            ]
        },
        "findings": findings
    }