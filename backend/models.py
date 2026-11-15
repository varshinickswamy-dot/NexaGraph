from sqlalchemy.ext.automap import automap_base

from backend.database import engine

# Automatically map existing PostgreSQL tables
Base = automap_base()

# Reflect existing database schema
Base.prepare(autoload_with=engine)

# Access mapped database tables
Organization = Base.classes.organizations
User = Base.classes.users
Role = Base.classes.roles
UserSession = Base.classes.user_sessions
Department = Base.classes.departments

AssetMetadata = Base.classes.assets_metadata
Vulnerability = Base.classes.vulnerabilities
AssetVulnerability = Base.classes.asset_vulnerabilities

SecurityEvent = Base.classes.security_events
Incident = Base.classes.incidents
IncidentAssignment = Base.classes.incident_assignments

RiskHistory = Base.classes.risk_history
RemediationAction = Base.classes.remediation_actions

AuditLog = Base.classes.audit_logs
Notification = Base.classes.notifications
Integration = Base.classes.integrations
Report = Base.classes.reports


def get_registered_tables():
    return list(Base.classes.keys())