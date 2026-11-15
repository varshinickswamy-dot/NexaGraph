-- =====================================================
-- NEXAGRAPH AI
-- ENTERPRISE DATABASE SCHEMA V1.0
-- PostgreSQL 18
-- =====================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(200) NOT NULL,
    industry VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    role_id UUID NOT NULL REFERENCES roles(id),
    full_name VARCHAR(150) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE departments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(150) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(organization_id, name)
);

CREATE TABLE assets_metadata (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    graph_asset_id VARCHAR(100) NOT NULL,
    asset_name VARCHAR(200) NOT NULL,
    asset_type VARCHAR(100),
    ip_address INET,
    operating_system VARCHAR(150),
    environment VARCHAR(50),
    criticality VARCHAR(20) DEFAULT 'MEDIUM'
        CHECK (criticality IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    owner_id UUID REFERENCES users(id) ON DELETE SET NULL,
    department_id UUID REFERENCES departments(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(organization_id, graph_asset_id)
);

CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id VARCHAR(30) UNIQUE,
    title TEXT NOT NULL,
    description TEXT,
    cvss_score NUMERIC(3,1)
        CHECK (cvss_score BETWEEN 0 AND 10),
    severity VARCHAR(20)
        CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    published_at TIMESTAMPTZ,
    last_modified TIMESTAMPTZ,
    source VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE asset_vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES assets_metadata(id) ON DELETE CASCADE,
    vulnerability_id UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    status VARCHAR(30) DEFAULT 'OPEN'
        CHECK (status IN ('OPEN','IN_PROGRESS','RESOLVED','ACCEPTED')),
    detected_at TIMESTAMPTZ DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    UNIQUE(asset_id, vulnerability_id)
);

CREATE TABLE security_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    asset_id UUID REFERENCES assets_metadata(id) ON DELETE SET NULL,
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL
        CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    description TEXT,
    source_ip INET,
    destination_ip INET,
    event_data JSONB DEFAULT '{}'::jsonb,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    title VARCHAR(250) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(30) DEFAULT 'NEW'
        CHECK (status IN ('NEW','INVESTIGATING','CONTAINED','RESOLVED','CLOSED')),
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

CREATE TABLE incident_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id),
    assigned_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(incident_id, user_id)
);

CREATE TABLE risk_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    asset_id UUID REFERENCES assets_metadata(id) ON DELETE CASCADE,
    risk_score NUMERIC(5,2) NOT NULL
        CHECK (risk_score BETWEEN 0 AND 100),
    risk_level VARCHAR(20),
    calculation_details JSONB DEFAULT '{}'::jsonb,
    recorded_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE remediation_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    asset_id UUID REFERENCES assets_metadata(id) ON DELETE SET NULL,
    vulnerability_id UUID REFERENCES vulnerabilities(id) ON DELETE SET NULL,
    assigned_to UUID REFERENCES users(id) ON DELETE SET NULL,
    title VARCHAR(250) NOT NULL,
    description TEXT,
    status VARCHAR(30) DEFAULT 'PENDING'
        CHECK (status IN ('PENDING','IN_PROGRESS','COMPLETED','CANCELLED')),
    due_date TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(100),
    entity_id VARCHAR(100),
    details JSONB DEFAULT '{}'::jsonb,
    ip_address INET,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(200) NOT NULL,
    message TEXT,
    notification_type VARCHAR(50),
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    integration_name VARCHAR(150) NOT NULL,
    integration_type VARCHAR(100),
    configuration JSONB DEFAULT '{}'::jsonb,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    generated_by UUID REFERENCES users(id),
    report_name VARCHAR(200) NOT NULL,
    report_type VARCHAR(100),
    file_path TEXT,
    report_data JSONB DEFAULT '{}'::jsonb,
    generated_at TIMESTAMPTZ DEFAULT NOW()
);

-- =====================================================
-- INDEXES
-- =====================================================

CREATE INDEX idx_users_email ON users(email);

CREATE INDEX idx_assets_organization
ON assets_metadata(organization_id);

CREATE INDEX idx_assets_graph_id
ON assets_metadata(graph_asset_id);

CREATE INDEX idx_vulnerabilities_cve
ON vulnerabilities(cve_id);

CREATE INDEX idx_asset_vulnerabilities_asset
ON asset_vulnerabilities(asset_id);

CREATE INDEX idx_security_events_organization_time
ON security_events(organization_id, occurred_at DESC);

CREATE INDEX idx_security_events_severity
ON security_events(severity);

CREATE INDEX idx_incidents_organization_status
ON incidents(organization_id, status);

CREATE INDEX idx_risk_history_asset_time
ON risk_history(asset_id, recorded_at DESC);

CREATE INDEX idx_audit_logs_created
ON audit_logs(created_at DESC);

CREATE INDEX idx_notifications_user
ON notifications(user_id, is_read);

CREATE INDEX idx_remediation_status
ON remediation_actions(status);

CREATE INDEX idx_integrations_organization
ON integrations(organization_id);

CREATE INDEX idx_reports_organization
ON reports(organization_id);

-- =====================================================
-- INITIAL ROLES
-- =====================================================

INSERT INTO roles (name, description)
VALUES
('SUPER_ADMIN', 'Platform administrator'),
('ORG_ADMIN', 'Organization administrator'),
('SECURITY_ANALYST', 'Security monitoring and investigation'),
('VIEWER', 'Read-only dashboard access')
ON CONFLICT (name) DO NOTHING;
