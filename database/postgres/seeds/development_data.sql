-- =====================================================
-- NEXAGRAPH AI
-- ENTERPRISE DEVELOPMENT DATA V1.0
-- Synthetic testing data only
-- =====================================================

BEGIN;

-- ORGANIZATIONS

INSERT INTO organizations (id, name, industry)
SELECT
    md5('nexa-org-' || i)::uuid,
    name,
    industry
FROM (
    VALUES
    (1, 'Nexa Financial Group', 'Financial Services'),
    (2, 'Nexa Healthcare Systems', 'Healthcare'),
    (3, 'Nexa Cloud Technologies', 'Technology')
) AS o(i, name, industry)
ON CONFLICT (id) DO NOTHING;


-- DEPARTMENTS

INSERT INTO departments (id, organization_id, name)
SELECT
    md5('nexa-dept-' || o.i || '-' || d.i)::uuid,
    md5('nexa-org-' || o.i)::uuid,
    d.name
FROM generate_series(1, 3) o(i)
CROSS JOIN (
    VALUES
    (1, 'IT Security'),
    (2, 'Infrastructure'),
    (3, 'Operations')
) d(i, name)
ON CONFLICT (id) DO NOTHING;

-- USERS
-- Synthetic accounts with random, unusable passwords.
-- Actual authentication accounts will be created later.

INSERT INTO users (
    id,
    organization_id,
    role_id,
    full_name,
    email,
    password_hash,
    is_active
)
SELECT
    md5('nexa-user-' || i)::uuid,
    md5('nexa-org-' || ((i - 1) / 4 + 1))::uuid,
    r.id,
    'Security User ' || i,
    'security' || i || '@example.test',
    crypt(gen_random_uuid()::text, gen_salt('bf')),
    TRUE
FROM generate_series(1, 12) i
JOIN roles r
ON r.name = CASE
    WHEN i IN (1, 5, 9) THEN 'ORG_ADMIN'
    WHEN i IN (2, 6, 10) THEN 'SECURITY_ANALYST'
    ELSE 'VIEWER'
END
ON CONFLICT (id) DO NOTHING;

-- =====================================================
-- PART 3: ENTERPRISE ASSET MANAGEMENT
-- 50 SYNTHETIC ENTERPRISE ASSETS
-- =====================================================

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
SELECT
    md5('nexa-asset-' || i)::uuid,

    md5(
        'nexa-org-' || ((i - 1) / 17 + 1)
    )::uuid,

    'NEXA-ASSET-' || LPAD(i::text, 3, '0'),

    'Enterprise Asset ' || i,

    CASE i % 5
        WHEN 0 THEN 'DATABASE'
        WHEN 1 THEN 'SERVER'
        WHEN 2 THEN 'WORKSTATION'
        WHEN 3 THEN 'FIREWALL'
        ELSE 'APPLICATION'
    END,

    (
        '10.' ||
        ((i - 1) / 250) || '.' ||
        ((i - 1) / 50 % 5) || '.' ||
        (i % 250 + 1)
    )::inet,

    CASE i % 3
        WHEN 0 THEN 'Ubuntu Linux'
        WHEN 1 THEN 'Windows Server'
        ELSE 'Red Hat Enterprise Linux'
    END,

    CASE i % 3
        WHEN 0 THEN 'PRODUCTION'
        WHEN 1 THEN 'STAGING'
        ELSE 'DEVELOPMENT'
    END,

    CASE i % 4
        WHEN 0 THEN 'CRITICAL'
        WHEN 1 THEN 'HIGH'
        WHEN 2 THEN 'MEDIUM'
        ELSE 'LOW'
    END,

    -- Corrected user mapping:
    -- Each organization uses its own four users.

    md5(
        'nexa-user-' ||
        (
            ((i - 1) / 17) * 4 +
            ((i - 1) % 4) + 1
        )
    )::uuid,

    -- Department mapping

    md5(
        'nexa-dept-' ||
        ((i - 1) / 17 + 1) ||
        '-' ||
        (i % 3 + 1)
    )::uuid

FROM generate_series(1, 50) i

ON CONFLICT (id) DO NOTHING;
-- =====================================================
-- PART 4: VULNERABILITY INTELLIGENCE
-- 30 SYNTHETIC VULNERABILITIES
-- =====================================================

INSERT INTO vulnerabilities (
    id,
    cve_id,
    title,
    description,
    cvss_score,
    severity,
    published_at,
    source
)

SELECT
    md5('nexa-vulnerability-' || i)::uuid,

    NULL,

    'Synthetic Security Vulnerability ' || i,

    'Artificial vulnerability record for NexaGraph AI testing.',

    -- Improved CVSS-style score distribution

    ROUND(
        (1 + (i * 7 % 90) / 10.0)::numeric,
        1
    ),

    CASE
        WHEN (1 + (i * 7 % 90) / 10.0) >= 9.0
            THEN 'CRITICAL'

        WHEN (1 + (i * 7 % 90) / 10.0) >= 7.0
            THEN 'HIGH'

        WHEN (1 + (i * 7 % 90) / 10.0) >= 4.0
            THEN 'MEDIUM'

        ELSE 'LOW'
    END,

    NOW() - (i || ' days')::interval,

    'SYNTHETIC_TEST_DATA'

FROM generate_series(1, 30) i

ON CONFLICT (id) DO NOTHING;


-- =====================================================
-- ASSET VULNERABILITY MAPPINGS
-- 60 SYNTHETIC MAPPINGS
-- =====================================================

INSERT INTO asset_vulnerabilities (
    id,
    asset_id,
    vulnerability_id,
    status
)

SELECT
    md5('nexa-mapping-' || i)::uuid,

    md5(
        'nexa-asset-' ||
        ((i - 1) % 50 + 1)
    )::uuid,

    md5(
        'nexa-vulnerability-' ||
        ((i - 1) % 30 + 1)
    )::uuid,

    CASE
        WHEN i % 5 = 0 THEN 'RESOLVED'
        WHEN i % 4 = 0 THEN 'IN_PROGRESS'
        ELSE 'OPEN'
    END

FROM generate_series(1, 60) i

ON CONFLICT (id) DO NOTHING;

-- ASSET VULNERABILITY MAPPINGS

INSERT INTO asset_vulnerabilities (
    id,
    asset_id,
    vulnerability_id,
    status
)
SELECT
    md5('nexa-mapping-' || i)::uuid,
    md5('nexa-asset-' || ((i - 1) % 50 + 1))::uuid,
    md5('nexa-vulnerability-' || ((i - 1) % 30 + 1))::uuid,
    CASE
        WHEN i % 5 = 0 THEN 'RESOLVED'
        WHEN i % 4 = 0 THEN 'IN_PROGRESS'
        ELSE 'OPEN'
    END
FROM generate_series(1, 60) i
ON CONFLICT (id) DO NOTHING;

-- SECURITY EVENTS

INSERT INTO security_events (
    id,
    organization_id,
    asset_id,
    event_type,
    severity,
    description,
    source_ip,
    destination_ip,
    event_data,
    occurred_at
)
SELECT
    md5('nexa-event-' || i)::uuid,
    md5('nexa-org-' || ((i - 1) % 3 + 1))::uuid,
    md5('nexa-asset-' || ((i - 1) % 50 + 1))::uuid,
    CASE i % 5
        WHEN 0 THEN 'UNAUTHORIZED_ACCESS'
        WHEN 1 THEN 'SUSPICIOUS_LOGIN'
        WHEN 2 THEN 'NETWORK_ANOMALY'
        WHEN 3 THEN 'VULNERABILITY_DETECTED'
        ELSE 'POLICY_VIOLATION'
    END,
    CASE i % 4
        WHEN 0 THEN 'CRITICAL'
        WHEN 1 THEN 'HIGH'
        WHEN 2 THEN 'MEDIUM'
        ELSE 'LOW'
    END,
    'Synthetic security event ' || i,
    ('192.168.' || (i % 255) || '.' || (i % 254 + 1))::inet,
    ('10.0.' || (i % 255) || '.' || (i % 254 + 1))::inet,
    jsonb_build_object(
        'source', 'NEXAGRAPH_SIMULATOR',
        'event_number', i,
        'synthetic', TRUE
    ),
    NOW() - (i || ' hours')::interval
FROM generate_series(1, 100) i
ON CONFLICT (id) DO NOTHING;

-- SECURITY INCIDENTS

INSERT INTO incidents (
    id,
    organization_id,
    title,
    description,
    severity,
    status,
    created_by
)
SELECT
    md5('nexa-incident-' || i)::uuid,
    md5('nexa-org-' || ((i - 1) % 3 + 1))::uuid,
    'Security Incident ' || i,
    'Synthetic security investigation record.',
    CASE i % 4
        WHEN 0 THEN 'CRITICAL'
        WHEN 1 THEN 'HIGH'
        WHEN 2 THEN 'MEDIUM'
        ELSE 'LOW'
    END,
    CASE i % 5
        WHEN 0 THEN 'NEW'
        WHEN 1 THEN 'INVESTIGATING'
        WHEN 2 THEN 'CONTAINED'
        WHEN 3 THEN 'RESOLVED'
        ELSE 'CLOSED'
    END,
    md5('nexa-user-' || ((i - 1) % 12 + 1))::uuid
FROM generate_series(1, 15) i
ON CONFLICT (id) DO NOTHING;


-- INCIDENT ASSIGNMENTS

INSERT INTO incident_assignments (
    id,
    incident_id,
    user_id
)
SELECT
    md5('nexa-assignment-' || i)::uuid,
    md5('nexa-incident-' || i)::uuid,
    md5('nexa-user-' || ((i - 1) % 12 + 1))::uuid
FROM generate_series(1, 15) i
ON CONFLICT (id) DO NOTHING;

-- RISK HISTORY

INSERT INTO risk_history (
    id,
    organization_id,
    asset_id,
    risk_score,
    risk_level,
    calculation_details,
    recorded_at
)
SELECT
    md5('nexa-risk-' || i)::uuid,
    md5('nexa-org-' || ((i - 1) % 3 + 1))::uuid,
    md5('nexa-asset-' || ((i - 1) % 50 + 1))::uuid,
    ROUND((10 + (i * 7 % 90))::numeric, 2),
    CASE
        WHEN (10 + (i * 7 % 90)) >= 80 THEN 'CRITICAL'
        WHEN (10 + (i * 7 % 90)) >= 60 THEN 'HIGH'
        WHEN (10 + (i * 7 % 90)) >= 30 THEN 'MEDIUM'
        ELSE 'LOW'
    END,
    jsonb_build_object(
        'method', 'SYNTHETIC_RISK_MODEL',
        'synthetic', TRUE
    ),
    NOW() - (i || ' hours')::interval
FROM generate_series(1, 100) i
ON CONFLICT (id) DO NOTHING;

-- REMEDIATION ACTIONS

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
SELECT
    md5('nexa-remediation-' || i)::uuid,
    md5('nexa-org-' || ((i - 1) % 3 + 1))::uuid,
    md5('nexa-asset-' || ((i - 1) % 50 + 1))::uuid,
    md5('nexa-vulnerability-' || ((i - 1) % 30 + 1))::uuid,
    md5('nexa-user-' || ((i - 1) % 12 + 1))::uuid,
    'Security Remediation ' || i,
    'Synthetic remediation task for testing.',
    CASE i % 4
        WHEN 0 THEN 'COMPLETED'
        WHEN 1 THEN 'IN_PROGRESS'
        WHEN 2 THEN 'PENDING'
        ELSE 'CANCELLED'
    END,
    NOW() + (i || ' days')::interval
FROM generate_series(1, 30) i
ON CONFLICT (id) DO NOTHING;


COMMIT;