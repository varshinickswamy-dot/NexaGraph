-- =====================================================
-- NEXAGRAPH AI
-- MIGRATION 004: ORGANIZATION INVITATIONS
-- =====================================================

BEGIN;

CREATE TABLE IF NOT EXISTS organization_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    organization_id UUID NOT NULL
        REFERENCES organizations(id) ON DELETE CASCADE,

    email VARCHAR(255) NOT NULL,

    code_hash VARCHAR(64) NOT NULL UNIQUE,

    role_id UUID NOT NULL
        REFERENCES roles(id),

    created_by UUID
        REFERENCES users(id) ON DELETE SET NULL,

    accepted_by UUID
        REFERENCES users(id) ON DELETE SET NULL,

    expires_at TIMESTAMPTZ NOT NULL,

    accepted_at TIMESTAMPTZ,

    revoked_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT invitation_expiry_check
        CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS idx_org_invitations_org
ON organization_invitations(organization_id);

CREATE INDEX IF NOT EXISTS idx_org_invitations_email
ON organization_invitations(LOWER(email));

CREATE INDEX IF NOT EXISTS idx_org_invitations_expiry
ON organization_invitations(expires_at);

CREATE INDEX IF NOT EXISTS idx_org_invitations_creator
ON organization_invitations(created_by);

COMMENT ON TABLE organization_invitations IS
'Secure, single-use invitations for joining NexaGraph AI organizations.';

COMMIT;