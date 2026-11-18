-- =====================================================
-- NexaGraph AI
-- Migration 002: Asset Network Relationships
-- =====================================================

CREATE TABLE IF NOT EXISTS asset_network_relationships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    organization_id UUID NOT NULL
        REFERENCES organizations(id) ON DELETE CASCADE,

    source_asset_id UUID NOT NULL
        REFERENCES assets_metadata(id) ON DELETE CASCADE,

    target_asset_id UUID NOT NULL
        REFERENCES assets_metadata(id) ON DELETE CASCADE,

    relationship_type VARCHAR(40) NOT NULL,

    protocol VARCHAR(30) DEFAULT 'TCP',

    port INTEGER,

    direction VARCHAR(20) DEFAULT 'OUTBOUND',

    status VARCHAR(20) DEFAULT 'ACTIVE',

    description TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT chk_different_assets
        CHECK (source_asset_id <> target_asset_id),

    CONSTRAINT chk_relationship_type
        CHECK (
            relationship_type IN (
                'CONNECTS_TO',
                'ALLOWS_TRAFFIC',
                'HOSTED_ON',
                'DEPENDS_ON',
                'PROTECTED_BY'
            )
        ),

    CONSTRAINT chk_valid_port
        CHECK (port IS NULL OR port BETWEEN 1 AND 65535),

    CONSTRAINT chk_relationship_direction
        CHECK (direction IN ('INBOUND', 'OUTBOUND', 'BIDIRECTIONAL')),

    CONSTRAINT chk_relationship_status
        CHECK (status IN ('ACTIVE', 'INACTIVE', 'PENDING'))
);

-- Performance indexes

CREATE INDEX IF NOT EXISTS idx_network_source
ON asset_network_relationships(source_asset_id);

CREATE INDEX IF NOT EXISTS idx_network_target
ON asset_network_relationships(target_asset_id);

CREATE INDEX IF NOT EXISTS idx_network_organization
ON asset_network_relationships(organization_id);

CREATE INDEX IF NOT EXISTS idx_network_relationship_type
ON asset_network_relationships(relationship_type);

CREATE INDEX IF NOT EXISTS idx_network_status
ON asset_network_relationships(status);