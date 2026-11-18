BEGIN;

CREATE TABLE IF NOT EXISTS incident_notes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID NOT NULL
        REFERENCES incidents(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    note TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS incident_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID NOT NULL
        REFERENCES incidents(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL
        REFERENCES assets_metadata(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (incident_id, asset_id)
);

CREATE INDEX IF NOT EXISTS idx_incidents_org
ON incidents(organization_id);

CREATE INDEX IF NOT EXISTS idx_incidents_status
ON incidents(status);

CREATE INDEX IF NOT EXISTS idx_incident_notes_incident
ON incident_notes(incident_id);

CREATE INDEX IF NOT EXISTS idx_incident_assets_incident
ON incident_assets(incident_id);

COMMIT;