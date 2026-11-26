CREATE TABLE riswan_data.investigation_events (
    tenant_id uuid NOT NULL, product_id text NOT NULL, investigation_id text NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal >= 0), event_id text NOT NULL,
    observed_at timestamptz NOT NULL, event jsonb NOT NULL,
    PRIMARY KEY (tenant_id, product_id, investigation_id, ordinal),
    UNIQUE (tenant_id, product_id, investigation_id, event_id),
    CHECK (event ? 'id' AND event->>'id' = event_id),
    FOREIGN KEY (tenant_id, product_id, investigation_id)
      REFERENCES riswan_data.investigations (tenant_id, product_id, investigation_id)
);
ALTER TABLE riswan_data.investigation_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE riswan_data.investigation_events FORCE ROW LEVEL SECURITY;
CREATE POLICY scoped_events ON riswan_data.investigation_events USING (
    tenant_id = NULLIF(current_setting('riswan.tenant_id', true), '')::uuid
    AND product_id = NULLIF(current_setting('riswan.product_id', true), '')
);
GRANT SELECT, INSERT ON riswan_data.investigation_events TO riswan_runtime;
