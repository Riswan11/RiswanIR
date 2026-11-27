CREATE TABLE riswan_data.investigation_ownership (
    tenant_id uuid NOT NULL,
    product_id text NOT NULL CHECK (length(product_id) BETWEEN 1 AND 64),
    investigation_id text NOT NULL CHECK (investigation_id ~ '^[a-f0-9]{32}$'),
    creator_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, product_id, investigation_id)
);
CREATE INDEX investigation_ownership_recent
ON riswan_data.investigation_ownership(tenant_id, product_id, created_at DESC, investigation_id DESC);

ALTER TABLE riswan_data.investigation_ownership ENABLE ROW LEVEL SECURITY;
ALTER TABLE riswan_data.investigation_ownership FORCE ROW LEVEL SECURITY;
CREATE POLICY scoped_investigation_ownership ON riswan_data.investigation_ownership
    USING (
        tenant_id = NULLIF(current_setting('riswan.tenant_id', true), '')::uuid
        AND product_id = NULLIF(current_setting('riswan.product_id', true), '')
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('riswan.tenant_id', true), '')::uuid
        AND product_id = NULLIF(current_setting('riswan.product_id', true), '')
    );
GRANT SELECT, INSERT ON riswan_data.investigation_ownership TO riswan_runtime;
