CREATE TABLE riswan_data.investigations (
    tenant_id uuid NOT NULL,
    product_id text NOT NULL,
    investigation_id text NOT NULL,
    report jsonb NOT NULL CHECK (jsonb_typeof(report) = 'object' AND report->>'id' = investigation_id),
    artifacts jsonb NOT NULL CHECK (jsonb_typeof(artifacts) = 'object'),
    PRIMARY KEY (tenant_id, product_id, investigation_id),
    FOREIGN KEY (tenant_id, product_id, investigation_id)
        REFERENCES riswan_data.investigation_ownership (tenant_id, product_id, investigation_id)
);

ALTER TABLE riswan_data.investigations ENABLE ROW LEVEL SECURITY;
ALTER TABLE riswan_data.investigations FORCE ROW LEVEL SECURITY;
CREATE POLICY scoped_investigations ON riswan_data.investigations
    USING (
        tenant_id = NULLIF(current_setting('riswan.tenant_id', true), '')::uuid
        AND product_id = NULLIF(current_setting('riswan.product_id', true), '')
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('riswan.tenant_id', true), '')::uuid
        AND product_id = NULLIF(current_setting('riswan.product_id', true), '')
    );
GRANT SELECT, INSERT ON riswan_data.investigations TO riswan_runtime;
GRANT UPDATE (report) ON riswan_data.investigations TO riswan_runtime;
