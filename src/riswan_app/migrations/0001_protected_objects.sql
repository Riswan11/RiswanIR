CREATE SCHEMA IF NOT EXISTS riswan_data;
REVOKE CREATE ON SCHEMA riswan_data FROM PUBLIC;
CREATE TABLE IF NOT EXISTS riswan_data.protected_objects (
    tenant_id uuid NOT NULL,
    product_id text NOT NULL CHECK (length(product_id) BETWEEN 1 AND 64),
    object_id uuid NOT NULL,
    envelope bytea NOT NULL,
    PRIMARY KEY (tenant_id, product_id, object_id)
);
ALTER TABLE riswan_data.protected_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE riswan_data.protected_objects FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS scoped_objects ON riswan_data.protected_objects;
CREATE POLICY scoped_objects ON riswan_data.protected_objects
    USING (
        tenant_id = NULLIF(current_setting('riswan.tenant_id', true), '')::uuid
        AND product_id = NULLIF(current_setting('riswan.product_id', true), '')
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('riswan.tenant_id', true), '')::uuid
        AND product_id = NULLIF(current_setting('riswan.product_id', true), '')
    );
GRANT USAGE ON SCHEMA riswan_data TO riswan_runtime;
GRANT SELECT, INSERT, DELETE ON riswan_data.protected_objects TO riswan_runtime;
