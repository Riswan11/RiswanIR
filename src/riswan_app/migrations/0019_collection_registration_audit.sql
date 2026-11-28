CREATE TABLE riswan_data.collection_registration_audit (
    audit_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    product_id text NOT NULL,
    integration_id uuid NOT NULL,
    workload_id uuid NOT NULL,
    provider_instance_id uuid NOT NULL,
    request_id text NOT NULL CHECK (request_id <> ''),
    correlation_id text NOT NULL CHECK (correlation_id <> ''),
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_id, product_id, integration_id)
);
ALTER TABLE riswan_data.collection_registration_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE riswan_data.collection_registration_audit FORCE ROW LEVEL SECURITY;
CREATE POLICY scoped_registration_event ON riswan_data.collection_registration_audit
    FOR INSERT TO riswan_runtime WITH CHECK (
        tenant_id = NULLIF(current_setting('riswan.tenant_id', true), '')::uuid
        AND product_id = current_setting('riswan.product_id', true)
        AND integration_id = NULLIF(current_setting('riswan.collection_integration', true), '')::uuid
        AND workload_id = NULLIF(current_setting('riswan.collection_workload', true), '')::uuid
        AND workload_id = NULLIF(current_setting('riswan.audit_actor', true), '')::uuid
        AND current_setting('riswan.audit_actor_type', true) IN ('service', 'integration')
        AND request_id = current_setting('riswan.audit_request', true)
        AND correlation_id = current_setting('riswan.audit_correlation', true)
        AND EXISTS (
            SELECT 1 FROM riswan_data.collection_integrations i
            WHERE (i.tenant_id, i.product_id, i.integration_id, i.workload_id, i.provider_instance_id)
                = (collection_registration_audit.tenant_id, collection_registration_audit.product_id,
                   collection_registration_audit.integration_id, collection_registration_audit.workload_id,
                   collection_registration_audit.provider_instance_id)
        )
    );
GRANT INSERT (tenant_id, product_id, integration_id, workload_id, provider_instance_id, request_id, correlation_id)
    ON riswan_data.collection_registration_audit TO riswan_runtime;
CREATE FUNCTION riswan_data.record_collection_registration() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    INSERT INTO riswan_data.collection_registration_audit
        (tenant_id, product_id, integration_id, workload_id, provider_instance_id, request_id, correlation_id)
    VALUES (
        NEW.tenant_id, NEW.product_id, NEW.integration_id, NEW.workload_id, NEW.provider_instance_id,
        current_setting('riswan.audit_request', true), current_setting('riswan.audit_correlation', true)
    );
    RETURN NULL;
END;
$$;
REVOKE EXECUTE ON FUNCTION riswan_data.record_collection_registration() FROM PUBLIC;
CREATE TRIGGER audit_collection_registration AFTER INSERT ON riswan_data.collection_integrations
    FOR EACH ROW EXECUTE FUNCTION riswan_data.record_collection_registration();
