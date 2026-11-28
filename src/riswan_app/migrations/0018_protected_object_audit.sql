CREATE TABLE riswan_data.protected_object_audit (
    audit_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    product_id text NOT NULL,
    object_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation IN ('INSERT', 'DELETE')),
    actor_id text NOT NULL CHECK (actor_id <> ''),
    actor_type text NOT NULL CHECK (actor_type IN ('human', 'service', 'integration', 'agent')),
    request_id text NOT NULL CHECK (request_id <> ''),
    correlation_id text NOT NULL CHECK (correlation_id <> ''),
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE riswan_data.protected_object_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE riswan_data.protected_object_audit FORCE ROW LEVEL SECURITY;
CREATE POLICY scoped_object_audit ON riswan_data.protected_object_audit FOR INSERT TO riswan_runtime
    WITH CHECK (
        tenant_id = NULLIF(current_setting('riswan.tenant_id', true), '')::uuid
        AND product_id = current_setting('riswan.product_id', true)
        AND actor_id = current_setting('riswan.audit_actor', true)
        AND actor_type = current_setting('riswan.audit_actor_type', true)
        AND request_id = current_setting('riswan.audit_request', true)
        AND correlation_id = current_setting('riswan.audit_correlation', true)
    );
GRANT INSERT (tenant_id, product_id, object_id, operation, actor_id, actor_type, request_id, correlation_id)
    ON riswan_data.protected_object_audit TO riswan_runtime;
CREATE FUNCTION riswan_data.record_protected_object_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    INSERT INTO riswan_data.protected_object_audit
        (tenant_id, product_id, object_id, operation, actor_id, actor_type, request_id, correlation_id)
    VALUES (
        COALESCE(NEW.tenant_id, OLD.tenant_id), COALESCE(NEW.product_id, OLD.product_id),
        COALESCE(NEW.object_id, OLD.object_id), TG_OP,
        current_setting('riswan.audit_actor', true), current_setting('riswan.audit_actor_type', true),
        current_setting('riswan.audit_request', true), current_setting('riswan.audit_correlation', true)
    );
    RETURN NULL;
END;
$$;
REVOKE EXECUTE ON FUNCTION riswan_data.record_protected_object_mutation() FROM PUBLIC;
CREATE TRIGGER audit_protected_object_mutation AFTER INSERT OR DELETE ON riswan_data.protected_objects
    FOR EACH ROW EXECUTE FUNCTION riswan_data.record_protected_object_mutation();
