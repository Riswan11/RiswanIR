CREATE TABLE riswan_data.investigation_legal_holds (
    tenant_id uuid NOT NULL, product_id text NOT NULL, investigation_id text NOT NULL,
    id uuid NOT NULL, created_at timestamptz NOT NULL, released_at timestamptz,
    PRIMARY KEY (tenant_id, product_id, investigation_id, id),
    FOREIGN KEY (tenant_id, product_id, investigation_id)
      REFERENCES riswan_data.investigations (tenant_id, product_id, investigation_id)
);
CREATE TABLE riswan_data.investigation_hold_audit (
    tenant_id uuid NOT NULL, product_id text NOT NULL, investigation_id text NOT NULL,
    hold_id uuid NOT NULL, action text NOT NULL CHECK (action IN ('created', 'released')),
    actor_id uuid NOT NULL, occurred_at timestamptz NOT NULL,
    request_id text NOT NULL, reason text NOT NULL,
    PRIMARY KEY (tenant_id, product_id, investigation_id, hold_id, action),
    FOREIGN KEY (tenant_id, product_id, investigation_id, hold_id)
      REFERENCES riswan_data.investigation_legal_holds (tenant_id, product_id, investigation_id, id)
);
CREATE TABLE riswan_data.investigation_memory_removals (
    tenant_id uuid NOT NULL, product_id text NOT NULL, investigation_id text NOT NULL,
    PRIMARY KEY (tenant_id, product_id, investigation_id),
    FOREIGN KEY (tenant_id, product_id, investigation_id)
      REFERENCES riswan_data.investigations (tenant_id, product_id, investigation_id)
);
DO $policy$
DECLARE target text;
BEGIN
    FOREACH target IN ARRAY ARRAY['investigation_legal_holds','investigation_hold_audit','investigation_memory_removals']
    LOOP
        EXECUTE format('ALTER TABLE riswan_data.%I ENABLE ROW LEVEL SECURITY', target);
        EXECUTE format('ALTER TABLE riswan_data.%I FORCE ROW LEVEL SECURITY', target);
        EXECUTE format(
            'CREATE POLICY scoped ON riswan_data.%I USING (
                tenant_id = NULLIF(current_setting(''riswan.tenant_id'', true), '''')::uuid
                AND product_id = NULLIF(current_setting(''riswan.product_id'', true), '''')
            )', target
        );
    END LOOP;
END;
$policy$;
GRANT SELECT, INSERT ON riswan_data.investigation_legal_holds, riswan_data.investigation_hold_audit,
    riswan_data.investigation_memory_removals TO riswan_runtime;
GRANT UPDATE (released_at) ON riswan_data.investigation_legal_holds TO riswan_runtime;
