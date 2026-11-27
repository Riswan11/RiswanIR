CREATE TABLE riswan_data.case_temporal_snapshots (
    tenant_id uuid NOT NULL, product_id text NOT NULL, investigation_id text NOT NULL,
    snapshot text NOT NULL,
    PRIMARY KEY (tenant_id, product_id, investigation_id),
    FOREIGN KEY (tenant_id, product_id, investigation_id)
        REFERENCES riswan_data.investigations (tenant_id, product_id, investigation_id)
);
CREATE TABLE riswan_data.case_risk_assessments (
    tenant_id uuid NOT NULL, product_id text NOT NULL, investigation_id text NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal > 0), id text NOT NULL,
    kind text NOT NULL, subject_id text NOT NULL, archive text NOT NULL,
    PRIMARY KEY (tenant_id, product_id, investigation_id, ordinal),
    UNIQUE (tenant_id, product_id, investigation_id, id),
    FOREIGN KEY (tenant_id, product_id, investigation_id)
        REFERENCES riswan_data.investigations (tenant_id, product_id, investigation_id)
);
CREATE INDEX case_risk_subject_history
    ON riswan_data.case_risk_assessments
        (tenant_id, product_id, investigation_id, kind, subject_id, ordinal DESC);
DO $policy$
DECLARE target text;
BEGIN
    FOREACH target IN ARRAY ARRAY['case_temporal_snapshots', 'case_risk_assessments']
    LOOP
        EXECUTE format('ALTER TABLE riswan_data.%I ENABLE ROW LEVEL SECURITY', target);
        EXECUTE format('ALTER TABLE riswan_data.%I FORCE ROW LEVEL SECURITY', target);
        EXECUTE format(
            'CREATE POLICY scoped ON riswan_data.%I USING (
                tenant_id = NULLIF(current_setting(''riswan.tenant_id'', true), '''')::uuid
                AND product_id = NULLIF(current_setting(''riswan.product_id'', true), '''')
            )', target
        );
        EXECUTE format('GRANT SELECT, INSERT ON riswan_data.%I TO riswan_runtime', target);
    END LOOP;
END;
$policy$;
