CREATE TABLE riswan_data.case_raw_evidence (
    tenant_id uuid NOT NULL, product_id text NOT NULL, investigation_id text NOT NULL,
    raw_id text NOT NULL, digest text NOT NULL, payload text NOT NULL,
    PRIMARY KEY (tenant_id, product_id, investigation_id, raw_id),
    UNIQUE (tenant_id, product_id, investigation_id, digest),
    FOREIGN KEY (tenant_id, product_id, investigation_id)
        REFERENCES riswan_data.investigations (tenant_id, product_id, investigation_id)
);
CREATE TABLE riswan_data.case_evidence_receipts (
    tenant_id uuid NOT NULL, product_id text NOT NULL, investigation_id text NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal >= 0), raw_id text NOT NULL,
    ingested_at text NOT NULL, provenance text NOT NULL,
    PRIMARY KEY (tenant_id, product_id, investigation_id, ordinal),
    FOREIGN KEY (tenant_id, product_id, investigation_id, raw_id)
        REFERENCES riswan_data.case_raw_evidence (tenant_id, product_id, investigation_id, raw_id)
);
CREATE TABLE riswan_data.case_evidence_transformations (
    tenant_id uuid NOT NULL, product_id text NOT NULL, investigation_id text NOT NULL,
    event_id text NOT NULL, normalized_id text NOT NULL, metadata text NOT NULL,
    PRIMARY KEY (tenant_id, product_id, investigation_id, event_id),
    UNIQUE (tenant_id, product_id, investigation_id, normalized_id),
    FOREIGN KEY (tenant_id, product_id, investigation_id, event_id)
        REFERENCES riswan_data.investigation_events (tenant_id, product_id, investigation_id, event_id)
);
CREATE TABLE riswan_data.case_custody (
    tenant_id uuid NOT NULL, product_id text NOT NULL, investigation_id text NOT NULL,
    sequence integer NOT NULL CHECK (sequence > 0), entry text NOT NULL,
    PRIMARY KEY (tenant_id, product_id, investigation_id, sequence),
    FOREIGN KEY (tenant_id, product_id, investigation_id)
        REFERENCES riswan_data.investigations (tenant_id, product_id, investigation_id)
);
CREATE TABLE riswan_data.case_findings (
    tenant_id uuid NOT NULL, product_id text NOT NULL, investigation_id text NOT NULL,
    family text NOT NULL CHECK (family IN ('detection', 'assessment')),
    ordinal integer NOT NULL CHECK (ordinal >= 0), finding jsonb NOT NULL,
    PRIMARY KEY (tenant_id, product_id, investigation_id, family, ordinal),
    FOREIGN KEY (tenant_id, product_id, investigation_id)
        REFERENCES riswan_data.investigations (tenant_id, product_id, investigation_id)
);
DO $policy$
DECLARE target text;
BEGIN
    FOREACH target IN ARRAY ARRAY['case_raw_evidence', 'case_evidence_receipts',
        'case_evidence_transformations', 'case_custody', 'case_findings']
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
CREATE INDEX scoped_event_timeline ON riswan_data.investigation_events
    (tenant_id, product_id, investigation_id, observed_at, ordinal);
CREATE INDEX scoped_event_type_timeline ON riswan_data.investigation_events
    (tenant_id, product_id, investigation_id, (event #>> '{classification,type_uid}'), observed_at, ordinal);
