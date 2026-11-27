CREATE TABLE riswan_data.case_graph_snapshots (
    tenant_id uuid NOT NULL, product_id text NOT NULL, investigation_id text NOT NULL,
    snapshot text NOT NULL,
    PRIMARY KEY (tenant_id, product_id, investigation_id),
    FOREIGN KEY (tenant_id, product_id, investigation_id)
        REFERENCES riswan_data.investigations (tenant_id, product_id, investigation_id)
);
ALTER TABLE riswan_data.case_graph_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE riswan_data.case_graph_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY scoped_graph_snapshots ON riswan_data.case_graph_snapshots USING (
    tenant_id = NULLIF(current_setting('riswan.tenant_id', true), '')::uuid
    AND product_id = NULLIF(current_setting('riswan.product_id', true), '')
);
GRANT SELECT, INSERT ON riswan_data.case_graph_snapshots TO riswan_runtime;
