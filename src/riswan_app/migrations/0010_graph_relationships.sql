CREATE TABLE riswan_data.case_graph_nodes (
    tenant_id uuid NOT NULL, product_id text NOT NULL, investigation_id text NOT NULL,
    node_id text NOT NULL, ordinal integer NOT NULL, node jsonb NOT NULL,
    PRIMARY KEY (tenant_id, product_id, investigation_id, node_id),
    UNIQUE (tenant_id, product_id, investigation_id, ordinal),
    FOREIGN KEY (tenant_id, product_id, investigation_id)
        REFERENCES riswan_data.case_graph_snapshots (tenant_id, product_id, investigation_id)
);
CREATE TABLE riswan_data.case_graph_edges (
    tenant_id uuid NOT NULL, product_id text NOT NULL, investigation_id text NOT NULL,
    edge_id text NOT NULL, ordinal integer NOT NULL,
    source_id text NOT NULL, target_id text NOT NULL, edge jsonb NOT NULL,
    PRIMARY KEY (tenant_id, product_id, investigation_id, edge_id),
    UNIQUE (tenant_id, product_id, investigation_id, ordinal),
    FOREIGN KEY (tenant_id, product_id, investigation_id, source_id)
        REFERENCES riswan_data.case_graph_nodes (tenant_id, product_id, investigation_id, node_id),
    FOREIGN KEY (tenant_id, product_id, investigation_id, target_id)
        REFERENCES riswan_data.case_graph_nodes (tenant_id, product_id, investigation_id, node_id)
);
DO $policy$
DECLARE target text;
BEGIN
    FOREACH target IN ARRAY ARRAY['case_graph_nodes', 'case_graph_edges']
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
