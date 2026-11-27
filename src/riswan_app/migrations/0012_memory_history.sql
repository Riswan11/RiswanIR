CREATE TABLE riswan_data.case_memory_history (
    tenant_id uuid NOT NULL, product_id text NOT NULL, investigation_id text NOT NULL,
    id uuid NOT NULL, actor_id text NOT NULL, kind text NOT NULL
        CHECK (kind IN ('review', 'feedback', 'response', 'audit')),
    ordinal bigint NOT NULL CHECK (ordinal > 0), recorded_at text NOT NULL,
    entry jsonb NOT NULL,
    PRIMARY KEY (tenant_id, product_id, investigation_id, kind, ordinal),
    UNIQUE (tenant_id, product_id, investigation_id, id),
    FOREIGN KEY (tenant_id, product_id, investigation_id)
        REFERENCES riswan_data.case_memory_snapshots (tenant_id, product_id, investigation_id)
);
ALTER TABLE riswan_data.case_memory_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE riswan_data.case_memory_history FORCE ROW LEVEL SECURITY;
CREATE POLICY scoped_memory_history ON riswan_data.case_memory_history USING (
    tenant_id = NULLIF(current_setting('riswan.tenant_id', true), '')::uuid
    AND product_id = NULLIF(current_setting('riswan.product_id', true), '')
);
GRANT SELECT, INSERT ON riswan_data.case_memory_history TO riswan_runtime;
CREATE INDEX memory_snapshot_window ON riswan_data.case_memory_snapshots
    (tenant_id, product_id, (snapshot #>> '{memory_cases,0,indexed_at}') DESC, investigation_id);
