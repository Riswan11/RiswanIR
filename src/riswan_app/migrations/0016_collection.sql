CREATE TABLE riswan_data.collection_integrations (
 tenant_id uuid NOT NULL, product_id text NOT NULL, integration_id uuid NOT NULL,
 workload_id uuid NOT NULL, provider_instance_id uuid NOT NULL, source_scope text NOT NULL,
 connector text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, product_id, integration_id),
 UNIQUE (tenant_id, product_id, integration_id, source_scope)
);
CREATE TABLE riswan_data.collection_progress (
 tenant_id uuid NOT NULL, product_id text NOT NULL, integration_id uuid NOT NULL,
 source_scope text NOT NULL, watermark timestamptz, healthy boolean, attempted_at timestamptz,
 PRIMARY KEY (tenant_id, product_id, integration_id, source_scope),
 FOREIGN KEY (tenant_id, product_id, integration_id, source_scope)
 REFERENCES riswan_data.collection_integrations (tenant_id, product_id, integration_id, source_scope)
);
CREATE TABLE riswan_data.collection_observations (
 tenant_id uuid NOT NULL, product_id text NOT NULL, integration_id uuid NOT NULL,
 source_scope text NOT NULL, event_id text NOT NULL, location text NOT NULL,
 digest text NOT NULL, case_id text NOT NULL,
 PRIMARY KEY (tenant_id, product_id, integration_id, source_scope, event_id, location),
 FOREIGN KEY (tenant_id, product_id, integration_id, source_scope)
 REFERENCES riswan_data.collection_integrations (tenant_id, product_id, integration_id, source_scope),
 FOREIGN KEY (tenant_id, product_id, case_id)
 REFERENCES riswan_data.investigations (tenant_id, product_id, investigation_id)
);
CREATE TABLE riswan_data.collection_runs (
 tenant_id uuid NOT NULL, product_id text NOT NULL, integration_id uuid NOT NULL,
 source_scope text NOT NULL, run_id uuid NOT NULL, actor_id uuid NOT NULL,
 start_at timestamptz NOT NULL, end_at timestamptz NOT NULL, completed_at timestamptz NOT NULL DEFAULT now(),
 received bigint NOT NULL CHECK (received >= 0),
 persisted bigint NOT NULL CHECK (persisted BETWEEN 0 AND received),
 PRIMARY KEY (tenant_id, product_id, integration_id, source_scope, run_id),
 CHECK (end_at > start_at),
 FOREIGN KEY (tenant_id, product_id, integration_id, source_scope)
 REFERENCES riswan_data.collection_integrations (tenant_id, product_id, integration_id, source_scope)
);
DO $ddl$
DECLARE t text;
BEGIN
 FOREACH t IN ARRAY ARRAY['collection_integrations', 'collection_progress', 'collection_observations', 'collection_runs']
 LOOP
  EXECUTE format('ALTER TABLE riswan_data.%I ENABLE ROW LEVEL SECURITY', t);
  EXECUTE format('ALTER TABLE riswan_data.%I FORCE ROW LEVEL SECURITY', t);
  EXECUTE format('CREATE POLICY collection_scope ON riswan_data.%I USING (
   tenant_id = nullif(current_setting(''riswan.tenant_id'',true),'''')::uuid
   AND product_id = nullif(current_setting(''riswan.product_id'',true),'''')
   AND integration_id = nullif(current_setting(''riswan.collection_integration'',true),'''')::uuid)', t);
  EXECUTE format('GRANT SELECT, INSERT ON riswan_data.%I TO riswan_runtime', t);
 END LOOP;
END;
$ddl$;
GRANT UPDATE (watermark, healthy, attempted_at) ON riswan_data.collection_progress TO riswan_runtime;
