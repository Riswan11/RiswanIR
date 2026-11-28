CREATE TABLE riswan_data.collection_integrations (
 tenant_id uuid NOT NULL, product_id text NOT NULL, integration_id uuid NOT NULL,
 workload_id uuid NOT NULL, provider_instance_id uuid NOT NULL, source_scope text NOT NULL,
 connector text NOT NULL, membership_joined timestamptz NOT NULL, namespace text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), enabled boolean NOT NULL DEFAULT true,
 PRIMARY KEY (tenant_id, product_id, integration_id),
 UNIQUE (tenant_id, product_id, integration_id, source_scope)
);
CREATE TABLE riswan_data.collection_progress (
 tenant_id uuid NOT NULL, product_id text NOT NULL, integration_id uuid NOT NULL,
 source_scope text NOT NULL, watermark timestamptz, healthy boolean, attempted_at timestamptz,
 failure_code text CHECK (failure_code IN ('provider_failure', 'storage_failure')),
 pending_start timestamptz, pending_end timestamptz,
 CHECK ((pending_start IS NULL AND pending_end IS NULL) OR
        (pending_start IS NOT NULL AND pending_end IS NOT NULL AND pending_end > pending_start)),
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
 failure_code text CHECK (failure_code IN ('provider_failure', 'storage_failure')),
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
  IF t = 'collection_integrations' THEN
   EXECUTE 'CREATE POLICY collection_scope ON riswan_data.collection_integrations USING (
     tenant_id = nullif(current_setting(''riswan.tenant_id'',true),'''')::uuid
     AND product_id = nullif(current_setting(''riswan.product_id'',true),'''')
     AND integration_id = nullif(current_setting(''riswan.collection_integration'',true),'''')::uuid
     AND workload_id = nullif(current_setting(''riswan.collection_workload'',true),'''')::uuid)';
  ELSE
   EXECUTE format('CREATE POLICY collection_scope ON riswan_data.%I USING (
     EXISTS (SELECT 1 FROM riswan_data.collection_integrations i
     WHERE (i.tenant_id,i.product_id,i.integration_id,i.source_scope) =
     (%I.tenant_id,%I.product_id,%I.integration_id,%I.source_scope)))', t,t,t,t,t);
  END IF;
  EXECUTE format('GRANT SELECT, INSERT ON riswan_data.%I TO riswan_runtime', t);
 END LOOP;
END;
$ddl$;
GRANT UPDATE (watermark, healthy, attempted_at, failure_code, pending_start, pending_end) ON riswan_data.collection_progress TO riswan_runtime;

-- Administrative enable/disable changes serialize with product publication.
CREATE FUNCTION riswan_data.lock_collection_integration() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $fn$
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(OLD.integration_id::text, 796016));
 RETURN NEW;
END;
$fn$;
CREATE TRIGGER collection_integration_change BEFORE UPDATE ON riswan_data.collection_integrations
 FOR EACH ROW EXECUTE FUNCTION riswan_data.lock_collection_integration();

-- Privileged binding edits take the control lock before acquiring row locks.
CREATE FUNCTION riswan_control.lock_collection_binding() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $fn$
BEGIN
 PERFORM pg_advisory_xact_lock(947062);
 RETURN NULL;
END;
$fn$;
CREATE TRIGGER collection_provider_binding_change BEFORE UPDATE OR DELETE ON riswan_control.secret_provider_bindings
 FOR EACH STATEMENT EXECUTE FUNCTION riswan_control.lock_collection_binding();
CREATE TRIGGER collection_credential_binding_change BEFORE UPDATE OR DELETE ON riswan_control.credential_bindings
 FOR EACH STATEMENT EXECUTE FUNCTION riswan_control.lock_collection_binding();

-- Direct identity status writes honor the same lock as application mutations.
CREATE FUNCTION riswan_auth.lock_collection_identity_status() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $fn$
BEGIN
 PERFORM pg_advisory_xact_lock(947061);
 RETURN NULL;
END;
$fn$;
CREATE TRIGGER collection_identity_status_change BEFORE UPDATE OF status ON riswan_auth.identities
 FOR EACH STATEMENT EXECUTE FUNCTION riswan_auth.lock_collection_identity_status();
