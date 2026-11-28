CREATE TABLE riswan_control.secret_provider_bindings (
 tenant_id text NOT NULL REFERENCES riswan_control.tenants,
 product text NOT NULL, instance_id text NOT NULL, binding text NOT NULL,
 PRIMARY KEY (tenant_id, product, instance_id), UNIQUE (instance_id)
);
CREATE TABLE riswan_control.secret_metadata (
 id text NOT NULL, tenant_id text NOT NULL REFERENCES riswan_control.tenants,
 product text NOT NULL, metadata text NOT NULL,
 active_version text GENERATED ALWAYS AS (metadata::jsonb->>'current_version') STORED,
 provider_instance text GENERATED ALWAYS AS (metadata::jsonb->>'provider_instance_id') STORED,
 PRIMARY KEY (tenant_id, product, id), UNIQUE (tenant_id, id),
 FOREIGN KEY (tenant_id, product, provider_instance) REFERENCES riswan_control.secret_provider_bindings,
 CHECK (metadata::jsonb->>'id' IS NOT DISTINCT FROM id AND metadata::jsonb->>'tenant_id' IS NOT DISTINCT FROM tenant_id
   AND metadata::jsonb->>'product_id' IS NOT DISTINCT FROM product)
);
CREATE TABLE riswan_control.secret_versions (
 secret_id text NOT NULL, id text NOT NULL, version text NOT NULL,
 tenant_id text NOT NULL DEFAULT current_setting('riswan.control_tenant', true),
 product text NOT NULL DEFAULT current_setting('riswan.secret_product', true),
 rowid bigint GENERATED ALWAYS AS IDENTITY,
 PRIMARY KEY (tenant_id, product, secret_id, id),
 FOREIGN KEY (tenant_id, product, secret_id) REFERENCES riswan_control.secret_metadata,
 CHECK (version::jsonb->>'id' IS NOT DISTINCT FROM id)
);
ALTER TABLE riswan_control.secret_metadata ADD CONSTRAINT secret_active_version
 FOREIGN KEY (tenant_id, product, id, active_version)
 REFERENCES riswan_control.secret_versions (tenant_id, product, secret_id, id);
CREATE TABLE riswan_control.secret_rotations (
 secret_id text NOT NULL, id text NOT NULL, operation text NOT NULL,
 tenant_id text NOT NULL DEFAULT current_setting('riswan.control_tenant', true),
 product text NOT NULL DEFAULT current_setting('riswan.secret_product', true),
 PRIMARY KEY (tenant_id, product, secret_id, id),
 FOREIGN KEY (tenant_id, product, secret_id) REFERENCES riswan_control.secret_metadata,
 CHECK (operation::jsonb->>'id' IS NOT DISTINCT FROM id AND operation::jsonb->>'secret_id' IS NOT DISTINCT FROM secret_id)
);
CREATE TABLE riswan_control.secret_consumer_policies (
 secret_id text NOT NULL, workload_id text NOT NULL, purpose text NOT NULL,
 policy text NOT NULL, membership_joined text NOT NULL,
 tenant_id text NOT NULL DEFAULT current_setting('riswan.control_tenant', true),
 product text NOT NULL DEFAULT current_setting('riswan.secret_product', true),
 UNIQUE (secret_id, workload_id, purpose, tenant_id, product),
 FOREIGN KEY (tenant_id, product, secret_id) REFERENCES riswan_control.secret_metadata,
 FOREIGN KEY (tenant_id, workload_id) REFERENCES riswan_control.organization_memberships,
 CHECK (policy::jsonb->>'workload_id' IS NOT DISTINCT FROM workload_id AND policy::jsonb->>'purpose' IS NOT DISTINCT FROM purpose)
);
CREATE TABLE riswan_control.secret_access_events (
 sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 secret_id text NOT NULL, tenant_id text NOT NULL REFERENCES riswan_control.tenants, event text NOT NULL,
 product text GENERATED ALWAYS AS (event::jsonb->>'product_id') STORED NOT NULL,
 CHECK (event::jsonb->>'secret_id' IS NOT DISTINCT FROM secret_id AND event::jsonb->>'tenant_id' IS NOT DISTINCT FROM tenant_id)
);
CREATE INDEX secret_scoped_audit ON riswan_control.secret_access_events
 (tenant_id, product, secret_id, sequence DESC);

DO $ddl$
DECLARE item text;
BEGIN
 FOREACH item IN ARRAY ARRAY['secret_provider_bindings','secret_metadata','secret_versions',
 'secret_rotations','secret_consumer_policies','secret_access_events']
 LOOP
  EXECUTE format('ALTER TABLE riswan_control.%I ENABLE ROW LEVEL SECURITY', item);
  EXECUTE format('ALTER TABLE riswan_control.%I FORCE ROW LEVEL SECURITY', item);
  EXECUTE format('CREATE POLICY scoped_secret ON riswan_control.%I USING (
   tenant_id = nullif(current_setting(''riswan.control_tenant'',true),'''')
   AND product = nullif(current_setting(''riswan.secret_product'',true),'''')
   AND nullif(current_setting(''riswan.control_actor'',true),'''') IS NOT NULL)', item);
  EXECUTE format('GRANT SELECT, INSERT ON riswan_control.%I TO riswan_control_runtime', item);
 END LOOP;
END;
$ddl$;
CREATE POLICY secret_audit_actor ON riswan_control.secret_access_events AS RESTRICTIVE
 FOR INSERT TO riswan_control_runtime WITH CHECK (
  event::jsonb->>'actor_id' IS NOT DISTINCT FROM nullif(current_setting('riswan.control_actor',true),'')
 );
GRANT UPDATE (metadata) ON riswan_control.secret_metadata TO riswan_control_runtime;
GRANT UPDATE (version) ON riswan_control.secret_versions TO riswan_control_runtime;
GRANT UPDATE (operation) ON riswan_control.secret_rotations TO riswan_control_runtime;
GRANT UPDATE (policy, membership_joined), DELETE ON riswan_control.secret_consumer_policies TO riswan_control_runtime;

CREATE TABLE riswan_control.credential_bindings (
 tenant_id text NOT NULL, product text NOT NULL, integration_id text NOT NULL,
 instance_id text NOT NULL, workload_id text NOT NULL, membership_joined text NOT NULL,
 request text NOT NULL,
 PRIMARY KEY (tenant_id, product, integration_id, workload_id, membership_joined),
 FOREIGN KEY (tenant_id, product, instance_id) REFERENCES riswan_control.secret_provider_bindings,
 FOREIGN KEY (tenant_id, workload_id) REFERENCES riswan_control.organization_memberships,
 CHECK (request::jsonb->>'integration_id' IS NOT DISTINCT FROM integration_id AND request::jsonb->>'workload_id' IS NOT DISTINCT FROM workload_id)
);
CREATE TABLE riswan_control.credential_leases (
 tenant_id text NOT NULL, product text NOT NULL, integration_id text NOT NULL,
 workload_id text NOT NULL, membership_joined text NOT NULL, id text NOT NULL, expires_at timestamptz NOT NULL,
 PRIMARY KEY (tenant_id, product, id),
 FOREIGN KEY (tenant_id, product, integration_id, workload_id, membership_joined)
 REFERENCES riswan_control.credential_bindings
);
DO $ddl$
DECLARE item text;
BEGIN
 FOREACH item IN ARRAY ARRAY['credential_bindings','credential_leases']
 LOOP
  EXECUTE format('ALTER TABLE riswan_control.%I ENABLE ROW LEVEL SECURITY', item);
  EXECUTE format('ALTER TABLE riswan_control.%I FORCE ROW LEVEL SECURITY', item);
  EXECUTE format('CREATE POLICY scoped_credential ON riswan_control.%I USING (
   tenant_id = nullif(current_setting(''riswan.control_tenant'',true),'''')
   AND product = nullif(current_setting(''riswan.secret_product'',true),'''')
   AND workload_id = nullif(current_setting(''riswan.control_actor'',true),''''))', item);
  EXECUTE format('GRANT SELECT, INSERT ON riswan_control.%I TO riswan_control_runtime', item);
 END LOOP;
END;
$ddl$;
