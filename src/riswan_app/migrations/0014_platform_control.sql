CREATE SCHEMA riswan_control;
REVOKE ALL ON SCHEMA riswan_control FROM PUBLIC;
GRANT USAGE ON SCHEMA riswan_control TO riswan_control_runtime;

CREATE TABLE riswan_control.organizations (
 id text PRIMARY KEY, name text NOT NULL, settings text NOT NULL, created_at text NOT NULL
);
CREATE TABLE riswan_control.tenants (
 id text PRIMARY KEY, organization_id text NOT NULL UNIQUE REFERENCES riswan_control.organizations,
 status text NOT NULL CHECK (status IN ('active','suspended','archived'))
);
CREATE TABLE riswan_control.organization_memberships (
 tenant_id text NOT NULL REFERENCES riswan_control.tenants,
 identity_id text NOT NULL REFERENCES riswan_auth.identities,
 role text NOT NULL CHECK (role IN ('owner','admin','analyst','viewer')),
 joined_at text NOT NULL, revoked_at text, PRIMARY KEY (tenant_id, identity_id)
);
CREATE UNIQUE INDEX control_active_owner ON riswan_control.organization_memberships(tenant_id)
 WHERE role = 'owner' AND revoked_at IS NULL;
CREATE INDEX control_actor_memberships ON riswan_control.organization_memberships(identity_id, tenant_id)
 WHERE revoked_at IS NULL;
CREATE TABLE riswan_control.organization_invitations (
 id text PRIMARY KEY, tenant_id text NOT NULL REFERENCES riswan_control.tenants,
 identity_id text NOT NULL REFERENCES riswan_auth.identities, role text NOT NULL CHECK (role IN ('analyst','viewer')),
 inviter_id text NOT NULL, digest text NOT NULL UNIQUE, expires_at text NOT NULL, closed_at text,
 FOREIGN KEY (tenant_id, inviter_id) REFERENCES riswan_control.organization_memberships
);
CREATE TABLE riswan_control.authorization_snapshots (
 actor_id text NOT NULL, tenant_id text NOT NULL, policy text NOT NULL,
 PRIMARY KEY (actor_id, tenant_id),
 FOREIGN KEY (tenant_id, actor_id) REFERENCES riswan_control.organization_memberships
);
CREATE TABLE riswan_control.organization_audit_events (
 id text PRIMARY KEY, tenant_id text REFERENCES riswan_control.tenants,
 actor_id text NOT NULL REFERENCES riswan_auth.identities,
 event text NOT NULL, target text, occurred_at text NOT NULL, request_id text NOT NULL
);
CREATE TABLE riswan_control.authorization_audit_events (
 decision_id text PRIMARY KEY, event_type text NOT NULL, decision text NOT NULL,
 tenant_id text GENERATED ALWAYS AS (decision::jsonb->>'tenant_id') STORED NOT NULL
 REFERENCES riswan_control.tenants
);

DO $ddl$
DECLARE item text;
BEGIN
 FOREACH item IN ARRAY ARRAY['organizations','tenants','organization_memberships',
  'organization_invitations','authorization_snapshots','organization_audit_events','authorization_audit_events']
 LOOP
  EXECUTE format('ALTER TABLE riswan_control.%I ENABLE ROW LEVEL SECURITY', item);
  EXECUTE format('ALTER TABLE riswan_control.%I FORCE ROW LEVEL SECURITY', item);
 END LOOP;
END;
$ddl$;

CREATE POLICY membership_self ON riswan_control.organization_memberships FOR SELECT
 USING (identity_id = nullif(current_setting('riswan.control_actor', true),'') AND revoked_at IS NULL);
CREATE POLICY membership_tenant ON riswan_control.organization_memberships
 USING (tenant_id = nullif(current_setting('riswan.control_tenant',true),'')
 AND nullif(current_setting('riswan.control_actor',true),'') IS NOT NULL);
CREATE POLICY invitation_recipient ON riswan_control.organization_invitations FOR SELECT
 USING (identity_id = nullif(current_setting('riswan.control_actor',true),''));
CREATE POLICY invitation_consume ON riswan_control.organization_invitations FOR UPDATE
 USING (identity_id = nullif(current_setting('riswan.control_actor',true),'') AND closed_at IS NULL)
 WITH CHECK (identity_id = nullif(current_setting('riswan.control_actor',true),'') AND closed_at IS NOT NULL);
CREATE POLICY invitation_tenant ON riswan_control.organization_invitations
 USING (tenant_id = nullif(current_setting('riswan.control_tenant',true),'')
 AND nullif(current_setting('riswan.control_actor',true),'') IS NOT NULL);
CREATE POLICY tenant_scope ON riswan_control.tenants
 USING (id = nullif(current_setting('riswan.control_tenant',true),'')
 AND nullif(current_setting('riswan.control_actor',true),'') IS NOT NULL);
CREATE POLICY tenant_discovery ON riswan_control.tenants FOR SELECT USING (
 EXISTS (SELECT 1 FROM riswan_control.organization_memberships m WHERE m.tenant_id = id
  AND m.identity_id = nullif(current_setting('riswan.control_actor', true),'') AND m.revoked_at IS NULL)
 OR (status = 'active' AND EXISTS (SELECT 1 FROM riswan_control.organization_invitations i
  WHERE i.tenant_id = tenants.id AND i.identity_id = nullif(current_setting('riswan.control_actor', true),'')
    AND i.closed_at IS NULL))
);
CREATE POLICY organization_scope ON riswan_control.organizations
 USING (id = nullif(current_setting('riswan.control_org',true),'')
 AND nullif(current_setting('riswan.control_actor',true),'') IS NOT NULL);
CREATE POLICY organization_discovery ON riswan_control.organizations FOR SELECT USING (
 EXISTS (SELECT 1 FROM riswan_control.tenants t JOIN riswan_control.organization_memberships m ON m.tenant_id = t.id
  WHERE t.organization_id = organizations.id
  AND m.identity_id = nullif(current_setting('riswan.control_actor', true),'') AND m.revoked_at IS NULL)
);
CREATE POLICY snapshot_scope ON riswan_control.authorization_snapshots
 USING (tenant_id = nullif(current_setting('riswan.control_tenant',true),'')
 AND nullif(current_setting('riswan.control_actor',true),'') IS NOT NULL);
CREATE POLICY organization_audit_scope ON riswan_control.organization_audit_events FOR INSERT
 WITH CHECK (actor_id = nullif(current_setting('riswan.control_actor',true),'')
  AND (tenant_id = nullif(current_setting('riswan.control_tenant',true),'')
       OR (tenant_id IS NULL AND event = 'platform.tenancy.request_denied')));
CREATE POLICY authorization_audit_scope ON riswan_control.authorization_audit_events FOR INSERT
 WITH CHECK (tenant_id = nullif(current_setting('riswan.control_tenant',true),'')
  AND decision::jsonb->>'actor_id' = nullif(current_setting('riswan.control_actor',true),''));

GRANT SELECT, INSERT ON riswan_control.organizations, riswan_control.tenants,
 riswan_control.organization_memberships, riswan_control.organization_invitations,
 riswan_control.authorization_snapshots TO riswan_control_runtime;
GRANT UPDATE (name, settings) ON riswan_control.organizations TO riswan_control_runtime;
GRANT UPDATE (status) ON riswan_control.tenants TO riswan_control_runtime;
GRANT UPDATE (role, joined_at, revoked_at) ON riswan_control.organization_memberships TO riswan_control_runtime;
GRANT UPDATE (closed_at) ON riswan_control.organization_invitations TO riswan_control_runtime;
GRANT UPDATE (policy), DELETE ON riswan_control.authorization_snapshots TO riswan_control_runtime;
GRANT INSERT ON riswan_control.organization_audit_events, riswan_control.authorization_audit_events
 TO riswan_control_runtime;

CREATE FUNCTION riswan_control.require_active_owner() RETURNS trigger LANGUAGE plpgsql
 SET search_path = pg_catalog, riswan_control, pg_temp AS $fn$
DECLARE target text;
BEGIN
 target := CASE WHEN TG_TABLE_NAME = 'tenants' THEN to_jsonb(NEW)->>'id' ELSE to_jsonb(NEW)->>'tenant_id' END;
 IF NOT EXISTS (SELECT 1 FROM riswan_control.organization_memberships m
  WHERE m.tenant_id = target AND m.role = 'owner' AND m.revoked_at IS NULL) THEN
  RAISE EXCEPTION 'Tenant requires an active owner' USING ERRCODE = '23514';
 END IF;
 RETURN NULL;
END;
$fn$;
CREATE CONSTRAINT TRIGGER tenant_requires_owner AFTER INSERT ON riswan_control.tenants
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION riswan_control.require_active_owner();
CREATE CONSTRAINT TRIGGER membership_requires_owner AFTER INSERT OR UPDATE ON riswan_control.organization_memberships
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION riswan_control.require_active_owner();
