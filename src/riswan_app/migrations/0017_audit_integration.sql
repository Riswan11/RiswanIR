CREATE INDEX organization_audit_timeline ON riswan_control.organization_audit_events
 (tenant_id, occurred_at DESC, id DESC) WHERE tenant_id IS NOT NULL;

CREATE POLICY organization_audit_read ON riswan_control.organization_audit_events
 FOR SELECT TO riswan_control_runtime USING (
  tenant_id = nullif(current_setting('riswan.control_tenant', true),'')
  AND tenant_id = nullif(current_setting('riswan.audit_read_tenant', true),'')
  AND nullif(current_setting('riswan.control_actor', true),'') IS NOT NULL
 );
GRANT SELECT ON riswan_control.organization_audit_events TO riswan_control_runtime;

ALTER TABLE riswan_data.collection_runs
 ADD COLUMN request_id text,
 ADD COLUMN correlation_id text;
CREATE INDEX collection_runs_correlation ON riswan_data.collection_runs
 (tenant_id, product_id, integration_id, correlation_id) WHERE correlation_id IS NOT NULL;

CREATE POLICY collection_run_attribution ON riswan_data.collection_runs AS RESTRICTIVE
 FOR INSERT TO riswan_runtime WITH CHECK (
  actor_id = nullif(current_setting('riswan.collection_workload', true),'')::uuid
  AND request_id = nullif(current_setting('riswan.audit_request', true),'')
  AND correlation_id = nullif(current_setting('riswan.audit_correlation', true),'')
 );
