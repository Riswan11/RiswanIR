ALTER TABLE riswan_data.investigations ADD COLUMN parent_id text;
ALTER TABLE riswan_data.investigations ADD CONSTRAINT scoped_revision_parent
    FOREIGN KEY (tenant_id, product_id, parent_id)
    REFERENCES riswan_data.investigations (tenant_id, product_id, investigation_id);
