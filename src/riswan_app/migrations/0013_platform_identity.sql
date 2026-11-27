CREATE SCHEMA riswan_auth;
REVOKE ALL ON SCHEMA riswan_auth FROM PUBLIC;
GRANT USAGE ON SCHEMA riswan_auth TO riswan_identity_runtime;

CREATE TABLE riswan_auth.identities (
    id text PRIMARY KEY, kind text NOT NULL CHECK (kind IN ('human', 'service', 'integration', 'agent')),
    display_name text NOT NULL, email text, status text NOT NULL,
    created double precision NOT NULL, updated double precision NOT NULL
);
CREATE TABLE riswan_auth.identity_provider_links (
    issuer text NOT NULL, subject text NOT NULL,
    identity_id text NOT NULL UNIQUE REFERENCES riswan_auth.identities(id),
    PRIMARY KEY (issuer, subject)
);
CREATE TABLE riswan_auth.identity_sessions (
    id text PRIMARY KEY, identity_id text NOT NULL REFERENCES riswan_auth.identities(id),
    digest text NOT NULL UNIQUE, created double precision NOT NULL,
    last_seen double precision NOT NULL, expires double precision NOT NULL,
    mfa integer NOT NULL CHECK (mfa IN (0, 1)), revoked double precision
);
CREATE INDEX identity_sessions_owner ON riswan_auth.identity_sessions(identity_id, expires);
CREATE TABLE riswan_auth.identity_status_history (
    identity_id text NOT NULL REFERENCES riswan_auth.identities(id), status text NOT NULL,
    recorded double precision NOT NULL
);
CREATE TABLE riswan_auth.authentication_events (
    ordinal bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, event_type text NOT NULL,
    actor_id text, identity_type text, method text NOT NULL,
    mfa integer NOT NULL CHECK (mfa IN (0, 1)), request_id text NOT NULL,
    outcome text NOT NULL, occurred double precision NOT NULL
);

GRANT SELECT, INSERT ON riswan_auth.identities, riswan_auth.identity_provider_links,
    riswan_auth.identity_sessions TO riswan_identity_runtime;
GRANT UPDATE (display_name, email, status, updated) ON riswan_auth.identities TO riswan_identity_runtime;
GRANT UPDATE (last_seen, revoked) ON riswan_auth.identity_sessions TO riswan_identity_runtime;
GRANT INSERT ON riswan_auth.identity_status_history, riswan_auth.authentication_events TO riswan_identity_runtime;
