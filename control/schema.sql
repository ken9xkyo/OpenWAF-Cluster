CREATE TABLE IF NOT EXISTS users (
 id bigserial PRIMARY KEY, username text UNIQUE NOT NULL, password_hash text NOT NULL,
 role text NOT NULL CHECK(role IN ('admin','engineer','viewer')), enabled boolean NOT NULL DEFAULT true
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash text PRIMARY KEY, user_id bigint REFERENCES users(id) ON DELETE CASCADE,
 csrf text NOT NULL, expires_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS sites (
 id bigserial PRIMARY KEY, hostname text UNIQUE NOT NULL, backend_ip text NOT NULL,
 backend_port integer NOT NULL, mode text NOT NULL DEFAULT 'DetectionOnly',
 paranoia integer NOT NULL DEFAULT 1, enabled boolean NOT NULL DEFAULT true,
 excluded_rules jsonb NOT NULL DEFAULT '[]', exception_reason text NOT NULL DEFAULT '',
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS revisions (
 id bigserial PRIMARY KEY, snapshot jsonb NOT NULL, configs jsonb NOT NULL,
 note text NOT NULL, created_by bigint REFERENCES users(id), created_at timestamptz NOT NULL DEFAULT now(),
 validated boolean NOT NULL DEFAULT false, approved_by bigint REFERENCES users(id),
 approved_at timestamptz, digest text NOT NULL
);
CREATE TABLE IF NOT EXISTS nodes (
 id text PRIMARY KEY, address text NOT NULL, token_hash text NOT NULL,
 desired_revision bigint REFERENCES revisions(id), generation bigint NOT NULL DEFAULT 0,
 actual_revision bigint, actual_digest text, health text NOT NULL DEFAULT 'unknown',
 last_seen timestamptz, detail text NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS deployments (
 id bigserial PRIMARY KEY, revision_id bigint REFERENCES revisions(id) NOT NULL,
 kind text NOT NULL DEFAULT 'deploy', state text NOT NULL DEFAULT 'canary',
 created_by bigint REFERENCES users(id), created_at timestamptz NOT NULL DEFAULT now(),
 completed_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_deployment ON deployments ((true))
 WHERE state IN ('canary','rollout');
CREATE TABLE IF NOT EXISTS audit_events (
 id bigserial PRIMARY KEY, actor text NOT NULL, action text NOT NULL,
 detail jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS waf_events (
 id bigserial PRIMARY KEY, event_key text UNIQUE NOT NULL, node_id text NOT NULL,
 site_id bigint, client_ip text, rule_ids jsonb NOT NULL,
 interrupted boolean NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS waf_events_date ON waf_events(created_at DESC);
