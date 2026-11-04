-- Observatorio DNSSEC - FASE 2 laboratory schema
-- Target: PostgreSQL / Cloud SQL PostgreSQL
--
-- This schema stores access control, DNSViz jobs, normalized domains,
-- artifacts, structured findings, infrastructure groupings, reports,
-- publications, and audit/rate-limit data.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE app_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL UNIQUE,
    display_name TEXT,
    auth_provider TEXT NOT NULL DEFAULT 'google_workspace',
    workspace_subject TEXT,
    password_hash TEXT,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ
);

CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_by UUID REFERENCES app_users(id) ON DELETE SET NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);

INSERT INTO roles (code, name, description) VALUES
    ('superadmin', 'Superadmin', 'Full system access, including users, settings, laboratory, and publications.'),
    ('admin', 'Admin', 'Manage users, reports, limits, and operational review.'),
    ('researcher', 'Researcher', 'Run laboratory jobs and generate internal reports.'),
    ('viewer', 'Viewer', 'Read-only access to authorized internal results.')
ON CONFLICT (code) DO NOTHING;

CREATE TABLE system_settings (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    updated_by UUID REFERENCES app_users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO system_settings (key, value) VALUES
    ('bulk_limits', '{"max_domains_per_job":100,"max_concurrent_jobs":2,"max_concurrent_domains":2,"cache_ttl_hours":24}'::jsonb),
    ('phase_contract', '{"phase1_public_downloads":["graph.png","graph.svg"],"phase2_requires_auth":true}'::jsonb)
ON CONFLICT (key) DO NOTHING;

CREATE TABLE analysis_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_type TEXT NOT NULL CHECK (job_type IN ('single', 'bulk')),
    title TEXT,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'queued'
        CHECK (status IN ('draft', 'queued', 'running', 'done', 'partial', 'failed', 'cancelled')),
    requested_by UUID REFERENCES app_users(id) ON DELETE SET NULL,
    source TEXT NOT NULL DEFAULT 'lab',
    total_domains INTEGER NOT NULL DEFAULT 0,
    completed_domains INTEGER NOT NULL DEFAULT 0,
    failed_domains INTEGER NOT NULL DEFAULT 0,
    progress INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
    queue_priority INTEGER NOT NULL DEFAULT 100,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX idx_analysis_jobs_status ON analysis_jobs(status, created_at);
CREATE INDEX idx_analysis_jobs_requested_by ON analysis_jobs(requested_by, created_at DESC);

CREATE TABLE domain_inputs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    original_value TEXT NOT NULL,
    normalized_domain TEXT NOT NULL,
    registrable_domain TEXT,
    public_suffix TEXT,
    tld TEXT,
    tld_type TEXT CHECK (tld_type IN ('ccTLD', 'gTLD', 'arpa', 'unknown') OR tld_type IS NULL),
    normalization_status TEXT NOT NULL DEFAULT 'accepted'
        CHECK (normalization_status IN ('accepted', 'changed', 'ambiguous', 'invalid')),
    normalization_rules JSONB NOT NULL DEFAULT '[]'::jsonb,
    warning TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_domain_inputs_normalized ON domain_inputs(normalized_domain);
CREATE INDEX idx_domain_inputs_tld ON domain_inputs(tld, tld_type);

CREATE TABLE analysis_job_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL REFERENCES analysis_jobs(id) ON DELETE CASCADE,
    domain_input_id UUID NOT NULL REFERENCES domain_inputs(id) ON DELETE RESTRICT,
    normalized_domain TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'running', 'done', 'failed', 'skipped', 'cancelled')),
    progress INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    result_snapshot_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    UNIQUE (job_id, normalized_domain)
);

CREATE INDEX idx_analysis_job_items_job_status ON analysis_job_items(job_id, status);
CREATE INDEX idx_analysis_job_items_domain ON analysis_job_items(normalized_domain);

CREATE TABLE domain_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_item_id UUID REFERENCES analysis_job_items(id) ON DELETE SET NULL,
    domain TEXT NOT NULL,
    generated_at TIMESTAMPTZ NOT NULL,
    vantage_point TEXT NOT NULL DEFAULT 'gcp_dual_stack',
    worker_project TEXT,
    worker_zone TEXT,
    worker_vm TEXT,
    dnssec_status TEXT,
    service_health TEXT,
    error_count INTEGER NOT NULL DEFAULT 0,
    warning_count INTEGER NOT NULL DEFAULT 0,
    zone_chain TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    dnsviz_version TEXT,
    public_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    structured_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE analysis_job_items
    ADD CONSTRAINT fk_analysis_job_items_snapshot
    FOREIGN KEY (result_snapshot_id) REFERENCES domain_snapshots(id) ON DELETE SET NULL;

CREATE INDEX idx_domain_snapshots_domain_time ON domain_snapshots(domain, generated_at DESC);
CREATE INDEX idx_domain_snapshots_status ON domain_snapshots(dnssec_status, service_health);

CREATE TABLE dnsviz_artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_id UUID NOT NULL REFERENCES domain_snapshots(id) ON DELETE CASCADE,
    artifact_type TEXT NOT NULL CHECK (artifact_type IN (
        'probe_json', 'grok_json', 'print_txt', 'graph_html', 'graph_png', 'graph_svg',
        'result_json', 'public_json', 'report_pdf', 'report_html', 'report_csv'
    )),
    storage_provider TEXT NOT NULL DEFAULT 'cloud_storage',
    storage_uri TEXT NOT NULL,
    content_type TEXT,
    byte_size BIGINT,
    sha256 TEXT,
    public_access BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (snapshot_id, artifact_type)
);

CREATE INDEX idx_dnsviz_artifacts_snapshot ON dnsviz_artifacts(snapshot_id);
CREATE INDEX idx_dnsviz_artifacts_public ON dnsviz_artifacts(public_access, artifact_type);

CREATE TABLE dnssec_status_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_id UUID NOT NULL REFERENCES domain_snapshots(id) ON DELETE CASCADE,
    section TEXT NOT NULL CHECK (section IN ('rrset_status', 'dnskey_ds_nsec_status', 'delegation_status')),
    status TEXT NOT NULL,
    item_count INTEGER NOT NULL DEFAULT 0,
    items JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_dnssec_status_groups_snapshot ON dnssec_status_groups(snapshot_id, section);

CREATE TABLE dnssec_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_id UUID NOT NULL REFERENCES domain_snapshots(id) ON DELETE CASCADE,
    severity TEXT NOT NULL CHECK (severity IN ('error', 'warning', 'notice', 'info')),
    code TEXT,
    zone TEXT,
    node_key TEXT,
    node_label TEXT,
    node_status TEXT,
    original_message TEXT NOT NULL,
    rfcs TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    servers TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    query_options TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    dnsviz_section TEXT,
    dnsviz_group TEXT,
    applies_to TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    source_artifact_id UUID REFERENCES dnsviz_artifacts(id) ON DELETE SET NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_dnssec_findings_snapshot ON dnssec_findings(snapshot_id);
CREATE INDEX idx_dnssec_findings_code ON dnssec_findings(code);
CREATE INDEX idx_dnssec_findings_zone ON dnssec_findings(zone);
CREATE INDEX idx_dnssec_findings_severity ON dnssec_findings(severity);

CREATE TABLE infrastructure_entities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type TEXT NOT NULL CHECK (entity_type IN (
        'nameserver', 'ip', 'asn', 'dns_provider', 'hosting_provider',
        'registrar', 'registry', 'tld', 'zone', 'resolver', 'unknown'
    )),
    name TEXT NOT NULL,
    normalized_name TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (entity_type, normalized_name)
);

CREATE INDEX idx_infrastructure_entities_type ON infrastructure_entities(entity_type);

CREATE TABLE domain_entity_links (
    snapshot_id UUID NOT NULL REFERENCES domain_snapshots(id) ON DELETE CASCADE,
    entity_id UUID NOT NULL REFERENCES infrastructure_entities(id) ON DELETE CASCADE,
    relation_type TEXT NOT NULL CHECK (relation_type IN (
        'uses_nameserver', 'resolves_to_ip', 'belongs_to_asn', 'uses_dns_provider',
        'uses_hosting_provider', 'delegated_under', 'registered_at', 'registry_zone'
    )),
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (snapshot_id, entity_id, relation_type)
);

CREATE INDEX idx_domain_entity_links_entity ON domain_entity_links(entity_id, relation_type);

CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    report_type TEXT NOT NULL CHECK (report_type IN (
        'domain', 'bulk', 'executive', 'technical', 'comparative',
        'by_tld', 'by_provider', 'by_failure_pattern'
    )),
    status TEXT NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'review', 'approved', 'published', 'archived')),
    language TEXT NOT NULL DEFAULT 'es' CHECK (language IN ('es', 'en')),
    created_by UUID REFERENCES app_users(id) ON DELETE SET NULL,
    approved_by UUID REFERENCES app_users(id) ON DELETE SET NULL,
    source_job_id UUID REFERENCES analysis_jobs(id) ON DELETE SET NULL,
    filters JSONB NOT NULL DEFAULT '{}'::jsonb,
    summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at TIMESTAMPTZ
);

CREATE INDEX idx_reports_status ON reports(status, created_at DESC);
CREATE INDEX idx_reports_type ON reports(report_type);

CREATE TABLE report_sections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    section_type TEXT NOT NULL,
    title TEXT NOT NULL,
    body JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (report_id, position)
);

CREATE TABLE report_publications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    public_slug TEXT NOT NULL UNIQUE,
    public_status TEXT NOT NULL DEFAULT 'draft'
        CHECK (public_status IN ('draft', 'published', 'unpublished', 'archived')),
    published_by UUID REFERENCES app_users(id) ON DELETE SET NULL,
    published_at TIMESTAMPTZ,
    public_summary TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_report_publications_status ON report_publications(public_status, published_at DESC);

CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_user_id UUID REFERENCES app_users(id) ON DELETE SET NULL,
    actor_email TEXT,
    action TEXT NOT NULL,
    entity_type TEXT,
    entity_id UUID,
    ip_address INET,
    user_agent TEXT,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_log_actor ON audit_log(actor_user_id, created_at DESC);
CREATE INDEX idx_audit_log_action ON audit_log(action, created_at DESC);

CREATE TABLE rate_limits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope TEXT NOT NULL CHECK (scope IN ('ip', 'user', 'global')),
    scope_key TEXT NOT NULL,
    action TEXT NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    window_seconds INTEGER NOT NULL,
    used_count INTEGER NOT NULL DEFAULT 0,
    limit_count INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scope, scope_key, action, window_start, window_seconds)
);

CREATE INDEX idx_rate_limits_lookup ON rate_limits(scope, scope_key, action, window_start DESC);

COMMIT;
