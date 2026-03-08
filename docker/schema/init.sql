-- Vigil — Database Schema
-- PostgreSQL 17 — Single source of truth
-- Run via Docker entrypoint or: psql -f init.sql

-- ══════════════════════════════════════════════════════════════════
-- Extensions
-- ══════════════════════════════════════════════════════════════════

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ══════════════════════════════════════════════════════════════════
-- ENUM Types
-- ══════════════════════════════════════════════════════════════════

CREATE TYPE user_role AS ENUM ('admin', 'analyst', 'viewer');
CREATE TYPE target_type AS ENUM ('domain', 'ip', 'url', 'cidr', 'host', 'application', 'image', 'repo');
CREATE TYPE scan_status AS ENUM ('pending', 'queued', 'running', 'analyzing', 'completed', 'failed', 'cancelled');
CREATE TYPE scanner_type AS ENUM ('nmap', 'nuclei', 'nikto', 'sqlmap', 'gobuster', 'zap', 'trivy', 'osint', 'osint_domain', 'osint_ip', 'osint_phone', 'dns', 'dns_audit', 'shannon', 'claude_review', 'full_audit', 'custom');
CREATE TYPE severity_level AS ENUM ('critical', 'high', 'medium', 'low', 'info');
CREATE TYPE finding_status AS ENUM ('open', 'confirmed', 'false_positive', 'remediated', 'accepted_risk', 'ticket_created');
CREATE TYPE osint_result_type AS ENUM ('whois', 'dns', 'subdomain', 'certificate', 'reverse_ip', 'geolocation', 'port', 'technology', 'social', 'breach', 'phone', 'email');
CREATE TYPE report_type AS ENUM ('executive', 'technical', 'compliance', 'pentest', 'vulnerability', 'osint', 'full_audit', 'scan_summary', 'custom');
CREATE TYPE message_role AS ENUM ('system', 'user', 'assistant', 'tool');
CREATE TYPE service_status AS ENUM ('healthy', 'degraded', 'down', 'unknown');

-- ══════════════════════════════════════════════════════════════════
-- Tables
-- ══════════════════════════════════════════════════════════════════

-- ── Users ─────────────────────────────────────────────────────────
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    totp_secret TEXT,                            -- AES-256-GCM encrypted
    totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    backup_codes TEXT[],                         -- hashed backup codes
    role user_role NOT NULL DEFAULT 'analyst',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,     -- account enable/disable
    last_login_at TIMESTAMPTZ,                   -- last successful login
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Sessions ──────────────────────────────────────────────────────
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(512) NOT NULL UNIQUE,
    ip_address INET,
    user_agent TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Targets ───────────────────────────────────────────────────────
CREATE TABLE targets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    target_type target_type NOT NULL,
    target_value VARCHAR(1024) NOT NULL,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Scans ─────────────────────────────────────────────────────────
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_id UUID REFERENCES targets(id) ON DELETE SET NULL,
    scanner scanner_type NOT NULL,
    target TEXT,                                 -- target URL/IP/domain (denormalized for quick display)
    status scan_status NOT NULL DEFAULT 'pending',
    config JSONB NOT NULL DEFAULT '{}',
    progress INTEGER NOT NULL DEFAULT 0 CHECK (progress >= 0 AND progress <= 100),
    findings_count INTEGER NOT NULL DEFAULT 0,   -- denormalized count
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    duration_ms INTEGER,                        -- scan duration in milliseconds
    raw_output JSONB,
    summary JSONB,
    ai_analysis TEXT,
    error_message TEXT
);

-- ── Findings ──────────────────────────────────────────────────────
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    severity severity_level NOT NULL DEFAULT 'info',
    category VARCHAR(255),
    title VARCHAR(1024) NOT NULL,
    description TEXT,
    cve_id VARCHAR(50),
    cvss_score NUMERIC(3,1) CHECK (cvss_score >= 0 AND cvss_score <= 10),
    target_url VARCHAR(2048),
    evidence TEXT,
    poc TEXT,
    remediation TEXT,
    ai_remediation TEXT,
    scanner_ref JSONB,
    status finding_status NOT NULL DEFAULT 'open',
    ticket_text TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── OSINT Results ─────────────────────────────────────────────────
CREATE TABLE osint_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    result_type osint_result_type NOT NULL,
    data JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── AI Conversations ──────────────────────────────────────────────
CREATE TABLE ai_conversations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(512) NOT NULL DEFAULT 'New Conversation',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── AI Messages ───────────────────────────────────────────────────
CREATE TABLE ai_messages (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    conversation_id UUID NOT NULL REFERENCES ai_conversations(id) ON DELETE CASCADE,
    role message_role NOT NULL,
    content TEXT NOT NULL,
    tool_calls JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE ai_notes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    conversation_id UUID REFERENCES ai_conversations(id) ON DELETE SET NULL,
    title VARCHAR(255) NOT NULL DEFAULT 'Untitled Note',
    content TEXT NOT NULL DEFAULT '',
    pinned BOOLEAN NOT NULL DEFAULT FALSE,
    tags TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE ai_faq_entries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    category VARCHAR(120) NOT NULL DEFAULT 'General',
    question TEXT NOT NULL,
    answer TEXT NOT NULL,
    tags TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, question)
);

CREATE TABLE ai_knowledge_chunks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source_type VARCHAR(32) NOT NULL,
    source_id TEXT NOT NULL,
    source_hash TEXT,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    tags TEXT[] NOT NULL DEFAULT '{}',
    chunk_index INTEGER NOT NULL DEFAULT 0,
    embedding JSONB,
    embedding_model VARCHAR(200),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (source_type IN ('faq', 'note', 'conversation', 'manual'))
);

-- ── Reports ───────────────────────────────────────────────────────
CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(512) NOT NULL,
    report_type report_type NOT NULL DEFAULT 'technical',
    scan_ids UUID[] NOT NULL DEFAULT '{}',
    content JSONB,
    markdown TEXT,
    generated_by VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Audit Log ─────────────────────────────────────────────────────
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(255) NOT NULL,
    resource_type VARCHAR(255),
    resource_id UUID,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Service Health ────────────────────────────────────────────────
CREATE TABLE service_health (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    service_name VARCHAR(255) NOT NULL UNIQUE,
    status service_status NOT NULL DEFAULT 'unknown',
    last_checked TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    details JSONB
);

-- App Settings (key/value JSON)
CREATE TABLE app_settings (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Model Cache ──────────────────────────────────────────────────
CREATE TABLE model_cache (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    model_name TEXT NOT NULL UNIQUE,
    model_family TEXT,
    purpose TEXT NOT NULL DEFAULT 'general',
    size_bytes BIGINT DEFAULT 0,
    digest TEXT,
    parameter_size TEXT,
    quantization TEXT,
    source TEXT NOT NULL DEFAULT 'ollama' CHECK (source IN ('ollama', 'huggingface')),
    source_ref TEXT,                         -- HF repo: "hf.co/org/model-GGUF"
    is_pulled BOOLEAN NOT NULL DEFAULT FALSE,
    auto_pull BOOLEAN NOT NULL DEFAULT TRUE,
    priority INTEGER NOT NULL DEFAULT 5 CHECK (priority >= 1 AND priority <= 10),
    last_used_at TIMESTAMPTZ,
    use_count INTEGER NOT NULL DEFAULT 0,
    total_tokens_generated BIGINT NOT NULL DEFAULT 0,
    avg_tokens_per_sec NUMERIC(8,2),
    pulled_at TIMESTAMPTZ,
    evicted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Model Usage Log ─────────────────────────────────────────────
CREATE TABLE model_usage_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    model_name TEXT NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    purpose TEXT NOT NULL,
    input_tokens INTEGER,
    output_tokens INTEGER,
    duration_ms INTEGER,
    tokens_per_sec NUMERIC(8,2),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ══════════════════════════════════════════════════════════════════
-- Indexes
-- ══════════════════════════════════════════════════════════════════

-- Users
CREATE INDEX idx_users_email ON users(email);

-- Sessions
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_token ON sessions(token);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

-- Targets
CREATE INDEX idx_targets_user_id ON targets(user_id);
CREATE INDEX idx_targets_type ON targets(target_type);

-- Scans
CREATE INDEX idx_scans_user_id ON scans(user_id);
CREATE INDEX idx_scans_target_id ON scans(target_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_scanner ON scans(scanner);
CREATE INDEX idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX idx_scans_user_status ON scans(user_id, status);

-- Findings
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_cve_id ON findings(cve_id);
CREATE INDEX idx_findings_scan_severity ON findings(scan_id, severity);
CREATE INDEX idx_findings_created_at ON findings(created_at DESC);

-- OSINT Results
CREATE INDEX idx_osint_scan_id ON osint_results(scan_id);
CREATE INDEX idx_osint_result_type ON osint_results(result_type);

-- AI Conversations
CREATE INDEX idx_ai_conversations_user_id ON ai_conversations(user_id);
CREATE INDEX idx_ai_conversations_created_at ON ai_conversations(created_at DESC);

-- AI Messages
CREATE INDEX idx_ai_messages_conversation_id ON ai_messages(conversation_id);
CREATE INDEX idx_ai_messages_created_at ON ai_messages(created_at);
CREATE INDEX idx_ai_notes_user_id ON ai_notes(user_id);
CREATE INDEX idx_ai_notes_conversation_id ON ai_notes(conversation_id);
CREATE INDEX idx_ai_notes_updated_at ON ai_notes(updated_at DESC);
CREATE INDEX idx_ai_faq_user_updated ON ai_faq_entries(user_id, updated_at DESC);
CREATE INDEX idx_ai_faq_category ON ai_faq_entries(user_id, category);
CREATE INDEX idx_ai_knowledge_user_source ON ai_knowledge_chunks(user_id, source_type, source_id);
CREATE INDEX idx_ai_knowledge_updated ON ai_knowledge_chunks(user_id, updated_at DESC);
CREATE INDEX idx_ai_knowledge_source_hash ON ai_knowledge_chunks(source_hash);

-- Reports
CREATE INDEX idx_reports_user_id ON reports(user_id);
CREATE INDEX idx_reports_type ON reports(report_type);
CREATE INDEX idx_reports_created_at ON reports(created_at DESC);

-- Audit Log
CREATE INDEX idx_audit_user_id ON audit_log(user_id);
CREATE INDEX idx_audit_action ON audit_log(action);
CREATE INDEX idx_audit_resource ON audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_created_at ON audit_log(created_at DESC);

-- Service Health
CREATE INDEX idx_service_health_name ON service_health(service_name);
CREATE INDEX idx_service_health_status ON service_health(status);

-- App Settings
CREATE INDEX idx_app_settings_updated_at ON app_settings(updated_at DESC);

-- Model Cache
CREATE INDEX idx_model_cache_purpose ON model_cache(purpose);
CREATE INDEX idx_model_cache_priority ON model_cache(priority);
CREATE INDEX idx_model_cache_pulled ON model_cache(is_pulled);
CREATE INDEX idx_model_cache_last_used ON model_cache(last_used_at DESC);

-- Model Usage Log
CREATE INDEX idx_model_usage_model ON model_usage_log(model_name);
CREATE INDEX idx_model_usage_created ON model_usage_log(created_at DESC);

-- ══════════════════════════════════════════════════════════════════
-- Functions
-- ══════════════════════════════════════════════════════════════════

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER findings_updated_at
    BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Auto-cleanup expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM sessions WHERE expires_at < NOW();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Scan statistics for a user
CREATE OR REPLACE FUNCTION get_scan_stats(p_user_id UUID)
RETURNS TABLE (
    total_scans BIGINT,
    running_scans BIGINT,
    completed_scans BIGINT,
    failed_scans BIGINT,
    total_findings BIGINT,
    critical_findings BIGINT,
    high_findings BIGINT,
    medium_findings BIGINT,
    low_findings BIGINT,
    info_findings BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        (SELECT COUNT(*) FROM scans WHERE user_id = p_user_id),
        (SELECT COUNT(*) FROM scans WHERE user_id = p_user_id AND status = 'running'),
        (SELECT COUNT(*) FROM scans WHERE user_id = p_user_id AND status = 'completed'),
        (SELECT COUNT(*) FROM scans WHERE user_id = p_user_id AND status = 'failed'),
        (SELECT COUNT(*) FROM findings f JOIN scans s ON f.scan_id = s.id WHERE s.user_id = p_user_id),
        (SELECT COUNT(*) FROM findings f JOIN scans s ON f.scan_id = s.id WHERE s.user_id = p_user_id AND f.severity = 'critical'),
        (SELECT COUNT(*) FROM findings f JOIN scans s ON f.scan_id = s.id WHERE s.user_id = p_user_id AND f.severity = 'high'),
        (SELECT COUNT(*) FROM findings f JOIN scans s ON f.scan_id = s.id WHERE s.user_id = p_user_id AND f.severity = 'medium'),
        (SELECT COUNT(*) FROM findings f JOIN scans s ON f.scan_id = s.id WHERE s.user_id = p_user_id AND f.severity = 'low'),
        (SELECT COUNT(*) FROM findings f JOIN scans s ON f.scan_id = s.id WHERE s.user_id = p_user_id AND f.severity = 'info');
END;
$$ LANGUAGE plpgsql;

-- Finding severity breakdown for a scan
CREATE OR REPLACE FUNCTION get_finding_breakdown(p_scan_id UUID)
RETURNS TABLE (
    severity severity_level,
    count BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT f.severity, COUNT(*)
    FROM findings f
    WHERE f.scan_id = p_scan_id
    GROUP BY f.severity
    ORDER BY
        CASE f.severity
            WHEN 'critical' THEN 1
            WHEN 'high' THEN 2
            WHEN 'medium' THEN 3
            WHEN 'low' THEN 4
            WHEN 'info' THEN 5
        END;
END;
$$ LANGUAGE plpgsql;

-- ══════════════════════════════════════════════════════════════════
-- Seed service health rows
-- ══════════════════════════════════════════════════════════════════

INSERT INTO service_health (service_name, status) VALUES
    ('security-db', 'healthy'),
    ('zap', 'unknown'),
    ('trivy', 'unknown'),
    ('security-bridge', 'unknown'),
    ('warp-proxy', 'unknown'),
    ('dns-server', 'unknown'),
    ('ollama', 'unknown')
ON CONFLICT (service_name) DO NOTHING;

-- Seed: LLM settings
INSERT INTO app_settings (key, value) VALUES
    ('llm', '{"provider":"ollama","base_url":"http://security-ollama:11434","default_model":"qwen3:8b","embedding_model":"nomic-embed-text:latest","knowledge_enabled":true,"knowledge_top_k":6,"temperature":0.3,"request_timeout_ms":120000}')
ON CONFLICT (key) DO NOTHING;

-- ── Seed: Security Model Presets ────────────────────────────────
INSERT INTO model_cache (model_name, model_family, purpose, source, priority, auto_pull, parameter_size) VALUES
    ('llama3.1:8b',                                    'llama',     'general',          'ollama', 1, true,  '8B'),
    ('qwen2.5-coder:7b',                               'qwen2',    'code-security',    'ollama', 2, true,  '7.6B'),
    ('qwen2.5-coder:32b',                              'qwen2',    'deep-analysis',    'ollama', 4, false, '32B'),
    ('ALIENTELLIGENCE/cybersecuritythreatanalysisv2',   'llama',    'threat-analysis',  'ollama', 3, true,  '8B'),
    ('alpernae/qwen2.5-auditor',                        'qwen2',    'code-review',      'ollama', 5, false, '7B'),
    ('deepseek-coder-v2:16b',                           'deepseek', 'multi-file',       'ollama', 6, false, '16B'),
    ('codellama:7b',                                    'codellama','fallback',          'ollama', 8, false, '7B')
ON CONFLICT (model_name) DO NOTHING;

-- Agent fleet runtime tables (Phase 1-5 foundation)
CREATE TABLE IF NOT EXISTS agents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    slug TEXT NOT NULL,
    name VARCHAR(160) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    category VARCHAR(60) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    system_prompt TEXT NOT NULL,
    task_prompt TEXT NOT NULL,
    tools_allowed TEXT[] NOT NULL DEFAULT '{}',
    risk_level VARCHAR(16) NOT NULL DEFAULT 'medium',
    model_profile VARCHAR(16) NOT NULL DEFAULT 'auto',
    memory_policy VARCHAR(16) NOT NULL DEFAULT 'session',
    budget_limit INTEGER NOT NULL DEFAULT 10,
    autonomy_mode VARCHAR(16) NOT NULL DEFAULT 'assisted',
    settings JSONB NOT NULL DEFAULT '{}'::jsonb,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, slug)
);

CREATE TABLE IF NOT EXISTS agent_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    system_prompt TEXT NOT NULL,
    task_prompt TEXT NOT NULL,
    settings JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS agent_runs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status VARCHAR(16) NOT NULL DEFAULT 'queued',
    input_text TEXT NOT NULL,
    output_text TEXT,
    error_text TEXT,
    evaluation_score NUMERIC(5,2),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS agent_run_steps (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    run_id UUID NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
    step_index INTEGER NOT NULL,
    phase VARCHAR(80) NOT NULL,
    status VARCHAR(24) NOT NULL,
    detail TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS agent_notes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
    run_id UUID REFERENCES agent_runs(id) ON DELETE SET NULL,
    title VARCHAR(255) NOT NULL DEFAULT 'Agent Note',
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS agent_memories (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    memory_key VARCHAR(120) NOT NULL,
    memory_value JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, agent_id, memory_key)
);

CREATE TABLE IF NOT EXISTS agent_artifacts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    run_id UUID NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
    artifact_type VARCHAR(60) NOT NULL,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS agent_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    policy_name VARCHAR(120) NOT NULL,
    policy JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, policy_name)
);

CREATE TABLE IF NOT EXISTS agent_eval_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    run_id UUID REFERENCES agent_runs(id) ON DELETE SET NULL,
    eval_suite VARCHAR(120) NOT NULL,
    pass BOOLEAN NOT NULL DEFAULT FALSE,
    score NUMERIC(5,2) NOT NULL DEFAULT 0,
    results JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_evidence (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    run_id UUID REFERENCES agent_runs(id) ON DELETE SET NULL,
    control_framework VARCHAR(80) NOT NULL,
    control_id VARCHAR(120) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    artifact_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
    status VARCHAR(20) NOT NULL DEFAULT 'open',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS agent_campaigns (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    goal TEXT NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'queued',
    summary TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS agent_campaign_runs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    campaign_id UUID NOT NULL REFERENCES agent_campaigns(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    run_id UUID NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
    run_order INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agents_user_category ON agents(user_id, category);
CREATE INDEX IF NOT EXISTS idx_agent_runs_user_created ON agent_runs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_run_steps_run_idx ON agent_run_steps(run_id, step_index);
CREATE INDEX IF NOT EXISTS idx_agent_eval_agent_created ON agent_eval_results(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_evidence_user_created ON audit_evidence(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_campaigns_user_created ON agent_campaigns(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_campaign_runs_campaign_order ON agent_campaign_runs(campaign_id, run_order);

INSERT INTO app_settings (key, value) VALUES
    ('agents_policy', '{"allow_ssh":false,"allow_destructive_commands":false,"default_autonomy":"assisted","max_budget_limit":50}')
ON CONFLICT (key) DO NOTHING;

-- Autonomous Brain tables (RSS + Calendar) for fresh environments
CREATE TABLE IF NOT EXISTS brain_rss_feeds (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    url TEXT NOT NULL,
    category VARCHAR(120),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    refresh_interval_min INTEGER NOT NULL DEFAULT 180 CHECK (refresh_interval_min >= 15 AND refresh_interval_min <= 1440),
    last_fetched_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, url)
);

CREATE TABLE IF NOT EXISTS brain_feed_items (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    feed_id UUID NOT NULL REFERENCES brain_rss_feeds(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    guid TEXT NOT NULL,
    url TEXT,
    title TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    content TEXT NOT NULL DEFAULT '',
    source VARCHAR(255),
    published_at TIMESTAMPTZ,
    importance_score INTEGER NOT NULL DEFAULT 0 CHECK (importance_score >= 0 AND importance_score <= 100),
    tags TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(feed_id, guid)
);

CREATE TABLE IF NOT EXISTS brain_calendar_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ NOT NULL,
    category VARCHAR(120) NOT NULL DEFAULT 'security-task',
    status VARCHAR(20) NOT NULL DEFAULT 'planned' CHECK (status IN ('planned','in_progress','completed','blocked')),
    priority VARCHAR(20) NOT NULL DEFAULT 'medium' CHECK (priority IN ('low','medium','high','critical')),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (end_time >= start_time)
);

CREATE INDEX IF NOT EXISTS idx_brain_feeds_user_active ON brain_rss_feeds(user_id, is_active, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_brain_feed_items_user_published ON brain_feed_items(user_id, published_at DESC, importance_score DESC);
CREATE INDEX IF NOT EXISTS idx_brain_feed_items_feed_created ON brain_feed_items(feed_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_brain_calendar_user_start ON brain_calendar_events(user_id, start_time ASC);

-- AI response cache (exact prompt+context cache with TTL)
CREATE TABLE IF NOT EXISTS ai_response_cache (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    model TEXT NOT NULL,
    cache_key TEXT NOT NULL,
    response TEXT NOT NULL,
    sources JSONB NOT NULL DEFAULT '[]'::jsonb,
    hits INTEGER NOT NULL DEFAULT 0,
    last_hit_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, model, cache_key)
);

CREATE INDEX IF NOT EXISTS idx_ai_response_cache_expiry ON ai_response_cache(expires_at);

-- AI cache telemetry (analytics panel)
CREATE TABLE IF NOT EXISTS ai_cache_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(32) NOT NULL DEFAULT 'ollama',
    model TEXT NOT NULL,
    cache_hit BOOLEAN NOT NULL DEFAULT FALSE,
    cache_hit_type VARCHAR(16) NOT NULL DEFAULT 'none' CHECK (cache_hit_type IN ('none','exact','semantic')),
    degraded BOOLEAN NOT NULL DEFAULT FALSE,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    prompt_chars INTEGER NOT NULL DEFAULT 0,
    response_chars INTEGER NOT NULL DEFAULT 0,
    estimated_tokens INTEGER NOT NULL DEFAULT 0,
    estimated_cost_usd NUMERIC(12,6) NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_cache_events_user_created ON ai_cache_events(user_id, created_at DESC);
