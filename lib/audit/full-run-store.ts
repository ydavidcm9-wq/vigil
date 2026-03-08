import { execute, query, queryOne } from "@/lib/db/pool";

let ensured = false;

export type AuditFullRunStatus = "queued" | "running" | "completed" | "failed";

export interface AuditFullRunRecord {
  id: string;
  user_id: string;
  status: AuditFullRunStatus;
  targets: string[];
  max_agents: number;
  include_pentest: boolean;
  include_intel: boolean;
  include_report: boolean;
  campaign_ids: string[];
  pentest_scan_id: string | null;
  report_id: string | null;
  intel_summary: Record<string, unknown> | null;
  error_text: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface AuditFullRunEvent {
  id: string;
  run_id: string;
  level: "info" | "warn" | "error";
  message: string;
  data: Record<string, unknown>;
  created_at: string;
}

export async function ensureAuditFullRunTables(): Promise<void> {
  if (ensured) return;

  await execute(`
    CREATE TABLE IF NOT EXISTS audit_full_runs (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      status VARCHAR(16) NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','completed','failed')),
      targets JSONB NOT NULL DEFAULT '[]'::jsonb,
      max_agents INTEGER NOT NULL DEFAULT 4,
      include_pentest BOOLEAN NOT NULL DEFAULT TRUE,
      include_intel BOOLEAN NOT NULL DEFAULT TRUE,
      include_report BOOLEAN NOT NULL DEFAULT TRUE,
      campaign_ids UUID[] NOT NULL DEFAULT '{}',
      pentest_scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
      report_id UUID REFERENCES reports(id) ON DELETE SET NULL,
      intel_summary JSONB,
      error_text TEXT,
      started_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await execute(`
    CREATE TABLE IF NOT EXISTS audit_full_run_events (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      run_id UUID NOT NULL REFERENCES audit_full_runs(id) ON DELETE CASCADE,
      level VARCHAR(10) NOT NULL CHECK (level IN ('info','warn','error')),
      message TEXT NOT NULL,
      data JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await execute(`
    CREATE INDEX IF NOT EXISTS idx_audit_full_runs_user_created
    ON audit_full_runs (user_id, created_at DESC)
  `);
  await execute(`
    CREATE INDEX IF NOT EXISTS idx_audit_full_runs_user_status
    ON audit_full_runs (user_id, status, created_at DESC)
  `);
  await execute(`
    CREATE INDEX IF NOT EXISTS idx_audit_full_run_events_run_created
    ON audit_full_run_events (run_id, created_at DESC)
  `);

  ensured = true;
}

export async function createAuditFullRun(input: {
  userId: string;
  targets: string[];
  maxAgents: number;
  includePentest: boolean;
  includeIntel: boolean;
  includeReport: boolean;
}): Promise<AuditFullRunRecord> {
  await ensureAuditFullRunTables();
  const row = await queryOne<AuditFullRunRecord>(
    `INSERT INTO audit_full_runs (
       user_id, status, targets, max_agents, include_pentest, include_intel, include_report
     ) VALUES ($1, 'queued', $2::jsonb, $3, $4, $5, $6)
     RETURNING *`,
    [
      input.userId,
      JSON.stringify(input.targets),
      input.maxAgents,
      input.includePentest,
      input.includeIntel,
      input.includeReport,
    ]
  );
  if (!row) throw new Error("Failed to create full audit run");
  return row;
}

export async function setAuditFullRunRunning(
  runId: string,
  userId: string
): Promise<void> {
  await ensureAuditFullRunTables();
  await execute(
    `UPDATE audit_full_runs
     SET status = 'running',
         started_at = COALESCE(started_at, NOW()),
         updated_at = NOW()
     WHERE id = $1 AND user_id = $2`,
    [runId, userId]
  );
}

export async function updateAuditFullRunArtifacts(input: {
  runId: string;
  userId: string;
  campaignIds?: string[];
  pentestScanId?: string | null;
  reportId?: string | null;
  intelSummary?: Record<string, unknown> | null;
}): Promise<void> {
  await ensureAuditFullRunTables();
  const sets: string[] = [];
  const params: unknown[] = [];
  let idx = 1;

  if (input.campaignIds !== undefined) {
    sets.push(`campaign_ids = $${idx++}::uuid[]`);
    params.push(input.campaignIds);
  }
  if (input.pentestScanId !== undefined) {
    sets.push(`pentest_scan_id = $${idx++}`);
    params.push(input.pentestScanId);
  }
  if (input.reportId !== undefined) {
    sets.push(`report_id = $${idx++}`);
    params.push(input.reportId);
  }
  if (input.intelSummary !== undefined) {
    sets.push(`intel_summary = $${idx++}::jsonb`);
    params.push(
      input.intelSummary === null ? null : JSON.stringify(input.intelSummary)
    );
  }

  if (sets.length === 0) return;

  sets.push(`updated_at = NOW()`);
  params.push(input.runId, input.userId);

  await execute(
    `UPDATE audit_full_runs
     SET ${sets.join(", ")}
     WHERE id = $${idx++} AND user_id = $${idx}`,
    params
  );
}

export async function setAuditFullRunCompleted(
  runId: string,
  userId: string
): Promise<void> {
  await ensureAuditFullRunTables();
  await execute(
    `UPDATE audit_full_runs
     SET status = 'completed',
         completed_at = NOW(),
         updated_at = NOW()
     WHERE id = $1 AND user_id = $2`,
    [runId, userId]
  );
}

export async function setAuditFullRunFailed(
  runId: string,
  userId: string,
  errorText: string
): Promise<void> {
  await ensureAuditFullRunTables();
  await execute(
    `UPDATE audit_full_runs
     SET status = 'failed',
         error_text = $3,
         completed_at = NOW(),
         updated_at = NOW()
     WHERE id = $1 AND user_id = $2`,
    [runId, userId, errorText]
  );
}

export async function appendAuditFullRunEvent(input: {
  runId: string;
  level: "info" | "warn" | "error";
  message: string;
  data?: Record<string, unknown>;
}): Promise<void> {
  await ensureAuditFullRunTables();
  await execute(
    `INSERT INTO audit_full_run_events (run_id, level, message, data)
     VALUES ($1, $2, $3, $4::jsonb)`,
    [input.runId, input.level, input.message, JSON.stringify(input.data || {})]
  );
}

export async function getAuditFullRunById(
  userId: string,
  runId: string
): Promise<AuditFullRunRecord | null> {
  await ensureAuditFullRunTables();
  return queryOne<AuditFullRunRecord>(
    `SELECT * FROM audit_full_runs
     WHERE id = $1 AND user_id = $2`,
    [runId, userId]
  );
}

export async function listAuditFullRuns(
  userId: string,
  limit = 20
): Promise<AuditFullRunRecord[]> {
  await ensureAuditFullRunTables();
  return query<AuditFullRunRecord>(
    `SELECT * FROM audit_full_runs
     WHERE user_id = $1
     ORDER BY created_at DESC
     LIMIT $2`,
    [userId, Math.min(Math.max(limit, 1), 100)]
  );
}

export async function listAuditFullRunEvents(
  runId: string,
  limit = 100
): Promise<AuditFullRunEvent[]> {
  await ensureAuditFullRunTables();
  return query<AuditFullRunEvent>(
    `SELECT * FROM audit_full_run_events
     WHERE run_id = $1
     ORDER BY created_at DESC
     LIMIT $2`,
    [runId, Math.min(Math.max(limit, 1), 300)]
  );
}
