import { execute, queryOne } from "@/lib/db/pool";

let ensured = false;

interface AppSettingRow {
  key: string;
  value: unknown;
}

async function ensureAppSettingsTable(): Promise<void> {
  if (ensured) return;

  await execute(`
    CREATE TABLE IF NOT EXISTS app_settings (
      key TEXT PRIMARY KEY,
      value JSONB NOT NULL,
      updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  ensured = true;
}

export async function getSetting<T>(
  key: string,
  fallback: T
): Promise<T> {
  await ensureAppSettingsTable();
  const row = await queryOne<AppSettingRow>(
    `SELECT key, value FROM app_settings WHERE key = $1`,
    [key]
  );
  if (!row) return fallback;
  return row.value as T;
}

export async function setSetting<T>(
  key: string,
  value: T,
  updatedBy: string | null = null
): Promise<void> {
  await ensureAppSettingsTable();
  await execute(
    `INSERT INTO app_settings (key, value, updated_by, updated_at)
     VALUES ($1, $2::jsonb, $3, NOW())
     ON CONFLICT (key)
     DO UPDATE SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
    [key, JSON.stringify(value), updatedBy]
  );
}
