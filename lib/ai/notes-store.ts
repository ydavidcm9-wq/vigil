import { execute } from "@/lib/db/pool";

let aiNotesEnsured = false;

export async function ensureAiNotesTable(): Promise<void> {
  if (aiNotesEnsured) return;

  await execute(`
    CREATE TABLE IF NOT EXISTS ai_notes (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      conversation_id UUID REFERENCES ai_conversations(id) ON DELETE SET NULL,
      title VARCHAR(255) NOT NULL DEFAULT 'Untitled Note',
      content TEXT NOT NULL DEFAULT '',
      pinned BOOLEAN NOT NULL DEFAULT FALSE,
      tags TEXT[] NOT NULL DEFAULT '{}',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await execute(`
    CREATE INDEX IF NOT EXISTS idx_ai_notes_user_id
    ON ai_notes(user_id)
  `);

  await execute(`
    CREATE INDEX IF NOT EXISTS idx_ai_notes_conversation_id
    ON ai_notes(conversation_id)
  `);

  await execute(`
    CREATE INDEX IF NOT EXISTS idx_ai_notes_updated_at
    ON ai_notes(updated_at DESC)
  `);

  aiNotesEnsured = true;
}
