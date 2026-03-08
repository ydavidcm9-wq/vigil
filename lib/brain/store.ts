import { createHash } from "crypto";
import { execute, query, queryOne } from "@/lib/db/pool";

let ensured = false;

export interface BrainFeed {
  id: string;
  user_id: string;
  name: string;
  url: string;
  category: string | null;
  is_active: boolean;
  refresh_interval_min: number;
  last_fetched_at: string | null;
  last_error: string | null;
  created_at: string;
  updated_at: string;
}

export interface BrainFeedItem {
  id: string;
  feed_id: string;
  user_id: string;
  guid: string;
  url: string | null;
  title: string;
  summary: string;
  content: string;
  source: string | null;
  published_at: string | null;
  importance_score: number;
  tags: string[];
  created_at: string;
}

export interface BrainCalendarEvent {
  id: string;
  user_id: string;
  title: string;
  description: string | null;
  start_time: string;
  end_time: string;
  category: string;
  status: "planned" | "in_progress" | "completed" | "blocked";
  priority: "low" | "medium" | "high" | "critical";
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

function normalizeGuid(value: string | null, title: string, url: string | null): string {
  if (value && value.trim()) return value.trim();
  return createHash("sha256").update(`${title}|${url || ""}`).digest("hex");
}

export async function ensureBrainTables(): Promise<void> {
  if (ensured) return;

  await execute(`
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

    CREATE INDEX IF NOT EXISTS idx_brain_feeds_user_active
      ON brain_rss_feeds(user_id, is_active, updated_at DESC);

    CREATE INDEX IF NOT EXISTS idx_brain_feed_items_user_published
      ON brain_feed_items(user_id, published_at DESC, importance_score DESC);

    CREATE INDEX IF NOT EXISTS idx_brain_feed_items_feed_created
      ON brain_feed_items(feed_id, created_at DESC);

    CREATE INDEX IF NOT EXISTS idx_brain_calendar_user_start
      ON brain_calendar_events(user_id, start_time ASC);
  `);

  ensured = true;
}

export async function listFeeds(userId: string): Promise<BrainFeed[]> {
  await ensureBrainTables();
  return query<BrainFeed>(
    `SELECT * FROM brain_rss_feeds
     WHERE user_id = $1
     ORDER BY is_active DESC, updated_at DESC`,
    [userId]
  );
}

export async function getFeedById(userId: string, feedId: string): Promise<BrainFeed | null> {
  await ensureBrainTables();
  return queryOne<BrainFeed>(
    `SELECT * FROM brain_rss_feeds WHERE id = $1 AND user_id = $2`,
    [feedId, userId]
  );
}

export async function createFeed(
  userId: string,
  input: {
    name: string;
    url: string;
    category?: string | null;
    refresh_interval_min?: number;
  }
): Promise<BrainFeed> {
  await ensureBrainTables();
  const row = await queryOne<BrainFeed>(
    `INSERT INTO brain_rss_feeds (user_id, name, url, category, refresh_interval_min)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING *`,
    [
      userId,
      input.name,
      input.url,
      input.category || null,
      input.refresh_interval_min ?? 180,
    ]
  );

  if (!row) throw new Error("Failed to create feed");
  return row;
}

export async function updateFeed(
  userId: string,
  feedId: string,
  patch: {
    name?: string;
    category?: string | null;
    is_active?: boolean;
    refresh_interval_min?: number;
  }
): Promise<BrainFeed | null> {
  await ensureBrainTables();
  const sets: string[] = [];
  const params: unknown[] = [];
  let idx = 1;

  if (patch.name !== undefined) {
    sets.push(`name = $${idx++}`);
    params.push(patch.name);
  }
  if (patch.category !== undefined) {
    sets.push(`category = $${idx++}`);
    params.push(patch.category);
  }
  if (patch.is_active !== undefined) {
    sets.push(`is_active = $${idx++}`);
    params.push(patch.is_active);
  }
  if (patch.refresh_interval_min !== undefined) {
    sets.push(`refresh_interval_min = $${idx++}`);
    params.push(patch.refresh_interval_min);
  }

  if (sets.length === 0) {
    return getFeedById(userId, feedId);
  }

  sets.push("updated_at = NOW()");
  params.push(feedId, userId);

  return queryOne<BrainFeed>(
    `UPDATE brain_rss_feeds
     SET ${sets.join(", ")}
     WHERE id = $${idx++} AND user_id = $${idx}
     RETURNING *`,
    params
  );
}

export async function deleteFeed(userId: string, feedId: string): Promise<boolean> {
  await ensureBrainTables();
  const count = await execute(
    `DELETE FROM brain_rss_feeds WHERE id = $1 AND user_id = $2`,
    [feedId, userId]
  );
  return count > 0;
}

export async function markFeedRefresh(
  userId: string,
  feedId: string,
  ok: boolean,
  errorMessage?: string
): Promise<void> {
  await ensureBrainTables();
  await execute(
    `UPDATE brain_rss_feeds
     SET last_fetched_at = NOW(),
         last_error = CASE WHEN $3 THEN NULL ELSE LEFT($4, 3000) END,
         updated_at = NOW()
     WHERE id = $1 AND user_id = $2`,
    [feedId, userId, ok, errorMessage || null]
  );
}

export async function upsertFeedItem(
  userId: string,
  feedId: string,
  input: {
    guid: string | null;
    url: string | null;
    title: string;
    summary: string;
    content: string;
    source: string | null;
    published_at: string | null;
    importance_score: number;
    tags: string[];
  }
): Promise<BrainFeedItem | null> {
  await ensureBrainTables();
  const guid = normalizeGuid(input.guid, input.title, input.url);
  return queryOne<BrainFeedItem>(
    `INSERT INTO brain_feed_items (
       feed_id, user_id, guid, url, title, summary, content, source, published_at, importance_score, tags
     ) VALUES (
       $1, $2, $3, $4, $5, $6, $7, $8, $9::timestamptz, $10, $11::text[]
     )
     ON CONFLICT (feed_id, guid) DO NOTHING
     RETURNING *`,
    [
      feedId,
      userId,
      guid,
      input.url,
      input.title,
      input.summary,
      input.content,
      input.source,
      input.published_at,
      input.importance_score,
      input.tags,
    ]
  );
}

export async function listFeedItems(
  userId: string,
  options?: { limit?: number; feedId?: string }
): Promise<BrainFeedItem[]> {
  await ensureBrainTables();
  const limit = Math.min(Math.max(options?.limit ?? 60, 1), 300);

  if (options?.feedId) {
    return query<BrainFeedItem>(
      `SELECT * FROM brain_feed_items
       WHERE user_id = $1 AND feed_id = $2
       ORDER BY COALESCE(published_at, created_at) DESC
       LIMIT $3`,
      [userId, options.feedId, limit]
    );
  }

  return query<BrainFeedItem>(
    `SELECT * FROM brain_feed_items
     WHERE user_id = $1
     ORDER BY COALESCE(published_at, created_at) DESC
     LIMIT $2`,
    [userId, limit]
  );
}

export async function listCalendarEvents(
  userId: string,
  options?: { from?: string; to?: string; limit?: number }
): Promise<BrainCalendarEvent[]> {
  await ensureBrainTables();
  const limit = Math.min(Math.max(options?.limit ?? 200, 1), 1000);

  const params: unknown[] = [userId];
  const where: string[] = ["user_id = $1"];
  let idx = 2;

  if (options?.from) {
    where.push(`end_time >= $${idx++}::timestamptz`);
    params.push(options.from);
  }
  if (options?.to) {
    where.push(`start_time <= $${idx++}::timestamptz`);
    params.push(options.to);
  }

  params.push(limit);
  return query<BrainCalendarEvent>(
    `SELECT * FROM brain_calendar_events
     WHERE ${where.join(" AND ")}
     ORDER BY start_time ASC
     LIMIT $${idx}`,
    params
  );
}

export async function createCalendarEvent(
  userId: string,
  input: {
    title: string;
    description?: string | null;
    start_time: string;
    end_time: string;
    category?: string;
    status?: BrainCalendarEvent["status"];
    priority?: BrainCalendarEvent["priority"];
    metadata?: Record<string, unknown>;
  }
): Promise<BrainCalendarEvent> {
  await ensureBrainTables();
  const row = await queryOne<BrainCalendarEvent>(
    `INSERT INTO brain_calendar_events (
       user_id, title, description, start_time, end_time, category, status, priority, metadata
     ) VALUES (
       $1, $2, $3, $4::timestamptz, $5::timestamptz, $6, $7, $8, $9::jsonb
     ) RETURNING *`,
    [
      userId,
      input.title,
      input.description || null,
      input.start_time,
      input.end_time,
      input.category || "security-task",
      input.status || "planned",
      input.priority || "medium",
      JSON.stringify(input.metadata || {}),
    ]
  );

  if (!row) throw new Error("Failed to create calendar event");
  return row;
}

export async function updateCalendarEvent(
  userId: string,
  eventId: string,
  patch: Partial<
    Pick<
      BrainCalendarEvent,
      "title" | "description" | "start_time" | "end_time" | "category" | "status" | "priority"
    >
  > & { metadata?: Record<string, unknown> }
): Promise<BrainCalendarEvent | null> {
  await ensureBrainTables();
  const sets: string[] = [];
  const params: unknown[] = [];
  let idx = 1;

  if (patch.title !== undefined) {
    sets.push(`title = $${idx++}`);
    params.push(patch.title);
  }
  if (patch.description !== undefined) {
    sets.push(`description = $${idx++}`);
    params.push(patch.description);
  }
  if (patch.start_time !== undefined) {
    sets.push(`start_time = $${idx++}::timestamptz`);
    params.push(patch.start_time);
  }
  if (patch.end_time !== undefined) {
    sets.push(`end_time = $${idx++}::timestamptz`);
    params.push(patch.end_time);
  }
  if (patch.category !== undefined) {
    sets.push(`category = $${idx++}`);
    params.push(patch.category);
  }
  if (patch.status !== undefined) {
    sets.push(`status = $${idx++}`);
    params.push(patch.status);
  }
  if (patch.priority !== undefined) {
    sets.push(`priority = $${idx++}`);
    params.push(patch.priority);
  }
  if (patch.metadata !== undefined) {
    sets.push(`metadata = $${idx++}::jsonb`);
    params.push(JSON.stringify(patch.metadata));
  }

  if (sets.length === 0) {
    return queryOne<BrainCalendarEvent>(
      `SELECT * FROM brain_calendar_events WHERE id = $1 AND user_id = $2`,
      [eventId, userId]
    );
  }

  sets.push("updated_at = NOW()");
  params.push(eventId, userId);

  return queryOne<BrainCalendarEvent>(
    `UPDATE brain_calendar_events
     SET ${sets.join(", ")}
     WHERE id = $${idx++} AND user_id = $${idx}
     RETURNING *`,
    params
  );
}

export async function deleteCalendarEvent(userId: string, eventId: string): Promise<boolean> {
  await ensureBrainTables();
  const count = await execute(
    `DELETE FROM brain_calendar_events WHERE id = $1 AND user_id = $2`,
    [eventId, userId]
  );
  return count > 0;
}

export async function getBrainSummary(userId: string): Promise<{
  feeds_active: number;
  feed_items_24h: number;
  upcoming_events_7d: number;
  critical_open: number;
  high_open: number;
}> {
  await ensureBrainTables();

  const [feedsRow, itemsRow, eventsRow, critRow, highRow] = await Promise.all([
    queryOne<{ count: string }>(
      `SELECT COUNT(*)::text AS count FROM brain_rss_feeds WHERE user_id = $1 AND is_active = TRUE`,
      [userId]
    ),
    queryOne<{ count: string }>(
      `SELECT COUNT(*)::text AS count
       FROM brain_feed_items
       WHERE user_id = $1 AND COALESCE(published_at, created_at) >= NOW() - INTERVAL '24 hours'`,
      [userId]
    ),
    queryOne<{ count: string }>(
      `SELECT COUNT(*)::text AS count
       FROM brain_calendar_events
       WHERE user_id = $1 AND start_time <= NOW() + INTERVAL '7 days' AND end_time >= NOW()`,
      [userId]
    ),
    queryOne<{ count: string }>(
      `SELECT COUNT(*)::text AS count
       FROM findings f JOIN scans s ON s.id = f.scan_id
       WHERE s.user_id = $1 AND f.status NOT IN ('false_positive','remediated') AND f.severity = 'critical'`,
      [userId]
    ),
    queryOne<{ count: string }>(
      `SELECT COUNT(*)::text AS count
       FROM findings f JOIN scans s ON s.id = f.scan_id
       WHERE s.user_id = $1 AND f.status NOT IN ('false_positive','remediated') AND f.severity = 'high'`,
      [userId]
    ),
  ]);

  return {
    feeds_active: Number(feedsRow?.count || "0"),
    feed_items_24h: Number(itemsRow?.count || "0"),
    upcoming_events_7d: Number(eventsRow?.count || "0"),
    critical_open: Number(critRow?.count || "0"),
    high_open: Number(highRow?.count || "0"),
  };
}
