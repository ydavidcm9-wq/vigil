import { execute, queryOne } from "@/lib/db/pool";
import { ensureBrainTables } from "@/lib/brain/store";
import {
  listDueCampaignSchedules,
  tryAcquireSchedulerLease,
  updateCampaignSchedule,
  type AgentCampaignScheduleRecord,
  type AgentCampaignScheduleType,
} from "@/lib/agents/store";
import { launchAutonomousCampaign } from "@/lib/agents/autonomous";

const SCHEDULE_EVENT_DURATION_MINUTES = 20;
const RUNNER_RETRY_MINUTES = 5;

const WEB_AGENT_TEMPLATE_NOTES: Record<string, string> = {
  "ghost-recon":
    "Use passive reconnaissance only (CT logs, DNS, Wayback, job postings, social mentions) to map surface area before active testing.",
  "tech-stack-xray":
    "Infer stack and dependency signals from passive metadata to prioritize likely framework/library weaknesses.",
  "pricing-drift-monitor":
    "Look for trust and abuse changes around billing, trial boundaries, and pricing-flow security posture.",
  "talent-signal-radar":
    "Use hiring and roadmap signals to predict near-term attack-surface expansion and pre-stage controls.",
  "domain-empire-scanner":
    "Map all related domains/subdomains and evaluate auth/session and DNS trust boundaries between them.",
  "social-sentiment-forecast":
    "Correlate sentiment and abuse chatter with login, phishing, and account takeover indicators.",
  "supply-chain-audit":
    "Prioritize dependency, third-party script, and SaaS integration risk with remediation sequencing.",
  "content-gap-finder":
    "Identify public content exposure patterns that could leak sensitive implementation details.",
  "infra-fingerprint":
    "Fingerprint infrastructure and protection layers to focus hardening checks on realistic bypass paths.",
  "competitive-drift-report":
    "Track external drift signals weekly and convert them into updated defensive testing priorities.",
};

function parseTime(value: string): { hour: number; minute: number } {
  const parts = value.split(":");
  if (parts.length !== 2) throw new Error("time must be HH:MM");
  const hour = Number.parseInt(parts[0] || "", 10);
  const minute = Number.parseInt(parts[1] || "", 10);
  if (!Number.isInteger(hour) || hour < 0 || hour > 23) throw new Error("Invalid hour in time");
  if (!Number.isInteger(minute) || minute < 0 || minute > 59) throw new Error("Invalid minute in time");
  return { hour, minute };
}

function getTzParts(date: Date, timezone: string): {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  weekday: number;
} {
  const formatter = new Intl.DateTimeFormat("en-US", {
    timeZone: timezone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
    weekday: "short",
  });
  const parts = formatter.formatToParts(date);
  const lookup = (type: string): string =>
    parts.find((part) => part.type === type)?.value || "0";
  const weekdayMap: Record<string, number> = {
    Sun: 0,
    Mon: 1,
    Tue: 2,
    Wed: 3,
    Thu: 4,
    Fri: 5,
    Sat: 6,
  };
  return {
    year: Number.parseInt(lookup("year"), 10),
    month: Number.parseInt(lookup("month"), 10),
    day: Number.parseInt(lookup("day"), 10),
    hour: Number.parseInt(lookup("hour"), 10),
    minute: Number.parseInt(lookup("minute"), 10),
    weekday: weekdayMap[lookup("weekday")] ?? date.getDay(),
  };
}

function zonedTimeToUtc(
  year: number,
  month: number,
  day: number,
  hour: number,
  minute: number,
  timezone: string
): Date {
  const approxUtc = Date.UTC(year, month - 1, day, hour, minute, 0);
  const tzAtApprox = getTzParts(new Date(approxUtc), timezone);
  const asUtc = Date.UTC(
    tzAtApprox.year,
    tzAtApprox.month - 1,
    tzAtApprox.day,
    tzAtApprox.hour,
    tzAtApprox.minute,
    0
  );
  const offsetMs = asUtc - approxUtc;
  return new Date(approxUtc - offsetMs);
}

function addDays(date: Date, days: number): Date {
  return new Date(date.getTime() + days * 24 * 60 * 60 * 1000);
}

function nextDailyRun(
  time: string,
  timezone: string,
  fromDate: Date
): Date {
  const { hour, minute } = parseTime(time);
  const nowLocal = getTzParts(fromDate, timezone);
  let dayOffset = 0;
  if (
    nowLocal.hour > hour ||
    (nowLocal.hour === hour && nowLocal.minute >= minute)
  ) {
    dayOffset = 1;
  }
  const targetUtc = zonedTimeToUtc(
    nowLocal.year,
    nowLocal.month,
    nowLocal.day + dayOffset,
    hour,
    minute,
    timezone
  );
  return targetUtc;
}

function nextWeeklyRun(
  dayOfWeek: number,
  time: string,
  timezone: string,
  fromDate: Date
): Date {
  if (dayOfWeek < 0 || dayOfWeek > 6) {
    throw new Error("day_of_week must be 0-6");
  }
  const { hour, minute } = parseTime(time);
  const nowLocal = getTzParts(fromDate, timezone);
  let delta = dayOfWeek - nowLocal.weekday;
  if (delta < 0) delta += 7;
  if (
    delta === 0 &&
    (nowLocal.hour > hour || (nowLocal.hour === hour && nowLocal.minute >= minute))
  ) {
    delta = 7;
  }
  const base = addDays(
    zonedTimeToUtc(nowLocal.year, nowLocal.month, nowLocal.day, 0, 0, timezone),
    delta
  );
  const localTarget = getTzParts(base, timezone);
  return zonedTimeToUtc(
    localTarget.year,
    localTarget.month,
    localTarget.day,
    hour,
    minute,
    timezone
  );
}

export function computeInitialNextRunAt(input: {
  scheduleType: AgentCampaignScheduleType;
  scheduleConfig: Record<string, unknown>;
  timezone: string;
  now?: Date;
}): string {
  const now = input.now || new Date();
  const cfg = input.scheduleConfig || {};
  if (input.scheduleType === "once") {
    const runAtRaw = String(cfg.run_at || "");
    const runAt = new Date(runAtRaw);
    if (Number.isNaN(runAt.getTime())) {
      throw new Error("schedule_config.run_at must be an ISO datetime");
    }
    if (runAt.getTime() <= now.getTime()) {
      throw new Error("run_at must be in the future");
    }
    return runAt.toISOString();
  }
  if (input.scheduleType === "interval") {
    const minutes = Number(cfg.interval_minutes || 0);
    if (!Number.isInteger(minutes) || minutes < 5 || minutes > 7 * 24 * 60) {
      throw new Error("interval_minutes must be an integer between 5 and 10080");
    }
    return new Date(now.getTime() + minutes * 60_000).toISOString();
  }
  if (input.scheduleType === "daily") {
    return nextDailyRun(String(cfg.time || ""), input.timezone, now).toISOString();
  }
  return nextWeeklyRun(
    Number(cfg.day_of_week),
    String(cfg.time || ""),
    input.timezone,
    now
  ).toISOString();
}

export function computeFollowingNextRunAt(
  schedule: AgentCampaignScheduleRecord,
  now = new Date()
): string | null {
  if (schedule.schedule_type === "once") return null;
  return computeInitialNextRunAt({
    scheduleType: schedule.schedule_type,
    scheduleConfig: schedule.schedule_config || {},
    timezone: schedule.timezone || "America/Chicago",
    now,
  });
}

export function buildScheduledCampaignGoal(
  goal: string,
  webAgentTemplate: string | null,
  webAgentConfig: Record<string, unknown>
): string {
  if (!webAgentTemplate) return goal;
  const note =
    WEB_AGENT_TEMPLATE_NOTES[webAgentTemplate] ||
    "Apply passive web-intelligence enrichment before active campaign execution.";
  const cfg = Object.keys(webAgentConfig || {}).length
    ? `\nTemplate config: ${JSON.stringify(webAgentConfig)}`
    : "";
  return `${goal}

Passive Web-Agent profile (from /admin template: ${webAgentTemplate}):
- ${note}${cfg}
- Keep enrichment passive-first, then prioritize high-impact validation paths.`;
}

export async function syncScheduleCalendarEvent(
  schedule: AgentCampaignScheduleRecord
): Promise<void> {
  await ensureBrainTables();
  const start = new Date(schedule.next_run_at);
  const end = new Date(start.getTime() + SCHEDULE_EVENT_DURATION_MINUTES * 60_000);
  const metadata = {
    autonomous_schedule_id: schedule.id,
    schedule_type: schedule.schedule_type,
    schedule_config: schedule.schedule_config,
    timezone: schedule.timezone,
    web_agent_template: schedule.web_agent_template,
    web_agent_config: schedule.web_agent_config,
  };

  const existing = await queryOne<{ id: string }>(
    `SELECT id
     FROM brain_calendar_events
     WHERE user_id = $1
       AND category = 'autonomous-campaign'
       AND metadata->>'autonomous_schedule_id' = $2
       AND status = 'planned'
     ORDER BY start_time ASC
     LIMIT 1`,
    [schedule.user_id, schedule.id]
  );

  if (existing) {
    await execute(
      `UPDATE brain_calendar_events
       SET title = $3,
           description = $4,
           start_time = $5::timestamptz,
           end_time = $6::timestamptz,
           priority = CASE WHEN $7 IN ('high','critical') THEN $7 ELSE 'high' END,
           metadata = $8::jsonb,
           updated_at = NOW()
       WHERE id = $1 AND user_id = $2`,
      [
        existing.id,
        schedule.user_id,
        schedule.title,
        schedule.goal,
        start.toISOString(),
        end.toISOString(),
        "high",
        JSON.stringify(metadata),
      ]
    );
    return;
  }

  await execute(
    `INSERT INTO brain_calendar_events (
       user_id, title, description, start_time, end_time, category, status, priority, metadata
     ) VALUES (
       $1, $2, $3, $4::timestamptz, $5::timestamptz, 'autonomous-campaign', 'planned', 'high', $6::jsonb
     )`,
    [
      schedule.user_id,
      schedule.title,
      schedule.goal,
      start.toISOString(),
      end.toISOString(),
      JSON.stringify(metadata),
    ]
  );
}

export async function completeScheduleCalendarEvent(args: {
  userId: string;
  scheduleId: string;
  campaignId?: string | null;
  ok: boolean;
  error?: string | null;
}): Promise<void> {
  await ensureBrainTables();
  const metadataPatch = {
    last_campaign_id: args.campaignId || null,
    last_run_ok: args.ok,
    last_error: args.error || null,
    last_run_at: new Date().toISOString(),
  };
  await execute(
    `UPDATE brain_calendar_events
     SET status = $3,
         metadata = COALESCE(metadata, '{}'::jsonb) || $4::jsonb,
         updated_at = NOW()
     WHERE id = (
       SELECT id
       FROM brain_calendar_events
       WHERE user_id = $1
         AND category = 'autonomous-campaign'
         AND metadata->>'autonomous_schedule_id' = $2
         AND status = 'planned'
       ORDER BY start_time ASC
       LIMIT 1
     )`,
    [
      args.userId,
      args.scheduleId,
      args.ok ? "completed" : "blocked",
      JSON.stringify(metadataPatch),
    ]
  );
}

export async function removeScheduleCalendarEvents(
  userId: string,
  scheduleId: string
): Promise<void> {
  await ensureBrainTables();
  await execute(
    `DELETE FROM brain_calendar_events
     WHERE user_id = $1
       AND category = 'autonomous-campaign'
       AND metadata->>'autonomous_schedule_id' = $2`,
    [userId, scheduleId]
  );
}

export async function runDueCampaignSchedules(
  limit = 10
): Promise<{
  checked: number;
  launched: number;
  failed: number;
  schedule_ids: string[];
}> {
  const holder = `pid:${process.pid}`;
  const hasLease = await tryAcquireSchedulerLease(
    "agent_campaign_schedules_runner",
    holder,
    55
  );
  if (!hasLease) {
    return { checked: 0, launched: 0, failed: 0, schedule_ids: [] };
  }

  const now = new Date();
  const due = await listDueCampaignSchedules(now.toISOString(), limit);
  let launched = 0;
  let failed = 0;
  const scheduleIds: string[] = [];

  for (const schedule of due) {
    scheduleIds.push(schedule.id);
    const followingNextRun = computeFollowingNextRunAt(schedule, now);
    const provisionalNext =
      followingNextRun || new Date(now.getTime() + RUNNER_RETRY_MINUTES * 60_000).toISOString();

    await updateCampaignSchedule(schedule.user_id, schedule.id, {
      next_run_at: provisionalNext,
      enabled: schedule.schedule_type === "once" ? false : schedule.enabled,
      last_status: "running",
      last_error: null,
    });

    try {
      const campaignGoal = buildScheduledCampaignGoal(
        schedule.goal,
        schedule.web_agent_template,
        schedule.web_agent_config || {}
      );
      const launchedCampaign = await launchAutonomousCampaign(schedule.user_id, {
        goal: campaignGoal,
        maxAgents: schedule.max_agents,
      });
      launched += 1;

      await updateCampaignSchedule(schedule.user_id, schedule.id, {
        last_run_at: now.toISOString(),
        last_campaign_id: launchedCampaign.campaign.id,
        last_status: "completed",
        last_error: null,
        run_count: schedule.run_count + 1,
        enabled: schedule.schedule_type === "once" ? false : schedule.enabled,
        next_run_at: followingNextRun || provisionalNext,
      });

      await completeScheduleCalendarEvent({
        userId: schedule.user_id,
        scheduleId: schedule.id,
        campaignId: launchedCampaign.campaign.id,
        ok: true,
      });

      if (schedule.schedule_type !== "once" && followingNextRun) {
        const refreshed = await queryOne<AgentCampaignScheduleRecord>(
          `SELECT * FROM agent_campaign_schedules WHERE id = $1 AND user_id = $2`,
          [schedule.id, schedule.user_id]
        );
        if (refreshed) {
          await syncScheduleCalendarEvent(refreshed);
        }
      }
    } catch (err) {
      failed += 1;
      const message = err instanceof Error ? err.message : "Schedule runner failed";
      const retryAt = new Date(now.getTime() + RUNNER_RETRY_MINUTES * 60_000).toISOString();
      await updateCampaignSchedule(schedule.user_id, schedule.id, {
        next_run_at: retryAt,
        enabled: schedule.enabled,
        last_status: "failed",
        last_error: message,
      });
      await completeScheduleCalendarEvent({
        userId: schedule.user_id,
        scheduleId: schedule.id,
        ok: false,
        error: message,
      });
      const refreshed = await queryOne<AgentCampaignScheduleRecord>(
        `SELECT * FROM agent_campaign_schedules WHERE id = $1 AND user_id = $2`,
        [schedule.id, schedule.user_id]
      );
      if (refreshed && refreshed.enabled) {
        await syncScheduleCalendarEvent(refreshed);
      }
    }
  }

  return {
    checked: due.length,
    launched,
    failed,
    schedule_ids: scheduleIds,
  };
}
