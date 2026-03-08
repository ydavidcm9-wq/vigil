import { query } from "@/lib/db/pool";

export interface TrafficSignalPoint {
  date: string;
  sessions?: number;
  signups?: number;
  paid?: number;
  failed_logins?: number;
  bot_ratio?: number; // 0..1
  error_rate_5xx?: number; // 0..1
}

interface MetricSnapshot {
  sessions_total: number;
  signups_total: number;
  paid_total: number;
  signup_to_paid_rate: number;
  failed_logins_total: number;
  avg_bot_ratio: number;
  avg_error_rate_5xx: number;
}

interface Anomaly {
  metric: string;
  severity: "critical" | "high" | "medium" | "low";
  message: string;
}

export interface TrafficIntelReport {
  source: "uploaded" | "internal-security-signals";
  window_days: number;
  metrics: MetricSnapshot;
  anomalies: Anomaly[];
  recommended_actions: string[];
}

function safeNumber(input: unknown): number {
  const n = Number(input);
  return Number.isFinite(n) ? n : 0;
}

function clamp01(value: number): number {
  if (!Number.isFinite(value)) return 0;
  if (value < 0) return 0;
  if (value > 1) return 1;
  return value;
}

function average(nums: number[]): number {
  if (nums.length === 0) return 0;
  return nums.reduce((a, b) => a + b, 0) / nums.length;
}

function detectSpike(
  values: number[],
  metric: string,
  highThreshold: number,
  criticalThreshold: number
): Anomaly[] {
  if (values.length < 4) return [];
  const latest = values[values.length - 1];
  const baseline = average(values.slice(0, -1));
  if (baseline <= 0) return [];

  const ratio = latest / baseline;
  if (ratio >= criticalThreshold) {
    return [
      {
        metric,
        severity: "critical",
        message: `${metric} spiked to ${latest.toFixed(2)} (baseline ${baseline.toFixed(2)}).`,
      },
    ];
  }
  if (ratio >= highThreshold) {
    return [
      {
        metric,
        severity: "high",
        message: `${metric} increased to ${latest.toFixed(2)} (baseline ${baseline.toFixed(2)}).`,
      },
    ];
  }
  return [];
}

function summarize(points: TrafficSignalPoint[]): MetricSnapshot {
  const sessions = points.map((p) => safeNumber(p.sessions));
  const signups = points.map((p) => safeNumber(p.signups));
  const paid = points.map((p) => safeNumber(p.paid));
  const failedLogins = points.map((p) => safeNumber(p.failed_logins));
  const botRatios = points.map((p) => clamp01(safeNumber(p.bot_ratio)));
  const errorRates = points.map((p) => clamp01(safeNumber(p.error_rate_5xx)));

  const sessionsTotal = sessions.reduce((a, b) => a + b, 0);
  const signupsTotal = signups.reduce((a, b) => a + b, 0);
  const paidTotal = paid.reduce((a, b) => a + b, 0);

  return {
    sessions_total: sessionsTotal,
    signups_total: signupsTotal,
    paid_total: paidTotal,
    signup_to_paid_rate:
      signupsTotal > 0 ? Number((paidTotal / signupsTotal).toFixed(4)) : 0,
    failed_logins_total: failedLogins.reduce((a, b) => a + b, 0),
    avg_bot_ratio: Number(average(botRatios).toFixed(4)),
    avg_error_rate_5xx: Number(average(errorRates).toFixed(4)),
  };
}

function generateActions(anomalies: Anomaly[], metrics: MetricSnapshot): string[] {
  const actions = new Set<string>();

  if (anomalies.some((a) => a.metric === "failed_logins")) {
    actions.add("Tighten auth rate limits and review credential stuffing protections.");
    actions.add("Enforce MFA on high-risk login flows and monitor lockout abuse.");
  }
  if (anomalies.some((a) => a.metric === "bot_ratio")) {
    actions.add("Deploy bot mitigation rules on signup, login, and pricing endpoints.");
  }
  if (anomalies.some((a) => a.metric === "error_rate_5xx")) {
    actions.add("Investigate 5xx spikes for abuse-driven load or deployment regression.");
  }
  if (metrics.signup_to_paid_rate < 0.05 && metrics.signups_total > 0) {
    actions.add(
      "Correlate security friction in signup/checkout with conversion drop before shipping controls globally."
    );
  }
  if (actions.size === 0) {
    actions.add("No critical traffic-security anomalies detected in this window.");
    actions.add("Keep weekly autonomous campaigns and monthly policy reviews.");
  }

  return Array.from(actions);
}

async function buildInternalSignals(userId: string, windowDays: number): Promise<TrafficSignalPoint[]> {
  const rows = await query<{
    day: string;
    failed_logins: string;
    critical_findings: string;
    high_findings: string;
    scans: string;
  }>(
    `WITH days AS (
       SELECT generate_series(
         date_trunc('day', NOW() - ($2::int || ' days')::interval),
         date_trunc('day', NOW()),
         interval '1 day'
       ) AS day
     ),
     auth AS (
       SELECT date_trunc('day', created_at) AS day, COUNT(*) AS failed_logins
       FROM audit_log
       WHERE user_id = $1
         AND action IN ('login_failed', 'login_rate_limited', '2fa_verify_failed')
         AND created_at >= NOW() - ($2::int || ' days')::interval
       GROUP BY 1
     ),
     findings_daily AS (
       SELECT date_trunc('day', f.created_at) AS day,
         COUNT(*) FILTER (WHERE f.severity = 'critical') AS critical_findings,
         COUNT(*) FILTER (WHERE f.severity = 'high') AS high_findings
       FROM findings f
       JOIN scans s ON s.id = f.scan_id
       WHERE s.user_id = $1
         AND f.created_at >= NOW() - ($2::int || ' days')::interval
       GROUP BY 1
     ),
     scans_daily AS (
       SELECT date_trunc('day', created_at) AS day, COUNT(*) AS scans
       FROM scans
       WHERE user_id = $1
         AND created_at >= NOW() - ($2::int || ' days')::interval
       GROUP BY 1
     )
     SELECT d.day::text AS day,
       COALESCE(a.failed_logins, 0)::text AS failed_logins,
       COALESCE(f.critical_findings, 0)::text AS critical_findings,
       COALESCE(f.high_findings, 0)::text AS high_findings,
       COALESCE(s.scans, 0)::text AS scans
     FROM days d
     LEFT JOIN auth a ON a.day = d.day
     LEFT JOIN findings_daily f ON f.day = d.day
     LEFT JOIN scans_daily s ON s.day = d.day
     ORDER BY d.day ASC`,
    [userId, windowDays]
  );

  return rows.map((row) => {
    const critical = safeNumber(row.critical_findings);
    const high = safeNumber(row.high_findings);
    const scans = safeNumber(row.scans);
    const proxySessions = Math.max(1, scans * 25 + critical * 8 + high * 4);
    return {
      date: row.day,
      sessions: proxySessions,
      signups: Math.max(0, Math.round(proxySessions * 0.05)),
      paid: Math.max(0, Math.round(proxySessions * 0.01)),
      failed_logins: safeNumber(row.failed_logins),
      bot_ratio: Math.min(0.95, safeNumber(row.failed_logins) / Math.max(1, proxySessions)),
      error_rate_5xx: Math.min(0.8, (critical + high) / Math.max(1, proxySessions)),
    };
  });
}

export async function buildTrafficIntelReport(args: {
  userId: string;
  points?: TrafficSignalPoint[];
  windowDays?: number;
}): Promise<TrafficIntelReport> {
  const windowDays = Math.min(Math.max(args.windowDays || 14, 3), 90);
  const sourcePoints =
    Array.isArray(args.points) && args.points.length > 0
      ? args.points
      : await buildInternalSignals(args.userId, windowDays);

  const points = sourcePoints
    .slice(-windowDays)
    .map((p) => ({
      date: p.date,
      sessions: safeNumber(p.sessions),
      signups: safeNumber(p.signups),
      paid: safeNumber(p.paid),
      failed_logins: safeNumber(p.failed_logins),
      bot_ratio: clamp01(safeNumber(p.bot_ratio)),
      error_rate_5xx: clamp01(safeNumber(p.error_rate_5xx)),
    }));

  const metrics = summarize(points);
  const anomalies: Anomaly[] = [];
  anomalies.push(
    ...detectSpike(
      points.map((p) => p.failed_logins || 0),
      "failed_logins",
      1.7,
      2.5
    )
  );
  anomalies.push(
    ...detectSpike(points.map((p) => p.bot_ratio || 0), "bot_ratio", 1.5, 2.2)
  );
  anomalies.push(
    ...detectSpike(
      points.map((p) => p.error_rate_5xx || 0),
      "error_rate_5xx",
      1.8,
      2.8
    )
  );

  if (metrics.avg_bot_ratio >= 0.35) {
    anomalies.push({
      metric: "bot_ratio",
      severity: "high",
      message: `Average bot ratio is elevated (${(metrics.avg_bot_ratio * 100).toFixed(1)}%).`,
    });
  }
  if (metrics.avg_error_rate_5xx >= 0.1) {
    anomalies.push({
      metric: "error_rate_5xx",
      severity: "medium",
      message: `Average 5xx error rate is ${(metrics.avg_error_rate_5xx * 100).toFixed(1)}%.`,
    });
  }

  return {
    source:
      Array.isArray(args.points) && args.points.length > 0
        ? "uploaded"
        : "internal-security-signals",
    window_days: windowDays,
    metrics,
    anomalies,
    recommended_actions: generateActions(anomalies, metrics),
  };
}
