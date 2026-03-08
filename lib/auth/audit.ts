import { execute } from "@/lib/db/pool";

export async function logAuditEvent(
  userId: string | null,
  action: string,
  resourceType?: string,
  resourceId?: string,
  details?: Record<string, unknown>,
  ip?: string,
  userAgent?: string
): Promise<void> {
  try {
    await execute(
      `INSERT INTO audit_log (user_id, action, resource_type, resource_id, details, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6::inet, $7)`,
      [
        userId,
        action,
        resourceType || null,
        resourceId || null,
        details ? JSON.stringify(details) : null,
        ip || null,
        userAgent || null,
      ]
    );
  } catch (err) {
    console.error("[audit] Failed to log event:", err);
  }
}
