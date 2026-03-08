import { SignJWT, jwtVerify, type JWTPayload } from "jose";
import { cookies } from "next/headers";
import { query, queryOne } from "@/lib/db/pool";
import crypto from "crypto";
import { getJwtSigningKey } from "@/lib/auth/keys";

export const SESSION_COOKIE = "security_session";
export const TWO_FA_COOKIE = "security_2fa_pending";
export const CSRF_COOKIE = "security_csrf";
const SESSION_EXPIRY_HOURS = 24;
const TWO_FA_EXPIRY_SECONDS = 5 * 60;

export type AppUserRole = "admin" | "analyst" | "viewer";

interface SessionPayload extends JWTPayload {
  sub: string;
  sid?: string;
  role?: AppUserRole;
  type?: "session" | "2fa_pending";
}

function shouldUseSecureCookies(): boolean {
  const override = process.env.AUTH_COOKIE_SECURE;
  if (override === "true") return true;
  if (override === "false") return false;
  return process.env.NODE_ENV === "production";
}

function createCsrfToken(): string {
  return crypto.randomBytes(32).toString("hex");
}

export async function createSession(
  userId: string,
  role: AppUserRole,
  ip: string,
  userAgent: string
): Promise<string> {
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(
    Date.now() + SESSION_EXPIRY_HOURS * 60 * 60 * 1000
  );

  await query(
    `INSERT INTO sessions (user_id, token, ip_address, user_agent, expires_at)
     VALUES ($1, $2, $3::inet, $4, $5)`,
    [userId, token, ip, userAgent, expiresAt.toISOString()]
  );

  const jwt = await new SignJWT({
    sub: userId,
    sid: token,
    role,
    type: "session",
  })
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime(`${SESSION_EXPIRY_HOURS}h`)
    .setIssuedAt()
    .sign(getJwtSigningKey());

  const cookieStore = await cookies();
  cookieStore.set(SESSION_COOKIE, jwt, {
    httpOnly: true,
    secure: shouldUseSecureCookies(),
    sameSite: "lax",
    path: "/",
    maxAge: SESSION_EXPIRY_HOURS * 60 * 60,
  });
  cookieStore.set(CSRF_COOKIE, createCsrfToken(), {
    httpOnly: false,
    secure: shouldUseSecureCookies(),
    sameSite: "strict",
    path: "/",
    maxAge: SESSION_EXPIRY_HOURS * 60 * 60,
  });

  return jwt;
}

export async function getSession(): Promise<{
  userId: string;
  sessionId: string;
  role: AppUserRole;
} | null> {
  const cookieStore = await cookies();
  const token = cookieStore.get(SESSION_COOKIE)?.value;
  if (!token) return null;

  try {
    const { payload } = await jwtVerify(token, getJwtSigningKey());
    const claims = payload as SessionPayload;
    if (claims.type && claims.type !== "session") return null;
    const sid = claims.sid;
    const userId = claims.sub;
    if (!sid || !userId) return null;

    const session = await queryOne<{
      id: string;
      user_id: string;
      role: AppUserRole;
      is_active: boolean;
    }>(
      `SELECT s.id, s.user_id, u.role, u.is_active
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.token = $1
         AND s.expires_at > NOW()`,
      [sid]
    );

    if (!session) return null;
    if (!session.is_active) return null;
    return {
      userId: session.user_id,
      sessionId: session.id,
      role: session.role || claims.role || "analyst",
    };
  } catch {
    return null;
  }
}

export async function requireAuth(): Promise<{
  userId: string;
  sessionId: string;
  role: AppUserRole;
}> {
  const session = await getSession();
  if (!session) {
    throw new Error("Unauthorized");
  }
  return session;
}

export function requireRole(
  session: { role: AppUserRole },
  allowed: AppUserRole[]
): void {
  if (!allowed.includes(session.role)) {
    throw new Error("Forbidden");
  }
}

export async function destroySession(): Promise<void> {
  const cookieStore = await cookies();
  const token = cookieStore.get(SESSION_COOKIE)?.value;
  if (token) {
    try {
      const { payload } = await jwtVerify(token, getJwtSigningKey());
      const claims = payload as SessionPayload;
      if (claims.sid) {
        await query(`DELETE FROM sessions WHERE token = $1`, [claims.sid]);
      }
    } catch {
      // Token invalid, just clear cookie
    }
  }
  cookieStore.delete(SESSION_COOKIE);
  cookieStore.delete(TWO_FA_COOKIE);
  cookieStore.delete(CSRF_COOKIE);
}

export async function set2FAPending(userId: string): Promise<void> {
  const token = await new SignJWT({
    sub: userId,
    type: "2fa_pending",
  })
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime(`${TWO_FA_EXPIRY_SECONDS}s`)
    .setIssuedAt()
    .sign(getJwtSigningKey());

  const cookieStore = await cookies();
  cookieStore.set(TWO_FA_COOKIE, token, {
    httpOnly: true,
    secure: shouldUseSecureCookies(),
    sameSite: "lax",
    path: "/",
    maxAge: TWO_FA_EXPIRY_SECONDS,
  });
}

export async function get2FAPending(): Promise<string | null> {
  const cookieStore = await cookies();
  const token = cookieStore.get(TWO_FA_COOKIE)?.value;
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, getJwtSigningKey());
    const claims = payload as SessionPayload;
    if (claims.type !== "2fa_pending" || !claims.sub) return null;
    return claims.sub;
  } catch {
    return null;
  }
}

export async function clear2FAPending(): Promise<void> {
  const cookieStore = await cookies();
  cookieStore.delete(TWO_FA_COOKIE);
}
