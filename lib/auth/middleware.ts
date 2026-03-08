import { NextRequest, NextResponse } from "next/server";
import { jwtVerify } from "jose";
import { getJwtSigningKey } from "@/lib/auth/keys";

const SESSION_COOKIE = "security_session";
const CSRF_COOKIE = "security_csrf";
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

type AppUserRole = "admin" | "analyst" | "viewer";

// Routes that don't require authentication
const PUBLIC_PATHS = [
  "/login",
  "/verify-2fa",
  "/api/auth/login",
  "/api/auth/logout",
  "/api/auth/2fa/verify",
  "/api/health",
];

const PUBLIC_PREFIXES = ["/_next/", "/favicon"];

function isPublicPath(pathname: string): boolean {
  if (PUBLIC_PATHS.includes(pathname)) return true;
  if (pathname.startsWith("/api/cron/")) return true;

  for (const prefix of PUBLIC_PREFIXES) {
    if (pathname.startsWith(prefix)) return true;
  }

  if (
    pathname.startsWith("/_next") ||
    pathname.startsWith("/static") ||
    pathname.includes(".")
  ) {
    return true;
  }

  return false;
}

function isStateChangingApiRequest(request: NextRequest): boolean {
  return request.nextUrl.pathname.startsWith("/api/") && !SAFE_METHODS.has(request.method);
}

function isTrustedFetchSite(request: NextRequest): boolean {
  const site = request.headers.get("sec-fetch-site");
  if (!site) return true;
  return site === "same-origin" || site === "same-site" || site === "none";
}

function normalizedPort(url: URL): string {
  if (url.port) return url.port;
  if (url.protocol === "https:") return "443";
  if (url.protocol === "http:") return "80";
  return "";
}

function loopbackEquivalent(a: URL, b: URL): boolean {
  const localHosts = new Set([
    "127.0.0.1",
    "localhost",
    "::1",
    "[::1]",
    "0.0.0.0",
    "security-app",
  ]);
  const aLocal = localHosts.has(a.hostname.toLowerCase());
  const bLocal = localHosts.has(b.hostname.toLowerCase());
  if (!aLocal || !bLocal) return false;
  return a.protocol === b.protocol && normalizedPort(a) === normalizedPort(b);
}

function parseOriginCandidate(candidate: string | null): URL | null {
  if (!candidate) return null;
  try {
    return new URL(candidate);
  } catch {
    return null;
  }
}

function isSameOrigin(request: NextRequest): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return true;

  try {
    const source = new URL(origin);
    const candidates: URL[] = [];

    const host =
      request.headers.get("x-forwarded-host") || request.headers.get("host");
    const proto =
      request.headers.get("x-forwarded-proto") ||
      request.nextUrl.protocol.replace(":", "") ||
      "http";
    if (host) {
      const fromHost = parseOriginCandidate(`${proto}://${host}`);
      if (fromHost) candidates.push(fromHost);
    }

    const nextOrigin = parseOriginCandidate(request.nextUrl.origin);
    if (nextOrigin) candidates.push(nextOrigin);

    const appUrl = parseOriginCandidate(process.env.APP_URL ?? null);
    if (appUrl) candidates.push(appUrl);

    for (const target of candidates) {
      if (source.origin === target.origin) return true;
      if (loopbackEquivalent(source, target)) return true;
    }

    return false;
  } catch {
    return false;
  }
}

function hasValidCsrfToken(request: NextRequest): boolean {
  const csrfHeader = request.headers.get("x-csrf-token");
  const csrfCookie = request.cookies.get(CSRF_COOKIE)?.value;
  return Boolean(csrfHeader && csrfCookie && csrfCookie === csrfHeader);
}

function viewerWriteAllowed(pathname: string): boolean {
  if (!pathname.startsWith("/api/auth/")) return false;
  if (pathname === "/api/auth/logout") return true;
  if (pathname === "/api/auth/change-password") return true;
  if (pathname === "/api/auth/2fa/enable") return true;
  if (pathname === "/api/auth/2fa/disable") return true;
  if (pathname === "/api/auth/2fa/verify") return true;
  if (pathname === "/api/auth/sessions") return true;
  if (pathname.startsWith("/api/auth/sessions/")) return true;
  return false;
}

function clearAuthCookies(response: NextResponse): void {
  response.cookies.delete(SESSION_COOKIE);
  response.cookies.delete(CSRF_COOKIE);
}

export async function authMiddleware(
  request: NextRequest
): Promise<NextResponse> {
  const { pathname } = request.nextUrl;

  if (isPublicPath(pathname)) {
    return NextResponse.next();
  }

  const sessionToken = request.cookies.get(SESSION_COOKIE)?.value;

  if (!sessionToken) {
    if (pathname.startsWith("/api/")) {
      return NextResponse.json(
        { error: "Authentication required" },
        { status: 401 }
      );
    }

    const loginUrl = new URL("/login", request.url);
    loginUrl.searchParams.set("redirect", pathname);
    return NextResponse.redirect(loginUrl);
  }

  try {
    const { payload } = await jwtVerify(sessionToken, getJwtSigningKey());
    const claims = payload as { role?: AppUserRole; type?: string };

    if (claims.type && claims.type !== "session") {
      throw new Error("Invalid token type");
    }

    if (isStateChangingApiRequest(request)) {
      const trustedFetchSite = isTrustedFetchSite(request);
      const sameOrigin = isSameOrigin(request);
      const validCsrf = hasValidCsrfToken(request);
      if (!trustedFetchSite || !sameOrigin || !validCsrf) {
        const csrfHeader = request.headers.get("x-csrf-token");
        const csrfCookie = request.cookies.get(CSRF_COOKIE)?.value;
        console.warn("[auth/csrf] validation failed", {
          method: request.method,
          path: pathname,
          origin_header: request.headers.get("origin"),
          host_header: request.headers.get("host"),
          forwarded_host: request.headers.get("x-forwarded-host"),
          forwarded_proto: request.headers.get("x-forwarded-proto"),
          next_origin: request.nextUrl.origin,
          app_url: process.env.APP_URL ?? null,
          trusted_fetch_site: trustedFetchSite,
          same_origin: sameOrigin,
          has_csrf_header: Boolean(csrfHeader),
          has_csrf_cookie: Boolean(csrfCookie),
          csrf_match: Boolean(csrfHeader && csrfCookie && csrfHeader === csrfCookie),
        });
        return NextResponse.json({ error: "CSRF validation failed" }, { status: 403 });
      }

      if (claims.role === "viewer" && !viewerWriteAllowed(pathname)) {
        return NextResponse.json({ error: "Insufficient permissions" }, { status: 403 });
      }
    }

    return NextResponse.next();
  } catch {
    if (pathname.startsWith("/api/")) {
      const response = NextResponse.json(
        { error: "Session expired" },
        { status: 401 }
      );
      clearAuthCookies(response);
      return response;
    }

    const loginUrl = new URL("/login", request.url);
    loginUrl.searchParams.set("redirect", pathname);
    const response = NextResponse.redirect(loginUrl);
    clearAuthCookies(response);
    return response;
  }
}
