import "server-only";
import { cookies } from "next/headers";

/**
 * The browser holds only an opaque, httpOnly, SameSite=Strict cookie. The control-plane bearer (a development
 * session locally, a Google ID token in production) never reaches client-side JavaScript.
 */
export const SESSION_COOKIE = "warrant_session";
export const TENANT_COOKIE = "warrant_tenant";

export function controlPlaneUrl(): string {
  return (process.env.WARRANT_CONTROL_PLANE_URL ?? "http://localhost:8081").replace(/\/+$/, "");
}

/**
 * Headers for every control-plane call. When the console runs off the demo VM (e.g. on Vercel), the VM only lets
 * requests through that carry WARRANT_CP_PROXY_KEY, so the control plane is never open to the internet.
 */
export function controlPlaneHeaders(headers: Record<string, string>): Record<string, string> {
  const key = process.env.WARRANT_CP_PROXY_KEY;
  return key ? { ...headers, "X-Warrant-Proxy-Key": key } : headers;
}

export function isDevelopment(): boolean {
  return ["local", "demo", "test"].includes(process.env.WARRANT_ENV ?? "local");
}

export function secureCookies(): boolean {
  return (process.env.WARRANT_CONSOLE_URL ?? "").startsWith("https://");
}

export async function bearer(): Promise<string | null> {
  return (await cookies()).get(SESSION_COOKIE)?.value ?? null;
}

export async function tenant(): Promise<string | null> {
  return (await cookies()).get(TENANT_COOKIE)?.value ?? null;
}

export async function startSession(token: string, tenantId: string | null, maxAgeSeconds: number): Promise<void> {
  const jar = await cookies();
  const base = { httpOnly: true, secure: secureCookies(), sameSite: "strict" as const, path: "/", maxAge: maxAgeSeconds };
  jar.set(SESSION_COOKIE, token, base);
  if (tenantId) jar.set(TENANT_COOKIE, tenantId, base);
}

export async function endSession(): Promise<void> {
  const jar = await cookies();
  jar.delete(SESSION_COOKIE);
  jar.delete(TENANT_COOKIE);
}
