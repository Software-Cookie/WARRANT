import { NextResponse } from "next/server";
import { accessCodeMatches, clientAddress, lockedOut, recordFailure } from "@/lib/access";
import { sameOriginWrite } from "@/lib/guard";
import { controlPlaneUrl, isDevelopment, startSession } from "@/lib/session";

/**
 * Demo sign-in as a seeded user. Absent (404) outside local/demo/test environments. On a public demo deployment
 * (WARRANT_DEMO_ACCESS_CODE set) it also needs the access code; wrong codes are rate limited per client address.
 */
export async function POST(request: Request): Promise<Response> {
  if (!isDevelopment()) return NextResponse.json({ error: "not_found" }, { status: 404 });
  if (!sameOriginWrite(request)) return NextResponse.json({ error: "forbidden" }, { status: 403 });
  const address = clientAddress(request);
  if (lockedOut(address)) return NextResponse.json({ error: "too_many_attempts" }, { status: 429 });
  const { email, access_code } = (await request.json().catch(() => ({}))) as { email?: string; access_code?: unknown };
  if (!accessCodeMatches(access_code)) {
    recordFailure(address);
    return NextResponse.json({ error: "bad_access_code" }, { status: 403 });
  }
  if (!email || email.length > 254) return NextResponse.json({ error: "bad_request" }, { status: 400 });
  const response = await fetch(`${controlPlaneUrl()}/v1/dev/session`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
    cache: "no-store",
  }).catch(() => null);
  if (!response) return NextResponse.json({ error: "unavailable" }, { status: 502 });
  if (!response.ok) return NextResponse.json({ error: "unknown_user" }, { status: 401 });
  const session = (await response.json()) as { token: string; tenants: Record<string, string[]> };
  const tenants = Object.keys(session.tenants ?? {});
  await startSession(session.token, tenants[0] ?? null, 8 * 3600);
  return NextResponse.json({ ok: true, tenants });
}
