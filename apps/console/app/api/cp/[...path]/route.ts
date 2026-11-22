import { NextResponse } from "next/server";
import { allowedPath, sameOriginWrite } from "@/lib/guard";
import { bearer, controlPlaneHeaders, controlPlaneUrl, tenant } from "@/lib/session";

export const dynamic = "force-dynamic";

/** Backend-for-frontend: forwards an allow-listed set of control-plane calls with the session's bearer attached. */
async function forward(request: Request, context: { params: Promise<{ path: string[] }> }): Promise<Response> {
  const { path } = await context.params;
  const joined = path.join("/");
  if (!allowedPath(joined)) {
    return NextResponse.json({ error: "not_found" }, { status: 404 });
  }
  if (!sameOriginWrite(request)) {
    return NextResponse.json({ error: "forbidden", message: "cross-site request refused" }, { status: 403 });
  }
  const token = await bearer();
  if (!token) {
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 });
  }
  const search = new URL(request.url).search;
  const headers: Record<string, string> = { Authorization: `Bearer ${token}`, Accept: "application/json" };
  const tenantId = await tenant();
  if (tenantId) headers["X-Warrant-Tenant"] = tenantId;
  let body: string | undefined;
  if (request.method !== "GET" && request.method !== "DELETE") {
    body = await request.text();
    headers["Content-Type"] = "application/json";
  }
  const upstream = await fetch(`${controlPlaneUrl()}/v1/${joined}${search}`, {
    method: request.method,
    headers: controlPlaneHeaders(headers),
    body,
    cache: "no-store",
  }).catch(() => null);
  if (!upstream) {
    return NextResponse.json({ error: "unavailable", message: "control plane unreachable" }, { status: 502 });
  }
  return new Response(upstream.body, {
    status: upstream.status,
    headers: { "Content-Type": upstream.headers.get("content-type") ?? "application/json", "Cache-Control": "no-store" },
  });
}

export const GET = forward;
export const POST = forward;
export const PUT = forward;
export const DELETE = forward;
