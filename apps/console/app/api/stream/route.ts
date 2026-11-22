import { bearer, controlPlaneUrl, tenant } from "@/lib/session";

export const dynamic = "force-dynamic";

/** Server-sent decision stream, relayed so the bearer stays server-side. */
export async function GET(request: Request): Promise<Response> {
  const token = await bearer();
  if (!token) return new Response("unauthenticated", { status: 401 });
  const headers: Record<string, string> = { Authorization: `Bearer ${token}`, Accept: "text/event-stream" };
  const tenantId = await tenant();
  if (tenantId) headers["X-Warrant-Tenant"] = tenantId;
  const upstream = await fetch(`${controlPlaneUrl()}/v1/decisions/stream`, {
    headers,
    cache: "no-store",
    signal: request.signal,
  }).catch(() => null);
  if (!upstream || !upstream.ok || !upstream.body) return new Response("unavailable", { status: 502 });
  return new Response(upstream.body, {
    headers: { "Content-Type": "text/event-stream", "Cache-Control": "no-store", Connection: "keep-alive" },
  });
}
