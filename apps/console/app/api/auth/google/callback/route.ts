import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { startSession } from "@/lib/session";

interface OAuthState {
  verifier: string;
  state: string;
  nonce: string;
}

export async function GET(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const jar = await cookies();
  const raw = jar.get("warrant_oauth")?.value;
  jar.delete("warrant_oauth");
  const consoleUrl = process.env.WARRANT_CONSOLE_URL ?? url.origin;
  const fail = () => NextResponse.redirect(`${consoleUrl}/login?error=signin`);
  if (!raw) return fail();
  const expected = JSON.parse(raw) as OAuthState;
  const code = url.searchParams.get("code");
  if (!code || url.searchParams.get("state") !== expected.state) return fail();

  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: process.env.WARRANT_OIDC_CLIENT_ID ?? "",
      client_secret: process.env.WARRANT_OIDC_CLIENT_SECRET ?? "",
      redirect_uri: `${consoleUrl}/api/auth/google/callback`,
      grant_type: "authorization_code",
      code_verifier: expected.verifier,
    }),
    cache: "no-store",
  }).catch(() => null);
  if (!response?.ok) return fail();
  const tokens = (await response.json()) as { id_token?: string; expires_in?: number };
  if (!tokens.id_token) return fail();
  const claims = JSON.parse(Buffer.from(tokens.id_token.split(".")[1], "base64url").toString("utf8")) as { nonce?: string };
  // The control plane verifies signature, issuer, audience and expiry on every call; the nonce binds this login.
  if (claims.nonce !== expected.nonce) return fail();
  await startSession(tokens.id_token, process.env.WARRANT_DEFAULT_TENANT ?? null, Math.min(tokens.expires_in ?? 3600, 3600));
  return NextResponse.redirect(`${consoleUrl}/`);
}
