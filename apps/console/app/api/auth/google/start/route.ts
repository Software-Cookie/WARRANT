import { createHash, randomBytes } from "node:crypto";
import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { secureCookies } from "@/lib/session";

/**
 * Production sign-in: OAuth 2.0 authorization code flow with PKCE against Google. The resulting ID token is the
 * control-plane bearer (audience = this OAuth client id). The client secret is injected from Secret Manager.
 */
export async function GET(): Promise<Response> {
  const clientId = process.env.WARRANT_OIDC_CLIENT_ID;
  const consoleUrl = process.env.WARRANT_CONSOLE_URL;
  if (!clientId || !consoleUrl) return NextResponse.json({ error: "oidc_not_configured" }, { status: 404 });
  const verifier = randomBytes(32).toString("base64url");
  const state = randomBytes(16).toString("base64url");
  const nonce = randomBytes(16).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const jar = await cookies();
  const transient = { httpOnly: true, secure: secureCookies(), sameSite: "lax" as const, path: "/api/auth", maxAge: 600 };
  jar.set("warrant_oauth", JSON.stringify({ verifier, state, nonce }), transient);
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.search = new URLSearchParams({
    client_id: clientId,
    redirect_uri: `${consoleUrl}/api/auth/google/callback`,
    response_type: "code",
    scope: "openid email",
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
    prompt: "select_account",
  }).toString();
  return NextResponse.redirect(url.toString());
}
