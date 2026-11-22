import { NextResponse } from "next/server";
import { accessCodeRequired } from "@/lib/access";
import { isDevelopment } from "@/lib/session";

export const dynamic = "force-dynamic";

/** Which sign-in methods this deployment offers. No secrets: only whether each is configured. */
export async function GET(): Promise<Response> {
  return NextResponse.json({
    google: Boolean(process.env.WARRANT_OIDC_CLIENT_ID),
    demo: isDevelopment(),
    access_code: isDevelopment() && accessCodeRequired(),
  });
}
