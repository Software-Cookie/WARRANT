import { NextResponse } from "next/server";
import { sameOriginWrite } from "@/lib/guard";
import { endSession } from "@/lib/session";

export async function POST(request: Request): Promise<Response> {
  if (!sameOriginWrite(request)) return NextResponse.json({ error: "forbidden" }, { status: 403 });
  await endSession();
  return NextResponse.json({ ok: true });
}
