import { NextResponse, type NextRequest } from "next/server";

/**
 * Pages require a session; the landing page, login page, auth endpoints and static assets do not.
 * A visitor without a session who opens "/" sees the public landing page; any other page sends them to sign in.
 */
export function middleware(request: NextRequest) {
  const hasSession = Boolean(request.cookies.get("warrant_session")?.value);
  if (!hasSession) {
    if (request.nextUrl.pathname === "/") return NextResponse.rewrite(new URL("/welcome", request.url));
    const login = new URL("/login", request.url);
    login.searchParams.set("next", request.nextUrl.pathname);
    return NextResponse.redirect(login);
  }
  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!login|welcome|api|_next|brand|favicon.ico|icon.png).*)"],
};
