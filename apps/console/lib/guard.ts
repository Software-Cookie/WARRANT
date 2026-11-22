import "server-only";

/**
 * Cross-site request protection for state-changing BFF calls: the cookie is SameSite=Strict, and in addition the
 * request must come from this origin and carry a header a cross-site form cannot set.
 */
export function sameOriginWrite(request: Request): boolean {
  if (request.method === "GET" || request.method === "HEAD") return true;
  if (request.headers.get("x-warrant-console") !== "1") return false;
  const origin = request.headers.get("origin");
  if (!origin) return false;
  const host = request.headers.get("x-forwarded-host") ?? request.headers.get("host");
  try {
    return new URL(origin).host === host;
  } catch {
    return false;
  }
}

/** Only these control-plane paths are reachable through the console. */
const ALLOWED = [
  /^dashboard\/summary$/,
  /^decisions(\/\d+)?$/,
  /^escalations(\/esc_[A-Za-z0-9]+(\/decision)?)?$/,
  /^policies(\/(compile|test|replay|publish|active|[A-Za-z0-9._-]+))?$/,
  /^audit\/(trace|verify)$/,
  /^warrants(\/wrt_[A-Za-z0-9]+)?$/,
  /^admin\/(me|tenant|tenant\/fail-mode|change-requests\/[A-Za-z0-9_]+\/approve|agents(\/[a-z0-9-]+(\/suspend)?)?|tools(\/[a-z0-9_.-]+)?|approvers(\/[^/]+)?|users(\/[^/]+)?|keys)$/,
];

export function allowedPath(path: string): boolean {
  return ALLOWED.some((pattern) => pattern.test(path));
}
