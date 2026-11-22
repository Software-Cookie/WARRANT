import "server-only";
import { createHash, timingSafeEqual } from "node:crypto";

/**
 * Optional access code for a public demo deployment (WARRANT_DEMO_ACCESS_CODE). When it is set, demo sign-in needs
 * the code; when it is empty, demo sign-in stays open (local development). The code is compared as SHA-256 digests in
 * constant time, and repeated wrong guesses from one address are locked out for a while.
 */
const WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILURES = 10;
const MAX_TRACKED = 10_000;
const failures = new Map<string, { count: number; since: number }>();

export function accessCodeRequired(): boolean {
  return Boolean(process.env.WARRANT_DEMO_ACCESS_CODE);
}

/** The client address. Caddy replaces any client-supplied X-Forwarded-For, so the first entry is the real peer. */
export function clientAddress(request: Request): string {
  const first = (request.headers.get("x-forwarded-for") ?? "").split(",")[0]?.trim();
  return first || "direct";
}

export function lockedOut(address: string, now = Date.now()): boolean {
  const entry = failures.get(address);
  if (!entry) return false;
  if (now - entry.since > WINDOW_MS) {
    failures.delete(address);
    return false;
  }
  return entry.count >= MAX_FAILURES;
}

export function recordFailure(address: string, now = Date.now()): void {
  if (failures.size >= MAX_TRACKED) {
    for (const [key, entry] of failures) if (now - entry.since > WINDOW_MS) failures.delete(key);
    if (failures.size >= MAX_TRACKED) failures.clear();
  }
  const entry = failures.get(address);
  if (!entry || now - entry.since > WINDOW_MS) failures.set(address, { count: 1, since: now });
  else entry.count += 1;
}

export function accessCodeMatches(given: unknown): boolean {
  const expected = process.env.WARRANT_DEMO_ACCESS_CODE ?? "";
  if (!expected) return true;
  if (typeof given !== "string" || given.length === 0 || given.length > 256) return false;
  const digest = (value: string) => createHash("sha256").update(value, "utf8").digest();
  return timingSafeEqual(digest(given.trim()), digest(expected));
}
