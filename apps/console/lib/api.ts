"use client";

import { useCallback, useEffect, useRef, useState } from "react";

export class ApiError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
  }
}

/** Calls the console's own BFF. Writes carry the header the BFF requires for cross-site protection. */
export async function api<T>(path: string, init?: { method?: string; body?: unknown }): Promise<T> {
  const method = init?.method ?? "GET";
  const response = await fetch(`/api/cp/${path}`, {
    method,
    headers: method === "GET" ? undefined : { "Content-Type": "application/json", "X-Warrant-Console": "1" },
    body: init?.body === undefined ? undefined : JSON.stringify(init.body),
    cache: "no-store",
  });
  if (response.status === 401) {
    window.location.assign(`/login?next=${encodeURIComponent(window.location.pathname)}`);
    throw new ApiError(401, "unauthenticated", "Your session has ended.");
  }
  const text = await response.text();
  const json = text ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new ApiError(response.status, json?.error ?? "error", json?.message ?? `Request failed (${response.status}).`);
  }
  return json as T;
}

export type Load<T> =
  | { state: "loading" }
  | { state: "error"; error: string }
  | { state: "ready"; data: T; at: number; stale: boolean };

/**
 * Polls a GET endpoint. On a failed refresh the last good data stays visible and is marked stale rather than being
 * replaced by an error, so an approver never loses the card they are reading.
 */
export function usePoll<T>(path: string | null, everyMs = 5000): [Load<T>, () => void] {
  const [load, setLoad] = useState<Load<T>>({ state: "loading" });
  const last = useRef<{ data: T; at: number } | null>(null);
  const refresh = useCallback(() => {
    if (!path) return;
    api<T>(path)
      .then((data) => {
        last.current = { data, at: Date.now() };
        setLoad({ state: "ready", data, at: Date.now(), stale: false });
      })
      .catch((error: Error) => {
        if (last.current) setLoad({ state: "ready", ...last.current, stale: true });
        else setLoad({ state: "error", error: error.message });
      });
  }, [path]);
  useEffect(() => {
    refresh();
    if (!everyMs) return;
    const timer = setInterval(refresh, everyMs);
    return () => clearInterval(timer);
  }, [refresh, everyMs]);
  return [load, refresh];
}

export function fmt(n: number | null | undefined): string {
  return n === null || n === undefined ? "—" : Math.round(n).toLocaleString("en-US");
}

export function remaining(expiresAt: string, now: number): string {
  const seconds = Math.max(0, Math.floor((Date.parse(expiresAt) - now) / 1000));
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
}
