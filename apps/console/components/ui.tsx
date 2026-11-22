"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";

export type Signal = "danger" | "caution" | "safe" | "neutral";

const SIGNAL_CLASS: Record<Signal, string> = {
  danger: "bg-danger text-on-signal",
  caution: "bg-caution text-on-signal",
  safe: "bg-safe text-on-signal",
  neutral: "bg-sunken text-muted border border-line",
};

export function Badge({ signal, children }: { signal: Signal; children: ReactNode }) {
  return (
    <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-semibold uppercase tracking-wide ${SIGNAL_CLASS[signal]}`}>
      {children}
    </span>
  );
}

export function verdictSignal(verdict: string | null | undefined): Signal {
  switch ((verdict ?? "").toLowerCase()) {
    case "deny":
    case "denied":
    case "timeout":
      return "danger";
    case "escalate":
    case "pending":
      return "caution";
    default:
      return "neutral";
  }
}

export function Card({ title, children, action }: { title?: string; children: ReactNode; action?: ReactNode }) {
  return (
    <section className="rounded-card border border-line bg-surface p-5">
      {(title || action) && (
        <header className="mb-3 flex items-center justify-between gap-4">
          {title && <h2 className="text-sm font-semibold text-muted">{title}</h2>}
          {action}
        </header>
      )}
      {children}
    </section>
  );
}

export function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="rounded-card border border-line bg-surface p-4">
      <div className="text-xs font-medium uppercase tracking-wide text-faint">{label}</div>
      <div className="tabular mt-1 text-2xl font-semibold">{value}</div>
      {hint && <div className="mt-1 text-xs text-muted">{hint}</div>}
    </div>
  );
}

export function Loading({ label = "Loading" }: { label?: string }) {
  return (
    <div role="status" aria-live="polite" className="rounded-card border border-line bg-surface p-6 text-muted">
      {label}…
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="rounded-card border border-dashed border-line p-6 text-center text-muted">{children}</div>;
}

export function ErrorState({ message, retry }: { message: string; retry?: () => void }) {
  return (
    <div role="alert" className="rounded-card border border-line bg-surface p-6">
      <p className="font-medium">This view could not load.</p>
      <p className="mt-1 text-sm text-muted">{message}</p>
      {retry && (
        <button type="button" onClick={retry} className="mt-3 rounded border border-line px-3 py-1.5 text-sm">
          Try again
        </button>
      )}
    </div>
  );
}

export function StaleNotice({ at }: { at: number }) {
  return (
    <p role="status" className="mb-3 rounded border border-line bg-sunken px-3 py-2 text-sm text-muted">
      Showing data from {new Date(at).toLocaleTimeString()}; the latest refresh failed and will retry.
    </p>
  );
}

const NAV = [
  { href: "/", label: "Dashboard" },
  { href: "/approvals", label: "Approvals" },
  { href: "/decisions", label: "Decisions" },
  { href: "/console", label: "Policy" },
  { href: "/admin", label: "Admin" },
];

export function Shell({ children }: { children: ReactNode }) {
  const path = usePathname();
  const signOut = async () => {
    await fetch("/api/auth/logout", { method: "POST", headers: { "X-Warrant-Console": "1" } });
    window.location.assign("/login");
  };
  return (
    <div className="min-h-screen">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-10 focus:bg-surface focus:p-2">
        Skip to content
      </a>
      <header className="border-b border-line bg-surface">
        <div className="mx-auto flex max-w-7xl items-center gap-6 px-6 py-3">
          <Link href="/" className="flex items-center" aria-label="Warrant home">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src="/brand/warrant-wordmark-on-light.png" alt="Warrant" className="brand-light h-6 w-auto" />
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src="/brand/warrant-wordmark-on-dark.png" alt="Warrant" className="brand-dark h-6 w-auto" />
          </Link>
          <nav aria-label="Primary" className="flex flex-wrap gap-1">
            {NAV.map((item) => {
              const active = item.href === "/" ? path === "/" : path.startsWith(item.href);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  aria-current={active ? "page" : undefined}
                  className={`rounded px-3 py-1.5 text-sm ${active ? "bg-sunken font-semibold text-ink" : "text-muted hover:text-ink"}`}
                >
                  {item.label}
                </Link>
              );
            })}
          </nav>
          <button type="button" onClick={signOut} className="ml-auto rounded border border-line px-3 py-1.5 text-sm text-muted">
            Sign out
          </button>
        </div>
      </header>
      <main id="main" className="mx-auto max-w-7xl px-6 py-8">
        {children}
      </main>
    </div>
  );
}
