"use client";

import { useEffect, useState, type FormEvent } from "react";

const SEEDED = [
  { email: "r.menon@acme.example", name: "R. Menon", role: "Approver", does: "Approves or denies what agents ask for. Start here." },
  { email: "priya@acme.example", name: "Priya", role: "Security admin", does: "Agents, tools, signing keys and tenant settings." },
  { email: "meera@acme.example", name: "Meera", role: "Developer", does: "Writes policy and replays it against past traffic." },
  { email: "daniel@acme.example", name: "Daniel", role: "Auditor", does: "Read-only decisions and the tamper-evident audit log." },
];

interface Methods { google: boolean; demo: boolean; access_code: boolean }

export default function LoginPage() {
  const [email, setEmail] = useState(SEEDED[0].email);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [methods, setMethods] = useState<Methods | null>(null);

  useEffect(() => {
    fetch("/api/auth/methods")
      .then((r) => r.json())
      .then(setMethods)
      .catch(() => setMethods({ google: false, demo: true, access_code: false }));
  }, []);

  const next = () => {
    const target = new URLSearchParams(window.location.search).get("next") ?? "/";
    return target.startsWith("/") && !target.startsWith("//") ? target : "/";
  };

  const signIn = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    const response = await fetch("/api/auth/dev", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Warrant-Console": "1" },
      body: JSON.stringify({ email, access_code: code }),
    }).catch(() => null);
    setBusy(false);
    if (response?.ok) return window.location.assign(next());
    const reason = response ? ((await response.json().catch(() => ({}))) as { error?: string }).error : "unavailable";
    setError(
      reason === "bad_access_code" ? "That access code is not right. Check it and try again."
      : reason === "too_many_attempts" ? "Too many wrong attempts. Wait 15 minutes, then try again."
      : reason === "not_found" ? "Demo sign-in is switched off here. Use Google sign-in."
      : reason === "unknown_user" ? "That user does not exist in this tenant."
      : "Warrant is starting up or unreachable. Wait a moment and try again.",
    );
  };

  return (
    <main className="min-h-screen px-4 py-10 sm:px-6">
      <div className="mx-auto w-full max-w-md">
        <a href="/" className="flex justify-center" aria-label="Warrant home">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/brand/warrant-mark-on-light.png" alt="" className="brand-light h-14 w-auto" />
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/brand/warrant-mark-on-dark.png" alt="" className="brand-dark h-14 w-auto" />
        </a>
        <h1 className="mt-5 text-center text-2xl font-semibold tracking-tight">Sign in to Warrant</h1>
        <p className="mt-2 text-center text-sm text-muted">Live demo · tenant Acme Corp · sample data only</p>

        <div className="mt-8 rounded-card border border-line bg-surface p-6 shadow-sm">
          {methods?.google && (
            <>
              <a href="/api/auth/google/start"
                 className="block rounded border border-line px-4 py-2.5 text-center font-medium hover:bg-sunken">
                Sign in with Google
              </a>
              {methods.demo && (
                <div className="my-5 flex items-center gap-3 text-xs uppercase tracking-wide text-faint">
                  <span className="h-px flex-1 bg-line" /> or use a demo account <span className="h-px flex-1 bg-line" />
                </div>
              )}
            </>
          )}

          {methods === null && <p role="status" className="text-sm text-muted">Loading sign-in options…</p>}

          {methods?.demo && (
            <form onSubmit={signIn} className="space-y-5">
              {methods.access_code && (
                <div>
                  <label htmlFor="access-code" className="block text-sm font-medium">Access code</label>
                  <input id="access-code" type="password" autoComplete="current-password" required value={code}
                         onChange={(e) => setCode(e.target.value)}
                         className="mt-1.5 w-full rounded border border-line bg-surface px-3 py-2.5" />
                  <p className="mt-1.5 text-xs text-muted">Shared with the demo link.</p>
                </div>
              )}

              <fieldset>
                <legend className="text-sm font-medium">Sign in as</legend>
                <div className="mt-2 space-y-2">
                  {SEEDED.map((u) => {
                    const checked = email === u.email;
                    return (
                      <label key={u.email}
                             className={`flex cursor-pointer items-start gap-3 rounded border px-3 py-2.5 ${checked ? "border-ink bg-sunken" : "border-line hover:bg-sunken"}`}>
                        <input type="radio" name="user" value={u.email} checked={checked}
                               onChange={() => setEmail(u.email)} className="mt-1 accent-ink" aria-describedby={`${u.email}-does`} />
                        <span className="min-w-0">
                          <span className="block text-sm font-semibold">{u.name} <span className="font-normal text-muted">· {u.role}</span></span>
                          <span id={`${u.email}-does`} className="block text-xs text-muted">{u.does}</span>
                        </span>
                      </label>
                    );
                  })}
                </div>
              </fieldset>

              <button type="submit" disabled={busy}
                      className="w-full rounded bg-accent px-4 py-2.5 font-medium text-on-accent disabled:opacity-60">
                {busy ? "Signing in…" : "Sign in"}
              </button>
              {error && <p role="alert" className="rounded border border-line bg-sunken px-3 py-2 text-sm">{error}</p>}
            </form>
          )}
        </div>

        <p className="mt-6 text-center text-sm">
          <a href="/" className="text-muted underline-offset-4 hover:text-ink hover:underline">← Back to home</a>
        </p>
      </div>
    </main>
  );
}
