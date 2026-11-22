"use client";

import { useParams, useRouter } from "next/navigation";
import { Fragment, useEffect, useRef, useState } from "react";
import { api, fmt, remaining, usePoll } from "@/lib/api";
import { Badge, ErrorState, Loading, StaleNotice } from "@/components/ui";

interface Detail {
  id: string;
  state: string;
  version: number;
  severity: string;
  reason_code: string;
  created_at: string;
  expires_at: string;
  approver: string | null;
  decided_at: string | null;
  card: {
    headline: string;
    risk: string;
    strip?: string[];
    provenance?: { on_behalf_of: string; requested_by: string; agent: string; mandate: string; warrant: string; scope: string[]; ceiling_rows: number; ceiling_irreversible: boolean; policy_v: string };
    alternative?: { label: string; tool: string; verb: string; rows: number };
    facts?: { rows: number | null; reversible: boolean; target: string; protected: Record<string, number>; model_version: string | null; rationale: string | null; drift_score: number | null; confidence: number | null };
  };
  raw_call: { tool: string; verb: string; target: string; arg_digest: string; arguments: unknown };
}

type Action = "deny" | "approve_partial" | "approve";

export default function ApprovalView() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [load, refresh] = usePoll<Detail>(id === "demo" ? null : `escalations/${id}`, 3000);
  const [now, setNow] = useState(Date.now());
  const [busy, setBusy] = useState<Action | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<Action | null>(null);
  const confirmRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const tick = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(tick);
  }, []);

  useEffect(() => {
    if (id !== "demo") return;
    api<{ id: string }[]>("escalations?state=pending")
      .then((rows) => router.replace(rows.length ? `/approve/${rows[rows.length - 1].id}` : "/approvals"))
      .catch(() => router.replace("/approvals"));
  }, [id, router]);

  useEffect(() => {
    if (confirming) confirmRef.current?.focus();
  }, [confirming]);

  if (id === "demo" || load.state === "loading") return <Loading label="Loading request" />;
  if (load.state === "error") return <ErrorState message={load.error} retry={refresh} />;
  const e = load.data;
  const card = e.card;
  const pending = e.state === "pending";
  const expired = Date.parse(e.expires_at) <= now;

  const decide = async (action: Action) => {
    setBusy(action);
    setMessage(null);
    try {
      const result = await api<{ state: string }>(`escalations/${e.id}/decision`, { method: "POST", body: { action, version: e.version } });
      setMessage(`Decision recorded: ${result.state}.`);
      refresh();
    } catch (error) {
      setMessage((error as Error).message);
    } finally {
      setBusy(null);
      setConfirming(null);
    }
  };

  const labels: Record<Action, string> = {
    deny: "Deny",
    approve_partial: card.alternative ? card.alternative.label : "Approve partial",
    approve: card.facts?.rows ? `Approve all ${fmt(card.facts.rows)}` : "Approve",
  };

  return (
    <article className="mx-auto max-w-3xl space-y-6" aria-labelledby="headline">
      {load.stale && <StaleNotice at={load.at} />}
      <div className="flex flex-wrap items-center gap-3">
        <Badge signal={pending ? "caution" : e.state === "denied" || e.state === "timeout" ? "danger" : "neutral"}>{e.state}</Badge>
        {e.severity === "high" && <Badge signal="danger">High severity</Badge>}
        <span className="text-sm text-muted">{e.reason_code}</span>
        {pending && (
          <span className="tabular ml-auto text-sm" role="timer" aria-live="off">
            {expired ? "Expired — this request is denied" : `${remaining(e.expires_at, now)} until it is denied automatically`}
          </span>
        )}
      </div>

      <h1 id="headline" className="text-3xl font-semibold leading-tight">{card.headline}</h1>
      <p className="text-lg">{card.risk}</p>

      {card.strip && card.strip.length > 0 && (
        <ul className="flex flex-wrap gap-2" aria-label="Key facts">
          {card.strip.map((s) => <li key={s} className="rounded border border-line bg-surface px-2 py-1 text-sm">{s}</li>)}
        </ul>
      )}

      {card.provenance && (
        <section aria-labelledby="provenance" className="rounded-card border border-line bg-surface p-5">
          <h2 id="provenance" className="text-sm font-semibold text-muted">From the warrant (verbatim)</h2>
          <dl className="mt-3 grid grid-cols-[10rem_1fr] gap-x-4 gap-y-2 text-sm">
            <dt className="text-muted">Asked by</dt><dd>{card.provenance.on_behalf_of}</dd>
            <dt className="text-muted">Instruction</dt><dd>&ldquo;{card.provenance.mandate}&rdquo;</dd>
            <dt className="text-muted">Agent</dt><dd className="break-all">{card.provenance.agent}</dd>
            <dt className="text-muted">Allowed scope</dt><dd>{card.provenance.scope.join(", ")}</dd>
            <dt className="text-muted">Row ceiling</dt><dd className="tabular">{fmt(card.provenance.ceiling_rows)} · irreversible {card.provenance.ceiling_irreversible ? "allowed" : "not allowed"}</dd>
            <dt className="text-muted">Policy</dt><dd>{card.provenance.policy_v}</dd>
            <dt className="text-muted">Warrant</dt><dd className="font-mono text-xs">{card.provenance.warrant}</dd>
          </dl>
        </section>
      )}

      {card.facts && (
        <section aria-labelledby="assessment" className="rounded-card border border-line bg-surface p-5">
          <h2 id="assessment" className="text-sm font-semibold text-muted">Assessment</h2>
          <dl className="mt-3 grid grid-cols-[10rem_1fr] gap-x-4 gap-y-2 text-sm">
            <dt className="text-muted">Records</dt><dd className="tabular">{fmt(card.facts.rows)} · {card.facts.reversible ? "reversible" : "cannot be undone"}</dd>
            <dt className="text-muted">Target</dt><dd>{card.facts.target}</dd>
            {Object.entries(card.facts.protected ?? {}).map(([k, v]) => (
              <Fragment key={k}><dt className="text-muted">Protected: {k.replace(/_/g, " ")}</dt><dd className="tabular">{fmt(v)}</dd></Fragment>
            ))}
            {card.facts.rationale && (<><dt className="text-muted">Model note</dt><dd>{card.facts.rationale}</dd></>)}
            {card.facts.model_version && (<><dt className="text-muted">Model</dt><dd className="break-all text-muted">{card.facts.model_version}</dd></>)}
          </dl>
        </section>
      )}

      <details className="rounded-card border border-line bg-surface p-5">
        <summary className="cursor-pointer text-sm font-semibold">Show the exact call</summary>
        <dl className="mt-3 grid grid-cols-[10rem_1fr] gap-x-4 gap-y-2 text-sm">
          <dt className="text-muted">Tool</dt><dd>{e.raw_call.tool} ({e.raw_call.verb})</dd>
          <dt className="text-muted">Target</dt><dd>{e.raw_call.target}</dd>
          <dt className="text-muted">Digest</dt><dd className="break-all font-mono text-xs">{e.raw_call.arg_digest}</dd>
        </dl>
        <pre className="mt-3 max-h-72 overflow-auto rounded bg-sunken p-3 font-mono text-xs">{JSON.stringify(e.raw_call.arguments, null, 2)}</pre>
      </details>

      {pending && !expired ? (
        <section aria-labelledby="decide" className="rounded-card border border-line bg-surface p-5">
          <h2 id="decide" className="text-sm font-semibold text-muted">Your decision</h2>
          {confirming ? (
            <div className="mt-3 space-y-3" role="group" aria-label="Confirm decision">
              <p>Confirm: <strong>{labels[confirming]}</strong>?</p>
              <div className="flex flex-wrap gap-3">
                <button ref={confirmRef} type="button" disabled={busy !== null} onClick={() => decide(confirming)}
                        className="rounded bg-accent px-4 py-2 font-medium text-on-accent disabled:opacity-60">
                  {busy ? "Recording…" : `Confirm ${labels[confirming].toLowerCase()}`}
                </button>
                <button type="button" onClick={() => setConfirming(null)} className="rounded border border-line px-4 py-2">Go back</button>
              </div>
            </div>
          ) : (
            <div className="mt-3 flex flex-wrap gap-3">
              <button type="button" onClick={() => setConfirming("deny")} className="rounded border border-line px-4 py-2 font-medium">
                Deny
              </button>
              {card.alternative && (
                <button type="button" onClick={() => setConfirming("approve_partial")} className="rounded bg-accent px-4 py-2 font-medium text-on-accent">
                  {card.alternative.label}
                </button>
              )}
              <button type="button" onClick={() => setConfirming("approve")} className="rounded border border-line px-4 py-2 font-medium">
                {labels.approve}
              </button>
            </div>
          )}
          {e.severity === "high" && <p className="mt-3 text-sm text-muted">High-severity approvals need a sign-in from the last five minutes.</p>}
        </section>
      ) : (
        <p className="text-sm text-muted">
          {e.approver ? `Decided by ${e.approver}` : "Decided"}{e.decided_at ? ` at ${new Date(e.decided_at).toLocaleString()}` : ""}.
        </p>
      )}
      {message && <p role="status" className="text-sm">{message}</p>}
    </article>
  );
}
