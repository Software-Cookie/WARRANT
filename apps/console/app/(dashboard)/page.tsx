"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { fmt, remaining, usePoll } from "@/lib/api";
import { Badge, Card, Empty, ErrorState, Loading, StaleNotice, Stat, verdictSignal } from "@/components/ui";

interface Pending {
  id: string;
  severity: string;
  reason_code: string;
  expires_at: string;
  card: { headline?: string };
}

interface Summary {
  pending_escalations: Pending[];
  decisions_24h: { total: number; allowed: number; escalated: number; denied: number; stage_l0: number; stage_l1: number; stage_l2: number };
  latency_ms: { p50: number | null; p95: number | null; l1_p95: number | null; l2_p95: number | null };
  prevented: { denied_rows_7d: number | null; escalation_rows_held_7d: number | null; decisions_blocked_7d: number | null };
  reasons_24h: { reason_code: string; count: number }[];
  chain: { head_idx: number; ok: boolean | null; verified_to?: number; broken_at?: number | null; reason?: string | null; checked_at?: string };
  policy: { version: string; published_at: string } | null;
}

interface LiveDecision {
  request_id: string;
  verdict: string;
  reason_code: string | null;
  tool_id: string;
  stage: string;
  latency_ms: number;
}

export default function Dashboard() {
  const [load, retry] = usePoll<Summary>("dashboard/summary", 5000);
  const [now, setNow] = useState(Date.now());
  const [live, setLive] = useState<LiveDecision[]>([]);
  const [liveState, setLiveState] = useState<"connecting" | "open" | "closed">("connecting");

  useEffect(() => {
    const tick = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(tick);
  }, []);

  useEffect(() => {
    const source = new EventSource("/api/stream");
    source.onopen = () => setLiveState("open");
    source.onerror = () => setLiveState("closed");
    source.addEventListener("decision", (event) => {
      const decision = JSON.parse((event as MessageEvent).data) as LiveDecision;
      setLive((list) => [decision, ...list].slice(0, 12));
    });
    return () => source.close();
  }, []);

  if (load.state === "loading") return <Loading label="Loading dashboard" />;
  if (load.state === "error") return <ErrorState message={load.error} retry={retry} />;
  const s = load.data;
  const d = s.decisions_24h;
  const resolvedFast = d.total ? ((d.stage_l0 + d.stage_l1) / d.total) * 100 : null;

  return (
    <div className="space-y-6">
      {load.stale && <StaleNotice at={load.at} />}
      <div className="flex flex-wrap items-end justify-between gap-4">
        <h1 className="text-2xl font-semibold">Dashboard</h1>
        <p className="text-sm text-muted">Policy {s.policy?.version ?? "not published"} · last 24 hours</p>
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Decisions" value={fmt(d.total)} hint={resolvedFast === null ? undefined : `${resolvedFast.toFixed(0)}% resolved at L0/L1`} />
        <Stat label="Allowed" value={fmt(d.allowed)} />
        <Stat label="Escalated" value={fmt(d.escalated)} />
        <Stat label="Denied" value={fmt(d.denied)} />
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <Card title="Pending escalations" action={<Link href="/approvals" className="text-sm underline">All approvals</Link>}>
            {s.pending_escalations.length === 0 ? (
              <Empty>Nothing is waiting for a human.</Empty>
            ) : (
              <ul className="divide-y divide-line">
                {s.pending_escalations.map((e) => (
                  <li key={e.id} className="flex flex-wrap items-center justify-between gap-3 py-3">
                    <div>
                      <Link href={`/approve/${e.id}`} className="font-medium underline-offset-2 hover:underline">
                        {e.card?.headline ?? e.id}
                      </Link>
                      <div className="mt-1 text-xs text-muted">{e.reason_code} · {e.severity} severity</div>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="tabular text-sm text-muted" aria-label="time remaining">{remaining(e.expires_at, now)} left</span>
                      <Badge signal="caution">Pending</Badge>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>

        <Card title="Audit chain">
          {s.chain.ok === null ? (
            <p className="text-sm text-muted">Not yet verified. Head at entry {fmt(s.chain.head_idx)}.</p>
          ) : s.chain.ok ? (
            <div className="space-y-2">
              <Badge signal="safe">Intact</Badge>
              <p className="text-sm text-muted">Verified to entry {fmt(s.chain.verified_to)} of {fmt(s.chain.head_idx)}.</p>
            </div>
          ) : (
            <div className="space-y-2">
              <Badge signal="danger">Broken</Badge>
              <p className="text-sm">Tampering detected at entry {fmt(s.chain.broken_at)}: {s.chain.reason}</p>
            </div>
          )}
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card title="Latency (ms)">
          <dl className="grid grid-cols-2 gap-3 text-sm">
            <dt className="text-muted">p50</dt><dd className="tabular text-right">{fmt(s.latency_ms.p50)}</dd>
            <dt className="text-muted">p95</dt><dd className="tabular text-right">{fmt(s.latency_ms.p95)}</dd>
            <dt className="text-muted">L0/L1 p95</dt><dd className="tabular text-right">{fmt(s.latency_ms.l1_p95)}</dd>
            <dt className="text-muted">L2 p95</dt><dd className="tabular text-right">{fmt(s.latency_ms.l2_p95)}</dd>
          </dl>
        </Card>
        <Card title="Blast radius prevented (7 days)">
          <dl className="grid grid-cols-2 gap-3 text-sm">
            <dt className="text-muted">Rows denied</dt><dd className="tabular text-right">{fmt(s.prevented.denied_rows_7d)}</dd>
            <dt className="text-muted">Rows held for a human</dt><dd className="tabular text-right">{fmt(s.prevented.escalation_rows_held_7d)}</dd>
            <dt className="text-muted">Calls blocked</dt><dd className="tabular text-right">{fmt(s.prevented.decisions_blocked_7d)}</dd>
          </dl>
        </Card>
        <Card title="Reasons (24 hours)">
          {s.reasons_24h.length === 0 ? (
            <Empty>No denials or escalations.</Empty>
          ) : (
            <ul className="space-y-2 text-sm">
              {s.reasons_24h.map((r) => (
                <li key={r.reason_code} className="flex justify-between"><span>{r.reason_code}</span><span className="tabular">{fmt(r.count)}</span></li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Card title="Live decisions" action={<span className="text-xs text-muted">{liveState === "open" ? "Streaming" : liveState === "connecting" ? "Connecting…" : "Reconnecting…"}</span>}>
        {live.length === 0 ? (
          <Empty>Decisions appear here as agents act.</Empty>
        ) : (
          <table className="w-full text-left text-sm">
            <caption className="sr-only">Most recent decisions</caption>
            <thead className="text-xs uppercase text-faint">
              <tr><th className="py-2">Verdict</th><th>Tool</th><th>Reason</th><th>Stage</th><th className="text-right">ms</th></tr>
            </thead>
            <tbody className="divide-y divide-line">
              {live.map((x) => (
                <tr key={x.request_id}>
                  <td className="py-2"><Badge signal={verdictSignal(x.verdict)}>{x.verdict}</Badge></td>
                  <td>{x.tool_id}</td>
                  <td className="text-muted">{x.reason_code ?? "—"}</td>
                  <td>{x.stage}</td>
                  <td className="tabular text-right">{x.latency_ms}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
