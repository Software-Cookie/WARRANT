"use client";

import { useState } from "react";
import { api, fmt, usePoll } from "@/lib/api";
import { Badge, Card, Empty, ErrorState, Loading, StaleNotice, verdictSignal } from "@/components/ui";

interface DecisionRow {
  id: number;
  request_id: string;
  decided_at: string;
  agent_id: string;
  principal: string;
  tool_id: string;
  verb: string;
  target: string;
  verdict: string;
  reason_code: string | null;
  stage: string;
  latency_ms: number;
  policy_v: string;
  model_v: string | null;
  approver: string | null;
  explanation: string;
  rows_affected: number | null;
  chain_idx: number | null;
}

interface VerifyReport { ok: boolean; checked: number; broken_at: number | null; reason: string | null; signed_heads_verified: number }

export default function Decisions() {
  const [verdict, setVerdict] = useState("");
  const [stage, setStage] = useState("");
  const query = new URLSearchParams({ limit: "100", ...(verdict && { verdict }), ...(stage && { stage }) }).toString();
  const [load, retry] = usePoll<DecisionRow[]>(`decisions?${query}`, 5000);
  const [verify, setVerify] = useState<VerifyReport | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);

  const runVerify = async () => {
    setVerifyError(null);
    try {
      setVerify(await api<VerifyReport>("audit/verify"));
    } catch (e) {
      setVerifyError((e as Error).message);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <h1 className="text-2xl font-semibold">Decisions</h1>
        <div className="flex flex-wrap items-end gap-3">
          <label className="text-sm">Verdict
            <select value={verdict} onChange={(e) => setVerdict(e.target.value)} className="ml-2 rounded border border-line bg-surface px-2 py-1">
              <option value="">All</option><option value="allow">Allow</option><option value="escalate">Escalate</option><option value="deny">Deny</option>
            </select>
          </label>
          <label className="text-sm">Stage
            <select value={stage} onChange={(e) => setStage(e.target.value)} className="ml-2 rounded border border-line bg-surface px-2 py-1">
              <option value="">All</option><option value="L0">L0</option><option value="L1">L1</option><option value="L2">L2</option>
            </select>
          </label>
        </div>
      </div>

      <Card title="Audit chain" action={<button type="button" onClick={runVerify} className="rounded border border-line px-3 py-1.5 text-sm">Verify now</button>}>
        {verifyError && <ErrorState message={verifyError} />}
        {!verify && !verifyError && <p className="text-sm text-muted">Recomputes every hash and checks every signed head. Auditors and security admins only.</p>}
        {verify && (verify.ok
          ? <p className="text-sm"><Badge signal="safe">Intact</Badge> <span className="ml-2">{fmt(verify.checked)} entries and {fmt(verify.signed_heads_verified)} signed heads verified.</span></p>
          : <p className="text-sm"><Badge signal="danger">Broken</Badge> <span className="ml-2">At entry {fmt(verify.broken_at)}: {verify.reason}</span></p>)}
      </Card>

      {load.state === "loading" && <Loading label="Loading decisions" />}
      {load.state === "error" && <ErrorState message={load.error} retry={retry} />}
      {load.state === "ready" && (
        <>
          {load.stale && <StaleNotice at={load.at} />}
          {load.data.length === 0 ? <Empty>No decisions match.</Empty> : (
            <div className="overflow-x-auto rounded-card border border-line bg-surface">
              <table className="w-full text-left text-sm">
                <caption className="sr-only">Decisions, newest first</caption>
                <thead className="border-b border-line text-xs uppercase text-faint">
                  <tr><th className="px-3 py-2">Time</th><th>Verdict</th><th>Call</th><th>Reason</th><th>Principal</th><th>Stage</th><th className="text-right">ms</th><th className="px-3 text-right">Chain</th></tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {load.data.map((d) => (
                    <tr key={d.id} className="align-top">
                      <td className="tabular whitespace-nowrap px-3 py-2 text-muted">{new Date(d.decided_at).toLocaleTimeString()}</td>
                      <td className="py-2"><Badge signal={verdictSignal(d.verdict)}>{d.verdict}</Badge></td>
                      <td className="py-2">{d.tool_id} · {d.verb}<div className="text-xs text-muted">{d.target}{d.rows_affected !== null ? ` · ${fmt(d.rows_affected)} rows` : ""}</div></td>
                      <td className="py-2">{d.reason_code ?? "—"}<div className="max-w-xs text-xs text-muted">{d.explanation}</div></td>
                      <td className="py-2 text-muted">{d.principal}{d.approver ? <div className="text-xs">approved by {d.approver}</div> : null}</td>
                      <td className="py-2">{d.stage}</td>
                      <td className="tabular py-2 text-right">{d.latency_ms}</td>
                      <td className="tabular px-3 py-2 text-right text-muted">{d.chain_idx ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}
