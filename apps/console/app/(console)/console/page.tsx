"use client";

import { useEffect, useRef, useState } from "react";
import { api, fmt } from "@/lib/api";
import { Badge, Card, Empty, ErrorState, Loading } from "@/components/ui";

interface Diagnostic { line: number; column: number; severity: string; message: string }
interface TestResult { name: string; line: number; passed: boolean; expected: string; actual?: string }
interface CompileResult { ok: boolean; diagnostics: Diagnostic[]; tests: TestResult[] | null }
interface ReplayChange { request_id: string; decided_at: string; tool_id: string; verb: string; target: string; before: string; after: string; reason: string }
interface ReplayReport { evaluated: number; changed: number; newly_blocked: number; newly_allowed: number; changes: ReplayChange[] }
interface PolicyVersion { version: string; source: string; published_at: string }

export default function PolicyEditor() {
  const [source, setSource] = useState<string | null>(null);
  const [active, setActive] = useState<PolicyVersion | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [compile, setCompile] = useState<CompileResult | null>(null);
  const [replay, setReplay] = useState<ReplayReport | null>(null);
  const [replayError, setReplayError] = useState<string | null>(null);
  const [publishMessage, setPublishMessage] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    api<PolicyVersion>("policies/active")
      .then((p) => { setActive(p); setSource(p.source); })
      .catch((e: Error) => { setLoadError(e.message); setSource(""); });
  }, []);

  useEffect(() => {
    if (source === null) return;
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(async () => {
      try {
        const result = await api<CompileResult>("policies/compile", { method: "POST", body: { source } });
        setCompile(result);
        if (result.ok) {
          setReplayError(null);
          setReplay(await api<ReplayReport>("policies/replay", { method: "POST", body: { source, n: 1000 } }));
        } else {
          setReplay(null);
        }
      } catch (e) {
        setReplayError((e as Error).message);
      }
    }, 600);
  }, [source]);

  const publish = async () => {
    setPublishMessage(null);
    try {
      const published = await api<{ version: string }>("policies/publish", { method: "POST", body: { source } });
      setPublishMessage(`Published as ${published.version}. Gateways pick it up within seconds.`);
    } catch (e) {
      setPublishMessage((e as Error).message);
    }
  };

  if (source === null) return <Loading label="Loading active policy" />;
  const errors = compile?.diagnostics.filter((d) => d.severity === "ERROR") ?? [];
  const failingTests = compile?.tests?.filter((t) => !t.passed) ?? [];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <h1 className="text-2xl font-semibold">Policy</h1>
        <p className="text-sm text-muted">{active ? `Active: ${active.version}` : loadError ?? "No active policy"}</p>
      </div>
      <div className="grid gap-6 lg:grid-cols-5">
        <div className="lg:col-span-3">
          <label htmlFor="policy" className="mb-2 block text-sm font-semibold text-muted">Source</label>
          <textarea id="policy" value={source} onChange={(e) => setSource(e.target.value)} spellCheck={false}
                    aria-describedby="diagnostics"
                    className="h-[32rem] w-full rounded-card border border-line bg-surface p-4 font-mono text-sm leading-6" />
          <div id="diagnostics" aria-live="polite" className="mt-3 space-y-2">
            {compile === null && <p className="text-sm text-muted">Compiling…</p>}
            {compile && errors.length === 0 && failingTests.length === 0 && (
              <p className="text-sm"><Badge signal="safe">Compiles</Badge> <span className="ml-2 text-muted">{compile.tests?.length ?? 0} inline tests pass</span></p>
            )}
            {errors.map((d) => (
              <p key={`${d.line}:${d.column}:${d.message}`} className="text-sm"><Badge signal="danger">Error</Badge> <span className="ml-2">Line {d.line}, column {d.column}: {d.message}</span></p>
            ))}
            {failingTests.map((t) => (
              <p key={t.name} className="text-sm"><Badge signal="danger">Test</Badge> <span className="ml-2">{t.name} (line {t.line}): expected {t.expected}{t.actual ? `, got ${t.actual}` : ""}</span></p>
            ))}
          </div>
          <button type="button" onClick={publish} disabled={!compile?.ok || failingTests.length > 0}
                  className="mt-4 rounded bg-accent px-4 py-2 font-medium text-on-accent disabled:opacity-50">
            Publish policy
          </button>
          <p className="mt-2 text-xs text-muted">Publishing requires the security admin role; the author of a change is not its approver.</p>
          {publishMessage && <p role="status" className="mt-2 text-sm">{publishMessage}</p>}
        </div>
        <div className="lg:col-span-2">
          <Card title="Live replay against recent decisions">
            {replayError && <ErrorState message={replayError} />}
            {!replay && !replayError && <p className="text-sm text-muted">Replay runs once the policy compiles.</p>}
            {replay && (
              <>
                <dl className="grid grid-cols-2 gap-2 text-sm">
                  <dt className="text-muted">Evaluated</dt><dd className="tabular text-right">{fmt(replay.evaluated)}</dd>
                  <dt className="text-muted">Would change</dt><dd className="tabular text-right">{fmt(replay.changed)}</dd>
                  <dt className="text-muted">Newly blocked</dt><dd className="tabular text-right">{fmt(replay.newly_blocked)}</dd>
                  <dt className="text-muted">Newly allowed</dt><dd className="tabular text-right">{fmt(replay.newly_allowed)}</dd>
                </dl>
                {replay.newly_allowed > 0 && (
                  <p className="mt-3 text-sm"><Badge signal="danger">Loosens</Badge> <span className="ml-2">This change would allow calls that were stopped.</span></p>
                )}
                <div className="mt-4 max-h-96 overflow-auto">
                  {replay.changes.length === 0 ? <Empty>No recent decision changes.</Empty> : (
                    <table className="w-full text-left text-sm">
                      <caption className="sr-only">Decisions that would change</caption>
                      <thead className="text-xs uppercase text-faint"><tr><th className="py-1">Call</th><th>Before</th><th>After</th></tr></thead>
                      <tbody className="divide-y divide-line">
                        {replay.changes.map((c) => (
                          <tr key={c.request_id}>
                            <td className="py-1.5">{c.tool_id} · {c.verb}<div className="text-xs text-muted">{c.target}</div></td>
                            <td>{c.before}</td>
                            <td>{c.after}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              </>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}
