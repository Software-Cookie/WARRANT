"use client";

import { useState, type FormEvent } from "react";
import { api, usePoll } from "@/lib/api";
import { Badge, Card, Empty, ErrorState, Loading } from "@/components/ui";

interface Me { email: string; tenant: string; roles: string[] }
interface Agent { name: string; build_hash: string; allowed_scope: string[]; owner: string; suspended_at: string | null }
interface Tool { id: string; protocol: string; derivation: string; target_prefix: string }
interface Key { kid: string; purpose: string; algorithm: string; source: string; created_at: string; retired_at: string | null }
interface Tenant { id: string; name: string; fail_mode?: string; escalation_ttl_seconds?: number }

export default function Admin() {
  const [me] = usePoll<Me>("admin/me", 0);
  const [agents, refreshAgents] = usePoll<Agent[]>("admin/agents", 10000);
  const [tools] = usePoll<Tool[]>("admin/tools", 0);
  const [keys] = usePoll<Key[]>("admin/keys", 0);
  const [tenant] = usePoll<Tenant>("admin/tenant", 0);
  const [suspending, setSuspending] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const [toolJson, setToolJson] = useState("");
  const [agentName, setAgentName] = useState("");
  const [agentHash, setAgentHash] = useState("");
  const [agentScope, setAgentScope] = useState("");

  const registerTool = async (event: FormEvent) => {
    event.preventDefault();
    setMessage(null);
    try {
      const definition = JSON.parse(toolJson) as { id?: string };
      if (!definition.id) throw new Error("The tool definition needs an id.");
      await api(`admin/tools/${encodeURIComponent(definition.id)}`, { method: "PUT", body: definition });
      setMessage(`Tool ${definition.id} registered. Gateways pick it up with the next policy bundle.`);
      setToolJson("");
    } catch (e) {
      setMessage((e as Error).message);
    }
  };

  const registerAgent = async (event: FormEvent) => {
    event.preventDefault();
    setMessage(null);
    try {
      const allowed = agentScope.split(",").map((s) => s.trim()).filter(Boolean);
      await api(`admin/agents/${encodeURIComponent(agentName)}`, { method: "PUT", body: { build_hash: agentHash.trim(), allowed_scope: allowed } });
      setMessage(`Agent ${agentName} registered and pinned to ${agentHash.slice(0, 19)}…`);
      setAgentName("");
      setAgentHash("");
      setAgentScope("");
      refreshAgents();
    } catch (e) {
      setMessage((e as Error).message);
    }
  };

  const suspend = async (name: string) => {
    setMessage(null);
    try {
      const result = await api<{ revoked_warrants: string[] }>(`admin/agents/${name}/suspend`, { method: "POST", body: {} });
      setMessage(`${name} suspended; ${result.revoked_warrants.length} live warrant(s) revoked.`);
      refreshAgents();
    } catch (e) {
      setMessage((e as Error).message);
    } finally {
      setSuspending(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <h1 className="text-2xl font-semibold">Admin</h1>
        {me.state === "ready" && <p className="text-sm text-muted">{me.data.email} · {me.data.tenant} · {me.data.roles.join(", ")}</p>}
      </div>
      {message && <p role="status" className="text-sm">{message}</p>}

      <Card title="Agents">
        {agents.state === "loading" && <Loading />}
        {agents.state === "error" && <ErrorState message={agents.error} />}
        {agents.state === "ready" && (agents.data.length === 0 ? <Empty>No agents registered.</Empty> : (
          <ul className="divide-y divide-line">
            {agents.data.map((a) => (
              <li key={a.name} className="flex flex-wrap items-center justify-between gap-3 py-3">
                <div>
                  <div className="font-medium">{a.name} {a.suspended_at && <Badge signal="danger">Suspended</Badge>}</div>
                  <div className="break-all font-mono text-xs text-muted">{a.build_hash}</div>
                  <div className="text-xs text-muted">Scope: {(a.allowed_scope ?? []).join(", ")} · registered by {a.owner}</div>
                </div>
                {!a.suspended_at && (suspending === a.name ? (
                  <span className="flex gap-2">
                    <button type="button" onClick={() => suspend(a.name)} className="rounded bg-accent px-3 py-1.5 text-sm text-on-accent">Confirm suspend and revoke warrants</button>
                    <button type="button" onClick={() => setSuspending(null)} className="rounded border border-line px-3 py-1.5 text-sm">Cancel</button>
                  </span>
                ) : (
                  <button type="button" onClick={() => setSuspending(a.name)} className="rounded border border-line px-3 py-1.5 text-sm">Suspend agent</button>
                ))}
              </li>
            ))}
          </ul>
        ))}
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Tools">
          {tools.state === "ready" ? (tools.data.length === 0 ? <Empty>No tools registered.</Empty> : (
            <ul className="space-y-2 text-sm">
              {tools.data.map((t) => <li key={t.id}><span className="font-medium">{t.id}</span> <span className="text-muted">· {t.protocol} · verbs {(t.derivation ?? "declared").toLowerCase()} · {t.target_prefix}</span></li>)}
            </ul>
          )) : tools.state === "error" ? <ErrorState message={tools.error} /> : <Loading />}
        </Card>
        <Card title="Signing keys">
          {keys.state === "ready" ? (keys.data.length === 0 ? <Empty>No keys.</Empty> : (
            <ul className="space-y-2 text-sm">
              {keys.data.map((k) => <li key={k.kid} className="break-all"><span className="font-mono text-xs">{k.kid}</span> <span className="text-muted">· {k.purpose} · {k.algorithm} · {k.source === "kms" ? "Cloud KMS" : "development key"}{k.retired_at ? " · retired" : ""}</span></li>)}
            </ul>
          )) : keys.state === "error" ? <ErrorState message={keys.error} /> : <Loading />}
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Register or update a tool">
          <form onSubmit={registerTool} className="space-y-3">
            <label htmlFor="tool-json" className="block text-sm text-muted">
              Tool definition (JSON). Credentials are references such as gcp-secret://projects/…/secrets/…/versions/latest, never values.
            </label>
            <textarea id="tool-json" value={toolJson} onChange={(e) => setToolJson(e.target.value)} spellCheck={false}
                      className="h-48 w-full rounded border border-line bg-surface p-3 font-mono text-xs" />
            <button type="submit" disabled={!toolJson.trim()} className="rounded bg-accent px-4 py-2 text-sm font-medium text-on-accent disabled:opacity-50">
              Save tool
            </button>
          </form>
        </Card>
        <Card title="Register or update an agent">
          <form onSubmit={registerAgent} className="space-y-3">
            <div>
              <label htmlFor="agent-name" className="block text-sm text-muted">Name</label>
              <input id="agent-name" value={agentName} onChange={(e) => setAgentName(e.target.value)} pattern="[a-z0-9-]{2,64}" required
                     className="mt-1 w-full rounded border border-line bg-surface px-3 py-2" />
            </div>
            <div>
              <label htmlFor="agent-hash" className="block text-sm text-muted">Build hash (sha256:…) of the deployed agent artifact</label>
              <input id="agent-hash" value={agentHash} onChange={(e) => setAgentHash(e.target.value)} pattern="sha256:[0-9a-f]{64}" required
                     className="mt-1 w-full rounded border border-line bg-surface px-3 py-2 font-mono text-xs" />
            </div>
            <div>
              <label htmlFor="agent-scope" className="block text-sm text-muted">Allowed scope (comma separated, e.g. vendors.read, vendors.archive)</label>
              <input id="agent-scope" value={agentScope} onChange={(e) => setAgentScope(e.target.value)} required
                     className="mt-1 w-full rounded border border-line bg-surface px-3 py-2" />
            </div>
            <button type="submit" className="rounded border border-line px-4 py-2 text-sm font-medium">Save agent</button>
          </form>
        </Card>
      </div>

      <Card title="Tenant">
        {tenant.state === "ready" ? (
          <dl className="grid grid-cols-[12rem_1fr] gap-2 text-sm">
            <dt className="text-muted">Tenant</dt><dd>{tenant.data.name} ({tenant.data.id})</dd>
            <dt className="text-muted">Escalation timeout</dt><dd>{tenant.data.escalation_ttl_seconds ?? "—"} s · timeout means denied</dd>
            <dt className="text-muted">Fail mode</dt><dd>{tenant.data.fail_mode ?? "closed"} · changing it needs two security admins</dd>
          </dl>
        ) : tenant.state === "error" ? <ErrorState message={tenant.error} /> : <Loading />}
      </Card>
    </div>
  );
}
