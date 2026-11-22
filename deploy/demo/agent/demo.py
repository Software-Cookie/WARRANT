"""Demo orchestration (Build Specification Milestone 9).

    python demo.py setup                 register tools, the agent (build hash pinned) and the policy; idempotent
    python demo.py run --gate off        the agent holds the ERP credential and talks to it directly
    python demo.py run --gate on         the agent holds only a warrant; every call goes through the gateway
           [--approve partial|approve|deny|console]

The human roles (principal starting the task, approver deciding the card, security admin configuring Warrant) use
local development sessions. In production the same calls are made from the console with an OIDC identity.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import httpx

import vendor_hygiene
from warrant_client import AgentKey, WarrantClient

HERE = Path(__file__).resolve().parent
CP = os.environ.get("WARRANT_CONTROL_PLANE_URL", "http://control-plane:8081")
PEP = os.environ.get("WARRANT_PEP_URL", "http://pep-gateway:8080")
ERP = os.environ.get("ACME_ERP_URL", "http://acme-erp:8095")
TOKEN_FILE = Path(os.environ.get("ACME_ERP_TOKEN_FILE", "/run/secrets/acme-erp-token"))
KEY_FILE = Path(os.environ.get("WARRANT_AGENT_KEY_FILE", "/agent-keys/vendor-hygiene.key.pem"))
POLICY_FILE = Path(os.environ.get("WARRANT_POLICY_FILE", "/policies/vendors.policy"))
TOOLS_FILE = HERE / "tools.json"

PRINCIPAL = "r.menon@acme.example"
APPROVER = "r.menon@acme.example"
SECURITY_ADMIN = "priya@acme.example"
MANDATE = "clean up stale vendor records"
SCOPE = ["vendors.read", "vendors.archive"]
AGENT = "vendor-hygiene"

BOLD, DIM, RED, AMBER, GREEN, RESET = "\033[1m", "\033[2m", "\033[31m", "\033[33m", "\033[32m", "\033[0m"


def say(text: str, colour: str = "") -> None:
    print(f"{colour}{text}{RESET}" if colour else text, flush=True)


def build_hash() -> str:
    return "sha256:" + hashlib.sha256((HERE / "vendor_hygiene.py").read_bytes()).hexdigest()


class Person:
    """A signed-in human, talking to the control plane."""

    def __init__(self, email: str) -> None:
        self.email = email
        self.http = httpx.Client(base_url=CP, timeout=30.0)
        response = self.http.post("/v1/dev/session", json={"email": email})
        response.raise_for_status()
        self.http.headers["Authorization"] = "Bearer " + response.json()["token"]
        self.http.headers["X-Warrant-Tenant"] = "acme"

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        response = self.http.request(method, path, **kwargs)
        if response.status_code >= 400:
            raise SystemExit(f"{method} {path} -> {response.status_code} {response.text}")
        return response.json() if response.content else None


def wait_for(url: str, seconds: int = 120) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if httpx.get(url, timeout=2.0).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(1)
    raise SystemExit(f"{url} did not become healthy")


def setup() -> None:
    wait_for(f"{CP}/health")
    admin = Person(SECURITY_ADMIN)
    for tool in json.loads(TOOLS_FILE.read_text(encoding="utf-8")):
        admin.request("PUT", f"/v1/admin/tools/{tool['id']}", json=tool)
    admin.request("PUT", f"/v1/admin/agents/{AGENT}", json={"build_hash": build_hash(), "allowed_scope": SCOPE})
    source = POLICY_FILE.read_text(encoding="utf-8")
    active = admin.http.get("/v1/policies/active")
    if active.status_code != 200 or active.json().get("source") != source:
        published = admin.request("POST", "/v1/policies/publish", json={"source": source})
        say(f"policy published: {published['version']}")
    if not KEY_FILE.exists():
        KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
        AgentKey.generate().save(KEY_FILE)
    say(f"setup complete: agent {AGENT} pinned to {build_hash()[:19]}…", DIM)


def stats() -> dict[str, int]:
    return httpx.get(f"{ERP}/stats", timeout=10.0).json()


def show_stats(title: str) -> dict[str, int]:
    s = stats()
    say(f"{title}: {s['vendors']:,} vendors · {s['archived']:,} archived · {s['deleted']:,} deleted · "
        f"{s['payment_holds']:,} payment holds", DIM)
    return s


def run_gate_off() -> int:
    say(f"{BOLD}GATE OFF{RESET} — the agent holds the ERP credential and acts on its own judgement")
    token = TOKEN_FILE.read_text(encoding="utf-8").strip()
    erp = httpx.Client(base_url=ERP, headers={"Authorization": f"Bearer {token}"}, timeout=60.0)

    def direct(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        response = erp.post(f"/tools/{tool}", json=arguments)
        response.raise_for_status()
        return response.json()

    show_stats("before")
    report = vendor_hygiene.run(direct, lambda line: say(f"  agent: {line}", DIM))
    after = show_stats("after")
    deleted = report["delete"]["rowcount"]
    say(f"{RED}{BOLD}{deleted:,} vendor rows deleted{RESET}{RED}, including every vendor with an open invoice; "
        f"{report.get('purge_holds', {}).get('rowcount', 0):,} payment holds purged by an instruction found in data.{RESET}")
    return 0 if deleted == 1284 and after["deleted"] == 1284 else 1


def run_gate_on(approve: str) -> int:
    say(f"{BOLD}GATE ON{RESET} — the agent holds a warrant, never a credential")
    wait_for(f"{PEP}/health")
    show_stats("before")
    key = AgentKey.load(KEY_FILE)
    principal = Person(PRINCIPAL)
    issued = principal.request("POST", "/v1/warrants", json={
        "agent": AGENT, "build_hash": build_hash(), "mandate": MANDATE, "scope": SCOPE,
        "ceiling": {"rows": 250, "irreversible": False, "spend": 0}, "ttl_seconds": 900, "hops": 3, "cnf": key.cnf})
    say(f"warrant {issued['wid']} issued by {PRINCIPAL}: \"{MANDATE}\" · scope {', '.join(SCOPE)} · ceiling 250 rows",
        DIM)
    client = WarrantClient(PEP, issued["token"], key)
    outcomes: dict[str, Any] = {}

    def gated(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        result = client.call(tool, arguments)
        label = {"allow": GREEN, "deny": RED, "escalate": AMBER}.get(result.decision, "")
        detail = f" {result.reason_code}" if result.reason_code else ""
        say(f"  warrant: {result.decision.upper()}{detail} at {result.stage} — {result.explanation or 'forwarded'}", label)
        outcomes.setdefault(result.decision, []).append(result)
        if result.decision == "allow":
            return result.body
        return {"rows": [], "rowcount": 0, "decision": result.decision, "reason_code": result.reason_code,
                "escalation_id": result.escalation_id}

    vendor_hygiene.run(gated, lambda line: say(f"  agent: {line}", DIM))

    denied = [r for r in outcomes.get("deny", []) if r.reason_code == "INTENT_DRIFT"]
    escalated = outcomes.get("escalate", [])
    if not escalated:
        say("expected the bulk delete to escalate", RED)
        return 1
    escalation_id = escalated[0].escalation_id
    approver = Person(APPROVER)
    card = approver.request("GET", f"/v1/escalations/{escalation_id}")
    show_card(card)

    if approve == "console":
        say(f"open http://localhost:3000/approve/{escalation_id} and decide; waiting…", AMBER)
    else:
        action = {"partial": "approve_partial", "approve": "approve", "deny": "deny"}[approve]
        decided = approver.request("POST", f"/v1/escalations/{escalation_id}/decision",
                                   json={"action": action, "version": card["version"]})
        say(f"approver {APPROVER}: {action} → {decided['state']}", DIM)

    status = client.wait(escalation_id, timeout_s=360)
    say(f"escalation {escalation_id}: {status['state']} · release {status.get('release_state')} · "
        f"result {json.dumps(status.get('result'))}", DIM)
    after = show_stats("after")
    return 0 if outcome_matches(status.get("state"), bool(denied), after) else 1


def outcome_matches(state: str | None, injection_denied: bool, after: dict[str, int]) -> bool:
    """What the data must look like after each human decision. The injection is denied in every case."""
    expected = {
        "partial": after["archived"] == 1072 and after["deleted"] == 0 and after["payment_holds"] == 212,
        "denied": after["archived"] == 0 and after["deleted"] == 0 and after["payment_holds"] == 212,
        "timeout": after["archived"] == 0 and after["deleted"] == 0 and after["payment_holds"] == 212,
        "approved": after["deleted"] == 1284,
    }
    ok = injection_denied and expected.get(state or "", False)
    summary = {
        "partial": f"{after['archived']:,} safe vendors archived, 0 deleted, payment holds intact",
        "denied": "nothing was changed",
        "timeout": "nobody decided in time, so nothing was changed",
        "approved": f"the approver accepted the full delete of {after['deleted']:,} vendors",
    }.get(state or "", f"unexpected state {state}")
    say(f"{GREEN}{BOLD}injection dropped (INTENT_DRIFT), bulk delete escalated, {summary}{RESET}" if ok
        else f"{RED}demo expectations not met ({summary}){RESET}")
    return ok


def show_card(card: dict[str, Any]) -> None:
    body = card.get("card") or {}
    if isinstance(body, str):
        body = json.loads(body)
    say("")
    say(f"  ┌ {BOLD}{body.get('headline', '')}{RESET}", AMBER)
    say(f"  │ {body.get('risk', '')}")
    for line in body.get("strip", []) or []:
        say(f"  │ · {line}", DIM)
    provenance = body.get("provenance") or {}
    if provenance:
        say(f"  │ asked by {provenance.get('on_behalf_of')}: \"{provenance.get('mandate')}\" · policy {provenance.get('policy_v')}",
            DIM)
    alternative = body.get("alternative") or {}
    if alternative:
        say(f"  │ safe alternative: {alternative.get('label')}")
    say(f"  └ expires {card.get('expires_at')}", DIM)
    say("")


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("setup")
    run = sub.add_parser("run")
    run.add_argument("--gate", choices=["on", "off"], required=True)
    run.add_argument("--approve", choices=["partial", "approve", "deny", "console"], default="partial")
    args = parser.parse_args()
    if args.command == "setup":
        setup()
        return 0
    return run_gate_off() if args.gate == "off" else run_gate_on(args.approve)


if __name__ == "__main__":
    sys.exit(main())
