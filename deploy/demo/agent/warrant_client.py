"""Minimal Python client for the Warrant gateway — the same protocol as packages/sdk-java.

Every call carries the warrant chain (X-Warrant) and a fresh Ed25519 proof of possession (X-Warrant-Proof) over
the warrant id, a single-use request id, the request time, the tool and the SHA-256 of the canonical arguments.
The agent never holds a target credential; the gateway injects it after the decision.

    client = WarrantClient("http://pep-gateway:8080", warrant_token, AgentKey.load("agent.key.pem"))
    result = client.call("sql.execute", {"q": "SELECT id FROM vendors"})
    if result.decision == "escalate":
        status = client.wait(result.escalation_id, timeout_s=300)
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PROOF_DOMAIN = b"warrant-proof/v1\n"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def canonical_json(value: Any) -> str:
    """Byte-identical to io.warrant.core.json.CanonicalJson: keys in UTF-16 order, no whitespace, no floats."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        raise ValueError("binary floating point is not canonicalizable; pass a Decimal or a string")
    if isinstance(value, Decimal):
        text = format(value.normalize(), "f")
        return text[:-2] if text.endswith(".0") else text
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_string(k) + ":" + canonical_json(value[k]) for k in keys) + "}"
    raise TypeError(f"unsupported type for canonical JSON: {type(value).__name__}")


_SHORT = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _string(text: str) -> str:
    out = ['"']
    for ch in text:
        if ch in _SHORT:
            out.append(_SHORT[ch])
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def arg_digest(arguments: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(arguments).encode("utf-8")).hexdigest()


class AgentKey:
    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._key = private_key

    @staticmethod
    def generate() -> "AgentKey":
        return AgentKey(Ed25519PrivateKey.generate())

    @staticmethod
    def load(path: str | Path) -> "AgentKey":
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("agent key must be Ed25519")
        return AgentKey(key)

    def save(self, path: str | Path) -> None:
        target = Path(path)
        target.write_bytes(self._key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
        target.chmod(0o600)

    @property
    def cnf(self) -> str:
        raw = self._key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return b64url(raw)

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)

    def __repr__(self) -> str:
        return f"AgentKey(cnf={self.cnf})"


@dataclass(frozen=True)
class Result:
    decision: str
    status: int
    reason_code: str | None = None
    stage: str | None = None
    explanation: str | None = None
    escalation_id: str | None = None
    body: Any = None


def leaf_claims(warrant_chain: str) -> dict[str, Any]:
    leaf = warrant_chain.split("~")[-1]
    prefix, claims, _signature = leaf.split(".")
    if prefix != "wt1":
        raise ValueError("not a wt1 warrant")
    return json.loads(b64url_decode(claims))


class WarrantClient:
    def __init__(self, gateway: str, warrant_chain: str, key: AgentKey, timeout_s: float = 15.0) -> None:
        self._gateway = gateway.rstrip("/")
        self._warrant = warrant_chain
        self._wid = leaf_claims(warrant_chain)["wid"]
        self._key = key
        self._http = httpx.Client(timeout=timeout_s)

    def _headers(self, operation: str, arguments: dict[str, Any]) -> dict[str, str]:
        request_id = "req_" + secrets.token_hex(12)
        ts = datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
        payload = {"arg_digest": arg_digest(arguments), "request_id": request_id, "tool": operation, "ts": ts,
                   "wid": self._wid}
        proof = "v1." + b64url(self._key.sign(PROOF_DOMAIN + canonical_json(payload).encode("utf-8")))
        return {"X-Warrant": self._warrant, "X-Request-Id": request_id, "X-Request-Time": ts,
                "X-Warrant-Proof": proof}

    def call(self, tool: str, arguments: dict[str, Any], hold_s: int = 0) -> Result:
        headers = self._headers(tool, arguments)
        if hold_s:
            headers["Prefer"] = f"wait={hold_s}"
        response = self._http.post(f"{self._gateway}/v1/proxy/{tool}", headers=headers, json={"arguments": arguments},
                                   timeout=15.0 + hold_s)
        body = response.json() if response.content else {}
        if response.headers.get("X-Warrant-Decision") == "allow":
            return Result("allow", response.status_code, stage=response.headers.get("X-Warrant-Stage"), body=body)
        return Result(body.get("decision", "error"), response.status_code, body.get("reason_code"), body.get("stage"),
                      body.get("explanation"), body.get("escalation_id"), body)

    def escalation(self, escalation_id: str) -> dict[str, Any]:
        arguments = {"escalation_id": escalation_id}
        response = self._http.get(f"{self._gateway}/v1/escalations/{escalation_id}",
                                  headers=self._headers("warrant.escalation.poll", arguments))
        response.raise_for_status()
        return response.json()

    def wait(self, escalation_id: str, timeout_s: float = 300.0) -> dict[str, Any]:
        """Polls until the escalation settles. A gateway restart or network blip is retried until the deadline: the
        parked request lives in the control plane's database, not in the gateway, so it survives."""
        deadline = time.monotonic() + timeout_s
        pause = 0.5
        status: dict[str, Any] = {"id": escalation_id, "state": "pending", "release_state": "none"}
        while True:
            try:
                status = self.escalation(escalation_id)
            except (httpx.TransportError, httpx.HTTPStatusError):
                if time.monotonic() > deadline:
                    return status
                time.sleep(pause)
                pause = min(pause * 2, 3.0)
                continue
            state, release = status.get("state"), status.get("release_state")
            approved = state in ("approved", "partial")
            if (state != "pending" and (not approved or release in ("released", "failed"))) \
                    or time.monotonic() > deadline:
                return status
            time.sleep(pause)
            pause = min(pause * 2, 3.0)
