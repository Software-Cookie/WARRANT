"""Pre-signs N single-use /v1/authorize requests for the k6 L1-path test (proofs cannot be reused).

    python load/presign.py 30000 > load/requests.json
Needs WARRANT_TOKEN (a warrant chain) and WARRANT_AGENT_KEY_FILE (the agent's PEM key) in the environment.
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "deploy" / "demo" / "agent"))
from warrant_client import AgentKey, WarrantClient  # noqa: E402

count = int(sys.argv[1]) if len(sys.argv) > 1 else 10000
client = WarrantClient("http://unused", os.environ["WARRANT_TOKEN"], AgentKey.load(os.environ["WARRANT_AGENT_KEY_FILE"]))
arguments = {"q": "SELECT id, name FROM vendors WHERE id = 7"}
out = []
for _ in range(count):
    headers = client._headers("sql.execute", arguments)  # noqa: SLF001 - deliberate: signing without sending
    headers["Content-Type"] = "application/json"
    out.append({"headers": headers, "body": json.dumps({"tool": {"id": "sql.execute"}, "arguments": arguments})})
json.dump(out, sys.stdout)
