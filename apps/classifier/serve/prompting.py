"""Prompt assembly with injection isolation: instructions come only from versioned prompt files; the call is
inserted as delimited DATA with the delimiters neutralised inside it, and model output is parsed and validated."""
from __future__ import annotations

import json
from typing import Any

from .models import ScoreRequest

OPEN = "<<<DATA"
CLOSE = "DATA>>>"


def neutralise(text: str) -> str:
    """Breaks any delimiter the data itself contains, so data cannot close its own block."""
    return text.replace("<<<", "< < <").replace(">>>", "> > >")


def data_block(payload: dict[str, Any]) -> str:
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return f"{OPEN}\n{neutralise(serialized)}\n{CLOSE}"


def score_payload(request: ScoreRequest) -> dict[str, Any]:
    r = request.request
    return {
        "mandate": r.warrant.mandate,
        "tool": r.tool.id,
        "verb": r.tool.verb,
        "target": r.tool.target,
        "arguments": r.arguments,
        "dry_run": request.impact.model_dump(),
        "ceiling": r.warrant.ceiling.model_dump(),
    }


def parse_json_object(text: str) -> dict[str, Any]:
    """Model output must be exactly one JSON object; anything else is a failure, never an instruction."""
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.strip("`")
        stripped = stripped[stripped.find("{"):] if "{" in stripped else stripped
    value = json.loads(stripped)
    if not isinstance(value, dict):
        raise ValueError("model output is not a JSON object")
    return value
