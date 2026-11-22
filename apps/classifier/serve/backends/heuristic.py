"""Deterministic scorer used locally and as the model-killed fallback.

It never sees the model and never makes a decision on its own: it produces the §5.3 scores from the request, the
target's dry run and the mandate, and the gateway combines them under the strictness rule.
"""
from __future__ import annotations

import re

from ..models import ClassificationResult, ScoreRequest

VERSION = "heuristic-v1"
IRREVERSIBLE_VERBS = {"delete", "truncate", "drop", "purge", "send", "admin", "unknown", "pay", "transfer"}
READ_VERBS = {"select", "read", "get", "list", "search", "head"}
READ_ONLY_MANDATE_WORDS = {"summarise", "summarize", "summary", "report", "review", "read", "list", "analyse",
                           "analyze", "check", "look", "find", "show", "count", "audit"}
STOP_WORDS = {"the", "a", "an", "of", "and", "or", "to", "for", "our", "my", "all", "up", "with", "in", "on", "that",
              "this", "these", "those", "please", "stale", "old", "records", "record", "data", "clean", "cleanup"}
_WORD = re.compile(r"[a-z0-9]+")
_TABLE = re.compile(r"\b(?:from|join|update|into|table)\s+(?:only\s+)?([a-z_][a-z0-9_.]*)", re.IGNORECASE)


def stem(word: str) -> str:
    for suffix in ("ings", "ing", "ies", "es", "s", "ed"):
        if len(word) > len(suffix) + 2 and word.endswith(suffix):
            return word[: -len(suffix)] + ("y" if suffix == "ies" else "")
    return word


def words(text: str) -> set[str]:
    return {stem(w) for w in _WORD.findall(text.lower()) if w not in STOP_WORDS}


def _parts(name: str) -> set[str]:
    return {stem(part) for part in re.split(r"[_\-.]", name.lower()) if part}


def touched_resources(request: ScoreRequest) -> set[str]:
    """Targets are ``<system>:<resource>``; the system prefix says nothing about intent, so only the resource and the
    tables named in the call count."""
    resources = _parts(request.request.tool.target.rsplit(":", 1)[-1])
    for value in request.request.arguments.values():
        if isinstance(value, str):
            for table in _TABLE.findall(value):
                resources |= _parts(table.split(".")[-1])
    return {r for r in resources if r not in STOP_WORDS}


def drift(request: ScoreRequest) -> tuple[float, str]:
    mandate_words = words(request.request.warrant.mandate)
    resources = touched_resources(request)
    verb = request.request.tool.verb
    if not resources:
        return 0.5, "the call names no resource that can be related to the mandate"
    unrelated = {r for r in resources if r not in mandate_words}
    if mandate_words & READ_ONLY_MANDATE_WORDS and verb not in READ_VERBS:
        return 0.8, "the mandate asks only to read, but this call changes data"
    if not unrelated:
        return 0.08, "the call stays within the resources the mandate names"
    named = ", ".join(sorted(unrelated))
    if verb in READ_VERBS:
        if len(unrelated) < len(resources):
            return 0.2, f"the call reads the mandate's records together with related {named}"
        return 0.5, f"the call reads only {named}, which the mandate does not mention"
    return min(0.95, 0.55 + 0.2 * len(unrelated)), f"the call changes {named}, which the mandate does not mention"


def score(request: ScoreRequest) -> ClassificationResult:
    tool = request.request.tool
    impact = request.impact
    irreversible = tool.verb in IRREVERSIBLE_VERBS
    rows = impact.estimated_rows if impact.available else 0
    protected = sorted(name for name, count in impact.protected.items() if count > 0)
    drift_score, why = drift(request)
    # A write whose blast radius the target could not measure is not something to be confident about.
    confidence = 0.92 if impact.available or tool.verb in READ_VERBS else 0.55
    if tool.verb == "unknown":
        confidence = 0.5
    consequence = ("permanently " if irreversible else "") + tool.verb
    rationale = f"{consequence.capitalize()} affecting {rows:,} record(s) of {tool.target}; {why}."
    if protected:
        rationale = rationale[:-1] + f"; includes protected records ({', '.join(protected)})."
    return ClassificationResult(rows_affected=max(0, rows), irreversible=irreversible, protected_classes=protected,
                                drift_score=round(drift_score, 2), confidence=confidence, rationale=rationale[:500],
                                model_version=VERSION)
