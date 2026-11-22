"""Local stub: returns the labelled verdicts recorded in eval/corpus.jsonl, matched on the normalised call shape, so
the whole system runs without a model. Unknown calls get low confidence, which escalates."""
from __future__ import annotations

import json
from pathlib import Path

from ..models import ClassificationResult, ScoreRequest
from ..normalize import shape

VERSION = "fixture-v1"
CORPUS = Path(__file__).resolve().parent.parent.parent / "eval" / "corpus.jsonl"


def _key(tool: str, verb: str, mandate: str, arguments: dict) -> str:
    return json.dumps([tool, verb, mandate.lower(), shape(arguments)], sort_keys=True)


def _load() -> dict[str, dict]:
    table: dict[str, dict] = {}
    if not CORPUS.exists():
        return table
    for line in CORPUS.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        case = json.loads(line)
        request = case["request"]
        table[_key(request["tool"]["id"], request["tool"]["verb"], request["warrant"]["mandate"],
                   request["arguments"])] = case["expected_scores"]
    return table


_TABLE = _load()


def score(request: ScoreRequest) -> ClassificationResult:
    r = request.request
    expected = _TABLE.get(_key(r.tool.id, r.tool.verb, r.warrant.mandate, r.arguments))
    rows = request.impact.estimated_rows if request.impact.available else 0
    if expected is None:
        return ClassificationResult(rows_affected=rows, irreversible=True, protected_classes=[], drift_score=0.5,
                                    confidence=0.0, rationale="No fixture matches this call; a human must decide.",
                                    model_version=VERSION)
    return ClassificationResult(rows_affected=rows, irreversible=expected["irreversible"],
                                protected_classes=sorted(k for k, v in request.impact.protected.items() if v > 0),
                                drift_score=expected["drift_score"], confidence=expected["confidence"],
                                rationale=expected["rationale"], model_version=VERSION)
