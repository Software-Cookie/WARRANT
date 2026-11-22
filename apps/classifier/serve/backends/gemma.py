"""Hot-path model: Gemma 3 instruction-tuned, self-hosted inside the customer boundary behind an OpenAI-compatible
endpoint (vLLM, Ollama or TGI). Two fixed, versioned prompts score blast radius and intent drift; the call is passed
as delimited data. Output that does not parse or validate is a failure and becomes a low-confidence result."""
from __future__ import annotations

from typing import Any

import httpx

from ..models import ClassificationResult, ScoreRequest
from ..prompting import data_block, parse_json_object, score_payload
from ..settings import Settings, prompt


class ModelFailure(Exception):
    pass


class GemmaBackend:
    def __init__(self, settings: Settings, client: httpx.Client | None = None) -> None:
        if not settings.gemma_endpoint:
            raise ValueError("WARRANT_GEMMA_ENDPOINT is required for the gemma backend")
        self._settings = settings
        self._client = client or httpx.Client(timeout=httpx.Timeout(0.4, connect=0.2))
        self._blast_version, self._blast_prompt = prompt("blast_radius.v1")
        self._drift_version, self._drift_prompt = prompt("intent_drift.v1")

    @property
    def version(self) -> str:
        return f"{self._settings.gemma_model};prompts={self._blast_version},{self._drift_version}"

    def score(self, request: ScoreRequest) -> ClassificationResult:
        try:
            data = data_block(score_payload(request))
            blast = self._complete(self._blast_prompt, data)
            drift = self._complete(self._drift_prompt, data)
            rows = request.impact.estimated_rows if request.impact.available else int(blast["rows_affected"])
            measured = sorted(k for k, v in request.impact.protected.items() if v > 0)
            reported = [str(c) for c in blast.get("protected_classes", []) if isinstance(c, str)]
            return ClassificationResult(
                rows_affected=max(0, int(blast["rows_affected"])) if not request.impact.available else rows,
                irreversible=bool(blast["irreversible"]),
                protected_classes=sorted(set(measured) | set(reported)),
                drift_score=float(drift["drift_score"]),
                confidence=min(float(blast["confidence"]), float(drift["confidence"])),
                rationale=str(blast.get("rationale", ""))[:500],
                model_version=self.version,
            )
        except (ModelFailure, KeyError, TypeError, ValueError, httpx.HTTPError):
            return low_confidence(request, self.version)

    def _complete(self, system: str, data: str) -> dict[str, Any]:
        response = self._client.post(f"{self._settings.gemma_endpoint.rstrip('/')}/v1/chat/completions", json={
            "model": self._settings.gemma_model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": data}],
        })
        if response.status_code != 200:
            raise ModelFailure(f"model endpoint responded {response.status_code}")
        try:
            content = response.json()["choices"][0]["message"]["content"]
        except (KeyError, IndexError, ValueError) as error:
            raise ModelFailure("unexpected completion envelope") from error
        return parse_json_object(content)


def low_confidence(request: ScoreRequest, version: str) -> ClassificationResult:
    rows = request.impact.estimated_rows if request.impact.available else 0
    return ClassificationResult(rows_affected=rows, irreversible=True, protected_classes=[], drift_score=0.5,
                                confidence=0.0, rationale="The model output could not be validated; a human decides.",
                                model_version=version)
