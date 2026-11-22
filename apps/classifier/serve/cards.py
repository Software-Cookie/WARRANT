"""Approval-card wording. Gemini Flash (Vertex AI) rewrites the deterministic draft for readability when configured;
its output is kept only if it validates and still states the real number. Only metadata and counts are sent."""
from __future__ import annotations

import os
import time

import httpx

from .models import CardDraft, CardRequest
from .prompting import data_block, parse_json_object
from .settings import Settings, prompt

METADATA_TOKEN_URL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"


class CardWriter:
    def __init__(self, settings: Settings, client: httpx.Client | None = None) -> None:
        self._settings = settings
        self._client = client or httpx.Client(timeout=httpx.Timeout(1.5, connect=0.3))
        self._version, self._prompt = prompt("card.v1")
        self._token: tuple[str, float] | None = None

    def write(self, request: CardRequest) -> CardDraft:
        if self._settings.card_backend != "gemini" or not self._settings.gemini_project:
            return request.draft
        try:
            candidate = self._gemini(request)
        except (httpx.HTTPError, KeyError, IndexError, ValueError):
            return request.draft
        if request.rows is not None and f"{request.rows:,}" not in candidate.headline:
            return request.draft
        return candidate

    def _gemini(self, request: CardRequest) -> CardDraft:
        s = self._settings
        url = (f"https://{s.gemini_location}-aiplatform.googleapis.com/v1/projects/{s.gemini_project}/locations/"
               f"{s.gemini_location}/publishers/google/models/{s.gemini_flash_model}:generateContent")
        facts = request.model_dump()
        response = self._client.post(url, headers={"Authorization": f"Bearer {self._access_token()}"}, json={
            "systemInstruction": {"parts": [{"text": self._prompt}]},
            "contents": [{"role": "user", "parts": [{"text": data_block(facts)}]}],
            "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json", "maxOutputTokens": 256},
        })
        response.raise_for_status()
        text = response.json()["candidates"][0]["content"]["parts"][0]["text"]
        return CardDraft.model_validate(parse_json_object(text))

    def _access_token(self) -> str:
        if self._token and self._token[1] > time.time():
            return self._token[0]
        host = os.getenv("GCE_METADATA_HOST")
        url = METADATA_TOKEN_URL if not host else f"http://{host}/computeMetadata/v1/instance/service-accounts/default/token"
        body = self._client.get(url, headers={"Metadata-Flavor": "Google"}).json()
        self._token = (body["access_token"], time.time() + int(body["expires_in"]) - 60)
        return self._token[0]
