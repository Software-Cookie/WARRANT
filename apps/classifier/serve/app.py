"""Warrant classifier service (L2). Stateless; scales horizontally on queue depth."""
from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .backends import fixture, heuristic
from .batching import MicroBatcher
from .cache import CachedVerdict, SemanticCache
from .cards import CardWriter
from .models import CardDraft, CardRequest, ClassificationResult, ScoreRequest
from .normalize import cache_key
from .settings import Settings

LOG = logging.getLogger("warrant.classifier")
PROMPT_VERSIONS = "blast_radius.v1,intent_drift.v1"


def build_scorer(settings: Settings) -> Callable[[ScoreRequest], ClassificationResult]:
    if settings.backend == "gemma":
        from .backends.gemma import GemmaBackend
        return GemmaBackend(settings).score
    if settings.backend == "fixture":
        return fixture.score
    if settings.backend == "heuristic":
        return heuristic.score
    raise ValueError(f"unknown WARRANT_CLASSIFIER_BACKEND {settings.backend!r}")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    scorer = build_scorer(settings)
    cache = SemanticCache(settings.cache_size, settings.cache_ttl_seconds)
    cards = CardWriter(settings)

    def score_batch(requests: Sequence[ScoreRequest]) -> list[ClassificationResult]:
        return [score_one(r) for r in requests]

    def score_one(request: ScoreRequest) -> ClassificationResult:
        r = request.request
        protected_present = sorted(k for k, v in request.impact.protected.items() if v > 0)
        key = cache_key(r.tool.id, r.tool.verb, r.tool.target, r.warrant.mandate, r.arguments, protected_present)
        rows = request.impact.estimated_rows if request.impact.available else None
        cached = cache.get(key)
        if cached is not None and rows is not None:
            return ClassificationResult(rows_affected=rows, irreversible=cached.irreversible,
                                        protected_classes=list(cached.protected_classes), drift_score=cached.drift_score,
                                        confidence=cached.confidence, rationale=cached.rationale,
                                        model_version=cached.model_version)
        result = scorer(request)
        versioned = result.model_copy(update={"model_version": _with_prompts(result.model_version)})
        if versioned.confidence > 0:
            cache.put(key, CachedVerdict(versioned.irreversible, tuple(versioned.protected_classes),
                                         versioned.drift_score, versioned.confidence, versioned.rationale,
                                         versioned.model_version))
        return versioned

    batcher: MicroBatcher[ScoreRequest, ClassificationResult] = MicroBatcher(score_batch, settings.batch_ms,
                                                                             settings.max_batch)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        batcher.start()
        yield
        await batcher.stop()

    app = FastAPI(title="warrant-classifier", version="1.0.0", lifespan=lifespan, docs_url=None, redoc_url=None,
                  openapi_url=None)
    app.state.cache = cache
    app.state.batcher = batcher

    @app.middleware("http")
    async def limit_body(request: Request, call_next):  # type: ignore[no-untyped-def]
        length = request.headers.get("content-length")
        if length is not None and int(length) > settings.max_body_bytes:
            return JSONResponse(status_code=413, content={"error": "payload_too_large"})
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "up", "service": "classifier", "version": "1.0.0", "backend": settings.backend}

    @app.post("/score", response_model=ClassificationResult)
    async def score(body: ScoreRequest) -> ClassificationResult:
        LOG.info("score request_id=%s tool=%s verb=%s arg_digest=%s", body.request.request_id, body.request.tool.id,
                 body.request.tool.verb, body.request.arg_digest)
        return await batcher.submit(body)

    @app.post("/card", response_model=CardDraft)
    async def card(body: CardRequest) -> CardDraft:
        return cards.write(body)

    return app


def _with_prompts(model_version: str) -> str:
    return model_version if "prompts=" in model_version else f"{model_version};prompts={PROMPT_VERSIONS}"


app = create_app()
