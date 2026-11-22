"""Configuration from environment variables. No secret is read here: model endpoints are authenticated with the
workload's own identity (metadata server) in Google Cloud."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"


@dataclass(frozen=True)
class Settings:
    backend: str
    batch_ms: int
    max_batch: int
    cache_size: int
    cache_ttl_seconds: int
    gemma_endpoint: str
    gemma_model: str
    gemini_project: str
    gemini_location: str
    gemini_flash_model: str
    card_backend: str
    max_body_bytes: int

    @staticmethod
    def from_env() -> "Settings":
        return Settings(
            backend=os.getenv("WARRANT_CLASSIFIER_BACKEND", "heuristic"),
            batch_ms=int(os.getenv("WARRANT_CLASSIFIER_BATCH_MS", "") or 20),
            max_batch=int(os.getenv("WARRANT_CLASSIFIER_MAX_BATCH", "") or 16),
            cache_size=int(os.getenv("WARRANT_CLASSIFIER_CACHE_SIZE", "") or 10_000),
            cache_ttl_seconds=int(os.getenv("WARRANT_CLASSIFIER_CACHE_TTL", "") or 3600),
            gemma_endpoint=os.getenv("WARRANT_GEMMA_ENDPOINT", ""),
            gemma_model=os.getenv("WARRANT_GEMMA_MODEL", "") or "gemma-3-4b-it",
            gemini_project=os.getenv("WARRANT_GEMINI_PROJECT", ""),
            gemini_location=os.getenv("WARRANT_GEMINI_LOCATION", "") or "asia-south1",
            gemini_flash_model=os.getenv("WARRANT_GEMINI_FLASH_MODEL", "") or "gemini-2.5-flash",
            card_backend=os.getenv("WARRANT_CARD_BACKEND", "template"),
            max_body_bytes=int(os.getenv("WARRANT_CLASSIFIER_MAX_BODY", "") or 262_144),
        )


def prompt(name: str) -> tuple[str, str]:
    """Returns (version, text). The version is the file name without extension, e.g. ``blast_radius.v1``."""
    path = PROMPTS_DIR / f"{name}.txt"
    return path.stem, path.read_text(encoding="utf-8")
