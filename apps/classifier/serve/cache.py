"""Bounded LRU with expiry for semantic verdicts. Stores judgements only, never arguments."""
from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass


@dataclass(frozen=True)
class CachedVerdict:
    irreversible: bool
    protected_classes: tuple[str, ...]
    drift_score: float
    confidence: float
    rationale: str
    model_version: str


class SemanticCache:
    def __init__(self, capacity: int, ttl_seconds: int) -> None:
        self._capacity = capacity
        self._ttl = ttl_seconds
        self._entries: OrderedDict[str, tuple[float, CachedVerdict]] = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> CachedVerdict | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None or entry[0] < time.monotonic():
                self._entries.pop(key, None)
                self.misses += 1
                return None
            self._entries.move_to_end(key)
            self.hits += 1
            return entry[1]

    def put(self, key: str, verdict: CachedVerdict) -> None:
        with self._lock:
            self._entries[key] = (time.monotonic() + self._ttl, verdict)
            self._entries.move_to_end(key)
            while len(self._entries) > self._capacity:
                self._entries.popitem(last=False)
