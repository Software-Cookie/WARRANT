"""Normalised argument shape for the semantic cache: literals are replaced by placeholders so that two calls that
differ only in a date, a number or a string literal share one verdict."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

_SQL_STRING = re.compile(r"'(?:[^']|'')*'")
_SQL_NUMBER = re.compile(r"\b\d+(?:\.\d+)?\b")
_WHITESPACE = re.compile(r"\s+")


def normalize_sql(sql: str) -> str:
    shape = _SQL_STRING.sub("?", sql)
    shape = _SQL_NUMBER.sub("?", shape)
    return _WHITESPACE.sub(" ", shape).strip().lower()


def shape(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: shape(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return ["[]" if not value else shape(value[0]), "len>0" if value else "len=0"]
    if isinstance(value, str):
        looks_like_sql = re.match(r"\s*(select|insert|update|delete|with|truncate|drop)\b", value, re.IGNORECASE)
        return normalize_sql(value) if looks_like_sql else "?"
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return "?"
    return None


def cache_key(tool: str, verb: str, target: str, mandate: str, arguments: dict[str, Any],
              protected_present: list[str]) -> str:
    material = json.dumps({
        "tool": tool,
        "verb": verb,
        "target": target,
        "mandate": hashlib.sha256(mandate.encode("utf-8")).hexdigest(),
        "shape": shape(arguments),
        "protected": sorted(protected_present),
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
