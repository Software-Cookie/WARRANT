"""Wire contracts. ClassificationResult is frozen contract §5.3; anything that fails validation is a failure."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Ceiling(BaseModel):
    model_config = ConfigDict(extra="ignore")
    rows: int = 0
    irreversible: bool = False
    spend: int = 0


class WarrantClaims(BaseModel):
    model_config = ConfigDict(extra="ignore")
    wid: str
    tenant: str
    principal: str
    agent: str
    mandate: str = Field(max_length=2000)
    scope: list[str]
    ceiling: Ceiling


class ToolRef(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(max_length=128)
    verb: str = Field(max_length=32)
    target: str = Field(max_length=256)
    protocol: str = Field(max_length=16)


class ActionRequest(BaseModel):
    """§5.1. ``arguments`` are attacker-controlled; they are only ever placed inside a DATA block."""

    model_config = ConfigDict(extra="ignore")
    request_id: str
    warrant: WarrantClaims
    tool: ToolRef
    arguments: dict[str, Any]
    arg_digest: str
    hop: int = 0


class ImpactEstimate(BaseModel):
    model_config = ConfigDict(extra="ignore")
    available: bool = False
    estimated_rows: int = 0
    protected: dict[str, int] = Field(default_factory=dict)


class ScoreRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request: ActionRequest
    impact: ImpactEstimate = Field(default_factory=ImpactEstimate)


class ClassificationResult(BaseModel):
    """Frozen contract §5.3."""

    model_config = ConfigDict(extra="forbid")
    rows_affected: int = Field(ge=0)
    irreversible: bool
    protected_classes: list[str]
    drift_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(max_length=500)
    model_version: str = Field(max_length=200)


class CardDraft(BaseModel):
    model_config = ConfigDict(extra="ignore")
    headline: str = Field(max_length=200)
    risk: str = Field(max_length=600)


class CardRequest(BaseModel):
    """Metadata and counts only. Tool-call arguments are never sent for card wording."""

    model_config = ConfigDict(extra="forbid")
    verb: str
    resource: str
    rows: int | None = None
    irreversible: bool
    protected: dict[str, int] = Field(default_factory=dict)
    mandate: str = Field(max_length=2000)
    ceiling_rows: int
    draft: CardDraft
