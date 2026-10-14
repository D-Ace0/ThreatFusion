from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from .models import IOC, Analysis, utcnow

Disposition = Literal["unreviewed", "investigate", "expected", "escalate"]


class Observation(BaseModel):
    line: int
    excerpt: str
    tags: list[str] = Field(default_factory=list)


class CaseIndicator(BaseModel):
    id: str
    ioc: IOC
    occurrences: int = 0
    observations: list[Observation] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    analysis: Analysis | None = None
    disposition: Disposition = "unreviewed"
    note: str = ""
    priority: Literal["high", "review", "context"] = "context"
    reasons: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)


class Relationship(BaseModel):
    source: str
    target: str
    kind: Literal["same_line", "url_host"]
    count: int
    lines: list[int]


class AuditEntry(BaseModel):
    at: datetime = Field(default_factory=utcnow)
    action: str
    detail: str


class Case(BaseModel):
    id: str
    title: str
    source_name: str
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    synthetic: bool = False
    line_count: int
    input_sha256: str
    indicators: list[CaseIndicator]
    relationships: list[Relationship]
    warnings: list[str] = Field(default_factory=list)
    audit: list[AuditEntry] = Field(default_factory=list)


class EnrichmentJob(BaseModel):
    id: str
    case_id: str
    mode: Literal["demo", "live"]
    status: Literal["queued", "running", "completed", "cancelled", "interrupted", "failed"] = (
        "queued"
    )
    total: int
    completed: int = 0
    skipped: int = 0
    message: str = ""
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
