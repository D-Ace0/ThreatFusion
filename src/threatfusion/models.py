from datetime import UTC, datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


def utcnow() -> datetime:
    return datetime.now(UTC)


class IOCType(str, Enum):
    ipv4 = "ipv4"
    ipv6 = "ipv6"
    domain = "domain"
    url = "url"
    md5 = "md5"
    sha1 = "sha1"
    sha256 = "sha256"


class IOC(BaseModel):
    value: str
    type: IOCType
    public: bool = True


class Evidence(BaseModel):
    model_config = ConfigDict(allow_inf_nan=False)
    source: str
    metric: Literal["detections", "abuse_confidence", "pulse_count"]
    value: float = Field(ge=0)
    total: int | None = Field(default=None, ge=0)
    description: str
    source_url: str
    retrieved_at: datetime = Field(default_factory=utcnow)
    observed_at: datetime | None = None

    @field_validator("retrieved_at", "observed_at")
    @classmethod
    def aware_timestamps(cls, value):
        if value is not None and value.tzinfo is None:
            raise ValueError("Evidence timestamps must include a timezone")
        return value


class ProviderResult(BaseModel):
    source: str
    status: Literal[
        "ok", "not_found", "unsupported", "unconfigured", "blocked", "rate_limited", "error"
    ]
    retrieved_at: datetime = Field(default_factory=utcnow)
    evidence: list[Evidence] = Field(default_factory=list)
    message: str = ""
    attempts: int = 0
    retry_after: float | None = None
    cached: bool = False


class Contribution(BaseModel):
    source: str
    points: float
    reason: str


class Score(BaseModel):
    risk: int | None
    label: str
    confidence: int
    coverage: int
    freshness: int
    contributions: list[Contribution]
    methodology: str = "heuristic-v1; unvalidated triage aid, not a probability or verdict"


class Analysis(BaseModel):
    id: str
    ioc: IOC
    mode: Literal["demo", "live"]
    created_at: datetime = Field(default_factory=utcnow)
    results: list[ProviderResult]
    score: Score
