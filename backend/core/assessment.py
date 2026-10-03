"""Assessment record persisted by the local desktop workflow."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Assessment:
    assessment_id: str = field(default_factory=lambda: f"TRACER-{uuid4().hex[:12].upper()}")
    name: str = ""
    description: str = ""
    analyst: str = ""
    reference_id: str | None = None
    status: str = "draft"
    created_at: str = field(default_factory=utc_now)
    started_at: str | None = None
    completed_at: str | None = None
    duration_seconds: float | None = None
    results_path: str | None = None
    dataset: dict[str, Any] = field(default_factory=dict)
    reference_dataset: dict[str, Any] | None = None
    model: dict[str, Any] = field(default_factory=dict)
    configuration: dict[str, Any] = field(default_factory=dict)
    compute: dict[str, Any] = field(default_factory=dict)
    engines: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    report: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    technical_error: str | None = None
    lifecycle_events: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
