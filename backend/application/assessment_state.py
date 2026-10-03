"""Assessment lifecycle state machine."""
from __future__ import annotations

from enum import StrEnum


class AssessmentState(StrEnum):
    CREATED = "CREATED"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    COMPLETED_WITH_WARNINGS = "COMPLETED_WITH_WARNINGS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


TRANSITIONS = {
    AssessmentState.CREATED: {AssessmentState.QUEUED, AssessmentState.CANCELLED},
    AssessmentState.QUEUED: {AssessmentState.RUNNING, AssessmentState.CANCELLED, AssessmentState.FAILED},
    AssessmentState.RUNNING: {AssessmentState.COMPLETED, AssessmentState.COMPLETED_WITH_WARNINGS,
                              AssessmentState.FAILED, AssessmentState.CANCELLED},
    AssessmentState.COMPLETED: set(),
    AssessmentState.COMPLETED_WITH_WARNINGS: set(),
    AssessmentState.FAILED: set(),
    AssessmentState.CANCELLED: set(),
}


def transition(current: str, target: AssessmentState) -> str:
    try:
        state = AssessmentState(str(current).upper())
    except ValueError as exc:
        raise ValueError(f"Unknown assessment lifecycle state: {current}") from exc
    if target not in TRANSITIONS[state]:
        raise ValueError(f"Invalid assessment state transition: {state.value} → {target.value}")
    return target.value
