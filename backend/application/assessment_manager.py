"""Local assessment lifecycle manager backed by existing stores and engines."""
from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from threading import RLock
from time import monotonic
from typing import Any, Callable

from backend.application.assessment_state import AssessmentState, transition
from backend.application.execution_context import ExecutionContext
from backend.core.assessment import Assessment, utc_now
from backend.core.assessment_runner import run_assessment


class AssessmentManager:
    def __init__(self, *, config: Any, assessment_store: Any, evidence_store: Any = None,
                 runner: Callable[..., Assessment] = run_assessment) -> None:
        self.config = config
        self.assessment_store = assessment_store
        self.evidence_store = evidence_store
        self.runner = runner
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="tracer-assessment")
        self._lock = RLock()
        self._contexts: dict[str, ExecutionContext] = {}
        self._futures: dict[str, Future] = {}

    def create(self, assessment: Assessment) -> Assessment:
        if not assessment.name.strip():
            raise ValueError("Assessment name is required")
        if not assessment.dataset.get("path") or not assessment.model.get("path"):
            raise ValueError("A local dataset and model are required")
        assessment.status = AssessmentState.CREATED.value
        assessment.engines = assessment.engines or {}
        assessment.lifecycle_events.append({"event_type":"ASSESSMENT_CREATED","timestamp":assessment.created_at})
        self.assessment_store.save(assessment.to_dict())
        return assessment

    def queue(self, assessment: Assessment, *, on_event: Callable[..., None] | None = None) -> Future:
        with self._lock:
            active = self._futures.get(assessment.assessment_id)
            if active is not None and not active.done():
                raise ValueError("This assessment is already queued or running")
            if assessment.status == AssessmentState.CREATED.value:
                assessment.status = transition(assessment.status, AssessmentState.QUEUED)
                assessment.lifecycle_events.append({"event_type":"ASSESSMENT_QUEUED","timestamp":utc_now()})
                self.assessment_store.save(assessment.to_dict())
            if assessment.status != AssessmentState.QUEUED.value:
                raise ValueError(f"Only CREATED or QUEUED assessments can run (current: {assessment.status})")
            context = self._contexts.setdefault(assessment.assessment_id, ExecutionContext())
            future = self._pool.submit(self._execute, assessment, context, on_event)
            self._futures[assessment.assessment_id] = future
            return future

    def _execute(self, assessment: Assessment, context: ExecutionContext, on_event: Callable[..., None] | None) -> Assessment:
        started_clock = monotonic()
        assessment.status = transition(assessment.status, AssessmentState.RUNNING)
        assessment.started_at = assessment.started_at or utc_now()
        self.assessment_store.save(assessment.to_dict())
        self._notify("assessment", "started", {"status": assessment.status}, context, on_event)

        def forward(engine: str, state: str, result: dict[str, Any] | None) -> None:
            self._notify(engine, state, result, context, on_event)

        try:
            self.runner(assessment, config=self.config, assessment_store=self.assessment_store,
                        evidence_store=self.evidence_store, on_event=forward,
                        execution_context=context)
            if context.cancellation_requested:
                assessment.status = AssessmentState.CANCELLED.value
                assessment.completed_at = assessment.completed_at or utc_now()
            elif assessment.status not in {AssessmentState.CANCELLED.value, AssessmentState.FAILED.value}:
                assessment.status = (AssessmentState.COMPLETED_WITH_WARNINGS.value
                                     if any(e.get("status") in {"error", "failed", "unavailable", "not_assessed", "completed_with_errors"}
                                            for e in assessment.engines.values() if isinstance(e, dict))
                                     else AssessmentState.COMPLETED.value)
        except Exception as exc:
            assessment.status = AssessmentState.FAILED.value
            assessment.error = f"Assessment orchestration failed: {type(exc).__name__}: {exc}"
            assessment.technical_error = repr(exc)
            assessment.completed_at = utc_now()
        assessment.duration_seconds = round(monotonic() - started_clock, 3)
        self.assessment_store.save(assessment.to_dict())
        self._notify("assessment", assessment.status.lower(), {"status": assessment.status, "duration_seconds": assessment.duration_seconds}, context, on_event)
        return assessment

    @staticmethod
    def _notify(engine: str, state: str, result: dict[str, Any] | None,
                context: ExecutionContext, on_event: Callable[..., None] | None) -> None:
        context.record(engine, state, result)
        if on_event:
            on_event(engine, state, result)

    def cancel(self, assessment_id: str) -> bool:
        with self._lock:
            context = self._contexts.get(assessment_id)
            record = self.assessment_store.load(assessment_id)
            if not record or record.get("status") not in {AssessmentState.QUEUED.value, AssessmentState.RUNNING.value}:
                return False
            if context is None:
                context = self._contexts.setdefault(assessment_id, ExecutionContext())
            context.cancel()
            return True

    def recoverable(self) -> list[dict[str, Any]]:
        return [row for row in self.assessment_store.list_assessments()
                if str(row.get("status", "")).upper() in {AssessmentState.QUEUED.value, AssessmentState.RUNNING.value}]

    def mark_interrupted(self, assessment_id: str) -> dict[str, Any] | None:
        row = self.assessment_store.load(assessment_id)
        if not row or str(row.get("status", "")).upper() not in {AssessmentState.QUEUED.value, AssessmentState.RUNNING.value}:
            return row
        row["status"] = AssessmentState.FAILED.value
        row["error"] = "Assessment interrupted by application shutdown. Existing engine results were preserved."
        row["completed_at"] = utc_now()
        self.assessment_store.save(row)
        return row

    def resume_if_safe(self, assessment_id: str, *, on_event: Callable[..., None] | None = None) -> Future | None:
        row = self.assessment_store.load(assessment_id)
        if not row or row.get("status") != AssessmentState.QUEUED.value or row.get("engines"):
            return None
        assessment = Assessment(**{k: row[k] for k in Assessment.__dataclass_fields__ if k in row})
        return self.queue(assessment, on_event=on_event)

    def load(self, assessment_id: str) -> dict[str, Any] | None:
        return self.assessment_store.load(assessment_id)

    def events(self, assessment_id: str) -> list[dict[str, Any]]:
        context = self._contexts.get(assessment_id)
        return context.snapshot() if context else []

    def close(self, *, wait: bool = True) -> None:
        for context in self._contexts.values(): context.cancel()
        self._pool.shutdown(wait=wait, cancel_futures=False)
