"""Thread-safe cancellation and real execution event collection."""
from __future__ import annotations

from threading import Event, Lock
from typing import Any


class ExecutionContext:
    def __init__(self) -> None:
        self._cancel = Event()
        self._lock = Lock()
        self.events: list[dict[str, Any]] = []

    def cancel(self) -> None:
        self._cancel.set()

    @property
    def cancellation_requested(self) -> bool:
        return self._cancel.is_set()

    def record(self, engine: str, state: str, result: dict[str, Any] | None = None) -> None:
        summary = None
        if isinstance(result, dict):
            summary = {key: result[key] for key in ("status", "reason", "evidence_id", "sha256") if key in result}
        with self._lock:
            self.events.append({"engine": engine, "state": state, "result": summary})

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.events)
