"""Persist analyst decisions separately from immutable C3 finding evidence.

Every saved change appends an existing C4 audit-chain entry in the same local
governance document. This is local tamper-evidence, not an external trust anchor.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.engines.provenance.audit_trail import GENESIS_HASH, create_audit_entry, audit_entry_from_dict, digest_object, verify_audit_chain

DISPOSITIONS = ("ACCEPT", "REVIEW", "QUARANTINE")


class DispositionStoreError(ValueError):
    """Malformed or mismatched persisted governance state."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def finding_digest(finding: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(finding)).hexdigest()


class DispositionManager:
    """Local append-only decision history stored beside an assessment."""

    def __init__(self, assessment_dir: str | Path, assessment_id: str, base_audit_entries: list[dict[str, Any]] | None = None):
        self.root = Path(assessment_dir).resolve()
        self.assessment_id = str(assessment_id)
        if Path(self.assessment_id).name != self.assessment_id:
            raise ValueError("Invalid assessment ID")
        self.path = self.root / "analyst_dispositions.json"
        self.base_audit_entries = [row for row in (base_audit_entries or []) if isinstance(row, dict)]

    def load(self) -> dict[str, Any]:
        try:
            return self._load_strict()
        except DispositionStoreError:
            return {"schema_version": 1, "assessment_id": self.assessment_id,
                    "decisions": [], "audit_entries": [], "error": "Stored disposition evidence could not be interpreted."}

    def _load_strict(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"schema_version": 1, "assessment_id": self.assessment_id,
                    "decisions": [], "audit_entries": []}
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise DispositionStoreError("Stored disposition evidence could not be interpreted; no update was written.") from exc
        if (not isinstance(value, dict) or value.get("assessment_id") != self.assessment_id
                or not isinstance(value.get("decisions"), list) or not isinstance(value.get("audit_entries"), list)):
            raise DispositionStoreError("Stored disposition evidence has an incompatible assessment/schema; no update was written.")
        entries = {str(row.get("event_id")): row for row in value["audit_entries"] if isinstance(row, dict)}
        if len(entries) != len(value["audit_entries"]) or len(value["decisions"]) != len(value["audit_entries"]):
            raise DispositionStoreError("Stored disposition/audit records are incomplete; no update was written.")
        for decision in value["decisions"]:
            if not isinstance(decision, dict):
                raise DispositionStoreError("Stored disposition record is malformed; no update was written.")
            event = entries.get(str(decision.get("audit_event_id", "")))
            binding = {"assessment_id": decision.get("assessment_id"), "finding_id": decision.get("finding_id"),
                       "old_disposition": decision.get("old_disposition"), "new_disposition": decision.get("disposition"),
                       "analyst_note": decision.get("analyst_note", ""), "finding_digest": decision.get("finding_digest")}
            if (event is None or event.get("entry_hash") != decision.get("audit_entry_hash")
                    or event.get("payload_digest") != digest_object(binding)):
                raise DispositionStoreError("Stored disposition no longer matches its C4 event binding; no update was written.")
        return value

    def decision_for(self, finding_id: str) -> dict[str, Any] | None:
        rows = self.load().get("decisions", [])
        return next((row for row in reversed(rows) if isinstance(row, dict) and row.get("finding_id") == finding_id), None)

    def save(self, finding: dict[str, Any], disposition: str, note: str = "") -> dict[str, Any]:
        disposition = str(disposition).upper()
        if disposition not in DISPOSITIONS:
            raise ValueError("Disposition must be ACCEPT, REVIEW, or QUARANTINE")
        finding_id = str(finding.get("finding_id", "")).strip()
        if not finding_id:
            raise ValueError("Persisted finding ID is required")
        if len(note) > 4000:
            raise ValueError("Analyst note exceeds 4000 characters")
        self.root.mkdir(parents=True, exist_ok=True)
        document = self._load_strict()
        previous = self.decision_for(finding_id)
        old = previous.get("disposition") if previous else None
        digest = finding_digest(finding)
        now = datetime.now(timezone.utc).isoformat()
        payload = {"assessment_id": self.assessment_id, "finding_id": finding_id,
                   "old_disposition": old, "new_disposition": disposition,
                   "analyst_note": note, "finding_digest": digest}
        base_entries = [audit_entry_from_dict(row) for row in self.base_audit_entries]
        entries = [audit_entry_from_dict(row) for row in document.get("audit_entries", []) if isinstance(row, dict)]
        previous_hash = (entries[-1].entry_hash if entries else base_entries[-1].entry_hash) if entries or base_entries else GENESIS_HASH
        entry = create_audit_entry(sequence=len(base_entries) + len(entries) + 1,
                                   event_type="ANALYST_DISPOSITION_CHANGED",
                                   source_engine="C3", affected_asset=str(finding.get("affected_asset") or finding_id),
                                   payload=payload, previous_entry_hash=previous_hash, timestamp=now)
        decision = {**payload, "disposition": disposition, "timestamp": now,
                    "audit_event_id": entry.event_id, "audit_entry_hash": entry.entry_hash}
        document["decisions"].append(decision)
        document["audit_entries"].append(entry.as_dict())
        document["audit_verification"] = verify_audit_chain(base_entries + entries + [entry])
        self._atomic_write(document)
        return decision

    def _atomic_write(self, document: dict[str, Any]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".analyst-dispositions-", suffix=".tmp", dir=self.root)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(document, stream, ensure_ascii=False, indent=2)
                stream.flush(); os.fsync(stream.fileno())
            os.replace(name, self.path)
        finally:
            try: os.unlink(name)
            except FileNotFoundError: pass


__all__ = ["DISPOSITIONS", "DispositionManager", "DispositionStoreError", "finding_digest"]
