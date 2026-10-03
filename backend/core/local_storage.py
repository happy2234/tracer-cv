"""Local asset/evidence/report storage primitives."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.core.local_config import LocalConfig


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _atomic_write(target: Path, payload: bytes, *, overwrite: bool) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if target.exists() and not overwrite:
        if target.is_file() and target.read_bytes() == payload:
            return target
        raise FileExistsError(target)
    fd, tmp_name = tempfile.mkstemp(prefix=".tracer-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            os.replace(tmp_name, target)
        else:
            # Hard-link creation is atomic and fails if another writer won.
            try:
                os.link(tmp_name, target)
            except FileExistsError:
                if target.is_file() and target.read_bytes() == payload:
                    return target
                raise
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
    return target


class EvidenceStore:
    def __init__(self, root: Path):
        self.root = root.resolve() / "objects"

    def put_bytes(self, payload: bytes, suffix: str = ".bin") -> dict[str, Any]:
        digest = sha256(payload)
        if suffix not in {".bin", ".json", ".txt", ".png", ".jpg"}:
            suffix = ".bin"
        path = self.root / digest[:2] / f"{digest}{suffix}"
        _atomic_write(path, payload, overwrite=False)
        return {"sha256": digest, "size_bytes": len(payload), "uri": str(path)}

    def put_json(self, value: Any) -> dict[str, Any]:
        payload = canonical_json(value)
        result = self.put_bytes(payload, ".json")
        result["serialization"] = "canonical-json"
        return result


class ReportStore:
    def __init__(self, root: Path):
        self.root = root.resolve()

    def save(self, filename: str, payload: bytes, *, overwrite: bool = False) -> Path:
        name = Path(filename)
        if name.is_absolute() or filename in {"", ".", ".."} or ".." in name.parts:
            raise ValueError("report filename must be a safe relative local path")
        target = (self.root / name).resolve()
        if not target.is_relative_to(self.root):
            raise ValueError("report path escapes the local report directory")
        current = self.root
        for part in name.parts[:-1]:
            current = current / part
            if current.is_symlink():
                raise ValueError("refusing to write through a report-directory symlink")
        if (self.root / name).is_symlink():
            raise ValueError("refusing to write through a report symlink")
        return _atomic_write(target, payload, overwrite=overwrite)


class AssetRegistry:
    """Local SQLite registry; registers identity metadata without executing assets."""
    def __init__(self, database: Path, max_file_bytes: int):
        self.database = database.resolve()
        self.database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.max_file_bytes = max_file_bytes
        with self._connect() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS assets (
                asset_id TEXT PRIMARY KEY, kind TEXT NOT NULL, display_name TEXT NOT NULL,
                local_path TEXT NOT NULL, size_bytes INTEGER, sha256 TEXT,
                registered_at TEXT NOT NULL, trust_state TEXT NOT NULL)""")

    def _connect(self):
        connection = sqlite3.connect(self.database, timeout=10)
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def register(self, path: Path, kind: str, *, hash_file: bool = True) -> dict[str, Any]:
        path = Path(path).expanduser()
        absolute = path.absolute()
        current = Path(absolute.anchor)
        for part in absolute.parts[1:]:
            current = current / part
            if current.is_symlink():
                raise ValueError("symbolic-link traversal is not accepted for asset registration")
        resolved = path.resolve(strict=True)
        if not (resolved.is_file() or resolved.is_dir()):
            raise ValueError("asset must be a regular file or directory")
        size = resolved.stat().st_size if resolved.is_file() else None
        if size is not None and size > self.max_file_bytes:
            raise ValueError(f"asset exceeds configured maximum ({self.max_file_bytes} bytes)")
        digest = None
        if resolved.is_file() and hash_file:
            hasher = hashlib.sha256()
            with resolved.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    hasher.update(chunk)
            digest = hasher.hexdigest()
        registered = datetime.now(timezone.utc).isoformat()
        identity = sha256(canonical_json({"path": str(resolved), "kind": kind, "sha256": digest, "size": size}))
        with self._connect() as conn:
            conn.execute("INSERT OR IGNORE INTO assets VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                         (identity, kind, resolved.name, str(resolved), size, digest, registered,
                          "trusted_for_hashing" if digest else "untrusted"))
        return {"asset_id": identity, "kind": kind, "display_name": resolved.name,
                "local_path": str(resolved), "size_bytes": size, "sha256": digest,
                "trust_state": "trusted_for_hashing" if digest else "untrusted"}

    def list_assets(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT asset_id,kind,display_name,local_path,size_bytes,sha256,registered_at,trust_state FROM assets ORDER BY registered_at DESC").fetchall()
        fields = ("asset_id", "kind", "display_name", "local_path", "size_bytes", "sha256", "registered_at", "trust_state")
        return [dict(zip(fields, row)) for row in rows]


class AssessmentStore:
    """Persist complete local assessment objects in SQLite."""
    def __init__(self, database: Path):
        self.database = database.resolve()
        self.database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self._connect() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS assessments (
                assessment_id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL, payload TEXT NOT NULL)""")

    def _connect(self):
        conn = sqlite3.connect(self.database, timeout=10)
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def save(self, assessment: dict[str, Any]) -> None:
        payload = json.dumps(assessment, sort_keys=True, ensure_ascii=False, default=str)
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute("""INSERT INTO assessments VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(assessment_id) DO UPDATE SET name=excluded.name,
                status=excluded.status, updated_at=excluded.updated_at, payload=excluded.payload""",
                (assessment["assessment_id"], assessment.get("name", ""),
                 assessment.get("status", "draft"), assessment.get("created_at", now), now, payload))

    def load(self, assessment_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT payload FROM assessments WHERE assessment_id=?", (assessment_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def list_assessments(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT payload, updated_at FROM assessments ORDER BY updated_at DESC").fetchall()
        results=[]
        for payload,updated_at in rows:
            item=json.loads(payload); item["updated_at"]=updated_at; results.append(item)
        return results


def initialize_local_storage(config: LocalConfig) -> dict[str, Any]:
    config.ensure_local_directories()
    registry = AssetRegistry(config.evidence_dir / "asset_registry.sqlite3", config.max_file_bytes)
    assessments = AssessmentStore(config.evidence_dir / "assessment_registry.sqlite3")
    return {"asset_registry": registry, "evidence_store": EvidenceStore(config.evidence_dir),
            "report_store": ReportStore(config.reports_dir), "assessment_store": assessments}


def import_demo_outputs(source_reports: Path, config: LocalConfig, *, overwrite: bool = False) -> list[dict[str, Any]]:
    """Copy known demo result files into configured local report/evidence stores."""
    bundle = initialize_local_storage(config)
    store: ReportStore = bundle["report_store"]
    evidence: EvidenceStore = bundle["evidence_store"]
    names = [
        "engine_results/dataset_integrity.json",
        "engine_results/model_assurance.json",
        "engine_results/provenance.json",
        "engine_results/distribution_shift.json",
        "engine_results/findings.json",
        "evidence/audit_chain.json",
        "tracer_cv_assurance_report.json",
        "tracer_cv_assurance_report.txt",
    ]
    imported = []
    source_reports = source_reports.resolve()
    for name in names:
        src = (source_reports / name).resolve()
        if not src.is_relative_to(source_reports) or not src.is_file():
            continue
        payload = src.read_bytes()
        try:
            target = store.save(name, payload, overwrite=overwrite)
        except FileExistsError:
            # Preserve non-demo report evidence during migration/initial sync.
            target = (config.reports_dir / name).resolve()
        artifact = evidence.put_bytes(payload, ".json" if name.endswith(".json") else ".txt")
        imported.append({"name": name, "report_path": str(target), "evidence": artifact})
    return imported
