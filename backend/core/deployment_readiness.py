"""Deployment readiness derivation from local self-test outcomes."""
from __future__ import annotations

from typing import Any

REQUIRED_CHECKS = frozenset({"runtime_core", "configuration", "storage_evidence", "temporary_workspace", "sha256", "ed25519", "merkle", "audit", "provenance", "report_rendering", "pdf_generation", "offline_configuration"})

def readiness_for(checks: list[dict[str, Any]]) -> tuple[str, str]:
    indexed = {str(row.get("test_id")): row for row in checks}
    required_failures = [key for key in REQUIRED_CHECKS if indexed.get(key, {}).get("status") != "PASS"]
    if required_failures:
        return "NOT READY", "Required local assurance checks did not pass: " + ", ".join(sorted(required_failures))
    warnings = [row for row in checks if row.get("status") in {"WARN", "FAIL"}]
    if warnings:
        return "READY WITH WARNINGS", "Required local checks passed; review optional capability or environment warnings."
    return "READY", "All required local TRACER-CV function checks passed. This does not assess whether any dataset or model is secure."

__all__ = ["REQUIRED_CHECKS", "readiness_for"]
