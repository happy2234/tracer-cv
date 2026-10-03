"""Offline capability checks that never make network requests."""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from backend.core.local_config import LocalConfig

_NETWORK_MODULES = {"requests", "httpx", "urllib.request", "ftplib", "smtplib", "websocket", "socket", "http.client"}
_NETWORK_CALLS = {"requests.get", "requests.post", "httpx.get", "httpx.post", "urlopen", "create_connection"}


def _imports_network(source: str) -> bool:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name in _NETWORK_MODULES or alias.name.startswith("urllib.request") for alias in node.names):
                return True
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module in _NETWORK_MODULES or node.module.startswith("urllib.request"):
                return True
        if isinstance(node, ast.Call):
            value = node.func
            if isinstance(value, ast.Name) and value.id == "urlopen":
                return True
            if isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name):
                if f"{value.value.id}.{value.attr}" in _NETWORK_CALLS:
                    return True
    return False


def offline_capability_check(config: LocalConfig) -> dict[str, Any]:
    """Static-check runtime source for common remote clients; does not test connectivity."""
    roots = (config.project_root / "backend", config.project_root / "desktop", config.project_root / "demos")
    offenders = []
    for root in roots:
        if not root.is_dir():
            continue
        for source_path in root.rglob("*.py"):
            try:
                if _imports_network(source_path.read_text(encoding="utf-8")):
                    offenders.append(str(source_path.relative_to(config.project_root)))
            except OSError:
                offenders.append(str(source_path.relative_to(config.project_root)))
    return {
        "status": "pass" if config.offline_mode and not offenders else "review_required",
        "operating_mode": "offline / air-gapped" if config.offline_mode else "offline mode disabled",
        "network_dependency": "none detected in backend/desktop/demos source" if not offenders else "possible network client import/call found",
        "network_probes_performed": False,
        "network_probe_note": "Connectivity was not tested; this check performs no network requests.",
        "remote_dependencies": offenders,
        "local_resources_directory": str(config.resources_dir),
    }
