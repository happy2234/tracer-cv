"""TRACER-CV local command line entry point."""
from __future__ import annotations

import argparse
import json
import sys

from backend.core.compute import DeviceUnavailableError, resolve_compute
from backend.core.local_config import LocalConfig
from backend.core.offline_status import offline_capability_check
from backend.core.runtime_selftest import self_test


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tracer-cv", description="TRACER-CV offline assurance workbench")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--self-test", action="store_true", help="check local storage, resources, imports and compute")
    group.add_argument("--offline-check", action="store_true", help="check local source/config without probing network connectivity")
    parser.add_argument("--device", choices=("auto", "cpu", "cuda"), help="override local compute preference")
    args = parser.parse_args(argv)
    config = LocalConfig.load()
    if args.device:
        from dataclasses import replace
        config = replace(config, device=args.device)
    if args.offline_check:
        result = offline_capability_check(config)
        print(json.dumps(result, indent=2))
        return 0 if result["status"] == "pass" else 1
    if args.self_test:
        result = self_test(config)
        print(json.dumps(result, indent=2))
        return 0 if result["status"] == "pass" else 1
    try:
        resolve_compute(config.device)
    except DeviceUnavailableError as exc:
        print(f"TRACER-CV cannot start with configured device: {exc}", file=sys.stderr)
        return 2
    from desktop.app import main as desktop_main
    desktop_main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
