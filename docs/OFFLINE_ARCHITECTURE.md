# Offline Architecture

## Operational guarantee and boundary

The supported TRACER-CV desktop and full-demo code paths use local Python modules, local files and local PySide6 widgets. They do not call cloud APIs, remote databases, external authentication, telemetry, CDNs, remote fonts/JavaScript, online model/dataset downloads or external report services. No network listener is started by `python -m desktop.app` or the `tracer-cv` launcher. `backend/app/main.py` is a separate optional FastAPI entry point and is not started by the desktop; deployment can omit it entirely.

Runtime operation can be air-gapped after Python and required local dependencies/assets are installed. Installation on an air-gapped machine requires a prepared local environment or a locally provided package wheelhouse; the runtime does not fetch missing packages.

## Local-only services

| Function | Local implementation |
|---|---|
| Settings | TOML under `configs/tracer_cv.toml` by default; `TRACER_CV_CONFIG` can select another local file |
| Asset registry | SQLite under `evidence_store/asset_registry.sqlite3` by default |
| Dataset/model inputs | `datasets_store/` and `models_store/` by default; existing demo assets remain under `demos/assets/` |
| Evidence artifacts | Content-addressed SHA-256 objects under `evidence_store/objects/` |
| Reports | Local `reports/`; atomic local saves and existing C5 JSON/text reports |
| Logs | Rotating local logs under `logs/` |
| Fonts | Qt system font selection from fonts installed on the host; no remote font URLs |
| Icons | Qt platform style standard icons; no external icon font/CDN |
| Stylesheet | `desktop/resources/tracer.qss`, loaded from the local project resource directory |
| Compute | Local PyTorch runtime; CPU always supported, CUDA selected only after a local runtime probe |

Paths can be overridden with supported `TRACER_CV_*` variables or the TOML config. Directory and configuration paths remain on the filesystem chosen by the operator. The project does not synchronize any path remotely.

## Offline status check

`tracer-cv --offline-check` performs a local static scan of `backend/`, `desktop/` and `demos/` for common network client imports/calls and reports configured offline mode. It performs **no DNS query, HTTP request, socket connection, interface-state probe or connectivity test**. A pass means the scanned application/demo source has no matched remote client calls and offline mode is enabled; it is not a proof that the operating system has no network adapter or that every installed dependency is network-incapable.

## Resource behavior

The desktop loads its stylesheet from the local repository/configured resource directory. Qt fonts and standard icons come from local platform resources. A missing stylesheet falls back to Qt defaults. The application has no remote resource fallback. Demo model and dataset are bundled local assets; no download occurs.

## Assessment data flow

The full demo calls the existing local A1–A8, B1–B4 and C1–C5 engines. Generated report files are imported into the configured local report/evidence stores. Registry, evidence and report stores use local SQLite/filesystem APIs only. C1/C4 records do not require an external ledger or trusted timestamp server.

## Offline operational checks

1. Prepare the supported Linux deployment and all Python packages from approved local media.
2. Disconnect or physically isolate the host according to site policy.
3. Run `tracer-cv --offline-check`; note that this check does not test link state.
4. Run `tracer-cv --self-test` to check installed modules, local resource loading, storage and compute selection.
5. Launch `python -m desktop.app` and use bundled evidence or already-staged local assets.
6. Export evidence/reports to approved local media using site handling rules.

The product check is not a substitute for host firewall policy, removable-media controls, or physical air-gap verification.
