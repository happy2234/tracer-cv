# TRACER-CV Offline Deployment

## Supported target and limits

The currently supported deployment target is **Linux x86_64**. The development environment observed here is Python 3.14.7, PySide6 6.11.2 and PyTorch 2.11.0+cu128; CUDA was not available in the validation host. The application supports CPU execution. CUDA needs compatible local NVIDIA drivers, hardware and a CUDA-enabled PyTorch installation. Windows and macOS are not yet validated; this project does not claim cross-platform portability.

## Provisioning for an isolated host

Prepare the host and dependencies before isolation, or transfer them through approved offline media:

1. Provision Linux and Python 3.11 or newer according to the site image.
2. Create a virtual environment and install the project’s required local dependencies from the approved internal wheelhouse/media. The repository currently has no complete lockfile/wheelhouse; resolve and verify dependencies during connected staging, then transfer them. The installed TRACER-CV runtime itself does not install or download packages.
3. Copy the repository and approved demo/assessment assets onto local storage.
4. Verify repository/package digests through the deployment site's established trusted process.
5. Set local configuration and storage paths if needed. Do not place credentials/private keys in the repository or report folders.
6. Isolate the host per site policy and run local checks below.

This deployment guide does not prescribe downloading any specific artifact from the Internet; connected provisioning is an administrator-controlled staging step. A deployment can instead be provisioned entirely from previously validated offline packages.

## Local configuration

Defaults keep the current repository workflow intact:

| Setting | Default | Override |
|---|---|---|
| Config file | `configs/tracer_cv.toml` | `TRACER_CV_CONFIG` |
| App data root | Project directory | `TRACER_CV_DATA_DIR` |
| Dataset store | `<data root>/datasets_store` | `TRACER_CV_DATASETS_DIR` or TOML |
| Model store | `<data root>/models_store` | `TRACER_CV_MODELS_DIR` or TOML |
| Evidence and asset registry | `<data root>/evidence_store` | `TRACER_CV_EVIDENCE_DIR` or TOML |
| Reports | `<project>/reports` | `TRACER_CV_REPORTS_DIR` or TOML |
| Logs | `<data root>/logs` | `TRACER_CV_LOGS_DIR` or TOML |
| Device | `auto` | `TRACER_CV_DEVICE` or TOML |
| Offline policy | `true` | `TRACER_CV_OFFLINE` or TOML |
| Batch/workers/file/image limits | Conservative local defaults | TOML |

Environment values take precedence over TOML. Configuration is non-secret. Directories are local and created as needed with restrictive permissions where supported. Operators should ensure chosen storage is on approved encrypted/controlled local media if required by policy.

Example local settings:

```toml
[tracer_cv]
offline_mode = true
device = "auto" # auto, cpu, cuda
batch_size = 16
workers = 2
max_file_bytes = 2147483648
max_image_pixels = 40000000
logging_level = "INFO"
```

## Run commands

From the repository root:

```bash
source .venv/bin/activate
python -m desktop.app
```

The checkout-local launcher can be used with the virtual environment active:

```bash
./tracer-cv
./tracer-cv --offline-check
./tracer-cv --self-test
```

The full bundled assessment demo is:

```bash
python demos/run_full_assurance_demo.py
```

This full demo uses bundled local assets and writes local reports. It currently reports B3 error for the bundled checkpoint in the validated environment; do not interpret B3 as complete merely because the pipeline exits successfully.

## Device selection

The desktop selector offers Automatic, CPU and CUDA. Automatic probes CUDA locally; when unavailable/unsuitable it selects CPU. Explicit CUDA fails clearly if the local runtime probe is unavailable. Dataset and cryptographic engines remain CPU-oriented. Device support is passed to supported model adapters. A later CUDA workload can still fail; universal mid-run CPU retry is not currently implemented.

## Local outputs

- Registry: `evidence_store/asset_registry.sqlite3`.
- Content-addressed evidence: `evidence_store/objects/<prefix>/<sha256>.<suffix>`.
- Engine and report JSON/text: `reports/` and `reports/engine_results/`.
- C4 audit file: `reports/evidence/audit_chain.json`.
- Logs: `logs/tracer-cv.log` with local rotation.

Demo results are imported into the configured local stores. Re-running the demo intentionally updates the generated current-result files; preserve/export prior reports before rerunning when historical versions are needed. This does not alter source dataset/model assets.

## Self-test and offline check

`./tracer-cv --self-test` checks local directories, SQLite registry, evidence/report writes in a temporary local directory, local QSS resource loading, required imports, engine imports and compute resolution. It may create the configured directories and registry database. It makes no network request.

`./tracer-cv --offline-check` statically checks backend/desktop/demo Python source for known network client imports/calls and reports the offline setting. It does not test whether network hardware is physically disabled or whether all installed third-party libraries are free of network code. Use host controls to establish air-gap state.

## Local resources and OS requirements

The QSS file is `desktop/resources/tracer.qss`. Fonts and icons come from local Qt/system resources. Required Python packages, model files, datasets, label files and reference assets must already be present on local media. Missing optional CUDA hardware does not prevent CPU-only use. No browser, JavaScript runtime, web server, remote font, CDN, telemetry agent, external login, cloud account, blockchain node or remote database is required for desktop operation.

## Backup and handling

Back up local report/evidence directories, `asset_registry.sqlite3`, configuration and any operator-approved exported chain checkpoints according to site retention policy. Verify digests after transfer. Keep signing private keys separate. Report/evidence export must follow data classification and removable-media policy. TRACER-CV does not encrypt its evidence directory automatically.
