# Reproducibility

## Environment observed during this implementation

Python 3.14.7, PySide6 6.11.2, PyTorch 2.11.0+cu128. CUDA was unavailable in this runtime, so only CPU execution was observed. The project code does not currently expose an application-wide device selector or automatic CUDA fallback. Dataset and cryptographic operations are CPU-oriented.

## Demo workflow

From the project root:

```bash
source .venv/bin/activate
python demos/create_demo_assets.py
python demos/run_full_assurance_demo.py
```

The module form keeps the project root on Python’s import path. It reads `demos/assets` and writes JSON/text reports under `reports/`, including engine results in `reports/engine_results/` and audit evidence in `reports/evidence/`.

## Engine sequence

The full demo executes A1–A8, then B1–B4, then creates C1 provenance, analyzes C2 shift, aggregates C3 findings, appends/verifies C4 audit entries and builds C5 JSON/text outputs. The single end-to-end command above is the supported reproducible sequence; individual engine tests and helper functions are under `tests/`.

## Launching the desktop

```bash
python -m desktop.app
```

For an evaluator run, generate the demo evidence first. Dashboard and detail pages read local JSON files and expose raw evidence through a secondary dialog. Tamper actions operate on copied in-memory objects.

## Verification commands

```bash
python -m compileall -q desktop backend demos
pytest -q
python demos/run_full_assurance_demo.py
python -m desktop.app
```

The repository’s current pytest discovery includes test-named helper functions with required parameters but no fixtures. The full run therefore has passing tests and fixture-setup errors; this is a pre-existing test organization limitation. Some tests can be invoked as ordinary Python helper functions, but they are not all pytest tests as currently named.

## Reproducibility notes

Demo input assets are generated locally. Hashes and deterministic report fields should be stable for unchanged assets and configuration. Timestamps, generated nonces/event IDs and some model outputs can vary. C1 demo currently supplies a fixed nonce and timestamp for its record. CUDA availability changes execution only where an engine adapter uses it; CPU is the fallback available in this validated environment. No internet connection is used by the demo or desktop workflows.
