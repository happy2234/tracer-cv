# TRACER-CV Synthetic Benchmark

This local benchmark generates synthetic images and byte strings using a fixed seed, then calls existing dataset/model identity engines and the C1 synthetic provenance verification cases. It includes a five-file exact-duplicate group, a label conflict, changed reference/candidate populations, localized repeated-pattern images, changed synthetic tensor bytes, a trigger-sensitive callable, and signed-provenance verification/tampering/replay scenarios. It does not download data, train a model, or represent an operational assessment.

Run from the repository root:

```bash
.venv/bin/python demos/benchmark/run_benchmark.py
```

To preserve generated scenario inputs and a JSON result locally:

```bash
.venv/bin/python demos/benchmark/run_benchmark.py --output /path/to/local/output
```

Output is labeled `DEMONSTRATION DATA`. A negative observation means only that the particular configured method did not establish the expected behavior in that synthetic scenario. This benchmark does not provide an overall accuracy estimate.
