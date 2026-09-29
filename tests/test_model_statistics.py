
"""Standalone B3 tests for TRACER-CV.

Run:
    python -m tests.test_model_statistics
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

from backend.engines.model import model_statistics as ms


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def run(name, fn):
    try:
        fn()
        print(f"PASS {name}")
        return True
    except Exception as exc:
        print(f"FAIL {name}: {type(exc).__name__}: {exc}")
        return False


def test_01_array_statistics():
    arr = np.array([0, 1, 2, 3], dtype=np.float32)
    s = ms.compute_array_statistics(arr)

    check(s["element_count"] == 4, "element count")
    check(s["zero_count"] == 1, "zero count")
    check(abs(s["mean"] - 1.5) < 1e-9, "mean")
    check(abs(s["std"] - np.std(arr)) < 1e-9, "std")
    check(s["min"] == 0.0 and s["max"] == 3.0, "range")
    check(len(s["digest_sha256"]) == 64, "digest")


def test_02_nonfinite_statistics():
    arr = np.array([1.0, np.nan, np.inf, -np.inf, 0.0])
    s = ms.compute_array_statistics(arr)

    check(s["nan_count"] == 1, "nan")
    check(s["posinf_count"] == 1, "posinf")
    check(s["neginf_count"] == 1, "neginf")
    check(s["non_finite_count"] == 3, "nonfinite")


def test_03_empty_and_invalid():
    s = ms.compute_array_statistics(np.empty(0, dtype=np.float32))

    check(s["element_count"] == 0, "empty")
    check(s["mean"] is None, "empty mean")

    try:
        ms.compute_array_statistics(np.array([1 + 2j]))
    except TypeError:
        pass
    else:
        raise AssertionError("complex array accepted")


def test_04_probe_generation_deterministic():
    a = ms.make_synthetic_probe_images(3, 8, 9, seed=123)
    b = ms.make_synthetic_probe_images(3, 8, 9, seed=123)

    check(len(a) == 3, "count")
    check(all(x.dtype == np.uint8 for x in a), "dtype")
    check(all(x.shape == (8, 9, 3) for x in a), "shape")
    check(
        all(np.array_equal(x, y) for x, y in zip(a, b)),
        "not deterministic",
    )


def test_05_probe_preparation():
    images = ms.make_synthetic_probe_images(2, 8, 9, seed=1)
    batch, info = ms.prepare_probe_batch(images, probe_set_id="b3-test")

    check(batch.shape == (2, 3, 8, 9), f"shape={batch.shape}")
    check(batch.dtype == np.float32, "dtype")
    check(info["probe_count"] == 2, "count")
    check(info["probe_set_id"] == "b3-test", "probe id")
    check(len(info["probe_digest"]) == 64, "digest")


def test_06_named_arrays():
    tensors = {
        "weight": np.arange(12, dtype=np.float32).reshape(3, 4),
        "bias": np.zeros(3, dtype=np.float32),
    }

    report = ms.analyze_named_arrays(tensors)

    check(report["status"] == "completed", report["status"])
    check(
        report["parameters"]["totals"]["parameter_tensor_count"] == 2,
        "tensor count",
    )
    check(
        report["parameters"]["totals"]["total_parameter_count"] == 15,
        "parameter count",
    )
    check(
        report["activations"]["status"] == "unavailable",
        "activations",
    )


def test_07_black_box():
    report = ms.analyze_model(access="black_box")

    check(report["status"] == "unavailable", report["status"])
    check(
        report["parameter_statistics"] == "unavailable",
        "parameters",
    )
    check(
        report["activation_statistics"] == "unavailable",
        "activations",
    )


def test_08_path_never_loaded():
    report = ms.analyze_model("/tmp/fake_model.pt")

    check(report["status"] == "unavailable", report["status"])
    check(
        "never loads" in report["reason"].lower(),
        report["reason"],
    )


def test_09_unknown_object():
    report = ms.analyze_model(lambda x: x)

    check(report["status"] == "unavailable", report["status"])


def test_10_torch_parameter_statistics():
    torch = ms._import_torch()

    if torch is None:
        print("SKIP test_10_torch_parameter_statistics (PyTorch unavailable)")
        return

    model = torch.nn.Linear(4, 2)

    with torch.no_grad():
        model.weight.fill_(2.0)
        model.bias.zero_()

    report = ms.analyze_torch_model(model)

    check(report["status"] == "completed", report["status"])

    entries = {
        item["name"]: item
        for item in report["parameters"]["tensors"]
    }

    check("weight" in entries, "weight missing")
    check("bias" in entries, "bias missing")
    check(
        entries["weight"]["statistics"]["mean"] == 2.0,
        "weight mean",
    )
    check(
        entries["bias"]["statistics"]["zero_fraction"] == 1.0,
        "bias zero",
    )


def test_11_torch_structure():
    torch = ms._import_torch()

    if torch is None:
        print("SKIP test_11_torch_structure (PyTorch unavailable)")
        return

    model = torch.nn.Sequential(
        torch.nn.Conv2d(3, 2, 3, padding=1),
        torch.nn.ReLU(),
        torch.nn.Flatten(),
        torch.nn.Linear(2 * 8 * 8, 2),
    )

    report = ms.analyze_torch_model(model)

    check(
        report["structure"]["status"] == "available",
        "structure",
    )
    check(
        report["structure"]["module_count"] >= 5,
        "module count",
    )
    check(
        report["parameters"]["totals"]["total_parameter_count"] > 0,
        "parameter count",
    )


def test_12_activation_capture():
    torch = ms._import_torch()

    if torch is None:
        print("SKIP test_12_activation_capture (PyTorch unavailable)")
        return

    model = torch.nn.Sequential(
        torch.nn.Conv2d(3, 2, 3, padding=1),
        torch.nn.ReLU(),
        torch.nn.Flatten(),
        torch.nn.Linear(2 * 8 * 8, 2),
    )

    images = ms.make_synthetic_probe_images(3, 8, 8, seed=3)

    report = ms.analyze_torch_model(
        model,
        images=images,
    )

    activations = report["activations"]

    check(
        activations["status"] == "completed",
        activations,
    )
    check(
        activations["layer_count"] > 0,
        "no layers",
    )

    for layer in activations["layers"]:
        check(
            "output_shape" in layer,
            "missing shape",
        )
        check(
            "statistics" in layer,
            "missing statistics",
        )


def test_13_hooks_removed():
    torch = ms._import_torch()

    if torch is None:
        print("SKIP test_13_hooks_removed (PyTorch unavailable)")
        return

    # CHW probe shape is [N, 4, 1, 1], so use Conv2d rather than Linear.
    model = torch.nn.Sequential(
        torch.nn.Conv2d(4, 3, kernel_size=1),
        torch.nn.ReLU(),
    )

    images = [
        np.zeros((4, 1, 1), dtype=np.uint8),
        np.zeros((4, 1, 1), dtype=np.uint8),
    ]

    config = ms.ModelStatisticsConfig(input_layout="CHW")

    report = ms.analyze_torch_model(
        model,
        images=images,
        config=config,
    )

    check(
        report["activations"]["status"] == "completed",
        report,
    )

    for module in model.modules():
        check(
            len(getattr(module, "_forward_hooks", {})) == 0,
            "forward hook leaked",
        )


def test_14_training_state_restored():
    torch = ms._import_torch()

    if torch is None:
        print(
            "SKIP test_14_training_state_restored "
            "(PyTorch unavailable)"
        )
        return

    # CHW probe shape is [N, 4, 1, 1], so use Conv2d.
    model = torch.nn.Sequential(
        torch.nn.Conv2d(4, 3, kernel_size=1),
        torch.nn.ReLU(),
    )

    model.train()

    before = {
        id(module): module.training
        for module in model.modules()
    }

    images = [
        np.zeros((4, 1, 1), dtype=np.uint8),
    ]

    config = ms.ModelStatisticsConfig(input_layout="CHW")

    ms.analyze_torch_model(
        model,
        images=images,
        config=config,
    )

    after = {
        id(module): module.training
        for module in model.modules()
    }

    check(
        before == after,
        "training state not restored",
    )


def test_15_modified_model_detected():
    torch = ms._import_torch()

    if torch is None:
        print(
            "SKIP test_15_modified_model_detected "
            "(PyTorch unavailable)"
        )
        return

    torch.manual_seed(11)

    reference = torch.nn.Linear(4, 3)
    assessed = torch.nn.Linear(4, 3)

    assessed.load_state_dict(reference.state_dict())

    with torch.no_grad():
        assessed.weight[0, 0] += 10.0

    ref_report = ms.analyze_torch_model(reference)
    assessed_report = ms.analyze_torch_model(assessed)

    comparison = ms.compare_reports(
        ref_report,
        assessed_report,
    )

    check(
        comparison["status"] == "completed",
        comparison,
    )
    check(
        comparison["summary"]["candidate_anomaly_count"] > 0,
        comparison["summary"],
    )


def test_16_identical_models_no_deviation():
    torch = ms._import_torch()

    if torch is None:
        print(
            "SKIP test_16_identical_models_no_deviation "
            "(PyTorch unavailable)"
        )
        return

    torch.manual_seed(12)

    reference = torch.nn.Linear(4, 3)
    assessed = torch.nn.Linear(4, 3)

    assessed.load_state_dict(reference.state_dict())

    ref_report = ms.analyze_torch_model(reference)
    assessed_report = ms.analyze_torch_model(assessed)

    comparison = ms.compare_reports(
        ref_report,
        assessed_report,
    )

    check(
        comparison["status"] == "completed",
        comparison,
    )
    check(
        comparison["summary"]["candidate_anomaly_count"] == 0,
        comparison["summary"],
    )


def test_17_probe_mismatch_incompatible():
    torch = ms._import_torch()

    if torch is None:
        print(
            "SKIP test_17_probe_mismatch_incompatible "
            "(PyTorch unavailable)"
        )
        return

    # CHW probe shape is [N, 3, 1, 1], so use Conv2d.
    model_a = torch.nn.Conv2d(3, 2, kernel_size=1)
    model_b = torch.nn.Conv2d(3, 2, kernel_size=1)

    model_b.load_state_dict(model_a.state_dict())

    config = ms.ModelStatisticsConfig(input_layout="CHW")

    images_a = [
        np.zeros((3, 1, 1), dtype=np.uint8),
    ]

    images_b = [
        np.full((3, 1, 1), 255, dtype=np.uint8),
    ]

    ref_report = ms.analyze_torch_model(
        model_a,
        images=images_a,
        config=config,
    )

    assessed_report = ms.analyze_torch_model(
        model_b,
        images=images_b,
        config=config,
    )

    comparison = ms.compare_reports(
        ref_report,
        assessed_report,
    )

    check(
    comparison["status"] == "completed",
    comparison,
    )

    check(
    comparison["compatibility"]["status"] == "partially_compatible",
    comparison["compatibility"],
    )

    codes = {
        issue["code"]
        for issue in comparison["compatibility"]["issues"]
    }

    check(
        "probe_configuration_mismatch" in codes,
        comparison["compatibility"],
    )


def test_18_invalid_thresholds():
    report = ms.analyze_named_arrays(
        {"w": np.ones((2, 2), dtype=np.float32)}
    )

    thresholds = ms.ComparisonThresholds(
        param_mean_norm_diff=-1.0
    )

    comparison = ms.compare_reports(
        report,
        report,
        thresholds,
    )

    check(
        comparison["status"] == "error",
        comparison["status"],
    )


def test_19_no_timestamps():
    report = ms.analyze_named_arrays(
        {"w": np.ones((2, 2), dtype=np.float32)}
    )

    serialized = json.dumps(report).lower()

    check(
        "timestamp" not in serialized,
        "timestamp found",
    )
    check(
        "datetime" not in serialized,
        "datetime found",
    )


def test_20_no_network_imports():
    source = Path(ms.__file__).read_text(
        encoding="utf-8"
    )

    for token in (
        "requests",
        "httpx",
        "urllib.request",
        "socket",
        "wget",
        "curl",
    ):
        check(
            token not in source,
            f"network token found: {token}",
        )


def test_21_torchscript_requires_trust():
    try:
        ms.load_torchscript_model(
            "/tmp/nonexistent.pt"
        )
    except ValueError as exc:
        check(
            "trusted=True" in str(exc),
            str(exc),
        )
    except Exception as exc:
        raise AssertionError(
            f"unexpected exception: {type(exc).__name__}: {exc}"
        )
    else:
        raise AssertionError(
            "TorchScript loader did not require trusted=True"
        )


def test_22_fingerprint_deterministic():
    tensors = {
        "w": np.arange(
            6,
            dtype=np.float32,
        ).reshape(2, 3)
    }

    a = ms.analyze_named_arrays(tensors)
    b = ms.analyze_named_arrays(tensors)

    check(
        a["fingerprint"]["digest"]
        == b["fingerprint"]["digest"],
        "fingerprint changed",
    )


def test_23_invalid_task_comparison():
    base = ms.analyze_named_arrays(
        {"w": np.ones((2, 2), dtype=np.float32)}
    )

    altered = dict(base)
    altered["task"] = "wrong_task"

    comparison = ms.compare_reports(
        base,
        altered,
    )

    check(
        comparison["status"] == "incompatible",
        comparison,
    )


def main():
    tests = [
        test_01_array_statistics,
        test_02_nonfinite_statistics,
        test_03_empty_and_invalid,
        test_04_probe_generation_deterministic,
        test_05_probe_preparation,
        test_06_named_arrays,
        test_07_black_box,
        test_08_path_never_loaded,
        test_09_unknown_object,
        test_10_torch_parameter_statistics,
        test_11_torch_structure,
        test_12_activation_capture,
        test_13_hooks_removed,
        test_14_training_state_restored,
        test_15_modified_model_detected,
        test_16_identical_models_no_deviation,
        test_17_probe_mismatch_incompatible,
        test_18_invalid_thresholds,
        test_19_no_timestamps,
        test_20_no_network_imports,
        test_21_torchscript_requires_trust,
        test_22_fingerprint_deterministic,
        test_23_invalid_task_comparison,
    ]

    passed = 0
    failed = 0

    for test in tests:
        if run(test.__name__, test):
            passed += 1
        else:
            failed += 1

    print(
        f"Ran {len(tests)} tests: "
        f"{passed} passed, {failed} failed"
    )

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
