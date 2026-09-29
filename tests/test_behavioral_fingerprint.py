"""
Standalone tests for TRACER-CV B2 (behavioral fingerprint).

Run:  python -m tests.test_behavioral_fingerprint
No pytest, no network, no downloads, no torch required.

FakeClassificationAdapter below is a TEST-ONLY adapter. It derives class
probabilities from simple image statistics with fixed random weights. It is
NOT a neural network and does not represent any real model.
"""
import ast
import copy
import inspect
import json
import math
import os
import socket
import sys
import tempfile
import traceback
import zipfile

import numpy as np

from backend.engines.model import behavioral_fingerprint as bf


# ------------------------------ test fixtures ------------------------------
class FakeClassificationAdapter(bf.ClassificationModelAdapter):
    """TEST ONLY: deterministic fake classifier built from image statistics."""
    name = "fake_test_adapter (TEST ONLY, not a real model)"

    def __init__(self, class_count=4, weight_seed=1234):
        self.class_count = class_count
        self._w = np.random.default_rng(weight_seed).normal(0.0, 4.0, size=(5, class_count))

    def predict(self, batch_images):
        x = np.asarray(batch_images, dtype=np.float64) / 255.0
        half = x.shape[2] // 2
        feats = np.stack([
            x[..., 0].mean(axis=(1, 2)),
            x[..., 1].mean(axis=(1, 2)),
            x[..., 2].mean(axis=(1, 2)),
            x.std(axis=(1, 2, 3)),
            x[:, :, :half, :].mean(axis=(1, 2, 3)) - x[:, :, half:, :].mean(axis=(1, 2, 3)),
        ], axis=1)
        logits = feats @ self._w
        z = logits - logits.max(axis=1, keepdims=True)
        e = np.exp(z)
        return bf.predictions_from_probabilities(e / e.sum(axis=1, keepdims=True))


class LabelOnlyFakeAdapter(bf.ClassificationModelAdapter):
    """TEST ONLY: exposes labels but no probabilities (black-box style)."""
    name = "label_only_fake_adapter (TEST ONLY)"
    class_count = 4

    def __init__(self):
        self._inner = FakeClassificationAdapter(class_count=4)

    def predict(self, batch_images):
        return bf.predictions_from_labels(self._inner.predict(batch_images).predicted_classes)


class RaisingAdapter(bf.ClassificationModelAdapter):
    name = "raising_adapter (TEST ONLY)"

    def predict(self, batch_images):
        raise RuntimeError("boom")


class WrongLengthAdapter(bf.ClassificationModelAdapter):
    name = "wrong_length_adapter (TEST ONLY)"

    def predict(self, batch_images):
        return bf.predictions_from_labels(np.zeros(len(batch_images) + 1, dtype=np.int64))


def make_images(n=12, size=32, seed=7):
    rng = np.random.default_rng(seed)
    yy, xx = np.mgrid[0:size, 0:size]
    out = []
    for i in range(n):
        r = 127.5 + 127.5 * np.sin(xx / (3.0 + i % 4) + 0.5 * i)
        g = 127.5 + 127.5 * np.cos(yy / (4.0 + i % 3) - 0.5 * i)
        b = (xx * (i + 1) + yy * (12 - i)) % 256
        base = np.stack([r, g, b], axis=-1) * 0.8 + rng.normal(0, 5, (size, size, 3))
        out.append(np.clip(base, 0, 255).astype(np.uint8))
    return out


IMAGES = make_images()


def run(seed=bf.DEFAULT_SEED, adapter=None, **kw):
    return bf.compute_behavioral_fingerprint(IMAGES, adapter or FakeClassificationAdapter(), seed=seed, **kw)


def key_paths(obj, found=None):
    found = [] if found is None else found
    if isinstance(obj, dict):
        for k, v in obj.items():
            found.append(str(k))
            key_paths(v, found)
    elif isinstance(obj, list):
        for v in obj:
            key_paths(v, found)
    return found


# --------------------------------- tests -----------------------------------
def test_01_deterministic_probe_generation():
    assert bf.default_probe_battery(5) == bf.default_probe_battery(5)
    for spec in bf.default_probe_battery():
        a = bf.apply_probe(spec, IMAGES[0], 3)
        b = bf.apply_probe(spec, IMAGES[0], 3)
        assert np.array_equal(a, b), spec.name


def test_02_expected_probe_count():
    battery = bf.default_probe_battery()
    names = [p.name for p in battery]
    assert len(battery) == 10 and len(set(names)) == 10
    expected = {"clean", "horizontal_flip", "brightness_decrease", "brightness_increase",
                "contrast_decrease", "contrast_increase", "gaussian_noise", "mild_blur",
                "small_translation", "jpeg_quality_degradation"}
    assert set(names) == expected
    assert names[0] == "clean"


def test_03_transforms_preserve_dimensions():
    rng = np.random.default_rng(0)
    img = rng.integers(0, 256, size=(24, 40, 3), dtype=np.uint8)   # non-square
    for spec in bf.default_probe_battery():
        out = bf.apply_probe(spec, img, 0)
        assert out.shape == img.shape, spec.name
        assert out.dtype == np.uint8, spec.name


def test_04_same_input_same_output_no_mutation():
    img = IMAGES[1].copy()
    before = img.copy()
    for spec in bf.default_probe_battery():
        bf.apply_probe(spec, img, 0)
    assert np.array_equal(img, before), "input was mutated"
    assert np.array_equal(bf.horizontal_flip(bf.horizontal_flip(img)), img)
    assert np.array_equal(bf.brightness(img, 1.0), img)
    assert np.array_equal(bf.translation(img, 0, 0), img)
    shifted = bf.translation(img, 2, 0)
    assert np.array_equal(shifted[:, 2:], img[:, :-2])
    assert bf.horizontal_flip(img) is not img


def test_05_adapter_interface():
    try:
        bf.ClassificationModelAdapter()
        raise AssertionError("abstract adapter should not instantiate")
    except TypeError:
        pass
    ad = FakeClassificationAdapter()
    batch = np.stack(IMAGES)
    out = ad.predict(batch)
    assert isinstance(out, bf.ClassificationPredictions)
    assert out.predicted_classes.shape == (12,)
    assert out.probabilities.shape == (12, 4)
    assert np.allclose(out.probabilities.sum(axis=1), 1.0)
    assert np.allclose(out.confidence, out.probabilities.max(axis=1))
    assert out.entropy.shape == (12,)
    again = FakeClassificationAdapter().predict(batch)
    assert np.array_equal(out.predicted_classes, again.predicted_classes)
    assert np.allclose(out.probabilities, again.probabilities)


def test_06_clean_prediction_statistics():
    res = run()
    assert res["status"] == "completed"
    clean = res["probes"][0]
    assert clean["probe"] == "clean" and clean["images"] == 12
    assert clean["prediction_agreement"] == 1.0
    assert sum(clean["prediction_distribution"].values()) == 12
    assert sum(clean["class_histogram"]) == 12
    assert 0.25 - 1e-9 <= clean["mean_confidence"] <= 1.0
    assert 0.0 <= clean["mean_entropy"] <= math.log(4) + 1e-6
    assert abs(sum(clean["mean_probability_vector"]) - 1.0) < 1e-4
    assert res["baseline"] == clean


def test_07_entropy_calculation():
    assert abs(bf.shannon_entropy([0.25] * 4) - math.log(4)) < 1e-12
    h = bf.shannon_entropy([1.0, 0.0, 0.0])
    assert h == 0.0 and not math.isnan(h)
    assert abs(bf.shannon_entropy([0.5, 0.5, 0.0]) - math.log(2)) < 1e-12
    batch = bf.shannon_entropy(np.array([[0.5, 0.5], [1.0, 0.0]]))
    assert batch.shape == (2,) and abs(batch[0] - math.log(2)) < 1e-12 and batch[1] == 0.0
    assert np.allclose(bf.normalize_probabilities([[2.0, 2.0]]), [[0.5, 0.5]])
    for bad in ([[-0.1, 1.1]], [[0.0, 0.0]], [[float("nan"), 1.0]]):
        try:
            bf.normalize_probabilities(bad)
            raise AssertionError("expected ValueError")
        except ValueError:
            pass


def test_08_prediction_agreement():
    assert bf.prediction_agreement([0, 1, 2, 3], [0, 1, 0, 0]) == 0.5
    assert bf.prediction_agreement([1, 1], [1, 1]) == 1.0
    for a, b in (([0, 1], [0]), ([], [])):
        try:
            bf.prediction_agreement(a, b)
            raise AssertionError("expected ValueError")
        except ValueError:
            pass


def test_09_fingerprint_structure():
    res = run()
    for k in ("status", "method", "task", "probe_count", "model", "dataset", "config",
              "baseline", "probes", "fingerprint", "limitations"):
        assert k in res, k
    assert res["method"] == "deterministic classification behavioral fingerprint"
    assert res["task"] == "image_classification"
    assert res["probe_count"] == 10 == len(res["probes"])
    for k in ("model_id", "adapter", "class_count"):
        assert k in res["model"]
    assert res["model"]["class_count"] == 4
    for p in res["probes"]:
        for k in ("probe", "params", "images", "prediction_agreement", "mean_confidence",
                  "confidence_std", "mean_entropy", "prediction_distribution",
                  "mean_probability_vector", "class_histogram"):
            assert k in p, (p["probe"], k)
    noise = [p for p in res["probes"] if p["probe"] == "gaussian_noise"][0]
    assert noise["params"] == {"sigma": 8.0, "seed": bf.DEFAULT_SEED}
    assert len(res["fingerprint"]["digest"]) == 64
    bf.canonical_json(res)                      # must be strictly JSON-serializable
    assert len(res["limitations"]) >= 10


def test_10_reference_vs_reference_no_deviations():
    ref = run()
    cmp = bf.compare_fingerprints(ref, copy.deepcopy(ref))
    assert cmp["status"] == "completed"
    assert cmp["summary"]["deviation_count"] == 0 and cmp["deviations"] == []
    assert cmp["summary"]["finding_count"] == 10 * 5
    assert all(f["status"] == "within_threshold" for f in cmp["findings"])
    for banned in ("score", "verdict", "probability_malicious", "ranking"):
        assert banned not in cmp


def test_11_altered_fingerprint_detected():
    ref = run()
    alt = copy.deepcopy(ref)
    probe = [p for p in alt["probes"] if p["probe"] == "brightness_increase"][0]
    ref_probe = [p for p in ref["probes"] if p["probe"] == "brightness_increase"][0]
    a0, c0 = ref_probe["prediction_agreement"], ref_probe["mean_confidence"]
    probe["prediction_agreement"] = round(a0 - 0.5, 6) if a0 >= 0.5 else round(a0 + 0.5, 6)
    probe["mean_confidence"] = round(c0 - 0.2, 6) if c0 >= 0.5 else round(c0 + 0.2, 6)
    cmp = bf.compare_fingerprints(ref, alt)
    assert cmp["status"] == "completed"
    assert cmp["summary"]["deviation_count"] >= 2
    assert cmp["summary"]["probes_with_deviation"] == ["brightness_increase"]
    f = [d for d in cmp["deviations"] if d["metric"] == "prediction_agreement"][0]
    assert f["status"] == "deviation" and abs(f["absolute_difference"] - 0.5) < 1e-6
    assert f["reference"] == a0 and f["assessed"] == probe["prediction_agreement"]
    # thresholds are explicit configuration
    loose = bf.ComparisonThresholds(prediction_agreement=0.6, mean_confidence=0.6,
                                    prediction_distribution_tv=1.0, mean_probability_js=1.0)
    cmp2 = bf.compare_fingerprints(ref, alt, thresholds=loose)
    assert cmp2["summary"]["deviation_count"] == 0


def test_12_invalid_and_empty_input():
    ad = FakeClassificationAdapter()
    cases = [
        (bf.compute_behavioral_fingerprint([], ad), "empty_input"),
        (bf.compute_behavioral_fingerprint(None, ad), "empty_input"),
        (bf.compute_behavioral_fingerprint([np.zeros((4, 4), dtype=np.uint8)], ad), "invalid_input"),
        (bf.compute_behavioral_fingerprint([np.zeros((4, 4, 3), dtype=np.float32)], ad), "invalid_input"),
        (bf.compute_behavioral_fingerprint(
            [np.zeros((4, 4, 3), dtype=np.uint8), np.zeros((5, 5, 3), dtype=np.uint8)], ad), "invalid_input"),
        (bf.compute_behavioral_fingerprint(IMAGES, None), "invalid_adapter"),
        (bf.compute_behavioral_fingerprint(IMAGES, RaisingAdapter()), "adapter_error"),
        (bf.compute_behavioral_fingerprint(IMAGES, WrongLengthAdapter()), "invalid_adapter_output"),
        (bf.compute_behavioral_fingerprint(IMAGES, ad, batch_size=0), "invalid_input"),
    ]
    for res, code in cases:
        assert res["status"] == "error", code
        assert res["error"]["code"] == code, (code, res["error"])
    cmp = bf.compare_fingerprints(cases[0][0], run())
    assert cmp["status"] == "incompatible" and cmp["compatibility_errors"]


class _NoNetwork:
    def __enter__(self):
        self._orig = (socket.socket.connect, socket.getaddrinfo, socket.create_connection)

        def blocked(*args, **kwargs):
            raise AssertionError("network access attempted")

        socket.socket.connect = blocked
        socket.getaddrinfo = blocked
        socket.create_connection = blocked
        return self

    def __exit__(self, *exc):
        socket.socket.connect, socket.getaddrinfo, socket.create_connection = self._orig
        return False


def test_13_no_network():
    with _NoNetwork():
        res = run()
        cmp = bf.compare_fingerprints(res, copy.deepcopy(res))
    assert res["status"] == "completed" and cmp["status"] == "completed"
    tree = ast.parse(inspect.getsource(bf))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    banned = {"socket", "urllib", "http", "requests", "subprocess", "ftplib", "smtplib", "httpx"}
    assert not (imported & banned), imported & banned


def test_14_deterministic_seed():
    img = IMAGES[0]
    a = bf.gaussian_noise(img, 8.0, 5)
    assert np.array_equal(a, bf.gaussian_noise(img, 8.0, 5))
    assert not np.array_equal(a, bf.gaussian_noise(img, 8.0, 6))
    r1, r2, r3 = run(seed=11), run(seed=11), run(seed=12)
    assert bf.canonical_json(r1) == bf.canonical_json(r2)
    assert r1["fingerprint"]["digest"] == r2["fingerprint"]["digest"]
    assert r1["fingerprint"]["probe_config_digest"] != r3["fingerprint"]["probe_config_digest"]
    noise = [p for p in r1["probes"] if p["probe"] == "gaussian_noise"][0]
    assert noise["params"]["seed"] == 11


def test_15_label_only_adapter():
    res = run(adapter=LabelOnlyFakeAdapter())
    assert res["status"] == "completed"
    assert res["model"]["probabilities_available"] is False
    for p in res["probes"]:
        assert p["mean_confidence"] is None and p["mean_entropy"] is None
        assert p["mean_probability_vector"] is None
        assert p["prediction_agreement"] is not None
    assert res["notes"]
    cmp = bf.compare_fingerprints(res, copy.deepcopy(res))
    assert cmp["status"] == "completed" and cmp["summary"]["deviation_count"] == 0
    na = [f for f in cmp["findings"] if f["status"] == "not_available"]
    assert len(na) == 10 * 3     # confidence, entropy, JS per probe


def test_16_incompatible_fingerprints():
    ref = run()
    alt = copy.deepcopy(ref)
    alt["model"]["class_count"] = 5
    cmp = bf.compare_fingerprints(ref, alt)
    assert cmp["status"] == "incompatible"
    assert any("class_count" in e for e in cmp["compatibility_errors"])
    alt2 = copy.deepcopy(ref)
    alt2["fingerprint"]["dataset_digest"] = "0" * 64
    assert bf.compare_fingerprints(ref, alt2)["status"] == "incompatible"
    assert bf.compare_fingerprints(ref, alt2, allow_dataset_mismatch=True)["status"] == "completed"
    other = run(adapter=FakeClassificationAdapter(class_count=6))
    assert bf.compare_fingerprints(ref, other)["status"] == "incompatible"


def test_17_distance_metrics():
    assert bf.total_variation_distance([0.5, 0.5], [0.5, 0.5]) == 0.0
    assert abs(bf.total_variation_distance([1, 0], [0, 1]) - 1.0) < 1e-12
    assert abs(bf.total_variation_distance([3, 1], [1, 3]) - 0.5) < 1e-12
    assert bf.jensen_shannon_divergence([0.3, 0.7], [0.3, 0.7]) == 0.0
    assert abs(bf.jensen_shannon_divergence([1, 0], [0, 1]) - 1.0) < 1e-9
    a, b = [0.2, 0.8], [0.6, 0.4]
    assert abs(bf.jensen_shannon_divergence(a, b) - bf.jensen_shannon_divergence(b, a)) < 1e-12
    try:
        bf.jensen_shannon_divergence([0.5, 0.5], [1 / 3] * 3)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_18_torch_optional_and_safe_loading():
    assert not hasattr(bf, "torch"), "torch must not be imported at module level"
    try:
        bf.TorchScriptClassificationAdapter(object(), output_type="raw")
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    with tempfile.TemporaryDirectory() as d:
        pkl = os.path.join(d, "model.pkl")
        with open(pkl, "wb") as fh:
            fh.write(b"not a real model; never unpickled")
        assert bf.try_load_torchscript_adapter(pkl, output_type="logits")["status"] == "unsupported"
        junk = os.path.join(d, "model.pt")
        with open(junk, "wb") as fh:
            fh.write(b"junk")
        assert bf.try_load_torchscript_adapter(junk, output_type="logits")["status"] == "unsupported"
        ckpt = os.path.join(d, "checkpoint.pth")
        with zipfile.ZipFile(ckpt, "w") as zf:               # checkpoint-like: data.pkl, no code/
            zf.writestr("archive/data.pkl", b"\x80\x02.")
        res = bf.try_load_torchscript_adapter(ckpt, output_type="logits")
        assert res["status"] == "unsupported" and "adapter" not in res
        missing = bf.try_load_torchscript_adapter(os.path.join(d, "missing.pt"), output_type="logits")
        assert missing["status"] == "error"


def test_19_model_id_preserved():
    ident = {"model_id": "abc123", "sha256": "f" * 64}
    assert run(model_identity=ident)["model"]["model_id"] == "abc123"
    assert run()["model"]["model_id"] is None
    assert run(model_identity=ident, model_id="explicit")["model"]["model_id"] == "explicit"


def test_20_no_timestamps():
    bad = [k for k in key_paths(run()) if any(t in k.lower() for t in ("time", "date", "created", "generated"))]
    assert not bad, bad


# --------------------------------- runner ----------------------------------
def main():
    tests = sorted((n, f) for n, f in globals().items() if n.startswith("test_") and callable(f))
    passed = failed = 0
    for name, fn in tests:
        try:
            fn()
            print("PASS", name)
            passed += 1
        except Exception:
            print("FAIL", name)
            traceback.print_exc()
            failed += 1
    print("Ran %d tests: %d passed, %d failed" % (len(tests), passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
