"""Real .onnx file inference validation for TRACER-CV.

These tests build a tiny synthetic ONNX model in memory, save it to a
temporary file, and run actual inference through the existing adapter.
No model is downloaded; all computation is local and offline.
"""
from __future__ import annotations

import hashlib
import os

import numpy as np
import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# ---------------------------------------------------------------------------
# Synthetic model builder
# ---------------------------------------------------------------------------

def _make_tiny_onnx(path, *, num_classes: int = 3, input_h: int = 32, input_w: int = 32):
    """Build and save a minimal valid ONNX classification model.

    Architecture: Flatten [N,3,H,W] → [N,3*H*W], then Gemm → [N, num_classes].
    Uses only standard opset-17 ops with embedded weights; no external data.
    """
    import onnx
    from onnx import TensorProto, helper, numpy_helper

    in_features = 3 * input_h * input_w
    rng = np.random.default_rng(26228)
    W = (rng.standard_normal((in_features, num_classes)) * 0.01).astype(np.float32)
    b = np.zeros(num_classes, dtype=np.float32)

    W_init = numpy_helper.from_array(W, name="W")
    b_init = numpy_helper.from_array(b, name="b")
    shape_vals = np.array([-1, in_features], dtype=np.int64)
    shape_init = numpy_helper.from_array(shape_vals, name="reshape_shape")

    input_t = helper.make_tensor_value_info(
        "input", TensorProto.FLOAT, [None, 3, input_h, input_w]
    )
    output_t = helper.make_tensor_value_info(
        "output", TensorProto.FLOAT, [None, num_classes]
    )

    reshape_node = helper.make_node(
        "Reshape", inputs=["input", "reshape_shape"], outputs=["flat"]
    )
    gemm_node = helper.make_node(
        "Gemm", inputs=["flat", "W", "b"], outputs=["output"]
    )

    graph = helper.make_graph(
        [reshape_node, gemm_node],
        "tiny_classifier",
        [input_t],
        [output_t],
        initializer=[W_init, b_init, shape_init],
    )
    model = helper.make_model(
        graph, opset_imports=[helper.make_opsetid("", 17)]
    )
    model.ir_version = 8
    onnx.checker.check_model(model)
    onnx.save(model, str(path))
    return path


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def onnx_model_path(tmp_path_factory):
    """A real, saved .onnx file in a temporary directory."""
    td = tmp_path_factory.mktemp("onnx_models")
    path = td / "tiny_classifier.onnx"
    _make_tiny_onnx(path, num_classes=3, input_h=32, input_w=32)
    return path


@pytest.fixture(scope="module")
def loaded_adapter(onnx_model_path):
    """The adapter loaded from the real .onnx file."""
    from backend.engines.model.onnx_adapter import try_load_onnx_adapter
    result = try_load_onnx_adapter(onnx_model_path)
    return result


# ---------------------------------------------------------------------------
# B1 identity on a real .onnx file
# ---------------------------------------------------------------------------

def test_onnx_real_b1_identity(onnx_model_path):
    """B1 inspect_model identifies a real .onnx file correctly."""
    from backend.engines.model.identity import inspect_model
    result = inspect_model(onnx_model_path)
    assert result["format"] == "ONNX", f"Expected ONNX, got {result['format']}"
    assert len(result["sha256"]) == 64
    assert all(c in "0123456789abcdef" for c in result["sha256"])
    assert result["sha256"] == hashlib.sha256(onnx_model_path.read_bytes()).hexdigest()
    assert result["file_name"] == "tiny_classifier.onnx"


def test_onnx_real_b1_identity_is_deterministic(onnx_model_path):
    """B1 identity hash is stable across multiple calls on the same file."""
    from backend.engines.model.identity import inspect_model
    a = inspect_model(onnx_model_path)
    b = inspect_model(onnx_model_path)
    assert a["sha256"] == b["sha256"]
    assert a["model_id"] == b["model_id"]


# ---------------------------------------------------------------------------
# Adapter loading
# ---------------------------------------------------------------------------

def test_try_load_onnx_adapter_succeeds_on_valid_model(loaded_adapter):
    """try_load_onnx_adapter returns status='loaded' for a valid local model."""
    assert loaded_adapter["status"] == "loaded", (
        f"Expected loaded, got {loaded_adapter['status']}: {loaded_adapter.get('reason')}"
    )


def test_loaded_adapter_exposes_class_count(loaded_adapter):
    """Loaded adapter reports the correct class count."""
    assert loaded_adapter["status"] == "loaded"
    adapter = loaded_adapter["adapter"]
    assert adapter.class_count == 3


def test_try_load_onnx_adapter_fails_gracefully_on_missing_file(tmp_path):
    """try_load_onnx_adapter returns error status for a missing file."""
    from backend.engines.model.onnx_adapter import try_load_onnx_adapter
    result = try_load_onnx_adapter(tmp_path / "nonexistent.onnx")
    assert result["status"] in {"unavailable", "error"}
    assert "reason" in result


def test_try_load_onnx_adapter_fails_on_non_onnx_file(tmp_path):
    """try_load_onnx_adapter rejects files that are not valid ONNX."""
    bad = tmp_path / "not_a_model.onnx"
    bad.write_bytes(b"this is not a valid ONNX model")
    from backend.engines.model.onnx_adapter import try_load_onnx_adapter
    result = try_load_onnx_adapter(bad)
    assert result["status"] in {"unavailable", "error"}


# ---------------------------------------------------------------------------
# Real inference
# ---------------------------------------------------------------------------

def test_onnx_real_inference_produces_output(loaded_adapter):
    """Real ONNX Runtime inference produces a valid output array."""
    assert loaded_adapter["status"] == "loaded"
    adapter = loaded_adapter["adapter"]
    batch = np.full((2, 32, 32, 3), 120, dtype=np.uint8)
    result = adapter.predict(batch)
    assert len(result.predicted_classes) == 2
    assert result.probabilities.shape == (2, 3)


def test_onnx_real_inference_is_deterministic(loaded_adapter):
    """Real ONNX Runtime inference is deterministic across runs."""
    assert loaded_adapter["status"] == "loaded"
    adapter = loaded_adapter["adapter"]
    batch = np.full((3, 32, 32, 3), 64, dtype=np.uint8)
    first = adapter.predict(batch)
    second = adapter.predict(batch)
    np.testing.assert_array_equal(first.predicted_classes, second.predicted_classes)
    np.testing.assert_allclose(first.probabilities, second.probabilities, rtol=1e-5)


def test_onnx_real_inference_batch_size_preserved(loaded_adapter):
    """Each image in the batch gets exactly one prediction."""
    assert loaded_adapter["status"] == "loaded"
    adapter = loaded_adapter["adapter"]
    for n in (1, 4, 7):
        batch = np.zeros((n, 32, 32, 3), dtype=np.uint8)
        result = adapter.predict(batch)
        assert len(result.predicted_classes) == n, f"Expected {n}, got {len(result.predicted_classes)}"


def test_onnx_real_scores_are_finite(loaded_adapter):
    """predict_scores returns a finite array for a normal input."""
    assert loaded_adapter["status"] == "loaded"
    adapter = loaded_adapter["adapter"]
    batch = np.ones((2, 32, 32, 3), dtype=np.uint8) * 128
    scores = adapter.predict_scores(batch)
    assert np.all(np.isfinite(scores)), "Scores contained non-finite values"
    assert scores.shape == (2, 3)


def test_onnx_real_rejects_non_uint8_input(loaded_adapter):
    """predict_scores rejects float32 input (must be uint8)."""
    assert loaded_adapter["status"] == "loaded"
    adapter = loaded_adapter["adapter"]
    bad_batch = np.zeros((1, 32, 32, 3), dtype=np.float32)
    with pytest.raises(ValueError):
        adapter.predict_scores(bad_batch)


# ---------------------------------------------------------------------------
# B2 behavioral fingerprint through real ONNX adapter
# ---------------------------------------------------------------------------

def test_onnx_real_b2_behavioral_fingerprint(loaded_adapter):
    """B2 behavioral fingerprint runs end-to-end through a real ONNX adapter."""
    assert loaded_adapter["status"] == "loaded"
    adapter = loaded_adapter["adapter"]
    from backend.engines.model.behavioral_fingerprint import compute_behavioral_fingerprint
    probe_images = [np.full((32, 32, 3), v, dtype=np.uint8) for v in (64, 128, 200)]
    model_id = "sha256:" + "a" * 64
    result = compute_behavioral_fingerprint(probe_images, adapter, model_id=model_id)
    assert result["status"] == "completed", f"B2 status: {result['status']}"
    assert result["probe_count"] > 0


def test_onnx_real_b2_fingerprint_is_deterministic(loaded_adapter):
    """B2 fingerprint is the same when run twice on the same model and inputs."""
    assert loaded_adapter["status"] == "loaded"
    adapter = loaded_adapter["adapter"]
    from backend.engines.model.behavioral_fingerprint import compute_behavioral_fingerprint
    probe_images = [np.full((32, 32, 3), 100, dtype=np.uint8)]
    model_id = "sha256:" + "b" * 64
    r1 = compute_behavioral_fingerprint(probe_images, adapter, model_id=model_id)
    r2 = compute_behavioral_fingerprint(probe_images, adapter, model_id=model_id)
    assert r1["probe_count"] == r2["probe_count"]
    assert r1["status"] == r2["status"]


# ---------------------------------------------------------------------------
# Different model files have different B1 identity
# ---------------------------------------------------------------------------

def test_onnx_modified_model_has_different_b1_hash(tmp_path):
    """Two different .onnx files have different B1 SHA-256 identity."""
    from backend.engines.model.identity import inspect_model
    path_a = tmp_path / "model_a.onnx"
    path_b = tmp_path / "model_b.onnx"
    _make_tiny_onnx(path_a, num_classes=2, input_h=32, input_w=32)
    _make_tiny_onnx(path_b, num_classes=4, input_h=32, input_w=32)
    id_a = inspect_model(path_a)
    id_b = inspect_model(path_b)
    assert id_a["sha256"] != id_b["sha256"], "Different models must have different B1 hashes"
