"""
TRACER-CV B2 - Model Behavioral Fingerprint (image classification only).

Builds a reproducible behavioral fingerprint of a classification model by
running it on a fixed, deterministic battery of image probes. The fingerprint
is EVIDENCE for comparison against a trusted reference fingerprint. It does
NOT prove a model is malicious, backdoored, compromised, or safe.

Core dependencies: standard library, NumPy, Pillow.
PyTorch is OPTIONAL and only imported lazily inside the TorchScript adapter.

Global side effect (documented): compute_behavioral_fingerprint() seeds
Python's `random` and NumPy's legacy global RNG with the supplied seed so that
adapters relying on global RNGs are reproducible. All probe randomness itself
uses local, explicitly seeded generators.
"""
from __future__ import annotations

import abc
import copy
import hashlib
import io
import json
import math
import os
import random
import zipfile
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Sequence

import numpy as np
from PIL import Image, ImageFilter

ENGINE_VERSION = "b2-1.0"
METHOD = "deterministic classification behavioral fingerprint"
COMPARISON_METHOD = "behavioral fingerprint comparison"
TASK = "image_classification"
DEFAULT_SEED = 1337
DECIMALS = 6

LIMITATIONS: List[str] = [
    "Behavioral fingerprinting is model- and dataset-dependent.",
    "A difference between fingerprints does not prove malicious modification.",
    "Similar fingerprints do not prove model integrity.",
    "Probe coverage is limited to the listed transformations.",
    "Classification-only in this version (no detection or segmentation).",
    "Black-box models may expose only predictions/confidence.",
    "Some adapters may not expose full probability distributions; "
    "probability-based statistics are then reported as unavailable.",
    "Floating-point and backend differences can affect exact reproducibility.",
    "Probe parameters influence the observed behavior.",
    "This does not reconstruct hidden triggers.",
    "This does not prove the absence of backdoors.",
]


# --------------------------------------------------------------------------
# Errors and serialization helpers
# --------------------------------------------------------------------------
class BehavioralFingerprintError(Exception):
    """Internal error carrying a machine-readable code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class UnsupportedModelError(Exception):
    """Raised when a model file cannot be loaded without unsafe deserialization."""


def _r(x: Any) -> Optional[float]:
    """Deterministic rounding for serialization (also normalizes -0.0)."""
    if x is None:
        return None
    v = round(float(x), DECIMALS)
    return 0.0 if v == 0 else v


def canonical_json(obj: Any) -> str:
    """Canonical JSON: sorted keys, compact separators, no NaN/Infinity."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Image handling and deterministic transforms (Pillow + NumPy)
# All transforms return NEW uint8 HxWx3 arrays and never mutate the input.
# --------------------------------------------------------------------------
def to_uint8_rgb(image: Any) -> np.ndarray:
    """Convert a PIL image or uint8 HxWx3 array into a fresh uint8 array."""
    if isinstance(image, Image.Image):
        return np.array(image.convert("RGB"), dtype=np.uint8, copy=True)
    arr = np.asarray(image)
    if arr.dtype != np.uint8:
        raise ValueError("images must be uint8 arrays or PIL images (got dtype %s)" % arr.dtype)
    if arr.ndim != 3 or arr.shape[2] != 3:
        raise ValueError("images must have shape HxWx3 (got %s)" % (arr.shape,))
    if arr.shape[0] < 1 or arr.shape[1] < 1:
        raise ValueError("images must be non-empty")
    return np.array(arr, dtype=np.uint8, copy=True)


def _to_u8(a: np.ndarray) -> np.ndarray:
    return np.clip(np.rint(a), 0, 255).astype(np.uint8)


def identity(image: Any) -> np.ndarray:
    return to_uint8_rgb(image)


def horizontal_flip(image: Any) -> np.ndarray:
    a = to_uint8_rgb(image)
    return np.ascontiguousarray(a[:, ::-1, :])


def brightness(image: Any, factor: float) -> np.ndarray:
    a = to_uint8_rgb(image).astype(np.float64)
    return _to_u8(a * float(factor))


def contrast(image: Any, factor: float) -> np.ndarray:
    a = to_uint8_rgb(image).astype(np.float64)
    m = a.mean()
    return _to_u8((a - m) * float(factor) + m)


def gaussian_noise(image: Any, sigma: float, seed: int) -> np.ndarray:
    a = to_uint8_rgb(image).astype(np.float64)
    rng = np.random.default_rng(int(seed))
    return _to_u8(a + rng.normal(0.0, float(sigma), size=a.shape))


def blur(image: Any, radius: float) -> np.ndarray:
    a = to_uint8_rgb(image)
    out = Image.fromarray(a).filter(ImageFilter.GaussianBlur(radius=float(radius)))
    return np.array(out.convert("RGB"), dtype=np.uint8, copy=True)


def translation(image: Any, dx: int, dy: int) -> np.ndarray:
    """Shift content by (dx, dy) pixels, replicating edge pixels. Size preserved."""
    a = to_uint8_rgb(image)
    dx, dy = int(dx), int(dy)
    h, w = a.shape[:2]
    pad = max(abs(dx), abs(dy))
    if pad == 0:
        return a
    p = np.pad(a, ((pad, pad), (pad, pad), (0, 0)), mode="edge")
    y0, x0 = pad - dy, pad - dx          # out[y, x] = in[y - dy, x - dx]
    return np.ascontiguousarray(p[y0:y0 + h, x0:x0 + w, :])


def jpeg_degradation(image: Any, quality: int) -> np.ndarray:
    """Round-trip through in-memory JPEG compression at the given quality."""
    a = to_uint8_rgb(image)
    buf = io.BytesIO()
    Image.fromarray(a).save(buf, format="JPEG", quality=int(quality))
    buf.seek(0)
    with Image.open(buf) as im:
        return np.array(im.convert("RGB"), dtype=np.uint8, copy=True)


TRANSFORMS = {
    "identity": identity,
    "horizontal_flip": horizontal_flip,
    "brightness": brightness,
    "contrast": contrast,
    "gaussian_noise": gaussian_noise,
    "blur": blur,
    "translation": translation,
    "jpeg_degradation": jpeg_degradation,
}


@dataclass(frozen=True)
class ProbeSpec:
    name: str
    transform: str
    params: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "transform": self.transform, "params": dict(self.params)}


def default_probe_battery(seed: int = DEFAULT_SEED) -> List[ProbeSpec]:
    """The fixed 10-probe battery. All parameters are recorded in the result."""
    return [
        ProbeSpec("clean", "identity", {}),
        ProbeSpec("horizontal_flip", "horizontal_flip", {}),
        ProbeSpec("brightness_decrease", "brightness", {"factor": 0.7}),
        ProbeSpec("brightness_increase", "brightness", {"factor": 1.3}),
        ProbeSpec("contrast_decrease", "contrast", {"factor": 0.6}),
        ProbeSpec("contrast_increase", "contrast", {"factor": 1.5}),
        ProbeSpec("gaussian_noise", "gaussian_noise", {"sigma": 8.0, "seed": int(seed)}),
        ProbeSpec("mild_blur", "blur", {"radius": 1.0}),
        ProbeSpec("small_translation", "translation", {"dx": 2, "dy": 2}),
        ProbeSpec("jpeg_quality_degradation", "jpeg_degradation", {"quality": 30}),
    ]


def apply_probe(spec: ProbeSpec, image: Any, index: int = 0) -> np.ndarray:
    """Apply one probe to one image. Noise seeds are (base seed + image index)."""
    fn = TRANSFORMS.get(spec.transform)
    if fn is None:
        raise ValueError("unknown transform: %r" % spec.transform)
    params = dict(spec.params)
    if spec.transform == "gaussian_noise":
        params["seed"] = int(params.get("seed", 0)) + int(index)
    return fn(image, **params)


# --------------------------------------------------------------------------
# Numerics
# --------------------------------------------------------------------------
def normalize_probabilities(p: Any) -> np.ndarray:
    """Validate an N x C probability matrix and renormalize each row to sum 1."""
    a = np.asarray(p, dtype=np.float64)
    if a.ndim != 2 or a.shape[1] < 1:
        raise ValueError("probabilities must have shape (N, C)")
    if not np.all(np.isfinite(a)) or np.any(a < 0):
        raise ValueError("probabilities must be finite and non-negative")
    s = a.sum(axis=1, keepdims=True)
    if np.any(s <= 0):
        raise ValueError("each probability row must have a positive sum")
    return a / s


def shannon_entropy(p: Any) -> Any:
    """H(p) = -sum(p_i * ln p_i) with log(0) protection. Accepts 1-D or 2-D."""
    a = np.asarray(p, dtype=np.float64)
    single = a.ndim == 1
    a2 = np.atleast_2d(a)
    safe = np.where(a2 > 0, a2, 1.0)
    h = np.abs(-np.sum(np.where(a2 > 0, a2 * np.log(safe), 0.0), axis=1))
    return float(h[0]) if single else h


def prediction_agreement(clean_predictions: Any, probe_predictions: Any) -> float:
    """Fraction of probe predictions equal to the clean prediction."""
    c = np.asarray(clean_predictions)
    q = np.asarray(probe_predictions)
    if c.shape != q.shape or c.ndim != 1:
        raise ValueError("prediction arrays must be 1-D and equal length")
    if c.size == 0:
        raise ValueError("cannot compute agreement over zero samples")
    return float(np.sum(c == q)) / float(c.size)


def total_variation_distance(p: Sequence[float], q: Sequence[float]) -> float:
    """TV = 0.5 * sum|p_i - q_i| after normalizing each vector to sum 1."""
    a = np.asarray(p, dtype=np.float64)
    b = np.asarray(q, dtype=np.float64)
    if a.shape != b.shape or a.ndim != 1:
        raise ValueError("vectors must be 1-D and equal length")
    if a.sum() <= 0 or b.sum() <= 0:
        raise ValueError("vectors must have a positive sum")
    a, b = a / a.sum(), b / b.sum()
    return float(0.5 * np.abs(a - b).sum())


def jensen_shannon_divergence(p: Sequence[float], q: Sequence[float]) -> float:
    """JS divergence with log base 2 (range [0, 1]). Vectors must be same length."""
    a = np.asarray(p, dtype=np.float64)
    b = np.asarray(q, dtype=np.float64)
    if a.shape != b.shape or a.ndim != 1:
        raise ValueError("vectors must be 1-D and equal length (incompatible dimensions)")
    if a.sum() <= 0 or b.sum() <= 0:
        raise ValueError("vectors must have a positive sum")
    a, b = a / a.sum(), b / b.sum()
    m = 0.5 * (a + b)

    def kl(x: np.ndarray, y: np.ndarray) -> float:
        mask = x > 0
        return float(np.sum(x[mask] * np.log2(x[mask] / y[mask])))

    return float(min(1.0, max(0.0, 0.5 * kl(a, m) + 0.5 * kl(b, m))))


# --------------------------------------------------------------------------
# Adapter abstraction
# --------------------------------------------------------------------------
@dataclass
class ClassificationPredictions:
    """Per-batch model output.

    predicted_classes: (N,) int array (required)
    probabilities:     (N, C) rows summing to 1, or None if unavailable
    confidence:        (N,) max probability, or None if probabilities unavailable
    entropy:           (N,) Shannon entropy (nats), or None if unavailable
    """
    predicted_classes: np.ndarray
    probabilities: Optional[np.ndarray] = None
    confidence: Optional[np.ndarray] = None
    entropy: Optional[np.ndarray] = None
    notes: List[str] = field(default_factory=list)


def predictions_from_probabilities(probabilities: Any) -> ClassificationPredictions:
    p = normalize_probabilities(probabilities)
    return ClassificationPredictions(
        predicted_classes=np.argmax(p, axis=1).astype(np.int64),
        probabilities=p,
        confidence=p.max(axis=1),
        entropy=shannon_entropy(p),
    )


def predictions_from_labels(labels: Any) -> ClassificationPredictions:
    """For black-box models exposing labels only. Nothing is invented."""
    arr = np.asarray(labels)
    if arr.ndim != 1 or arr.size == 0:
        raise ValueError("labels must be a non-empty 1-D array")
    lab = arr.astype(np.int64)
    if np.any(lab < 0):
        raise ValueError("class labels must be non-negative integers")
    return ClassificationPredictions(
        predicted_classes=lab,
        notes=["probabilities unavailable: confidence and entropy not reported"],
    )


class ClassificationModelAdapter(abc.ABC):
    """Interface between the behavioral engine and a concrete model.

    Implementations receive a uint8 batch of shape (N, H, W, 3) and return a
    ClassificationPredictions with N rows. The engine never depends on a
    specific architecture. `class_count` may be None if unknown.
    """
    name: str = "abstract_classification_adapter"
    class_count: Optional[int] = None

    @abc.abstractmethod
    def predict(self, batch_images: np.ndarray) -> ClassificationPredictions:
        raise NotImplementedError


# --------------------------------------------------------------------------
# Optional PyTorch (TorchScript) adapter - torch is imported lazily
# --------------------------------------------------------------------------
_UNSAFE_SUFFIXES = (".pkl", ".pickle", ".joblib", ".dill")


def _require_torch():
    try:
        import torch  # noqa: WPS433 (lazy, optional)
    except ImportError as exc:
        raise ImportError("PyTorch is not installed; the TorchScript adapter is unavailable") from exc
    return torch


def _inspect_torchscript_archive(path: str) -> None:
    """Heuristic pre-check that `path` is a TorchScript archive, not a checkpoint.

    Plain torch.save() checkpoints contain data.pkl but no code/ directory and
    load via arbitrary pickle. Those are rejected. This is a heuristic, not a
    sandbox: a crafted archive can fake these names. Verify the B1 SHA-256
    against a trusted source and only load models you trust.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    if not zipfile.is_zipfile(path):
        raise UnsupportedModelError(
            "not a zip-based TorchScript archive; legacy/pickle serialization is not supported")
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
    has_code = any(n.startswith("code/") or "/code/" in n for n in names)
    has_constants = any(n.endswith("constants.pkl") for n in names)
    if not (has_code and has_constants):
        raise UnsupportedModelError(
            "archive looks like a serialized checkpoint (state_dict/pickle), not TorchScript; "
            "loading it would require unsafe deserialization")


class TorchScriptClassificationAdapter(ClassificationModelAdapter):
    """Adapter for a loaded TorchScript classification module.

    `output_type` is REQUIRED and must be "logits" (softmax applied here, as a
    documented interpretation) or "probabilities" (used as-is, renormalized).
    Input: RGB uint8 -> optional bilinear resize -> [0,1] -> (x-mean)/std -> NCHW.
    """
    name = "torchscript_classification"

    def __init__(self, model: Any, *, output_type: str,
                 input_size: Optional[Sequence[int]] = None,
                 mean: Sequence[float] = (0.0, 0.0, 0.0),
                 std: Sequence[float] = (1.0, 1.0, 1.0),
                 device: str = "cpu", class_count: Optional[int] = None, seed: int = 0):
        if output_type not in ("logits", "probabilities"):
            raise ValueError("output_type must be 'logits' or 'probabilities'")
        self._model = model
        if hasattr(model, "eval"):
            model.eval()
        self._output_type = output_type
        self._input_size = tuple(input_size) if input_size else None   # (height, width)
        self._mean = np.asarray(mean, dtype=np.float32).reshape(1, 1, 1, 3)
        self._std = np.asarray(std, dtype=np.float32).reshape(1, 1, 1, 3)
        self._device = device
        self._seed = int(seed)
        self.class_count = class_count

    def predict(self, batch_images: np.ndarray) -> ClassificationPredictions:
        torch = _require_torch()
        torch.manual_seed(self._seed)
        batch = np.asarray(batch_images, dtype=np.uint8)
        if self._input_size is not None:
            h, w = self._input_size
            resample = getattr(Image, "Resampling", Image).BILINEAR
            batch = np.stack([np.asarray(Image.fromarray(im).resize((w, h), resample)) for im in batch])
        x = (batch.astype(np.float32) / 255.0 - self._mean) / self._std
        tensor = torch.from_numpy(np.ascontiguousarray(x.transpose(0, 3, 1, 2)))
        with torch.no_grad():
            out = self._model(tensor.to(self._device))
        arr = out.detach().cpu().numpy().astype(np.float64)
        if arr.ndim != 2:
            raise ValueError("model output must have shape (N, C)")
        if self._output_type == "logits":
            z = arr - arr.max(axis=1, keepdims=True)
            e = np.exp(z)
            arr = e / e.sum(axis=1, keepdims=True)
        return predictions_from_probabilities(arr)


def try_load_torchscript_adapter(path: str, *, output_type: str, **adapter_kwargs: Any) -> Dict[str, Any]:
    """Safely attempt to build a TorchScript adapter. Never unpickles checkpoints.

    Returns {"status": "loaded", "adapter": ..., "warnings": [...]} or a dict
    with status "unsupported" | "unavailable" | "error" and a "reason".
    NOTE: torch.jit.load still deserializes model content. Only load models
    whose SHA-256 (B1) matches a trusted source.
    """
    try:
        if str(path).lower().endswith(_UNSAFE_SUFFIXES):
            raise UnsupportedModelError("pickle-based model files are not supported (unsafe deserialization)")
        _inspect_torchscript_archive(str(path))
        torch = _require_torch()
        model = torch.jit.load(str(path), map_location="cpu")
        adapter = TorchScriptClassificationAdapter(model, output_type=output_type, **adapter_kwargs)
        return {"status": "loaded", "adapter": adapter,
                "warnings": ["torch.jit.load deserializes model content; load only trusted models"]}
    except UnsupportedModelError as exc:
        return {"status": "unsupported", "reason": str(exc)}
    except FileNotFoundError:
        return {"status": "error", "reason": "model file not found: %s" % path}
    except ImportError as exc:
        return {"status": "unavailable", "reason": str(exc)}
    except Exception as exc:  # noqa: BLE001 - report, never crash
        return {"status": "error", "reason": "%s: %s" % (type(exc).__name__, exc)}


# --------------------------------------------------------------------------
# Fingerprint computation
# --------------------------------------------------------------------------
def _error_result(code: str, message: str) -> Dict[str, Any]:
    return {
        "status": "error",
        "method": METHOD,
        "task": TASK,
        "error": {"code": code, "message": message},
        "limitations": list(LIMITATIONS),
    }


def _validate_probes(probes: Sequence[ProbeSpec]) -> None:
    if not probes:
        raise BehavioralFingerprintError("invalid_probe", "probe battery is empty")
    if probes[0].transform != "identity":
        raise BehavioralFingerprintError("invalid_probe", "the first probe must be the identity (clean) probe")
    names = [p.name for p in probes]
    if len(set(names)) != len(names):
        raise BehavioralFingerprintError("invalid_probe", "probe names must be unique")
    for p in probes:
        if p.transform not in TRANSFORMS:
            raise BehavioralFingerprintError("invalid_probe", "unknown transform: %r" % p.transform)
        try:
            canonical_json(p.to_dict())
        except (TypeError, ValueError) as exc:
            raise BehavioralFingerprintError("invalid_probe", "probe params not serializable: %s" % exc)


def _run_adapter(adapter: Any, stack: np.ndarray, batch_size: int) -> ClassificationPredictions:
    classes: List[np.ndarray] = []
    probs: List[Optional[np.ndarray]] = []
    for start in range(0, len(stack), batch_size):
        batch = stack[start:start + batch_size]
        try:
            out = adapter.predict(batch)
        except Exception as exc:  # noqa: BLE001
            raise BehavioralFingerprintError("adapter_error", "adapter.predict failed: %s: %s" % (type(exc).__name__, exc))
        if not isinstance(out, ClassificationPredictions):
            raise BehavioralFingerprintError("invalid_adapter_output", "adapter must return ClassificationPredictions")
        pc = np.asarray(out.predicted_classes)
        if pc.shape != (len(batch),):
            raise BehavioralFingerprintError("invalid_adapter_output", "predicted_classes must have shape (N,)")
        classes.append(pc.astype(np.int64))
        if out.probabilities is None:
            probs.append(None)
        else:
            try:
                p = normalize_probabilities(out.probabilities)
            except ValueError as exc:
                raise BehavioralFingerprintError("invalid_adapter_output", str(exc))
            if p.shape[0] != len(batch):
                raise BehavioralFingerprintError("invalid_adapter_output", "probabilities row count mismatch")
            probs.append(p)
    have = [p is not None for p in probs]
    if any(have) and not all(have):
        raise BehavioralFingerprintError("invalid_adapter_output", "adapter returned probabilities for only some batches")
    merged_classes = np.concatenate(classes)
    if not any(have):
        return ClassificationPredictions(predicted_classes=merged_classes)
    merged = np.vstack(probs)  # type: ignore[arg-type]
    return ClassificationPredictions(
        predicted_classes=merged_classes,
        probabilities=merged,
        confidence=merged.max(axis=1),
        entropy=shannon_entropy(merged),
    )


def _summarize_probe(spec: ProbeSpec, preds: ClassificationPredictions,
                     clean_classes: np.ndarray, class_count: Optional[int]) -> Dict[str, Any]:
    n = int(len(preds.predicted_classes))
    counts = Counter(int(c) for c in preds.predicted_classes)
    distribution = {str(k): int(counts[k]) for k in sorted(counts)}
    histogram = None
    if class_count is not None:
        histogram = [int(counts.get(i, 0)) for i in range(class_count)]
    entry: Dict[str, Any] = {
        "probe": spec.name,
        "transform": spec.transform,
        "params": dict(spec.params),
        "images": n,
        "prediction_agreement": _r(prediction_agreement(clean_classes, preds.predicted_classes)),
        "prediction_distribution": distribution,
        "class_histogram": histogram,
        "probabilities_available": preds.probabilities is not None,
        "mean_confidence": None,
        "confidence_std": None,
        "mean_entropy": None,
        "entropy_std": None,
        "mean_probability_vector": None,
    }
    if preds.probabilities is not None:
        entry["mean_confidence"] = _r(preds.confidence.mean())
        entry["confidence_std"] = _r(preds.confidence.std())
        entry["mean_entropy"] = _r(preds.entropy.mean())
        entry["entropy_std"] = _r(preds.entropy.std())
        entry["mean_probability_vector"] = [_r(v) for v in preds.probabilities.mean(axis=0)]
    return entry


def _resolve_model_id(model_identity: Any, model_id: Optional[str]) -> Optional[str]:
    """Preserve a caller-supplied model_id; never invent one."""
    if model_id is not None:
        return model_id
    if isinstance(model_identity, dict):
        if model_identity.get("model_id") is not None:
            return model_identity["model_id"]
        nested = model_identity.get("model")
        if isinstance(nested, dict) and nested.get("model_id") is not None:
            return nested["model_id"]
    return None


def compute_behavioral_fingerprint(images: Sequence[Any], adapter: Any, *,
                                   model_identity: Optional[Dict[str, Any]] = None,
                                   model_id: Optional[str] = None,
                                   seed: int = DEFAULT_SEED,
                                   probes: Optional[Sequence[ProbeSpec]] = None,
                                   batch_size: int = 32) -> Dict[str, Any]:
    """Compute a behavioral fingerprint. Never raises for bad input; returns
    a result with status "error" instead. Result contains no timestamps."""
    try:
        return _compute(images, adapter, model_identity, model_id, seed, probes, batch_size)
    except BehavioralFingerprintError as exc:
        return _error_result(exc.code, str(exc))


def _compute(images, adapter, model_identity, model_id, seed, probes, batch_size) -> Dict[str, Any]:
    if images is None or not hasattr(images, "__len__") or len(images) == 0:
        raise BehavioralFingerprintError("empty_input", "no images supplied")
    if adapter is None or not callable(getattr(adapter, "predict", None)):
        raise BehavioralFingerprintError("invalid_adapter", "adapter must implement predict(batch_images)")
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise BehavioralFingerprintError("invalid_input", "seed must be an int")
    if not isinstance(batch_size, int) or batch_size < 1:
        raise BehavioralFingerprintError("invalid_input", "batch_size must be a positive int")

    arrays: List[np.ndarray] = []
    for i, im in enumerate(images):
        try:
            arrays.append(to_uint8_rgb(im))
        except ValueError as exc:
            raise BehavioralFingerprintError("invalid_input", "image %d: %s" % (i, exc))
    if len({a.shape for a in arrays}) != 1:
        raise BehavioralFingerprintError("invalid_input", "all images must share the same shape")

    battery = list(probes) if probes is not None else default_probe_battery(seed)
    _validate_probes(battery)

    random.seed(seed)
    np.random.seed(seed % (2 ** 32))

    ds_hash = hashlib.sha256()
    ds_hash.update(str(len(arrays)).encode())
    for a in arrays:
        ds_hash.update(str(a.shape).encode())
        ds_hash.update(a.tobytes())
    dataset_digest = ds_hash.hexdigest()

    class_count = getattr(adapter, "class_count", None)
    clean_classes: Optional[np.ndarray] = None
    probe_results: List[Dict[str, Any]] = []

    for spec in battery:
        stack = np.stack([apply_probe(spec, a, i) for i, a in enumerate(arrays)])
        preds = _run_adapter(adapter, stack, batch_size)
        if preds.probabilities is not None:
            width = int(preds.probabilities.shape[1])
            if class_count is not None and class_count != width:
                raise BehavioralFingerprintError("invalid_adapter_output", "probability width %d != adapter.class_count %d" % (width, class_count))
            class_count = width
        if class_count is not None and int(preds.predicted_classes.max()) >= class_count:
            raise BehavioralFingerprintError("invalid_adapter_output", "predicted class index >= class_count")
        if int(preds.predicted_classes.min()) < 0:
            raise BehavioralFingerprintError("invalid_adapter_output", "negative class index")
        if clean_classes is None:
            clean_classes = preds.predicted_classes.copy()
        probe_results.append(_summarize_probe(spec, preds, clean_classes, class_count))

    # class_count may only become known mid-run; rebuild histograms consistently.
    if class_count is not None:
        for entry in probe_results:
            hist = [0] * class_count
            for k, v in entry["prediction_distribution"].items():
                hist[int(k)] = v
            entry["class_histogram"] = hist

    probabilities_available = all(p["probabilities_available"] for p in probe_results)
    config_digest = sha256_hex(canonical_json([s.to_dict() for s in battery]))
    fingerprint_digest = sha256_hex(canonical_json({
        "engine_version": ENGINE_VERSION,
        "dataset_digest": dataset_digest,
        "probe_config_digest": config_digest,
        "probes": probe_results,
    }))

    notes: List[str] = []
    if not probabilities_available:
        notes.append("Adapter does not expose probabilities; confidence, entropy and "
                     "probability-vector metrics are unavailable (not estimated).")

    return {
        "status": "completed",
        "method": METHOD,
        "task": TASK,
        "engine_version": ENGINE_VERSION,
        "probe_count": len(probe_results),
        "model": {
            "model_id": _resolve_model_id(model_identity, model_id),
            "adapter": getattr(adapter, "name", type(adapter).__name__),
            "class_count": class_count,
            "probabilities_available": probabilities_available,
        },
        "dataset": {
            "image_count": len(arrays),
            "image_shape": list(arrays[0].shape),
            "dataset_digest": dataset_digest,
        },
        "config": {
            "seed": seed,
            "decimals": DECIMALS,
            "probes": [s.to_dict() for s in battery],
        },
        "baseline": copy.deepcopy(probe_results[0]),
        "probes": probe_results,
        "fingerprint": {
            "algorithm": "sha256 over canonical JSON of dataset digest, probe config and rounded per-probe statistics",
            "digest": fingerprint_digest,
            "dataset_digest": dataset_digest,
            "probe_config_digest": config_digest,
            "seed": seed,
        },
        "notes": notes,
        "limitations": list(LIMITATIONS),
    }


# --------------------------------------------------------------------------
# Reference comparison
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class ComparisonThresholds:
    """Explicit deviation thresholds. A finding is a "deviation" if strictly greater."""
    prediction_agreement: float = 0.05        # absolute difference
    mean_confidence: float = 0.05             # absolute difference
    mean_entropy: float = 0.10                # absolute difference (nats)
    prediction_distribution_tv: float = 0.10  # total variation distance
    mean_probability_js: float = 0.05         # Jensen-Shannon divergence (base 2)


_SCALAR_METRICS = (
    ("prediction_agreement", "prediction_agreement"),
    ("mean_confidence", "mean_confidence"),
    ("mean_entropy", "mean_entropy"),
)


def _compat_errors(reference: Any, assessed: Any, allow_dataset_mismatch: bool) -> List[str]:
    errs: List[str] = []
    for label, r in (("reference", reference), ("assessed", assessed)):
        if not isinstance(r, dict) or r.get("status") != "completed":
            errs.append("%s is not a completed fingerprint result" % label)
    if errs:
        return errs
    try:
        rc, ac = reference["model"].get("class_count"), assessed["model"].get("class_count")
        if rc != ac:
            errs.append("class_count mismatch: reference=%r assessed=%r" % (rc, ac))
        rn = [p["probe"] for p in reference["probes"]]
        an = [p["probe"] for p in assessed["probes"]]
        if rn != an:
            errs.append("probe sets differ: reference=%r assessed=%r" % (rn, an))
        else:
            for rp, ap in zip(reference["probes"], assessed["probes"]):
                if rp["images"] != ap["images"]:
                    errs.append("image count mismatch for probe %r" % rp["probe"])
        if reference["fingerprint"]["probe_config_digest"] != assessed["fingerprint"]["probe_config_digest"]:
            errs.append("probe configuration digest mismatch")
        if (not allow_dataset_mismatch and
                reference["fingerprint"]["dataset_digest"] != assessed["fingerprint"]["dataset_digest"]):
            errs.append("dataset digest mismatch (fingerprints were computed on different inputs)")
    except (KeyError, TypeError, AttributeError) as exc:
        errs.append("malformed fingerprint structure: %s: %s" % (type(exc).__name__, exc))
    return errs


def _distribution_vectors(rd: Dict[str, int], ad: Dict[str, int]):
    keys = sorted(set(rd) | set(ad), key=int)
    return (np.array([rd.get(k, 0) for k in keys], dtype=np.float64),
            np.array([ad.get(k, 0) for k in keys], dtype=np.float64))


def compare_fingerprints(reference: Dict[str, Any], assessed: Dict[str, Any],
                         thresholds: Any = None,
                         allow_dataset_mismatch: bool = False) -> Dict[str, Any]:
    """Compare two fingerprints. Reports measured differences only: no
    maliciousness probability, no safe/unsafe verdict, no score, no ranking."""
    if thresholds is None:
        thr = ComparisonThresholds()
    elif isinstance(thresholds, ComparisonThresholds):
        thr = thresholds
    elif isinstance(thresholds, dict):
        thr = ComparisonThresholds(**thresholds)
    else:
        raise TypeError("thresholds must be ComparisonThresholds, dict or None")

    errs = _compat_errors(reference, assessed, allow_dataset_mismatch)
    if errs:
        return {
            "status": "incompatible",
            "method": COMPARISON_METHOD,
            "compatibility_errors": errs,
            "thresholds": asdict(thr),
            "findings": [],
            "deviations": [],
            "limitations": list(LIMITATIONS),
        }

    findings: List[Dict[str, Any]] = []
    for rp, ap in zip(reference["probes"], assessed["probes"]):
        name = rp["probe"]
        thr_by_metric = {
            "prediction_agreement": thr.prediction_agreement,
            "mean_confidence": thr.mean_confidence,
            "mean_entropy": thr.mean_entropy,
        }
        for metric, key in _SCALAR_METRICS:
            rv, av = rp.get(key), ap.get(key)
            f: Dict[str, Any] = {"probe": name, "metric": metric, "reference": rv, "assessed": av,
                                 "absolute_difference": None, "threshold": thr_by_metric[metric]}
            if rv is None or av is None:
                f["status"] = "not_available"
            else:
                diff = _r(abs(rv - av))
                f["absolute_difference"] = diff
                f["status"] = "deviation" if diff > thr_by_metric[metric] else "within_threshold"
            findings.append(f)

        rvec, avec = _distribution_vectors(rp["prediction_distribution"], ap["prediction_distribution"])
        tv = _r(total_variation_distance(rvec, avec))
        findings.append({"probe": name, "metric": "prediction_distribution_tv", "distance": tv,
                         "threshold": thr.prediction_distribution_tv,
                         "status": "deviation" if tv > thr.prediction_distribution_tv else "within_threshold"})

        rm, am = rp.get("mean_probability_vector"), ap.get("mean_probability_vector")
        f = {"probe": name, "metric": "mean_probability_js", "distance": None,
             "threshold": thr.mean_probability_js}
        if rm is None or am is None:
            f["status"] = "not_available"
        else:
            try:
                js = _r(jensen_shannon_divergence(rm, am))
                f["distance"] = js
                f["status"] = "deviation" if js > thr.mean_probability_js else "within_threshold"
            except ValueError:
                f["status"] = "incompatible_dimensions"
        findings.append(f)

    deviations = [f for f in findings if f["status"] == "deviation"]
    return {
        "status": "completed",
        "method": COMPARISON_METHOD,
        "compatibility_errors": [],
        "thresholds": asdict(thr),
        "findings": findings,
        "deviations": deviations,
        "summary": {
            "finding_count": len(findings),
            "deviation_count": len(deviations),
            "not_available_count": sum(1 for f in findings if f["status"] == "not_available"),
            "probes_with_deviation": sorted({f["probe"] for f in deviations}),
        },
        "interpretation": ("Deviations are measured behavioral differences against explicit thresholds. "
                           "They are candidate anomalies for review, not evidence of tampering."),
        "limitations": list(LIMITATIONS),
    }


__all__ = [
    "ClassificationModelAdapter", "ClassificationPredictions", "ComparisonThresholds", "ProbeSpec",
    "TorchScriptClassificationAdapter", "UnsupportedModelError", "apply_probe", "blur", "brightness",
    "canonical_json", "compare_fingerprints", "compute_behavioral_fingerprint", "contrast",
    "default_probe_battery", "gaussian_noise", "horizontal_flip", "jensen_shannon_divergence",
    "jpeg_degradation", "normalize_probabilities", "prediction_agreement",
    "predictions_from_labels", "predictions_from_probabilities", "shannon_entropy",
    "total_variation_distance", "translation", "try_load_torchscript_adapter",
]
