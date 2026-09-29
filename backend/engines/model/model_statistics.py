"""TRACER-CV B3 - Model Parameter & Activation Statistics.

Standalone, deterministic, offline engine that reports measurable structural
and numerical statistics about an *accessible* image-classification model:

* parameter / buffer tensor statistics (shape, dtype, mean, std, min, max,
  zero fraction, NaN / +Inf / -Inf counts, optional byte digest),
* module-level structural summary,
* activation statistics captured with temporary forward hooks on controlled
  probe images,
* reference-vs-assessed comparison with explicit, configurable thresholds.

ASSURANCE POSITION
------------------
B3 reports measurable statistics and threshold-based *candidate anomalies*
for analyst review. It does NOT claim that unusual parameters or activations
prove malicious modification or a backdoor, that a deviation proves
tampering, or that a model is safe, clean or malicious. The absence of
deviations does not prove the absence of backdoors. There is no maliciousness
score, no probability of compromise and no safe/unsafe verdict.

SAFETY / LOADING DECISION
-------------------------
* B3 never loads checkpoints from paths and never unpickles anything. If a
  path / bytes object is supplied, the report is ``unavailable``.
* Analysis takes an already-instantiated model object (or a mapping of named
  tensors / arrays). The caller is responsible for how it was obtained.
* ``load_torchscript_model`` exists only as an explicit, opt-in helper
  (``trusted=True`` required). TorchScript deserialization must only be done
  on trusted artifacts. B3 does NOT sandbox model execution: activation
  capture runs the supplied model's forward code in the caller's process.
* Artifact identity is B1's job. ``model_id`` is recorded as supplied by the
  caller and is not verified here.

DEPENDENCIES
------------
Standard library + NumPy. PyTorch is optional and imported lazily, only when
activation capture needs it. B2 is neither imported nor modified; callers
(or higher-level orchestration) may pass B2's probe images to this engine via
the ``images`` argument.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from dataclasses import asdict, dataclass
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Mapping,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
)

import numpy as np

__all__ = [
    "ENGINE_VERSION",
    "METHOD",
    "COMPARISON_METHOD",
    "TASK",
    "LIMITATIONS",
    "ModelStatisticsConfig",
    "ComparisonThresholds",
    "compute_array_statistics",
    "make_synthetic_probe_images",
    "prepare_probe_batch",
    "analyze_model",
    "analyze_named_arrays",
    "analyze_torch_model",
    "build_unavailable_report",
    "load_torchscript_model",
    "compare_reports",
]

ENGINE_VERSION = "1.0.0"
METHOD = "model_parameter_activation_statistics"
COMPARISON_METHOD = "model_statistics_comparison"
TASK = "image_classification"

BLACK_BOX_REASON = "parameter and activation statistics are unavailable for black-box access"

LIMITATIONS: Tuple[str, ...] = (
    "B3 reports measurable structural and numerical statistics only; it produces no maliciousness "
    "score, no probability of compromise and no safe/unsafe verdict.",
    "Unusual parameter or activation statistics do not prove malicious modification or a backdoor, "
    "and a statistical deviation does not prove tampering.",
    "The absence of deviations does not prove the absence of backdoors; the model is not thereby "
    "shown to be safe or clean.",
    "Activation statistics depend entirely on the supplied probe images and describe only those probes.",
    "Only aggregate summaries are kept; localized or low-magnitude changes that leave aggregates "
    "unchanged cannot be seen.",
    "B3 does not sandbox model execution: activation capture runs the supplied model's forward code "
    "in the caller's process. Analyze only models from trusted artifacts.",
    "B3 does not establish model identity or provenance (see B1); a caller-supplied model_id is "
    "recorded as given and not verified.",
)

COMPARISON_LIMITATIONS: Tuple[str, ...] = (
    "Candidate anomalies are threshold-based measurable deviations that require analyst review; "
    "they are not evidence of tampering.",
    "The absence of candidate anomalies is not evidence of integrity, safety or absence of backdoors.",
    "Thresholds are configurable heuristics, not calibrated decision boundaries.",
    "No overall score, ranking, probability or safe/unsafe classification is produced.",
)

_EPS_DEFAULT = 1e-12


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def _canonical_json(obj: Any) -> str:
    """Canonical JSON: sorted keys, compact separators, ASCII, no NaN/Inf."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def _clean_float(value: Any) -> Optional[float]:
    """Return a finite Python float or None (JSON-safe)."""
    if value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _dtype_name(dtype: Any) -> str:
    return str(dtype).replace("torch.", "")


def _require_int(name: str, value: Any, minimum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}, got {value!r}")


def _require_nonneg_float(name: str, value: Any) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError(f"{name} must be a finite number >= 0, got {value!r}")


def _import_torch() -> Any:
    """Lazily import PyTorch; return None when unavailable."""
    try:
        import torch  # noqa: WPS433 (deliberate lazy import)
    except Exception:  # pragma: no cover - depends on environment
        return None
    return torch


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ModelStatisticsConfig:
    """Configuration for B3 statistics collection.

    Attributes:
        batch_size: probe images per forward pass.
        input_layout: layout of supplied probe images, ``"HWC"`` or ``"CHW"``.
        input_mean / input_std: optional per-channel normalization applied
            after scaling uint8 to [0, 1]. Both default to no normalization.
        activation_scope: ``"leaf"`` (modules without children) or ``"all"``
            (every module including the root, named ``<root>``).
        include_percentiles: add approximate percentile summaries to
            activation statistics (bounded deterministic sample).
        percentiles: percentiles to report, each in [0, 100].
        percentile_sample_size: maximum sample size per layer for percentiles.
        include_tensor_digest: add a SHA-256 of each parameter tensor's bytes.
        chunk_elements: elements processed at a time (bounds memory).
        max_listed_modules: maximum modules listed in the structure summary.
    """

    batch_size: int = 8
    input_layout: str = "HWC"
    input_mean: Optional[Tuple[float, ...]] = None
    input_std: Optional[Tuple[float, ...]] = None
    activation_scope: str = "leaf"
    include_percentiles: bool = True
    percentiles: Tuple[float, ...] = (1.0, 50.0, 99.0)
    percentile_sample_size: int = 4096
    include_tensor_digest: bool = True
    chunk_elements: int = 1 << 22
    max_listed_modules: int = 1000

    def validate(self) -> None:
        """Raise ValueError when the configuration is invalid."""
        _require_int("batch_size", self.batch_size, 1)
        _require_int("chunk_elements", self.chunk_elements, 1)
        _require_int("max_listed_modules", self.max_listed_modules, 0)
        _require_int("percentile_sample_size", self.percentile_sample_size, 0)
        if self.input_layout not in ("HWC", "CHW"):
            raise ValueError(f"input_layout must be 'HWC' or 'CHW', got {self.input_layout!r}")
        if self.activation_scope not in ("leaf", "all"):
            raise ValueError(f"activation_scope must be 'leaf' or 'all', got {self.activation_scope!r}")
        for p in self.percentiles:
            if isinstance(p, bool) or not isinstance(p, (int, float)) or not 0.0 <= p <= 100.0:
                raise ValueError(f"percentiles must be numbers in [0, 100], got {p!r}")
        if self.include_percentiles and self.percentiles and self.percentile_sample_size < 1:
            raise ValueError("percentile_sample_size must be >= 1 when percentiles are requested")
        for label, values in (("input_mean", self.input_mean), ("input_std", self.input_std)):
            if values is None:
                continue
            if not all(isinstance(v, (int, float)) and math.isfinite(v) for v in values) or len(values) == 0:
                raise ValueError(f"{label} must be a non-empty tuple of finite numbers")
        if self.input_std is not None and any(v == 0 for v in self.input_std):
            raise ValueError("input_std must not contain zeros")

    def to_dict(self) -> Dict[str, Any]:
        """Canonical, JSON-safe representation."""
        return json.loads(_canonical_json(asdict(self)))


@dataclass(frozen=True)
class ComparisonThresholds:
    """Explicit thresholds for reference-vs-assessed comparison.

    A metric is a *candidate anomaly* when its threshold basis value is
    strictly greater than the threshold. Basis definitions:

    * absolute:   |assessed - reference|
    * relative:   |assessed - reference| / max(|reference|, eps)
    * normalized: |assessed - reference| / (scale + eps), where scale is the
      reference standard deviation (means, percentiles) or reference range
      (min / max).

    Default count thresholds of 0.0 flag any difference.
    """

    count_rel_diff: float = 0.0
    param_mean_norm_diff: float = 0.05
    param_std_rel_diff: float = 0.05
    param_zero_fraction_abs_diff: float = 0.01
    param_extreme_norm_diff: float = 0.25
    activation_mean_norm_diff: float = 0.10
    activation_std_rel_diff: float = 0.10
    activation_zero_fraction_abs_diff: float = 0.05
    activation_extreme_norm_diff: float = 0.25
    activation_percentile_norm_diff: float = 0.25
    non_finite_count_abs_diff: float = 0.0
    eps: float = _EPS_DEFAULT

    def validate(self) -> None:
        """Raise ValueError when any threshold is negative or non-finite."""
        for name, value in asdict(self).items():
            _require_nonneg_float(name, value)
        if self.eps <= 0:
            raise ValueError("eps must be > 0")

    def to_dict(self) -> Dict[str, Any]:
        """Canonical, JSON-safe representation."""
        return json.loads(_canonical_json(asdict(self)))


# --------------------------------------------------------------------------- #
# Numerical statistics (NumPy core)
# --------------------------------------------------------------------------- #
def _stride_sample(values: np.ndarray, cap: int) -> np.ndarray:
    """Deterministic evenly spaced subsample of at most ``cap`` values."""
    if values.size <= cap:
        return values
    idx = np.linspace(0, values.size - 1, cap).astype(np.int64)
    return values[idx]


class _RunningStats:
    """Streaming, deterministic summary statistics (Chan et al. merge)."""

    def __init__(self, sample_cap: int = 0) -> None:
        self.total = 0
        self.nan = 0
        self.posinf = 0
        self.neginf = 0
        self.zero = 0
        self.n = 0
        self.mean = 0.0
        self.m2 = 0.0
        self.min: Optional[float] = None
        self.max: Optional[float] = None
        self.sample_cap = sample_cap
        self._samples: List[np.ndarray] = []
        self._sample_size = 0

    def update(self, values: Any) -> None:
        """Fold an array into the running statistics."""
        flat = np.asarray(values).reshape(-1)
        if flat.dtype.kind not in "iufb":
            raise TypeError(f"unsupported dtype for statistics: {flat.dtype}")
        if flat.size == 0:
            return
        flat = flat.astype(np.float64)
        self.total += int(flat.size)
        self.nan += int(np.isnan(flat).sum())
        self.posinf += int(np.isposinf(flat).sum())
        self.neginf += int(np.isneginf(flat).sum())
        self.zero += int(np.count_nonzero(flat == 0.0))
        finite = flat[np.isfinite(flat)]
        if finite.size == 0:
            return
        with np.errstate(over="ignore", invalid="ignore"):
            nb = int(finite.size)
            mb = float(finite.mean())
            m2b = float(np.square(finite - mb).sum())
            delta = mb - self.mean
            new_n = self.n + nb
            self.mean += delta * nb / new_n
            self.m2 += m2b + delta * delta * self.n * nb / new_n
        self.n = new_n
        lo, hi = float(finite.min()), float(finite.max())
        self.min = lo if self.min is None else min(self.min, lo)
        self.max = hi if self.max is None else max(self.max, hi)
        if self.sample_cap > 0:
            piece = _stride_sample(finite, self.sample_cap)
            self._samples.append(piece)
            self._sample_size += int(piece.size)
            if self._sample_size > 2 * self.sample_cap:
                merged = _stride_sample(np.concatenate(self._samples), self.sample_cap)
                self._samples = [merged]
                self._sample_size = int(merged.size)

    def finalize(self, percentiles: Sequence[float] = ()) -> Dict[str, Any]:
        """Return the summary dictionary (population std, ddof=0)."""
        std = math.sqrt(self.m2 / self.n) if self.n > 0 else None
        out: Dict[str, Any] = {
            "element_count": self.total,
            "finite_count": self.n,
            "nan_count": self.nan,
            "posinf_count": self.posinf,
            "neginf_count": self.neginf,
            "non_finite_count": self.nan + self.posinf + self.neginf,
            "zero_count": self.zero,
            "zero_fraction": (self.zero / self.total) if self.total > 0 else None,
            "mean": _clean_float(self.mean) if self.n > 0 else None,
            "std": _clean_float(std),
            "min": _clean_float(self.min),
            "max": _clean_float(self.max),
        }
        if percentiles:
            values: Dict[str, Optional[float]] = {}
            sample = (
                _stride_sample(np.concatenate(self._samples), self.sample_cap)
                if self._samples
                else np.empty(0, dtype=np.float64)
            )
            for p in percentiles:
                key = f"p{p:g}"
                values[key] = _clean_float(np.percentile(sample, p)) if sample.size else None
            out["percentiles"] = values
            out["percentile_method"] = "approximate: deterministic bounded sample of finite values"
        return out


def compute_array_statistics(
    array: Any,
    *,
    chunk_elements: int = 1 << 22,
    include_digest: bool = True,
) -> Dict[str, Any]:
    """Compute summary statistics for one array.

    Mean / std / min / max use finite values only; NaN / +Inf / -Inf are
    counted separately. Empty arrays yield ``None`` statistics. Raises
    ``TypeError`` for unsupported dtypes (e.g. complex).

    Returns a dictionary of counts and statistics, plus ``digest_sha256`` (a
    hash over dtype, shape and little-endian bytes) when requested.
    """
    _require_int("chunk_elements", chunk_elements, 1)
    arr = np.asarray(array)
    if arr.dtype.kind not in "iufb":
        raise TypeError(f"unsupported dtype for statistics: {arr.dtype}")
    flat = arr.reshape(-1)
    acc = _RunningStats(0)
    hasher = hashlib.sha256() if include_digest else None
    if hasher is not None:
        hasher.update(f"{_dtype_name(arr.dtype)}|{list(arr.shape)}|".encode("ascii"))
    for start in range(0, int(flat.size), chunk_elements):
        chunk = flat[start:start + chunk_elements]
        acc.update(chunk)
        if hasher is not None:
            hasher.update(np.ascontiguousarray(chunk.astype(chunk.dtype.newbyteorder("<"), copy=False)).tobytes())
    stats = acc.finalize()
    if hasher is not None:
        stats["digest_sha256"] = hasher.hexdigest()
    return stats


# --------------------------------------------------------------------------- #
# Probe images
# --------------------------------------------------------------------------- #
def make_synthetic_probe_images(
    count: int = 4,
    height: int = 16,
    width: int = 16,
    channels: int = 3,
    seed: int = 0,
) -> List[np.ndarray]:
    """Deterministic uint8 HWC probe images (for tests / smoke checks).

    Higher-level orchestration is expected to pass B2's probe images to the
    engine instead; B3 deliberately does not import B2.
    """
    for label, value in (("count", count), ("height", height), ("width", width), ("channels", channels)):
        _require_int(label, value, 1)
    rng = np.random.RandomState(seed)
    return [rng.randint(0, 256, size=(height, width, channels)).astype(np.uint8) for _ in range(count)]


def prepare_probe_batch(
    images: Any,
    config: Optional[ModelStatisticsConfig] = None,
    probe_set_id: Optional[str] = None,
) -> Tuple[np.ndarray, Dict[str, Any]]:
    """Validate probe images and build a float32 NCHW batch plus probe info.

    ``images`` is either a 4-D ndarray (N,H,W,C or N,C,H,W according to
    ``config.input_layout``) or a sequence of 2-D / 3-D arrays sharing one
    shape. uint8 is scaled by 1/255; floating point is assumed to already be
    in the model's expected range. Raises ValueError / TypeError on bad input.
    """
    cfg = config or ModelStatisticsConfig()
    cfg.validate()
    if images is None or isinstance(images, (str, bytes, os.PathLike)):
        raise TypeError("images must be an ndarray or a sequence of image arrays")
    if isinstance(images, np.ndarray):
        if images.ndim != 4:
            raise ValueError("an ndarray of images must be 4-D; wrap single images in a list")
        items: List[np.ndarray] = [images[i] for i in range(images.shape[0])]
    else:
        items = [np.asarray(im) for im in images]
    if not items:
        raise ValueError("at least one probe image is required")

    prepared: List[np.ndarray] = []
    for idx, arr in enumerate(items):
        if arr.ndim == 2:
            arr = arr[:, :, None] if cfg.input_layout == "HWC" else arr[None, :, :]
        if arr.ndim != 3:
            raise ValueError(f"probe image {idx} must be 2-D or 3-D, got {arr.ndim}-D")
        if arr.dtype == np.uint8:
            arr = arr.astype(np.float32) / np.float32(255.0)
        elif arr.dtype.kind == "f":
            arr = arr.astype(np.float32)
        else:
            raise TypeError(f"probe image {idx} has unsupported dtype {arr.dtype}; use uint8 or float")
        if not bool(np.isfinite(arr).all()):
            raise ValueError(f"probe image {idx} contains non-finite values")
        if cfg.input_layout == "HWC":
            arr = np.transpose(arr, (2, 0, 1))
        prepared.append(arr)
    if len({a.shape for a in prepared}) != 1:
        raise ValueError("all probe images must share one shape")

    batch = np.ascontiguousarray(np.stack(prepared, axis=0), dtype=np.float32)
    normalization: Optional[Dict[str, List[float]]] = None
    if cfg.input_mean is not None or cfg.input_std is not None:
        channels = int(batch.shape[1])
        mean = list(cfg.input_mean) if cfg.input_mean is not None else [0.0] * channels
        std = list(cfg.input_std) if cfg.input_std is not None else [1.0] * channels
        if len(mean) != channels or len(std) != channels:
            raise ValueError(f"input_mean / input_std must have {channels} entries")
        m = np.asarray(mean, dtype=np.float32).reshape(1, channels, 1, 1)
        s = np.asarray(std, dtype=np.float32).reshape(1, channels, 1, 1)
        batch = np.ascontiguousarray((batch - m) / s, dtype=np.float32)
        normalization = {"mean": [float(v) for v in mean], "std": [float(v) for v in std]}

    hasher = hashlib.sha256()
    hasher.update(f"float32|{list(batch.shape)}|".encode("ascii"))
    hasher.update(batch.astype("<f4", copy=False).tobytes())
    info = {
        "probe_count": int(batch.shape[0]),
        "input_shape": [int(d) for d in batch.shape],
        "input_layout_supplied": cfg.input_layout,
        "normalization": normalization,
        "probe_digest": hasher.hexdigest(),
        "probe_set_id": probe_set_id,
    }
    return batch, info


# --------------------------------------------------------------------------- #
# Tensor sources and parameter section
# --------------------------------------------------------------------------- #
class _TensorSource(NamedTuple):
    name: str
    kind: str
    trainable: Optional[bool]
    shape: Tuple[int, ...]
    dtype: str
    numel: int
    getter: Callable[[], np.ndarray]


def _tensor_to_numpy(tensor: Any) -> np.ndarray:
    """Convert a torch-like tensor to NumPy without touching the original."""
    detached = tensor.detach()
    if hasattr(detached, "cpu"):
        detached = detached.cpu()
    try:
        return np.asarray(detached.numpy())
    except (TypeError, RuntimeError):
        return np.asarray(detached.float().numpy())


def _error_text(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"


def _build_tensor_entry(src: _TensorSource, cfg: ModelStatisticsConfig) -> Dict[str, Any]:
    entry: Dict[str, Any] = {
        "name": src.name,
        "kind": src.kind,
        "trainable": src.trainable,
        "shape": [int(d) for d in src.shape],
        "dtype": src.dtype,
        "num_elements": int(src.numel),
    }
    try:
        array = src.getter()
        entry["statistics"] = compute_array_statistics(
            array, chunk_elements=cfg.chunk_elements, include_digest=cfg.include_tensor_digest
        )
        entry["status"] = "available"
    except Exception as exc:  # explicit: one bad tensor must not abort the assessment
        entry["status"] = "unavailable"
        entry["reason"] = _error_text(exc)
        entry["statistics"] = None
    return entry


def _build_parameter_section(sources: Sequence[_TensorSource], cfg: ModelStatisticsConfig) -> Dict[str, Any]:
    ordered = sorted(sources, key=lambda s: s.name)
    tensors = [_build_tensor_entry(s, cfg) for s in ordered]

    params = [t for t in tensors if t["kind"] == "parameter"]
    buffers = [t for t in tensors if t["kind"] == "buffer"]
    trainable_known = all(t["trainable"] is not None for t in params)
    dtype_dist: Dict[str, Dict[str, int]] = {}
    rank_dist: Dict[str, int] = {}
    for t in tensors:
        d = dtype_dist.setdefault(t["dtype"], {"tensor_count": 0, "element_count": 0})
        d["tensor_count"] += 1
        d["element_count"] += t["num_elements"]
        key = str(len(t["shape"]))
        rank_dist[key] = rank_dist.get(key, 0) + 1
    largest = max(tensors, key=lambda t: (t["num_elements"], t["name"]), default=None)

    layout = [[t["name"], t["kind"], t["shape"], t["dtype"]] for t in tensors]
    unavailable = [t["name"] for t in tensors if t["status"] != "available"]
    totals = {
        "tensor_count": len(tensors),
        "parameter_tensor_count": len(params),
        "buffer_tensor_count": len(buffers),
        "total_parameter_count": sum(t["num_elements"] for t in params),
        "trainable_parameter_count": (
            sum(t["num_elements"] for t in params if t["trainable"]) if trainable_known else None
        ),
        "non_trainable_parameter_count": (
            sum(t["num_elements"] for t in params if not t["trainable"]) if trainable_known else None
        ),
        "trainable_status": "available" if trainable_known else "not_available",
        "buffer_element_count": sum(t["num_elements"] for t in buffers),
        "unavailable_tensor_count": len(unavailable),
        "layout_digest": _sha256_text(_canonical_json(layout)),
    }
    return {
        "status": "completed" if not unavailable else "partial",
        "totals": totals,
        "dtype_distribution": {k: dtype_dist[k] for k in sorted(dtype_dist)},
        "shape_summary": {
            "rank_distribution": {k: rank_dist[k] for k in sorted(rank_dist)},
            "empty_tensor_count": sum(1 for t in tensors if t["num_elements"] == 0),
            "largest_tensor": (
                {"name": largest["name"], "num_elements": largest["num_elements"]} if largest else None
            ),
        },
        "unavailable_tensors": unavailable,
        "tensors": tensors,
    }


# --------------------------------------------------------------------------- #
# Report assembly
# --------------------------------------------------------------------------- #
def _model_info(
    *, model_id: Optional[str], model_type: Optional[str], framework: Optional[str], access: str
) -> Dict[str, Any]:
    return {
        "model_id": model_id,
        "model_id_note": "caller-supplied; not verified by B3" if model_id is not None else "not supplied",
        "model_type": model_type,
        "framework": framework,
        "access": access,
    }


def _fingerprint(payload: Mapping[str, Any]) -> Dict[str, Any]:
    digest = hashlib.sha256(_canonical_json(dict(payload)).encode("ascii")).hexdigest()
    return {
        "status": "computed",
        "algorithm": "sha256",
        "serialization": "canonical JSON (sorted keys, compact separators, ASCII)",
        "digest": digest,
        "covers": ["engine_version", "task", "structure", "parameters", "activations", "config"],
        "note": "Fingerprints this statistics report only; it is not a model artifact identity (see B1).",
    }


def _summary_statistics(parameters: Mapping[str, Any], activations: Mapping[str, Any]) -> Dict[str, Any]:
    tensors = parameters.get("tensors") or []
    layers = activations.get("layers") or []

    def nonfinite(item: Mapping[str, Any]) -> bool:
        stats = item.get("statistics") or {}
        return bool(stats.get("non_finite_count"))

    probes = activations.get("probes") or {}
    return {
        "tensor_count": len(tensors),
        "tensors_with_statistics": sum(1 for t in tensors if t.get("status") == "available"),
        "tensors_unavailable": sum(1 for t in tensors if t.get("status") != "available"),
        "tensors_with_non_finite_values": sum(1 for t in tensors if nonfinite(t)),
        "activation_layer_count": len(layers),
        "activation_layers_with_non_finite_values": sum(1 for layer in layers if nonfinite(layer)),
        "probe_count": probes.get("probe_count"),
    }


def _assemble_report(
    *,
    model_info: Dict[str, Any],
    structure: Dict[str, Any],
    parameters: Dict[str, Any],
    activations: Dict[str, Any],
    cfg: ModelStatisticsConfig,
    errors: List[str],
    warnings: List[str],
) -> Dict[str, Any]:
    config_dict = cfg.to_dict()
    payload = {
        "engine_version": ENGINE_VERSION,
        "task": TASK,
        "structure": structure,
        "parameters": parameters,
        "activations": activations,
        "config": config_dict,
    }
    return {
        "status": "error" if errors else "completed",
        "method": METHOD,
        "task": TASK,
        "engine_version": ENGINE_VERSION,
        "model": model_info,
        "structure": structure,
        "parameters": parameters,
        "activations": activations,
        "config": config_dict,
        "statistics": _summary_statistics(parameters, activations),
        "errors": list(errors),
        "warnings": list(warnings),
        "fingerprint": _fingerprint(payload),
        "limitations": list(LIMITATIONS),
    }


def build_unavailable_report(
    reason: str = BLACK_BOX_REASON,
    *,
    model_id: Optional[str] = None,
    status: str = "unavailable",
    access: str = "black_box",
    model_type: Optional[str] = None,
    config: Optional[ModelStatisticsConfig] = None,
    errors: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Report for models whose internals cannot be inspected (or on error).

    No statistics are fabricated and none are inferred from outputs.
    """
    cfg_dict: Dict[str, Any] = {}
    if config is not None:
        try:
            config.validate()
            cfg_dict = config.to_dict()
        except ValueError:
            cfg_dict = {}
    return {
        "status": status,
        "method": METHOD,
        "task": TASK,
        "engine_version": ENGINE_VERSION,
        "reason": reason,
        "parameter_statistics": "unavailable",
        "activation_statistics": "unavailable",
        "model": _model_info(model_id=model_id, model_type=model_type, framework=None, access=access),
        "structure": {"status": "not_available", "reason": reason},
        "parameters": {"status": "unavailable", "reason": reason, "tensors": []},
        "activations": {"status": "unavailable", "reason": reason, "layers": []},
        "config": cfg_dict,
        "statistics": {},
        "errors": list(errors or []),
        "warnings": [],
        "fingerprint": {"status": "not_computed", "algorithm": "sha256", "digest": None},
        "limitations": list(LIMITATIONS),
    }


def _resolve_config(config: Optional[ModelStatisticsConfig]) -> Tuple[ModelStatisticsConfig, Optional[str]]:
    cfg = config if config is not None else ModelStatisticsConfig()
    try:
        cfg.validate()
    except (ValueError, AttributeError, TypeError) as exc:
        return ModelStatisticsConfig(), f"invalid configuration: {exc}"
    return cfg, None


def _check_model_id(model_id: Optional[str]) -> Optional[str]:
    if model_id is not None and not isinstance(model_id, str):
        return "model_id must be a string or None"
    return None


# --------------------------------------------------------------------------- #
# Named-array analysis (framework independent)
# --------------------------------------------------------------------------- #
def analyze_named_arrays(
    tensors: Mapping[str, Any],
    config: Optional[ModelStatisticsConfig] = None,
    *,
    model_id: Optional[str] = None,
    model_type: Optional[str] = None,
) -> Dict[str, Any]:
    """Parameter statistics for an in-memory mapping of name -> array/tensor.

    Nothing is loaded or unpickled. Every entry is treated as a parameter of
    unknown trainability. Module structure and activations are unavailable
    because a bare mapping cannot be executed.
    """
    cfg, cfg_error = _resolve_config(config)
    id_error = _check_model_id(model_id)
    if cfg_error or id_error:
        return build_unavailable_report(
            cfg_error or id_error or "invalid input", status="error", access="white_box",
            model_id=model_id if id_error is None else None, errors=[cfg_error or id_error or ""],
        )
    if not isinstance(tensors, Mapping):
        return build_unavailable_report(
            "tensors must be a mapping of name -> array", status="error", access="white_box",
            model_id=model_id, errors=["tensors must be a mapping of name -> array"],
        )

    sources: List[_TensorSource] = []
    for name in sorted(str(k) for k in tensors):
        value = tensors[name] if name in tensors else next(v for k, v in tensors.items() if str(k) == name)
        if hasattr(value, "detach"):
            shape = tuple(int(d) for d in value.shape)
            dtype = _dtype_name(value.dtype)
            numel = int(value.numel())
            getter: Callable[[], np.ndarray] = (lambda v=value: _tensor_to_numpy(v))
        else:
            arr = np.asarray(value)
            shape, dtype, numel = tuple(int(d) for d in arr.shape), _dtype_name(arr.dtype), int(arr.size)
            getter = (lambda a=arr: a)
        sources.append(_TensorSource(name, "parameter", None, shape, dtype, numel, getter))

    parameters = _build_parameter_section(sources, cfg)
    structure = {
        "status": "not_available",
        "reason": "module structure is not available for a bare mapping of named tensors",
    }
    activations = {
        "status": "unavailable",
        "reason": "activation statistics require an executable model object",
        "layers": [],
    }
    warnings = _param_warnings(parameters)
    return _assemble_report(
        model_info=_model_info(model_id=model_id, model_type=model_type or "named_tensors",
                               framework="named_tensors", access="white_box"),
        structure=structure, parameters=parameters, activations=activations,
        cfg=cfg, errors=[], warnings=warnings,
    )


def _param_warnings(parameters: Mapping[str, Any]) -> List[str]:
    unavailable = parameters.get("unavailable_tensors") or []
    if not unavailable:
        return []
    return [f"statistics unavailable for {len(unavailable)} tensor(s): " + ", ".join(unavailable[:10])
            + (" ..." if len(unavailable) > 10 else "")]


# --------------------------------------------------------------------------- #
# PyTorch analysis (duck-typed; torch imported lazily and only for activations)
# --------------------------------------------------------------------------- #
def _is_inspectable_module(obj: Any) -> bool:
    needed = ("named_parameters", "named_buffers", "named_modules", "register_forward_hook", "modules")
    return all(callable(getattr(obj, attr, None)) for attr in needed)


def _torch_sources(model: Any) -> List[_TensorSource]:
    sources: List[_TensorSource] = []
    for kind, iterator in (("parameter", model.named_parameters()), ("buffer", model.named_buffers())):
        for name, tensor in iterator:
            trainable = bool(getattr(tensor, "requires_grad", False)) if kind == "parameter" else False
            sources.append(_TensorSource(
                str(name), kind, trainable,
                tuple(int(d) for d in tensor.shape), _dtype_name(tensor.dtype), int(tensor.numel()),
                (lambda t=tensor: _tensor_to_numpy(t)),
            ))
    return sources


def _torch_structure(model: Any, cfg: ModelStatisticsConfig) -> Dict[str, Any]:
    modules = [(str(name), type(mod).__name__, len(list(mod.children())) == 0) for name, mod in model.named_modules()]
    type_counts: Dict[str, int] = {}
    for _, type_name, _ in modules:
        type_counts[type_name] = type_counts.get(type_name, 0) + 1
    listed = [{"name": n if n else "<root>", "type": t} for n, t, _ in modules[: cfg.max_listed_modules]]
    return {
        "status": "available",
        "model_type": type(model).__name__,
        "module_count": len(modules),
        "leaf_module_count": sum(1 for _, _, leaf in modules if leaf),
        "module_type_counts": {k: type_counts[k] for k in sorted(type_counts)},
        "modules": listed,
        "modules_truncated": len(modules) > cfg.max_listed_modules,
        "layout_digest": _sha256_text(_canonical_json([[n, t] for n, t, _ in modules])),
    }


def _iter_output_tensors(output: Any) -> Iterator[Tuple[str, Any]]:
    def is_tensor(x: Any) -> bool:
        return hasattr(x, "detach") and hasattr(x, "shape")

    if is_tensor(output):
        yield "", output
    elif isinstance(output, (tuple, list)):
        for i, item in enumerate(output):
            if is_tensor(item):
                yield f"[{i}]", item


class _LayerRecord:
    def __init__(self, module_type: str, sample_cap: int) -> None:
        self.module_type = module_type
        self.acc = _RunningStats(sample_cap)
        self.call_count = 0
        self.shape: Optional[Tuple[int, ...]] = None
        self.dtype: Optional[str] = None
        self.shape_consistent = True

    def add(self, array: np.ndarray, dtype: str) -> None:
        per_sample = tuple(int(d) for d in array.shape[1:])
        if self.shape is None:
            self.shape, self.dtype = per_sample, dtype
        elif per_sample != self.shape:
            self.shape_consistent = False
        self.call_count += 1
        self.acc.update(array)


def _select_modules(model: Any, scope: str) -> List[Tuple[str, str, Any]]:
    selected: List[Tuple[str, str, Any]] = []
    for name, module in model.named_modules():
        is_leaf = len(list(module.children())) == 0
        if scope == "leaf" and (name == "" or not is_leaf):
            continue
        selected.append((str(name) if name else "<root>", type(module).__name__, module))
    return selected


def _capture_activations(
    model: Any, torch: Any, batch: np.ndarray, probe_info: Dict[str, Any], cfg: ModelStatisticsConfig
) -> Dict[str, Any]:
    """Run probes through ``model`` with temporary forward hooks.

    Hooks are always removed and per-module training flags restored, even on
    failure. Weights are never modified.
    """
    targets = _select_modules(model, cfg.activation_scope)
    sample_cap = cfg.percentile_sample_size if (cfg.include_percentiles and cfg.percentiles) else 0
    records: Dict[str, _LayerRecord] = {}
    called: set = set()
    layer_errors: Dict[str, str] = {}
    handles: List[Any] = []
    training_flags = [(m, bool(getattr(m, "training", False))) for m in model.modules()]

    def make_hook(layer_name: str, module_type: str) -> Callable[..., None]:
        def hook(_module: Any, _inputs: Any, output: Any) -> None:
            called.add(layer_name)
            for suffix, tensor in _iter_output_tensors(output):
                key = layer_name + suffix
                try:
                    array = _tensor_to_numpy(tensor)
                    record = records.setdefault(key, _LayerRecord(module_type, sample_cap))
                    record.add(array, _dtype_name(tensor.dtype))
                except Exception as exc:  # per-layer problems are reported, not fatal
                    layer_errors[key] = _error_text(exc)
            return None
        return hook

    try:
        for name, module_type, module in targets:
            handles.append(module.register_forward_hook(make_hook(name, module_type)))
        model.eval()
        first_param = next(iter(model.parameters()), None)
        with torch.no_grad():
            for start in range(0, int(batch.shape[0]), cfg.batch_size):
                x = torch.from_numpy(np.ascontiguousarray(batch[start:start + cfg.batch_size]))
                if first_param is not None:
                    if getattr(first_param, "is_floating_point", lambda: False)():
                        x = x.to(device=first_param.device, dtype=first_param.dtype)
                    else:
                        x = x.to(device=first_param.device)
                model(x)
    except Exception as exc:
        return {
            "status": "error",
            "reason": f"forward pass failed during activation capture: {_error_text(exc)}",
            "scope": cfg.activation_scope,
            "probes": probe_info,
            "layers": [],
        }
    finally:
        for handle in handles:
            handle.remove()
        for module, flag in training_flags:
            module.training = flag

    percentiles = tuple(cfg.percentiles) if sample_cap > 0 else ()
    layers = []
    for key in sorted(records):
        rec = records[key]
        layers.append({
            "name": key,
            "module_type": rec.module_type,
            "call_count": rec.call_count,
            "output_shape": list(rec.shape or ()),
            "shape_consistent": rec.shape_consistent,
            "dtype": rec.dtype,
            "statistics": rec.acc.finalize(percentiles),
        })
    target_names = sorted(name for name, _, _ in targets)
    return {
        "status": "completed",
        "scope": cfg.activation_scope,
        "output_shape_note": "shapes exclude the batch dimension",
        "probes": probe_info,
        "layer_count": len(layers),
        "layers": layers,
        "layers_not_called": [n for n in target_names if n not in called],
        "layer_errors": {k: layer_errors[k] for k in sorted(layer_errors)},
    }


def _activation_section(
    model: Any, images: Any, cfg: ModelStatisticsConfig, probe_set_id: Optional[str]
) -> Dict[str, Any]:
    if images is None:
        return {"status": "not_requested", "reason": "no probe images supplied", "probes": None, "layers": []}
    try:
        batch, probe_info = prepare_probe_batch(images, cfg, probe_set_id)
    except (ValueError, TypeError) as exc:
        return {"status": "error", "reason": f"invalid probe images: {exc}", "probes": None, "layers": []}
    torch = _import_torch()
    if torch is None:
        return {
            "status": "unavailable",
            "reason": "PyTorch is not importable; activation capture requires it",
            "probes": probe_info,
            "layers": [],
        }
    return _capture_activations(model, torch, batch, probe_info, cfg)


def analyze_torch_model(
    model: Any,
    images: Any = None,
    config: Optional[ModelStatisticsConfig] = None,
    *,
    model_id: Optional[str] = None,
    probe_set_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Parameter, structure and (optionally) activation statistics for a
    PyTorch ``nn.Module`` (or a TorchScript module loaded by the caller).

    ``images`` are optional controlled probes (see ``prepare_probe_batch``).
    Without images, activations are reported as ``not_requested``. The model
    is executed in eval mode under ``torch.no_grad()``; weights are not
    modified and module training flags are restored afterwards.
    """
    cfg, cfg_error = _resolve_config(config)
    id_error = _check_model_id(model_id)
    if cfg_error or id_error:
        message = cfg_error or id_error or "invalid input"
        return build_unavailable_report(message, status="error", access="white_box", errors=[message])
    if not _is_inspectable_module(model):
        return build_unavailable_report(
            "object does not expose PyTorch-style parameter / module inspection", model_id=model_id,
            model_type=type(model).__name__, config=cfg,
        )
    try:
        sources = _torch_sources(model)
        structure = _torch_structure(model, cfg)
    except Exception as exc:
        message = f"model inspection failed: {_error_text(exc)}"
        return build_unavailable_report(message, status="error", access="white_box", model_id=model_id,
                                        model_type=type(model).__name__, config=cfg, errors=[message])
    parameters = _build_parameter_section(sources, cfg)
    activations = _activation_section(model, images, cfg, probe_set_id)

    errors: List[str] = []
    warnings = _param_warnings(parameters)
    if activations.get("status") == "error":
        errors.append(str(activations.get("reason")))
    if activations.get("layer_errors"):
        warnings.append(f"activation statistics unavailable for {len(activations['layer_errors'])} layer output(s)")
    return _assemble_report(
        model_info=_model_info(model_id=model_id, model_type=type(model).__name__,
                               framework="pytorch", access="white_box"),
        structure=structure, parameters=parameters, activations=activations,
        cfg=cfg, errors=errors, warnings=warnings,
    )


def load_torchscript_model(path: Any, *, trusted: bool = False) -> Any:
    """Explicit, opt-in TorchScript loader.

    WARNING: TorchScript deserialization must only be performed on trusted
    artifacts, and B3 does not sandbox model execution. ``trusted=True`` must
    be passed to acknowledge this. B3's own analysis functions never call
    this helper. Activation hooks on a scripted module only fire for modules
    invoked from Python; unreached layers are listed in ``layers_not_called``.
    """
    if trusted is not True:
        raise ValueError(
            "refusing to deserialize a TorchScript artifact without trusted=True; "
            "only load artifacts you trust (B3 does not sandbox model execution)"
        )
    torch = _import_torch()
    if torch is None:
        raise RuntimeError("PyTorch is not available")
    return torch.jit.load(str(path), map_location="cpu")


def analyze_model(
    model: Any = None,
    images: Any = None,
    config: Optional[ModelStatisticsConfig] = None,
    *,
    model_id: Optional[str] = None,
    access: str = "auto",
    probe_set_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Dispatch to the right analysis for the supplied model representation.

    * ``access="black_box"`` or ``model is None`` -> ``unavailable``.
    * path / bytes -> ``unavailable`` (B3 never loads or unpickles files).
    * mapping of name -> array/tensor -> ``analyze_named_arrays``.
    * PyTorch-style module -> ``analyze_torch_model``.
    * anything else (e.g. a bare predict callable) -> ``unavailable``.
    """
    if access not in ("auto", "white_box", "black_box"):
        message = f"access must be 'auto', 'white_box' or 'black_box', got {access!r}"
        return build_unavailable_report(message, status="error", errors=[message])
    id_error = _check_model_id(model_id)
    if id_error:
        return build_unavailable_report(id_error, status="error", errors=[id_error])
    cfg, cfg_error = _resolve_config(config)
    if cfg_error:
        return build_unavailable_report(cfg_error, status="error", access="white_box", errors=[cfg_error])

    if access == "black_box" or model is None:
        return build_unavailable_report(BLACK_BOX_REASON, model_id=model_id, config=cfg)
    if isinstance(model, (str, bytes, bytearray, os.PathLike)):
        return build_unavailable_report(
            "a file path or raw bytes was supplied; B3 never loads checkpoints or unpickles files. "
            "Supply an already-instantiated model object",
            model_id=model_id, access="not_inspected", config=cfg,
        )
    if isinstance(model, Mapping):
        return analyze_named_arrays(model, cfg, model_id=model_id)
    if _is_inspectable_module(model):
        return analyze_torch_model(model, images, cfg, model_id=model_id, probe_set_id=probe_set_id)
    return build_unavailable_report(
        "object exposes no parameter / module inspection interface and is treated as black-box: "
        + BLACK_BOX_REASON,
        model_id=model_id, model_type=type(model).__name__, config=cfg,
    )


# --------------------------------------------------------------------------- #
# Reference-vs-assessed comparison
# --------------------------------------------------------------------------- #
def _issue(code: str, severity: str, detail: str) -> Dict[str, str]:
    return {"code": code, "severity": severity, "detail": detail}


def _metric(
    reference: Optional[float],
    assessed: Optional[float],
    basis: str,
    threshold: float,
    eps: float,
    scale: Optional[float] = None,
) -> Optional[Dict[str, Any]]:
    """One measurable difference with absolute / relative / normalized forms."""
    if reference is None and assessed is None:
        return None
    if reference is None or assessed is None:
        return {
            "reference": reference, "assessed": assessed, "absolute_difference": None,
            "relative_difference": None, "normalized_difference": None,
            "basis": basis, "threshold": threshold, "exceeded": True, "missing_statistic": True,
        }
    absolute = abs(assessed - reference)
    relative = absolute / max(abs(reference), eps)
    normalized = absolute / (scale + eps) if scale is not None else None
    used = {"absolute": absolute, "relative": relative, "normalized": normalized}[basis]
    if used is None:
        used = relative
    return {
        "reference": reference, "assessed": assessed,
        "absolute_difference": _clean_float(absolute), "relative_difference": _clean_float(relative),
        "normalized_difference": _clean_float(normalized),
        "basis": basis, "threshold": threshold, "exceeded": bool(used > threshold),
        "missing_statistic": False,
    }


def _statistics_metrics(
    ref: Mapping[str, Any], ass: Mapping[str, Any], *, mean_norm: float, std_rel: float,
    zero_abs: float, extreme_norm: float, nonfinite_abs: float, eps: float,
) -> Dict[str, Dict[str, Any]]:
    ref_std = ref.get("std")
    lo, hi = ref.get("min"), ref.get("max")
    span = (hi - lo) if (lo is not None and hi is not None) else None
    metrics: Dict[str, Optional[Dict[str, Any]]] = {
        "mean": _metric(ref.get("mean"), ass.get("mean"), "normalized", mean_norm, eps,
                        scale=ref_std if ref_std is not None else 0.0),
        "std": _metric(ref.get("std"), ass.get("std"), "relative", std_rel, eps),
        "zero_fraction": _metric(ref.get("zero_fraction"), ass.get("zero_fraction"), "absolute", zero_abs, eps),
        "min": _metric(lo, ass.get("min"), "normalized", extreme_norm, eps, scale=span if span is not None else 0.0),
        "max": _metric(hi, ass.get("max"), "normalized", extreme_norm, eps, scale=span if span is not None else 0.0),
    }
    for key in ("nan_count", "posinf_count", "neginf_count"):
        metrics[key] = _metric(float(ref.get(key, 0)), float(ass.get(key, 0)), "absolute", nonfinite_abs, eps)
    return {k: v for k, v in metrics.items() if v is not None}


def _flags(metrics: Mapping[str, Mapping[str, Any]]) -> List[str]:
    return sorted(k for k, v in metrics.items() if v.get("exceeded"))


def _compare_structure(ref: Mapping[str, Any], ass: Mapping[str, Any], th: ComparisonThresholds) -> Dict[str, Any]:
    items: List[Dict[str, Any]] = []
    rt, at = ref["parameters"].get("totals") or {}, ass["parameters"].get("totals") or {}
    for key in ("tensor_count", "parameter_tensor_count", "buffer_tensor_count", "total_parameter_count",
                "trainable_parameter_count", "non_trainable_parameter_count", "buffer_element_count"):
        r, a = rt.get(key), at.get(key)
        m = _metric(None if r is None else float(r), None if a is None else float(a),
                    "relative", th.count_rel_diff, th.eps)
        if m is not None:
            items.append({"item": key, **m})
    r_layout, a_layout = rt.get("layout_digest"), at.get("layout_digest")
    if r_layout is not None and a_layout is not None:
        items.append({"item": "parameter_layout_digest", "reference": r_layout, "assessed": a_layout,
                      "exceeded": r_layout != a_layout})
    rs, as_ = ref.get("structure") or {}, ass.get("structure") or {}
    module_comparison = "unavailable"
    if rs.get("status") == "available" and as_.get("status") == "available":
        module_comparison = "compared"
        for key in ("model_type", "layout_digest"):
            items.append({"item": f"module_{key}", "reference": rs.get(key), "assessed": as_.get(key),
                          "exceeded": rs.get(key) != as_.get(key)})
        for key in ("module_count", "leaf_module_count"):
            m = _metric(float(rs[key]), float(as_[key]), "relative", th.count_rel_diff, th.eps)
            if m is not None:
                items.append({"item": key, **m})
        r_types, a_types = rs.get("module_type_counts") or {}, as_.get("module_type_counts") or {}
        if r_types != a_types:
            diff = {k: {"reference": r_types.get(k, 0), "assessed": a_types.get(k, 0)}
                    for k in sorted(set(r_types) | set(a_types)) if r_types.get(k, 0) != a_types.get(k, 0)}
            items.append({"item": "module_type_counts", "differences": diff, "exceeded": True})
    return {
        "module_structure_comparison": module_comparison,
        "items": items,
        "flagged_items": [i["item"] for i in items if i.get("exceeded")],
    }


def _compare_parameters(ref: Mapping[str, Any], ass: Mapping[str, Any], th: ComparisonThresholds
                        ) -> Tuple[str, List[Dict[str, str]], Dict[str, Any]]:
    rp, ap = ref["parameters"], ass["parameters"]
    if rp.get("status") not in ("completed", "partial") or ap.get("status") not in ("completed", "partial"):
        reason = f"parameters status: reference={rp.get('status')}, assessed={ap.get('status')}"
        return "unavailable", [_issue("parameters_unavailable", "blocking", reason)], {}
    r_map = {t["name"]: t for t in rp.get("tensors", [])}
    a_map = {t["name"]: t for t in ap.get("tensors", [])}
    common = sorted(set(r_map) & set(a_map))
    only_ref, only_ass = sorted(set(r_map) - set(a_map)), sorted(set(a_map) - set(r_map))
    issues: List[Dict[str, str]] = []
    if (r_map or a_map) and not common:
        issues.append(_issue("no_common_tensors", "blocking", "reference and assessed share no tensor names"))
        return "incompatible", issues, {}

    flagged: List[Dict[str, Any]] = []
    digest_differs = 0
    compared = 0
    for name in common:
        r, a = r_map[name], a_map[name]
        entry: Dict[str, Any] = {"name": name, "flags": []}
        if r["shape"] != a["shape"]:
            entry.update({"flags": ["shape_mismatch"], "reference_shape": r["shape"], "assessed_shape": a["shape"]})
            issues.append(_issue("tensor_shape_mismatch", "warning", f"{name}: statistics not compared"))
            flagged.append(entry)
            continue
        if r.get("status") != "available" or a.get("status") != "available":
            entry["flags"] = ["statistics_unavailable"]
            flagged.append(entry)
            continue
        compared += 1
        flags: List[str] = []
        if r["dtype"] != a["dtype"]:
            flags.append("dtype_mismatch")
            entry.update({"reference_dtype": r["dtype"], "assessed_dtype": a["dtype"]})
        rs, as_ = r["statistics"], a["statistics"]
        if rs.get("digest_sha256") and as_.get("digest_sha256") and rs["digest_sha256"] != as_["digest_sha256"]:
            digest_differs += 1
            entry["tensor_digest_differs"] = True
        metrics = _statistics_metrics(
            rs, as_, mean_norm=th.param_mean_norm_diff, std_rel=th.param_std_rel_diff,
            zero_abs=th.param_zero_fraction_abs_diff, extreme_norm=th.param_extreme_norm_diff,
            nonfinite_abs=th.non_finite_count_abs_diff, eps=th.eps,
        )
        flags.extend(_flags(metrics))
        if flags:
            entry["flags"] = sorted(flags)
            entry["metrics"] = {k: metrics[k] for k in sorted(metrics) if metrics[k].get("exceeded")}
            flagged.append(entry)
    if only_ref or only_ass:
        issues.append(_issue("tensor_set_mismatch", "warning",
                             f"{len(only_ref)} tensor(s) only in reference, {len(only_ass)} only in assessed"))
    section_status = "partially_compatible" if issues else "compatible"
    return section_status, issues, {
        "compared_tensor_count": compared,
        "flagged_tensors": flagged,
        "unmatched_reference_tensors": only_ref,
        "unmatched_assessed_tensors": only_ass,
        "tensors_with_different_digest": digest_differs,
    }


def _compare_activations(ref: Mapping[str, Any], ass: Mapping[str, Any], th: ComparisonThresholds
                         ) -> Tuple[str, List[Dict[str, str]], Dict[str, Any]]:
    ra, aa = ref["activations"], ass["activations"]
    rs, as_ = ra.get("status"), aa.get("status")
    if rs == "not_requested" and as_ == "not_requested":
        return "not_requested", [], {}
    if rs != "completed" or as_ != "completed":
        reason = f"activation status: reference={rs}, assessed={as_}"
        return "unavailable", [_issue("activations_unavailable", "blocking", reason)], {}
    issues: List[Dict[str, str]] = []
    rdig = (ra.get("probes") or {}).get("probe_digest")
    adig = (aa.get("probes") or {}).get("probe_digest")
    if rdig is None or adig is None or rdig != adig:
        issues.append(_issue("probe_configuration_mismatch", "blocking",
                             "probe images differ (or probe digest missing); activation statistics are not comparable"))
    if ra.get("scope") != aa.get("scope"):
        issues.append(_issue("activation_scope_mismatch", "blocking",
                             f"reference scope={ra.get('scope')}, assessed scope={aa.get('scope')}"))
    if issues:
        return "incompatible", issues, {}
    r_map = {layer["name"]: layer for layer in ra.get("layers", [])}
    a_map = {layer["name"]: layer for layer in aa.get("layers", [])}
    common = sorted(set(r_map) & set(a_map))
    only_ref, only_ass = sorted(set(r_map) - set(a_map)), sorted(set(a_map) - set(r_map))
    if (r_map or a_map) and not common:
        return "incompatible", [_issue("no_common_layers", "blocking", "reference and assessed share no layers")], {}

    flagged: List[Dict[str, Any]] = []
    compared = 0
    for name in common:
        r, a = r_map[name], a_map[name]
        entry: Dict[str, Any] = {"name": name, "flags": []}
        if r["output_shape"] != a["output_shape"]:
            entry.update({"flags": ["activation_shape_mismatch"], "reference_shape": r["output_shape"],
                          "assessed_shape": a["output_shape"]})
            issues.append(_issue("layer_shape_mismatch", "warning", f"{name}: statistics not compared"))
            flagged.append(entry)
            continue
        compared += 1
        flags: List[str] = []
        if r.get("dtype") != a.get("dtype"):
            flags.append("dtype_mismatch")
        metrics = _statistics_metrics(
            r["statistics"], a["statistics"], mean_norm=th.activation_mean_norm_diff,
            std_rel=th.activation_std_rel_diff, zero_abs=th.activation_zero_fraction_abs_diff,
            extreme_norm=th.activation_extreme_norm_diff, nonfinite_abs=th.non_finite_count_abs_diff, eps=th.eps,
        )
        r_pct, a_pct = r["statistics"].get("percentiles") or {}, a["statistics"].get("percentiles") or {}
        scale = r["statistics"].get("std")
        for key in sorted(set(r_pct) & set(a_pct)):
            m = _metric(r_pct[key], a_pct[key], "normalized", th.activation_percentile_norm_diff, th.eps,
                        scale=scale if scale is not None else 0.0)
            if m is not None:
                metrics[key] = m
        flags.extend(_flags(metrics))
        if flags:
            entry["flags"] = sorted(flags)
            entry["metrics"] = {k: metrics[k] for k in sorted(metrics) if metrics[k].get("exceeded")}
            flagged.append(entry)
    if only_ref or only_ass:
        issues.append(_issue("layer_set_mismatch", "warning",
                             f"{len(only_ref)} layer(s) only in reference, {len(only_ass)} only in assessed"))
    return ("partially_compatible" if issues else "compatible"), issues, {
        "compared_layer_count": compared,
        "flagged_layers": flagged,
        "unmatched_reference_layers": only_ref,
        "unmatched_assessed_layers": only_ass,
    }


def _comparison_result(
    status: str, compat_status: str, issues: List[Dict[str, str]], th_dict: Dict[str, Any],
    reference: Any, assessed: Any, sections: Optional[Dict[str, str]] = None,
    body: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    def fp(report: Any) -> Optional[str]:
        if isinstance(report, Mapping) and isinstance(report.get("fingerprint"), Mapping):
            return report["fingerprint"].get("digest")
        return None

    def mid(report: Any) -> Optional[str]:
        if isinstance(report, Mapping) and isinstance(report.get("model"), Mapping):
            return report["model"].get("model_id")
        return None

    result: Dict[str, Any] = {
        "status": status,
        "method": COMPARISON_METHOD,
        "task": TASK,
        "engine_version": ENGINE_VERSION,
        "reference": {"model_id": mid(reference), "fingerprint_digest": fp(reference)},
        "assessed": {"model_id": mid(assessed), "fingerprint_digest": fp(assessed)},
        "compatibility": {"status": compat_status, "sections": sections or {}, "issues": issues},
        "thresholds": th_dict,
        "structure": {},
        "parameters": {},
        "activations": {},
        "summary": {},
        "limitations": list(COMPARISON_LIMITATIONS),
    }
    if body:
        result.update(body)
    return result


def compare_reports(
    reference: Mapping[str, Any],
    assessed: Mapping[str, Any],
    thresholds: Optional[ComparisonThresholds] = None,
) -> Dict[str, Any]:
    """Compare two B3 reports and list measurable deviations.

    Compatibility is checked first (report validity, status, task, engine
    version, probe configuration, tensor / layer overlap and shapes). Only
    comparable sections are compared. Output contains candidate anomalies
    for analyst review; there is no score, ranking or safe/unsafe verdict.
    """
    th = thresholds if thresholds is not None else ComparisonThresholds()
    try:
        th.validate()
    except (ValueError, AttributeError, TypeError) as exc:
        return _comparison_result("error", "unavailable", [_issue("invalid_thresholds", "blocking", str(exc))],
                                  {}, reference, assessed)
    th_dict = th.to_dict()

    issues: List[Dict[str, str]] = []
    for label, report in (("reference", reference), ("assessed", assessed)):
        if not isinstance(report, Mapping) or report.get("method") != METHOD:
            issues.append(_issue("invalid_report", "blocking", f"{label} is not a B3 report"))
    if issues:
        return _comparison_result("incompatible", "incompatible", issues, th_dict, reference, assessed)

    for label, report in (("reference", reference), ("assessed", assessed)):
        if report.get("status") != "completed":
            issues.append(_issue("report_not_completed", "blocking",
                                 f"{label} report status is '{report.get('status')}'"))
    if issues:
        return _comparison_result("unavailable", "unavailable", issues, th_dict, reference, assessed)

    if reference.get("task") != assessed.get("task"):
        issues.append(_issue("task_mismatch", "blocking",
                             f"reference task={reference.get('task')}, assessed task={assessed.get('task')}"))
    if reference.get("engine_version") != assessed.get("engine_version"):
        issues.append(_issue("engine_version_mismatch", "blocking",
                             "reports were produced by different B3 versions; regenerate the reference"))
    for label, report in (("reference", reference), ("assessed", assessed)):
        for section in ("parameters", "activations", "structure"):
            if not isinstance(report.get(section), Mapping):
                issues.append(_issue("missing_required_statistics", "blocking",
                                     f"{label} report lacks the '{section}' section"))
    if issues:
        return _comparison_result("incompatible", "incompatible", issues, th_dict, reference, assessed)

    p_status, p_issues, p_body = _compare_parameters(reference, assessed, th)
    a_status, a_issues, a_body = _compare_activations(reference, assessed, th)
    sections = {"parameters": p_status, "activations": a_status}
    all_issues = p_issues + a_issues
    comparable = [s for s in (p_status, a_status) if s in ("compatible", "partially_compatible")]

    if not comparable:
        overall = "incompatible" if "incompatible" in sections.values() else "unavailable"
        return _comparison_result(overall, overall, all_issues, th_dict, reference, assessed, sections)

    structure_body = _compare_structure(reference, assessed, th) if p_status != "unavailable" else {}
    flagged_tensors = p_body.get("flagged_tensors", [])
    flagged_layers = a_body.get("flagged_layers", [])
    unmatched = (len(p_body.get("unmatched_reference_tensors", [])) + len(p_body.get("unmatched_assessed_tensors", []))
                 + len(a_body.get("unmatched_reference_layers", [])) + len(a_body.get("unmatched_assessed_layers", [])))
    flagged_structure = structure_body.get("flagged_items", [])
    total = len(flagged_tensors) + len(flagged_layers) + len(flagged_structure) + unmatched
    fully = all(s in ("compatible", "not_requested") for s in sections.values())
    summary = {
        "candidate_anomaly_count": total,
        "flagged_structure_item_count": len(flagged_structure),
        "flagged_tensor_count": len(flagged_tensors),
        "flagged_layer_count": len(flagged_layers),
        "unmatched_tensor_or_layer_count": unmatched,
        "compared_tensor_count": p_body.get("compared_tensor_count", 0),
        "compared_layer_count": a_body.get("compared_layer_count", 0),
        "tensors_with_different_digest": p_body.get("tensors_with_different_digest", 0),
        "requires_review": total > 0,
        "interpretation": (
            "Candidate anomalies are measurable deviations that require analyst review. They do not "
            "establish tampering, and their absence does not establish integrity."
        ),
    }
    return _comparison_result(
        "completed", "compatible" if fully else "partially_compatible", all_issues, th_dict,
        reference, assessed, sections,
        {"structure": structure_body, "parameters": p_body, "activations": a_body, "summary": summary},
    )
