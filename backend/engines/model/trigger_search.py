"""TRACER-CV B4 - Trigger Search / Reconstruction.

Deterministic, offline, image-classification trigger-probe engine.

B4 searches for localized perturbations that repeatedly change model
behaviour across multiple input images. It is intended to provide
candidate trigger-like evidence for analyst review.

ASSURANCE POSITION
------------------
B4 does NOT prove that a model contains a backdoor.

A repeated prediction change can have many explanations, including
ordinary model sensitivity, distribution shift, preprocessing effects,
or an intentionally meaningful visual feature.

The engine therefore reports:
    * candidate trigger-like behaviour,
    * measurable prediction changes,
    * confidence changes,
    * spatial/pattern consistency,
    * affected samples,
    * exact search configuration.

It does NOT produce:
    * maliciousness probability,
    * compromise probability,
    * safe/unsafe verdict,
    * backdoor proof.

SCOPE
-----
* image classification
* deterministic local patch search
* offline execution
* no model retraining
* accessible callable model / adapter
* optional PyTorch adapter

The engine deliberately avoids loading arbitrary checkpoint files.
Model loading remains outside B4 and should use the project's trusted
model-loading workflow.

INPUT
-----
Images are HWC uint8 arrays or equivalent numeric arrays.

MODEL ADAPTER
-------------
An adapter must expose:

    predict(images) -> logits/probabilities

The returned array must have shape [N, C].

If raw logits are returned, B4 converts them to probabilities using
stable softmax.

If probabilities are returned, they are normalized safely.

MODEL ID
--------
The caller may provide B1's model_id / SHA-256. B4 records it with
the evidence but does not independently hash or load the model.

No timestamps are generated, so identical inputs/configuration produce
deterministic reports.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, asdict
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import numpy as np


ENGINE_VERSION = "b4-1.0"
METHOD = "deterministic localized trigger search"
TASK = "image_classification"

LIMITATIONS = (
    "B4 identifies trigger-like behavioural changes for analyst review; "
    "it does not prove a backdoor or malicious modification.",
    "Prediction changes may result from ordinary model sensitivity, "
    "distribution shift, preprocessing effects, or meaningful image features.",
    "The search covers only the configured patch sizes, positions and patterns.",
    "Results depend on the supplied input images and model preprocessing.",
    "B4 currently targets image classification and does not assess detection "
    "or segmentation models.",
    "Black-box models can be assessed only through their prediction interface; "
    "parameter and activation evidence requires separate white-box engines.",
)

DEFAULT_PATCH_SIZES = (8, 16)
DEFAULT_GRID_FRACTIONS = (0.25, 0.5, 0.75)
DEFAULT_PATTERNS = (
    "black",
    "white",
    "mean",
    "checkerboard",
)


@dataclass(frozen=True)
class TriggerSearchConfig:
    """Configuration for deterministic trigger search."""

    patch_sizes: Tuple[int, ...] = DEFAULT_PATCH_SIZES
    grid_fractions: Tuple[float, ...] = DEFAULT_GRID_FRACTIONS
    patterns: Tuple[str, ...] = DEFAULT_PATTERNS

    min_prediction_change_rate: float = 0.60
    min_confidence_gain: float = 0.05
    min_probability_l1_change: float = 1.0
    min_samples: int = 3

    max_images: int = 16
    seed: int = 1337

    def validate(self) -> None:
        if not self.patch_sizes:
            raise ValueError("patch_sizes cannot be empty")

        if any(int(x) <= 0 for x in self.patch_sizes):
            raise ValueError("patch sizes must be positive")

        if not self.grid_fractions:
            raise ValueError("grid_fractions cannot be empty")

        if any(float(x) < 0.0 or float(x) > 1.0 for x in self.grid_fractions):
            raise ValueError("grid fractions must be in [0, 1]")

        allowed = {"black", "white", "mean", "checkerboard"}
        unknown = set(self.patterns) - allowed
        if unknown:
            raise ValueError(f"unsupported trigger pattern(s): {sorted(unknown)}")

        if not 0.0 <= self.min_prediction_change_rate <= 1.0:
            raise ValueError("min_prediction_change_rate must be in [0, 1]")

        if self.min_confidence_gain < 0.0:
            raise ValueError("min_confidence_gain must be non-negative")

        if self.min_probability_l1_change < 0.0:
            raise ValueError("min_probability_l1_change must be non-negative")

        if self.min_samples < 1:
            raise ValueError("min_samples must be >= 1")

        if self.max_images < 1:
            raise ValueError("max_images must be >= 1")
        if self.min_confidence_gain < 0.0:
            raise ValueError("min_confidence_gain must be non-negative")

        if self.min_probability_l1_change < 0.0:
            raise ValueError("min_probability_l1_change must be non-negative")


@dataclass(frozen=True)
class CandidateSpec:
    """One deterministic trigger candidate."""

    patch_size: int
    x_fraction: float
    y_fraction: float
    pattern: str

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ClassificationAdapter:
    """Minimal B4 classification adapter protocol."""

    output_type = "auto"

    def predict(self, images: Sequence[np.ndarray]) -> np.ndarray:
        raise NotImplementedError


class CallableClassificationAdapter(ClassificationAdapter):
    """Adapter around a caller-supplied prediction callable.

    The callable must accept a sequence/list of HWC images and return an
    [N, C] array of logits or probabilities.
    """

    def __init__(self, predict_fn, output_type: str = "auto"):
        if not callable(predict_fn):
            raise TypeError("predict_fn must be callable")

        if output_type not in {"auto", "logits", "probabilities"}:
            raise ValueError("output_type must be auto, logits, or probabilities")

        self.predict_fn = predict_fn
        self.output_type = output_type

    def predict(self, images: Sequence[np.ndarray]) -> np.ndarray:
        return np.asarray(self.predict_fn(images))


class TorchClassificationAdapter(ClassificationAdapter):
    """Optional adapter for an already-instantiated PyTorch model.

    B4 never loads checkpoint files. The caller supplies an instantiated
    model object.

    The model is expected to accept NCHW float32 tensors. Images are scaled
    from uint8 [0,255] to [0,1] unless ``scale_inputs`` is False.
    """

    def __init__(
        self,
        model: Any,
        *,
        device: Optional[str] = None,
        output_type: str = "logits",
        scale_inputs: bool = True,
        mean: Optional[Sequence[float]] = None,
        std: Optional[Sequence[float]] = None,
    ):
        if model is None:
            raise ValueError("model is required")

        try:
            import torch
        except ImportError as exc:
            raise RuntimeError("PyTorch is required for TorchClassificationAdapter") from exc

        if output_type not in {"logits", "probabilities"}:
            raise ValueError("output_type must be logits or probabilities")

        self.torch = torch
        self.model = model
        self.output_type = output_type
        self.scale_inputs = bool(scale_inputs)
        self.mean = tuple(float(x) for x in mean) if mean is not None else None
        self.std = tuple(float(x) for x in std) if std is not None else None

        self.device = device or (
            "cuda" if torch.cuda.is_available() else "cpu"
        )

        self.model.to(self.device)
        self.model.eval()

    def predict(self, images: Sequence[np.ndarray]) -> np.ndarray:
        if not images:
            raise ValueError("at least one image is required")

        arrays = []
        for image in images:
            arr = _validate_image(image)
            x = arr.astype(np.float32)

            if self.scale_inputs:
                x = x / 255.0

            x = np.transpose(x, (2, 0, 1))
            arrays.append(x)

        batch = np.stack(arrays, axis=0).astype(np.float32, copy=False)

        tensor = self.torch.from_numpy(batch).to(self.device)

        if self.mean is not None:
            if len(self.mean) != 3:
                raise ValueError("mean must have three channels")
            mean = self.torch.tensor(
                self.mean, dtype=tensor.dtype, device=tensor.device
            ).view(1, 3, 1, 1)
            tensor = tensor - mean

        if self.std is not None:
            if len(self.std) != 3:
                raise ValueError("std must have three channels")
            std = self.torch.tensor(
                self.std, dtype=tensor.dtype, device=tensor.device
            ).view(1, 3, 1, 1)
            tensor = tensor / std

        with self.torch.no_grad():
            output = self.model(tensor)

        if isinstance(output, (tuple, list)):
            output = output[0]

        if hasattr(output, "logits"):
            output = output.logits

        if not hasattr(output, "detach"):
            raise TypeError("model output is not a tensor")

        return output.detach().float().cpu().numpy()


def _validate_image(image: Any) -> np.ndarray:
    arr = np.asarray(image)

    if arr.ndim != 3:
        raise ValueError("image must be HWC")

    if arr.shape[2] != 3:
        raise ValueError("image must have exactly 3 channels")

    if arr.shape[0] < 2 or arr.shape[1] < 2:
        raise ValueError("image is too small")

    if not np.issubdtype(arr.dtype, np.number):
        raise TypeError("image must contain numeric values")

    if not np.all(np.isfinite(arr)):
        raise ValueError("image contains non-finite values")

    if arr.dtype != np.uint8:
        arr = np.clip(arr, 0, 255).astype(np.uint8)

    return np.ascontiguousarray(arr)


def _stable_softmax(logits: np.ndarray) -> np.ndarray:
    x = np.asarray(logits, dtype=np.float64)

    if x.ndim != 2:
        raise ValueError("model output must have shape [N, C]")

    if x.shape[0] == 0 or x.shape[1] < 2:
        raise ValueError("model output must contain N samples and at least 2 classes")

    if not np.all(np.isfinite(x)):
        raise ValueError("model output contains non-finite values")

    shifted = x - np.max(x, axis=1, keepdims=True)
    exp = np.exp(np.clip(shifted, -700.0, 700.0))
    denom = np.sum(exp, axis=1, keepdims=True)

    return exp / denom


def _normalize_probabilities(values: np.ndarray) -> np.ndarray:
    x = np.asarray(values, dtype=np.float64)

    if x.ndim != 2:
        raise ValueError("model output must have shape [N, C]")

    if not np.all(np.isfinite(x)):
        raise ValueError("model output contains non-finite values")

    if np.any(x < -1e-8):
        raise ValueError("probability output contains negative values")

    x = np.clip(x, 0.0, None)

    sums = np.sum(x, axis=1, keepdims=True)

    if np.any(sums <= 0):
        raise ValueError("probability output contains an all-zero row")

    return x / sums


def _prediction_to_probabilities(
    values: np.ndarray,
    output_type: str,
) -> np.ndarray:
    if output_type == "logits":
        return _stable_softmax(values)

    if output_type == "probabilities":
        return _normalize_probabilities(values)

    # Auto detection is deliberately conservative.
    arr = np.asarray(values, dtype=np.float64)

    if np.all(arr >= -1e-8):
        row_sums = np.sum(arr, axis=1)

        if np.all(np.isfinite(row_sums)) and np.allclose(
            row_sums, 1.0, atol=1e-4
        ):
            return _normalize_probabilities(arr)

    return _stable_softmax(arr)


def _predict_probabilities(
    adapter: ClassificationAdapter,
    images: Sequence[np.ndarray],
) -> np.ndarray:
    raw = np.asarray(adapter.predict(images))

    output_type = getattr(adapter, "output_type", "auto")

    return _prediction_to_probabilities(raw, output_type)


def _patch_coordinates(
    height: int,
    width: int,
    patch_size: int,
    x_fraction: float,
    y_fraction: float,
) -> Tuple[int, int, int]:
    size = min(int(patch_size), height, width)

    max_x = width - size
    max_y = height - size

    x = int(round(float(x_fraction) * max_x))
    y = int(round(float(y_fraction) * max_y))

    x = min(max(x, 0), max_x)
    y = min(max(y, 0), max_y)

    return x, y, size


def _make_patch(
    base: np.ndarray,
    *,
    x: int,
    y: int,
    size: int,
    pattern: str,
) -> np.ndarray:
    output = base.copy()
    region = output[y:y + size, x:x + size]

    if pattern == "black":
        region[:] = 0

    elif pattern == "white":
        region[:] = 255

    elif pattern == "mean":
        value = np.mean(base, axis=(0, 1), keepdims=True)
        region[:] = np.clip(value, 0, 255).astype(np.uint8)

    elif pattern == "checkerboard":
        yy, xx = np.indices((size, size))
        mask = ((xx + yy) % 2).astype(bool)
        region[mask] = 255
        region[~mask] = 0

    else:
        raise ValueError(f"unsupported trigger pattern: {pattern}")

    return output


def apply_trigger(
    image: np.ndarray,
    candidate: CandidateSpec,
) -> np.ndarray:
    """Apply one deterministic candidate trigger to an image."""

    base = _validate_image(image)

    x, y, size = _patch_coordinates(
        base.shape[0],
        base.shape[1],
        candidate.patch_size,
        candidate.x_fraction,
        candidate.y_fraction,
    )

    return _make_patch(
        base,
        x=x,
        y=y,
        size=size,
        pattern=candidate.pattern,
    )


def generate_candidates(
    image_shape: Tuple[int, int, int],
    config: Optional[TriggerSearchConfig] = None,
) -> List[CandidateSpec]:
    """Generate the deterministic candidate search grid."""

    cfg = config or TriggerSearchConfig()
    cfg.validate()

    height, width, channels = image_shape

    if channels != 3:
         raise ValueError("B4 requires three-channel images")

    candidates: List[CandidateSpec] = []

    for patch_size in cfg.patch_sizes:
        if patch_size > min(height, width):
            continue

        for y_fraction in cfg.grid_fractions:
            for x_fraction in cfg.grid_fractions:
                for pattern in cfg.patterns:
                    candidates.append(
                        CandidateSpec(
                            patch_size=int(patch_size),
                            x_fraction=float(x_fraction),
                            y_fraction=float(y_fraction),
                            pattern=pattern,
                        )
                    )

    return candidates


def _candidate_key(candidate: CandidateSpec) -> str:
    raw = (
        f"{candidate.patch_size}|"
        f"{candidate.x_fraction:.6f}|"
        f"{candidate.y_fraction:.6f}|"
        f"{candidate.pattern}"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _top_class(probabilities: np.ndarray) -> Tuple[int, float]:
    index = int(np.argmax(probabilities))
    return index, float(probabilities[index])


def _candidate_metrics(
    clean_probs: np.ndarray,
    patched_probs: np.ndarray,
    target_class: Optional[int],
) -> Dict[str, Any]:
    clean_classes = np.argmax(clean_probs, axis=1)
    patched_classes = np.argmax(patched_probs, axis=1)

    class_changed = patched_classes != clean_classes

    clean_conf = np.max(clean_probs, axis=1)
    patched_conf = np.max(patched_probs, axis=1)

    confidence_gain = patched_conf - clean_conf

    if target_class is None:
        target_hits = class_changed
        resolved_target = None
    else:
        target_hits = patched_classes == int(target_class)
        resolved_target = int(target_class)

    return {
        "sample_count": int(len(clean_probs)),
        "class_change_count": int(np.sum(class_changed)),
        "class_change_rate": float(np.mean(class_changed)),
        "target_class": resolved_target,
        "target_hit_count": int(np.sum(target_hits)),
        "target_hit_rate": float(np.mean(target_hits)),
        "mean_clean_confidence": float(np.mean(clean_conf)),
        "mean_patched_confidence": float(np.mean(patched_conf)),
        "mean_confidence_gain": float(np.mean(confidence_gain)),
        "max_confidence_gain": float(np.max(confidence_gain)),
        "mean_probability_l1_change": float(
            np.mean(np.sum(np.abs(patched_probs - clean_probs), axis=1))
        ),
        "clean_classes": [int(x) for x in clean_classes],
        "patched_classes": [int(x) for x in patched_classes],
    }


def _infer_target_class(
    clean_probs: np.ndarray,
    candidate_results: Sequence[Dict[str, Any]],
) -> Optional[int]:
    """Infer a dominant changed target from the candidate results.

    This is descriptive only. It is not a maliciousness inference.
    """

    targets: List[int] = []

    for result in candidate_results:
        clean = result["clean_classes"]
        patched = result["patched_classes"]

        for c, p in zip(clean, patched):
            if c != p:
                targets.append(int(p))

    if not targets:
        return None

    values, counts = np.unique(np.asarray(targets, dtype=np.int64), return_counts=True)

    return int(values[int(np.argmax(counts))])


def _build_clean_summary(
    clean_probs: np.ndarray,
) -> Dict[str, Any]:
    classes = np.argmax(clean_probs, axis=1)
    confidences = np.max(clean_probs, axis=1)

    unique, counts = np.unique(classes, return_counts=True)

    distribution = {
        str(int(k)): int(v)
        for k, v in zip(unique, counts)
    }

    return {
        "sample_count": int(len(clean_probs)),
        "class_distribution": distribution,
        "mean_confidence": float(np.mean(confidences)),
        "min_confidence": float(np.min(confidences)),
        "max_confidence": float(np.max(confidences)),
    }


def search_triggers(
    images: Sequence[np.ndarray],
    adapter: ClassificationAdapter,
    *,
    config: Optional[TriggerSearchConfig] = None,
    model_id: Optional[str] = None,
    target_class: Optional[int] = None,
) -> Dict[str, Any]:
    """Search deterministic localized trigger candidates across images.

    Returns a structured evidence report. The report contains no timestamp
    or random identifier and is therefore reproducible for deterministic
    model/adapters.
    """

    cfg = config or TriggerSearchConfig()
    cfg.validate()

    if adapter is None or not hasattr(adapter, "predict"):
        return build_unavailable_report(
            "adapter_unavailable",
            "A classification prediction adapter is required.",
            model_id=model_id,
            config=cfg,
        )

    if images is None:
        return build_unavailable_report(
            "invalid_images",
            "images cannot be None.",
            model_id=model_id,
            config=cfg,
        )

    try:
        prepared = [_validate_image(image) for image in images]
    except Exception as exc:
        return build_unavailable_report(
            "invalid_images",
            str(exc),
            model_id=model_id,
            config=cfg,
        )

    if not prepared:
        return build_unavailable_report(
            "empty_images",
            "At least one image is required.",
            model_id=model_id,
            config=cfg,
        )

    prepared = prepared[: cfg.max_images]

    try:
        clean_probs = _predict_probabilities(adapter, prepared)
    except Exception as exc:
        return build_unavailable_report(
            "prediction_error",
            f"Clean-model prediction failed: {type(exc).__name__}: {exc}",
            model_id=model_id,
            config=cfg,
        )

    if clean_probs.shape[0] != len(prepared):
        return build_unavailable_report(
            "prediction_count_mismatch",
            "Model returned a different number of predictions than input images.",
            model_id=model_id,
            config=cfg,
        )

    candidates = generate_candidates(prepared[0].shape, cfg)

    if not candidates:
        return build_unavailable_report(
            "no_valid_candidates",
            "No trigger candidates fit the supplied image dimensions.",
            model_id=model_id,
            config=cfg,
        )

    candidate_results: List[Dict[str, Any]] = []

    for candidate in candidates:
        patched_images = [
            apply_trigger(image, candidate)
            for image in prepared
        ]

        try:
            patched_probs = _predict_probabilities(adapter, patched_images)
        except Exception as exc:
            return build_unavailable_report(
                "prediction_error",
                (
                    "Candidate prediction failed for "
                    f"{candidate.as_dict()}: {type(exc).__name__}: {exc}"
                ),
                model_id=model_id,
                config=cfg,
            )

        if patched_probs.shape != clean_probs.shape:
            return build_unavailable_report(
                "prediction_shape_mismatch",
                "Patched prediction shape differs from clean prediction shape.",
                model_id=model_id,
                config=cfg,
            )

        metrics = _candidate_metrics(
            clean_probs,
            patched_probs,
            target_class,
        )

        candidate_results.append(
            {
                "candidate_id": _candidate_key(candidate),
                "candidate": candidate.as_dict(),
                **metrics,
            }
        )

    resolved_target = target_class

    if resolved_target is None:
        resolved_target = _infer_target_class(clean_probs, candidate_results)

        if resolved_target is not None:
            for result in candidate_results:
                patched = result["patched_classes"]
                result["target_class"] = int(resolved_target)
                result["target_hit_count"] = int(
                    sum(int(x == resolved_target) for x in patched)
                )
                result["target_hit_rate"] = float(
                    result["target_hit_count"] / result["sample_count"]
                )

    candidate_evidence: List[Dict[str, Any]] = []

    for result in candidate_results:
        repeated = result["sample_count"] >= cfg.min_samples

        if resolved_target is None:
            target_consistency = result["class_change_rate"]
        else:
            target_consistency = result["target_hit_rate"]

        confidence_evidence = (
            result["mean_confidence_gain"] >= cfg.min_confidence_gain
        )

        probability_redistribution_evidence = (
            result["mean_probability_l1_change"]
            >= cfg.min_probability_l1_change
        )

        candidate_found = (
            repeated
            and result["class_change_rate"] >= cfg.min_prediction_change_rate
            and (
                confidence_evidence
                or probability_redistribution_evidence
            )
            and target_consistency >= cfg.min_prediction_change_rate
        )

        result["candidate_trigger_like"] = bool(candidate_found)

        if candidate_found:
            candidate_evidence.append(result)

    # Rank only by measurable evidence for internal deterministic ordering.
    # This is not a user-facing risk score.
    candidate_evidence.sort(
        key=lambda item: (
            item["class_change_rate"],
            item["mean_confidence_gain"],
            item["mean_probability_l1_change"],
        ),
        reverse=True,
    )

    return {
        "status": "completed",
        "engine": {
            "name": "B4",
            "version": ENGINE_VERSION,
            "method": METHOD,
            "task": TASK,
        },
        "model": {
            "model_id": model_id,
            "model_id_source": (
                "caller_supplied_B1_identity"
                if model_id
                else "not_supplied"
            ),
        },
        "search": {
            "configuration": asdict(cfg),
            "candidate_count": len(candidates),
            "images_requested": len(images),
            "images_assessed": len(prepared),
            "target_class_requested": target_class,
            "target_class_resolved": resolved_target,
        },
        "clean_baseline": _build_clean_summary(clean_probs),
        "candidate_evidence": candidate_evidence,
        "candidate_trigger_count": len(candidate_evidence),
        "all_candidates": candidate_results,
        "assessment": {
            "status": (
                "candidate_trigger_like_behavior"
                if candidate_evidence
                else "no_candidate_trigger_like_behavior"
            ),
            "interpretation": (
                "One or more localized perturbations produced repeated "
                "prediction changes meeting the configured evidence thresholds. "
                "This requires analyst review and does not prove a backdoor."
                if candidate_evidence
                else
                "No tested localized perturbation met the configured "
                "trigger-like evidence thresholds."
            ),
        },
        "limitations": list(LIMITATIONS),
    }


def build_unavailable_report(
    code: str,
    message: str,
    *,
    model_id: Optional[str] = None,
    config: Optional[TriggerSearchConfig] = None,
) -> Dict[str, Any]:
    """Return a structured unavailable/error report without raising."""

    cfg = config or TriggerSearchConfig()

    return {
        "status": "unavailable",
        "engine": {
            "name": "B4",
            "version": ENGINE_VERSION,
            "method": METHOD,
            "task": TASK,
        },
        "model": {
            "model_id": model_id,
            "model_id_source": (
                "caller_supplied_B1_identity"
                if model_id
                else "not_supplied"
            ),
        },
        "error": {
            "code": code,
            "message": message,
        },
        "search": {
            "configuration": asdict(cfg),
        },
        "candidate_trigger_count": 0,
        "candidate_evidence": [],
        "limitations": list(LIMITATIONS),
    }


__all__ = [
    "ENGINE_VERSION",
    "METHOD",
    "TASK",
    "LIMITATIONS",
    "TriggerSearchConfig",
    "CandidateSpec",
    "ClassificationAdapter",
    "CallableClassificationAdapter",
    "TorchClassificationAdapter",
    "apply_trigger",
    "generate_candidates",
    "search_triggers",
    "build_unavailable_report",
]
