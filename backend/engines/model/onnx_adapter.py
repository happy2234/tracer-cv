"""Local ONNX Runtime image-classification adapter.

Requires optional local ``onnx`` and ``onnxruntime`` packages. The adapter
never downloads models, registers custom operators, loads external tensor
data, or executes Python embedded in a model. Runtime execution uses CPU only.
"""
from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Sequence

import numpy as np
from PIL import Image

ENGINE_VERSION = "onnx-adapter-1.0"
METHOD = "local ONNX Runtime image classification adapter"
LIMITATIONS = (
    "Only local ONNX image-classification graphs with one image tensor input and a rank-2 logits/probabilities output are supported.",
    "ONNX graph execution runs native operators in the ONNX Runtime process and is not a general-purpose sandbox.",
    "External tensor data and custom operators are not supported.",
    "Image preprocessing assumptions (RGB resize, scale, normalization and layout) must match the model's expected input contract.",
    "B3 activation statistics are unavailable; initializer statistics describe stored graph constants, not trainable parameters.",
)


class ONNXAdapterError(RuntimeError):
    """Expected, analyst-displayable adapter error."""


def _optional_runtime():
    try:
        import onnx
        import onnxruntime as ort
    except Exception as exc:
        raise ONNXAdapterError("ONNX support is unavailable; install the approved local ONNX extras before use.") from exc
    return onnx, ort


def _graphs(model: Any):
    pending = [model.graph]
    while pending:
        graph = pending.pop()
        yield graph
        for node in graph.node:
            for attribute in node.attribute:
                if attribute.type == 5:  # AttributeProto.GRAPH
                    pending.append(attribute.g)
                elif attribute.type == 10:  # AttributeProto.GRAPHS
                    pending.extend(attribute.graphs)


def _validate_local_graph(onnx: Any, path: Path, max_model_bytes: int):
    try:
        resolved = path.expanduser().resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ONNXAdapterError(f"Local ONNX model path is unavailable: {exc}") from exc
    if not resolved.is_file() or resolved.suffix.lower() != ".onnx":
        raise ONNXAdapterError("A regular local .onnx file is required.")
    if resolved.stat().st_size > max_model_bytes:
        raise ONNXAdapterError(f"ONNX model exceeds the configured size limit ({max_model_bytes} bytes).")
    try:
        model = onnx.load(str(resolved), load_external_data=False)
        for graph in _graphs(model):
            tensors = list(graph.initializer)
            tensors.extend(item.values for item in graph.sparse_initializer)
            for tensor in tensors:
                if tensor.data_location == onnx.TensorProto.EXTERNAL or tensor.external_data:
                    raise ONNXAdapterError("ONNX external tensor data is not supported; keep model weights embedded in the local file.")
        onnx.checker.check_model(model)
    except ONNXAdapterError:
        raise
    except Exception as exc:
        raise ONNXAdapterError(f"ONNX graph validation failed: {type(exc).__name__}: {exc}") from exc
    return resolved, model


def _shape_dimension(value: Any, fallback: int) -> int:
    return int(value) if isinstance(value, int) and value > 0 else fallback


class ONNXClassificationAdapter:
    """Batch-compatible classification adapter for the existing B2 protocol."""

    name = "onnxruntime_cpu_classification_adapter"

    def __init__(self, session: Any, *, input_size: tuple[int, int] | None = None,
                 mean: Sequence[float] = (0.0, 0.0, 0.0), std: Sequence[float] = (1.0, 1.0, 1.0),
                 output_type: str = "logits", metadata: dict[str, Any] | None = None):
        if output_type not in {"logits", "probabilities"}:
            raise ValueError("output_type must be logits or probabilities")
        self.session = session
        self.metadata = metadata or {}
        self.input_meta = session.get_inputs()[0]
        self.output_meta = session.get_outputs()[0]
        shape = list(getattr(self.input_meta, "shape", []))
        if len(shape) != 4:
            raise ONNXAdapterError("Only rank-4 image tensor inputs are supported.")
        dims = shape[1:]
        if dims[0] in (3, "3"):
            self.layout, height_axis, width_axis = "NCHW", 1, 2
        elif dims[-1] in (3, "3"):
            self.layout, height_axis, width_axis = "NHWC", 0, 1
        elif input_size:
            # Dynamic/unknown channel position is ambiguous; do not guess.
            raise ONNXAdapterError("Could not identify a three-channel axis in ONNX input shape.")
        else:
            raise ONNXAdapterError("ONNX input channel axis is dynamic or unsupported; provide a fixed 3-channel image input.")
        selected_size = input_size or (_shape_dimension(dims[height_axis], 224), _shape_dimension(dims[width_axis], 224))
        self.height, self.width = int(selected_size[0]), int(selected_size[1])
        if min(self.height, self.width) <= 0 or self.height * self.width > 16_000_000:
            raise ONNXAdapterError("ONNX image input dimensions are invalid or exceed the local pixel limit.")
        self.mean = np.asarray(mean, dtype=np.float32).reshape(1, 1, 1, 3)
        self.std = np.asarray(std, dtype=np.float32).reshape(1, 1, 1, 3)
        if self.mean.size != 3 or self.std.size != 3 or np.any(self.std == 0):
            raise ValueError("mean and std must each contain three values; std must be non-zero")
        self.output_type = output_type
        output_shape = list(getattr(self.output_meta, "shape", []))
        self.class_count = output_shape[-1] if len(output_shape) == 2 and isinstance(output_shape[-1], int) else None

    @classmethod
    def load(cls, model_path: str | Path, *, input_size: tuple[int, int] | None = None,
             mean: Sequence[float] = (0.0, 0.0, 0.0), std: Sequence[float] = (1.0, 1.0, 1.0),
             output_type: str = "logits", max_model_bytes: int = 256 * 1024 * 1024,
             intra_op_threads: int = 1) -> "ONNXClassificationAdapter":
        onnx, ort = _optional_runtime()
        path, model = _validate_local_graph(onnx, Path(model_path), max_model_bytes)
        inputs, outputs = model.graph.input, model.graph.output
        initializers = {tensor.name for graph in _graphs(model) for tensor in graph.initializer}
        image_inputs = [item for item in inputs if item.name not in initializers]
        if len(image_inputs) != 1 or len(outputs) != 1:
            raise ONNXAdapterError("Only one-input, one-output classification graphs are supported.")
        options = ort.SessionOptions()
        options.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
        options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_DISABLE_ALL
        options.intra_op_num_threads = max(1, int(intra_op_threads))
        options.inter_op_num_threads = 1
        try:
            session = ort.InferenceSession(str(path), sess_options=options, providers=["CPUExecutionProvider"])
        except Exception as exc:
            raise ONNXAdapterError(f"ONNX Runtime could not load this local graph: {type(exc).__name__}: {exc}") from exc
        if session.get_providers() and session.get_providers()[0] != "CPUExecutionProvider":
            raise ONNXAdapterError("ONNX Runtime did not select the requested local CPU execution provider.")
        return cls(session, input_size=input_size, mean=mean, std=std, output_type=output_type,
                   metadata={"path": str(path), "input_name": image_inputs[0].name,
                             "input_shape": list(image_inputs[0].type.tensor_type.shape.dim[i].dim_value if image_inputs[0].type.tensor_type.shape.dim[i].HasField("dim_value") else None for i in range(len(image_inputs[0].type.tensor_type.shape.dim))),
                             "output_name": outputs[0].name, "output_shape": str(outputs[0].type.tensor_type.shape),
                             "provider": "CPUExecutionProvider", "onnx_ir_version": model.ir_version,
                             "opset_imports": [{"domain": item.domain, "version": item.version} for item in model.opset_import],
                             "initializer_statistics": _initializer_summary(onnx, model)})

    def _prepare(self, batch_images: np.ndarray) -> np.ndarray:
        values = np.asarray(batch_images)
        if values.ndim != 4 or values.shape[-1] != 3 or values.dtype != np.uint8:
            raise ValueError("images must be a uint8 batch with shape (N,H,W,3)")
        prepared = []
        for image in values:
            resized = Image.fromarray(image, mode="RGB").resize((self.width, self.height), Image.Resampling.BILINEAR)
            prepared.append(np.asarray(resized, dtype=np.float32))
        arr = np.stack(prepared, axis=0) / 255.0
        arr = (arr - self.mean) / self.std
        if self.layout == "NCHW":
            arr = np.transpose(arr, (0, 3, 1, 2))
        input_type = str(getattr(self.input_meta, "type", "tensor(float)"))
        dtype = np.float64 if input_type == "tensor(double)" else np.float32
        if input_type not in {"tensor(float)", "tensor(double)"}:
            raise ONNXAdapterError(f"Unsupported ONNX image input type: {input_type}")
        return np.ascontiguousarray(arr, dtype=dtype)

    def predict_scores(self, batch_images: np.ndarray) -> np.ndarray:
        tensor = self._prepare(batch_images)
        outputs = self.session.run([self.output_meta.name], {self.input_meta.name: tensor})
        scores = np.asarray(outputs[0], dtype=np.float64)
        if scores.ndim != 2 or scores.shape[0] != len(tensor) or scores.shape[1] < 1 or not np.all(np.isfinite(scores)):
            raise ONNXAdapterError("ONNX model output must be a finite rank-2 (N,C) classification tensor.")
        return scores

    def predict(self, batch_images: np.ndarray):
        from backend.engines.model.behavioral_fingerprint import predictions_from_probabilities
        scores = self.predict_scores(batch_images)
        if self.output_type == "probabilities":
            probabilities = scores
        else:
            shifted = scores - scores.max(axis=1, keepdims=True)
            exp = np.exp(shifted)
            probabilities = exp / exp.sum(axis=1, keepdims=True)
        result = predictions_from_probabilities(probabilities)
        if self.class_count is None:
            self.class_count = int(scores.shape[1])
        return result


def _initializer_summary(onnx: Any, model: Any, max_total_bytes: int = 256 * 1024 * 1024) -> dict[str, Any]:
    """Summarize embedded ONNX initializers with bounded transient memory."""
    tensors = [tensor for graph in _graphs(model) for tensor in graph.initializer]
    estimated = sum(int(tensor.ByteSize()) for tensor in tensors)
    if estimated > max_total_bytes:
        return {"status": "unavailable", "reason": "Initializer statistics exceed the bounded local inspection limit.", "initializer_tensor_count": len(tensors)}
    count = 0; total = 0.0; squares = 0.0; minimum = math.inf; maximum = -math.inf; nonfinite = 0
    for tensor in tensors:
        array = np.asarray(onnx.numpy_helper.to_array(tensor), dtype=np.float64).reshape(-1)
        finite = array[np.isfinite(array)]
        nonfinite += int(array.size - finite.size)
        if finite.size:
            count += int(finite.size); total += float(finite.sum()); squares += float(np.dot(finite, finite))
            minimum = min(minimum, float(finite.min())); maximum = max(maximum, float(finite.max()))
    mean = total / count if count else None
    std = math.sqrt(max(0.0, squares / count - mean * mean)) if count else None
    return {"status": "available", "initializer_tensor_count": len(tensors), "initializer_element_count": sum(int(np.prod(tensor.dims, dtype=np.int64)) for tensor in tensors),
            "finite_value_count": count, "mean": mean, "std": std, "min": minimum if count else None, "max": maximum if count else None,
            "non_finite_count": nonfinite, "trainable_parameter_count": None,
            "limitations": ["ONNX initializers are stored graph constants; ONNX does not identify which constants were trainable parameters.", "Activation statistics require graph execution hooks and are unavailable through this adapter."]}


def try_load_onnx_adapter(model_path: str | Path, **kwargs: Any) -> dict[str, Any]:
    """Load a local ONNX model and return a structured failure when unavailable."""
    try:
        adapter = ONNXClassificationAdapter.load(model_path, **kwargs)
        return {"status": "loaded", "adapter": adapter, "metadata": dict(adapter.metadata), "warnings": list(LIMITATIONS)}
    except Exception as exc:
        return {"status": "unavailable" if "unavailable" in str(exc).lower() else "error", "reason": str(exc), "limitations": list(LIMITATIONS)}


__all__ = ["ENGINE_VERSION", "METHOD", "LIMITATIONS", "ONNXAdapterError", "ONNXClassificationAdapter", "try_load_onnx_adapter"]
