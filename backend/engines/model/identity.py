"""TRACER-CV B1 - Model Identity / Cryptographic Fingerprinting.

Establishes a cryptographic identity for a model file from its raw bytes.

B1 is an identity/integrity engine, not a model-behaviour engine:
  * the model is NEVER loaded (no torch / onnx / tensorflow / transformers),
  * the file is hashed with streaming SHA-256 in 1 MiB chunks,
  * only the Python standard library is used,
  * no timestamps appear in the result, so output is deterministic.

Canonical identity:  model_id = "sha256:" + SHA-256(model bytes)
File name, size, path and modification time are metadata, never identity.

Public API:
    inspect_model(path, expected_sha256=None) -> dict
    verify_model(path, expected_sha256)       -> dict
    normalize_sha256(value)                   -> Optional[str]
"""

import hashlib
import hmac
import json
import os
import re
import sys
from typing import Any, Dict, Optional, Tuple

__all__ = [
    "CHUNK_SIZE",
    "METHOD",
    "FORMAT_BASIS",
    "EXTENSION_FORMATS",
    "classify_extension",
    "normalize_sha256",
    "inspect_model",
    "verify_model",
    "main",
]

CHUNK_SIZE = 1024 * 1024  # 1 MiB streaming chunks
HEAD_BYTES = 16  # leading bytes retained for the lightweight signature check
METHOD = "SHA-256 streaming model fingerprint"
FORMAT_BASIS = "format inferred from filename extension"
MODEL_ID_PREFIX = "sha256:"

_SAFETENSORS_MAX_HEADER = 100 * 1024 * 1024  # documented upper bound on header size
_HEX64 = re.compile(r"[0-9a-f]{64}")

# extension -> (format label, confidence). The extension does NOT prove the format.
EXTENSION_FORMATS = {
    ".pt": ("PyTorch checkpoint", "extension_inferred"),
    ".pth": ("PyTorch checkpoint", "extension_inferred"),
    ".torchscript": ("TorchScript", "extension_inferred"),
    ".onnx": ("ONNX", "extension_inferred"),
    ".safetensors": ("SafeTensors", "extension_inferred"),
    ".ckpt": ("Checkpoint", "extension_inferred"),
    ".pb": ("TensorFlow protobuf", "extension_inferred"),
    ".engine": ("TensorRT engine", "extension_inferred"),
    ".pkl": ("Pickle", "extension_inferred"),
    ".joblib": ("Joblib", "extension_inferred"),
    ".bin": ("generic binary", "extension_inferred_low"),
}

_SIGNATURE_DESCRIPTIONS = {
    "safetensors_like_header": (
        "8-byte little-endian header length followed by an opening brace "
        "(plausible SafeTensors header; not parsed or validated)"
    ),
    "zip_container": (
        "ZIP local-file header (used by PyTorch >= 1.6 checkpoints and "
        "TorchScript archives, among others; archive is not opened)"
    ),
    "pickle_stream": (
        "Pickle protocol 2-5 header byte pattern "
        "(unpickling is unsafe and is never performed)"
    ),
}

LIMITATIONS = (
    "Format is inferred from the filename extension only; it is not a "
    "confirmed internal format.",
    "The content signature is a heuristic check of the first bytes; model "
    "internals are never parsed or validated. ONNX, TensorFlow protobuf and "
    "TensorRT engine files have no reliable universal magic header.",
    "The SHA-256 digest proves byte identity only; it says nothing about "
    "model safety, correctness or provenance, and a verification result is "
    "only as trustworthy as the source of the expected digest.",
    "Pickle-based formats (.pkl, .joblib, and often .pt/.pth/.ckpt/.bin) can "
    "execute code when loaded; B1 never loads models and does not assess "
    "them for malicious content.",
    "Functionally equivalent models with different bytes (re-exports, "
    "re-serialisation) have different identities; sharded or multi-file "
    "models must be fingerprinted file by file.",
    "file_name, path and absolute_path are observation metadata and are not "
    "part of the model identity.",
)


def classify_extension(extension: str) -> Tuple[str, str]:
    """Return (format label, confidence) for a lower-case extension."""
    return EXTENSION_FORMATS.get(extension, ("unknown", "unknown"))


def normalize_sha256(value: Any) -> Optional[str]:
    """Return a bare lower-case 64-hex digest, or None if value is not one.

    Accepts optional surrounding whitespace, upper/lower case, and an
    optional "sha256:" prefix.
    """
    if not isinstance(value, str):
        return None
    candidate = value.strip().lower()
    if candidate.startswith(MODEL_ID_PREFIX):
        candidate = candidate[len(MODEL_ID_PREFIX):]
    if _HEX64.fullmatch(candidate):
        return candidate
    return None


def _new_result(path_str: Optional[str], requested: bool) -> Dict[str, Any]:
    file_name = os.path.basename(path_str) if path_str else None
    extension = os.path.splitext(file_name)[1].lower() if file_name else ""
    fmt, confidence = classify_extension(extension)
    try:
        absolute = os.path.abspath(path_str) if path_str else None
    except (OSError, ValueError):
        absolute = None
    return {
        "status": "error",
        "method": METHOD,
        "hash_algorithm": "SHA-256",
        "model_id": None,
        "sha256": None,
        "file_name": file_name,
        "path": path_str,
        "absolute_path": absolute,
        "file_size_bytes": None,
        "bytes_hashed": None,
        "extension": extension,
        "format": fmt,
        "format_confidence": confidence,
        "format_basis": FORMAT_BASIS,
        "content_signature": None,
        "verification": {
            "requested": requested,
            "expected_sha256": None,
            "match": None,
        },
        "error": None,
        "limitations": list(LIMITATIONS),
    }


def _fail(result: Dict[str, Any], code: str, message: str) -> Dict[str, Any]:
    result["status"] = "error"
    result["error"] = {"code": code, "message": message}
    return result


def _stream_sha256(path: str) -> Tuple[str, int, int, bytes]:
    """Hash the file in CHUNK_SIZE pieces. Never holds the whole file in memory.

    Returns (hex digest, bytes hashed, size reported by fstat, leading bytes).
    """
    hasher = hashlib.sha256()
    total = 0
    head = b""
    with open(path, "rb") as handle:
        declared = os.fstat(handle.fileno()).st_size
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            if len(head) < HEAD_BYTES:
                head += chunk[: HEAD_BYTES - len(head)]
            hasher.update(chunk)
            total += len(chunk)
    return hasher.hexdigest(), total, declared, head


def _detect_signature(head: bytes, total: int) -> Dict[str, Any]:
    """Lightweight, heuristic leading-byte check. Nothing is parsed or loaded.

    Order matters: a SafeTensors length prefix can begin with bytes that look
    like a pickle opcode, so it is tested first.
    """
    detected = None
    if len(head) >= 9 and total >= 9:
        header_len = int.from_bytes(head[:8], "little")
        if (
            0 < header_len <= min(total - 8, _SAFETENSORS_MAX_HEADER)
            and head[8:9] == b"{"
        ):
            detected = "safetensors_like_header"
    if detected is None and head[:4] == b"PK\x03\x04":
        detected = "zip_container"
    if detected is None and len(head) >= 2 and head[0] == 0x80 and 2 <= head[1] <= 5:
        detected = "pickle_stream"
    return {
        "detected": detected,
        "description": _SIGNATURE_DESCRIPTIONS.get(detected),
        "basis": "leading bytes only; heuristic; model internals not parsed",
    }


def _run(path: Any, expected: Any, requested: bool) -> Dict[str, Any]:
    # 1. Normalise the path argument.
    try:
        path_str = os.fspath(path)
        if isinstance(path_str, bytes):
            path_str = os.fsdecode(path_str)
    except TypeError:
        path_str = None

    result = _new_result(path_str, requested)

    # 2. Normalise the expected digest (if verification was requested).
    expected_norm = None
    if requested:
        expected_norm = normalize_sha256(expected)
        if expected_norm is not None:
            result["verification"]["expected_sha256"] = expected_norm
        elif isinstance(expected, str):
            result["verification"]["expected_sha256"] = expected

    if path_str is None:
        return _fail(result, "invalid_path", "path must be a str or os.PathLike")

    # 3. Safe file checks (also avoids blocking on FIFOs / devices).
    try:
        exists = os.path.exists(path_str)
        is_file = os.path.isfile(path_str)
    except (OSError, ValueError) as exc:
        return _fail(result, "read_error", "cannot stat path: %s" % exc)
    if not exists:
        return _fail(result, "file_not_found", "no such file: %s" % path_str)
    if not is_file:
        return _fail(result, "not_a_regular_file", "not a regular file: %s" % path_str)

    # 4. Stream-hash the actual bytes.
    try:
        digest, total, declared, head = _stream_sha256(path_str)
    except PermissionError as exc:
        return _fail(result, "permission_denied", "cannot read file: %s" % exc)
    except FileNotFoundError:
        return _fail(result, "file_not_found", "file disappeared: %s" % path_str)
    except OSError as exc:
        return _fail(result, "read_error", "cannot read file: %s" % exc)

    if declared != total:
        return _fail(
            result,
            "file_changed_during_hashing",
            "file size changed while hashing (%d vs %d bytes); result discarded"
            % (declared, total),
        )

    result["sha256"] = digest
    result["model_id"] = MODEL_ID_PREFIX + digest
    result["file_size_bytes"] = total
    result["bytes_hashed"] = total
    result["content_signature"] = _detect_signature(head, total)

    # 5. Verification (a mismatch is a finding, not an exception).
    if not requested:
        result["status"] = "completed"
    elif expected_norm is None:
        _fail(
            result,
            "invalid_expected_sha256",
            "expected_sha256 must be 64 hexadecimal characters "
            "(optionally prefixed with sha256:)",
        )
    else:
        match = hmac.compare_digest(digest, expected_norm)
        result["verification"]["match"] = match
        result["status"] = "verified" if match else "mismatch"
    return result


def inspect_model(path: Any, expected_sha256: Optional[str] = None) -> Dict[str, Any]:
    """Fingerprint a model file. If expected_sha256 is given, also verify it.

    Status values: "completed" (no verification requested), "verified",
    "mismatch", "error".
    """
    return _run(path, expected_sha256, expected_sha256 is not None)


def verify_model(path: Any, expected_sha256: Any) -> Dict[str, Any]:
    """Fingerprint a model file and compare against expected_sha256."""
    return _run(path, expected_sha256, True)


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if len(argv) not in (1, 2):
        sys.stderr.write("usage: python -m backend.engines.model.identity <model> [expected_sha256]\n")
        return 2
    result = inspect_model(argv[0], argv[1] if len(argv) == 2 else None)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] in ("completed", "verified") else 1


if __name__ == "__main__":
    sys.exit(main())
