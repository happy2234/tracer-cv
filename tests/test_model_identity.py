"""B1 tests - Model Identity / Cryptographic Fingerprinting.

Run without pytest:   python -m tests.test_model_identity
Also collectable by pytest (plain test_* functions, no fixtures).

All models are tiny synthetic byte strings. B1 tests byte identity, not
model validity, so no ML framework or downloaded model is needed.
"""

import hashlib
import json
import os
import sys
import tempfile

from backend.engines.model import identity
from backend.engines.model.identity import (
    CHUNK_SIZE,
    inspect_model,
    normalize_sha256,
    verify_model,
)

BYTES_A = b"TRACER-CV TEST MODEL A"
BYTES_B = b"TRACER-CV TEST MODEL B"
BYTES_XYZ = b"TRACER-CV TEST MODEL UNKNOWN"


def _check(condition, message="check failed"):
    if not condition:
        raise AssertionError(message)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


class _Workspace:
    """Temporary directory with a small write helper."""

    def __enter__(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="tracer_b1_")
        self.dir = self._tmp.name
        return self

    def __exit__(self, *exc_info):
        self._tmp.cleanup()
        return False

    def write(self, name, data):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as handle:
            handle.write(data)
        return path


def test_sha256_correct():
    with _Workspace() as ws:
        path = ws.write("model_a.pt", BYTES_A)
        result = inspect_model(path)
        _check(result["status"] == "completed", "status: %r" % result["status"])
        _check(result["sha256"] == _sha(BYTES_A), "sha256 mismatch")
        _check(result["method"] == "SHA-256 streaming model fingerprint")
        _check(result["file_name"] == "model_a.pt")
        _check(result["error"] is None)
        _check(result["verification"] == {
            "requested": False, "expected_sha256": None, "match": None})


def test_model_id_format():
    with _Workspace() as ws:
        result = inspect_model(ws.write("model_a.pt", BYTES_A))
        model_id = result["model_id"]
        _check(model_id.startswith("sha256:"), "model_id prefix")
        _check(model_id == "sha256:" + _sha(BYTES_A), "model_id value")
        digest = model_id[len("sha256:"):]
        _check(len(digest) == 64, "digest length")
        _check(all(c in "0123456789abcdef" for c in digest), "digest not lower-case hex")


def test_bytes_hashed_equals_file_size():
    with _Workspace() as ws:
        path = ws.write("model_b.onnx", BYTES_B)
        result = inspect_model(path)
        _check(result["bytes_hashed"] == len(BYTES_B), "bytes_hashed vs data")
        _check(result["bytes_hashed"] == result["file_size_bytes"], "bytes_hashed vs size")
        _check(result["file_size_bytes"] == os.path.getsize(path), "size vs os.path.getsize")


def test_deterministic_repeated_inspection():
    with _Workspace() as ws:
        path = ws.write("model_a.pt", BYTES_A)
        first = inspect_model(path)
        second = inspect_model(path)
        third = inspect_model(path)
        _check(first == second == third, "repeated results differ")
        _check(json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True))
        for key in ("sha256", "model_id", "file_size_bytes", "format", "format_confidence"):
            _check(first[key] == third[key], "%s not stable" % key)


def test_extension_classification():
    expected = [
        ("m1.pt", ".pt", "PyTorch checkpoint", "extension_inferred"),
        ("m2.pth", ".pth", "PyTorch checkpoint", "extension_inferred"),
        ("m3.torchscript", ".torchscript", "TorchScript", "extension_inferred"),
        ("m4.onnx", ".onnx", "ONNX", "extension_inferred"),
        ("m5.safetensors", ".safetensors", "SafeTensors", "extension_inferred"),
        ("m6.ckpt", ".ckpt", "Checkpoint", "extension_inferred"),
        ("m7.pb", ".pb", "TensorFlow protobuf", "extension_inferred"),
        ("m8.engine", ".engine", "TensorRT engine", "extension_inferred"),
        ("m9.pkl", ".pkl", "Pickle", "extension_inferred"),
        ("m10.joblib", ".joblib", "Joblib", "extension_inferred"),
        ("m11.bin", ".bin", "generic binary", "extension_inferred_low"),
        ("upper_case.ONNX", ".onnx", "ONNX", "extension_inferred"),
    ]
    with _Workspace() as ws:
        for name, ext, fmt, confidence in expected:
            result = inspect_model(ws.write(name, BYTES_A))
            _check(result["status"] == "completed", name)
            _check(result["extension"] == ext, "%s extension: %r" % (name, result["extension"]))
            _check(result["format"] == fmt, "%s format: %r" % (name, result["format"]))
            _check(result["format_confidence"] == confidence, "%s confidence" % name)
            _check(result["format_basis"] == "format inferred from filename extension")
            _check(result["file_name"] == name, "file_name preserved")


def test_unknown_extension():
    with _Workspace() as ws:
        result = inspect_model(ws.write("model_unknown.xyz", BYTES_XYZ))
        _check(result["status"] == "completed")
        _check(result["extension"] == ".xyz")
        _check(result["format"] == "unknown")
        _check(result["format_confidence"] == "unknown")
        _check(result["format_basis"] == "format inferred from filename extension")
        _check(result["sha256"] == _sha(BYTES_XYZ))
        bare = inspect_model(ws.write("model_noext", BYTES_XYZ))
        _check(bare["extension"] == "" and bare["format"] == "unknown")


def test_verify_correct_digest():
    with _Workspace() as ws:
        path = ws.write("model_a.pt", BYTES_A)
        result = verify_model(path, _sha(BYTES_A))
        _check(result["status"] == "verified", "status: %r" % result["status"])
        _check(result["verification"] == {
            "requested": True, "expected_sha256": _sha(BYTES_A), "match": True})
        unified = inspect_model(path, _sha(BYTES_A))
        _check(unified["status"] == "verified", "inspect_model with expected digest")


def test_verify_wrong_digest():
    with _Workspace() as ws:
        path = ws.write("model_a.pt", BYTES_A)
        result = verify_model(path, _sha(BYTES_B))  # must not raise
        _check(result["status"] == "mismatch", "status: %r" % result["status"])
        _check(result["verification"]["match"] is False)
        _check(result["verification"]["expected_sha256"] == _sha(BYTES_B))
        _check(result["sha256"] == _sha(BYTES_A), "actual digest still reported")
        _check(result["error"] is None, "mismatch is a finding, not an error")


def test_missing_file_returns_error():
    with _Workspace() as ws:
        missing = os.path.join(ws.dir, "does_not_exist.onnx")
        result = verify_model(missing, _sha(BYTES_A))
        _check(result["status"] == "error", "status: %r" % result["status"])
        _check(result["error"]["code"] == "file_not_found")
        _check(result["sha256"] is None and result["model_id"] is None)
        _check(result["file_name"] == "does_not_exist.onnx")
        _check(result["verification"]["match"] is None)
        plain = inspect_model(missing)
        _check(plain["status"] == "error" and plain["error"]["code"] == "file_not_found")


def test_one_byte_change_changes_digest():
    with _Workspace() as ws:
        original = ws.write("model_a.pt", BYTES_A)
        flipped = bytearray(BYTES_A)
        flipped[-1] ^= 0x01
        modified = ws.write("model_a_modified.pt", bytes(flipped))
        r1 = inspect_model(original)
        r2 = inspect_model(modified)
        _check(r1["file_size_bytes"] == r2["file_size_bytes"], "size should be equal")
        _check(r1["sha256"] != r2["sha256"], "sha256 should differ")
        _check(r1["model_id"] != r2["model_id"], "model_id should differ")
        _check(verify_model(modified, r1["sha256"])["status"] == "mismatch")


def test_identity_independent_of_filename():
    with _Workspace() as ws:
        r1 = inspect_model(ws.write("model_a.pt", BYTES_A))
        r2 = inspect_model(ws.write("renamed_copy.onnx", BYTES_A))
        _check(r1["model_id"] == r2["model_id"], "same bytes must give same model_id")
        _check(r1["format"] != r2["format"], "format follows the extension")


def test_multi_chunk_streaming():
    with _Workspace() as ws:
        data = bytes(range(256)) * (int(2.5 * CHUNK_SIZE) // 256)
        _check(len(data) > 2 * CHUNK_SIZE, "test data must span several chunks")
        result = inspect_model(ws.write("big.bin", data))
        _check(result["sha256"] == _sha(data), "multi-chunk digest wrong")
        _check(result["bytes_hashed"] == len(data) == result["file_size_bytes"])
        empty = inspect_model(ws.write("empty.pt", b""))
        _check(empty["status"] == "completed")
        _check(empty["sha256"] == _sha(b"") and empty["bytes_hashed"] == 0)


def test_expected_digest_normalization():
    with _Workspace() as ws:
        path = ws.write("model_a.pt", BYTES_A)
        upper_prefixed = "sha256:" + _sha(BYTES_A).upper()
        padded = "  " + _sha(BYTES_A).upper() + "\n"
        for supplied in (upper_prefixed, padded):
            result = verify_model(path, supplied)
            _check(result["status"] == "verified", "not verified for %r" % supplied)
            _check(result["verification"]["expected_sha256"] == _sha(BYTES_A))
        _check(normalize_sha256("zz") is None)
        _check(normalize_sha256(123) is None)
        _check(normalize_sha256(_sha(BYTES_A)) == _sha(BYTES_A))


def test_invalid_expected_digest():
    with _Workspace() as ws:
        path = ws.write("model_a.pt", BYTES_A)
        for bad in ("not-a-digest", "abcd", None, 12345):
            result = verify_model(path, bad)
            _check(result["status"] == "error", "status for %r" % (bad,))
            _check(result["error"]["code"] == "invalid_expected_sha256")
            _check(result["verification"]["match"] is None)
            _check(result["sha256"] == _sha(BYTES_A), "computed digest still reported")


def test_directory_returns_error():
    with _Workspace() as ws:
        result = inspect_model(ws.dir)
        _check(result["status"] == "error")
        _check(result["error"]["code"] == "not_a_regular_file")
        _check(result["sha256"] is None)


def test_content_signatures():
    header = b'{"__metadata__":{}}'
    safetensors = len(header).to_bytes(8, "little") + header + b"\x00" * 16
    zip_like = b"PK\x03\x04" + b"\x00" * 30
    pickle_like = b"\x80\x02}q\x00."
    truncated = (1000).to_bytes(8, "little") + b"{"  # claims a header longer than the file
    with _Workspace() as ws:
        r = inspect_model(ws.write("x.safetensors", safetensors))
        _check(r["content_signature"]["detected"] == "safetensors_like_header")
        r = inspect_model(ws.write("x.pt", zip_like))
        _check(r["content_signature"]["detected"] == "zip_container")
        r = inspect_model(ws.write("x.pkl", pickle_like))
        _check(r["content_signature"]["detected"] == "pickle_stream")
        r = inspect_model(ws.write("truncated.safetensors", truncated))
        _check(r["content_signature"]["detected"] is None, "implausible header accepted")
        r = inspect_model(ws.write("plain.onnx", BYTES_A))
        _check(r["content_signature"]["detected"] is None, "ONNX must not be claimed from bytes")
        # Signature is reported separately; the extension-based format is unchanged.
        r = inspect_model(ws.write("zip_named_onnx.onnx", zip_like))
        _check(r["format"] == "ONNX" and r["content_signature"]["detected"] == "zip_container")


def test_no_ml_frameworks_imported():
    _check(identity is not None)
    for name in ("torch", "onnx", "tensorflow", "transformers"):
        _check(name not in sys.modules, "%s was imported" % name)


ALL_TESTS = (
    test_sha256_correct,
    test_model_id_format,
    test_bytes_hashed_equals_file_size,
    test_deterministic_repeated_inspection,
    test_extension_classification,
    test_unknown_extension,
    test_verify_correct_digest,
    test_verify_wrong_digest,
    test_missing_file_returns_error,
    test_one_byte_change_changes_digest,
    test_identity_independent_of_filename,
    test_multi_chunk_streaming,
    test_expected_digest_normalization,
    test_invalid_expected_digest,
    test_directory_returns_error,
    test_content_signatures,
    test_no_ml_frameworks_imported,
)


def run_all():
    for test in ALL_TESTS:
        try:
            test()
        except Exception:
            print("  FAIL " + test.__name__)
            raise
        print("  ok  " + test.__name__)
    print("B1 tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(run_all())
