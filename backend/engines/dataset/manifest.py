from pathlib import Path
import json

from backend.core.hashing import sha256_bytes, sha256_file
from backend.core.merkle import merkle_root


def build_manifest(dataset_dir: Path) -> dict:
    dataset_dir = dataset_dir.resolve()

    if not dataset_dir.is_dir():
        raise ValueError(f"Dataset directory does not exist: {dataset_dir}")

    files = []

    for path in sorted(dataset_dir.rglob("*")):
        if not path.is_file():
            continue

        relative_path = path.relative_to(dataset_dir)

        files.append(
            {
                "path": relative_path.as_posix(),
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
        )

    canonical_files = json.dumps(
        files,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    dataset_sha256 = sha256_bytes(canonical_files)

    file_hashes = [item["sha256"] for item in files]
    dataset_merkle_root = merkle_root(file_hashes)

    return {
        "dataset_id": dataset_sha256,
        "file_count": len(files),
        "files": files,
        "dataset_sha256": dataset_sha256,
        "merkle_root": dataset_merkle_root,
    }
