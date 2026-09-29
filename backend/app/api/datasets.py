from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.engines.dataset.manifest import build_manifest


router = APIRouter(prefix="/datasets", tags=["Dataset Integrity"])


class DatasetScanRequest(BaseModel):
    path: str


@router.post("/scan")
def scan_dataset(request: DatasetScanRequest):
    dataset_path = Path(request.path).expanduser().resolve()

    if not dataset_path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Dataset path does not exist: {dataset_path}",
        )

    if not dataset_path.is_dir():
        raise HTTPException(
            status_code=400,
            detail="Dataset path must be a directory.",
        )

    try:
        manifest = build_manifest(dataset_path)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Dataset scan failed: {exc}",
        ) from exc

    return {
        "status": "completed",
        "dataset": manifest,
        "checks": {
            "file_hashing": "passed",
            "manifest_generation": "passed",
            "merkle_integrity": "passed",
            "duplicate_detection": "not_assessed",
            "ood_detection": "not_assessed",
            "label_consistency": "not_assessed",
            "contributor_analysis": "not_assessed",
        },
    }
