from fastapi import APIRouter

router = APIRouter(prefix="/api/v1")


@router.get("/health")
def health():
    return {
        "status": "ok",
        "product": "TRACER-CV",
        "version": "0.1.0",
        "offline_mode": True,
    }
