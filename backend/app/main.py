from fastapi import FastAPI

from backend.app.api.datasets import router as datasets_router
from backend.app.api.router import router as system_router
from backend.app.config import settings


app = FastAPI(
    title=settings.app_name,
    description="Trust, Reliability & Assurance for Computer Vision",
    version=settings.app_version,
)

app.include_router(system_router)
app.include_router(datasets_router, prefix="/api/v1")


@app.get("/")
def root():
    return {
        "product": settings.app_name,
        "description": "Trust, Reliability & Assurance for Computer Vision",
        "status": "running",
    }
