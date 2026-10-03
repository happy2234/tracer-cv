from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from backend.core.local_config import LocalConfig, PROJECT_ROOT

_local = LocalConfig.load()


class Settings(BaseSettings):
    app_name: str = "TRACER-CV"
    app_version: str = "0.1.0"
    environment: str = "development"

    offline_mode: bool = _local.offline_mode
    datasets_dir: Path = _local.datasets_dir
    models_dir: Path = _local.models_dir
    evidence_dir: Path = _local.evidence_dir
    reports_dir: Path = _local.reports_dir
    logs_dir: Path = _local.logs_dir
    device: str = _local.device

    model_config = SettingsConfigDict(
        env_file=None,
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
