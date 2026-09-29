from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    app_name: str = "TRACER-CV"
    app_version: str = "0.1.0"
    environment: str = "development"

    offline_mode: bool = True

    datasets_dir: Path = PROJECT_ROOT / "datasets_store"
    models_dir: Path = PROJECT_ROOT / "models_store"
    evidence_dir: Path = PROJECT_ROOT / "evidence_store"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
