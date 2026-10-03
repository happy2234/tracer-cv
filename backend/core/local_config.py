"""Local-only TRACER-CV runtime configuration (standard library only)."""
from __future__ import annotations

import os
import json
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _env_path(name: str, fallback: Path) -> Path:
    value = os.environ.get(name)
    return Path(value).expanduser().resolve() if value else fallback.resolve()


def _bounded_int(value: object, default: int, low: int, high: int) -> int:
    try:
        return max(low, min(high, int(value)))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class LocalConfig:
    project_root: Path
    app_data_dir: Path
    config_file: Path
    datasets_dir: Path
    models_dir: Path
    evidence_dir: Path
    reports_dir: Path
    logs_dir: Path
    resources_dir: Path
    device: str = "auto"
    offline_mode: bool = True
    batch_size: int = 16
    workers: int = 2
    max_file_bytes: int = 2 * 1024 * 1024 * 1024
    max_image_pixels: int = 40_000_000
    logging_level: str = "INFO"
    theme: str = "light"

    @classmethod
    def load(cls) -> "LocalConfig":
        project = PROJECT_ROOT
        app_root = _env_path("TRACER_CV_DATA_DIR", project)
        config_file = Path(os.environ.get("TRACER_CV_CONFIG", project / "configs" / "tracer_cv.toml")).expanduser()
        values = {}
        try:
            if config_file.is_file():
                with config_file.open("rb") as stream:
                    parsed = tomllib.load(stream)
                values = parsed.get("tracer_cv", {}) if isinstance(parsed.get("tracer_cv", {}), dict) else {}
        except (OSError, tomllib.TOMLDecodeError):
            # Invalid configuration never causes a remote fallback or code execution.
            values = {}

        def path_value(key: str, env: str, fallback: Path) -> Path:
            override = os.environ.get(env, values.get(key))
            if isinstance(override, (str, os.PathLike)) and str(override).strip():
                try:
                    return Path(override).expanduser().resolve()
                except (OSError, RuntimeError, ValueError):
                    pass
            return fallback.resolve()

        device = str(os.environ.get("TRACER_CV_DEVICE", values.get("device", "auto"))).lower()
        if device not in {"auto", "cpu", "cuda"}:
            device = "auto"
        return cls(
            project_root=project,
            app_data_dir=app_root,
            config_file=config_file.resolve(),
            datasets_dir=path_value("datasets_dir", "TRACER_CV_DATASETS_DIR", app_root / "datasets_store"),
            models_dir=path_value("models_dir", "TRACER_CV_MODELS_DIR", app_root / "models_store"),
            evidence_dir=path_value("evidence_dir", "TRACER_CV_EVIDENCE_DIR", app_root / "evidence_store"),
            reports_dir=path_value("reports_dir", "TRACER_CV_REPORTS_DIR", project / "reports"),
            logs_dir=path_value("logs_dir", "TRACER_CV_LOGS_DIR", app_root / "logs"),
            resources_dir=path_value("resources_dir", "TRACER_CV_RESOURCES_DIR", project / "desktop" / "resources"),
            device=device,
            offline_mode=str(os.environ.get("TRACER_CV_OFFLINE", values.get("offline_mode", "true"))).lower() not in {"0", "false", "no"},
            batch_size=_bounded_int(values.get("batch_size", 16), 16, 1, 512),
            workers=_bounded_int(values.get("workers", 2), 2, 1, 32),
            max_file_bytes=_bounded_int(values.get("max_file_bytes", 2 * 1024 * 1024 * 1024), 2 * 1024 * 1024 * 1024, 1024, 2**50),
            max_image_pixels=_bounded_int(values.get("max_image_pixels", 40_000_000), 40_000_000, 1024, 2**40),
            logging_level=str(values.get("logging_level", "INFO")).upper(),
            theme=str(values.get("theme", "light")).lower() if str(values.get("theme", "light")).lower() in {"light", "dark"} else "light",
        )

    def ensure_local_directories(self) -> None:
        for path in (self.app_data_dir, self.datasets_dir, self.models_dir,
                     self.evidence_dir, self.reports_dir, self.logs_dir):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            if path != self.project_root:
                try:
                    path.chmod(0o700)
                except OSError:
                    pass

    def save(self) -> Path:
        """Persist supported non-secret settings atomically to the local TOML file."""
        self.config_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fields = {
            "offline_mode": "true" if self.offline_mode else "false",
            "device": json.dumps(self.device),
            "batch_size": str(self.batch_size), "workers": str(self.workers),
            "max_file_bytes": str(self.max_file_bytes), "max_image_pixels": str(self.max_image_pixels),
            "datasets_dir": json.dumps(str(self.datasets_dir)),
            "models_dir": json.dumps(str(self.models_dir)),
            "evidence_dir": json.dumps(str(self.evidence_dir)),
            "reports_dir": json.dumps(str(self.reports_dir)),
            "logs_dir": json.dumps(str(self.logs_dir)),
            "resources_dir": json.dumps(str(self.resources_dir)),
            "logging_level": json.dumps(self.logging_level),
            "theme": json.dumps(self.theme),
        }
        content = "[tracer_cv]\n" + "".join(f"{key} = {value}\n" for key, value in fields.items())
        fd, temp = tempfile.mkstemp(prefix=".tracer-config-", dir=self.config_file.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temp, 0o600)
            os.replace(temp, self.config_file)
        finally:
            try:
                os.unlink(temp)
            except FileNotFoundError:
                pass
        return self.config_file


def write_example_config(path: Path) -> Path:
    """Write a non-secret local config template without replacing an existing file."""
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        raise FileExistsError(path)
    example = (
        "[tracer_cv]\n"
        'offline_mode = true\n'
        'device = "auto"\n'
        "batch_size = 16\nworkers = 2\n"
        "max_file_bytes = 2147483648\nmax_image_pixels = 40000000\n"
        'logging_level = "INFO"\n'
    )
    path.write_text(example, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path
