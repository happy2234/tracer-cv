"""CPU/CUDA selection with a local CUDA readiness probe."""
from __future__ import annotations

from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version as package_version


class DeviceUnavailableError(RuntimeError):
    pass


@dataclass(frozen=True)
class ComputeContext:
    requested: str
    device: str
    device_name: str
    cuda_available: bool | None
    torch_version: str
    fallback_reason: str | None = None


def resolve_compute(requested: str = "auto") -> ComputeContext:
    requested = str(requested).lower()
    if requested not in {"auto", "cpu", "cuda"}:
        raise ValueError("device must be auto, cpu, or cuda")
    if requested == "cpu":
        try:
            torch_version = package_version("torch")
        except PackageNotFoundError:
            torch_version = "unavailable"
        # CPU selection intentionally does not import a model framework or
        # initialize CUDA. CUDA state is left unprobed in this mode.
        return ComputeContext(requested, "cpu", "CPU", None, torch_version)
    try:
        import torch
        version = str(torch.__version__)
        available = bool(torch.cuda.is_available())
    except Exception as exc:
        if requested == "cuda":
            raise DeviceUnavailableError(f"CUDA requires a usable local PyTorch install: {exc}") from exc
        return ComputeContext(requested, "cpu", "CPU", False, "unavailable", "PyTorch unavailable")

    if not available:
        if requested == "cuda":
            raise DeviceUnavailableError("CUDA was explicitly requested, but torch.cuda.is_available() is false")
        return ComputeContext(requested, "cpu", "CPU", False, version, "CUDA unavailable")
    try:
        # Minimal local allocation and synchronization verifies the runtime and
        # device before exposing CUDA as active. No network access is used.
        probe = torch.empty((1,), device="cuda")
        torch.cuda.synchronize()
        del probe
        name = str(torch.cuda.get_device_name(0))
        return ComputeContext(requested, "cuda", name, True, version)
    except Exception as exc:
        if requested == "cuda":
            raise DeviceUnavailableError(f"CUDA device probe failed: {type(exc).__name__}: {exc}") from exc
        return ComputeContext(requested, "cpu", "CPU", False, version,
                              f"CUDA unsuitable; using CPU ({type(exc).__name__})")
