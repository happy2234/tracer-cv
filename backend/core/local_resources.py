"""Load bundled local resources only; reject URLs and path traversal."""
from pathlib import Path


def load_resource(root: Path, relative_name: str) -> bytes:
    if "://" in relative_name or relative_name.startswith(("http:", "https:")):
        raise ValueError("remote resources are not supported")
    relative = Path(relative_name)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("resource path must remain under the local resource directory")
    base = root.resolve()
    target = (base / relative).resolve(strict=True)
    if not target.is_relative_to(base) or not target.is_file():
        raise ValueError("resource must be a file under the local resource directory")
    return target.read_bytes()


def load_stylesheet(root: Path, relative_name: str = "tracer.qss") -> str:
    return load_resource(root, relative_name).decode("utf-8", errors="strict")
