"""Bounded local rotating log setup; no remote handlers."""
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


def configure_local_logging(log_dir: Path, level: str = "INFO") -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    logger = logging.getLogger("tracer_cv")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    if not any(isinstance(handler, RotatingFileHandler) for handler in logger.handlers):
        handler = RotatingFileHandler(log_dir / "tracer-cv.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        logger.addHandler(handler)
    logger.propagate = False
    return logger
