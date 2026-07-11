"""
Structured logging setup for ThreatFusion.

Design decisions
----------------
* We configure the **root** logger so that every library and sub-module
  inherits the same format and level — no per-module boilerplate.
* The format string includes ``%(name)s`` so you can immediately tell
  which component emitted a log line (e.g. ``threatfusion.vt_client``
  vs ``uvicorn.access``).
* ``setup_logging`` is idempotent: calling it twice won't duplicate
  handlers, because we clear existing handlers first.
"""

from __future__ import annotations

import logging
import sys


def setup_logging(level: str = "INFO") -> logging.Logger:
    """Configure the root logger with a consistent format and level.

    Parameters
    ----------
    level:
        Any standard Python log-level name (DEBUG, INFO, WARNING, …).
        Parsed case-insensitively.

    Returns
    -------
    logging.Logger
        The root ``threatfusion`` logger, ready to use.

    Notes
    -----
    This function should be called **once** during application startup
    (inside the FastAPI lifespan).  Subsequent calls are safe but
    redundant.
    """
    # Resolve the level string to its numeric constant.  ``getLevelName``
    # also accepts ints, so this is safe even if someone passes "10".
    numeric_level: int = logging.getLevelNamesMapping().get(
        level.upper(), logging.INFO
    )

    # ── Format ──────────────────────────────────────────────────────────
    # Compact, machine-grep-friendly, but still human-readable.
    log_format = "[%(asctime)s] %(levelname)s %(name)s: %(message)s"
    formatter = logging.Formatter(log_format, datefmt="%Y-%m-%d %H:%M:%S")

    # ── Stream handler → stderr ─────────────────────────────────────────
    # stderr is conventional for logs so that stdout is clean for
    # structured output (e.g. JSON API responses piped elsewhere).
    stream_handler = logging.StreamHandler(stream=sys.stderr)
    stream_handler.setFormatter(formatter)

    # ── Apply to root logger ────────────────────────────────────────────
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    # Remove any pre-existing handlers to prevent duplicate lines when
    # setup_logging is called more than once (e.g. during tests).
    root_logger.handlers.clear()
    root_logger.addHandler(stream_handler)

    # Return a namespaced logger for ThreatFusion's own messages.
    tf_logger = logging.getLogger("threatfusion")
    tf_logger.debug("Logging initialised at level %s", level.upper())
    return tf_logger


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the ``threatfusion`` namespace.

    Usage::

        from app.core.logging import get_logger
        logger = get_logger(__name__)   # → "threatfusion.app.services.vt"
        logger.info("Querying VirusTotal for %s", ioc)

    Keeping all application loggers under one namespace makes it trivial
    to adjust verbosity at runtime (``logging.getLogger("threatfusion").setLevel(...)``).
    """
    return logging.getLogger(f"threatfusion.{name}")
