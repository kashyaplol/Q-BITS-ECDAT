"""Logging configuration for the application.

Provides a simple ``get_logger`` helper. Any module can do::

    from backend.app.core.logging import get_logger
    logger = get_logger(__name__)

and start logging immediately.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

from .config import settings

_CONFIGURED = False


def configure_logging() -> None:
    """Set up the root logger once for the entire app."""
    global _CONFIGURED
    if _CONFIGURED:
        return

    level = logging.DEBUG if settings.debug else logging.INFO

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )

    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)

    _CONFIGURED = True


def get_logger(name: str) -> Any:
    """Return a logger configured for ``name`` (usually ``__name__``)."""
    configure_logging()
    return logging.getLogger(name)
