"""
NEMESIS structured logging.

Provides JSON and console formatters with stage-aware context.
Every log entry includes: timestamp, stage, target, duration.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog


def setup_logging(level: str = "INFO", fmt: str = "console") -> None:
    """
    Configure structured logging for the entire application.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR)
        fmt: Output format — "console" for human-readable, "json" for machine-parseable
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    if fmt == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(
            colors=sys.stderr.isatty(),
            pad_event=40,
        )

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )

    # Also configure stdlib logging for third-party libraries
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stderr,
        level=log_level,
    )


def get_logger(stage: str = "", **initial_context: Any) -> structlog.BoundLogger:
    """
    Get a logger bound with stage context.

    Usage:
        log = get_logger("recon", target="cab_checksum_finish")
        log.info("found blocker", blocker="__STDC_ISO_10646__")
    """
    logger = structlog.get_logger()
    if stage:
        logger = logger.bind(stage=stage)
    if initial_context:
        logger = logger.bind(**initial_context)
    return logger
