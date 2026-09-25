#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Central logging helpers for the ADCS application.

All application loggers live below the ``adcs`` namespace so authentication,
CEP/CES, issuance and TPM messages can be routed to the same handlers.
Sensitive request payloads and authentication secrets must never be logged.
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from typing import Any, Optional

from flask import g, has_request_context, request
from flask.logging import default_handler


_LOGGER_ROOT = "adcs"
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_LOGFMT_UNQUOTED_RE = re.compile(r"^[A-Za-z0-9._:/@,+-]+$")


class _UtcFormatter(logging.Formatter):
    converter = time.gmtime


class RequestContextFilter(logging.Filter):
    """Inject safe request metadata into every log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = "-"
        record.remote_addr = "-"
        record.endpoint = "-"
        record.username = "-"
        record.auth_method = "-"

        if has_request_context():
            record.request_id = safe_log_value(
                getattr(g, "correlation_id", None) or "-", max_length=128
            )
            record.remote_addr = safe_log_value(request.remote_addr or "-", max_length=128)
            record.endpoint = safe_log_value(request.endpoint or request.path or "-", max_length=256)
            record.username = safe_log_value(getattr(g, "username", None) or "-", max_length=256)
            record.auth_method = safe_log_value(getattr(g, "auth_method", None) or "-", max_length=64)

        return True


def safe_log_value(value: Any, *, max_length: int = 512) -> str:
    """Return a bounded logfmt-compatible representation for untrusted values.

    Simple values stay readable (``user@example.org``); values containing spaces,
    control characters or logfmt separators are JSON-quoted so one user-controlled
    value cannot create fake fields or extra log lines.
    """
    if value is None:
        return "-"

    text = str(value)
    if len(text) > max_length:
        text = text[: max_length - 3] + "..."

    if _LOGFMT_UNQUOTED_RE.fullmatch(text):
        return text

    return json.dumps(text, ensure_ascii=False)


def get_logger(component: Optional[str] = None) -> logging.Logger:
    if not component:
        return logging.getLogger(_LOGGER_ROOT)
    component = component.strip(".")
    return logging.getLogger(f"{_LOGGER_ROOT}.{component}")


def _parse_level(value: Any) -> int:
    name = str(value or "INFO").upper()
    level = getattr(logging, name, None)
    if not isinstance(level, int):
        raise ValueError(f"Invalid logging level: {value!r}")
    return level


def _make_handler(handler: logging.Handler, formatter: logging.Formatter) -> logging.Handler:
    handler.setFormatter(formatter)
    handler.addFilter(RequestContextFilter())
    setattr(handler, "_adcs_managed", True)
    return handler


def _remove_managed_handlers(logger: logging.Logger) -> None:
    for handler in list(logger.handlers):
        if getattr(handler, "_adcs_managed", False):
            logger.removeHandler(handler)
            try:
                handler.close()
            except Exception:
                pass


def configure_logging(app, conf: dict) -> logging.Logger:
    """Configure ADCS logging on stderr.

    The application only owns the log level and message format. Log routing,
    persistence and rotation are intentionally left to systemd/journald,
    rsyslog and the host logging policy.
    """
    cfg = conf.get("logging") or {}
    level = _parse_level(cfg.get("level", "INFO"))

    formatter = _UtcFormatter(
        fmt=(
            "%(asctime)s.%(msecs)03dZ %(levelname)s %(name)s "
            "request_id=%(request_id)s remote=%(remote_addr)s "
            "endpoint=%(endpoint)s user=%(username)s auth=%(auth_method)s "
            "%(message)s"
        ),
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    adcs_logger = get_logger()
    _remove_managed_handlers(adcs_logger)
    adcs_logger.setLevel(level)
    adcs_logger.propagate = False

    # StreamHandler writes to stderr by default. Under systemd this is captured
    # by journald and can then be routed/persisted by rsyslog as required.
    handler = _make_handler(logging.StreamHandler(), formatter)
    handler.setLevel(level)
    adcs_logger.addHandler(handler)

    # Flask logs uncaught request exceptions through app.logger. Route those to
    # the same dedicated handler without duplicating them through propagation.
    _remove_managed_handlers(app.logger)
    if default_handler in app.logger.handlers:
        app.logger.removeHandler(default_handler)
    app.logger.setLevel(level)
    app.logger.propagate = False
    app.logger.addHandler(handler)

    adcs_logger.info(
        "event=logging_configured level=%s sink=stderr",
        logging.getLevelName(level),
    )
    return adcs_logger


def install_request_logging(app) -> None:
    """Install request correlation and request completion logging once."""
    if getattr(app, "_adcs_request_logging_installed", False):
        return

    request_logger = get_logger("request")

    @app.before_request
    def _adcs_request_started():
        incoming_id = request.headers.get("X-Request-ID", "")
        if incoming_id and _REQUEST_ID_RE.fullmatch(incoming_id):
            correlation_id = incoming_id
        else:
            correlation_id = str(uuid.uuid4())

        g.correlation_id = correlation_id
        g.request_started_monotonic = time.perf_counter()

        request_logger.debug(
            "event=request_received method=%s path=%s content_length=%s",
            safe_log_value(request.method, max_length=16),
            safe_log_value(request.path, max_length=512),
            request.content_length if request.content_length is not None else "-",
        )

    @app.after_request
    def _adcs_request_finished(response):
        started = getattr(g, "request_started_monotonic", None)
        duration_ms = (time.perf_counter() - started) * 1000.0 if started is not None else -1.0
        correlation_id = getattr(g, "correlation_id", None)
        if correlation_id:
            response.headers.setdefault("X-Request-ID", correlation_id)

        # Client-side 4xx outcomes are logged by the component that knows the
        # precise reason (auth, CEP, CES, enrollment). Keeping the generic access
        # event at INFO avoids turning expected 401/403 protocol flows into a
        # second warning. Server-side 5xx responses remain ERROR.
        log_fn = request_logger.error if response.status_code >= 500 else request_logger.info
        response_length = response.calculate_content_length()

        log_fn(
            "event=request_complete method=%s path=%s status=%d duration_ms=%.2f response_length=%s",
            safe_log_value(request.method, max_length=16),
            safe_log_value(request.path, max_length=512),
            response.status_code,
            duration_ms,
            response_length if response_length is not None else "-",
        )
        return response

    app._adcs_request_logging_installed = True
