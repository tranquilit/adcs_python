#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Central structured logging helpers for ADCS-Python.

The logging contract is intentionally small and SIEM-friendly:

* one event per physical line;
* JSON in production by default, human-readable text optionally;
* a compact JSON envelope: ``timestamp``, ``type`` and a same-named event
  object containing ``version.major``/``version.minor``;
* stable machine identifiers in ``event`` and ``reason`` plus readable
  ``action``/``status`` values;
* structured events are explicit: legacy ``event=... key=value`` text is never
  parsed into security fields;
* the existing ADCS enrollment RequestID is exposed as ``requestId``;
* the HTTP correlation identifier is kept separately as ``correlationId``;
* sensitive values are redacted defensively.

All application loggers live below the ``adcs`` namespace so Flask, CEP/CES,
authentication, issuance and TPM messages share one configuration.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import re
import time
import uuid
from typing import Any, Mapping, Optional

from flask import g, has_request_context, request
from flask.logging import default_handler


_LOGGER_ROOT = "adcs"
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_TEXT_UNQUOTED_RE = re.compile(r"^[A-Za-z0-9._:/@,+-]+$")
_SENSITIVE_FIELD_RE = re.compile(
    r"(?:^|[._-])(?:password|passwd|authorization|cookie|secret|token|"
    r"private[_-]?key|challenge[_-]?response|csr[_-]?der|cert[_-]?der|"
    r"p7[_-]?der|pkcs7[_-]?der)(?:$|[._-])",
    re.IGNORECASE,
)

# Structured audit events use a small top-level envelope (timestamp/type) and
# a same-named object containing a per-type major/minor schema version. Stable
# event tokens are retained for SIEM detections. Adding a field to one type
# increments its minor version; removing, renaming, or changing the meaning of
# a field increments its major version.
_EVENT_TYPE_VERSIONS = {
    "ADCS": (1, 0),
    "Authentication": (1, 0),
    "Callback": (1, 0),
    "CEP": (1, 0),
    "CES": (1, 0),
    "CMC": (1, 0),
    "Certificate": (1, 0),
    "Configuration": (1, 0),
    "CRL": (1, 0),
    "Enrollment": (1, 0),
    "HTTP": (1, 0),
    "KET": (1, 0),
    "TPMAttestation": (1, 0),
}

# Stable event token -> (event type, human action). The stable event
# token remains present in the payload so SOC rules never need to parse text.
_EVENT_SPECS = {
    "logging_configured": ("Configuration", "Configure"),
    "config_loaded": ("Configuration", "Load"),
    "request_received": ("HTTP", "Receive"),
    "request_complete": ("HTTP", "Complete"),
    "authentication_challenge": ("Authentication", "Challenge"),
    "authentication_failed": ("Authentication", "Authenticate"),
    "authentication_succeeded": ("Authentication", "Authenticate"),
    "kerberos_auth_error": ("Authentication", "Kerberos"),
    "callback_exception": ("Callback", "Execute"),
    "cep_policy_request": ("CEP", "PolicyRequest"),
    "cep_request_rejected": ("CEP", "Request"),
    "cep_message_id_parse_failed": ("CEP", "ParseMessageId"),
    "cep_policy_build_failed": ("CEP", "BuildPolicy"),
    "cep_policy_response": ("CEP", "PolicyResponse"),
    "cep_policy_response_failed": ("CEP", "PolicyResponse"),
    "ces_request": ("CES", "Request"),
    "ces_request_rejected": ("CES", "Request"),
    "ces_template_build_failed": ("CES", "BuildTemplate"),
    "ket_response": ("KET", "Response"),
    "ket_response_failed": ("KET", "Response"),
    "tpm_challenge_rejected": ("TPMAttestation", "Challenge"),
    "tpm_attestation_failed": ("TPMAttestation", "Verify"),
    "tpm_pending_restore_failed": ("TPMAttestation", "RestorePending"),
    "pending_request_missing": ("Enrollment", "RestorePending"),
    "pending_request_read_failed": ("Enrollment", "RestorePending"),
    "cmc_payload_extract_failed": ("CMC", "ExtractPayload"),
    "cmc_parse_failed": ("CMC", "Parse"),
    "enrollment_requested": ("Enrollment", "Request"),
    "enrollment_rejected": ("Enrollment", "Request"),
    "certificate_pending": ("Certificate", "Issue"),
    "certificate_denied": ("Certificate", "Issue"),
    "certificate_issue_failed": ("Certificate", "Issue"),
    "certificate_response_failed": ("Certificate", "Response"),
    "certificate_issued": ("Certificate", "Issue"),
    "certificate_revoked": ("Certificate", "Revoke"),
    "certificate_revoke_failed": ("Certificate", "Revoke"),
    "certificate_unrevoked": ("Certificate", "Unrevoke"),
    "certificate_unrevoke_failed": ("Certificate", "Unrevoke"),
    "crl_generated": ("CRL", "Generate"),
    "crl_generation_failed": ("CRL", "Generate"),
}

# Existing call-site names -> concise structured field names. Unknown
# snake_case fields are converted to lowerCamelCase automatically.
_EVENT_FIELD_NAMES = {
    "enrollment_request_id": "requestId",
    "ca_id": "caId",
    "template": "template",
    "template_oid": "templateOid",
    "serial": "serialNumber",
    "error_type": "errorType",
    "callback_path": "callbackPath",
    "callback_func": "callback",
    "username": "account",
    "status_code": "statusCode",
    "content_length": "contentLength",
    "response_length": "responseLength",
    "duration_ms": "durationMs",
    "body_part_id": "bodyPartId",
    "soap_message_id": "soapMessageId",
    "template_name": "templateName",
    "challenge_request_id": "challengeRequestId",
    "crl_number": "crlNumber",
    "revoked_count": "revokedCount",
    "crl_path": "crlPath",
    # ``status`` is reserved for the event result itself. Call sites that pass
    # a protocol/callback status keep it separately.
    "status": "resultStatus",
}

class RequestContextFilter(logging.Filter):
    """Inject bounded request metadata into every ADCS log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.correlation_id = "-"
        record.enrollment_request_id = "-"
        record.remote_addr = "-"
        record.endpoint = "-"
        record.request_path = "-"
        record.request_method = "-"
        record.username = "-"
        record.auth_method = "-"

        if has_request_context():
            record.correlation_id = _bounded_text(
                getattr(g, "correlation_id", None) or "-", 128
            )
            record.enrollment_request_id = _bounded_text(
                getattr(g, "enrollment_request_id", None) or "-", 128
            )
            record.remote_addr = _bounded_text(request.remote_addr or "-", 128)
            record.endpoint = _bounded_text(request.endpoint or "-", 256)
            record.request_path = _bounded_text(request.path or "-", 512)
            record.request_method = _bounded_text(request.method or "-", 16)
            record.username = _bounded_text(getattr(g, "username", None) or "-", 256)
            record.auth_method = _bounded_text(getattr(g, "auth_method", None) or "-", 64)

        return True


class JsonFormatter(logging.Formatter):
    """Render one compact structured JSON object per log record."""

    def __init__(self, *, include_stack_trace: bool = True) -> None:
        super().__init__()
        self.include_stack_trace = bool(include_stack_trace)

    def format(self, record: logging.LogRecord) -> str:
        event_token = getattr(record, "event_action", None)
        outcome = getattr(record, "event_outcome", None)
        reason = getattr(record, "event_reason", None)

        explicit_fields = getattr(record, "event_fields", None) or {}
        fields = _sanitize_mapping(explicit_fields)

        if not outcome and event_token:
            outcome = _infer_outcome(event_token, fields)

        if getattr(record, "event_message", None):
            message = _bounded_text(record.event_message, 1024)
        else:
            message = _bounded_text(record.getMessage(), 2048)

        event_type, action = _event_spec(str(event_token or "log_message"))
        major, minor = _EVENT_TYPE_VERSIONS.get(event_type, (1, 0))

        body: dict[str, Any] = {
            "version": {"major": major, "minor": minor},
            "event": _bounded_text(event_token or "log_message", 128),
            "action": _bounded_text(action, 128),
            "logLevel": record.levelname,
            "message": message,
        }

        status = _event_status(str(event_token or ""), outcome)
        if status:
            body["status"] = status
        if reason:
            body["reason"] = _bounded_text(reason, 512)

        component = _component_from_logger(record.name)
        if component:
            body["component"] = component
        body["logger"] = _bounded_text(record.name, 256)

        correlation_id = getattr(record, "correlation_id", "-")
        if correlation_id != "-":
            body["correlationId"] = correlation_id

        enrollment_request_id = getattr(record, "enrollment_request_id", "-")
        if enrollment_request_id != "-":
            body["requestId"] = enrollment_request_id

        remote_addr = getattr(record, "remote_addr", "-")
        if remote_addr != "-":
            body["remoteAddress"] = remote_addr

        request_method = getattr(record, "request_method", "-")
        endpoint = getattr(record, "endpoint", "-")
        request_path = getattr(record, "request_path", "-")
        if request_method != "-":
            body["httpMethod"] = request_method
        if endpoint != "-":
            body["httpRoute"] = endpoint
        if request_path != "-":
            body["httpPath"] = request_path

        username = getattr(record, "username", "-")
        if username != "-":
            body["account"] = username

        auth_method = getattr(record, "auth_method", "-")
        if auth_method != "-":
            body["authType"] = auth_method

        # Flatten ADCS-specific fields inside the type object. Explicit request-context
        # values win over duplicate call-site
        # fields so a handler cannot accidentally overwrite trusted context.
        for key, value in fields.items():
            field_name = _event_field_name(key)
            if key == "method" and event_type == "Authentication":
                field_name = "authType"
            value = _normalize_event_field_value(field_name, value)
            if field_name in {
                "version", "event", "action", "status", "reason", "message",
                "logLevel", "logger", "component", "correlationId", "requestId",
                "remoteAddress", "httpMethod", "httpRoute", "httpPath", "account",
                "authType",
            } and field_name in body:
                # Keep the canonical context value and preserve the call-site
                # detail under a non-conflicting name when it differs.
                if body[field_name] != value:
                    body[_detail_field_name(field_name)] = value
                continue
            body[field_name] = value

        if record.exc_info:
            body.setdefault(
                "errorType", getattr(record.exc_info[0], "__name__", "Exception")
            )
            if self.include_stack_trace:
                body["stackTrace"] = _bounded_text(
                    self.formatException(record.exc_info), 16384
                )

        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ),
            "type": event_type,
            event_type: body,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)


class TextFormatter(logging.Formatter):
    """Human-readable formatter for local development and troubleshooting."""

    converter = time.gmtime

    def __init__(self, *, include_stack_trace: bool = True) -> None:
        super().__init__()
        self.include_stack_trace = bool(include_stack_trace)

    def format(self, record: logging.LogRecord) -> str:
        action = getattr(record, "event_action", None)
        outcome = getattr(record, "event_outcome", None)
        reason = getattr(record, "event_reason", None)
        explicit_fields = getattr(record, "event_fields", None) or {}
        fields = _sanitize_mapping(explicit_fields)

        if not outcome and action:
            outcome = _infer_outcome(action, fields)

        if getattr(record, "event_message", None):
            message = _bounded_text(record.event_message, 1024)
        else:
            message = _bounded_text(record.getMessage(), 2048)

        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        parts = [ts, record.levelname, record.name]

        correlation_id = getattr(record, "correlation_id", "-")
        enrollment_request_id = getattr(record, "enrollment_request_id", "-")
        if correlation_id != "-":
            parts.append(f"correlation_id={_text_log_value(correlation_id, max_length=128)}")
        if enrollment_request_id != "-":
            parts.append(f"request_id={_text_log_value(enrollment_request_id, max_length=128)}")
        remote_addr = getattr(record, "remote_addr", "-")
        username = getattr(record, "username", "-")
        auth_method = getattr(record, "auth_method", "-")
        request_path = getattr(record, "request_path", "-")
        if remote_addr != "-":
            parts.append(f"remote={_text_log_value(remote_addr, max_length=128)}")
        if username != "-":
            parts.append(f"user={_text_log_value(username, max_length=256)}")
        if auth_method != "-":
            parts.append(f"auth={_text_log_value(auth_method, max_length=64)}")
        if request_path != "-":
            parts.append(f"path={_text_log_value(request_path, max_length=512)}")
        if action:
            parts.append(f"event={_text_log_value(action, max_length=128)}")
        if outcome:
            parts.append(f"outcome={_text_log_value(outcome, max_length=32)}")
        if reason:
            parts.append(f"reason={_text_log_value(reason, max_length=512)}")

        parts.append(message)
        for key, value in fields.items():
            parts.append(f"{key}={_text_log_value(value)}")

        rendered = " ".join(parts)
        if record.exc_info and self.include_stack_trace:
            rendered += " stack_trace=" + _text_log_value(
                self.formatException(record.exc_info), max_length=16384
            )
        return rendered


def _bounded_text(value: Any, max_length: int) -> str:
    text = str(value)
    # Keep physical log lines safe even in text mode.
    text = text.replace("\x00", "\\0").replace("\r", "\\r").replace("\n", "\\n")
    if len(text) > max_length:
        text = text[: max(0, max_length - 3)] + "..."
    return text


def _text_log_value(value: Any, *, max_length: int = 512) -> str:
    """Return a bounded logfmt-style value for the optional text formatter."""
    if value is None:
        return "-"
    text = _bounded_text(value, max_length)
    if _TEXT_UNQUOTED_RE.fullmatch(text):
        return text
    return json.dumps(text, ensure_ascii=False)


def get_logger(component: Optional[str] = None) -> logging.Logger:
    if not component:
        return logging.getLogger(_LOGGER_ROOT)
    component = component.strip(".")
    return logging.getLogger(f"{_LOGGER_ROOT}.{component}")


def set_enrollment_request_id(request_id: Any) -> None:
    """Attach the existing ADCS protocol RequestID to the Flask request context."""
    if has_request_context():
        g.enrollment_request_id = _bounded_text(request_id, 128)


def log_event(
    logger: logging.Logger,
    level: int,
    action: str,
    message: str,
    *,
    outcome: Optional[str] = None,
    reason: Optional[str] = None,
    exc_info: Any = None,
    **fields: Any,
) -> None:
    """Emit a stable structured event without coupling callers to JSON.

    ``fields`` are raw values; dangerous field names are redacted by the
    formatter.  Do not intentionally pass secrets even though this defence in
    depth exists.
    """
    extra = {
        "event_action": _bounded_text(action, 128),
        "event_message": _bounded_text(message, 1024),
        "event_outcome": _bounded_text(outcome, 32) if outcome else None,
        "event_reason": _bounded_text(reason, 512) if reason else None,
        "event_fields": dict(fields),
    }
    logger.log(level, message, extra=extra, exc_info=exc_info)


def _parse_level(value: Any) -> int:
    name = str(value or "INFO").upper()
    level = getattr(logging, name, None)
    if not isinstance(level, int):
        raise ValueError(f"Invalid logging level: {value!r}")
    return level


def _parse_format(value: Any) -> str:
    name = str(value or "json").strip().lower()
    if name not in {"json", "text"}:
        raise ValueError(f"Invalid logging format: {value!r}; expected 'json' or 'text'")
    return name


def _parse_bool(value: Any, *, name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    raise ValueError(f"Invalid {name}: {value!r}; expected a boolean")


def _make_formatter(fmt_name: str, *, include_stack_trace: bool = True) -> logging.Formatter:
    if fmt_name == "json":
        return JsonFormatter(include_stack_trace=include_stack_trace)
    return TextFormatter(include_stack_trace=include_stack_trace)


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


def _configure_adcs_root(conf: dict) -> tuple[logging.Logger, logging.Handler, int, str, bool]:
    cfg = conf.get("logging") or {}
    level = _parse_level(cfg.get("level", "INFO"))
    fmt_name = _parse_format(cfg.get("format", "json"))
    include_stack_trace = _parse_bool(
        cfg.get("include_stack_trace", True), name="logging.include_stack_trace"
    )
    formatter = _make_formatter(
        fmt_name, include_stack_trace=include_stack_trace
    )

    adcs_logger = get_logger()
    _remove_managed_handlers(adcs_logger)
    adcs_logger.setLevel(level)
    adcs_logger.propagate = False

    # StreamHandler writes to stderr. Under systemd this is captured by
    # journald and can be forwarded to a SIEM by the host logging policy.
    handler = _make_handler(logging.StreamHandler(), formatter)
    handler.setLevel(level)
    adcs_logger.addHandler(handler)
    return adcs_logger, handler, level, fmt_name, include_stack_trace


def configure_logging(app, conf: dict) -> logging.Logger:
    """Configure Flask + ADCS logging on stderr."""
    adcs_logger, handler, level, fmt_name, include_stack_trace = _configure_adcs_root(conf)

    # Flask logs uncaught request exceptions through app.logger. Route those to
    # the same handler without duplicate propagation.
    _remove_managed_handlers(app.logger)
    if default_handler in app.logger.handlers:
        app.logger.removeHandler(default_handler)
    app.logger.setLevel(level)
    app.logger.propagate = False
    app.logger.addHandler(handler)

    log_event(
        adcs_logger,
        logging.INFO,
        "logging_configured",
        "Logging configured",
        outcome="success",
        configured_level=logging.getLevelName(level),
        format=fmt_name,
        include_stack_trace=include_stack_trace,
        sink="stderr",
    )
    return adcs_logger


def configure_standalone_logging(conf: dict) -> logging.Logger:
    """Configure the ``adcs`` logger for non-Flask CLI processes."""
    adcs_logger, _handler, level, fmt_name, include_stack_trace = _configure_adcs_root(conf)
    log_event(
        adcs_logger,
        logging.INFO,
        "logging_configured",
        "Logging configured",
        outcome="success",
        configured_level=logging.getLevelName(level),
        format=fmt_name,
        include_stack_trace=include_stack_trace,
        sink="stderr",
    )
    return adcs_logger


def install_request_logging(app) -> None:
    """Install HTTP correlation and request completion logging once."""
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

        log_event(
            request_logger,
            logging.DEBUG,
            "request_received",
            "HTTP request received",
            method=request.method,
            path=request.path,
            content_length=request.content_length,
        )

    @app.after_request
    def _adcs_request_finished(response):
        started = getattr(g, "request_started_monotonic", None)
        duration_ms = (time.perf_counter() - started) * 1000.0 if started is not None else -1.0
        correlation_id = getattr(g, "correlation_id", None)
        if correlation_id:
            response.headers.setdefault("X-Request-ID", correlation_id)

        # Component-specific 4xx events carry the actual policy/security reason.
        # The access event remains INFO; 5xx indicates a server-side failure.
        level = logging.ERROR if response.status_code >= 500 else logging.INFO
        outcome = "failure" if response.status_code >= 400 else "success"
        response_length = response.calculate_content_length()

        log_event(
            request_logger,
            level,
            "request_complete",
            "HTTP request completed",
            outcome=outcome,
            method=request.method,
            path=request.path,
            status_code=response.status_code,
            duration_ms=round(duration_ms, 2),
            response_length=response_length,
        )
        return response

    app._adcs_request_logging_installed = True


def _component_from_logger(name: str) -> Optional[str]:
    prefix = _LOGGER_ROOT + "."
    if name.startswith(prefix):
        return name[len(prefix):]
    if name == _LOGGER_ROOT:
        return "root"
    return None


def _event_spec(event_token: str) -> tuple[str, str]:
    spec = _EVENT_SPECS.get(event_token)
    if spec:
        return spec

    lowered = event_token.lower()
    prefix_types = (
        ("authentication_", "Authentication"),
        ("auth_", "Authentication"),
        ("callback_", "Callback"),
        ("cep_", "CEP"),
        ("ces_", "CES"),
        ("cmc_", "CMC"),
        ("certificate_", "Certificate"),
        ("crl_", "CRL"),
        ("enrollment_", "Enrollment"),
        ("request_", "HTTP"),
        ("tpm_", "TPMAttestation"),
    )
    event_type = "ADCS"
    for prefix, candidate in prefix_types:
        if lowered.startswith(prefix):
            event_type = candidate
            break
    return event_type, "".join(part.capitalize() for part in event_token.split("_") if part) or "Log"


def _event_status(event_token: str, outcome: Optional[str]) -> Optional[str]:
    lowered = event_token.lower()
    if lowered.endswith("_denied") or event_token == "certificate_denied":
        return "Denied"
    if lowered.endswith("_rejected"):
        return "Rejected"
    if event_token in {"certificate_pending", "authentication_challenge"}:
        return "Pending"
    if outcome:
        normalized = str(outcome).strip().lower()
        if normalized == "success":
            return "Success"
        if normalized == "failure":
            return "Failure"
        if normalized == "unknown":
            return "Unknown"
        return _bounded_text(outcome, 64)
    return None


def _event_field_name(key: str) -> str:
    mapped = _EVENT_FIELD_NAMES.get(key)
    if mapped:
        return mapped
    parts = re.split(r"[_.-]+", str(key))
    if not parts:
        return _bounded_text(key, 128)
    first = parts[0]
    return first + "".join(p[:1].upper() + p[1:] for p in parts[1:] if p)


def _normalize_event_field_value(field_name: str, value: Any) -> Any:
    """Keep identifier fields stable across all event producers."""
    if field_name in {"requestId", "challengeRequestId", "correlationId"}:
        return None if value is None else _bounded_text(value, 128)
    return value


def _detail_field_name(field_name: str) -> str:
    return "detail" + field_name[:1].upper() + field_name[1:]


def _humanize_action(action: str) -> str:
    return action.replace("_", " ").strip().capitalize()


def _infer_outcome(action: str, fields: Mapping[str, Any]) -> Optional[str]:
    status = fields.get("status_code") or fields.get("status")
    try:
        if status is not None and str(status).isdigit():
            return "failure" if int(status) >= 400 else "success"
    except (TypeError, ValueError):
        pass

    lowered = action.lower()
    if any(word in lowered for word in ("failed", "failure", "rejected", "denied", "invalid", "missing", "error")):
        return "failure"
    if any(word in lowered for word in ("success", "issued", "generated", "configured", "loaded", "revoked")):
        return "success"
    return None


def _sanitize_mapping(mapping: Mapping[str, Any]) -> dict[str, Any]:
    return {str(k): _sanitize_field(str(k), v, depth=0) for k, v in mapping.items()}


def _sanitize_field(key: str, value: Any, *, depth: int = 0) -> Any:
    # Boolean/metadata presence flags are safe and useful to the SOC; the
    # secret itself must still never be logged.
    if not key.lower().endswith("_present") and _SENSITIVE_FIELD_RE.search(key):
        return "[REDACTED]"
    return _json_safe_value(value, depth=depth)


def _json_safe_value(value: Any, *, depth: int = 0) -> Any:
    if depth > 3:
        return "<max-depth>"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, bytes):
        return f"<bytes:{len(value)}>"
    if isinstance(value, str):
        return _bounded_text(value, 2048)
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 50:
                out["..."] = "<truncated>"
                break
            key_text = _bounded_text(key, 128)
            out[key_text] = _sanitize_field(key_text, item, depth=depth + 1)
        return out
    if isinstance(value, (list, tuple, set)):
        items = list(value)
        rendered = [_json_safe_value(v, depth=depth + 1) for v in items[:50]]
        if len(items) > 50:
            rendered.append("<truncated>")
        return rendered
    return _bounded_text(value, 2048)
