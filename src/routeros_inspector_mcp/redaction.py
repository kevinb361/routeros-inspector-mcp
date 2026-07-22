"""Redaction of secrets and sensitive values before output.

Deterministic, tested, and idempotent. Works on strings, dicts, lists,
and arbitrary nested structures.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

# Patterns that match secret-like values. Order matters — more specific first.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # WG private keys (base64, 43 chars, ends with =)
    ("wireguard-private-key", re.compile(r"[A-Za-z0-9+/]{43}=", re.IGNORECASE)),
    # SNMP community strings (commonly quoted)
    ("snmp-community", re.compile(r'"[A-Za-z0-9_-]{8,}"')),
    # Generic password/token/secret fields by key name
    ("password", re.compile(r"(?i)\bpassword\b")),
    ("token", re.compile(r"(?i)\btoken\b")),
    ("secret", re.compile(r"(?i)\bsecret\b")),
    ("private-key", re.compile(r"(?i)private[_-]?key\b")),
    ("api-key", re.compile(r"(?i)api[_-]?key\b")),
    ("certificate", re.compile(r"(?i)BEGIN\s+CERTIFICATE")),
]

# Keys whose VALUES should always be redacted
_REDACT_VALUE_KEYS = {
    "password",
    "token",
    "secret",
    "private_key",
    "private-key",
    "wireguard_private_key",
    "wireguard-private-key",
    "snmp_community",
    "snmp-community",
    "api_key",
    "api-key",
    "certificate",
    "cert",
    "pre_shared_key",
    "pre-shared-key",
    "preshared_key",
    "preshared-key",
    "public_key",
    "public-key",
}

_REDACTED = "***REDACTED***"
_IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SAFE_ERROR_LABELS = {
    "auth",
    "denied",
    "hostkey_mismatch",
    "internal_error",
    "not_implemented",
    "parse_error",
    "timeout",
    "unreachable",
    "unsupported_version",
}


def _redact_public_ip_matches(value: str) -> str:
    """Redact globally routable IPv4 addresses while preserving RFC1918/local IPs."""

    def replace(match: re.Match[str]) -> str:
        candidate = match.group(0)
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            return candidate
        return _REDACTED if address.version == 4 and address.is_global else candidate

    return _IPV4_PATTERN.sub(replace, value)


def _redact_string(value: str) -> str:
    """Redact secret-like substrings in a string."""
    result = _redact_public_ip_matches(value)
    for _, pattern in _SECRET_PATTERNS:
        result = pattern.sub(_REDACTED, result)
    return result


def safe_error_label(exc: Exception) -> str:
    """Return a stable error label without exposing exception text."""
    error_class = getattr(exc, "error_class", None)
    if error_class in _SAFE_ERROR_LABELS:
        return str(error_class)
    return "internal_error"


def redact(obj: Any) -> Any:
    """Recursively redact secrets in an arbitrary structure.

    Returns a new object (deep copy for mutated parts).
    """
    if isinstance(obj, dict):
        return {k: _REDACTED if _should_redact_key(k) else redact(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(item) for item in obj]
    if isinstance(obj, str):
        return _redact_string(obj)
    # ints, floats, booleans, None — pass through
    return obj


def _should_redact_key(key: str) -> bool:
    """Check if a dict key name signals a secret value."""
    lower = key.lower().replace("-", "_")
    return lower in {k.lower().replace("-", "_") for k in _REDACT_VALUE_KEYS}
