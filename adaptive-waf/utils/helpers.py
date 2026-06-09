"""
utils/helpers.py — Shared utility functions.
"""

import re
import hashlib
import ipaddress
from datetime import datetime
from typing import Any


def sanitize_input(text: str, max_len: int = 1000) -> str:
    """Basic input sanitisation — strip dangerous chars, truncate."""
    if not isinstance(text, str):
        return ""
    text = text[:max_len]
    # Remove null bytes and control characters
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    return text.strip()


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def mask_ip(ip: str) -> str:
    """Partially mask IP for display: 192.168.1.10 → 192.168.x.x"""
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.x.x"
    return ip


def hash_ip(ip: str) -> str:
    return hashlib.sha256(ip.encode()).hexdigest()[:12]


def format_timestamp(ts) -> str:
    if isinstance(ts, str):
        return ts
    if isinstance(ts, datetime):
        return ts.strftime("%Y-%m-%d %H:%M:%S")
    return str(ts)


def severity_badge(severity: str) -> str:
    colors = {
        "critical": "danger",
        "high":     "warning",
        "medium":   "info",
        "low":      "secondary",
    }
    return colors.get(severity.lower(), "secondary")


def action_badge(action: str) -> str:
    colors = {"block": "danger", "allow": "success", "challenge": "warning"}
    return colors.get(action.lower(), "secondary")


def truncate(text: str, length: int = 80) -> str:
    if not text:
        return ""
    return text if len(text) <= length else text[:length] + "…"


def percentage(part: int, total: int) -> float:
    return round(part / max(total, 1) * 100, 1)


def safe_float(val: Any, default: float = 0.0) -> float:
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


def safe_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default
