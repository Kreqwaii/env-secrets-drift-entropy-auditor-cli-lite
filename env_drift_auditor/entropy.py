"""Shannon entropy calculation, secret pattern detection, and safe redaction."""

import math
import re
from typing import Dict, List, Optional, Tuple

SECRET_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{16,}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("jwt_token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    (
        "db_url_with_creds",
        re.compile(r"\b(?:postgres|postgresql|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@[^\s]+", re.IGNORECASE),
    ),
]

PLACEHOLDER_HINTS = (
    "example",
    "changeme",
    "your_",
    "replace_me",
    "dummy",
    "placeholder",
    "<",
    ">",
)


def shannon_entropy(value: str) -> float:
    """Compute Shannon entropy (bits per character) of a string."""
    if not value:
        return 0.0
    length = len(value)
    counts: Dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    for count in counts.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return round(entropy, 3)


def redact_secret(value: str, visible_prefix: int = 4, visible_suffix: int = 4) -> str:
    """Safely redact a secret value without leaking its middle characters."""
    if not value:
        return ""
    if len(value) <= visible_prefix + visible_suffix + 2:
        return "*" * len(value)
    return f"{value[:visible_prefix]}****{value[-visible_suffix:]}"


def is_placeholder(value: str) -> bool:
    """Return True if value looks like an intentional template placeholder."""
    lowered = value.strip().lower()
    if not lowered:
        return True
    return any(hint in lowered for hint in PLACEHOLDER_HINTS)


def detect_secret(
    key: str,
    value: str,
    entropy_threshold: float = 4.2,
    min_length: int = 20,
) -> Optional[Dict[str, object]]:
    """Inspect a key/value pair for known secret patterns or high entropy."""
    if not value:
        return None

    for pattern_name, regex in SECRET_PATTERNS:
        if regex.search(value):
            return {
                "key": key,
                "reason": f"pattern:{pattern_name}",
                "entropy": shannon_entropy(value),
                "redacted": redact_secret(value),
            }

    if len(value) >= min_length and not is_placeholder(value):
        ent = shannon_entropy(value)
        if ent >= entropy_threshold:
            return {
                "key": key,
                "reason": "high_entropy",
                "entropy": ent,
                "redacted": redact_secret(value),
            }

    return None
