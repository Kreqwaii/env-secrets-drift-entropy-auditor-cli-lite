"""Strict, dependency-free .env file parser."""

from pathlib import Path
import re
from typing import Dict, List, Tuple

_KEY_RE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def strip_inline_comment(raw_val: str) -> str:
    """Strip unquoted inline comments from a .env value."""
    in_single = False
    in_double = False
    escaped = False
    for idx, ch in enumerate(raw_val):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_double:
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if idx == 0 or raw_val[idx - 1].isspace():
                return raw_val[:idx].rstrip()
    return raw_val.strip()


def unquote_value(val: str) -> str:
    """Remove surrounding single or double quotes and unescape basic sequences."""
    val = val.strip()
    if len(val) >= 2:
        if (val[0] == '"' and val[-1] == '"') or (val[0] == "'" and val[-1] == "'"):
            inner = val[1:-1]
            if val[0] == '"':
                inner = (
                    inner.replace(r"\n", "\n")
                    .replace(r"\r", "\r")
                    .replace(r"\t", "\t")
                    .replace(r'\"', '"')
                    .replace(r"\\", "\\")
                )
            return inner
    return val


def parse_env_text(text: str) -> Tuple[Dict[str, str], List[str]]:
    """Parse .env text into (ordered_dict, warnings)."""
    result: Dict[str, str] = {}
    warnings: List[str] = []

    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _KEY_RE.match(line)
        if not match:
            warnings.append(f"Line {lineno}: malformed entry ignored")
            continue
        key, raw_val = match.group(1), match.group(2)
        cleaned = strip_inline_comment(raw_val)
        value = unquote_value(cleaned)
        if key in result:
            warnings.append(f"Line {lineno}: duplicate key '{key}' overwritten")
        result[key] = value

    return result, warnings


def parse_env_file(path: Path) -> Tuple[Dict[str, str], List[str]]:
    """Read and parse a .env file from disk."""
    content = path.read_text(encoding="utf-8")
    return parse_env_text(content)
