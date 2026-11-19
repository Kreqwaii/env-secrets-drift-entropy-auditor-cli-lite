"""Cross-environment drift analysis, unsafe prod flag checks, and reporting."""

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .entropy import detect_secret
from .parser import parse_env_file

UNSAFE_PROD_RULES: Dict[str, Tuple[str, ...]] = {
    "DEBUG": ("true", "1", "yes", "on"),
    "NODE_ENV": ("development", "dev", "local"),
    "ALLOW_ALL_CORS": ("true", "1", "yes"),
    "SSL_VERIFY": ("false", "0", "no"),
    "LOG_LEVEL": ("debug", "trace"),
}


def audit_environments(
    env_paths: Dict[str, Path],
    entropy_threshold: float = 4.2,
    min_secret_len: int = 20,
) -> Dict[str, object]:
    """Audit multiple named .env files and return structured findings + exit code."""
    parsed: Dict[str, Dict[str, str]] = {}
    parse_warnings: Dict[str, List[str]] = {}
    all_keys = set()

    for env_name, path in env_paths.items():
        data, warns = parse_env_file(path)
        parsed[env_name] = data
        if warns:
            parse_warnings[env_name] = warns
        all_keys.update(data.keys())

    sorted_keys = sorted(all_keys)
    env_names = list(env_paths.keys())

    missing_keys: Dict[str, List[str]] = {}
    empty_keys: Dict[str, List[str]] = {}
    unsafe_prod_flags: List[Dict[str, str]] = []
    secret_leaks: List[Dict[str, object]] = []

    for env_name in env_names:
        env_data = parsed[env_name]
        missing = [k for k in sorted_keys if k not in env_data]
        if missing:
            missing_keys[env_name] = missing

        empties = [k for k, v in env_data.items() if v == ""]
        if empties:
            empty_keys[env_name] = sorted(empties)

        is_prod = "prod" in env_name.lower()
        for key, val in env_data.items():
            if is_prod and key in UNSAFE_PROD_RULES:
                if val.strip().lower() in UNSAFE_PROD_RULES[key]:
                    unsafe_prod_flags.append(
                        {"env": env_name, "key": key, "value": val}
                    )

            leak = detect_secret(
                key,
                val,
                entropy_threshold=entropy_threshold,
                min_length=min_secret_len,
            )
            if leak:
                leak_entry = dict(leak)
                leak_entry["env"] = env_name
                secret_leaks.append(leak_entry)

    has_drift = bool(missing_keys or empty_keys or unsafe_prod_flags or parse_warnings)
    if secret_leaks:
        exit_code = 2
        status = "SECRET_LEAKS_DETECTED"
    elif has_drift:
        exit_code = 1
        status = "DRIFT_WARNINGS"
    else:
        exit_code = 0
        status = "CLEAN"

    return {
        "status": status,
        "exit_code": exit_code,
        "environments": env_names,
        "total_unique_keys": len(sorted_keys),
        "missing_keys": missing_keys,
        "empty_keys": empty_keys,
        "unsafe_prod_flags": unsafe_prod_flags,
        "secret_leaks": secret_leaks,
        "parse_warnings": parse_warnings,
    }


def generate_env_example(env_paths: Dict[str, Path]) -> str:
    """Generate a safe .env.example template from one or more .env files."""
    keys = set()
    for path in env_paths.values():
        data, _ = parse_env_file(path)
        keys.update(data.keys())

    lines = [
        "# Auto-generated safe .env.example template",
        "# Replace placeholders with environment-specific values.",
        "",
    ]
    for key in sorted(keys):
        lines.append(f"{key}=<CHANGE_ME>")
    return "\n".join(lines) + "\n"


def format_json_report(report: Dict[str, object]) -> str:
    """Serialize audit report as deterministic pretty JSON."""
    return json.dumps(report, indent=2, sort_keys=False)


def format_markdown_report(report: Dict[str, object]) -> str:
    """Render audit report as clean Markdown for PR comments or terminal."""
    lines: List[str] = [
        f"# Env Drift & Secrets Audit: `{report['status']}`",
        "",
        f"- **Exit Code**: `{report['exit_code']}`",
        f"- **Environments**: {', '.join(report['environments'])}",
        f"- **Total Unique Keys**: {report['total_unique_keys']}",
        "",
    ]

    leaks = report["secret_leaks"]
    lines.append(f"## Secret & High-Entropy Findings ({len(leaks)})")
    if leaks:
        lines.append("| Env | Key | Reason | Entropy | Redacted |")
        lines.append("| --- | --- | --- | --- | --- |")
        for item in leaks:
            lines.append(
                f"| {item['env']} | `{item['key']}` | `{item['reason']}` | {item['entropy']} | `{item['redacted']}` |"
            )
    else:
        lines.append("No secret leaks detected.")
    lines.append("")

    missing = report["missing_keys"]
    lines.append("## Missing Keys by Environment")
    if missing:
        for env_name, keys in missing.items():
            lines.append(f"- **{env_name}**: {', '.join(f'`{k}`' for k in keys)}")
    else:
        lines.append("No missing keys across environments.")
    lines.append("")

    unsafe = report["unsafe_prod_flags"]
    lines.append("## Unsafe Production Flags")
    if unsafe:
        for flag in unsafe:
            lines.append(
                f"- **{flag['env']}**: `{flag['key']}={flag['value']}`"
            )
    else:
        lines.append("No unsafe production flags detected.")
    lines.append("")

    return "\n".join(lines)
