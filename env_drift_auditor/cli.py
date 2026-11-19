"""Command-line interface for env-secrets-drift-entropy-auditor-cli-lite."""

import argparse
from pathlib import Path
import sys
from typing import Dict, List, Optional

from .auditor import (
    audit_environments,
    format_json_report,
    format_markdown_report,
    generate_env_example,
)


def parse_env_specs(specs: List[str]) -> Dict[str, Path]:
    """Parse `name=path` or plain `path` arguments into {env_name: Path}."""
    mapping: Dict[str, Path] = {}
    for spec in specs:
        if "=" in spec:
            name, raw_path = spec.split("=", 1)
            mapping[name.strip()] = Path(raw_path.strip())
        else:
            p = Path(spec.strip())
            mapping[p.name] = p
    return mapping


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="env-drift-auditor",
        description="Zero-dependency .env secrets, entropy, and cross-environment drift auditor.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit_p = subparsers.add_parser("audit", help="Audit one or more .env files")
    audit_p.add_argument(
        "envs",
        nargs="+",
        help="Environment specs as name=path (e.g. dev=.env.dev prod=.env.prod) or path",
    )
    audit_p.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="Output format (default: markdown)",
    )
    audit_p.add_argument(
        "--entropy-threshold",
        type=float,
        default=4.2,
        help="Shannon entropy threshold for generic secret detection (default: 4.2)",
    )
    audit_p.add_argument(
        "--min-secret-len",
        type=int,
        default=20,
        help="Minimum value length for entropy-based detection (default: 20)",
    )
    audit_p.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional file path to write the report",
    )

    tpl_p = subparsers.add_parser(
        "template", help="Generate a safe .env.example template"
    )
    tpl_p.add_argument("envs", nargs="+", help="Input .env file paths or name=path")
    tpl_p.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional output path (prints to stdout if omitted)",
    )

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    env_map = parse_env_specs(args.envs)
    for name, path in env_map.items():
        if not path.exists():
            print(f"Error: environment file not found for '{name}': {path}", file=sys.stderr)
            return 2

    if args.command == "template":
        content = generate_env_example(env_map)
        if args.output:
            args.output.write_text(content, encoding="utf-8")
        else:
            print(content, end="")
        return 0

    report = audit_environments(
        env_map,
        entropy_threshold=args.entropy_threshold,
        min_secret_len=args.min_secret_len,
    )
    rendered = (
        format_json_report(report)
        if args.format == "json"
        else format_markdown_report(report)
    )

    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered)

    return int(report["exit_code"])
