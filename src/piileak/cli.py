"""Command line entry point. Exit codes: 0 pass, 1 PII gate failed, 2 error."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from .detector import PiiDetector
from .models import Severity
from .normalize import SpecError, load_spec
from .prober import UnsafeTargetError
from .report import render_json, render_sarif, render_text
from .scanner import gate_failures, scan
from .suppressions import DEFAULT_IGNORE_FILE, SuppressionError, load_suppressions


def _pairs(items: list[str] | None, sep: str, flag: str, example: str) -> dict[str, str]:
    """Parse repeated 'name<sep>value' options. Bad input is an input error (exit 2), never exit 1,
    because exit 1 is reserved for 'the PII gate failed'."""
    out: dict[str, str] = {}
    for item in items or []:
        name, found, value = item.partition(sep)
        if not found or not name.strip():
            raise SpecError(f"bad {flag} {item!r}, expected {example!r}")
        out[name.strip()] = value.strip()
    return out


def _headers(items: list[str] | None) -> dict[str, str]:
    return _pairs(items, ":", "--header", "Name: value")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="piileak", description="Catch PII leaks introduced by API version migrations")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="diff two specs, probe the new API, scan responses for PII")
    s.add_argument("--old", required=True, help="old spec (Swagger 2.0 / OpenAPI 3.x, json or yaml)")
    s.add_argument("--new", required=True, help="new spec")
    s.add_argument(
        "--base-url", help="host of the NEW API, e.g. https://staging.example.com (not needed with --no-probe)"
    )
    s.add_argument("--no-probe", action="store_true", help="spec-only mode: never call the API, check field names only")
    s.add_argument(
        "--param", action="append", help="value for a path/query/header parameter, repeatable: --param username=user1"
    )
    s.add_argument(
        "--strip-prefix", action="append", help="drop a leading base path before matching endpoints, e.g. /api"
    )
    s.add_argument("--header", "-H", action="append", help="extra header, repeatable: -H 'Authorization: Bearer x'")
    s.add_argument("--fail-on", choices=[x.value for x in Severity], default="medium")
    s.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    s.add_argument("--output", help="write the chosen --format to this file (the text report is still printed)")
    s.add_argument("--ignore-file", help=f"accepted-risk suppressions (default: ./{DEFAULT_IGNORE_FILE} if present)")
    s.add_argument("--probe-all", action="store_true", help="probe unchanged endpoints too (finds undocumented leaks)")
    s.add_argument("--no-static", action="store_true", help="disable field-name heuristics")
    s.add_argument("--allow-unsafe", action="store_true", help="also probe POST/PUT/PATCH/DELETE (staging only!)")
    s.add_argument("--allow-private", action="store_true", help="allow probing localhost/private IPs (default: refuse)")
    s.add_argument("--max-retries", type=int, default=2, help="retries for 429/5xx/connection errors")
    s.add_argument("--max-requests", type=int, default=500, help="hard cap on total HTTP requests")
    s.add_argument("--keep-version-prefix", action="store_true", help="do not strip /v1 /v2 when matching endpoints")
    s.add_argument("--include-person", action="store_true", help="also report PERSON names (noisy)")
    s.add_argument("--min-score", type=float, default=0.5)
    s.add_argument("--concurrency", type=int, default=10)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if not args.no_probe and not args.base_url:
            raise SpecError("--base-url is required unless --no-probe is used")
        old, new = load_spec(args.old), load_spec(args.new)
        ignore_path = args.ignore_file or (DEFAULT_IGNORE_FILE if Path(DEFAULT_IGNORE_FILE).is_file() else None)
        suppressions = load_suppressions(ignore_path) if ignore_path else []
        detector = PiiDetector(min_score=args.min_score, include_person=args.include_person)
        result = asyncio.run(
            scan(
                old,
                new,
                args.base_url or "",
                detector,
                headers=_headers(args.header),
                probe=not args.no_probe,
                param_overrides=_pairs(args.param, "=", "--param", "name=value"),
                strip_prefixes=args.strip_prefix or [],
                probe_all=args.probe_all,
                static=not args.no_static,
                allow_unsafe=args.allow_unsafe,
                allow_private=args.allow_private,
                max_retries=args.max_retries,
                max_requests=args.max_requests,
                concurrency=args.concurrency,
                strip_version=not args.keep_version_prefix,
                suppressions=suppressions,
            )
        )
    except (SpecError, UnsafeTargetError, SuppressionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    fail_on = Severity(args.fail_on)
    text = render_text(result, fail_on)
    if args.format == "json":
        body = render_json(result, fail_on)
    elif args.format == "sarif":
        body = render_sarif(result, spec_uri=Path(args.new).as_posix())
    else:
        body = text
    if args.output:
        Path(args.output).write_text(body, encoding="utf-8")
        print(text)
    else:
        print(body)
    return 1 if gate_failures(result, fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
