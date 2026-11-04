"""Command line entry point. Exit codes: 0 pass, 1 PII gate failed, 2 error."""

from __future__ import annotations

import argparse
import asyncio
import sys

from .detector import PiiDetector
from .models import Severity
from .normalize import SpecError, load_spec
from .prober import UnsafeTargetError
from .report import render_json, render_text
from .scanner import gate_failures, scan


def _headers(items: list[str]) -> dict[str, str]:
    out = {}
    for item in items or []:
        if ":" not in item:
            raise SystemExit(f"Bad --header {item!r}, expected 'Name: value'")
        k, v = item.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="piileak", description="Catch PII leaks introduced by API version migrations")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="diff two specs, probe the new API, scan responses for PII")
    s.add_argument("--old", required=True, help="old spec (Swagger 2.0 / OpenAPI 3.x, json or yaml)")
    s.add_argument("--new", required=True, help="new spec")
    s.add_argument("--base-url", required=True, help="host of the NEW API, e.g. https://staging.example.com")
    s.add_argument("--header", "-H", action="append", help="extra header, repeatable: -H 'Authorization: Bearer x'")
    s.add_argument("--fail-on", choices=[x.value for x in Severity], default="medium")
    s.add_argument("--format", choices=["text", "json"], default="text")
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
        old, new = load_spec(args.old), load_spec(args.new)
        detector = PiiDetector(min_score=args.min_score, include_person=args.include_person)
        result = asyncio.run(
            scan(
                old,
                new,
                args.base_url,
                detector,
                headers=_headers(args.header),
                probe_all=args.probe_all,
                static=not args.no_static,
                allow_unsafe=args.allow_unsafe,
                allow_private=args.allow_private,
                max_retries=args.max_retries,
                max_requests=args.max_requests,
                concurrency=args.concurrency,
                strip_version=not args.keep_version_prefix,
            )
        )
    except (SpecError, UnsafeTargetError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    fail_on = Severity(args.fail_on)
    print(render_json(result, fail_on) if args.format == "json" else render_text(result, fail_on))
    return 1 if gate_failures(result, fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
