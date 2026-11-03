"""Orchestrates: normalise -> diff -> (static name check) -> probe -> detect."""

from __future__ import annotations

from .detector import ENTITY_SEVERITY, PiiDetector, canonical_field, name_hint, walk_leaves
from .diff import diff_specs
from .models import Finding, NormalizedSpec, ScanResult, Severity
from .normalize import normalize
from .prober import Prober


def _add(store: dict, f: Finding) -> None:
    """De-duplicate by (endpoint, field, entity); prefer live evidence over name hints."""
    key = (f.endpoint, f.field, f.entity)
    cur = store.get(key)
    if (
        cur is None
        or (cur.source == "spec" and f.source == "response")
        or (cur.source == f.source and f.score > cur.score)
    ):
        store[key] = f


async def scan(
    old_raw: dict,
    new_raw: dict,
    base_url: str,
    detector: PiiDetector,
    *,
    headers: dict | None = None,
    probe_all: bool = False,
    static: bool = True,
    allow_unsafe: bool = False,
    concurrency: int = 10,
    strip_version: bool = True,
    transport=None,
) -> ScanResult:
    old: NormalizedSpec = normalize(old_raw, strip_version)
    new: NormalizedSpec = normalize(new_raw, strip_version)
    diffs = diff_specs(old, new, include_unchanged=probe_all)
    diff_by_key = {d.key: d for d in diffs}
    store: dict = {}

    # 1) static: newly documented fields whose NAME looks sensitive
    if static:
        for d in diffs:
            for fld in d.added_fields:
                ent = name_hint(fld)
                if ent:
                    _add(
                        store,
                        Finding(
                            endpoint=d.key,
                            field=fld,
                            entity=ent,
                            severity=ENTITY_SEVERITY.get(ent, Severity.MEDIUM),
                            source="spec",
                            score=0.5,
                            is_new_field=True,
                        ),
                    )

    # 2) dynamic: probe the new API and scan real response values
    prober = Prober(base_url, headers, concurrency, allow_unsafe=allow_unsafe, transport=transport)
    probes = await prober.probe_all([d.endpoint for d in diffs])

    for pr in probes:
        if pr.status != "ok":
            continue
        d = diff_by_key[pr.endpoint]
        old_ep = old.endpoints.get(pr.endpoint)
        old_fields = set(old_ep.response_fields) if old_ep else set()
        for raw_path, value in walk_leaves(pr.body):
            field = canonical_field(raw_path)
            is_new = d.is_new_endpoint or field not in old_fields  # undocumented fields count as new
            hit = False
            for ent, score, sample in detector.scan_value(value):
                hit = True
                _add(
                    store,
                    Finding(
                        endpoint=pr.endpoint,
                        field=field,
                        entity=ent,
                        severity=ENTITY_SEVERITY.get(ent, Severity.MEDIUM),
                        source="response",
                        score=round(score, 2),
                        sample=sample,
                        is_new_field=is_new,
                    ),
                )
            if static and not hit and is_new:  # name looks sensitive, value did not match a pattern
                ent = name_hint(field)
                if ent:
                    _add(
                        store,
                        Finding(
                            endpoint=pr.endpoint,
                            field=field,
                            entity=ent,
                            severity=ENTITY_SEVERITY.get(ent, Severity.MEDIUM),
                            source="spec",
                            score=0.5,
                            is_new_field=True,
                        ),
                    )

    # a name-only hint is redundant once live evidence exists for the same field
    live = {(f.endpoint, f.field) for f in store.values() if f.source == "response"}
    kept = [f for f in store.values() if f.source == "response" or (f.endpoint, f.field) not in live]
    findings = sorted(kept, key=lambda f: (-f.severity.rank, f.endpoint, f.field))
    return ScanResult(diffs=diffs, probes=probes, findings=findings)


def gate_failures(result: ScanResult, fail_on: Severity) -> list[Finding]:
    """Only findings introduced by this migration, at or above the threshold, fail the build."""
    return [f for f in result.findings if f.is_new_field and f.severity.rank >= fail_on.rank]
