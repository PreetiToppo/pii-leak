"""Find what changed between two NormalizedSpecs (the endpoints worth probing)."""

from __future__ import annotations

from .models import EndpointDiff, NormalizedSpec


def diff_specs(old: NormalizedSpec, new: NormalizedSpec, include_unchanged: bool = False) -> list[EndpointDiff]:
    diffs: list[EndpointDiff] = []
    for key, ep in new.endpoints.items():
        prev = old.endpoints.get(key)
        if prev is None:
            diffs.append(
                EndpointDiff(key=key, endpoint=ep, is_new_endpoint=True, added_fields=sorted(ep.response_fields))
            )
            continue
        added = sorted(set(ep.response_fields) - set(prev.response_fields))
        type_changed = sorted(
            f
            for f in set(ep.response_fields) & set(prev.response_fields)
            if ep.response_fields[f] != prev.response_fields[f]
        )
        if added or type_changed or include_unchanged:
            diffs.append(
                EndpointDiff(
                    key=key, endpoint=ep, is_new_endpoint=False, added_fields=added, type_changed_fields=type_changed
                )
            )
    return diffs
