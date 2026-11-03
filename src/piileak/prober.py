"""Async endpoint prober. Read-only by default: only GET is sent unless
allow_unsafe is set. Use against staging/test environments."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Iterable
from typing import Any

import httpx

from .models import Endpoint, ProbeResult

SAFE_METHODS = {"GET"}
_PLACEHOLDER = re.compile(r"\{([^}]+)\}")
_DEFAULTS = {"integer": "1", "number": "1", "boolean": "true", "string": "1"}


def build_url_parts(ep: Endpoint) -> tuple[str, dict[str, str], dict[str, str]]:
    """Fill path params, required query params and required headers with examples."""
    by_name = {p.name: p for p in ep.params if p.location == "path"}

    def fill(m: re.Match) -> str:
        p = by_name.get(m.group(1))
        if p is None:
            return "1"
        return str(p.example if p.example is not None else _DEFAULTS.get(p.type, "1"))

    path = _PLACEHOLDER.sub(fill, ep.full_path)
    query = {
        p.name: str(p.example if p.example is not None else _DEFAULTS.get(p.type, "1"))
        for p in ep.params
        if p.location == "query" and p.required
    }
    headers = {
        p.name: str(p.example if p.example is not None else _DEFAULTS.get(p.type, "1"))
        for p in ep.params
        if p.location == "header" and p.required
    }
    return path, query, headers


class Prober:
    def __init__(
        self,
        base_url: str,
        headers: dict[str, str] | None = None,
        concurrency: int = 10,
        timeout: float = 10.0,
        allow_unsafe: bool = False,
        transport: Any = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.headers = headers or {}
        self.timeout = timeout
        self.allow_unsafe = allow_unsafe
        self.transport = transport  # inject httpx.ASGITransport in tests
        self._sem = asyncio.Semaphore(concurrency)

    async def _probe_one(self, client: httpx.AsyncClient, ep: Endpoint) -> ProbeResult:
        if ep.method not in SAFE_METHODS and not self.allow_unsafe:
            return ProbeResult(
                endpoint=ep.key, status="skipped", detail=f"{ep.method} is not read-only (use --allow-unsafe to probe)"
            )
        path, query, extra = build_url_parts(ep)
        async with self._sem:
            try:
                resp = await client.request(ep.method, path, params=query, headers=extra)
            except httpx.HTTPError as exc:
                return ProbeResult(
                    endpoint=ep.key, status="error", url=f"{self.base_url}{path}", detail=f"{type(exc).__name__}: {exc}"
                )
        url = str(resp.request.url)
        try:
            body = resp.json()
        except ValueError:
            return ProbeResult(
                endpoint=ep.key, url=url, status="error", http_status=resp.status_code, detail="response was not JSON"
            )
        if resp.status_code >= 400:
            return ProbeResult(
                endpoint=ep.key,
                url=url,
                status="error",
                http_status=resp.status_code,
                detail=f"HTTP {resp.status_code}",
            )
        return ProbeResult(endpoint=ep.key, url=url, status="ok", http_status=resp.status_code, body=body)

    async def probe_all(self, endpoints: Iterable[Endpoint]) -> list[ProbeResult]:
        async with httpx.AsyncClient(
            base_url=self.base_url, headers=self.headers, timeout=self.timeout, transport=self.transport
        ) as client:
            return await asyncio.gather(*(self._probe_one(client, ep) for ep in endpoints))
