"""Async endpoint prober.

Safe by default: read-only (GET) unless allow_unsafe is set, redirects are never followed,
private/loopback/link-local targets are refused unless allow_private is set (SSRF guard),
and the number of HTTP requests is capped. Transient failures are retried with backoff.
"""

from __future__ import annotations

import asyncio
import ipaddress
import random
import re
import socket
from collections.abc import Awaitable, Callable, Iterable
from typing import Any
from urllib.parse import urlparse

import httpx

from .models import Endpoint, ProbeResult

SAFE_METHODS = {"GET"}
RETRY_STATUSES = {429, 502, 503, 504}
_PLACEHOLDER = re.compile(r"\{([^}]+)\}")
_DEFAULTS = {"integer": "1", "number": "1", "boolean": "true", "string": "1"}

Resolver = Callable[[str, int], Awaitable[list[str]]]
Sleeper = Callable[[float], Awaitable[None]]


class UnsafeTargetError(ValueError):
    """The base URL is not allowed (bad scheme, unresolvable, or a non-public address)."""


# --------------------------------------------------------------------------- SSRF guard
async def _default_resolver(host: str, port: int) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]) for info in infos})


def _is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped  # ::ffff:127.0.0.1 must not sneak past the IPv4 checks
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local  # includes the 169.254.169.254 cloud metadata address
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


async def ensure_public_target(base_url: str, resolver: Resolver | None = None) -> None:
    """Raise UnsafeTargetError unless every address the host resolves to is public.

    WHY: when PIILeak runs as a service, a caller-supplied URL could otherwise be used
    to reach internal systems (SSRF). Known limit: DNS can change between this check
    and the request (rebinding), so also restrict egress at the network level.
    """
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise UnsafeTargetError(f"base URL must be http(s) with a host, got {base_url!r}")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        addresses = await (resolver or _default_resolver)(parsed.hostname, port)
    except OSError as exc:
        raise UnsafeTargetError(f"cannot resolve host {parsed.hostname!r}: {exc}") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address.split("%")[0])
        if _is_blocked(ip):
            raise UnsafeTargetError(
                f"{parsed.hostname} resolves to non-public address {ip}; pass --allow-private to probe it anyway"
            )


# --------------------------------------------------------------------------- URL building
def build_url_parts(ep: Endpoint) -> tuple[str, dict[str, str], dict[str, str]]:
    """Fill path params, required query params and required headers with examples."""
    by_name = {p.name: p for p in ep.params if p.location == "path"}

    def fill(m: re.Match[str]) -> str:
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


def _retry_delay(attempt: int, retry_after: str | None, base: float, cap: float) -> float:
    """Honour Retry-After (seconds form) if present, else exponential backoff with jitter."""
    if retry_after is not None:
        try:
            return min(float(retry_after), cap)
        except ValueError:
            pass  # HTTP-date form: fall back to backoff
    return min(cap, base * 2**attempt) * random.uniform(0.5, 1.0)  # noqa: S311


# --------------------------------------------------------------------------- prober
class Prober:
    def __init__(
        self,
        base_url: str,
        headers: dict[str, str] | None = None,
        concurrency: int = 10,
        timeout: float = 10.0,
        allow_unsafe: bool = False,
        transport: Any = None,
        *,
        allow_private: bool = False,
        max_retries: int = 2,
        backoff: float = 0.5,
        max_backoff: float = 30.0,
        max_requests: int = 500,
        max_response_bytes: int = 5_000_000,
        sleep: Sleeper = asyncio.sleep,
        resolver: Resolver | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers = headers or {}
        self.timeout = timeout
        self.allow_unsafe = allow_unsafe
        self.transport = transport  # tests inject httpx.MockTransport / ASGITransport
        self.allow_private = allow_private
        self.max_retries = max(0, max_retries)
        self.backoff = backoff
        self.max_backoff = max_backoff
        self.max_requests = max_requests
        self.max_response_bytes = max_response_bytes
        self._sleep = sleep
        self._resolver = resolver
        self._sem = asyncio.Semaphore(concurrency)
        self._requests = 0

    async def _send(
        self, client: httpx.AsyncClient, ep: Endpoint, path: str, query: dict[str, str], extra: dict[str, str]
    ) -> tuple[httpx.Response | None, str]:
        """One logical request with retries. Returns (response, error_detail)."""
        for attempt in range(self.max_retries + 1):
            if self._requests >= self.max_requests:
                return None, "request cap reached"
            self._requests += 1
            last_try = attempt == self.max_retries
            try:
                resp = await client.request(ep.method, path, params=query, headers=extra)
            except httpx.TransportError as exc:  # connect errors, timeouts, resets
                if last_try:
                    return None, type(exc).__name__  # no str(exc): it can echo URLs/secrets
                await self._sleep(_retry_delay(attempt, None, self.backoff, self.max_backoff))
                continue
            if resp.status_code in RETRY_STATUSES and not last_try:
                delay = _retry_delay(attempt, resp.headers.get("Retry-After"), self.backoff, self.max_backoff)
                await self._sleep(delay)
                continue
            return resp, ""
        return None, "retries exhausted"  # pragma: no cover

    async def _probe_one(self, client: httpx.AsyncClient, ep: Endpoint) -> ProbeResult:
        if ep.method not in SAFE_METHODS and not self.allow_unsafe:
            return ProbeResult(
                endpoint=ep.key,
                status="skipped",
                detail=f"{ep.method} is not read-only (use --allow-unsafe to probe)",
            )
        path, query, extra = build_url_parts(ep)
        async with self._sem:
            resp, error = await self._send(client, ep, path, query, extra)
        if resp is None:
            return ProbeResult(endpoint=ep.key, status="error", url=f"{self.base_url}{path}", detail=error)

        url = str(resp.request.url)
        code = resp.status_code
        if 300 <= code < 400:
            return ProbeResult(
                endpoint=ep.key, url=url, status="error", http_status=code, detail="redirect not followed"
            )
        if code >= 400:
            return ProbeResult(endpoint=ep.key, url=url, status="error", http_status=code, detail=f"HTTP {code}")
        if len(resp.content) > self.max_response_bytes:
            return ProbeResult(
                endpoint=ep.key, url=url, status="error", http_status=code, detail="response too large to scan"
            )
        try:
            body = resp.json()
        except ValueError:
            return ProbeResult(
                endpoint=ep.key, url=url, status="error", http_status=code, detail="response was not JSON"
            )
        return ProbeResult(endpoint=ep.key, url=url, status="ok", http_status=code, body=body)

    async def probe_all(self, endpoints: Iterable[Endpoint]) -> list[ProbeResult]:
        if self.transport is None and not self.allow_private:
            await ensure_public_target(self.base_url, self._resolver)
        async with httpx.AsyncClient(
            base_url=self.base_url,
            headers=self.headers,
            timeout=self.timeout,
            transport=self.transport,
            follow_redirects=False,  # a redirect could point at an internal address
        ) as client:
            return list(await asyncio.gather(*(self._probe_one(client, ep) for ep in endpoints)))
