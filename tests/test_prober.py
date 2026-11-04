"""Prober hardening: retries, Retry-After, request cap, redirects, SSRF guard."""

import httpx
import pytest

from piileak.models import Endpoint
from piileak.prober import Prober, UnsafeTargetError, ensure_public_target


def ep(path: str = "/x", method: str = "GET") -> Endpoint:
    return Endpoint(method=method, key_path=path, full_path=path)


class Recorder:
    """Fake sleep that records delays instead of waiting."""

    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)


def make_prober(handler, sleep=None, **kw) -> Prober:
    return Prober("http://test", transport=httpx.MockTransport(handler), sleep=sleep or Recorder(), **kw)


async def test_retries_503_then_succeeds():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(503) if len(calls) < 3 else httpx.Response(200, json={"ok": True})

    sleep = Recorder()
    [res] = await make_prober(handler, sleep).probe_all([ep()])
    assert res.status == "ok" and len(calls) == 3
    assert 0.25 <= sleep.delays[0] <= 0.5  # base 0.5 with jitter
    assert 0.5 <= sleep.delays[1] <= 1.0  # doubles


async def test_retry_after_header_is_honoured_and_capped():
    codes = iter([429, 429, 200])

    def handler(request):
        code = next(codes)
        headers = {"Retry-After": "7"} if code == 429 and len(sleep.delays) == 0 else {"Retry-After": "999"}
        return httpx.Response(code, headers=headers if code == 429 else {}, json={})

    sleep = Recorder()
    [res] = await make_prober(handler, sleep).probe_all([ep()])
    assert res.status == "ok"
    assert sleep.delays == [7.0, 30.0]  # second one capped at max_backoff


async def test_gives_up_after_max_retries():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(503)

    [res] = await make_prober(handler, max_retries=2).probe_all([ep()])
    assert res.status == "error" and res.detail == "HTTP 503" and len(calls) == 3


async def test_connection_error_is_retried_then_reported_without_details():
    calls = []

    def handler(request):
        calls.append(1)
        if len(calls) == 1:
            raise httpx.ConnectError("secret-host.internal refused")
        return httpx.Response(200, json={})

    [res] = await make_prober(handler).probe_all([ep()])
    assert res.status == "ok" and len(calls) == 2

    def always_down(request):
        raise httpx.ConnectError("secret-host.internal refused")

    [res] = await make_prober(always_down, max_retries=1).probe_all([ep()])
    assert res.status == "error" and res.detail == "ConnectError"
    assert "secret-host" not in res.detail


async def test_4xx_is_not_retried():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(404)

    [res] = await make_prober(handler).probe_all([ep()])
    assert res.status == "error" and len(calls) == 1


async def test_request_cap():
    def handler(request):
        return httpx.Response(200, json={})

    results = await make_prober(handler, max_requests=2).probe_all([ep("/a"), ep("/b"), ep("/c")])
    assert sorted(r.status for r in results) == ["error", "ok", "ok"]
    assert any(r.detail == "request cap reached" for r in results)


async def test_redirects_are_not_followed():
    def handler(request):
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data"})

    [res] = await make_prober(handler).probe_all([ep()])
    assert res.status == "error" and res.detail == "redirect not followed"


async def test_non_json_and_unsafe_method():
    def handler(request):
        return httpx.Response(200, text="<html>")

    results = await make_prober(handler).probe_all([ep("/a"), ep("/b", "POST")])
    by_status = {r.endpoint: r for r in results}
    assert by_status["GET /a"].detail == "response was not JSON"
    assert by_status["POST /b"].status == "skipped"


# ------------------------------------------------------------------ SSRF guard
def resolver_returning(*addrs: str):
    async def resolve(host: str, port: int) -> list[str]:
        return list(addrs)

    return resolve


@pytest.mark.parametrize(
    "addr",
    ["127.0.0.1", "10.0.0.5", "192.168.1.10", "172.16.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "0.0.0.0"],
)
async def test_non_public_addresses_are_refused(addr):
    with pytest.raises(UnsafeTargetError, match="non-public"):
        await ensure_public_target("https://api.example.com", resolver_returning(addr))


async def test_public_address_is_allowed():
    await ensure_public_target("https://api.example.com", resolver_returning("93.184.216.34"))


async def test_any_private_address_among_several_blocks():
    with pytest.raises(UnsafeTargetError):
        await ensure_public_target("https://x.example.com", resolver_returning("93.184.216.34", "10.1.1.1"))


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com", "http://", "example.com"])
async def test_bad_schemes_and_hosts_are_refused(url):
    with pytest.raises(UnsafeTargetError):
        await ensure_public_target(url, resolver_returning("93.184.216.34"))


async def test_unresolvable_host_is_refused():
    async def fail(host: str, port: int) -> list[str]:
        raise OSError("no such host")

    with pytest.raises(UnsafeTargetError, match="cannot resolve"):
        await ensure_public_target("https://nope.invalid", fail)


async def test_probe_all_blocks_private_target_before_any_request():
    prober = Prober("http://localhost:8000", resolver=resolver_returning("127.0.0.1"))
    with pytest.raises(UnsafeTargetError):
        await prober.probe_all([ep()])


async def test_allow_private_skips_the_guard():
    def never(host: str, port: int):
        raise AssertionError("resolver must not be called")

    prober = Prober(
        "http://localhost:8000",
        allow_private=True,
        resolver=never,
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})),
    )
    [res] = await prober.probe_all([ep()])
    assert res.status == "ok"
