"""FastAPI wrapper: health, host allowlist, input validation, SSRF refusal."""

import json
from pathlib import Path

import httpx
import pytest

from piileak import server
from piileak.models import ScanResult

SPECS = Path(__file__).parent.parent / "examples" / "specs"
OLD = json.loads((SPECS / "v1_swagger2.json").read_text())
NEW = json.loads((SPECS / "v2_openapi3.json").read_text())


@pytest.fixture
def client(detector, monkeypatch):
    monkeypatch.setattr(server, "_detector", detector)  # reuse the loaded model
    monkeypatch.delenv("PIILEAK_ALLOWED_HOSTS", raising=False)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=server.app), base_url="http://svc")


def payload(**kw):
    return {"old_spec": OLD, "new_spec": NEW, "base_url": "https://api.example.com", **kw}


async def test_health(client):
    async with client as c:
        assert (await c.get("/health")).json() == {"status": "ok"}


async def test_private_target_is_refused_with_400(client):
    async with client as c:
        r = await c.post("/scan", json=payload(base_url="http://127.0.0.1:9"))
    assert r.status_code == 400 and "non-public" in r.json()["detail"]


async def test_host_allowlist_blocks_other_hosts(client, monkeypatch):
    monkeypatch.setenv("PIILEAK_ALLOWED_HOSTS", "staging.example.com")
    async with client as c:
        r = await c.post("/scan", json=payload())
    assert r.status_code == 403


async def test_invalid_spec_returns_422(client):
    async with client as c:
        r = await c.post("/scan", json=payload(old_spec={"nope": 1}))
    assert r.status_code == 422


async def test_successful_scan_returns_gate_info(client, monkeypatch):
    async def fake_scan(*args, **kwargs):
        return ScanResult(diffs=[], probes=[], findings=[])

    monkeypatch.setattr(server, "scan", fake_scan)
    async with client as c:
        r = await c.post("/scan", json=payload())
    body = r.json()
    assert r.status_code == 200 and body["gate"]["failed"] is False


async def test_malformed_body_returns_422(client):
    async with client as c:
        r = await c.post("/scan", content=b"x" * 10, headers={"content-type": "application/json"})
    assert r.status_code == 422
