"""Optional FastAPI wrapper: POST /scan with two specs and a base URL.

SECURITY: this makes outbound requests to a caller-supplied URL (SSRF risk).
Set PIILEAK_ALLOWED_HOSTS="staging.example.com,localhost" before exposing it.
"""

from __future__ import annotations

import os
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .detector import PiiDetector
from .models import Severity
from .normalize import SpecError
from .report import render_json
from .scanner import scan

app = FastAPI(title="PIILeak", version="0.1.0")
_detector: PiiDetector | None = None


class ScanRequest(BaseModel):
    old_spec: dict
    new_spec: dict
    base_url: str
    headers: dict[str, str] = Field(default_factory=dict)
    fail_on: Severity = Severity.MEDIUM
    probe_all: bool = False


def get_detector() -> PiiDetector:
    global _detector
    if _detector is None:
        _detector = PiiDetector()
    return _detector


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan")
async def scan_endpoint(req: ScanRequest):
    allowed = [h.strip() for h in os.getenv("PIILEAK_ALLOWED_HOSTS", "").split(",") if h.strip()]
    host = urlparse(req.base_url).hostname
    if allowed and host not in allowed:
        raise HTTPException(403, f"host {host!r} is not in PIILEAK_ALLOWED_HOSTS")
    try:
        result = await scan(
            req.old_spec, req.new_spec, req.base_url, get_detector(), headers=req.headers, probe_all=req.probe_all
        )
    except SpecError as exc:
        raise HTTPException(422, str(exc)) from exc
    import json

    return json.loads(render_json(result, req.fail_on))
