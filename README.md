# PIILeak

A CI gate that catches **PII accidentally exposed when an API is migrated** (v1 to v2).

It compares the old and new API specs, probes the changed endpoints on the new API, scans the
responses for personal data, and fails the build (exit code 1) if the migration introduced
**new** exposure. It understands Indian identifiers (Aadhaar, PAN, UPI, IFSC, mobile numbers)
as well as emails, phone numbers and card numbers.

```
old spec --+                                    +-- static: sensitive field NAMES
           +-- normalise -- diff -- changed ----+
new spec --+  (Swagger 2.0 / OpenAPI 3.x        +-- dynamic: async probe -> Presidio + spaCy
               -> one internal model)                         + custom Indian recognizers
                                                                  |
                                              new PII found?      v   exit code 1
```

## Install

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
python -m spacy download en_core_web_sm
pytest
```

Linux / macOS:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m spacy download en_core_web_sm
pytest
```

## Try the demo

The demo API serves `/v1` (clean) and `/v2` (leaks fake PII). Start it in one terminal:

```bash
uvicorn examples.demo_api:app --port 8000
```

Then scan it from another (`--allow-private` is needed because the demo runs on localhost):

```bash
piileak scan --old examples/specs/v1_swagger2.json --new examples/specs/v2_openapi3.json \
             --base-url http://localhost:8000 --allow-private
```

Expected: `RESULT: FAIL` and exit code 1, with findings for Aadhaar, PAN, UPI, email and an
undocumented `phone` field. Values are always masked in the output.

## Usage

```
piileak scan --old OLD_SPEC --new NEW_SPEC --base-url URL [options]
```

| Option | Meaning |
|---|---|
| `-H "Name: value"` | Extra request header (repeatable), e.g. an auth token |
| `--fail-on low\|medium\|high` | Lowest severity that fails the build (default `medium`) |
| `--format text\|json` | Output format |
| `--probe-all` | Also probe unchanged endpoints (finds undocumented leaks) |
| `--no-static` | Disable field-name heuristics |
| `--allow-unsafe` | Also probe POST/PUT/PATCH/DELETE (staging only) |
| `--allow-private` | Allow localhost / private-network targets (refused by default) |
| `--max-retries N` | Retries for 429, 502, 503, 504 and connection errors (default 2) |
| `--max-requests N` | Hard cap on total HTTP requests (default 500) |
| `--include-person` | Also report person names (noisy) |

Exit codes: `0` pass, `1` PII gate failed, `2` invalid input or unsafe target.

## Design decisions

- **Normalise before diffing.** Swagger 2.0 and OpenAPI 3.x describe the same API differently, so
  a raw diff is full of format noise. `/v1`, `/v2` and `{param}` names are stripped from endpoint keys.
- **Only new exposure fails the build.** A field is new if its endpoint is new or its path is absent
  from the old spec, including fields that appear in a live response but in neither spec.
- **Aadhaar uses the Verhoeff checksum**, which removes most random 12-digit matches.
- **UPI IDs are limited to known payment handles**, so ordinary emails are not matched.
- **Reports never contain raw PII.** Values are masked and response bodies are never serialised.

## Security notes

- The prober is read-only (GET) by default and never follows redirects.
- Targets that resolve to private, loopback or link-local addresses are refused unless
  `--allow-private` is set. DNS can change between the check and the request, so also restrict
  egress at the network level when running this as a service.
- Run it against staging or test environments, not production.
- `piileak/server.py` exposes `POST /scan`. Set `PIILEAK_ALLOWED_HOSTS` and put it behind
  authentication before exposing it anywhere.

## Development

```bash
ruff check . && ruff format .
mypy src
pytest
```

## Known limitations

- Only local `$ref` values are resolved.
- Authentication is a static header; there are no OAuth flows.
- Only the first page of a paginated response is scanned.
- No GraphQL or gRPC support.
