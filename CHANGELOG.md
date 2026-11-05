# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `--strip-prefix` to match endpoints across specs with different base paths (for example `/api`).
- `--param name=value` to supply real path, query and header parameter values when probing.
- `--no-probe` spec-only mode that does not need `--base-url`.
- A warning when the two specs share no endpoints, since every endpoint is then treated as new.

### Fixed
- Invalid `--header` input exited with code 1 (the "gate failed" code). Bad input now exits with 2.
- Path parameter values are URL-quoted.

## [0.1.0] - 2026-11-04

### Added
- Normalisation of Swagger 2.0 and OpenAPI 3.x specs into one model, and a diff of changed endpoints and fields.
- Async, read-only prober with retries, `Retry-After` support, a request cap, redirect refusal and an SSRF guard.
- PII detection with Presidio and spaCy, plus Aadhaar (Verhoeff checksum), PAN, UPI, IFSC and Indian mobile recognizers.
- Field-name heuristics for sensitive fields that a probe cannot reach.
- Gate that fails only on exposure introduced by the migration, including undocumented response fields.
- Text, JSON and SARIF 2.1.0 reports. Values are always masked.
- `.piileak-ignore.yaml` suppressions with mandatory reasons and expiry dates.
- Optional FastAPI service with a host allowlist.
