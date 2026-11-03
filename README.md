# PIILeak

CI gate that catches PII accidentally exposed when an API is migrated from v1 to v2.

## Overview

```
┌─────────────┐    ┌─────────────┐
│  Old Spec   │    │  New Spec   │
│  (v1)       │    │  (v2)       │
└──────┬──────┘    └──────┬──────┘
       │                 │
       └────────┬────────┘
                │
                ▼
      ┌───────────────────┐
      │  Spec Diff        │
      │  Identify changes │
      └────────┬──────────┘
               │
               ▼
      ┌───────────────────┐
      │  Probe New API    │
      │  GET endpoints    │
      └────────┬──────────┘
               │
               ▼
      ┌───────────────────┐
      │  Scan Responses   │
      │  Detect PII       │
      └────────┬──────────┘
               │
               ▼
      ┌───────────────────┐
      │  Report Findings  │
      │  Fail on NEW PII  │
      └───────────────────┘
```

## Installation

### Windows PowerShell

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
python -m spacy download en_core_web_sm
pytest
```

### Linux/macOS

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python -m spacy download en_core_web_sm
pytest
```

## Usage

```bash
piileak --old-spec path/to/v1.yaml --new-spec path/to/v2.yaml --api-url https://api.example.com
```

## Development

PIILeak uses the src layout. Run linters and tests during development:

```bash
# Lint and format
ruff check .
ruff format .

# Type checking
mypy src

# Run tests with coverage
pytest --cov=piileak --cov-fail-under=85
```