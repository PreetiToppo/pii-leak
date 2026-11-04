# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub: open the repository's **Security** tab and choose
**Report a vulnerability**. Do not open a public issue. You can expect an acknowledgement within a week.

## Scope notes

- PIILeak sends HTTP requests to the URL you give it. Run it against staging or test environments, not production.
- Targets on private, loopback or link-local addresses are refused unless `--allow-private` is set.
- Reports contain masked values only, and probe response bodies are never serialised.
