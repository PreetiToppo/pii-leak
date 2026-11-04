# syntax=docker/dockerfile:1
# Two stages: build the virtualenv (with the spaCy model) once, then copy only the
# finished environment into a clean runtime image.

FROM python:3.12-slim AS builder
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install . \
    && python -m spacy download en_core_web_sm

FROM python:3.12-slim
LABEL org.opencontainers.image.title="PIILeak" \
      org.opencontainers.image.description="CI gate that catches PII leaks introduced by API version migrations" \
      org.opencontainers.image.source="https://github.com/PreetiToppo/pii-leak" \
      org.opencontainers.image.licenses="MIT"
# Run as an unprivileged user: the tool only needs to read specs and make HTTP requests.
RUN useradd --create-home --uid 10001 piileak
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
USER piileak
WORKDIR /work
ENTRYPOINT ["piileak"]
CMD ["--help"]
