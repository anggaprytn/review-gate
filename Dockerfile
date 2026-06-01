# syntax=docker/dockerfile:1

FROM rust:1-slim-bookworm AS builder

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libgcc-s1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home --home-dir /home/reviewgate --shell /usr/sbin/nologin reviewgate \
    && mkdir -p /work/.reviewgate \
    && chown -R reviewgate:reviewgate /work

COPY --from=builder /app/target/release/reviewgate /usr/local/bin/reviewgate

RUN set -eux; \
    { \
        printf '%s\n' '#!/bin/sh'; \
        printf '%s\n' 'set -e'; \
        printf '%s\n' 'case "${1:-}" in'; \
        printf '%s\n' '  ""|review|verify|doctor|fix-prompt|plan|--help|-h|--version|-V)'; \
        printf '%s\n' '    exec reviewgate "$@"'; \
        printf '%s\n' '    ;;'; \
        printf '%s\n' '  reviewgate)'; \
        printf '%s\n' '    shift'; \
        printf '%s\n' '    exec reviewgate "$@"'; \
        printf '%s\n' '    ;;'; \
        printf '%s\n' '  *)'; \
        printf '%s\n' '    exec "$@"'; \
        printf '%s\n' '    ;;'; \
        printf '%s\n' 'esac'; \
    } > /usr/local/bin/docker-entrypoint \
    && chmod +x /usr/local/bin/docker-entrypoint

USER reviewgate
WORKDIR /work

ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
CMD ["--help"]
