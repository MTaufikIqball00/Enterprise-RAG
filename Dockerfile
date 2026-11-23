# ============================================================================
# Stage 1: Build Native Rust Backend
# ============================================================================
FROM rust:1.83-slim-bookworm AS builder

WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

COPY backend_rust/Cargo.toml backend_rust/Cargo.lock ./backend_rust/
COPY backend_rust/src ./backend_rust/src

RUN cargo build --release --manifest-path backend_rust/Cargo.toml

# ============================================================================
# Stage 2: Minimal Runtime Image (Non-Root)
# ============================================================================
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 10001 appuser

WORKDIR /app
COPY --from=builder /app/backend_rust/target/release/backend_rust /usr/local/bin/enterprise-rag-backend
RUN mkdir -p /app/storage/documents && chown -R appuser:appuser /app

USER appuser

ENV HOST=0.0.0.0
ENV BACKEND_PORT=8010
ENV DATABASE_URL=sqlite:///./storage/enterprise_rag.db
ENV RAW_DOCUMENT_STORAGE_PATH=./storage/documents

EXPOSE 8010

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8010/api/v1/health || exit 1

ENTRYPOINT ["/usr/local/bin/enterprise-rag-backend"]
