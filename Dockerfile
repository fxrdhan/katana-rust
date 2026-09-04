# Multi-stage minimal Dockerfile for production Katana (Rust)
# Stage 1: Build static binary
FROM rust:1.85-alpine AS builder

RUN apk add --no-cache musl-dev gcc make cmake perl clang-dev

WORKDIR /app

# Copy manifests first for layer caching
COPY Cargo.toml Cargo.lock ./
COPY crates/katana-core/Cargo.toml crates/katana-core/
COPY crates/katana-similarity/Cargo.toml crates/katana-similarity/
COPY crates/katana-parser/Cargo.toml crates/katana-parser/
COPY crates/katana-engine/Cargo.toml crates/katana-engine/
COPY crates/katana-cli/Cargo.toml crates/katana-cli/

# Copy configuration and full source tree
COPY .cargo .cargo
COPY crates crates

# Build stripped release binary
RUN cargo build --release --bin katana

# Stage 2: Minimal hardened runtime container (<25MB)
FROM alpine:3.21

# Install minimal production runtime dependencies: root certs, DNS tools, and dumb-init (<25MB image).
# For in-container local headless execution, install chromium (apk add chromium) or pass --chrome-ws-url.
RUN apk add --no-cache ca-certificates bind-tools dumb-init && \
    addgroup -S katana && adduser -S katana -G katana

# Copy stripped binary from builder
COPY --from=builder /app/target/release/katana /usr/local/bin/katana

USER katana
WORKDIR /home/katana

ENTRYPOINT ["/usr/bin/dumb-init", "--", "katana"]
