# Build stage
FROM rust:1.77-slim-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release 2>/dev/null || true
COPY . .
RUN touch src/main.rs
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/tea-server-platform /app/
COPY --from=builder /app/templates/ /app/templates/
COPY --from=builder /app/static/ /app/static/
EXPOSE 3000
CMD ["/app/tea-server-platform"]