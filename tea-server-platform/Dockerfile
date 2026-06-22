# Build stage
FROM rust:bookworm AS builder
WORKDIR /app

# Copy only Cargo files first for caching
COPY Cargo.toml Cargo.lock ./

# Create minimal src to build dependencies
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs

# Build dependencies (cached if Cargo files haven't changed)
RUN cargo build --release --locked 2>/dev/null || true

# Now copy actual source code
COPY src/ ./src/
COPY templates/ ./templates/
COPY static/ ./static/

# Build the actual project
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/tea-server-platform /app/
COPY --from=builder /app/templates/ /app/templates/
COPY --from=builder /app/static/ /app/static/
COPY --from=builder /app/.env* /app/
EXPOSE 3000
CMD ["/app/tea-server-platform"]