# Build stage
FROM rust:bookworm AS builder
WORKDIR /app

# 单线程编译，减少内存使用
ENV CARGO_BUILD_JOBS=1

# 复制 Cargo 文件
COPY Cargo.toml Cargo.lock ./

# 创建最小项目结构
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs

# 构建依赖（缓存）
RUN cargo build --release --locked 2>/dev/null || true

# 复制源代码
COPY src/ ./src/
COPY templates/ ./templates/
COPY static/ ./static/

# 构建实际项目
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 sqlite3 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/tea-server-platform /app/
COPY --from=builder /app/templates/ /app/templates/
COPY --from=builder /app/static/ /app/static/
EXPOSE 3000
ENV RUST_LOG=info
CMD ["/app/tea-server-platform"]