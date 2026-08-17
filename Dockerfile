FROM rust:1.88-slim AS builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev protobuf-compiler && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN cargo build --release --bin kms-server

FROM debian:bookworm-slim
# curl is here for the compose healthcheck (the image ships no HTTP client otherwise), and it
# doubles as the tool every step of the ops runbook uses when shelling into a node.
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/kms-server /usr/local/bin/kms-server
CMD ["kms-server", "/config/kms.toml"]
