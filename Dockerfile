FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p zd-node

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/zd /usr/local/bin/zd
USER 65534:65534
ENTRYPOINT ["zd"]
