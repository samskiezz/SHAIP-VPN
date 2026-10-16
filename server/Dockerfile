# Build context: the repository root (server depends on the client crate, and the
# workspace also lists ffi/, so all three are copied).
# docker build -f server/Dockerfile .
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY client ./client
COPY server ./server
COPY ffi ./ffi
RUN cargo build --release --locked -p pqanon-server -p pqanon-client

FROM debian:bookworm-slim
# nftables: `pqanond --nat` installs its masquerade + MSS-clamp rules with nft.
RUN apt-get update \
 && apt-get install -y --no-install-recommends nftables ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -r -s /usr/sbin/nologin pqanon \
 && mkdir -p /var/lib/pqanon && chown pqanon /var/lib/pqanon
COPY --from=build /src/target/release/pqanond      /usr/local/bin/pqanond
COPY --from=build /src/target/release/pqanon-mixd  /usr/local/bin/pqanon-mixd
COPY --from=build /src/target/release/pqanon       /usr/local/bin/pqanon
# Unprivileged by default (echo mode, pqanon-mixd). The VPN server (--tun --nat)
# needs CAP_NET_ADMIN and /dev/net/tun; docker-compose.yml runs it that way.
USER pqanon
ENTRYPOINT ["/usr/local/bin/pqanond"]
