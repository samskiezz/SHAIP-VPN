# Build context: the repository root (server depends on the client crate, and the
# workspace also lists ffi/, so all three are copied).
# docker build -f server/Dockerfile .
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY client ./client
COPY server ./server
COPY ffi ./ffi
RUN cargo build --release --locked -p shaip-server -p shaip-client

FROM debian:bookworm-slim
# nftables: `shaipd --nat` installs its masquerade + MSS-clamp rules with nft.
# conntrack: it deletes a freed tunnel address's NAT state with conntrack, so
# --nat refuses to start without it.
RUN apt-get update \
 && apt-get install -y --no-install-recommends nftables conntrack ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -r -s /usr/sbin/nologin shaip \
 && mkdir -p /var/lib/shaip && chown shaip /var/lib/shaip
COPY --from=build /src/target/release/shaipd      /usr/local/bin/shaipd
COPY --from=build /src/target/release/shaip-mixd  /usr/local/bin/shaip-mixd
COPY --from=build /src/target/release/shaip       /usr/local/bin/shaip
# Unprivileged by default (echo mode, shaip-mixd). The VPN server (--tun --nat)
# needs CAP_NET_ADMIN and /dev/net/tun; docker-compose.yml runs it that way.
USER shaip
ENTRYPOINT ["/usr/local/bin/shaipd"]
