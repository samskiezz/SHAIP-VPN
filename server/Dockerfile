# Build context: the repository root (server depends on the client crate).
# docker build -f server/Dockerfile .
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml ./
COPY client ./client
COPY server ./server
RUN cargo build --release -p pqanon-server -p pqanon-client

FROM debian:bookworm-slim
RUN useradd -r -s /usr/sbin/nologin pqanon
COPY --from=build /src/target/release/pqanond      /usr/local/bin/pqanond
COPY --from=build /src/target/release/pqanon-mixd  /usr/local/bin/pqanon-mixd
COPY --from=build /src/target/release/pqanon       /usr/local/bin/pqanon
USER pqanon
# Default to the tunnel daemon; override `command:` for pqanon-mixd.
ENTRYPOINT ["/usr/local/bin/pqanond"]
