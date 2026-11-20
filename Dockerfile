# syntax=docker/dockerfile:1
# Pinned by tag and digest so a rebuild gives the same toolchain. To update:
# pick a newer tag on Docker Hub and replace both the tag and the digest.
FROM rust:1.99.0-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS build
# cmake is needed by libz-ng-sys, a dependency of Pingora.
RUN apt-get update && apt-get install -y --no-install-recommends cmake && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked && cp target/release/pingenv /pingenv && mkdir /data

# glibc, libgcc and CA roots, nothing else: no shell, no package manager.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /pingenv /pingenv
# Created here so a named volume mounted at /data starts out writable by the
# unprivileged user. A bind mount has to be made writable for uid 65532.
COPY --from=build --chown=nonroot:nonroot /data /data
VOLUME /data
EXPOSE 80 443
# No shell or curl in this image, so the binary checks itself: it succeeds if
# the HTTP port accepts connections. The environment is the container's own.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/pingenv", "--healthcheck"]
ENTRYPOINT ["/pingenv"]
