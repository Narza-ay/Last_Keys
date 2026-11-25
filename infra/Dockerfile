# Last Keys server image, built from source.
#
#   docker build -f infra/Dockerfile -t lastkeys/server:local .
#
# Behind a TLS-intercepting proxy, pass its CA as a BuildKit secret:
#   docker build --secret id=build_ca,src=/path/to/ca.pem ...

FROM rust:1.97.0-slim-trixie AS builder
WORKDIR /src
# The image ships exactly the pinned toolchain; do not let rust-toolchain.toml
# trigger component downloads.
ENV RUSTUP_TOOLCHAIN=1.97.0 \
    CARGO_TERM_COLOR=never
COPY . .
RUN --mount=type=secret,id=build_ca,required=false \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    if [ -f /run/secrets/build_ca ]; then export CARGO_HTTP_CAINFO=/run/secrets/build_ca; fi; \
    cargo build --release --locked -p lk-server \
    && install -m 0755 target/release/lk-server /usr/local/bin/lk-server

FROM debian:trixie-slim AS runtime
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin lastkeys
COPY --from=builder /usr/local/bin/lk-server /usr/local/bin/lk-server
USER 10001:10001
ENV LK_BIND=0.0.0.0:8080
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 CMD ["lk-server", "healthcheck"]
ENTRYPOINT ["lk-server"]
CMD ["serve"]
