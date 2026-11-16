# syntax=docker/dockerfile:1

# ---------- Compilation : serveur + module WebAssembly ----------
FROM rust:1-trixie AS build
RUN rustup target add wasm32-unknown-unknown
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY branding ./branding
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo test --locked -p locksy-core -p locksy-server \
 && cargo build --locked --release -p locksy-server \
 && cargo build --locked --release -p locksy-wasm --target wasm32-unknown-unknown \
 && mkdir -p /out \
 && cp target/release/locksy-server /out/ \
 && cp target/wasm32-unknown-unknown/release/locksy_wasm.wasm /out/locksy.wasm

# ---------- Image d'exécution minimale ----------
FROM debian:trixie-slim
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin locksy \
 && mkdir -p /data /app \
 && chown locksy:locksy /data
COPY --from=build /out/locksy-server /app/locksy-server
COPY web /app/web
COPY --from=build /out/locksy.wasm /app/web/locksy.wasm
USER locksy
ENV LOCKSY_DATA=/data LOCKSY_WEB=/app/web LOCKSY_BIND=0.0.0.0:8743 RUST_LOG=info
EXPOSE 8743 8443
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["/app/locksy-server", "healthcheck"]
ENTRYPOINT ["/app/locksy-server"]
