# syntax=docker/dockerfile:1
#
# Image de la version 1.0.0 de Locksy (N-1), reconstruite à partir de
# `git archive HEAD` dans un dossier temporaire HORS du dépôt
# (ops-tests/v100/construire.sh). Le contexte de construction est ce dossier
# temporaire : il ne contient que les sources de la 1.0.0.
#
# Différences avec le Dockerfile de la 1.0.0, toutes sans effet sur le binaire
# livré :
# - compilation dans l'image locale locksy-toolchain (même compilateur que le
#   reste du chantier) au lieu de rust:1-trixie ;
# - pas de `cargo test` (les tests de la 1.0.0 ne sont pas l'objet de la
#   recette ops) ;
# - caches BuildKit nommés q5-ops-* (aucun volume Docker nommé).
# L'image d'exécution est identique : Debian trixie-slim, utilisateur 10001,
# /data, interface web de la 1.0.0 et son locksy.wasm.

FROM locksy-toolchain AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY branding ./branding
ENV CARGO_BUILD_JOBS=3
RUN --mount=type=cache,id=q5-ops-v100-registre,target=/usr/local/cargo/registry \
    --mount=type=cache,id=q5-ops-v100-cible,target=/src/target \
    cargo build --locked --release -p locksy-server \
 && cargo build --locked --release -p locksy-wasm --target wasm32-unknown-unknown \
 && mkdir -p /out \
 && cp target/release/locksy-server /out/ \
 && cp target/wasm32-unknown-unknown/release/locksy_wasm.wasm /out/locksy.wasm

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
LABEL org.opencontainers.image.title="Locksy 1.0.0 (recette ops)" \
      org.opencontainers.image.version="1.0.0"
