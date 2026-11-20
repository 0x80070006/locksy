# syntax=docker/dockerfile:1

# Images de base épinglées par version ET par empreinte (digest d'index) :
# une reconstruction donne la même chaîne de compilation et le même système
# d'exécution. La version de Rust doit rester celle de rust-toolchain.toml
# (vérifié par la CI, job clippy, étape « toolchain cohérente »).
# Mise à jour : manuelle (tag ET empreinte, avec rust-toolchain.toml), car
# Dependabot ne suit pas les images passées par ARG ; relever l'empreinte avec
# `docker buildx imagetools inspect <image>:<tag>`.
ARG RUST_IMAGE=rust:1.100.0-trixie@sha256:e19840879045c951c905d0eaa9887f3439c62000e429963371b376bac8d38c31
ARG RUNTIME_IMAGE=debian:trixie-20261104-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

# ---------- Compilation : serveur + modules WebAssembly ----------
# Deux modules : locksy.wasm (noyau, sans les lecteurs d'import, budget des
# ressources) et locksy-import.wasm (complet, chargé seulement par le worker
# d'import KeePass et Bitwarden).
FROM ${RUST_IMAGE} AS build
RUN rustup target add wasm32-unknown-unknown
# Compilation reproductible : horodatage fixé par l'appelant
# (--build-arg SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)), pas de
# compilation incrémentale, chemins absolus de la machine retirés du binaire.
ARG SOURCE_DATE_EPOCH
ENV CARGO_INCREMENTAL=0 \
    RUSTFLAGS="--remap-path-prefix=/src=. --remap-path-prefix=/usr/local/cargo=/cargo"
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY branding ./branding
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo test --locked -p locksy-core -p locksy-server \
 && cargo build --locked --release -p locksy-server \
 && mkdir -p /out \
 && cargo build --locked --release -p locksy-wasm --target wasm32-unknown-unknown --no-default-features \
 && cp target/wasm32-unknown-unknown/release/locksy_wasm.wasm /out/locksy.wasm \
 && cargo build --locked --release -p locksy-wasm --target wasm32-unknown-unknown \
 && cp target/wasm32-unknown-unknown/release/locksy_wasm.wasm /out/locksy-import.wasm \
 && cp target/release/locksy-server /out/

# ---------- Image d'exécution minimale ----------
FROM ${RUNTIME_IMAGE}
# Métadonnées OCI (renseignées par la CI et release.yml).
ARG VERSION=dev
ARG REVISION=inconnue
ARG SOURCE=https://github.com/0x80070006/locksy
ARG LICENSES=MIT
LABEL org.opencontainers.image.title="Locksy" \
      org.opencontainers.image.description="Gestionnaire de mots de passe d'entreprise, chiffré de bout en bout" \
      org.opencontainers.image.source="${SOURCE}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="${LICENSES}"
# Correctifs de sécurité de la distribution parus après l'image épinglée
# (ex. zlib1g CVE-2026-85091 relevée par Trivy).
RUN apt-get -o Acquire::Retries=8 update \
 && DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=8 -y upgrade \
 && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin locksy \
 && mkdir -p /data /app \
 && chown locksy:locksy /data
COPY --from=build /out/locksy-server /app/locksy-server
COPY web /app/web
COPY --from=build /out/locksy.wasm /app/web/locksy.wasm
COPY --from=build /out/locksy-import.wasm /app/web/locksy-import.wasm
USER locksy
# Mémoire bornée sous charge : deux zones d'allocation glibc au lieu d'une
# par fil (sinon plus de 450 Mio résidents pour 512 Mio sur le jeu M, et la
# sauvegarde à chaud fait tuer le serveur) ; fichiers temporaires de SQLite
# (tris, VACUUM INTO) sur le volume de données et non dans /tmp (tmpfs en mémoire).
ENV MALLOC_ARENA_MAX=2 SQLITE_TMPDIR=/data
ENV LOCKSY_DATA=/data LOCKSY_WEB=/app/web LOCKSY_BIND=0.0.0.0:8743 RUST_LOG=info
EXPOSE 8743 8443
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["/app/locksy-server", "healthcheck"]
ENTRYPOINT ["/app/locksy-server"]
