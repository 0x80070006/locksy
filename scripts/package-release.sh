#!/usr/bin/env bash
# Assemble les fichiers d'une version à partir de dist/release (Dockerfile.release).
# Usage : bash scripts/package-release.sh <propriétaire/dépôt> <version>
# Résultat : dist/assets/ (archives, exécutable, scripts, SHA256SUMS).
set -euo pipefail
REPO=${1:?propriétaire/dépôt}
VERSION=${2:?version, ex. v1.0.0}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
REL="$ROOT/dist/release"
OUT="$ROOT/dist/assets"
for f in locksy-server locksy.wasm locksy.exe; do [ -f "$REL/$f" ] || { echo "Manque $REL/$f : lancez Dockerfile.release." >&2; exit 1; }; done
rm -rf "$OUT" && mkdir -p "$OUT"

# Extension (module WebAssembly de cette version)
LOCKSY_WASM="$REL/locksy.wasm" node "$ROOT/extension/build.mjs" >/dev/null

# Archives créées sous Linux (droits d'exécution conservés)
MSYS_NO_PATHCONV=1 docker run --rm -v "$(cd "$ROOT" && pwd -W 2>/dev/null || pwd):/src" -w /src \
  -e REPO="$REPO" -e VERSION="$VERSION" alpine:3.20 sh -euc '
  apk add --no-cache zip >/dev/null
  T=$(mktemp -d)
  mkdir -p $T/locksy-server/bin
  install -m 0755 dist/release/locksy-server $T/locksy-server/bin/locksy-server
  cp -r web $T/locksy-server/web
  cp dist/release/locksy.wasm $T/locksy-server/web/locksy.wasm
  install -m 0644 LICENSE $T/locksy-server/LICENSE
  sed "s#__REPO__#$REPO#g" install.sh > $T/locksy-server/install.sh && chmod 0755 $T/locksy-server/install.sh
  echo "$VERSION" > $T/locksy-server/VERSION
  tar -C $T -czf dist/assets/locksy-server-linux-x86_64.tar.gz locksy-server
  sed "s#__REPO__#$REPO#g" install.sh > dist/assets/install.sh && chmod 0755 dist/assets/install.sh
  (cd extension/dist && zip -qr ../../dist/assets/locksy-extension.zip locksy-extension)
  cp dist/release/locksy.exe dist/assets/locksy-windows-x64.exe
  cp install-client.ps1 dist/assets/install-client.ps1
  (cd dist/assets && sha256sum * > SHA256SUMS)
'
ls -la "$OUT"
