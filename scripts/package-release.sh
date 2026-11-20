#!/usr/bin/env bash
# Assemble les fichiers d'une version à partir de dist/release (Dockerfile.release).
# Usage : bash scripts/package-release.sh <propriétaire/dépôt> <version>
# Résultat : dist/assets/ (archives, exécutable, scripts, SBOM, SHA256SUMS).
#
# Environnement facultatif :
#   SOURCE_DATE_EPOCH    date des fichiers des archives (défaut : date du
#                        dernier commit, ou 0 hors git)
#   MINISIGN_PUBLIC_KEY  clé publique minisign inscrite dans install.sh
# Les SBOM dist/sbom/*.cdx.json sont copiés s'ils existent.
#
# Reproductible : deux exécutions sur les mêmes entrées produisent des archives
# et un SHA256SUMS identiques (ordre, dates, propriétaires et droits fixés,
# gzip sans nom ni date).
set -euo pipefail
REPO=${1:?propriétaire/dépôt}
VERSION=${2:?version, ex. v1.0.0}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
REL="$ROOT/dist/release"
OUT="$ROOT/dist/assets"
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || echo 0)}
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || { echo "SOURCE_DATE_EPOCH invalide : $SOURCE_DATE_EPOCH" >&2; exit 1; }
MINISIGN_PUBLIC_KEY=${MINISIGN_PUBLIC_KEY:-}
export REPO VERSION SOURCE_DATE_EPOCH MINISIGN_PUBLIC_KEY
for f in locksy-server locksy.wasm locksy-import.wasm locksy.exe; do [ -f "$REL/$f" ] || { echo "Manque $REL/$f : lancez Dockerfile.release." >&2; exit 1; }; done
[ -f "$ROOT/scripts/backup-locksy.sh" ] || { echo "Manque scripts/backup-locksy.sh." >&2; exit 1; }
rm -rf "$OUT" && mkdir -p "$OUT"

# Extension (module WebAssembly de cette version)
# (zip déterministe et son empreinte produits par build.mjs lui-même)
node "$ROOT/extension/build.mjs" --wasm "$REL/locksy.wasm" >/dev/null

# Assemblage, exécuté depuis la racine du dépôt avec GNU tar et gzip.
# shellcheck disable=SC2016 # développé par le bash d'assemblage, pas ici
ASSEMBLE='
set -euo pipefail
export LC_ALL=C TZ=UTC
T=$(mktemp -d); trap "rm -rf \"$T\"" EXIT
S=$T/locksy-server
# Remplacement des valeurs à substituer dans install.sh (__REPO__, clé minisign).
subst() {
  local key=${MINISIGN_PUBLIC_KEY:-}
  if [ -n "$key" ]; then
    sed -e "s#__REPO__#$REPO#g" -e "s#__MINISIGN_PUBKEY__#$key#g" "$1"
  else
    sed -e "s#__REPO__#$REPO#g" "$1"
  fi
}
mkdir -p "$S/bin" "$S/scripts"
cp dist/release/locksy-server "$S/bin/locksy-server"
cp -r web "$S/web"
rm -rf "$S/web/tests"
cp dist/release/locksy.wasm "$S/web/locksy.wasm"
cp dist/release/locksy-import.wasm "$S/web/locksy-import.wasm"
cp LICENSE "$S/LICENSE"
subst install.sh > "$S/install.sh"
cp scripts/backup-locksy.sh "$S/scripts/backup-locksy.sh"
printf "%s\n" "$VERSION" > "$S/VERSION"
# Droits et dates normalisés (indépendants du poste et du checkout).
find "$T" -type d -exec chmod 0755 {} +
find "$T" -type f -exec chmod 0644 {} +
chmod 0755 "$S/bin/locksy-server" "$S/install.sh" "$S/scripts/backup-locksy.sh"
find "$T" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner --format=gnu \
  -C "$T" -cf - locksy-server | gzip -n -9 > dist/assets/locksy-server-linux-x86_64.tar.gz

subst install.sh > dist/assets/install.sh && chmod 0755 dist/assets/install.sh
cp extension/dist/locksy-extension.zip dist/assets/locksy-extension.zip
cp dist/release/locksy.exe dist/assets/locksy-windows-x64.exe
cp install-client.ps1 dist/assets/install-client.ps1
if [ -d dist/sbom ]; then
  for f in dist/sbom/*.cdx.json; do [ -f "$f" ] && cp "$f" dist/assets/; done
fi
# Empreintes de tous les fichiers (SHA256SUMS ne se couvre pas lui-même).
(cd dist/assets && rm -f SHA256SUMS && files=(*) && sha256sum -- "${files[@]}" > SHA256SUMS.tmp && mv SHA256SUMS.tmp SHA256SUMS)
'

if [ "$(uname -s)" = Linux ] && tar --version 2>/dev/null | grep -q GNU && gzip --version >/dev/null 2>&1; then
  (cd "$ROOT" && bash -c "$ASSEMBLE")
else
  # Windows (Git Bash) ou tar non GNU : assemblage dans une Debian épinglée.
  MSYS_NO_PATHCONV=1 docker run --rm -v "$(cd "$ROOT" && pwd -W 2>/dev/null || pwd):/src" -w /src \
    -e REPO -e VERSION -e SOURCE_DATE_EPOCH -e MINISIGN_PUBLIC_KEY \
    debian:trixie-20261104-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 \
    bash -c "$ASSEMBLE"
fi
ls -la "$OUT"
