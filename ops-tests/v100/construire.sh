#!/usr/bin/env bash
# Construit l'image de la version 1.0.0 (N-1) à partir de git HEAD, sans
# toucher au dépôt : `git archive` vers un dossier temporaire HORS du dépôt,
# puis `docker build` avec ops-tests/v100/Dockerfile. Le dossier temporaire
# est supprimé à la fin. Mode d'emploi : ops-tests/README.md.
#
#   bash ops-tests/v100/construire.sh [image]      (défaut : locksy-ops:1.0.0)
#
# Variables : V100_REF (révision git, défaut HEAD). Code 0 réussite, 1 échec.
set -euo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/../.."

image=${1:-locksy-ops:1.0.0}
ref=${V100_REF:-HEAD}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

revision=$(git rev-parse "$ref")
git archive --format=tar "$ref" | tar -x -C "$tmp"
version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$tmp/Cargo.toml" | head -1)
if [ "$version" != 1.0.0 ]; then
  echo "Erreur : la révision $ref est en version « $version », 1.0.0 attendue." >&2
  exit 1
fi
cp ops-tests/v100/Dockerfile "$tmp/ops-v100.Dockerfile"
contexte=$tmp
command -v cygpath >/dev/null 2>&1 && contexte=$(cygpath -m "$tmp")

echo "Construction de $image depuis $ref (${revision:0:12}, version $version), contexte temporaire $contexte…" >&2
debut=$(date +%s)
docker build --cpu-quota=300000 \
  --label "org.opencontainers.image.revision=$revision" \
  -f "$contexte/ops-v100.Dockerfile" -t "$image" "$contexte"
echo "Image $image construite en $(( $(date +%s) - debut )) s." >&2
