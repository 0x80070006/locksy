#!/usr/bin/env bash
# Lance les tests de bout en bout de Locksy dans Docker, en une commande.
#
#   bash e2e/tools/run.sh -p <cle> [--profile sso|ldap|mail]… [--rebuild] [--fast-server] [--keep] [-- <arguments playwright>]
#
#   -p <cle>        obligatoire ; nomme le projet compose, l'image superposée et
#                   les dossiers de sortie (test-results/<cle>, playwright-report/<cle>,
#                   .state/<cle>). Deux clés différentes peuvent tourner en même temps.
#   --profile P     démarre aussi Dex (sso), Samba AD (ldap) ou mailpit (mail) ; répétable.
#   --rebuild       reconstruit l'image serveur de base même si elle existe.
#   --fast-server   image de base construite par e2e/tools/Dockerfile.server
#                   (release, SANS tests cargo) au lieu du Dockerfile du dépôt.
#   --keep          laisse l'environnement en place à la fin (sinon « down -v »).
#   -- …            tout ce qui suit est passé à « npx playwright test ».
#
# Étapes : image de base (construite si absente) → superposition de web/ →
# compose up --wait → playwright dans le service « runner » → down -v.
# Le code de sortie est celui de Playwright.
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

usage() {
  sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-2}"
}
die() { echo "run.sh : $*" >&2; exit 2; }

key="" rebuild=0 fast=0 keep=0
profiles=()
while (($#)); do
  case "$1" in
    -p) [[ $# -ge 2 ]] || die "valeur manquante après -p"; key="$2"; shift 2 ;;
    -p=*|--project-name=*) key="${1#*=}"; shift ;;
    --profile) [[ $# -ge 2 ]] || die "valeur manquante après --profile"; profiles+=("$2"); shift 2 ;;
    --profile=*) profiles+=("${1#*=}"); shift ;;
    --rebuild) rebuild=1; shift ;;
    --fast-server) fast=1; shift ;;
    --keep) keep=1; shift ;;
    -h|--help) usage 0 ;;
    --) shift; break ;;
    *) die "option inconnue : $1 (les arguments de Playwright vont après « -- »)" ;;
  esac
done
pw_args=("$@")

[[ -n "$key" ]] || die "la clé est obligatoire : -p <cle> (ex. -p q3a-e2e)"
# Nom de projet compose : minuscules, chiffres, « - » et « _ ».
key="$(printf '%s' "$key" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9_-' '-')"
key="${key#[-_]}"
[[ "$key" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || die "clé invalide : $key"
for p in "${profiles[@]}"; do
  case "$p" in sso|ldap|mail) ;; *) die "profil inconnu : $p (sso, ldap ou mail)" ;; esac
done

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
e2e="$(cd "$here/.." && pwd)"
repo="$(cd "$e2e/.." && pwd)"
cd "$repo"

command -v docker >/dev/null || die "docker est introuvable"
docker compose version >/dev/null 2>&1 || die "docker compose (v2) est introuvable"

if ((fast)); then
  base_image="locksy-e2e-server:fast"
  base_dockerfile="e2e/tools/Dockerfile.server"
else
  base_image="locksy-e2e-server:local"
  base_dockerfile="Dockerfile"
fi
web_image="locksy-e2e-web:$key"
# Chemins relatifs à la racine du dépôt : sous Git Bash, un chemin absolu « /c/… »
# ne serait pas converti pour docker (MSYS_NO_PATHCONV).
state_dir="e2e/.state/$key"
mkdir -p "$state_dir" e2e/.npm-cache

# « runner » n'est jamais dans un profil actif pour « up » (il lancerait les tests
# tout seul) ; « run » le cible explicitement, « down » le nettoie.
compose_args=(-p "$key" -f e2e/docker-compose.e2e.yml)
for p in "${profiles[@]}"; do compose_args+=(--profile "$p"); done
compose() { docker compose "${compose_args[@]}" "$@"; }

export E2E_KEY="$key"
export LOCKSY_E2E_IMAGE="$web_image"
export E2E_PROFILES
E2E_PROFILES="$(IFS=,; echo "${profiles[*]}")"
export E2E_WASM="/work/e2e/.state/$key/locksy.wasm"
export LOCKSY_SSO_ALLOW_HTTP=false
[[ ",$E2E_PROFILES," == *",sso,"* ]] && LOCKSY_SSO_ALLOW_HTTP=true

# shellcheck disable=SC2329  # appelée par « trap cleanup EXIT »
cleanup() {
  local code=$?
  if ((keep)); then
    echo "Environnement conservé (--keep). Pour le supprimer :"
    echo "  docker compose -p $key -f e2e/docker-compose.e2e.yml --profile runner --profile sso --profile ldap --profile mail down -v --remove-orphans && docker image rm $web_image"
  else
    echo "Nettoyage de l'environnement « $key »…"
    compose --profile runner down -v --remove-orphans --timeout 5 >/dev/null 2>&1 || echo "run.sh : « down -v » a échoué, voir docker compose -p $key ps" >&2
    docker image rm "$web_image" >/dev/null 2>&1 || true
  fi
  exit "$code"
}

# 1. Image serveur de base.
if ((rebuild)) || ! docker image inspect "$base_image" >/dev/null 2>&1; then
  echo "Construction de l'image serveur $base_image ($base_dockerfile)…"
  if ((fast)); then
    DOCKER_BUILDKIT=1 docker build -f "$base_dockerfile" -t "$base_image" .
  else
    DOCKER_BUILDKIT=1 docker build -f "$base_dockerfile" --build-arg VERSION=e2e -t "$base_image" .
  fi
fi

trap cleanup EXIT

# 2. Superposition de web/ (quelques secondes, locksy.wasm conservé).
echo "Superposition de web/ sur $base_image → $web_image…"
DOCKER_BUILDKIT=1 docker build -q -f e2e/tools/Dockerfile.web --build-arg "BASE=$base_image" -t "$web_image" web >/dev/null

# Module WebAssembly pour la galerie (servie par tools/static.mjs, sans serveur Locksy).
tmp="e2e-wasm-$key-$$"
docker create --name "$tmp" "$base_image" >/dev/null
docker cp "$tmp:/app/web/locksy.wasm" "$state_dir/locksy.wasm" >/dev/null || echo "run.sh : locksy.wasm introuvable dans $base_image (galerie sans module de chiffrement)" >&2
docker rm "$tmp" >/dev/null

# 3. Serveurs (et profils) prêts.
echo "Démarrage de l'environnement « $key »${E2E_PROFILES:+ (profils : $E2E_PROFILES)}…"
compose up -d --wait --wait-timeout 300

# 4. Tests. Le code de sortie de Playwright devient celui du script.
set +e
compose run --rm runner "${pw_args[@]}"
status=$?
set -e
echo "Rapport : e2e/playwright-report/$key/index.html ; résultats : e2e/test-results/$key/"
exit "$status"
