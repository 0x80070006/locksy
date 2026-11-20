#!/usr/bin/env bash
# Démarre le serveur du banc (image construite au besoin) puis lance les
# contrôles préalables. Mode d'emploi : bench/README.md.
set -euo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/../.."
# Valeurs de bench/.env, sans écraser l'environnement (même priorité que docker compose).
if [ -f bench/.env ]; then
  while IFS='=' read -r k v || [ -n "$k" ]; do
    if [[ $k =~ ^[A-Z_][A-Z0-9_]*$ && -z ${!k+x} ]]; then export "$k=${v%$'\r'}"; fi
  done < bench/.env
fi

usage() {
  cat <<'EOF'
Démarre le serveur Locksy du banc, puis lance preflight.sh.

Usage : bash bench/scripts/bench-up.sh [-p projet] [--profile REF-PROD|REF-1G] [--rebuild]

  -p projet   nom du projet docker compose (défaut : $BENCH_PROJECT, sinon locksy-bench)
  --profile   REF-PROD : 512 Mo (défaut, seuils bloquants) ; REF-1G : 1 Go (dimensionnement)
  --rebuild   reconstruit l'image $LOCKSY_IMAGE même si elle existe (le Dockerfile
              exécute les tests cargo : comptez plusieurs minutes)
  -h          affiche cette aide

Code de sortie : celui de preflight.sh (0 conforme, 1 avertissements, 2 bloquant),
ou 2 si l'image ou le serveur ne démarre pas.
EOF
}

project="${BENCH_PROJECT:-locksy-bench}"
rebuild=0
while [ $# -gt 0 ]; do
  case "$1" in
    -p) project="${2:?-p attend un nom de projet}"; shift 2 ;;
    --profile)
      case "${2:-}" in
        REF-PROD) export LOCKSY_MEM=512m ;;
        REF-1G) export LOCKSY_MEM=1g ;;
        *) echo "Profil inconnu : « ${2:-} » (REF-PROD ou REF-1G)." >&2; exit 2 ;;
      esac
      shift 2 ;;
    --rebuild) rebuild=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Argument inconnu : $1" >&2; usage >&2; exit 2 ;;
  esac
done
export LOCKSY_IMAGE="${LOCKSY_IMAGE:-locksy-bench:local}"
dc() { docker compose -p "$project" -f bench/docker-compose.bench.yml "$@"; }

if [ "$rebuild" = 1 ] || ! docker image inspect "$LOCKSY_IMAGE" >/dev/null 2>&1; then
  echo "Construction de l'image $LOCKSY_IMAGE (tests cargo compris)…"
  if ! docker build -f Dockerfile -t "$LOCKSY_IMAGE" .; then
    echo "Échec de la construction de l'image $LOCKSY_IMAGE." >&2
    exit 2
  fi
fi

echo "Démarrage du serveur (projet $project, image $LOCKSY_IMAGE, mémoire ${LOCKSY_MEM:-512m})…"
if ! dc up -d --wait --wait-timeout 180 locksy; then
  echo "Le serveur n'a pas démarré. Journal : docker compose -p $project -f bench/docker-compose.bench.yml logs locksy" >&2
  exit 2
fi
echo "Serveur prêt : http://$(dc port locksy 8743)"
exec bash bench/scripts/preflight.sh -p "$project"
