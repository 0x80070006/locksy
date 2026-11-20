#!/usr/bin/env bash
# Semis complet d'un jeu sur le serveur du banc : module WebAssembly extrait de
# l'image en service, semis par le vrai code client, vérification, puis
# instantané. Mode d'emploi : bench/README.md.
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
Semis d'un jeu de données sur le serveur du banc (instance neuve).

Usage : bash bench/scripts/seed.sh [-p projet] [--workers N] [--no-attachments] [--no-snapshot] <S|M|L|E2E>

  -p projet       nom du projet docker compose (défaut : $BENCH_PROJECT, sinon locksy-bench)
  --workers N     fils de semis, un compte en cours par fil (défaut : moitié des processeurs, 6 au plus)
  --no-attachments  aucune pièce jointe (M et L : semis bien plus court, voir bench/README.md)
  --no-snapshot   ne prend pas d'instantané après la vérification
  -h              affiche cette aide

Étapes : extraction de locksy.wasm (bench/.cache/), seed.mjs, verify.mjs, snapshot.sh save.
Sorties : bench/seed/out/<jeu>/{manifest,users}.json et bench/snapshots/<jeu>/.
Codes de sortie : 0 réussite, 1 échec, 2 usage invalide.
EOF
}

project="${BENCH_PROJECT:-locksy-bench}"
workers=()
snapshot=1
seed_opts=()
dataset=""
while [ $# -gt 0 ]; do
  case "$1" in
    -p) project="${2:?-p attend un nom de projet}"; shift 2 ;;
    --workers) workers=(--workers "${2:?--workers attend un nombre}"); shift 2 ;;
    --no-snapshot) snapshot=0; shift ;;
    --no-attachments) seed_opts+=(--no-attachments); shift ;;
    -h|--help) usage; exit 0 ;;
    S|M|L|E2E) dataset="$1"; shift ;;
    *) echo "Argument inconnu : $1" >&2; usage >&2; exit 2 ;;
  esac
done
if [ -z "$dataset" ]; then usage >&2; exit 2; fi
dc() { docker compose -p "$project" -f bench/docker-compose.bench.yml "$@"; }

cid=$(dc ps -q locksy)
if [ -z "$cid" ]; then echo "Serveur non démarré : bash bench/scripts/bench-up.sh -p $project" >&2; exit 1; fi
base="http://$(dc port locksy 8743)"
# Jeton d'installation : celui du conteneur en service.
setup_token=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$cid" | sed -n 's/^LOCKSY_SETUP_TOKEN=//p' | tr -d '\r')
out="bench/seed/out/$dataset"
wasm="bench/.cache/locksy.wasm"

# Module WebAssembly de l'image EN SERVICE : client et serveur de la même version.
image_id=$(docker inspect -f '{{.Image}}' "$cid")
mkdir -p bench/.cache
tmp_cid=$(docker create "$image_id")
trap 'docker rm "$tmp_cid" >/dev/null 2>&1 || true' EXIT
docker cp "$tmp_cid:/app/web/locksy.wasm" "$wasm"
docker rm "$tmp_cid" >/dev/null
trap - EXIT
echo "Module WebAssembly extrait de l'image ${image_id:7:12} : $wasm"

start=$(date +%s)
node bench/seed/seed.mjs --dataset "$dataset" --base "$base" --wasm "$wasm" --out "$out" \
  --setup-token "$setup_token" "${workers[@]}" "${seed_opts[@]}"
seeded=$(date +%s)
node bench/seed/verify.mjs --dataset "$dataset" --base "$base" --wasm "$wasm" --out "$out" "${workers[@]}"
verified=$(date +%s)
if [ "$snapshot" = 1 ]; then bash bench/scripts/snapshot.sh -p "$project" save "$dataset"; fi
done_at=$(date +%s)
echo "Jeu $dataset prêt : semis $((seeded - start)) s, vérification $((verified - seeded)) s, instantané $((done_at - verified)) s."
