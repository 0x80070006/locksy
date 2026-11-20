#!/usr/bin/env bash
# Instantanés d'un jeu semé : sauvegarde à chaud vérifiée (base + clé serveur)
# vers bench/snapshots/<jeu>/, et restauration dans le volume du projet.
# Mode d'emploi : bench/README.md.
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
Instantanés des jeux de données du banc.

Usage : bash bench/scripts/snapshot.sh [-p projet] save <jeu>
        bash bench/scripts/snapshot.sh [-p projet] restore <jeu>

  save      sauvegarde à chaud, vérifiée par le serveur (locksy-server backup --with-key),
            copiée avec manifest.json et users.json dans bench/snapshots/<jeu>/
  restore   arrête le serveur, remplace le contenu du volume /data par l'instantané,
            redémarre et attend la bonne santé ; remet aussi manifest.json et users.json
            dans bench/seed/out/<jeu>/
  -p projet nom du projet docker compose (défaut : $BENCH_PROJECT, sinon locksy-bench)
  -h        affiche cette aide

Codes de sortie : 0 réussite, 1 échec, 2 usage invalide.
EOF
}

project="${BENCH_PROJECT:-locksy-bench}"
args=()
while [ $# -gt 0 ]; do
  case "$1" in
    -p) project="${2:?-p attend un nom de projet}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "Option inconnue : $1" >&2; usage >&2; exit 2 ;;
    *) args+=("$1"); shift ;;
  esac
done
if [ "${#args[@]}" -ne 2 ] || [[ ! ${args[0]} =~ ^(save|restore)$ ]] || [[ ! ${args[1]} =~ ^(S|M|L|E2E)$ ]]; then
  usage >&2
  exit 2
fi
action="${args[0]}"
dataset="${args[1]}"
dir="bench/snapshots/$dataset"
out="bench/seed/out/$dataset"
# Conteneur utilitaire de la restauration (image épinglée).
BUSYBOX_IMAGE="${BUSYBOX_IMAGE:-busybox:1.37.0}"
dc() { docker compose -p "$project" -f bench/docker-compose.bench.yml "$@"; }

save() {
  local cid
  cid=$(dc ps -q locksy)
  if [ -z "$cid" ]; then echo "Serveur non démarré (projet $project) : rien à sauvegarder." >&2; exit 1; fi
  # Variable globale : le piège EXIT la relit après la fin de la fonction.
  tmp="bench/snapshots/.$dataset.en-cours"
  rm -rf "$tmp"
  mkdir -p "$tmp"
  # Copie de travail effacée du volume quoi qu'il arrive.
  trap 'dc exec -T locksy rm -f /data/instantane.db /data/instantane.db.server.key >/dev/null 2>&1 || true; rm -rf "$tmp"' EXIT
  echo "Sauvegarde à chaud du jeu $dataset (projet $project)…"
  dc exec -T locksy /app/locksy-server backup /data/instantane.db --with-key --force
  docker cp "$cid:/data/instantane.db" "$tmp/locksy.db"
  docker cp "$cid:/data/instantane.db.server.key" "$tmp/server.key"
  if [ -f "$out/manifest.json" ] && [ -f "$out/users.json" ]; then
    cp "$out/manifest.json" "$out/users.json" "$tmp/"
  else
    echo "Attention : $out/manifest.json ou users.json absent, instantané sans comptes de test." >&2
  fi
  (cd "$tmp" && sha256sum -- * > SHA256SUMS)
  cat > "$tmp/instantane.json" <<EOF
{
  "jeu": "$dataset",
  "cree_le": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "image": "$(docker inspect -f '{{.Config.Image}}' "$cid")",
  "image_id": "$(docker inspect -f '{{.Image}}' "$cid")",
  "octets_base": $(wc -c < "$tmp/locksy.db" | tr -d ' ')
}
EOF
  rm -rf "$dir"
  mv "$tmp" "$dir"
  echo "Instantané écrit : $dir ($(du -sh "$dir" | cut -f1))"
}

restore() {
  local cid volume
  for f in locksy.db server.key SHA256SUMS; do
    if [ ! -f "$dir/$f" ]; then echo "Instantané incomplet : $dir/$f absent (snapshot.sh save $dataset)." >&2; exit 1; fi
  done
  if ! (cd "$dir" && sha256sum --quiet -c SHA256SUMS); then
    echo "Instantané $dir altéré : empreintes SHA-256 différentes." >&2
    exit 1
  fi
  cid=$(dc ps -aq locksy)
  if [ -z "$cid" ]; then
    dc create locksy >/dev/null
    cid=$(dc ps -aq locksy)
  fi
  volume=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}' "$cid")
  if [ -z "$volume" ]; then echo "Volume /data du conteneur introuvable." >&2; exit 1; fi
  echo "Restauration du jeu $dataset dans le volume $volume (projet $project)…"
  dc stop locksy >/dev/null
  # Flux tar par l'entrée standard : aucun chemin Windows à monter.
  tar -C "$dir" -cf - locksy.db server.key | docker run --rm -i --network none -v "$volume:/data" "$BUSYBOX_IMAGE" sh -c \
    'find /data -mindepth 1 -delete && tar -xf - -C /data && chown -R 10001:10001 /data && chmod 600 /data/server.key'
  dc up -d --wait --wait-timeout 180 locksy
  if [ -f "$dir/manifest.json" ] && [ -f "$dir/users.json" ]; then
    mkdir -p "$out"
    cp "$dir/manifest.json" "$dir/users.json" "$out/"
  fi
  echo "Jeu $dataset restauré : http://$(dc port locksy 8743)"
}

"$action"
