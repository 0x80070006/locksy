#!/usr/bin/env bash
# Bibliothèque commune des recettes d'exploitation de Locksy (ops-tests/*.sh).
# Sourcée en tête de chaque script : mode strict, chemins, options communes,
# projets docker compose (supprimés à la sortie), volumes, chronomètres et
# rapport (resultats.json et resultats.md). Mode d'emploi : ops-tests/README.md.
#
# Aucune fonction n'écrit dans le dépôt hors de bench/results/ (ignoré par git).

set -euo pipefail
export MSYS_NO_PATHCONV=1

# Chemin compris par les programmes Windows (docker, node) sous Git Bash, et par bash.
chemin_hote() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
}

OPS_RACINE=$(chemin_hote "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)")
cd "$OPS_RACINE"

# ------------------------------------------------------------ Réglages

OPS_PROJET=${OPS_PROJET:-q5-ops}
OPS_JEU=${OPS_JEU:-}
OPS_GARDER=0
# Image du serveur courant (N). L'étiquette partagée n'est jamais reconstruite ici.
OPS_IMAGE=${OPS_IMAGE:-locksy-e2e-server:fast}
# Image de la version 1.0.0 (N-1), construite par ops-tests/v100/construire.sh.
OPS_IMAGE_V100=${OPS_IMAGE_V100:-locksy-ops:1.0.0}
BUSYBOX_IMAGE=${BUSYBOX_IMAGE:-busybox:1.37.0}
OPS_SCRIPT=$(basename "$0" .sh)
OPS_COMPOSE=ops-tests/compose.ops.yml
OPS_BANC=bench/docker-compose.bench.yml

_OPS_PROJETS=()     # projets compose ouverts par le script (supprimés à la sortie)
_OPS_TEMP=()        # dossiers temporaires hors du dépôt
_OPS_CONTENEURS=()  # conteneurs lancés hors compose
_OPS_ECHECS=0

# ------------------------------------------------------------ Affichage

etape() { printf '\n== %s\n' "$*" >&2; }
info() { printf '   %s\n' "$*" >&2; }
avertir() { printf '   ATTENTION : %s\n' "$*" >&2; }

erreur_usage() {
  printf 'Erreur : %s\n\n' "$1" >&2
  usage >&2
  exit 2
}

# Arrêt immédiat sur une erreur d'environnement (pas un verdict de recette).
fatal() {
  printf 'Erreur : %s\n' "$*" >&2
  exit 1
}

# code_de <commande…> : exécute sans arrêter le script ; code de sortie dans $CODE.
code_de() {
  set +e
  "$@"
  CODE=$?
  set -e
}

# ------------------------------------------------------------ Options

# Options communes : -p, --jeu, --garder, -h. Un script peut définir
# option_script "$@" : elle traite son option et pose OPS_DECALAGE (nombre
# d'arguments consommés, 0 si l'option lui est inconnue).
lire_options() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -p)
        [ $# -ge 2 ] && [[ ${2:-} =~ ^[a-z0-9][a-z0-9_-]*$ ]] || erreur_usage "-p attend un nom de projet (minuscules, chiffres, - et _)"
        OPS_PROJET=$2; shift 2 ;;
      --jeu)
        case "${2:-}" in E2E|M) OPS_JEU=$2 ;; *) erreur_usage "--jeu attend E2E ou M" ;; esac
        shift 2 ;;
      --garder) OPS_GARDER=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *)
        OPS_DECALAGE=0
        if declare -F option_script >/dev/null; then option_script "$@"; fi
        [ "$OPS_DECALAGE" -gt 0 ] || erreur_usage "argument inconnu : $1"
        shift "$OPS_DECALAGE" ;;
    esac
  done
}

# ------------------------------------------------------------ Sorties

# Dossier de sortie (ignoré par git) : $OPS_OUT, sinon bench/results/ops/<horodatage>-<script>.
preparer_sortie() {
  OPS_OUT=${OPS_OUT:-bench/results/ops/$(date +%Y%m%d-%H%M%S)-$OPS_SCRIPT}
  mkdir -p "$OPS_OUT"
  OPS_OUT=$(chemin_hote "$(cd "$OPS_OUT" && pwd)")
  : > "$OPS_OUT/.resultats.tsv"
  : > "$OPS_OUT/.mesures.tsv"
  info "sorties : $(chemin_relatif "$OPS_OUT")"
  trap _ops_sortie EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
}

chemin_relatif() { printf '%s' "${1#"$OPS_RACINE"/}"; }

# resultat <nom> <ok|echec|info> <détail> : un contrôle de la recette.
resultat() {
  local nom=$1 etat=$2 detail=${3:-}
  case "$etat" in
    ok) info "OK      $nom${detail:+ : $detail}" ;;
    echec) info "ÉCHEC   $nom${detail:+ : $detail}"; _OPS_ECHECS=$((_OPS_ECHECS + 1)) ;;
    info) info "CONSTAT $nom${detail:+ : $detail}" ;;
    *) fatal "état de résultat inconnu : $etat" ;;
  esac
  printf '%s\t%s\t%s\n' "$nom" "$etat" "${detail//$'\n'/ }" >> "$OPS_OUT/.resultats.tsv"
}

# verifier <nom> <détail> <commande…> : ok si la commande réussit, échec sinon.
verifier() {
  local nom=$1 detail=$2; shift 2
  if "$@"; then resultat "$nom" ok "$detail"; else resultat "$nom" echec "$detail"; fi
}

# mesure <nom> <valeur> <unité> : chiffre reporté dans le rapport.
mesure() {
  info "mesure  $1 = $2 $3"
  printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$OPS_OUT/.mesures.tsv"
}

# ------------------------------------------------------------ Chronomètres

maintenant_ms() { date +%s%3N; }
declare -A _OPS_CHRONOS=()
chrono_debut() { _OPS_CHRONOS[$1]=$(maintenant_ms); }
# chrono_fin <nom> : affiche la durée écoulée en millisecondes.
chrono_fin() {
  local debut=${_OPS_CHRONOS[$1]:?chronomètre $1 non démarré}
  echo $(( $(maintenant_ms) - debut ))
}
# Millisecondes en secondes lisibles (« 12,3 »).
en_secondes() { awk -v ms="$1" 'BEGIN { s = sprintf("%.1f", ms / 1000); sub(/\./, ",", s); print s }'; }

# ------------------------------------------------------------ Projets compose

# Surcouche compose facultative (OPS_SURCOUCHE), appliquée au service locksy
# du banc comme à celui des recettes : diagnostic d'une configuration non livrée.
_surcouche() { if [ -n "${OPS_SURCOUCHE:-}" ]; then printf '%s\n' -f "$OPS_SURCOUCHE"; fi; }

# ops_dc <projet> <arguments…> : serveur des recettes (ops-tests/compose.ops.yml).
# L'image se choisit par OPS_SERVEUR_IMAGE (défaut : $OPS_IMAGE).
ops_dc() {
  local p=$1; shift
  local surcouche; mapfile -t surcouche < <(_surcouche)
  OPS_SERVEUR_IMAGE=${OPS_SERVEUR_IMAGE:-$OPS_IMAGE} docker compose -p "$p" -f "$OPS_COMPOSE" "${surcouche[@]}" "$@"
}

# Sous-réseau du banc propre au projet : jamais celui par défaut (172.30.0.0/24),
# qu'un autre lot peut utiliser au même moment.
_octet_banc() { echo $(( 150 + $(printf '%s' "$1" | cksum | cut -d' ' -f1) % 100 )); }
env_banc() {
  local o; o=$(_octet_banc "$1")
  export BENCH_SUBNET="172.30.$o.0/24" BENCH_SERVER_IP="172.30.$o.10"
  export LOCKSY_IMAGE=${LOCKSY_IMAGE:-$OPS_IMAGE}
}
# banc_dc <projet> <arguments…> : compose du banc (bench/docker-compose.bench.yml).
banc_dc() {
  local p=$1; shift
  local surcouche; mapfile -t surcouche < <(_surcouche)
  ( env_banc "$p"; docker compose -p "$p" -f "$OPS_BANC" "${surcouche[@]}" "$@" )
}
# banc_script <projet> <script> <arguments…> : bench/scripts/<script> sur ce projet.
banc_script() {
  local p=$1 s=$2; shift 2
  ( env_banc "$p"; bash "bench/scripts/$s" -p "$p" "$@" )
}

# Retient un projet à supprimer (down -v) à la sortie. Type : ops ou banc.
ouvrir_projet() {
  local type=$1 p=$2
  _OPS_PROJETS+=("$type:$p")
}

# Supprime tout de suite un projet (conteneurs, réseau, volumes).
fermer_projet() {
  local type=$1 p=$2
  if [ "$type" = banc ]; then
    banc_dc "$p" --profile tools down -v --remove-orphans >/dev/null 2>&1 || true
  else
    ops_dc "$p" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}

# Dossier temporaire HORS du dépôt, supprimé à la sortie ; chemin dans
# OPS_TEMP_DIR (pas de sous-shell : la liste des dossiers à supprimer doit
# rester dans le shell du script).
dossier_temporaire() {
  OPS_TEMP_DIR=$(chemin_hote "$(mktemp -d)")
  _OPS_TEMP+=("$OPS_TEMP_DIR")
}

# Conteneur lancé par « docker run » ou « compose run -d », supprimé à la sortie.
retenir_conteneur() { _OPS_CONTENEURS+=("$1"); }

# ------------------------------------------------------------ Serveur

# port <projet> [ops|banc] : adresse hôte du serveur (127.0.0.1:<port aléatoire>).
port() {
  local p=$1 type=${2:-ops} a
  if [ "$type" = banc ]; then a=$(banc_dc "$p" port locksy 8743); else a=$(ops_dc "$p" port locksy 8743); fi
  printf '%s' "${a//$'\r'/}"
}

# attendre_sante <url> <délai en s> : attend /api/health en 200 ; code 1 au-delà.
attendre_sante() {
  local url=$1 delai=${2:-120} fin=$(( $(date +%s) + ${2:-120} ))
  while [ "$(date +%s)" -lt "$fin" ]; do
    if curl -fsS --max-time 3 "$url/api/health" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  printf 'Le serveur %s ne répond pas après %s s.\n' "$url" "$delai" >&2
  return 1
}

# version_serveur <url> : champ « version » de /api/health.
version_serveur() {
  curl -fsS --max-time 5 "$1/api/health" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>process.stdout.write(String(JSON.parse(s).version||"")))'
}

# lancer_detache <projet> <nom> [env K=V…] [-- commande…] : démarre le service
# locksy par « compose run -d » (même volume, port publié) et renvoie aussitôt.
lancer_detache() {
  local p=$1 nom=$2; shift 2
  local envs=()
  while [ $# -gt 0 ] && [ "$1" != "--" ]; do envs+=(-e "$1"); shift; done
  [ "${1:-}" = "--" ] && shift
  docker rm -f "$nom" >/dev/null 2>&1 || true
  retenir_conteneur "$nom"
  ops_dc "$p" run -d --no-deps --service-ports --name "$nom" "${envs[@]}" locksy "$@" >/dev/null
}

# attendre_fin <conteneur> <délai en s> : code de sortie du conteneur, ou
# « en_marche » s'il tourne encore après le délai.
attendre_fin() {
  local nom=$1 fin=$(( $(date +%s) + $2 )) etat
  while [ "$(date +%s)" -lt "$fin" ]; do
    etat=$(docker inspect -f '{{.State.Status}}' "$nom" 2>/dev/null || echo absent)
    if [ "$etat" = exited ] || [ "$etat" = dead ]; then
      docker inspect -f '{{.State.ExitCode}}' "$nom"
      return 0
    fi
    sleep 1
  done
  echo en_marche
}

# ------------------------------------------------------------ Volumes et fichiers

empreinte() { sha256sum "$1" | cut -d' ' -f1; }
taille() { wc -c < "$1" | tr -d ' '; }

volume_de() { printf '%s_data' "$1"; }

# copier_du_volume <volume> <chemin dans /data> <dossier hôte> : copie par flux tar.
copier_du_volume() {
  local vol=$1 chemin=$2 dest=$3
  mkdir -p "$dest"
  docker run --rm --network none -v "$vol:/data:ro" "$BUSYBOX_IMAGE" tar -C /data -cf - "$chemin" | tar -xf - -C "$dest"
}

# vers_le_volume <volume> <dossier hôte> <fichiers…> : vide /data puis y dépose
# les fichiers (propriétaire 10001, server.key en 600), comme snapshot.sh restore.
vers_le_volume() {
  local vol=$1 src=$2; shift 2
  tar -C "$src" -cf - "$@" | docker run --rm -i --network none -v "$vol:/data" "$BUSYBOX_IMAGE" sh -c \
    'find /data -mindepth 1 -delete && tar -xf - -C /data && chown -R 10001:10001 /data && if [ -f /data/server.key ]; then chmod 600 /data/server.key; fi'
}

# lister_volume <volume> : fichiers de /data avec leur taille.
lister_volume() {
  docker run --rm --network none -v "$1:/data:ro" "$BUSYBOX_IMAGE" sh -c 'cd /data && for f in * .[!.]*; do [ -e "$f" ] && echo "$f $(wc -c < "$f")"; done; true'
}

# extraire_de_image <image> <chemin dans l'image> <fichier hôte> : copie un fichier
# d'une image sans la démarrer (par exemple /app/web/locksy.wasm).
extraire_de_image() {
  local cid
  cid=$(docker create "$1")
  code_de docker cp "$cid:$2" "$(chemin_hote "$3")"
  docker rm "$cid" >/dev/null
  return "$CODE"
}

# base_js <commande> … : ops-tests/lib/base.mjs (lecture sur une copie).
base_js() { node ops-tests/lib/base.mjs "$@"; }

# json_champ <fichier json> <expression JS sur v> : extrait une valeur.
json_champ() {
  node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));const r=(new Function("v","return ("+process.argv[2]+")"))(v);process.stdout.write(typeof r==="object"?JSON.stringify(r):String(r))' "$1" "$2"
}

# assurer_instantane <jeu> : bench/snapshots/<jeu> (base, clé, manifeste,
# comptes) ; à défaut, sème le jeu sur un banc temporaire <projet>-semis.
assurer_instantane() {
  local jeu=$1 p=$OPS_PROJET-semis
  if [ -f "bench/snapshots/$jeu/locksy.db" ] && [ -f "bench/snapshots/$jeu/users.json" ]; then
    mkdir -p "bench/seed/out/$jeu"
    cp "bench/snapshots/$jeu/manifest.json" "bench/snapshots/$jeu/users.json" "bench/seed/out/$jeu/"
    info "instantané du jeu $jeu : bench/snapshots/$jeu"
    return 0
  fi
  info "instantané du jeu $jeu absent : semis sur le banc $p"
  ouvrir_projet banc "$p"
  code_de banc_script "$p" bench-up.sh
  [ "$CODE" -le 1 ] || fatal "banc $p indisponible (bench-up.sh : code $CODE)"
  banc_script "$p" seed.sh --workers 2 "$jeu"
  fermer_projet banc "$p"
}

# ------------------------------------------------------------ Image 1.0.0

# sources_v100 : sources de la 1.0.0 (git archive HEAD) dans un dossier
# temporaire HORS du dépôt, avec une copie de bench/seed pour le client 1.0.0
# (bench/seed/worker.mjs résout ../../web/js). Pose V100_SRC.
sources_v100() {
  if [ -n "${V100_SRC:-}" ] && [ -d "$V100_SRC/web/js" ]; then return 0; fi
  dossier_temporaire
  V100_SRC=$OPS_TEMP_DIR
  git -C "$OPS_RACINE" archive --format=tar "${V100_REF:-HEAD}" | tar -x -C "$V100_SRC"
  local version
  version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$V100_SRC/Cargo.toml" | head -1)
  [ "$version" = 1.0.0 ] || fatal "git ${V100_REF:-HEAD} est en version « $version », 1.0.0 attendue"
  mkdir -p "$V100_SRC/bench/seed"
  cp bench/seed/*.mjs "$V100_SRC/bench/seed/"
}

# image_v100 : construit $OPS_IMAGE_V100 si elle manque (ou si OPS_RECONSTRUIRE=1).
# Repli sur locksy:1.0.0 si la construction échoue (V1.6).
image_v100() {
  if [ "${OPS_RECONSTRUIRE:-0}" != 1 ] && docker image inspect "$OPS_IMAGE_V100" >/dev/null 2>&1; then
    info "image 1.0.0 présente : $OPS_IMAGE_V100"
    return 0
  fi
  if bash ops-tests/v100/construire.sh "$OPS_IMAGE_V100"; then return 0; fi
  avertir "construction de $OPS_IMAGE_V100 en échec : repli sur l'image locale locksy:1.0.0"
  docker image inspect locksy:1.0.0 >/dev/null 2>&1 || fatal "aucune image 1.0.0 disponible"
  OPS_IMAGE_V100=locksy:1.0.0
}

# ------------------------------------------------------------ Sortie

_ops_sortie() {
  local code=$?
  trap - EXIT INT TERM
  set +e
  local c entree
  # Tâches de fond du script (k6, échantillonneur) arrêtées avec lui.
  for c in $(jobs -p); do kill "$c" 2>/dev/null; done
  for c in "${_OPS_CONTENEURS[@]}"; do docker rm -f "$c" >/dev/null 2>&1; done
  if [ "$OPS_GARDER" = 1 ]; then
    for entree in "${_OPS_PROJETS[@]}"; do info "projet conservé (--garder) : ${entree#*:}"; done
  else
    for entree in "${_OPS_PROJETS[@]}"; do fermer_projet "${entree%%:*}" "${entree#*:}"; done
  fi
  for c in "${_OPS_TEMP[@]}"; do rm -rf "$c"; done
  if [ -n "${OPS_OUT:-}" ] && [ -f "$OPS_OUT/.resultats.tsv" ]; then
    if [ "$code" -ne 0 ] && [ "$_OPS_ECHECS" -eq 0 ]; then
      printf 'interruption\techec\tle script s'"'"'est arrêté avant la fin (code %s)\n' "$code" >> "$OPS_OUT/.resultats.tsv"
    fi
    node ops-tests/lib/rapport.mjs "$OPS_OUT" "$OPS_SCRIPT" "${OPS_JEU:-}" >&2 || true
  fi
  if [ "$code" -eq 0 ] && [ "$_OPS_ECHECS" -gt 0 ]; then code=1; fi
  exit "$code"
}

# terminer : verdict final (code 0 si aucun contrôle en échec, 1 sinon).
terminer() {
  if [ "$_OPS_ECHECS" -gt 0 ]; then
    printf '\nVerdict %s : ÉCHEC (%s contrôle(s) en échec).\n' "$OPS_SCRIPT" "$_OPS_ECHECS" >&2
    exit 1
  fi
  printf '\nVerdict %s : RÉUSSITE.\n' "$OPS_SCRIPT" >&2
  exit 0
}
