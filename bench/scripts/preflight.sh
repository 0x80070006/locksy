#!/usr/bin/env bash
# Contrôles préalables d'une passe de banc (audit 05, §1.1). Mode d'emploi :
# bench/README.md. Ne modifie rien, sauf le compteur de limitation du
# serveur pour deux adresses de test tirées au hasard.
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
Contrôles préalables du banc de charge Locksy.

Usage : bash bench/scripts/preflight.sh [-p projet]

  -p projet   nom du projet docker compose (défaut : $BENCH_PROJECT, sinon locksy-bench)
  -h          affiche cette aide

Contrôles : processeurs et mémoire de Docker, image, cœurs du serveur et de
l'injecteur disjoints, sous-réseau du banc sans chevauchement, limites
appliquées au conteneur, santé du serveur, prise en compte de X-Forwarded-For
(61e prelogin depuis la même adresse refusé en 429, adresse suivante acceptée).

Codes de sortie :
  0  conforme : les mesures sont valables ;
  1  avertissements : le banc fonctionne, mais les mesures ne sont qu'indicatives
     (moins de 8 processeurs, moins de 4 Go pour Docker, autres conteneurs actifs…) ;
  2  bloquant : la passe ne doit pas être lancée (serveur absent ou en mauvaise santé,
     X-Forwarded-For ignoré, cœurs partagés, sous-réseau en conflit, usage invalide).
EOF
}

project="${BENCH_PROJECT:-locksy-bench}"
while [ $# -gt 0 ]; do
  case "$1" in
    -p) project="${2:?-p attend un nom de projet}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Argument inconnu : $1" >&2; usage >&2; exit 2 ;;
  esac
done
LOCKSY_IMAGE="${LOCKSY_IMAGE:-locksy-bench:local}"
LOCKSY_MEM="${LOCKSY_MEM:-512m}"
BENCH_SUBNET="${BENCH_SUBNET:-172.30.0.0/24}"
BENCH_SERVER_IP="${BENCH_SERVER_IP:-172.30.0.10}"
SERVER_CPUSET="${SERVER_CPUSET:-0,1}"
INJECTOR_CPUSET="${INJECTOR_CPUSET:-4-7}"
dc() { docker compose -p "$project" -f bench/docker-compose.bench.yml "$@"; }

warnings=0
failures=0
ok() { echo "  [ok]        $*"; }
warn() { echo "  [attention] $*"; warnings=$((warnings + 1)); }
fail() { echo "  [bloquant]  $*"; failures=$((failures + 1)); }

ip2int() {
  local IFS=. a b c d
  read -r a b c d <<<"$1"
  echo $(((a << 24) | (b << 16) | (c << 8) | d))
}
# Premier et dernier entier d'un réseau CIDR IPv4.
cidr_range() {
  local ip="${1%/*}" bits="${1#*/}" base mask
  [ "$bits" = "$1" ] && bits=32
  mask=$(((0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF))
  base=$(($(ip2int "$ip") & mask))
  echo "$base $((base | (~mask & 0xFFFFFFFF)))"
}
# « 0,1 » ou « 4-7 » ou « 0-1,4 » → liste de cœurs, un par ligne.
expand_cpuset() {
  local part
  for part in ${1//,/ }; do
    if [[ $part == *-* ]]; then seq "${part%-*}" "${part#*-}"; else echo "$part"; fi
  done
}
# Code HTTP d'une requête curl (corps ignoré). Pas de « -o /dev/null » : avec
# MSYS_NO_PATHCONV, le curl de Git Bash le prendrait pour un fichier Windows.
http_code() {
  { curl -s --max-time 15 -w '\n%{http_code}' "$@" || true; } | tail -n 1
}
# « 512m », « 1g », « 1024k » → octets (unités binaires, comme docker compose).
to_bytes() {
  local n="${1%[bBkKmMgG]}" u="${1: -1}"
  case "$u" in
    k|K) echo $((n * 1024)) ;;
    m|M) echo $((n * 1024 * 1024)) ;;
    g|G) echo $((n * 1024 * 1024 * 1024)) ;;
    *) echo "$n" ;;
  esac
}

echo "Contrôles préalables du banc (projet $project)"

# --- Docker : processeurs et mémoire -------------------------------------
if ! info=$(docker info --format '{{.NCPU}} {{.MemTotal}}' 2>/dev/null); then
  echo "  [bloquant] Docker injoignable : démarrez Docker Desktop." >&2
  exit 2
fi
read -r ncpu memtotal <<<"$info"
mem_mib=$((memtotal / 1024 / 1024))
if [ "$ncpu" -ge 8 ]; then ok "$ncpu processeurs pour Docker"
elif [ "$ncpu" -ge 6 ]; then warn "$ncpu processeurs pour Docker (8 attendus) : serveur et injecteur se gênent, mesures indicatives"
else fail "$ncpu processeurs pour Docker : 6 au minimum (2 pour le serveur, 4 pour l'injecteur)"
fi
# Docker Desktop avec 4 Go déclarés expose environ 3,7 Gio.
if [ "$mem_mib" -ge 3700 ]; then ok "$mem_mib Mio de mémoire pour Docker"
else warn "$mem_mib Mio de mémoire pour Docker (4 Go conseillés : .wslconfig ou réglages de Docker Desktop)"
fi

# --- Image -------------------------------------------------------------------
if docker image inspect "$LOCKSY_IMAGE" >/dev/null 2>&1; then ok "image $LOCKSY_IMAGE présente"
else fail "image $LOCKSY_IMAGE absente : bash bench/scripts/bench-up.sh la construit"
fi

# --- Cœurs ---------------------------------------------------------------------
server_cpus=$(expand_cpuset "$SERVER_CPUSET" | sort -n | uniq)
injector_cpus=$(expand_cpuset "$INJECTOR_CPUSET" | sort -n | uniq)
shared=$(comm -12 <(echo "$server_cpus" | sort) <(echo "$injector_cpus" | sort) | tr '\n' ' ')
too_high=$(printf '%s\n%s\n' "$server_cpus" "$injector_cpus" | awk -v n="$ncpu" '$1 >= n' | sort -n | uniq | tr '\n' ' ')
n_server=$(echo "$server_cpus" | wc -l | tr -d ' ')
if [ -n "$too_high" ]; then fail "cœurs ${too_high}inexistants (Docker en voit $ncpu : 0 à $((ncpu - 1)))"
elif [ -n "$shared" ]; then fail "cœurs partagés entre serveur ($SERVER_CPUSET) et injecteur ($INJECTOR_CPUSET) : $shared"
else ok "cœurs disjoints : serveur $SERVER_CPUSET, injecteur $INJECTOR_CPUSET"
fi
if [ "$n_server" -ne 2 ]; then warn "le serveur dispose de $n_server cœur(s) (SERVER_CPUSET) : le profil de référence en prévoit 2"; fi

# --- Sous-réseau -------------------------------------------------------------
if [[ ! $BENCH_SUBNET =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
  fail "BENCH_SUBNET illisible : $BENCH_SUBNET (attendu : CIDR IPv4, par exemple 172.30.0.0/24)"
else
  read -r lo hi <<<"$(cidr_range "$BENCH_SUBNET")"
  ip=$(ip2int "$BENCH_SERVER_IP")
  if [ "$ip" -le "$lo" ] || [ "$ip" -ge "$hi" ]; then
    fail "BENCH_SERVER_IP ($BENCH_SERVER_IP) hors de BENCH_SUBNET ($BENCH_SUBNET)"
  fi
  conflicts=""
  # shellcheck disable=SC2046 # liste d'identifiants de réseaux, découpée volontairement
  while read -r name subnets; do
    [ "$name" = "${project}_bench" ] && continue
    for s in $subnets; do
      [[ $s == *:* ]] && continue
      read -r olo ohi <<<"$(cidr_range "$s")"
      if [ "$olo" -le "$hi" ] && [ "$lo" -le "$ohi" ]; then conflicts+="$name ($s) "; fi
    done
  done < <(docker network inspect $(docker network ls -q) --format '{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}')
  if [ -n "$conflicts" ]; then fail "BENCH_SUBNET $BENCH_SUBNET chevauche : $conflicts(changez BENCH_SUBNET et BENCH_SERVER_IP)"
  else ok "sous-réseau $BENCH_SUBNET libre"
  fi
fi

# --- Conteneur du serveur -----------------------------------------------------
cid=$(dc ps -q locksy 2>/dev/null || true)
if [ -z "$cid" ]; then
  fail "serveur non démarré : bash bench/scripts/bench-up.sh -p $project"
else
  read -r health cpuset nano mem pids ro <<<"$(docker inspect "$cid" --format \
    '{{if .State.Health}}{{.State.Health.Status}}{{else}}inconnue{{end}} {{.HostConfig.CpusetCpus}} {{.HostConfig.NanoCpus}} {{.HostConfig.Memory}} {{.HostConfig.PidsLimit}} {{.HostConfig.ReadonlyRootfs}}')"
  if [ "$health" = healthy ]; then ok "serveur en bonne santé (conteneur $(docker inspect -f '{{.Name}}' "$cid" | tr -d /))"
  else fail "serveur en état « $health »"
  fi
  case "$mem" in
    536870912) profile="REF-PROD (512 Mo)" ;;
    1073741824) profile="REF-1G (1 Go)" ;;
    *) profile="" ;;
  esac
  if [ "$cpuset" = "$SERVER_CPUSET" ] && [ "$nano" = 2000000000 ] && [ -n "$profile" ] && [ "$pids" = 128 ] && [ "$ro" = true ]; then
    ok "limites appliquées : profil $profile, cœurs $cpuset, 2 vCPU, 128 PID, racine en lecture seule"
  else
    fail "limites du conteneur hors référence (cœurs $cpuset, NanoCpus $nano, mémoire $mem octets, PID $pids, lecture seule $ro) : relancez bench-up.sh"
  fi
  # Profil en service différent de LOCKSY_MEM (par exemple bench-up.sh --profile REF-1G).
  if [ -n "$profile" ] && [ "$mem" != "$(to_bytes "$LOCKSY_MEM")" ]; then
    warn "profil $profile en service alors que LOCKSY_MEM=$LOCKSY_MEM : vérifiez le profil voulu"
  fi
  seen=$(dc exec -T locksy nproc 2>/dev/null | tr -d '\r' || echo "?")
  if [ "$seen" = "$n_server" ]; then ok "le serveur voit $seen processeurs (porte Argon2 dimensionnée en conséquence)"
  else warn "le serveur voit « $seen » processeurs, $n_server attendus"
  fi

  # --- X-Forwarded-For --------------------------------------------------------
  hostport=$(dc port locksy 8743 2>/dev/null || true)
  base="http://$hostport"
  if [ -z "$hostport" ] || [ "$(http_code "$base/api/health")" != 200 ]; then
    fail "le serveur ne répond pas sur $base/api/health"
  else
    ok "serveur joignable sur $base"
    prelogin() {
      http_code -X POST "$base/api/auth/prelogin" \
        -H 'content-type: application/json' -H "x-forwarded-for: $1" -d '{"email":"controle@banc.test"}'
    }
    # Deux adresses tirées au hasard : un second contrôle dans la minute reste valable.
    oct="$((RANDOM % 250 + 1)).$((RANDOM % 250 + 1))"
    first="10.9.$oct"
    refused=0
    for _ in $(seq 1 60); do [ "$(prelogin "$first")" = 200 ] || refused=$((refused + 1)); done
    last=$(prelogin "$first")
    other=$(prelogin "10.8.$oct")
    if [ "$refused" -eq 0 ] && [ "$last" = 429 ] && [ "$other" = 200 ]; then
      ok "X-Forwarded-For pris en compte : 61e prelogin depuis $first → 429, depuis 10.8.$oct → 200"
    else
      fail "X-Forwarded-For non pris en compte (refus avant la limite : $refused, 61e : $last, autre adresse : $other) ; vérifiez LOCKSY_TRUSTED_PROXIES=$BENCH_SUBNET"
    fi
  fi
fi

# --- Autres charges --------------------------------------------------------
others=$(docker ps --format '{{.Names}} {{.Label "com.docker.compose.project"}}' | awk -v p="$project" '$2 != p {print $1}' | tr '\n' ' ')
if [ -n "$others" ]; then warn "autres conteneurs actifs : ${others}(mesures indicatives)"
else ok "aucun autre conteneur actif"
fi
echo "  Rappel : fermez navigateur et compilations, suspendez l'antivirus sur le dossier pendant une mesure."

if [ "$failures" -gt 0 ]; then
  echo "Résultat : $failures contrôle(s) bloquant(s), $warnings avertissement(s). Passe refusée."
  exit 2
elif [ "$warnings" -gt 0 ]; then
  echo "Résultat : $warnings avertissement(s). Banc utilisable, mesures indicatives."
  exit 1
fi
echo "Résultat : conforme."
