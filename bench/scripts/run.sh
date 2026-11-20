#!/usr/bin/env bash
# Une passe de charge : restauration du jeu, contrôles préalables,
# échantillonneur système, scénario k6, collecte et rapport. Le code de sortie
# est le verdict du rapport. Mode d'emploi : bench/k6/README.md.
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
Une passe de charge k6 sur le serveur du banc, avec rapport.

Usage : bash bench/scripts/run.sh [-p projet] --dataset S|M|L --scenario <nom> [options]

  -p projet             projet docker compose (défaut : $BENCH_PROJECT, sinon locksy-bench)
  --dataset S|M|L       jeu restauré avant la passe (instantané bench/snapshots/<jeu>/)
  --scenario <nom>      fichier de bench/k6/scenarios/ (préfixe accepté : 03, 07-journee-type…)
  --vus N               utilisateurs virtuels (variable VUS du scénario)
  --duration D          durée principale du scénario (30s, 5m, 2h : variable DURATION)
  --profile P           REF-PROD (512 Mo, défaut) ou REF-1G (1 Go)
  --env K=V             variable de plus pour k6 (répétable : RATE=20, PAUSE=10…)
  --server-env K=V      variable de plus pour le serveur (répétable : LOCKSY_RATELIMIT_LOGIN_IP=300)
  --reference DIR       passe de comparaison (scénario 11 : une passe 07 à 200 VU)
  --no-restore          garde les données en place (mise au point seulement : résultats non reproductibles)
  --down                supprime conteneurs, réseau et volume à la fin (docker compose down -v)
  -h                    affiche cette aide

Variables : K6_CPUS et K6_MEM limitent l'injecteur (ex. 2 et 2g, poste partagé) ;
KILLS (5) et INTERVAL (120 s) règlent le scénario 10 ; LOCKSY_IMAGE, LOCKSY_ENV
et LOCKSY_MEM sont repris du conteneur en service s'ils ne sont pas fixés.

Résultats : bench/results/<horodatage>-<scénario>[-<N>vu]/ : summary.json, stats.csv,
context.json, preflight.txt, k6.log, rapport.md, cpu.svg, memoire.svg, pids.svg.
Codes de sortie : 0 passe, 1 échec, 2 passe impossible ou usage invalide,
3 indicative avec au moins un seuil bloquant dépassé.
EOF
}

project="${BENCH_PROJECT:-locksy-bench}"
dataset=""
scenario=""
vus=""
duration=""
profile=""
reference=""
restore=1
down=0
k6_env=()
server_env=()
while [ $# -gt 0 ]; do
  case "$1" in
    -p) project="${2:?-p attend un nom de projet}"; shift 2 ;;
    --dataset) dataset="${2:-}"; shift 2 ;;
    --scenario) scenario="${2:-}"; shift 2 ;;
    --vus) vus="${2:-}"; shift 2 ;;
    --duration) duration="${2:-}"; shift 2 ;;
    --profile) profile="${2:-}"; shift 2 ;;
    --env) k6_env+=("${2:?--env attend K=V}"); shift 2 ;;
    --server-env) server_env+=("${2:?--server-env attend K=V}"); shift 2 ;;
    --reference) reference="${2:?--reference attend un dossier}"; shift 2 ;;
    --no-restore) restore=0; shift ;;
    --down) down=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Argument inconnu : $1" >&2; usage >&2; exit 2 ;;
  esac
done
if [[ ! $dataset =~ ^(S|M|L)$ ]] || [ -z "$scenario" ]; then usage >&2; exit 2; fi
if [ -n "$vus" ] && [[ ! $vus =~ ^[1-9][0-9]*$ ]]; then echo "--vus attend un entier positif : $vus" >&2; exit 2; fi
if [ -n "$duration" ] && [[ ! $duration =~ ^[1-9][0-9]*(s|m|h)$ ]]; then echo "--duration attend 30s, 5m ou 2h : $duration" >&2; exit 2; fi
for kv in "${k6_env[@]}" "${server_env[@]}"; do
  if [[ ! $kv =~ ^[A-Z_][A-Z0-9_]*=.*$ ]]; then echo "Variable invalide (K=V attendu) : $kv" >&2; exit 2; fi
done
case "$profile" in
  "") ;;
  REF-PROD) export LOCKSY_MEM=512m ;;
  REF-1G) export LOCKSY_MEM=1g ;;
  *) echo "Profil inconnu : « $profile » (REF-PROD ou REF-1G)." >&2; exit 2 ;;
esac
if [ -n "$reference" ] && [ ! -f "$reference/summary.json" ]; then echo "Passe de référence sans summary.json : $reference" >&2; exit 2; fi

shopt -s nullglob
matches=(bench/k6/scenarios/"$scenario"*.js)
shopt -u nullglob
if [ "${#matches[@]}" -ne 1 ]; then
  echo "Scénario « $scenario » : ${#matches[@]} fichier(s) correspondant(s) dans bench/k6/scenarios/." >&2
  exit 2
fi
name=$(basename "${matches[0]}" .js)
if [ ! -f "bench/snapshots/$dataset/locksy.db" ] && [ "$restore" = 1 ]; then
  echo "Instantané du jeu $dataset absent : bash bench/scripts/seed.sh -p $project $dataset" >&2
  exit 2
fi
if [ ! -f "bench/seed/out/$dataset/users.json" ] && [ "$restore" = 0 ]; then
  echo "Comptes du jeu $dataset absents (bench/seed/out/$dataset/users.json)." >&2
  exit 2
fi

base_dc() { docker compose -p "$project" -f bench/docker-compose.bench.yml "$@"; }

# Configuration du conteneur en service reprise si elle n'est pas fixée :
# une restauration ne doit pas changer d'image ni de profil par surprise.
cid=$(base_dc ps -aq locksy 2>/dev/null || true)
if [ -n "$cid" ]; then
  if [ -z "${LOCKSY_IMAGE:-}" ]; then LOCKSY_IMAGE=$(docker inspect -f '{{.Config.Image}}' "$cid"); export LOCKSY_IMAGE; fi
  if [ -z "${LOCKSY_ENV:-}" ]; then
    LOCKSY_ENV=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$cid" | sed -n 's/^LOCKSY_ENV=//p' | tr -d '\r')
    export LOCKSY_ENV="${LOCKSY_ENV:-production}"
  fi
  if [ -z "${LOCKSY_MEM:-}" ]; then
    mem=$(docker inspect -f '{{.HostConfig.Memory}}' "$cid")
    if [ "$mem" = 1073741824 ]; then export LOCKSY_MEM=1g; else export LOCKSY_MEM=512m; fi
  fi
fi
export LOCKSY_MEM="${LOCKSY_MEM:-512m}"
# Les compteurs de réglages (/api/test/counters) n'existent qu'en mode test.
if [ "$name" = "11-reglages" ]; then export LOCKSY_ENV=test; fi

stamp=$(date -u +%Y%m%d-%H%M%S)
run="${stamp}-${name}${vus:+-${vus}vu}"
out="bench/results/$run"
mkdir -p "$out"
echo "Passe $run (projet $project, jeu $dataset, mémoire $LOCKSY_MEM, image ${LOCKSY_IMAGE:-locksy-bench:local})"

# Fichier compose supplémentaire : réglages du serveur et limites de l'injecteur.
files=(-f bench/docker-compose.bench.yml)
if [ "${#server_env[@]}" -gt 0 ] || [ -n "${K6_CPUS:-}" ] || [ -n "${K6_MEM:-}" ]; then
  {
    echo "# Écrit par run.sh pour la passe $run."
    echo "services:"
    if [ "${#server_env[@]}" -gt 0 ]; then
      echo "  locksy:"
      echo "    environment:"
      for kv in "${server_env[@]}"; do echo "      ${kv%%=*}: \"${kv#*=}\""; done
    fi
    if [ -n "${K6_CPUS:-}" ] || [ -n "${K6_MEM:-}" ]; then
      echo "  k6:"
      if [ -n "${K6_CPUS:-}" ]; then echo "    cpus: ${K6_CPUS}"; fi
      if [ -n "${K6_MEM:-}" ]; then echo "    mem_limit: ${K6_MEM}"; fi
    fi
  } > "$out/compose.override.yml"
  files+=(-f "$out/compose.override.yml")
fi
dc() { docker compose -p "$project" "${files[@]}" "$@"; }

sampler=""
k6_name="${project}-k6-${stamp}"
cleanup() {
  if [ -n "$sampler" ]; then kill "$sampler" 2>/dev/null || true; wait "$sampler" 2>/dev/null || true; sampler=""; fi
  docker rm -f "$k6_name" "$k6_name-verif" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'echo "Passe interrompue." >&2; exit 2' INT TERM

now_ms() { local t="$EPOCHREALTIME"; echo $(( ${t%[.,]*} * 1000 + 10#${t#*[.,]} / 1000 )); }

# 1. Données : instantané du jeu (reproductible), puis réglages du serveur.
if [ "$restore" = 1 ]; then
  bash bench/scripts/snapshot.sh -p "$project" restore "$dataset"
fi
if [ "${#server_env[@]}" -gt 0 ] || [ "$restore" = 0 ]; then
  dc up -d --wait --wait-timeout 180 locksy
fi

# 2. Contrôles préalables : 2 = pas de passe ; 1 = mesures indicatives.
set +e
bash bench/scripts/preflight.sh -p "$project" > "$out/preflight.txt" 2>&1
preflight=$?
set -e
tail -n 1 "$out/preflight.txt"
if [ "$preflight" -ge 2 ]; then
  echo "preflight.sh bloquant : passe annulée (détail : $out/preflight.txt)." >&2
  exit 2
fi

cid=$(dc ps -q locksy)
cname=$(docker inspect -f '{{.Name}}' "$cid" | sed 's#^/##')

# 3. Échantillonneur : 5 s de repos avant k6 (mémoire de base).
bash bench/scripts/sample-stats.sh "$cname" "$out/stats.csv" 2>>"$out/echantillonneur.log" &
sampler=$!
sleep 5

envs=(-e "DATASET=$dataset" -e "RUN=$run")
if [ -n "$vus" ]; then envs+=(-e "VUS=$vus"); fi
kills="${KILLS:-5}"
interval="${INTERVAL:-120}"
if [ -z "$duration" ] && [ "$name" = "10-arret-brutal" ]; then duration="$(( (kills + 1) * interval ))s"; fi
if [ -n "$duration" ]; then envs+=(-e "DURATION=$duration"); fi
for kv in "${k6_env[@]}"; do envs+=(-e "$kv"); done

k6_run() { # <nom du conteneur> <arguments k6…>
  local cname_k6="$1"
  shift
  dc --profile tools run --rm --no-deps --name "$cname_k6" "${envs[@]}" k6 run --quiet --no-color "$@"
}

# 4. Scénario. Le 10 tue le serveur pendant l'écriture, puis vérifie.
k6_start=$(now_ms)
restarts=()
integrity=""
set +e
if [ "$name" = "10-arret-brutal" ]; then
  k6_run "$k6_name" --console-output "/bench/results/$run/k6-console.log" \
    --summary-export "/bench/results/$run/k6-export.json" "/bench/k6/scenarios/$name.js" > "$out/k6.log" 2>&1 &
  k6_pid=$!
  for i in $(seq 1 "$kills"); do
    sleep "$interval"
    if ! kill -0 "$k6_pid" 2>/dev/null; then break; fi
    echo "Arrêt brutal $i/$kills (docker kill -s KILL)…"
    docker kill -s KILL "$cid" >/dev/null
    # Attente de l'arrêt effectif : un « docker start » trop tôt serait sans effet.
    until [ "$(docker inspect -f '{{.State.Running}}' "$cid")" = false ]; do sleep 0.1; done
    t0=$(now_ms)
    docker start "$cid" >/dev/null
    # Port hôte tiré au sort à chaque démarrage : relu à chaque essai. Sortie
    # de curl redirigée par le shell (curl.exe ne connaît pas /dev/null).
    until port=$(docker port "$cid" 8743/tcp 2>/dev/null | head -n 1 | tr -d '\r') && [ -n "$port" ] \
      && curl -fsS --max-time 1 "http://$port/api/health" >/dev/null 2>&1; do
      if [ $(( $(now_ms) - t0 )) -gt 120000 ]; then echo "Serveur non revenu après 120 s." >&2; break; fi
      sleep 0.2
    done
    secs=$(awk -v ms="$(( $(now_ms) - t0 ))" 'BEGIN { printf "%.1f", ms / 1000 }')
    restarts+=("$secs")
    echo "  serveur revenu en $secs s"
  done
  wait "$k6_pid"
  k6_code=$?
  k6_end=$(now_ms)
  if dc exec -T locksy /app/locksy-server check > "$out/integrite.txt" 2>&1 && grep -q "integrity_check" "$out/integrite.txt"; then
    integrity="ok"
  else
    integrity="erreur (voir integrite.txt)"
  fi
  envs+=(-e "PHASE=verification")
  k6_run "$k6_name-verif" "/bench/k6/scenarios/$name.js" >> "$out/k6.log" 2>&1
else
  k6_run "$k6_name" --summary-export "/bench/results/$run/k6-export.json" "/bench/k6/scenarios/$name.js" > "$out/k6.log" 2>&1
  k6_code=$?
  k6_end=$(now_ms)
fi
set -e
sleep 3
cleanup

# 5. Contexte de la passe (lu par report.mjs).
version=$(dc exec -T locksy /app/locksy-server version 2>/dev/null | tr -d '\r' || true)
others=$(docker ps --format '{{.Names}}' | grep -v "^${project}-" | tr '\n' ' ' || true)
login_cap=100
for kv in "${server_env[@]}"; do
  if [ "${kv%%=*}" = LOCKSY_RATELIMIT_LOGIN_IP ]; then login_cap="${kv#*=}"; fi
done
CTX_RUN="$run" CTX_SCENARIO="$name" CTX_DATASET="$dataset" CTX_MEM="$LOCKSY_MEM" CTX_IMAGE="${LOCKSY_IMAGE:-locksy-bench:local}" \
CTX_IMAGE_ID="$(docker inspect -f '{{.Image}}' "$cid" 2>/dev/null || true)" CTX_VERSION="$version" CTX_PREFLIGHT="$preflight" \
CTX_K6_CODE="$k6_code" CTX_K6_START="$k6_start" CTX_K6_END="$k6_end" CTX_SERVER_ENV="${server_env[*]}" \
CTX_RESTARTS="${restarts[*]}" CTX_INTEGRITY="$integrity" CTX_REFERENCE="$reference" CTX_LOGIN_CAP="$login_cap" \
CTX_DOCKER="$(docker info --format '{{.NCPU}} {{.MemTotal}}' 2>/dev/null || true)" CTX_OTHERS="$others" \
node -e '
const e = process.env;
const [cpus, mem] = (e.CTX_DOCKER || "").split(" ");
const serverEnv = {};
for (const kv of (e.CTX_SERVER_ENV || "").split(" ").filter(Boolean)) serverEnv[kv.split("=")[0]] = kv.slice(kv.indexOf("=") + 1);
const ctx = {
  run: e.CTX_RUN, scenario: e.CTX_SCENARIO, dataset: e.CTX_DATASET,
  profil: e.CTX_MEM === "1g" ? "REF-1G" : e.CTX_MEM === "512m" ? "REF-PROD" : null, memoire: e.CTX_MEM,
  image: e.CTX_IMAGE, image_id: e.CTX_IMAGE_ID || null, version_serveur: e.CTX_VERSION || null,
  preflight: Number(e.CTX_PREFLIGHT), k6_code: Number(e.CTX_K6_CODE),
  k6_debut_ms: Number(e.CTX_K6_START), k6_fin_ms: Number(e.CTX_K6_END),
  server_env: serverEnv, plafond_connexion_ip: Number(e.CTX_LOGIN_CAP),
  redemarrages: (e.CTX_RESTARTS || "").split(" ").filter(Boolean).map(Number),
  integrite: e.CTX_INTEGRITY ? (e.CTX_INTEGRITY === "ok" ? "ok" : e.CTX_INTEGRITY) : null,
  reference: e.CTX_REFERENCE || null,
  docker: cpus ? { cpus: Number(cpus), memoire_gio: Number(mem) / 1073741824 } : null,
  autres_conteneurs: (e.CTX_OTHERS || "").trim() || null,
};
require("fs").writeFileSync(process.argv[1], JSON.stringify(ctx, null, 2) + "\n");
' "$out/context.json"

# 6. Rapport : son code est celui de la passe.
set +e
node bench/scripts/report.mjs "$out"
code=$?
set -e
if [ "$k6_code" -ne 0 ] && [ "$k6_code" -ne 99 ] && [ "$code" -eq 0 ]; then
  echo "k6 s'est terminé en erreur (code $k6_code, voir $out/k6.log)." >&2
  code=2
fi
if [ "$down" = 1 ]; then base_dc down -v; fi
echo "Résultats : $out (code $code)."
exit "$code"
