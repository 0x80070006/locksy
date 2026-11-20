#!/usr/bin/env bash
# Échantillonneur système d'une passe : CPU, mémoire, PID, OOM et redémarrages
# du conteneur, une ligne CSV par période, jusqu'à SIGTERM (ou Ctrl+C).
# Mode d'emploi : bench/README.md.
set -euo pipefail
export MSYS_NO_PATHCONV=1
export TZ=UTC

usage() {
  cat <<'EOF'
Relevé des ressources d'un conteneur, une ligne CSV par période.

Usage : bash bench/scripts/sample-stats.sh <conteneur> <fichier.csv> [période en secondes, défaut 1]

  Exemple : bash bench/scripts/sample-stats.sh locksy-bench-locksy-1 bench/results/passe/stats.csv &
            échantillonneur=$!
            … mesure …
            kill "$échantillonneur"; wait "$échantillonneur"

  Arrêt : SIGTERM (kill), ou Ctrl+C au premier plan. Un script lancé en arrière-plan
  par un autre script ignore SIGINT (règle de bash) : utilisez kill sans option.

Colonnes : horodatage (UTC), epoch_ms, cpu_pct (200 = 2 vCPU saturés), mem_mio,
mem_limite_mio, pids, oom_killed, redemarrages, etat. Le flux continu de
« docker stats » fournit CPU, mémoire et PID ; « docker inspect », relu toutes
les 2 s, fournit l'état, OOMKilled et le nombre de redémarrages. Une ligne au
plus par période : le flux livre environ une mesure par seconde, parfois deux
secondes sur un Docker Desktop chargé (la colonne epoch_ms fait foi). Un
conteneur arrêté ou supprimé, ou une mesure que Docker ne fournit pas
momentanément (« -- »), donne une ligne aux mesures vides avec l'état.
Code de sortie : 0 à l'arrêt demandé, 2 usage invalide.
EOF
}

case "${1:-}" in -h|--help) usage; exit 0 ;; esac
if [ $# -lt 2 ] || [ $# -gt 3 ]; then usage >&2; exit 2; fi
container="$1"
csv="$2"
period="${3:-1}"
if [[ ! $period =~ ^[1-9][0-9]*$ ]]; then echo "Période invalide : $period (entier de secondes)." >&2; exit 2; fi

# « 6.3MiB », « 1.2GiB », « 512kB » → Mio, une décimale.
to_mib() {
  awk -v v="$1" 'BEGIN {
    n = v + 0; u = v; sub(/^[0-9.]+/, "", u)
    f = (u ~ /^Gi?B$/) ? 1024 : (u ~ /^Mi?B$/) ? 1 : (u ~ /^[kK]i?B$/) ? 1 / 1024 : (u == "B") ? 1 / 1048576 : 0
    printf "%.1f", n * f }'
}
# Champ texte d'une ligne JSON de docker stats (sans processus externe).
field() {
  local re="\"$1\":\"([^\"]*)\""
  if [[ $2 =~ $re ]]; then echo "${BASH_REMATCH[1]}"; fi
}
now_ms() { local t="$EPOCHREALTIME"; echo $(( ${t%[.,]*} * 1000 + 10#${t#*[.,]} / 1000 )); }

mkdir -p "$(dirname "$csv")"
[ -s "$csv" ] || echo "horodatage,epoch_ms,cpu_pct,mem_mio,mem_limite_mio,pids,oom_killed,redemarrages,etat" > "$csv"
state_file=$(mktemp)
read_state() {
  docker inspect -f '{{.State.Status}} {{.State.OOMKilled}} {{.RestartCount}}' "$container" > "$state_file.n" 2>/dev/null \
    || echo "absent" > "$state_file.n"
  mv -f "$state_file.n" "$state_file"
}
read_state

# État du conteneur relu ensuite en tâche de fond (docker inspect prend près d'une seconde).
(
  trap 'exit 0' TERM
  while :; do
    sleep 2
    read_state
  done
) &
inspector=$!

# Exécutable réel : sous Git Bash, « docker » est un script qui lance docker.exe ;
# arrêter le script laisserait docker.exe orphelin.
docker_bin=$(command -v docker.exe || command -v docker)
stop=0
stats_pid=""
cleanup() {
  kill "$inspector" 2>/dev/null || true
  if [ -n "$stats_pid" ]; then kill "$stats_pid" 2>/dev/null || true; fi
  rm -f "$state_file" "$state_file.n"
}
trap 'stop=1' INT TERM
trap cleanup EXIT
echo "Relevé de $container vers $csv toutes les $period s (arrêt : kill $$)." >&2

last=0
emit() {
  local t state oom restarts
  t=$(now_ms)
  read -r state oom restarts < "$state_file" || true
  printf -v stamp '%(%Y-%m-%dT%H:%M:%S)T' "$((t / 1000))"
  printf '%s.%03dZ,%s,%s,%s,%s,%s,%s,%s,%s\n' "$stamp" "$((t % 1000))" "$t" "$1" "$2" "$3" "$4" "${oom:-}" "${restarts:-}" "${state:-absent}" >> "$csv"
  last=$t
}

while [ "$stop" = 0 ]; do
  # Flux continu : une mise à jour par seconde environ, entrecoupée de codes d'effacement d'écran.
  coproc STATS { exec "$docker_bin" stats --format json "$container" 2>/dev/null; }
  # shellcheck disable=SC2153 # STATS_PID est posé par coproc
  stats_pid=$STATS_PID
  while [ "$stop" = 0 ] && IFS= read -r line <&"${STATS[0]}"; do
    [[ $line == *'"CPUPerc"'* ]] || continue
    (( $(now_ms) - last >= period * 1000 - 100 )) || continue
    cpu=$(field CPUPerc "$line")
    usage_mem=$(field MemUsage "$line")
    if [ "$cpu" = "--" ]; then
      # Mesure momentanément indisponible côté Docker : ligne vide plutôt que des zéros.
      emit "" "" "" ""
    else
      emit "${cpu%\%}" "$(to_mib "${usage_mem%% / *}")" "$(to_mib "${usage_mem##* / }")" "$(field PIDs "$line")"
    fi
  done || true
  kill "$stats_pid" 2>/dev/null || true
  wait "$stats_pid" 2>/dev/null || true
  stats_pid=""
  # Flux interrompu (conteneur supprimé ou arrêté) : une ligne d'état, puis nouvel essai.
  if [ "$stop" = 0 ]; then
    emit "" "" "" ""
    sleep "$period" || true
  fi
done
echo "Relevé arrêté : $(($(wc -l < "$csv") - 1)) ligne(s) dans $csv." >&2
