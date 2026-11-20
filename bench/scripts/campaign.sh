#!/usr/bin/env bash
# Campagne pré-release : enchaîne les scénarios de charge par run.sh sur les
# jeux M et L, profil REF-PROD, puis REF-1G pour les passes en échec. Reprise
# possible après interruption (--resume). Mode d'emploi : bench/k6/README.md.
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
Campagne de charge pré-release (scénarios 00 à 11).

Usage : bash bench/scripts/campaign.sh [-p projet] [options]

  -p projet          projet docker compose (défaut : $BENCH_PROJECT, sinon locksy-bench)
  --datasets LISTE   jeux, séparés par des virgules (défaut : M,L)
  --only LISTE       numéros de scénarios à passer (ex. 00,03,07)
  --endurance D      durée du scénario 08 (défaut : 30m ; 2h pour G23, 8h avant une release majeure)
  --no-1g            ne repasse pas en REF-1G les passes en échec sur REF-PROD
  --resume DIR       reprend la campagne de ce dossier (étapes terminées sautées)
  --keep             laisse le banc en service à la fin (sinon : docker compose down -v)
  --dry-run          affiche le plan et sa durée estimée, sans rien lancer
  -h                 affiche cette aide

Prérequis : instantanés bench/snapshots/<jeu>/ (bash bench/scripts/seed.sh <jeu>),
serveur du banc démarré ou démarrable (bench-up.sh).
Le 00 est un prérequis : s'il échoue, la campagne s'arrête.
Sorties : bench/results/campagne-<horodatage>/{plan.txt,etat.txt,campagne.md}
et un dossier par passe. Codes de sortie : 0 toutes les passes vertes ou
indicatives sans dépassement, 1 au moins un échec, 2 usage ou campagne interrompue.
EOF
}

project="${BENCH_PROJECT:-locksy-bench}"
datasets="M,L"
only=""
endurance="30m"
retry_1g=1
resume=""
keep=0
dry=0
while [ $# -gt 0 ]; do
  case "$1" in
    -p) project="${2:?-p attend un nom de projet}"; shift 2 ;;
    --datasets) datasets="${2:?}"; shift 2 ;;
    --only) only="${2:?}"; shift 2 ;;
    --endurance) endurance="${2:?}"; shift 2 ;;
    --no-1g) retry_1g=0; shift ;;
    --resume) resume="${2:?}"; shift 2 ;;
    --keep) keep=1; shift ;;
    --dry-run) dry=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Argument inconnu : $1" >&2; usage >&2; exit 2 ;;
  esac
done
if [[ ! $endurance =~ ^[1-9][0-9]*(m|h)$ ]]; then echo "--endurance attend 30m ou 2h : $endurance" >&2; exit 2; fi

# Plan : « jeu|scénario|minutes estimées|options de run.sh ». Les seuils de la
# plupart des scénarios sont définis pour M ; L sert au 04 (10 000 éléments).
# 09 et 11 se comparent aux passes 07 de la campagne (NOMINAL_P95, --reference).
endurance_min=$(( ${endurance%[mh]} * $([[ $endurance == *h ]] && echo 60 || echo 1) ))
plan_for() {
  case "$1" in
    M)
      echo "M|00-smoke|2|"
      echo "M|02a-arrivee-matin|7|"
      echo "M|02b-rafale|3|"
      echo "M|02c-nat|12|--server-env LOCKSY_RATELIMIT_LOGIN_IP=300"
      echo "M|02d-capacite|15|"
      echo "M|03-sync-1000|8|"
      echo "M|05-ecritures|7|"
      echo "M|06-pieces-jointes|8|"
      echo "M|07-journee-type|25|--vus 50"
      echo "M|07-journee-type|25|--vus 200"
      echo "M|07-journee-type|25|--vus 500"
      echo "M|08-endurance|$((endurance_min + 5))|--vus 200 --duration $endurance"
      echo "M|09-abus|13|"
      echo "M|10-arret-brutal|15|"
      echo "M|11-reglages|25|--vus 200"
      ;;
    L)
      echo "L|00-smoke|2|"
      echo "L|04-sync-10000|8|"
      ;;
    *) echo "Jeu inconnu : $1" >&2; exit 2 ;;
  esac
}
plan=()
IFS=',' read -r -a ds_list <<< "$datasets"
for ds in "${ds_list[@]}"; do
  while IFS= read -r step; do
    num="${step#*|}"; num="${num%%-*}"
    if [ -n "$only" ] && [[ ",$only," != *",$num,"* ]]; then continue; fi
    plan+=("$step")
  done < <(plan_for "$ds")
done
if [ "${#plan[@]}" -eq 0 ]; then echo "Plan vide." >&2; exit 2; fi
total=0
for step in "${plan[@]}"; do IFS='|' read -r _ _ minutes _ <<< "$step"; total=$((total + minutes + 2)); done

if [ -n "$resume" ]; then dir="$resume"; else dir="bench/results/campagne-$(date -u +%Y%m%d-%H%M%S)"; fi
plan_text() {
  echo "Campagne $(basename "$dir") : ${#plan[@]} passe(s) REF-PROD, environ $((total / 60)) h $((total % 60)) min"
  echo "(hors restaurations des gros jeux et hors repasses REF-1G)."
  for step in "${plan[@]}"; do IFS='|' read -r ds sc minutes opts <<< "$step"; echo "  $ds  $sc ${opts:+($opts) }≈ $minutes min"; done
}
if [ "$dry" = 1 ]; then plan_text; exit 0; fi
mkdir -p "$dir"
state="$dir/etat.txt"
touch "$state"
plan_text | tee "$dir/plan.txt"

for ds in "${ds_list[@]}"; do
  if [ ! -f "bench/snapshots/$ds/locksy.db" ]; then echo "Instantané du jeu $ds absent : bash bench/scripts/seed.sh -p $project $ds" >&2; exit 2; fi
done
if [ -z "$(docker compose -p "$project" -f bench/docker-compose.bench.yml ps -q locksy 2>/dev/null)" ]; then
  set +e
  bash bench/scripts/bench-up.sh -p "$project" --profile REF-PROD
  up=$?
  set -e
  if [ "$up" -ge 2 ]; then echo "Banc indisponible (bench-up.sh : $up)." >&2; exit 2; fi
fi

# Une étape : « profil|jeu|scénario|options » ; résultat dans etat.txt.
step_done() { grep -q "^$1|" "$state"; }
result_of() { grep "^$1|" "$state" | tail -n 1 | cut -d'|' -f5; }
dir_of() { grep "^$1|" "$state" | tail -n 1 | cut -d'|' -f6; }
p95_of() { # p95 de la journée type d'une passe
  node -e 'const s=require(require("path").resolve(process.argv[1],"summary.json"));const m=s.k6.metrics["http_req_duration{groupe:journee}"];console.log(m?Math.round(m.values["p(95)"]):"")' "$1"
}

run_step() { # <profil> <jeu> <scénario> <options…>
  local profile="$1" ds="$2" sc="$3"
  shift 3
  local key="$profile|$ds|$sc|$*"
  if step_done "$key"; then
    echo "Déjà faite : $key (code $(result_of "$key"))."
    return 0
  fi
  local before after code passe
  before=$(ls -1 bench/results | sort)
  set +e
  bash bench/scripts/run.sh -p "$project" --profile "$profile" --dataset "$ds" --scenario "$sc" "$@"
  code=$?
  set -e
  after=$(ls -1 bench/results | sort)
  passe=$(comm -13 <(echo "$before") <(echo "$after") | grep -- "-$sc" | tail -n 1 || true)
  echo "$key|$code|bench/results/$passe" >> "$state"
  return 0
}

for step in "${plan[@]}"; do
  IFS='|' read -r ds sc _ opts <<< "$step"
  extra=()
  if [ "$sc" = "09-abus" ]; then
    ref=$(dir_of "REF-PROD|M|07-journee-type|--vus 50" || true)
    if [ -n "$ref" ] && [ -f "$ref/summary.json" ]; then extra=(--env "NOMINAL_P95=$(p95_of "$ref")"); fi
  fi
  if [ "$sc" = "11-reglages" ]; then
    ref=$(dir_of "REF-PROD|M|07-journee-type|--vus 200" || true)
    if [ -n "$ref" ] && [ -f "$ref/summary.json" ]; then extra=(--reference "$ref"); fi
  fi
  # shellcheck disable=SC2086 # options du plan découpées volontairement
  run_step REF-PROD "$ds" "$sc" $opts "${extra[@]}"
  if [ "$sc" = "00-smoke" ] && [ "$(result_of "REF-PROD|$ds|00-smoke|")" != 0 ]; then
    echo "Le smoke du jeu $ds échoue : campagne arrêtée (voir $(dir_of "REF-PROD|$ds|00-smoke|")/rapport.md)." >&2
    exit 1
  fi
done

if [ "$retry_1g" = 1 ]; then
  while IFS='|' read -r profile ds sc opts code _; do
    if [ "$profile" = REF-PROD ] && { [ "$code" = 1 ] || [ "$code" = 3 ]; } && [ "$sc" != "00-smoke" ]; then
      # shellcheck disable=SC2086
      run_step REF-1G "$ds" "$sc" $opts
    fi
  done < <(cat "$state")
fi

# Synthèse.
{
  echo "# Campagne de charge $(basename "$dir")"
  echo
  echo "| Profil | Jeu | Scénario | Options | Code | Rapport |"
  echo "|---|---|---|---|---|---|"
  while IFS='|' read -r profile ds sc opts code passe; do
    case "$code" in 0) v="passe" ;; 1) v="échec" ;; 3) v="indicatif, dépassé" ;; *) v="inexploitable" ;; esac
    echo "| $profile | $ds | $sc | ${opts:-–} | $code ($v) | ${passe#bench/results/}/rapport.md |"
  done < "$state"
  echo
  echo "Codes : 0 passe, 1 échec, 2 inexploitable, 3 indicative avec dépassement (preflight ≠ 0)."
} > "$dir/campagne.md"
echo "Synthèse : $dir/campagne.md"
if [ "$keep" = 0 ]; then docker compose -p "$project" -f bench/docker-compose.bench.yml down -v; fi
# Échec : une passe en échec (1) ou inexploitable (2).
if cut -d'|' -f5 "$state" | grep -qx '[12]'; then exit 1; fi
exit 0
