#!/usr/bin/env bash
# Tests de sécurité automatisés de Locksy (lot Q4), en une commande.
#
#   bash e2e/security/run.sh -p <cle> [--zap] [--trivy] [--cargo] [--sans-tests] [-- <arguments playwright>]
#
#   -p <cle>       obligatoire ; nomme le projet compose et les sorties
#                  (e2e/test-results/<cle>-securite, e2e/playwright-report/<cle>-securite,
#                  e2e/.state/<cle>).
#   --zap          scan passif ZAP baseline 2.15.0 contre locksy-direct.
#   --trivy        Trivy 0.57.1 sur l'image locksy-e2e-server:fast (HIGH et CRITICAL corrigeables).
#   --cargo        cargo audit et cargo deny dans locksy-toolchain.
#   --sans-tests   scans seulement (pas de Playwright ni d'analyse de la base).
#   -- …           arguments passés à « npx playwright test » (filtres, --project…).
#
# Étapes : compose up (base e2e + surcouche docker-compose.securite.yml) →
# Playwright (-c security/playwright.config.ts) → zk-analyse.mjs (base du
# serveur) → scans demandés → down -v. Image : locksy-e2e-server:fast telle
# quelle (jamais reconstruite ici). Code de sortie : celui de Playwright,
# sinon celui de l'analyse de la base, sinon celui du premier scan en échec.
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-2}"
}
die() { echo "security/run.sh : $*" >&2; exit 2; }

key="" zap=0 trivy=0 cargo=0 tests=1
while (($#)); do
  case "$1" in
    -p) [[ $# -ge 2 ]] || die "valeur manquante après -p"; key="$2"; shift 2 ;;
    -p=*) key="${1#*=}"; shift ;;
    --zap) zap=1; shift ;;
    --trivy) trivy=1; shift ;;
    --cargo) cargo=1; shift ;;
    --sans-tests) tests=0; shift ;;
    -h|--help) usage 0 ;;
    --) shift; break ;;
    *) die "option inconnue : $1 (les arguments de Playwright vont après « -- »)" ;;
  esac
done
pw_args=("$@")

[[ -n "$key" ]] || die "la clé est obligatoire : -p <cle> (ex. -p q4-sec)"
key="$(printf '%s' "$key" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9_-' '-')"
key="${key#[-_]}"
[[ "$key" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || die "clé invalide : $key"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
cd "$repo"
command -v docker >/dev/null || die "docker est introuvable"
docker compose version >/dev/null 2>&1 || die "docker compose (v2) est introuvable"

image="locksy-e2e-server:fast"
docker image inspect "$image" >/dev/null 2>&1 \
  || die "image $image absente : construisez-la d'abord (voir e2e/README.md), ce script ne la reconstruit pas"

# Chemin de l'hôte pour « docker run -v » (forme C:/… sous Git Bash).
host_path() { (cd "$1" && { pwd -W 2>/dev/null || pwd; }); }

results="e2e/test-results/$key-securite"
state="e2e/.state/$key"
mkdir -p "$results" "$state" e2e/.npm-cache

export E2E_KEY="$key"
export LOCKSY_E2E_IMAGE="$image"
export E2E_PROFILES="" E2E_WASM="" LOCKSY_SSO_ALLOW_HTTP=false
compose_args=(-p "$key" -f e2e/docker-compose.e2e.yml -f e2e/security/docker-compose.securite.yml)
compose() { docker compose "${compose_args[@]}" "$@"; }

# shellcheck disable=SC2329  # appelée par « trap cleanup EXIT »
cleanup() {
  local code=$?
  echo "Nettoyage de l'environnement « $key »…"
  compose --profile runner down -v --remove-orphans --timeout 5 >/dev/null 2>&1 \
    || echo "security/run.sh : « down -v » a échoué, voir docker compose -p $key ps" >&2
  exit "$code"
}

status=0
note() { [[ $status -ne 0 ]] || status=$1; }

needs_stack=$((tests || zap))
if ((needs_stack)); then
  trap cleanup EXIT
  echo "Démarrage de l'environnement de sécurité « $key »…"
  compose up -d --wait --wait-timeout 300
fi

if ((tests)); then
  rm -f "$state/zk-clairs.json"
  set +e
  compose run --rm runner -c security/playwright.config.ts "${pw_args[@]}"
  pw=$?
  set -e
  echo "Playwright : code $pw ; rapport e2e/playwright-report/$key-securite/index.html"
  note "$pw"
  set +e
  node e2e/security/zk-analyse.mjs --cle "$key"
  zk=$?
  set -e
  note "$zk"
fi

if ((zap)); then
  echo "Scan ZAP baseline 2.15.0 de http://locksy-direct:8743…"
  mkdir -p "$results/zap"
  cp e2e/security/zap/zap-regles.tsv "$results/zap/zap-regles.tsv"
  set +e
  docker run --rm --cpus=2 --memory=2g --network "${key}_default" \
    -v "$(host_path "$results/zap"):/zap/wrk" \
    ghcr.io/zaproxy/zaproxy:2.15.0 zap-baseline.py -t http://locksy-direct:8743 -c zap-regles.tsv -J zap.json -I \
    | tee "$results/zap/zap.txt"
  zc=${PIPESTATUS[0]}
  set -e
  echo "ZAP : code $zc (0 sans échec, 1 règle FAIL, 3 erreur)"
  note "$zc"
  set +e
  node e2e/security/zap/verdict.mjs "$results/zap/zap.json"
  zv=$?
  set -e
  note "$zv"
fi

if ((trivy)); then
  echo "Trivy 0.57.1 sur $image (HIGH, CRITICAL, corrigeables)…"
  mkdir -p e2e/.state/trivy-cache
  set +e
  docker run --rm --cpus=2 --memory=2g -v //var/run/docker.sock:/var/run/docker.sock \
    -v "$(host_path e2e/.state/trivy-cache):/root/.cache/trivy" \
    aquasec/trivy:0.57.1 image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 "$image" \
    | tee "$results/trivy.txt"
  tc=${PIPESTATUS[0]}
  set -e
  echo "Trivy : code $tc (0 = aucune vulnérabilité HIGH ou CRITICAL corrigeable)"
  note "$tc"
fi

if ((cargo)); then
  echo "cargo audit et cargo deny dans locksy-toolchain…"
  set +e
  # shellcheck disable=SC2016  # variables développées dans le conteneur
  docker run --rm --cpus=3 --memory=6g -e CARGO_BUILD_JOBS=3 \
    -v "$(host_path .):/src" -v locksy-reg:/usr/local/cargo/registry -v locksy-tgt-srv:/src/target -w /src \
    locksy-toolchain bash -c '
      export CARGO_INSTALL_ROOT=/src/target/outils-securite PATH=/src/target/outils-securite/bin:$PATH
      # (ADAPTATION) cargo-audit 0.21.2 et cargo-deny 0.18.3 (versions du cahier) ne lisent pas les
      # avis notés en CVSS 4.0 de la base RustSec actuelle : versions plus récentes, toujours épinglées.
      # « cargo install » ne fait rien si la version demandée est déjà installée.
      cargo install --locked --quiet cargo-audit --version 0.23.0
      cargo install --locked --quiet cargo-deny --version 0.21.0
      echo "Versions : $(cargo audit --version) ; $(cargo deny --version)"
      # Mêmes exceptions que cargo deny : les avis écartés par deny.toml,
      # chacun avec sa justification et sa correction prévue, y sont listés.
      exceptions=$(grep -o "id = \"RUSTSEC-[0-9-]*\"" deny.toml | cut -d\" -f2)
      echo "Avis écartés par deny.toml : ${exceptions:-aucun}" | tr "\n" " "; echo
      a=0; d=0
      cargo audit $(printf -- "--ignore %s " $exceptions) || a=$?
      cargo deny check || d=$?
      echo "cargo audit : code $a ; cargo deny : code $d"
      [ "$a" -eq 0 ] && [ "$d" -eq 0 ]' 2>&1 | tee "$results/cargo-audit-deny.txt"
  cc=${PIPESTATUS[0]}
  set -e
  echo "cargo audit / deny : code $cc"
  note "$cc"
fi

echo "Sorties : $results/"
exit "$status"
