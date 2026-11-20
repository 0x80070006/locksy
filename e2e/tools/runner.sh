#!/usr/bin/env bash
# Point d'entrée du service « runner » (image Playwright) : installe les
# dépendances si besoin, puis lance Playwright avec les arguments reçus.
# Appelé par run.sh via « docker compose run --rm runner <arguments> ».
set -euo pipefail
cd /work/e2e

# node_modules est un volume du projet compose : on (ré)installe s'il est vide
# ou si package-lock.json a changé depuis la dernière installation.
lock_sum="$(sha256sum package-lock.json | cut -d' ' -f1)"
stamp=node_modules/.locksy-lock-sha256
if [[ ! -f "$stamp" || "$(cat "$stamp")" != "$lock_sum" ]]; then
  echo "Installation des dépendances de test (npm ci)…"
  npm ci --no-audit --no-fund --prefer-offline --loglevel=error
  echo "$lock_sum" > "$stamp"
fi

exec npx --no-install playwright test "$@"
