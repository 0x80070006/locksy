#!/usr/bin/env bash
# Copie naïve à chaud (test négatif) : pendant des écritures, on copie
# SEULEMENT locksy.db, sans -wal ni -shm, comme le ferait un « cp » ou une
# sauvegarde de fichiers. Le test RÉUSSIT s'il montre une perte d'écritures
# acquittées ou une incohérence : c'est ce qui justifie `locksy-server backup`.
# Second contrôle : la documentation ne conseille jamais une telle copie.
# Mode d'emploi : ops-tests/README.md.
source "$(dirname "$0")/lib.sh"

usage() {
  cat <<'EOF'
Copie naïve de locksy.db pendant des écritures (test négatif).

Usage : bash ops-tests/sauvegarde-naive.sh [-p projet] [--jeu E2E|M] [--essais N] [--garder]

  -p projet   préfixe des projets compose (défaut : q5-ops ; projets : <projet>-nv et <projet>-nv-r)
  --jeu       E2E (défaut) ou M
  --essais N  copies naïves successives, à 5 s d'écart (défaut : 5)
  --garder    garde les projets compose et les copies à la fin
  -h          affiche cette aide

Sorties : bench/results/ops/<horodatage>-sauvegarde-naive/ (ou $OPS_OUT).
Codes de sortie : 0 réussite (perte ou incohérence démontrée, documentation saine),
1 échec, 2 usage invalide.
EOF
}

ESSAIS=5
# shellcheck disable=SC2034 # OPS_DECALAGE et les variables d'option sont lues par lib.sh.
option_script() {
  case "$1" in
    --essais)
      [[ ${2:-} =~ ^[1-9]$ ]] || erreur_usage "--essais attend un nombre entre 1 et 9"
      ESSAIS=$2; OPS_DECALAGE=2 ;;
  esac
}
lire_options "$@"
OPS_JEU=${OPS_JEU:-E2E}
preparer_sortie

N=$OPS_PROJET-nv
NR=$OPS_PROJET-nv-r
ouvrir_projet banc "$N"
ouvrir_projet ops "$NR"
fermer_projet banc "$N"
fermer_projet ops "$NR"
REL=$(chemin_relatif "$OPS_OUT")
K6_DIR=/bench/${REL#bench/}

# ------------------------------------------------------------ 1. Documentation
etape "1. Documentation : aucune copie de fichier de la base conseillée"
# Une commande de copie (cp, rsync, scp, tar, Copy-Item…) qui vise le fichier
# vivant locksy.db (pas une sauvegarde locksy-<date>.db, ni -wal/-shm), hors
# d'une ligne d'avertissement.
DOCS=(docs/Sauvegarde-et-mises-a-jour.md docs/PRA-PCA.md docs/Exploitation.md docs/Installation-du-serveur.md deploiement/GUIDE-SUR-SITE.md)
: > "$OPS_OUT/doc-copies.txt"
for d in "${DOCS[@]}"; do
  [ -f "$d" ] || continue
  grep -nHE '\b(cp|rsync|scp|tar|copy|Copy-Item|robocopy)\b[^|]*locksy\.db([^-a-zA-Z0-9_.]|$)' "$d" \
    | grep -viE 'jamais|ne (copiez|faites) pas|n.est pas|déconseill|attention|interdit' >> "$OPS_OUT/doc-copies.txt" || true
done
if [ -s "$OPS_OUT/doc-copies.txt" ]; then
  resultat "documentation sans copie naïve de locksy.db" echec "$(head -3 "$OPS_OUT/doc-copies.txt" | tr '\n' ' ')"
else
  resultat "documentation sans copie naïve de locksy.db" ok "${#DOCS[@]} documents relus : seule la commande backup est conseillée"
fi
verifier "la documentation impose locksy-server backup" "docs/Sauvegarde-et-mises-a-jour.md" \
  grep -q 'locksy-server backup' docs/Sauvegarde-et-mises-a-jour.md

# ------------------------------------------------------------ 2. Copies naïves sous écritures
etape "2. Jeu $OPS_JEU sur le banc $N, écritures 05-ecritures, $ESSAIS copie(s) naïve(s)"
assurer_instantane "$OPS_JEU"
banc_script "$N" snapshot.sh restore "$OPS_JEU"
CID=$(banc_dc "$N" ps -q locksy)
VOLUME=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}' "$CID")
K6_NOM="$N-k6-ecritures"
retenir_conteneur "$K6_NOM"
banc_dc "$N" run --rm --no-deps --name "$K6_NOM" -e DATASET="$OPS_JEU" -e DURATION=30m \
  -e RESULTS_DIR="$K6_DIR/k6" k6 run --quiet /bench/k6/scenarios/05-ecritures.js > "$OPS_OUT/k6.log" 2>&1 &
K6_PID=$!
sleep 45
kill -0 "$K6_PID" 2>/dev/null || fatal "k6 s'est arrêté (journal : $REL/k6.log)"

declare -a T_COPIE=()
for i in $(seq 1 "$ESSAIS"); do
  T_COPIE[i]=$(banc_dc "$N" exec -T locksy date +%s | tr -dc 0-9)
  # Le fichier seul, lu pendant que le serveur écrit (ni -wal ni -shm).
  docker run --rm --network none -v "$VOLUME:/data:ro" "$BUSYBOX_IMAGE" cat /data/locksy.db > "$OPS_OUT/naive-$i.db"
  info "copie naïve $i : $(taille "$OPS_OUT/naive-$i.db") octets"
  [ "$i" -lt "$ESSAIS" ] && sleep 5
done
lister_volume "$VOLUME" > "$OPS_OUT/volume-pendant.txt"
sleep 5
docker stop -t 20 "$K6_NOM" >/dev/null 2>&1 || true
wait "$K6_PID" 2>/dev/null || true
docker cp "$CID:/data/server.key" "$(chemin_hote "$OPS_OUT/server.key")"

# Référence : sauvegarde cohérente prise APRÈS l'arrêt des écritures.
banc_dc "$N" exec -T locksy /app/locksy-server backup /data/reference.db --force > /dev/null
docker cp "$CID:/data/reference.db" "$(chemin_hote "$OPS_OUT/reference.db")"
resultat "journal WAL pendant les écritures" info "$(grep -E '^locksy\.db' "$OPS_OUT/volume-pendant.txt" | tr '\n' ' ')"

# ------------------------------------------------------------ 3. Bilan de chaque copie
etape "3. Pertes et incohérences des copies naïves"
DEMONTRE=0
for i in $(seq 1 "$ESSAIS"); do
  copie=$OPS_OUT/naive-$i.db
  if base_js info "$copie" > "$OPS_OUT/naive-$i.json" 2> "$OPS_OUT/naive-$i.err"; then
    integ=$(json_champ "$OPS_OUT/naive-$i.json" 'v.integrity')
  else
    integ="illisible : $(head -1 "$OPS_OUT/naive-$i.err")"
  fi
  bilan="comparaison impossible (copie illisible)"
  pertes=0
  if base_js acquittes --avant "${T_COPIE[i]}" --reference "$OPS_OUT/reference.db" --copie "$copie" > "$OPS_OUT/naive-$i-acquittes.json" 2>/dev/null; then
    pertes=$(json_champ "$OPS_OUT/naive-$i-acquittes.json" 'v.manquants + v.modifications_perdues')
    bilan=$(json_champ "$OPS_OUT/naive-$i-acquittes.json" \
      'v.manquants + " création(s) sur " + v.attendus + " et " + v.modifications_perdues + " modification(s) sur " + v.modifications_attendues + " absentes"')
  fi
  if [ "$integ" != ok ] || [ "$pertes" -gt 0 ]; then DEMONTRE=$((DEMONTRE + 1)); fi
  resultat "copie naïve $i" info "intégrité : $integ ; écritures acquittées avant la copie : $bilan"
  [ "$i" = 1 ] && mesure "copie naïve 1 : écritures acquittées perdues" "$pertes" "écritures"
done

# Restauration de la première copie : le serveur démarre-t-il, que contient-il ?
etape "4. Restauration de la copie naïve 1 ($NR)"
ops_dc "$NR" create locksy >/dev/null 2>&1
mkdir -p "$OPS_OUT/restaure"
cp "$OPS_OUT/naive-1.db" "$OPS_OUT/restaure/locksy.db"
cp "$OPS_OUT/server.key" "$OPS_OUT/restaure/server.key"
vers_le_volume "$(volume_de "$NR")" "$OPS_OUT/restaure" locksy.db server.key
code_de ops_dc "$NR" up -d --wait --wait-timeout 120 locksy
if [ "$CODE" -eq 0 ]; then
  code_de ops_dc "$NR" exec -T locksy /app/locksy-server check > "$OPS_OUT/check-naive.txt" 2>&1
  resultat "serveur sur la copie naïve" info "démarre ; check : code $CODE ; la perte est silencieuse pour l'exploitant"
else
  ops_dc "$NR" logs --no-color locksy > "$OPS_OUT/journal-naive.txt" 2>&1 || true
  resultat "serveur sur la copie naïve" info "ne démarre pas ($REL/journal-naive.txt)"
  DEMONTRE=$((DEMONTRE + 1))
fi

verifier "la copie naïve perd des écritures acquittées ou est incohérente" "$DEMONTRE copie(s) sur $ESSAIS le démontrent" \
  [ "$DEMONTRE" -gt 0 ]

if [ "$OPS_GARDER" = 0 ]; then rm -rf "$OPS_OUT"/naive-*.db "$OPS_OUT/reference.db" "$OPS_OUT/restaure" "$OPS_OUT/server.key"; fi
find "$OPS_OUT" -name "*.err" -empty -delete
terminer
