#!/usr/bin/env bash
# Sauvegarde à chaud avec server.key pendant des écritures, puis restauration
# chronométrée (RTO) sur un volume vide, vérifiée par le serveur et par le
# vrai client. Critères G29 et G30. Mode d'emploi : ops-tests/README.md.
source "$(dirname "$0")/lib.sh"

usage() {
  cat <<'EOF'
Sauvegarde à chaud (avec server.key) pendant des écritures, puis restauration chronométrée.

Usage : bash ops-tests/sauvegarde-restauration.sh [-p projet] [--jeu E2E|M] [--sans-pj] [--resemer]
                                                 [--nominal S] [--profil REF-PROD|REF-1G] [--garder]

  -p projet   préfixe des projets compose (défaut : q5-ops ; restauration : <projet>-r)
  --profil    mémoire du serveur : REF-PROD = 512 Mo (défaut, seuils bloquants), REF-1G = 1 Go
  --jeu       M (défaut, mesure du RTO) ou E2E (contrôle rapide, connexion 2FA de david@e2e.test)
  --sans-pj   semis sans pièce jointe (bench/scripts/seed.sh --no-attachments)
  --resemer   sème à neuf même si bench/snapshots/<jeu> existe (sinon l'instantané est restauré)
  --nominal S durée de la mesure nominale des écritures avant la sauvegarde (défaut : 60 s)
  --malloc-arena N  diagnostic : serveurs lancés avec MALLOC_ARENA_MAX=N (configuration non livrée)
  --garder    garde les projets compose et les copies de base à la fin
  -h          affiche cette aide

Contrôles : sauvegarde (code 0, clé de 32 octets identique à celle du serveur), p95 des écritures
pendant la sauvegarde < 3 × nominal et 0 erreur, aucune écriture acquittée avant la sauvegarde
perdue, RTO < 15 min (check = 0, verify-audit = 0, 20 comptes déchiffrés), puis hors RTO :
integrity_check, comptes de la base, déchiffrement complet.
Sorties : bench/results/ops/<horodatage>-sauvegarde-restauration/ (ou $OPS_OUT).
Codes de sortie : 0 réussite, 1 échec, 2 usage invalide.
EOF
}

SANS_PJ=0
RESEMER=0
NOMINAL=60
# shellcheck disable=SC2034 # OPS_DECALAGE et les variables d'option sont lues par lib.sh.
option_script() {
  case "$1" in
    --sans-pj) SANS_PJ=1; OPS_DECALAGE=1 ;;
    --resemer) RESEMER=1; OPS_DECALAGE=1 ;;
    --nominal)
      [[ ${2:-} =~ ^[1-9][0-9]*$ ]] || erreur_usage "--nominal attend un nombre de secondes"
      NOMINAL=$2; OPS_DECALAGE=2 ;;
    --profil)
      case "${2:-}" in
        REF-PROD) PROFIL=REF-PROD; export LOCKSY_MEM=512m OPS_MEM=512m ;;
        REF-1G) PROFIL=REF-1G; export LOCKSY_MEM=1g OPS_MEM=1g ;;
        *) erreur_usage "--profil attend REF-PROD ou REF-1G" ;;
      esac
      OPS_DECALAGE=2 ;;
    --malloc-arena)
      [[ ${2:-} =~ ^[1-9][0-9]?$ ]] || erreur_usage "--malloc-arena attend un nombre entre 1 et 99"
      ARENES=$2; OPS_DECALAGE=2 ;;
  esac
}
ARENES=""
PROFIL=REF-PROD
export LOCKSY_MEM=512m OPS_MEM=512m
lire_options "$@"
OPS_JEU=${OPS_JEU:-M}
preparer_sortie
resultat "profil du serveur" info "$PROFIL (mémoire $LOCKSY_MEM, 2 vCPU), image $OPS_IMAGE"
if [ -n "$ARENES" ]; then
  # Diagnostic du défaut Q5-H2 : nombre d'arènes de malloc (glibc) borné.
  OPS_SURCOUCHE=$OPS_OUT/surcouche.yml
  printf 'services:\n  locksy:\n    environment:\n      MALLOC_ARENA_MAX: "%s"\n' "$ARENES" > "$OPS_SURCOUCHE"
  resultat "configuration de diagnostic" info "MALLOC_ARENA_MAX=$ARENES (configuration NON livrée, handoff Q5-H2)"
fi

P=$OPS_PROJET
R=$OPS_PROJET-r
ouvrir_projet banc "$P"
ouvrir_projet ops "$R"
fermer_projet banc "$P"
fermer_projet ops "$R"
SEMIS=bench/seed/out/$OPS_JEU
INSTANTANE=bench/snapshots/$OPS_JEU
SAUVEGARDE=$OPS_OUT/sauvegarde
REL=$(chemin_relatif "$OPS_OUT")
K6_DIR=/bench/${REL#bench/}
mkdir -p "$SAUVEGARDE"

# ------------------------------------------------------------ 1. Banc et jeu
etape "1. Banc ($P, image $OPS_IMAGE) et jeu $OPS_JEU"
chrono_debut preparation
if [ "$RESEMER" = 0 ] && [ -f "$INSTANTANE/locksy.db" ] && [ -f "$INSTANTANE/users.json" ]; then
  info "instantané existant restauré : $INSTANTANE (--resemer pour semer à neuf)"
  banc_script "$P" snapshot.sh restore "$OPS_JEU"
  resultat "préparation" info "instantané $INSTANTANE ($(json_champ "$INSTANTANE/instantane.json" 'v.image + ", " + v.cree_le'))"
else
  code_de banc_script "$P" bench-up.sh
  [ "$CODE" -le 1 ] || fatal "banc indisponible (bench-up.sh : code $CODE)"
  [ "$CODE" -eq 0 ] || avertir "preflight.sh : avertissements, mesures indicatives"
  opts=(--workers 2)
  [ "$SANS_PJ" = 1 ] && opts+=(--no-attachments)
  chrono_debut semis
  banc_script "$P" seed.sh "${opts[@]}" "$OPS_JEU"
  mesure "durée du semis $OPS_JEU (semis, vérification, instantané)" "$(en_secondes "$(chrono_fin semis)")" s
  resultat "préparation" info "jeu $OPS_JEU semé$([ "$SANS_PJ" = 1 ] && echo " sans pièce jointe (--sans-pj)")"
fi
# Les scripts du banc ignorent la surcouche : le serveur est recréé avec elle (même volume).
if [ -n "${OPS_SURCOUCHE:-}" ]; then banc_dc "$P" up -d --wait --wait-timeout 180 locksy >/dev/null 2>&1; fi
mesure "préparation du banc" "$(en_secondes "$(chrono_fin preparation)")" s
PJ=$(json_champ "$SEMIS/manifest.json" 'v.counts.attachments')
mesure "jeu $OPS_JEU : comptes, éléments, pièces jointes" \
  "$(json_champ "$SEMIS/manifest.json" 'v.counts.accounts + " ; " + v.counts.items + " ; " + v.counts.attachments')" "nombre"
CID=$(banc_dc "$P" ps -q locksy)
[ -n "$CID" ] || fatal "serveur du banc introuvable"
WASM=$OPS_OUT/locksy.wasm
extraire_de_image "$OPS_IMAGE" /app/web/locksy.wasm "$WASM"

# ------------------------------------------------------------ 2. Sauvegarde pendant les écritures
etape "2. Sauvegarde à chaud pendant 05-ecritures (mesure nominale : $NOMINAL s)"
K6_NOM="$P-k6-ecritures"
retenir_conteneur "$K6_NOM"
banc_dc "$P" exec -T locksy mkdir -p /data/sauvegardes
mkdir -p "$OPS_OUT/k6"
# Mémoire, CPU, arrêts pour manque de mémoire : relevé du banc, une mesure par seconde.
bash bench/scripts/sample-stats.sh "$P-locksy-1" "$OPS_OUT/stats.csv" > "$OPS_OUT/stats.log" 2>&1 &
STATS_PID=$!
banc_dc "$P" run --rm --no-deps --name "$K6_NOM" -e DATASET="$OPS_JEU" -e DURATION=30m \
  -e RESULTS_DIR="$K6_DIR/k6" k6 run --quiet --out "json=$K6_DIR/k6-points.json" \
  /bench/k6/scenarios/05-ecritures.js > "$OPS_OUT/k6.log" 2>&1 &
K6_PID=$!
# Attente des premières écritures (connexions des VU faites), puis mesure nominale.
fin=$(( $(date +%s) + 180 ))
until [ -f "$OPS_OUT/k6-points.json" ] && grep -q '"name":"element_' "$OPS_OUT/k6-points.json" 2>/dev/null; do
  kill -0 "$K6_PID" 2>/dev/null || fatal "k6 s'est arrêté avant d'écrire (journal : $REL/k6.log)"
  [ "$(date +%s)" -lt "$fin" ] || fatal "aucune écriture de k6 après 180 s (journal : $REL/k6.log)"
  sleep 2
done
info "écritures en cours ; mesure nominale pendant $((NOMINAL + 10)) s"
sleep $((NOMINAL + 10))

HORO=$(date +%Y%m%d-%H%M%S)
FICHIER=/data/sauvegardes/locksy-$HORO.db
# Horodatages pris DANS le conteneur : même horloge que k6 (machine virtuelle Docker).
banc_dc "$P" exec -T locksy sh -c \
  "d=\$(date +%s%3N); /app/locksy-server backup $FICHIER --with-key; c=\$?; f=\$(date +%s%3N); echo \"CHRONO \$d \$f \$c\"" \
  > "$OPS_OUT/sauvegarde.txt" 2>&1 || true
CHRONO=$(grep '^CHRONO ' "$OPS_OUT/sauvegarde.txt" | tail -1 | tr -d '\r' || true)
read -r _ T_DEBUT T_FIN B_CODE <<< "$CHRONO" || true
info "$(grep -v '^CHRONO' "$OPS_OUT/sauvegarde.txt" | head -3 | tr '\n' ' ')"
sleep 20
docker stop -t 20 "$K6_NOM" >/dev/null 2>&1 || true
wait "$K6_PID" 2>/dev/null || true
kill "$STATS_PID" 2>/dev/null || true
wait "$STATS_PID" 2>/dev/null || true
MEM_MAX=$(awk -F, 'NR > 1 && $4 != "" && $4 + 0 > m { m = $4 + 0 } END { printf "%.0f", m }' "$OPS_OUT/stats.csv" 2>/dev/null || echo "?")
mesure "mémoire maximale du serveur (écritures et sauvegarde)" "$MEM_MAX sur $LOCKSY_MEM" Mio
ETAT=$(docker inspect -f '{{.State.Status}} {{.State.OOMKilled}} {{.State.ExitCode}}' "$CID" 2>/dev/null || echo "absent")
if [ -z "${B_CODE:-}" ] || [[ $ETAT != running* ]]; then
  # Le serveur est mort pendant la sauvegarde : la commande n'a pas pu finir.
  banc_dc "$P" logs --no-color --tail 50 locksy > "$OPS_OUT/journal-serveur.txt" 2>&1 || true
  if [[ $ETAT == *" true "* ]]; then CAUSE="arrêté pour manque de mémoire (OOMKilled, limite $LOCKSY_MEM)"; else CAUSE="état « $ETAT »"; fi
  resultat "G29 sauvegarde à chaud pendant les écritures" echec "serveur $CAUSE pendant la sauvegarde ; défaut produit, handoff Q5-H2"
  if [ "$OPS_GARDER" = 0 ]; then rm -rf "$SAUVEGARDE" "$WASM"; fi
  terminer
fi

verifier "sauvegarde à chaud (code 0)" "locksy-server backup --with-key : code $B_CODE" [ "$B_CODE" -eq 0 ]
docker cp "$CID:$FICHIER" "$(chemin_hote "$SAUVEGARDE/locksy.db")"
docker cp "$CID:$FICHIER.server.key" "$(chemin_hote "$SAUVEGARDE/server.key")"
docker cp "$CID:/data/server.key" "$(chemin_hote "$OPS_OUT/server.key.reference")"
B_MS=$((T_FIN - T_DEBUT))
B_OCTETS=$(taille "$SAUVEGARDE/locksy.db")
mesure "durée de la sauvegarde à chaud" "$(en_secondes "$B_MS")" s
mesure "taille de la sauvegarde" "$(awk -v o="$B_OCTETS" 'BEGIN { s = sprintf("%.1f", o / 1048576); sub(/\./, ",", s); print s }')" Mio
if [ "$(taille "$SAUVEGARDE/server.key")" = 32 ] && [ "$(empreinte "$SAUVEGARDE/server.key")" = "$(empreinte "$OPS_OUT/server.key.reference")" ]; then
  resultat "server.key dans la sauvegarde" ok "32 octets, identique à la clé du serveur"
else
  resultat "server.key dans la sauvegarde" echec "clé absente, tronquée ou différente de celle du serveur"
fi
rm -f "$OPS_OUT/server.key.reference"

# Latences : fenêtre nominale avant la sauvegarde, fenêtre pendant (au moins 10 s
# pour avoir un échantillon : une sauvegarde courte est mesurée avec ce qui suit).
P_FIN=$T_FIN
LARGIE=""
if [ "$B_MS" -lt 10000 ]; then P_FIN=$((T_DEBUT + 10000)); LARGIE=" (fenêtre élargie à 10 s)"; fi
node ops-tests/lib/k6.mjs --points "$OPS_OUT/k6-points.json" \
  --fenetre "nominal=$((T_DEBUT - NOMINAL * 1000)),$T_DEBUT" --fenetre "pendant=$T_DEBUT,$P_FIN" > "$OPS_OUT/latences.json"
N95=$(json_champ "$OPS_OUT/latences.json" 'v.fenetres.nominal.ecritures_p95_ms')
D95=$(json_champ "$OPS_OUT/latences.json" 'v.fenetres.pendant.ecritures_p95_ms')
DN=$(json_champ "$OPS_OUT/latences.json" 'v.fenetres.pendant.ecritures')
DERR=$(json_champ "$OPS_OUT/latences.json" 'v.fenetres.pendant.echecs')
NERR=$(json_champ "$OPS_OUT/latences.json" 'v.fenetres.nominal.echecs')
mesure "p95 des écritures, nominal ($NOMINAL s)" "${N95/./,}" ms
mesure "p95 des écritures pendant la sauvegarde$LARGIE" "${D95/./,}" ms
if [ "$N95" = null ] || [ "$D95" = null ]; then
  resultat "G29 p95 pendant la sauvegarde < 3 × nominal" echec "échantillon vide (journal : $REL/k6.log)"
elif awk -v d="$D95" -v n="$N95" 'BEGIN { exit !(d < 3 * n) }'; then
  resultat "G29 p95 pendant la sauvegarde < 3 × nominal" ok "${D95/./,} ms pendant, ${N95/./,} ms nominal, $DN écritures$LARGIE"
else
  resultat "G29 p95 pendant la sauvegarde < 3 × nominal" echec "${D95/./,} ms pendant, ${N95/./,} ms nominal (seuil : 3 × nominal)"
fi
verifier "G29 aucune erreur pendant la sauvegarde" "$DERR requête(s) en échec pendant (dont $(json_champ "$OPS_OUT/latences.json" 'v.fenetres.pendant.statuts_5xx') en 5xx), $NERR en nominal" [ "$DERR" = 0 ]

# Écritures acquittées avant la sauvegarde : référence = état après l'arrêt des écritures.
banc_dc "$P" exec -T locksy /app/locksy-server backup /data/sauvegardes/apres.db --force > /dev/null
docker cp "$CID:/data/sauvegardes/apres.db" "$(chemin_hote "$OPS_OUT/apres.db")"
base_js acquittes --avant $((T_DEBUT / 1000)) --reference "$OPS_OUT/apres.db" --copie "$SAUVEGARDE/locksy.db" > "$OPS_OUT/acquittes.json"
MANQ=$(json_champ "$OPS_OUT/acquittes.json" 'v.manquants + v.modifications_perdues')
verifier "aucune écriture acquittée avant la sauvegarde perdue" \
  "$(json_champ "$OPS_OUT/acquittes.json" 'v.presents + "/" + v.attendus + " créations et " + (v.modifications_attendues - v.modifications_perdues) + "/" + v.modifications_attendues + " dernières modifications présentes"')" \
  [ "$MANQ" = 0 ]

# ------------------------------------------------------------ 3. Restauration chronométrée
etape "3. Restauration sur un volume vide ($R) : RTO"
chrono_debut rto
ops_dc "$R" create locksy >/dev/null 2>&1
vers_le_volume "$(volume_de "$R")" "$SAUVEGARDE" locksy.db server.key
code_de ops_dc "$R" up -d --wait --wait-timeout 600 locksy
if [ "$CODE" -ne 0 ]; then
  ops_dc "$R" logs --no-color locksy > "$OPS_OUT/journal-restauration.txt" 2>&1 || true
  resultat "démarrage après restauration" echec "le serveur restauré ne démarre pas (journal : $REL/journal-restauration.txt)"
  terminer
fi
BASE_R="http://$(port "$R")"
attendre_sante "$BASE_R" 120
code_de ops_dc "$R" exec -T locksy /app/locksy-server check > "$OPS_OUT/check.txt" 2>&1
C_CHECK=$CODE
code_de ops_dc "$R" exec -T locksy /app/locksy-server verify-audit > "$OPS_OUT/verify-audit.txt" 2>&1
C_AUDIT=$CODE
code_de node ops-tests/lib/verif.mjs --base "$BASE_R" --out "$SEMIS" --wasm "$WASM" --echantillon 20 \
  --tolerer-illisibles --json "$OPS_OUT/verif-echantillon.json"
C_ECH=$CODE
RTO_MS=$(chrono_fin rto)
mesure "RTO (volume vide → service vérifié), jeu $OPS_JEU" "$(en_secondes "$RTO_MS")" s
verifier "check après restauration (code 0)" "$(grep -c '^OK' "$OPS_OUT/check.txt") ligne(s) OK, code $C_CHECK" [ "$C_CHECK" -eq 0 ]
verifier "verify-audit après restauration (code 0)" "$(head -1 "$OPS_OUT/verify-audit.txt"), code $C_AUDIT" [ "$C_AUDIT" -eq 0 ]
verifier "échantillon de 20 comptes déchiffré" \
  "$(json_champ "$OPS_OUT/verif-echantillon.json" 'v.comptes + " comptes, " + v.elements_dechiffres + "/" + v.elements_attendus + " éléments"' 2>/dev/null || echo "bilan absent")" [ "$C_ECH" -eq 0 ]
verifier "G30 RTO < 15 min" "$(en_secondes "$RTO_MS") s, jeu $OPS_JEU" [ "$RTO_MS" -lt 900000 ]

# ------------------------------------------------------------ 4. Contrôles hors RTO
etape "4. Contrôles hors RTO : base, comptes, déchiffrement complet"
base_js info "$SAUVEGARDE/locksy.db" > "$OPS_OUT/base-sauvegarde.json"
verifier "integrity_check de la sauvegarde" "$(json_champ "$OPS_OUT/base-sauvegarde.json" 'v.integrity + ", schéma v" + v.user_version')" \
  [ "$(json_champ "$OPS_OUT/base-sauvegarde.json" 'v.integrity')" = ok ]
comparer() { # comparer <libellé> <table> <attendu> <opérateur -eq|-ge>
  local n; n=$(json_champ "$OPS_OUT/base-sauvegarde.json" "v.tables.$2")
  verifier "$1 de la sauvegarde" "$n en base, $3 au manifeste" [ "$n" "$4" "$3" ]
}
comparer "comptes" users "$(json_champ "$SEMIS/manifest.json" 'v.counts.accounts')" -eq
comparer "coffres" collections "$(json_champ "$SEMIS/manifest.json" 'v.counts.collections')" -eq
comparer "pièces jointes" attachments "$PJ" -eq
comparer "éléments (semis plus écritures de k6)" items "$(json_champ "$SEMIS/manifest.json" 'v.counts.items')" -ge
code_de node ops-tests/lib/verif.mjs --base "$BASE_R" --out "$SEMIS" --wasm "$WASM" --tolerer-illisibles \
  --json "$OPS_OUT/verif-complete.json"
verifier "G30 100 % des éléments du semis déchiffrés (tous les comptes)" \
  "$(json_champ "$OPS_OUT/verif-complete.json" 'v.elements_dechiffres + "/" + v.elements_attendus + " éléments (" + v.taux_dechiffre + " %), " + v.pieces_jointes + " pièces jointes, " + v.illisibles_toleres + " écritures factices de k6 ignorées"' 2>/dev/null || echo "bilan absent")" \
  [ "$CODE" -eq 0 ]
ILL=$(json_champ "$OPS_OUT/verif-complete.json" 'v.illisibles_toleres' 2>/dev/null || echo -1)
K6_LIGNES=$(( $(json_champ "$OPS_OUT/base-sauvegarde.json" 'v.tables.items') - $(json_champ "$SEMIS/manifest.json" 'v.counts.items') ))
verifier "écritures de k6 sauvegardées toutes relues (chiffrés factices)" "$ILL relues, $K6_LIGNES lignes ajoutées par k6 dans la sauvegarde"   [ "$ILL" = "$K6_LIGNES" ]
mesure "durée de la vérification complète" "$(en_secondes "$(json_champ "$OPS_OUT/verif-complete.json" 'v.duree_ms' 2>/dev/null || echo 0)")" s
TOTP=$(json_champ "$OPS_OUT/verif-echantillon.json" 'v.comptes_totp' 2>/dev/null || echo 0)
if [ "$TOTP" -gt 0 ]; then
  verifier "G30 connexion 2FA après restauration" "$TOTP compte(s) à double authentification connecté(s) par code TOTP" [ "$C_ECH" -eq 0 ]
else
  resultat "G30 connexion 2FA après restauration" info "le jeu $OPS_JEU n'a aucun compte 2FA : contrôle fait par la variante --jeu E2E"
fi
resultat "G30 annuaire AD après restauration" info "non couvert dans le parcours rapide (pas de profil ldap sur le banc)"

if [ "$OPS_GARDER" = 0 ]; then rm -rf "$OPS_OUT/apres.db" "$SAUVEGARDE" "$WASM"; fi
terminer
