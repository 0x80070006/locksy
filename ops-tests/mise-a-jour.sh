#!/usr/bin/env bash
# Mise à jour 1.0.0 (N-1) → version courante (N), critère G32 : la 1.0.0,
# reconstruite depuis git HEAD, est semée par SON client ; sauvegarde d'avant
# mise à jour ; N démarre sur le même volume ; indisponibilité chronométrée ;
# migrations, schéma, check, déchiffrement par le client courant, connexion
# 2FA, lien de partage et anciens réglages contrôlés. Mode d'emploi : ops-tests/README.md.
source "$(dirname "$0")/lib.sh"

usage() {
  cat <<'EOF'
Mise à jour 1.0.0 → version courante, sur le même volume de données.

Usage : bash ops-tests/mise-a-jour.sh [-p projet] [--jeu E2E] [--reconstruire] [--garder]

  -p projet       préfixe du projet compose (défaut : q5-ops ; projet utilisé : <projet>-maj)
  --jeu           E2E seulement (semé par le client 1.0.0)
  --reconstruire  reconstruit l'image 1.0.0 même si elle existe (ops-tests/v100/construire.sh)
  --garder        garde le projet compose à la fin
  -h              affiche cette aide

Images : $OPS_IMAGE_V100 (défaut locksy-ops:1.0.0, construite si absente, repli locksy:1.0.0)
         et $OPS_IMAGE (défaut locksy-e2e-server:fast).
Sorties : bench/results/ops/<horodatage>-mise-a-jour/ (ou $OPS_OUT), dont avant-maj/ (sauvegarde
d'avant mise à jour), apres-maj/ (base migrée) et semis/ (comptes de test), reprises par
retour-arriere.sh.
Codes de sortie : 0 réussite, 1 échec, 2 usage invalide.
EOF
}

# shellcheck disable=SC2034 # OPS_DECALAGE et les variables d'option sont lues par lib.sh.
option_script() {
  case "$1" in
    --reconstruire) OPS_RECONSTRUIRE=1; OPS_DECALAGE=1 ;;
  esac
}
lire_options "$@"
OPS_JEU=${OPS_JEU:-E2E}
[ "$OPS_JEU" = E2E ] || erreur_usage "la mise à jour se recette avec le jeu E2E (semé par le client 1.0.0)"
preparer_sortie

U=$OPS_PROJET-maj
ouvrir_projet ops "$U"
fermer_projet ops "$U"
SEMIS=$OPS_OUT/semis
REL=$(chemin_relatif "$OPS_OUT")
mkdir -p "$SEMIS"

# ------------------------------------------------------------ 1. Images et clients
etape "1. Image 1.0.0, sources 1.0.0 et modules WebAssembly"
image_v100
sources_v100
REVISION=$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$OPS_IMAGE_V100" 2>/dev/null || true)
resultat "image 1.0.0" info "$OPS_IMAGE_V100${REVISION:+, révision ${REVISION:0:12}}"
WASM_V100=$OPS_OUT/locksy-v100.wasm
WASM_N=$OPS_OUT/locksy.wasm
extraire_de_image "$OPS_IMAGE_V100" /app/web/locksy.wasm "$WASM_V100"
extraire_de_image "$OPS_IMAGE" /app/web/locksy.wasm "$WASM_N"

# ------------------------------------------------------------ 2. Instance 1.0.0 semée par son client
etape "2. Démarrage de la 1.0.0 ($U) et semis par le client 1.0.0"
OPS_SERVEUR_IMAGE=$OPS_IMAGE_V100 ops_dc "$U" up -d --wait --wait-timeout 180 locksy
BASE="http://$(port "$U")"
attendre_sante "$BASE" 60
V_AVANT=$(version_serveur "$BASE")
verifier "serveur N-1 en version 1.0.0" "/api/health : version $V_AVANT" [ "$V_AVANT" = 1.0.0 ]
verifier "journal de démarrage de la 1.0.0" "« Locksy 1.0.0 à l'écoute »" \
  bash -c "docker compose -p '$U' -f '$OPS_COMPOSE' logs --no-color locksy 2>&1 | grep -q 'Locksy 1.0.0 à l.écoute'"
chrono_debut semis
code_de node "$V100_SRC/bench/seed/seed.mjs" --dataset E2E --base "$BASE" --wasm "$WASM_V100" --out "$SEMIS" \
  --setup-token sans-objet-en-1.0.0 --workers 2
verifier "semis E2E par le client 1.0.0 (bench/seed sur web/js de la 1.0.0)" "code $CODE" [ "$CODE" -eq 0 ]
[ "$CODE" -eq 0 ] || terminer
code_de node ops-tests/lib/semis-v100.mjs completer --base "$BASE" --client "$V100_SRC/web/js" --wasm "$WASM_V100" --out "$SEMIS"
verifier "réglages 1.0.0 et lien de partage créés par le client 1.0.0" "5 réglages, 1 lien" [ "$CODE" -eq 0 ]
code_de node "$V100_SRC/bench/seed/verify.mjs" --dataset E2E --base "$BASE" --wasm "$WASM_V100" --out "$SEMIS" --workers 2
verifier "référence : le client 1.0.0 relit tout sur la 1.0.0" "verify.mjs de la 1.0.0 : code $CODE" [ "$CODE" -eq 0 ]
mesure "semis et contrôle sur la 1.0.0" "$(en_secondes "$(chrono_fin semis)")" s

# ------------------------------------------------------------ 3. Mise à jour
etape "3. Arrêt de la 1.0.0, sauvegarde d'avant mise à jour, démarrage de N sur le même volume"
VOLUME=$(volume_de "$U")
chrono_debut indisponibilite
OPS_SERVEUR_IMAGE=$OPS_IMAGE_V100 ops_dc "$U" stop locksy >/dev/null 2>&1
copier_du_volume "$VOLUME" . "$OPS_OUT/avant-maj"
chrono_debut bascule
code_de ops_dc "$U" up -d --wait --wait-timeout 180 locksy
if [ "$CODE" -ne 0 ]; then
  ops_dc "$U" logs --no-color locksy > "$OPS_OUT/journal-n.txt" 2>&1 || true
  resultat "démarrage de N sur la base 1.0.0" echec "le serveur ne démarre pas ($REL/journal-n.txt)"
  terminer
fi
BASE="http://$(port "$U")"
attendre_sante "$BASE" 60
INDISPO=$(chrono_fin indisponibilite)
BASCULE=$(chrono_fin bascule)
mesure "indisponibilité de la mise à jour (arrêt 1.0.0 → N en bonne santé, copie du volume comprise)" "$(en_secondes "$INDISPO")" s
mesure "dont démarrage de N et migration" "$(en_secondes "$BASCULE")" s
verifier "G32 indisponibilité < 60 s" "$(en_secondes "$INDISPO") s (jeu E2E)" [ "$INDISPO" -lt 60000 ]
base_js info "$OPS_OUT/avant-maj/locksy.db" > "$OPS_OUT/base-avant.json"
verifier "base de la 1.0.0 sans PRAGMA user_version" "user_version = $(json_champ "$OPS_OUT/base-avant.json" 'v.user_version')" \
  [ "$(json_champ "$OPS_OUT/base-avant.json" 'v.user_version')" = 0 ]

# ------------------------------------------------------------ 4. Contrôles sur N
etape "4. Contrôles après mise à jour"
V_APRES=$(version_serveur "$BASE")
NOTE_VERSION=""
[ "$V_APRES" = "$V_AVANT" ] && NOTE_VERSION=" ; même numéro que N-1 : handoff Q5-H3 (passer à 1.1.0)"
resultat "version de N" info "/api/health : $V_APRES ; binaire : $(docker run --rm "$OPS_IMAGE" version 2>/dev/null | tr -d '\r')$NOTE_VERSION"
ops_dc "$U" logs --no-color locksy > "$OPS_OUT/journal-n.txt" 2>&1 || true
MIGRATIONS=$(grep -c 'schéma de la base migré' "$OPS_OUT/journal-n.txt" || true)
verifier "journal des migrations" "$MIGRATIONS palier(s) : $(grep -o 'version=[0-9]*' "$OPS_OUT/journal-n.txt" | tr '\n' ' ')" \
  [ "$MIGRATIONS" -ge 1 ]
code_de ops_dc "$U" exec -T locksy /app/locksy-server check > "$OPS_OUT/check.txt" 2>&1
verifier "check après mise à jour (code 0)" "$(grep -m1 'schéma' "$OPS_OUT/check.txt" || true)" [ "$CODE" -eq 0 ]
ops_dc "$U" exec -T locksy /app/locksy-server backup /data/apres-maj.db --with-key --force > /dev/null
CID=$(ops_dc "$U" ps -q locksy)
mkdir -p "$OPS_OUT/apres-maj"
docker cp "$CID:/data/apres-maj.db" "$(chemin_hote "$OPS_OUT/apres-maj/locksy.db")"
docker cp "$CID:/data/apres-maj.db.server.key" "$(chemin_hote "$OPS_OUT/apres-maj/server.key")"
ops_dc "$U" exec -T locksy rm -f /data/apres-maj.db /data/apres-maj.db.server.key
base_js info "$OPS_OUT/apres-maj/locksy.db" > "$OPS_OUT/base-apres.json"
SCHEMA=$(docker run --rm "$OPS_IMAGE" version | sed -n 's/.*schéma de base v\([0-9]*\).*/\1/p')
verifier "PRAGMA user_version = schéma de N" "user_version = $(json_champ "$OPS_OUT/base-apres.json" 'v.user_version'), attendu $SCHEMA" \
  [ "$(json_champ "$OPS_OUT/base-apres.json" 'v.user_version')" = "$SCHEMA" ]
for t in users collections memberships items attachments shares; do
  avant=$(json_champ "$OPS_OUT/base-avant.json" "v.tables.$t")
  apres=$(json_champ "$OPS_OUT/base-apres.json" "v.tables.$t")
  verifier "G32 sans perte : table $t" "$avant avant, $apres après" [ "$avant" = "$apres" ]
done

code_de node ops-tests/lib/verif.mjs --base "$BASE" --out "$SEMIS" --wasm "$WASM_N" --json "$OPS_OUT/verif.json"
C_VERIF=$CODE
TOTP=$(json_champ "$OPS_OUT/verif.json" 'v.comptes_totp' 2>/dev/null || echo 0)
verifier "G32 le client courant déchiffre 100 % des éléments semés par la 1.0.0" \
  "$(json_champ "$OPS_OUT/verif.json" 'v.elements_dechiffres + "/" + v.elements_attendus + " éléments, " + v.pieces_jointes + " pièces jointes, " + v.comptes + " comptes"' 2>/dev/null || echo "bilan absent")" \
  [ "$C_VERIF" -eq 0 ]
verifier "G32 connexion 2FA après mise à jour" "$TOTP compte(s) à double authentification connecté(s) par code TOTP" \
  test "$C_VERIF" -eq 0 -a "$TOTP" -ge 1
code_de node ops-tests/lib/semis-v100.mjs controler-lien --base "$BASE" --client web/js --wasm "$WASM_N" --out "$SEMIS"
verifier "lien de partage de la 1.0.0 ouvert et déchiffré par le client courant" "code $CODE" [ "$CODE" -eq 0 ]
code_de node ops-tests/lib/semis-v100.mjs controler-reglages --base "$BASE" --out "$SEMIS" > "$OPS_OUT/reglages.json"
verifier "G32 réglages 1.0.0 repris dans le registre (source org)" \
  "$(json_champ "$OPS_OUT/reglages.json" 'v.reglages.map((r) => r.cle + "=" + r.valeur + " (" + r.source + ")").join(", ")' 2>/dev/null || echo "relecture impossible")" \
  [ "$CODE" -eq 0 ]
resultat "G32 E2E lecture seule et extension N-1" info "hors du parcours rapide (non exécutés)"
if [ "$OPS_GARDER" = 0 ]; then rm -f "$WASM_V100" "$WASM_N"; fi
terminer
