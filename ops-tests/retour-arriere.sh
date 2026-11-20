#!/usr/bin/env bash
# Retour arrière après une mise à jour, critère G33 (ADAPTATION V1.6 : la
# 1.0.0 ne connaît pas user_version et ne peut donc rien refuser) :
#  (a) le binaire courant, face à une base d'un schéma PLUS RÉCENT que le sien
#      (copie forgée en user_version = schéma + 1), refuse de démarrer SANS
#      écrire (empreinte inchangée, aucun -wal non vide) et `check` répond 1 ;
#  (b) la 1.0.0 démarrée sur la base migrée en v3 : comportement CONSTATÉ et
#      consigné (limite connue), sans verdict ;
#  (c) procédure documentée : restaurer la sauvegarde d'avant mise à jour,
#      démarrer la 1.0.0, contrôler la santé et le déchiffrement (client 1.0.0).
# Mode d'emploi : ops-tests/README.md.
source "$(dirname "$0")/lib.sh"

usage() {
  cat <<'EOF'
Retour arrière : refus d'une base trop récente sans écriture, puis retour à la 1.0.0.

Usage : bash ops-tests/retour-arriere.sh [-p projet] [--depuis <dossier>] [--garder]

  -p projet        préfixe du projet compose (défaut : q5-ops ; projet utilisé : <projet>-ra)
  --depuis <dir>   sorties d'une passe de mise-a-jour.sh (avant-maj/, apres-maj/, semis/) ;
                   défaut : la plus récente de bench/results/ops/, sinon mise-a-jour.sh est lancé
  --garder         garde le projet compose à la fin
  -h               affiche cette aide

Sorties : bench/results/ops/<horodatage>-retour-arriere/ (ou $OPS_OUT).
Codes de sortie : 0 réussite, 1 échec, 2 usage invalide.
EOF
}

DEPUIS=""
# shellcheck disable=SC2034 # OPS_DECALAGE et les variables d'option sont lues par lib.sh.
option_script() {
  case "$1" in
    --depuis)
      [ -n "${2:-}" ] && [ -d "$2" ] || erreur_usage "--depuis attend un dossier existant"
      DEPUIS=$2; OPS_DECALAGE=2 ;;
  esac
}
lire_options "$@"
OPS_JEU=${OPS_JEU:-E2E}
preparer_sortie

RA=$OPS_PROJET-ra
ouvrir_projet ops "$RA"
fermer_projet ops "$RA"
REL=$(chemin_relatif "$OPS_OUT")
VOLUME=$(volume_de "$RA")

complet() { [ -f "$1/avant-maj/locksy.db" ] && [ -f "$1/apres-maj/locksy.db" ] && [ -f "$1/apres-maj/server.key" ] && [ -f "$1/semis/users.json" ]; }

# ------------------------------------------------------------ 0. Bases avant et après mise à jour
etape "0. Bases d'avant et d'après la mise à jour"
if [ -z "$DEPUIS" ]; then
  for d in $(ls -d bench/results/ops/*-mise-a-jour 2>/dev/null | sort -r); do
    if complet "$d"; then DEPUIS=$d; break; fi
  done
fi
if [ -z "$DEPUIS" ]; then
  info "aucune passe de mise-a-jour.sh réutilisable : lancement"
  DEPUIS=$OPS_OUT/mise-a-jour
  OPS_OUT=$DEPUIS bash ops-tests/mise-a-jour.sh -p "$OPS_PROJET" || fatal "mise-a-jour.sh en échec : retour arrière impossible à recetter"
fi
complet "$DEPUIS" || fatal "$DEPUIS incomplet (avant-maj/, apres-maj/ ou semis/ manquant)"
resultat "bases de départ" info "$(chemin_relatif "$(chemin_hote "$(cd "$DEPUIS" && pwd)")")"
image_v100
SCHEMA=$(docker run --rm "$OPS_IMAGE" version | sed -n 's/.*schéma de base v\([0-9]*\).*/\1/p')
[ -n "$SCHEMA" ] || fatal "version du schéma de $OPS_IMAGE illisible"

# ------------------------------------------------------------ (a) Base trop récente
etape "(a) $OPS_IMAGE face à une base forgée en user_version = $((SCHEMA + 1))"
mkdir -p "$OPS_OUT/forgee"
cp "$DEPUIS/apres-maj/locksy.db" "$DEPUIS/apres-maj/server.key" "$OPS_OUT/forgee/"
base_js forger "$OPS_OUT/forgee/locksy.db" $((SCHEMA + 1)) > "$OPS_OUT/forgee.json"
H0=$(empreinte "$OPS_OUT/forgee/locksy.db")
ops_dc "$RA" create locksy >/dev/null 2>&1
vers_le_volume "$VOLUME" "$OPS_OUT/forgee" locksy.db server.key
lancer_detache "$RA" "$RA-n"
FIN=$(attendre_fin "$RA-n" 60)
docker logs "$RA-n" > "$OPS_OUT/demarrage-trop-recente.txt" 2>&1 || true
docker rm -f "$RA-n" >/dev/null 2>&1 || true
info "$(grep -m1 'Erreur' "$OPS_OUT/demarrage-trop-recente.txt" || true)"
verifier "G33 refus de démarrer (code 1)" "code de sortie : $FIN" [ "$FIN" = 1 ]
verifier "G33 message « plus récent »" "$REL/demarrage-trop-recente.txt" grep -q 'plus récent' "$OPS_OUT/demarrage-trop-recente.txt"
code_de ops_dc "$RA" run --rm --no-deps -T locksy check > "$OPS_OUT/check-trop-recente.txt" 2>&1
verifier "check : ERREUR « plus récent » et code 1" "code $CODE" \
  bash -c "[ $CODE -eq 1 ] && grep -q '^ERREUR.*plus récent' '$OPS_OUT/check-trop-recente.txt'"
lister_volume "$VOLUME" > "$OPS_OUT/volume-apres-refus.txt"
copier_du_volume "$VOLUME" locksy.db "$OPS_OUT/forgee-apres"
H1=$(empreinte "$OPS_OUT/forgee-apres/locksy.db")
verifier "G33 aucune écriture : empreinte SHA-256 inchangée" "${H0:0:16}… avant, ${H1:0:16}… après" [ "$H0" = "$H1" ]
WAL=$(awk '$1 == "locksy.db-wal" { print $2 }' "$OPS_OUT/volume-apres-refus.txt")
verifier "G33 aucun journal -wal non vide" "locksy.db-wal : ${WAL:-absent}" bash -c "[ -z '$WAL' ] || [ '$WAL' = 0 ]"

# ------------------------------------------------------------ (b) 1.0.0 sur la base migrée
etape "(b) $OPS_IMAGE_V100 sur la base migrée en v$SCHEMA (constat, limite connue)"
mkdir -p "$OPS_OUT/migree"
cp "$DEPUIS/apres-maj/locksy.db" "$DEPUIS/apres-maj/server.key" "$OPS_OUT/migree/"
H2=$(empreinte "$OPS_OUT/migree/locksy.db")
vers_le_volume "$VOLUME" "$OPS_OUT/migree" locksy.db server.key
OPS_SERVEUR_IMAGE=$OPS_IMAGE_V100 lancer_detache "$RA" "$RA-v100"
ETAT=$(attendre_fin "$RA-v100" 20)
SANTE="sans objet"
if [ "$ETAT" = en_marche ]; then
  ADR=$(docker port "$RA-v100" 8743 | head -1 | tr -d '\r')
  if attendre_sante "http://$ADR" 30 2>/dev/null; then
    SANTE="/api/health 200, version $(version_serveur "http://$ADR")"
  else
    SANTE="/api/health injoignable"
  fi
  docker stop -t 10 "$RA-v100" >/dev/null 2>&1 || true
fi
docker logs "$RA-v100" > "$OPS_OUT/v100-sur-v3.txt" 2>&1 || true
docker rm -f "$RA-v100" >/dev/null 2>&1 || true
copier_du_volume "$VOLUME" . "$OPS_OUT/migree-apres"
H3=$(empreinte "$OPS_OUT/migree-apres/locksy.db")
base_js info "$OPS_OUT/migree-apres/locksy.db" > "$OPS_OUT/migree-apres.json" 2>/dev/null || true
ERREURS=$(grep -ciE 'error|erreur|panic' "$OPS_OUT/v100-sur-v3.txt" || true)
if [ "$ETAT" = en_marche ]; then DEMARRE="démarre ($SANTE)"; else DEMARRE="s'arrête (code $ETAT)"; fi
if [ "$H2" = "$H3" ]; then ECRIT="base inchangée"; else ECRIT="base MODIFIÉE (empreinte différente)"; fi
resultat "1.0.0 sur une base v$SCHEMA (limite connue)" info "$DEMARRE ; $ECRIT ; user_version après : $(json_champ "$OPS_OUT/migree-apres.json" 'v.user_version' 2>/dev/null || echo '?') ; $ERREURS ligne(s) d'erreur au journal ($REL/v100-sur-v3.txt)"
mesure "1.0.0 sur base v$SCHEMA" "$DEMARRE, $ECRIT" "constat"

# ------------------------------------------------------------ (c) Procédure documentée
etape "(c) Procédure : restaurer la sauvegarde d'avant mise à jour, démarrer la 1.0.0"
sources_v100
mkdir -p "$OPS_OUT/restauree"
# Tout le dossier de données copié à froid (la 1.0.0 a pu laisser un -wal).
cp "$DEPUIS/avant-maj/"* "$OPS_OUT/restauree/"
chrono_debut retour
mapfile -t FICHIERS < <(cd "$OPS_OUT/restauree" && ls)
vers_le_volume "$VOLUME" "$OPS_OUT/restauree" "${FICHIERS[@]}"
code_de env OPS_SERVEUR_IMAGE="$OPS_IMAGE_V100" docker compose -p "$RA" -f "$OPS_COMPOSE" up -d --wait --wait-timeout 120 locksy
if [ "$CODE" -ne 0 ]; then
  resultat "G33 retour à la 1.0.0 par la sauvegarde d'avant mise à jour" echec "la 1.0.0 ne démarre pas"
  terminer
fi
BASE="http://$(port "$RA")"
attendre_sante "$BASE" 60
mesure "retour arrière (dépôt de la sauvegarde → 1.0.0 en bonne santé)" "$(en_secondes "$(chrono_fin retour)")" s
V=$(version_serveur "$BASE")
verifier "G33 1.0.0 en service après restauration" "/api/health : version $V" [ "$V" = 1.0.0 ]
WASM_V100=$OPS_OUT/locksy-v100.wasm
extraire_de_image "$OPS_IMAGE_V100" /app/web/locksy.wasm "$WASM_V100"
code_de node "$V100_SRC/bench/seed/verify.mjs" --dataset E2E --base "$BASE" --wasm "$WASM_V100" --out "$DEPUIS/semis" --workers 2
verifier "G33 le client 1.0.0 déchiffre tout après le retour arrière" "verify.mjs (client 1.0.0) : code $CODE" [ "$CODE" -eq 0 ]
verifier "procédure documentée" "docs/Sauvegarde-et-mises-a-jour.md : section « Retour arrière »" \
  grep -q '^## Retour arrière' docs/Sauvegarde-et-mises-a-jour.md

if [ "$OPS_GARDER" = 0 ]; then rm -rf "$OPS_OUT/forgee" "$OPS_OUT/forgee-apres" "$OPS_OUT/migree" "$OPS_OUT/migree-apres" "$OPS_OUT/restauree" "$WASM_V100"; fi
terminer
