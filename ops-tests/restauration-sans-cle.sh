#!/usr/bin/env bash
# Restauration de la base SANS server.key (test négatif, critère G31) : le
# serveur doit refuser de démarrer avec un message clair ; avec
# LOCKSY_SERVER_KEY_RESET=true, il démarre, les comptes sans 2FA se connectent
# et déchiffrent, les comptes 2FA reçoivent une erreur claire (jamais une 500),
# et verify-audit signale un chaînage invérifiable. Mode d'emploi : ops-tests/README.md.
source "$(dirname "$0")/lib.sh"

usage() {
  cat <<'EOF'
Restauration de la base sans server.key (test négatif).

Usage : bash ops-tests/restauration-sans-cle.sh [-p projet] [--jeu E2E|M] [--garder]

  -p projet   préfixe du projet compose (défaut : q5-ops ; projet utilisé : <projet>-sc)
  --jeu       E2E (défaut : comptes avec et sans 2FA) ou M
  --garder    garde le projet compose à la fin
  -h          affiche cette aide

Source : bench/snapshots/<jeu> (semé sur un banc temporaire s'il manque).
Sorties : bench/results/ops/<horodatage>-restauration-sans-cle/ (ou $OPS_OUT).
Codes de sortie : 0 réussite, 1 échec, 2 usage invalide.
EOF
}

lire_options "$@"
OPS_JEU=${OPS_JEU:-E2E}
preparer_sortie

S=$OPS_PROJET-sc
ouvrir_projet ops "$S"
fermer_projet ops "$S"
SEMIS=bench/seed/out/$OPS_JEU
REL=$(chemin_relatif "$OPS_OUT")

etape "1. Base du jeu $OPS_JEU restaurée SANS server.key ($S)"
assurer_instantane "$OPS_JEU"
SOURCE=bench/snapshots/$OPS_JEU
ops_dc "$S" create locksy >/dev/null 2>&1
VOLUME=$(volume_de "$S")
vers_le_volume "$VOLUME" "$SOURCE" locksy.db
lister_volume "$VOLUME" > "$OPS_OUT/volume-avant.txt"
verifier "volume restauré sans clé" "$(tr '\n' ' ' < "$OPS_OUT/volume-avant.txt")" \
  bash -c "! grep -q '^server.key ' '$OPS_OUT/volume-avant.txt'"

etape "2. Démarrage normal : refus attendu"
lancer_detache "$S" "$S-sans-cle"
FIN=$(attendre_fin "$S-sans-cle" 90)
docker logs "$S-sans-cle" > "$OPS_OUT/demarrage-sans-cle.txt" 2>&1 || true
info "$(grep -m1 'Erreur' "$OPS_OUT/demarrage-sans-cle.txt" || true)"
verifier "G31 refus de démarrer (code 1)" "code de sortie : $FIN" [ "$FIN" = 1 ]
verifier "G31 message clair (« server.key » et « Restaurez »)" "$REL/demarrage-sans-cle.txt" \
  bash -c "grep -q 'server.key' '$OPS_OUT/demarrage-sans-cle.txt' && grep -q 'Restaurez' '$OPS_OUT/demarrage-sans-cle.txt'"
verifier "message en français, avec la variable de dernier recours" "LOCKSY_SERVER_KEY_RESET cité" \
  grep -q 'LOCKSY_SERVER_KEY_RESET' "$OPS_OUT/demarrage-sans-cle.txt"
docker rm -f "$S-sans-cle" >/dev/null 2>&1 || true
lister_volume "$VOLUME" > "$OPS_OUT/volume-apres-refus.txt"
verifier "aucune clé générée par le refus" "$(tr '\n' ' ' < "$OPS_OUT/volume-apres-refus.txt")" \
  bash -c "! grep -q '^server.key ' '$OPS_OUT/volume-apres-refus.txt'"

code_de ops_dc "$S" run --rm --no-deps -T locksy check > "$OPS_OUT/check-sans-cle.txt" 2>&1
verifier "check sans clé : ERREUR et code 1" "code $CODE, $(grep -c '^ERREUR' "$OPS_OUT/check-sans-cle.txt") ligne(s) ERREUR" \
  bash -c "[ $CODE -eq 1 ] && grep -q '^ERREUR.*server.key' '$OPS_OUT/check-sans-cle.txt'"

etape "3. Dernier recours : LOCKSY_SERVER_KEY_RESET=true"
code_de env OPS_KEY_RESET=true OPS_SERVEUR_IMAGE="$OPS_IMAGE" docker compose -p "$S" -f "$OPS_COMPOSE" up -d --wait --wait-timeout 180 locksy
ops_dc "$S" logs --no-color locksy > "$OPS_OUT/demarrage-reinitialise.txt" 2>&1 || true
if [ "$CODE" -ne 0 ]; then
  resultat "démarrage avec LOCKSY_SERVER_KEY_RESET=true" echec "le serveur ne démarre pas ($REL/demarrage-reinitialise.txt)"
  terminer
fi
resultat "démarrage avec LOCKSY_SERVER_KEY_RESET=true" ok "nouvelle clé générée"
verifier "avertissement journalisé au démarrage" "2FA, LDAP et SSO à reconfigurer" \
  grep -q 'LOCKSY_SERVER_KEY_RESET' "$OPS_OUT/demarrage-reinitialise.txt"
BASE="http://$(port "$S")"
attendre_sante "$BASE" 60
WASM=$OPS_OUT/locksy.wasm
extraire_de_image "$OPS_IMAGE" /app/web/locksy.wasm "$WASM"

# Comptes sans 2FA : connexion et déchiffrement complet (le chiffrement des
# coffres ne dépend pas de la clé serveur).
SANS_2FA=$(json_champ "$SEMIS/users.json" 'v.filter((u) => !u.totp_secret).slice(0, 3).map((u) => u.email).join(",")')
code_de node ops-tests/lib/verif.mjs --base "$BASE" --out "$SEMIS" --wasm "$WASM" --comptes "$SANS_2FA" \
  --json "$OPS_OUT/verif-sans-2fa.json"
verifier "G31 comptes sans 2FA : connexion et déchiffrement" \
  "$(json_champ "$OPS_OUT/verif-sans-2fa.json" 'v.comptes + " compte(s), " + v.elements_dechiffres + "/" + v.elements_attendus + " éléments"' 2>/dev/null || echo "bilan absent")" \
  [ "$CODE" -eq 0 ]

# Comptes 2FA : le secret TOTP, chiffré par l'ancienne clé, est illisible.
AVEC_2FA=$(json_champ "$SEMIS/users.json" '(v.find((u) => u.totp_secret) || {}).email || ""')
if [ -n "$AVEC_2FA" ]; then
  node ops-tests/lib/connexion.mjs --base "$BASE" --out "$SEMIS" --email "$AVEC_2FA" > "$OPS_OUT/connexion-2fa.json"
  ST=$(json_champ "$OPS_OUT/connexion-2fa.json" 'v.etapes[v.etapes.length - 1].status')
  CODE_ERR=$(json_champ "$OPS_OUT/connexion-2fa.json" 'v.etapes[v.etapes.length - 1].error')
  MSG=$(json_champ "$OPS_OUT/connexion-2fa.json" 'v.etapes[v.etapes.length - 1].message')
  MAX=$(json_champ "$OPS_OUT/connexion-2fa.json" 'Math.max(...v.etapes.map((e) => e.status))')
  STATUTS=$(json_champ "$OPS_OUT/connexion-2fa.json" 'v.etapes.map((e) => e.status + " " + e.error).join(", ")')
  if [ "$MAX" -ge 500 ]; then
    # Défaut connu : auth.rs, decrypt_totp_secret renvoie ApiError::internal (handoff Q5-H1).
    resultat "G31 compte 2FA : erreur claire, jamais 500" echec "statuts : $STATUTS ; défaut produit, handoff Q5-H1"
  else
    verifier "G31 compte 2FA : erreur claire, jamais 500" "statuts : $STATUTS" \
      bash -c "[ '$ST' -ge 400 ] && [ -n \"\$1\" ] && [ \"\$1\" != null ]" _ "$MSG"
  fi
  resultat "message reçu par le compte 2FA" info "$AVEC_2FA : HTTP $ST, code « $CODE_ERR », message « $MSG »"
else
  resultat "G31 compte 2FA" info "le jeu $OPS_JEU n'a aucun compte 2FA"
fi

code_de ops_dc "$S" exec -T locksy /app/locksy-server verify-audit > "$OPS_OUT/verify-audit.txt" 2>&1
verifier "verify-audit : chaînage invérifiable signalé (code non nul)" "code $CODE : $(head -1 "$OPS_OUT/verify-audit.txt")" \
  [ "$CODE" -ne 0 ]
verifier "verify-audit : cause probable (clé changée) indiquée" "$(tail -1 "$OPS_OUT/verify-audit.txt")" \
  grep -q 'LOCKSY_SERVER_KEY_RESET' "$OPS_OUT/verify-audit.txt"
resultat "G31 liaison AD (mot de passe du compte de service)" info "non couverte dans le parcours rapide (pas de profil ldap)"

etape "4. Documentation"
DOC=docs/Sauvegarde-et-mises-a-jour.md
verifier "procédure sans clé documentée" "$DOC cite le refus de démarrer et LOCKSY_SERVER_KEY_RESET" \
  bash -c "grep -q 'refuse de démarrer' '$DOC' && grep -q 'LOCKSY_SERVER_KEY_RESET' '$DOC'"

terminer
