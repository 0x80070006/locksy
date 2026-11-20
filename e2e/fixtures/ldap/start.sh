#!/bin/bash
# Démarrage du contrôleur Active Directory des tests (profil « ldap ») :
# provisionne le domaine E2E.LOCAL par le script d'origine de l'image, crée
# les comptes de comptes.tsv, publie le certificat de l'autorité LDAPS dans le
# volume partagé /ldap-ca (lu par le lanceur Playwright), puis signale qu'il est
# prêt (/tmp/e2e-pret, lu par le healthcheck de docker-compose.e2e.yml).
set -euo pipefail

/init.sh &
init_pid=$!

echo "Attente du provisionnement du domaine…"
for _ in $(seq 1 180); do
  if samba-tool user show Administrator >/dev/null 2>&1 && [[ -f /var/lib/samba/private/tls/ca.pem ]]; then
    break
  fi
  kill -0 "$init_pid" 2>/dev/null || { echo "Le provisionnement de Samba a échoué." >&2; exit 1; }
  sleep 1
done

while IFS=$'\t' read -r login password given surname mail state; do
  [[ -z "$login" || "$login" == \#* ]] && continue
  state="${state%$'\r'}"
  if ! samba-tool user show "$login" >/dev/null 2>&1; then
    samba-tool user create "$login" "$password" --given-name="$given" --surname="$surname" \
      --mail-address="$mail" --use-username-as-cn >/dev/null
  fi
  if [[ "$state" == "desactive" ]]; then
    samba-tool user disable "$login" >/dev/null
  fi
done < /e2e/comptes.tsv

install -m 0644 /var/lib/samba/private/tls/ca.pem /ldap-ca/ca.pem
touch /tmp/e2e-pret
echo "Annuaire E2E.LOCAL prêt."
wait "$init_pid"
