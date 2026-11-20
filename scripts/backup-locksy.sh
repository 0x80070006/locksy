#!/usr/bin/env bash
# =============================================================================
#  Locksy : sauvegarde de la base, vérifiée par un test de restauration
#
#  Usage :
#    backup-locksy.sh [--dest DIR] [--keep N] [--name NOM] [--with-key]
#                     [--age-recipient R | --gpg-recipient R]
#                     [--docker CONTENEUR] [--no-restore-test]
#
#  Options :
#    --dest DIR             dossier des sauvegardes (défaut /var/backups/locksy)
#    --keep N               nombre de sauvegardes locksy-* conservées (défaut 14)
#    --name NOM             nom de la sauvegarde (NOM.db) au lieu de
#                           locksy-AAAAMMJJ-HHMMSS.db ; non concernée par la rotation
#    --with-key             copie aussi la clé serveur (<base>.db.server.key) ;
#                           refusé sans chiffrement
#    --age-recipient R      chiffre avec age pour le destinataire R (age1...)
#    --gpg-recipient R      chiffre avec GnuPG pour la clé publique R
#    --docker CONTENEUR     sauvegarde la base d'un conteneur Locksy en marche
#    --no-restore-test      ne pas tester la restauration (déconseillé)
#
#  Variables de repli (fichier backup.env du timer, ou environnement) :
#    LOCKSY_BACKUP_DIR, LOCKSY_BACKUP_KEEP, LOCKSY_BACKUP_AGE_RECIPIENT,
#    LOCKSY_BACKUP_GPG_RECIPIENT, LOCKSY_BACKUP_WITH_KEY (0 ou 1),
#    LOCKSY_SERVER_BIN (défaut /opt/locksy/locksy-server), LOCKSY_DATA et
#    LOCKSY_SERVER_KEY_FILE (transmis au serveur). Absentes de l'environnement,
#    elles sont lues dans /etc/locksy/backup.env et /etc/locksy/locksy.env.
#
#  Fichiers produits dans le dossier des sauvegardes :
#    locksy-AAAAMMJJ-HHMMSS.db[.age|.gpg]
#    locksy-AAAAMMJJ-HHMMSS.db.server.key[.age|.gpg]   (avec --with-key)
#  Les N plus récentes sont conservées ; les sauvegardes d'avant mise à jour
#  (pre-upgrade-*, écrites par install.sh) sont gardées à part : 5 dernières.
#
#  Test de restauration : la copie en clair est restaurée dans un dossier
#  temporaire et contrôlée par « locksy-server check » (code 0 exigé), avant
#  chiffrement. Rien n'est écrit dans la base de production.
#
#  Codes de sortie : 0 succès, 1 échec (test de restauration compris),
#  2 mauvaise utilisation. Une ligne de résultat est écrite sur la sortie
#  standard (journald avec le timer locksy-backup).
# =============================================================================
set -euo pipefail
umask 077

PROG=locksy-backup
CONF_DIR=/etc/locksy
PRE_UPGRADE_KEEP=5

log() { printf '%s: %s\n' "$PROG" "$*"; }
fail() { # Échec : détail sur la sortie d'erreur, ligne de résultat sur stdout.
  printf '%s: erreur : %s\n' "$PROG" "$*" >&2
  printf '%s: ÉCHEC %s\n' "$PROG" "$*"
  exit 1
}
bad_usage() { printf '%s: %s (voir --help)\n' "$PROG" "$*" >&2; exit 2; }
has() { command -v "$1" >/dev/null 2>&1; }
usage() {
  if [ -r "$0" ]; then sed -n '2,/^# =\{20,\}/p' "$0" | sed 's/^# \{0,1\}//'
  else echo "Usage : backup-locksy.sh [--dest DIR] [--keep N] [--name NOM] [--with-key] [--age-recipient R | --gpg-recipient R] [--docker CONTENEUR] [--no-restore-test]"; fi
}

# Valeur de CLE dans un fichier CLE=valeur, sans l'exécuter (pas de source).
file_get() { # fichier clé
  [ -r "$1" ] || return 0
  sed -n "s/^[[:space:]]*$2=//p" "$1" | tail -n 1 | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/"
}
# Variable absente de l'environnement (même vide, elle compte comme présente) :
# reprise du fichier de configuration.
default_from() { # fichier variable
  local v
  if [ -z "${!2+x}" ]; then
    v=$(file_get "$1" "$2")
    if [ -n "$v" ]; then printf -v "$2" '%s' "$v"; export "${2?}"; fi
  fi
}
for v in LOCKSY_BACKUP_DIR LOCKSY_BACKUP_KEEP LOCKSY_BACKUP_AGE_RECIPIENT LOCKSY_BACKUP_GPG_RECIPIENT \
  LOCKSY_BACKUP_WITH_KEY GNUPGHOME; do
  default_from "$CONF_DIR/backup.env" "$v"
done
for v in LOCKSY_DATA LOCKSY_SERVER_KEY_FILE; do default_from "$CONF_DIR/locksy.env" "$v"; done

is_true() { case "${1,,}" in 1|true|yes|oui|on) return 0 ;; *) return 1 ;; esac; }

DEST=${LOCKSY_BACKUP_DIR:-/var/backups/locksy}
KEEP=${LOCKSY_BACKUP_KEEP:-14}
NAME=""
WITH_KEY=0; is_true "${LOCKSY_BACKUP_WITH_KEY:-0}" && WITH_KEY=1
ENV_AGE=${LOCKSY_BACKUP_AGE_RECIPIENT:-} ENV_GPG=${LOCKSY_BACKUP_GPG_RECIPIENT:-}
CLI_AGE="" CLI_GPG=""
DOCKER=""
RESTORE_TEST=1
ARGS=("$@")

need_arg() { [ $# -ge 2 ] && [ -n "$2" ] || bad_usage "l'option $1 attend une valeur"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --dest) need_arg "$@"; DEST=$2; shift 2 ;;
    --keep) need_arg "$@"; KEEP=$2; shift 2 ;;
    --name) need_arg "$@"; NAME=$2; shift 2 ;;
    --with-key) WITH_KEY=1; shift ;;
    --age-recipient) need_arg "$@"; CLI_AGE=$2; shift 2 ;;
    --gpg-recipient) need_arg "$@"; CLI_GPG=$2; shift 2 ;;
    --docker) need_arg "$@"; DOCKER=$2; shift 2 ;;
    --no-restore-test) RESTORE_TEST=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) bad_usage "option inconnue : $1" ;;
  esac
done

# Destinataire : la ligne de commande remplace la configuration.
if [ -n "$CLI_AGE" ] && [ -n "$CLI_GPG" ]; then bad_usage "--age-recipient et --gpg-recipient s'excluent"; fi
if [ -n "$CLI_AGE$CLI_GPG" ]; then AGE_R=$CLI_AGE GPG_R=$CLI_GPG
else AGE_R=$ENV_AGE GPG_R=$ENV_GPG; fi
if [ -n "$AGE_R" ] && [ -n "$GPG_R" ]; then
  bad_usage "LOCKSY_BACKUP_AGE_RECIPIENT et LOCKSY_BACKUP_GPG_RECIPIENT sont tous deux définis : choisissez-en un"
fi
ENC=none; [ -n "$AGE_R" ] && ENC=age; [ -n "$GPG_R" ] && ENC=gpg
if [ "$WITH_KEY" = 1 ] && [ "$ENC" = none ]; then
  bad_usage "--with-key exige le chiffrement (--age-recipient ou --gpg-recipient) : la clé serveur ne doit jamais être copiée en clair"
fi
[[ "$KEEP" =~ ^[0-9]+$ ]] && [ "$KEEP" -ge 1 ] || bad_usage "--keep attend un entier supérieur ou égal à 1 (reçu : $KEEP)"
case "$DEST" in /*) ;; *) bad_usage "--dest attend un chemin absolu (reçu : $DEST)" ;; esac
[ "$DEST" != / ] || bad_usage "--dest / refusé"
if [ -n "$NAME" ]; then
  NAME=${NAME%.db}
  [[ "$NAME" =~ ^[A-Za-z0-9_][A-Za-z0-9._-]*$ ]] || bad_usage "--name : lettres, chiffres, . _ - uniquement (reçu : $NAME)"
fi
if [ -n "$DOCKER" ]; then
  [[ "$DOCKER" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || bad_usage "--docker : nom de conteneur invalide ($DOCKER)"
fi

case "$ENC" in
  age) has age || fail "age est introuvable : installez-le (paquet age) ou retirez le destinataire age" ;;
  gpg) has gpg || fail "gpg est introuvable : installez GnuPG ou retirez le destinataire GPG" ;;
esac

# Mode natif lancé en root : la sauvegarde s'exécute sous le compte du service,
# pour que les fichiers de la base (-shm) gardent le bon propriétaire.
if [ -z "$DOCKER" ] && [ "$(id -u)" = 0 ] && id locksy >/dev/null 2>&1 && [ -z "${LOCKSY_BACKUP_REEXEC:-}" ]; then
  has runuser || fail "runuser est introuvable : lancez ce script avec le compte locksy (sudo -u locksy)"
  export LOCKSY_BACKUP_REEXEC=1 LOCKSY_BACKUP_DIR="$DEST"
  if [ -n "${LOCKSY_DATA:-}" ]; then export LOCKSY_DATA; fi
  if [ -n "${LOCKSY_SERVER_KEY_FILE:-}" ]; then export LOCKSY_SERVER_KEY_FILE; fi
  SELF=$(readlink -f "$0")
  cd /
  exec runuser -u locksy -- bash "$SELF" "${ARGS[@]}"
fi

# ----------------------------------------------------------------- Préparation
if [ ! -d "$DEST" ]; then
  mkdir -p "$DEST" || fail "impossible de créer le dossier des sauvegardes $DEST"
  chmod 0700 "$DEST"
fi
[ -w "$DEST" ] || fail "dossier des sauvegardes $DEST non accessible en écriture"
# Restes d'une exécution interrompue (plus d'un jour).
find "$DEST" -maxdepth 1 -type d -name '.locksy-backup.*' -mmin +1440 -exec rm -rf {} + 2>/dev/null || true

BASE=${NAME:-locksy-$(date +%Y%m%d-%H%M%S)}
for f in "$DEST/$BASE.db" "$DEST/$BASE.db".*; do
  if [ -e "$f" ]; then fail "$f existe déjà : choisissez un autre nom (--name)"; fi
done

# Dossier privé (0700) sur le même système de fichiers : renommage atomique.
PRIV=$(mktemp -d "$DEST/.locksy-backup.XXXXXX") || fail "dossier temporaire impossible dans $DEST"
chmod 0700 "$PRIV"
IN_CONTAINER=""
cleanup() {
  if [ -n "$IN_CONTAINER" ]; then
    docker exec "$DOCKER" rm -f "$IN_CONTAINER" "$IN_CONTAINER.server.key" >/dev/null 2>&1 || true
  fi
  rm -rf "$PRIV"
}
trap cleanup EXIT
trap 'exit 1' INT TERM HUP

DB="$PRIV/$BASE.db"
KEYCOPY="$DB.server.key"
OUTLOG="$PRIV/sortie.log"
show_log() { [ -s "$OUTLOG" ] && sed 's/^/    /' "$OUTLOG" >&2; return 0; }

# ----------------------------------------------------------------- Copie à chaud
if [ -z "$DOCKER" ]; then
  BIN=${LOCKSY_SERVER_BIN:-/opt/locksy/locksy-server}
  [ -x "$BIN" ] || fail "binaire du serveur introuvable : $BIN (LOCKSY_SERVER_BIN)"
  export LOCKSY_DATA="${LOCKSY_DATA:-/var/lib/locksy}"
  if [ -n "${LOCKSY_SERVER_KEY_FILE:-}" ]; then export LOCKSY_SERVER_KEY_FILE; fi
  bk_args=(backup "$DB"); if [ "$WITH_KEY" = 1 ]; then bk_args+=(--with-key); fi
  if ! "$BIN" "${bk_args[@]}" >"$OUTLOG" 2>&1; then
    show_log; fail "la sauvegarde de $LOCKSY_DATA a échoué (locksy-server backup)"
  fi
  PROD_KEY=${LOCKSY_SERVER_KEY_FILE:-$LOCKSY_DATA/server.key}
else
  has docker || fail "docker est introuvable"
  [ "$(docker inspect -f '{{.State.Running}}' "$DOCKER" 2>/dev/null)" = true ] \
    || fail "le conteneur $DOCKER n'existe pas ou n'est pas démarré"
  docker exec "$DOCKER" mkdir -p /data/backups >/dev/null 2>&1 || fail "création de /data/backups impossible dans $DOCKER"
  IN_CONTAINER="/data/backups/$BASE.db"
  bk_args=(backup "$IN_CONTAINER"); if [ "$WITH_KEY" = 1 ]; then bk_args+=(--with-key); fi
  if ! docker exec "$DOCKER" /app/locksy-server "${bk_args[@]}" >"$OUTLOG" 2>&1; then
    show_log; fail "la sauvegarde dans le conteneur $DOCKER a échoué (locksy-server backup)"
  fi
  docker cp "$DOCKER:$IN_CONTAINER" "$DB" >/dev/null || fail "copie de la sauvegarde hors du conteneur impossible"
  if [ "$WITH_KEY" = 1 ]; then
    docker cp "$DOCKER:$IN_CONTAINER.server.key" "$KEYCOPY" >/dev/null || fail "copie de la clé serveur hors du conteneur impossible"
  fi
  docker exec "$DOCKER" rm -f "$IN_CONTAINER" "$IN_CONTAINER.server.key" >/dev/null 2>&1 || true
  IN_CONTAINER=""
  chmod 0600 "$DB"
  if [ -f "$KEYCOPY" ]; then chmod 0600 "$KEYCOPY"; fi
fi
[ -s "$DB" ] || fail "sauvegarde vide ou absente : $DB"
[ "$WITH_KEY" = 0 ] || [ -s "$KEYCOPY" ] || fail "clé serveur absente de la sauvegarde"

# ----------------------------------------------------------------- Test de restauration
RESTORE=non
if [ "$RESTORE_TEST" = 1 ]; then
  RT=$(mktemp -d "$PRIV/restauration.XXXXXX")
  cp "$DB" "$RT/locksy.db"
  if [ -z "$DOCKER" ]; then
    key=$PROD_KEY; [ "$WITH_KEY" = 1 ] && key=$KEYCOPY
    # Environnement minimal : seuls la base restaurée et la clé comptent.
    if ! env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LOCKSY_DATA="$RT" LOCKSY_SERVER_KEY_FILE="$key" \
        "$BIN" check >"$OUTLOG" 2>&1; then
      show_log; fail "test de restauration en échec (locksy-server check) : sauvegarde $BASE inutilisable"
    fi
  else
    image=$(docker inspect -f '{{.Image}}' "$DOCKER")
    run_args=(run --rm --network none --user 10001 -v "$RT:/restore"
      -e LOCKSY_DATA=/restore -e LOCKSY_TLS_CERT= -e LOCKSY_TLS_KEY= -e LOCKSY_SYSLOG= -e LOCKSY_SYSLOG_CA_FILE=)
    if [ "$WITH_KEY" = 1 ]; then
      cp "$KEYCOPY" "$RT/server.key"
      run_args+=(-e LOCKSY_SERVER_KEY_FILE=/restore/server.key)
    else
      # Clé de production lue sur place (volumes du conteneur en lecture seule) :
      # elle n'est jamais copiée sur l'hôte.
      ckey=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$DOCKER" \
        | sed -n 's/^LOCKSY_SERVER_KEY_FILE=//p' | tail -n 1)
      run_args+=(--volumes-from "$DOCKER:ro" -e "LOCKSY_SERVER_KEY_FILE=${ckey:-/data/server.key}")
    fi
    # Le conteneur de test tourne avec l'uid du service (10001).
    chown -R 10001 "$RT" 2>/dev/null || chmod -R a+rwX "$RT"
    if ! docker "${run_args[@]}" "$image" check >"$OUTLOG" 2>&1; then
      show_log; fail "test de restauration en échec (locksy-server check) : sauvegarde $BASE inutilisable"
    fi
  fi
  rm -rf "$RT"
  RESTORE=ok
fi

# ----------------------------------------------------------------- Chiffrement
# Chiffre un fichier ; le chemin produit est rendu dans ENC_OUT et le clair est
# supprimé après succès. Pas de sous-shell : un échec arrête bien le script.
ENC_OUT=""
encrypt() { # fichier
  local f=$1
  case "$ENC" in
    age) age -r "$AGE_R" -o "$f.age" "$f" || fail "chiffrement age de $(basename "$f") impossible"
         rm -f "$f"; ENC_OUT="$f.age" ;;
    gpg) gpg --batch --yes --trust-model always -r "$GPG_R" -o "$f.gpg" -e "$f" >/dev/null 2>&1 \
           || fail "chiffrement GnuPG de $(basename "$f") impossible (clé $GPG_R importée ? GNUPGHOME ?)"
         rm -f "$f"; ENC_OUT="$f.gpg" ;;
    *) ENC_OUT=$f ;;
  esac
}
encrypt "$DB"; OUT_DB=$ENC_OUT
OUT_KEY=""
if [ "$WITH_KEY" = 1 ]; then encrypt "$KEYCOPY"; OUT_KEY=$ENC_OUT; fi

# Clé d'abord, base ensuite : une base visible a toujours sa clé à côté.
if [ -n "$OUT_KEY" ]; then mv "$OUT_KEY" "$DEST/" || fail "écriture dans $DEST impossible"; fi
mv "$OUT_DB" "$DEST/" || fail "écriture dans $DEST impossible"
FINAL="$DEST/$(basename "$OUT_DB")"

# ----------------------------------------------------------------- Rotation
# Bases des sauvegardes d'un préfixe, de la plus récente à la plus ancienne.
list_bases() { # préfixe
  local f
  for f in "$DEST/$1"*.db*; do
    [ -f "$f" ] || continue
    case "$f" in *.server.key*) continue ;; esac
    printf '%s %s\n' "$(stat -c %Y "$f")" "$(basename "$f")"
  done | sort -k1,1nr -k2,2r | cut -d' ' -f2- | while IFS= read -r f; do printf '%s\n' "${f%.db*}"; done | awk '!seen[$0]++'
}
rotate() { # préfixe nombre_conservé
  local b n=0
  while IFS= read -r b; do
    n=$((n + 1))
    if [ "$n" -le "$2" ]; then continue; fi
    for s in .db .db.age .db.gpg .db.server.key .db.server.key.age .db.server.key.gpg; do
      rm -f -- "$DEST/$b$s"
    done
  done < <(list_bases "$1")
}
rotate locksy- "$KEEP" || printf '%s: attention : rotation incomplète dans %s\n' "$PROG" "$DEST" >&2
rotate pre-upgrade- "$PRE_UPGRADE_KEEP" || true
KEPT=$(list_bases locksy- | wc -l)

size=$(stat -c %s "$FINAL" 2>/dev/null || echo "?")
chiffrement=$ENC; [ "$ENC" = none ] && chiffrement="aucun (en clair)"
log "OK $FINAL ($size octets) ; chiffrement : $chiffrement ; clé serveur : $([ "$WITH_KEY" = 1 ] && echo incluse || echo non incluse) ; test de restauration : $RESTORE ; sauvegardes conservées : $KEPT"
