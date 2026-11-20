#!/usr/bin/env bash
# =============================================================================
#  Locksy : installation du serveur sur Linux
#
#  Deux modes :
#    native  service systemd, sans Docker (VM Debian, Ubuntu, RHEL, Rocky…)
#    docker  conteneur Docker durci (si Docker est présent)
#
#  Installation en une ligne (accès Internet) :
#    curl -fsSL https://github.com/__REPO__/releases/latest/download/install.sh | sudo bash
#
#  Installation hors ligne (réseau isolé) : copiez dans un même dossier
#  install.sh, l'archive locksy-server-linux-x86_64.tar.gz, SHA256SUMS et ses
#  signatures (SHA256SUMS.sigstore.json, SHA256SUMS.minisig), puis :
#    sudo bash install.sh --archive locksy-server-linux-x86_64.tar.gz
#
#  Options :
#    --mode native|docker      mode d'installation (défaut : demandé, ou native)
#    --domain NOM              nom DNS de Locksy, ex. locksy.corp.local
#    --cert FICHIER --key FICHIER
#                              certificat (chaîne PEM) et clé, ex. émis par AD CS.
#                              Sans eux : certificat autosigné temporaire.
#    --port N                  port HTTPS (défaut 443)
#    --listen ADDR             adresse d'écoute (défaut 0.0.0.0 ; :: pour IPv6) ;
#                              en Docker, adresse sur laquelle le port est publié
#    --archive FICHIER         archive de version locale (installation hors ligne)
#    --version vX.Y.Z          version à installer (défaut : la dernière) ; avec
#                              --archive, doit correspondre à son fichier VERSION
#    --sha256 HEX              empreinte SHA-256 attendue de l'archive
#                              (prime sur SHA256SUMS)
#    --skip-verify             installer une archive sans empreinte vérifiable
#                              (déconseillé)
#    --require-signature       refuser si la signature de SHA256SUMS n'est pas
#                              vérifiée (minisign ou cosign)
#    --backup-dir DIR          dossier des sauvegardes (défaut /var/backups/locksy)
#    --no-backup-timer         pas de sauvegarde quotidienne automatique
#    --yes                     aucune question (valeurs par défaut)
#    --rollback                revenir à la version précédente
#    --uninstall               désinstaller (données et sauvegardes conservées)
#    --purge                   avec --uninstall : supprimer aussi les données
#                              (confirmation : taper SUPPRIMER, ou --yes)
#    --no-start                installer sans démarrer (tests)
#
#  Signature : si minisign (avec la clé publique de l'éditeur, inscrite dans
#  ce script) ou cosign (identité du workflow GitHub de publication) est
#  présent, la signature de SHA256SUMS est vérifiée et un échec est fatal.
#
#  Réinstaller avec une archive plus récente met Locksy à jour : la base est
#  sauvegardée avant, la version précédente est conservée (--rollback) ; les
#  données sont conservées.
# =============================================================================
set -euo pipefail

REPO="__REPO__"
# Clé publique minisign de l'éditeur (ligne base64 de minisign.pub), inscrite
# par scripts/package-release.sh à la publication. Valeur laissée telle quelle
# (gabarit) : aucune clé, la vérification minisign est sautée. La vérification
# cosign, elle, utilise l'identité GitHub du dépôt (REPO ci-dessus).
LOCKSY_MINISIGN_PUBKEY="__MINISIGN_PUBKEY__"
PREFIX=/opt/locksy
DATA=/var/lib/locksy
CONF=/etc/locksy
UNIT=/etc/systemd/system/locksy.service
BK_UNIT=/etc/systemd/system/locksy-backup.service
BK_TIMER=/etc/systemd/system/locksy-backup.timer
IMAGE=locksy:local
PREV_IMAGE=locksy:previous
CONTAINER=locksy
VOLUME=locksy-data
DEFAULT_BACKUP_DIR=/var/backups/locksy
SAFE_PATH=/usr/sbin:/usr/bin:/sbin:/bin

MODE="" DOMAIN="" CERT="" KEY="" PORT="" LISTEN="" ARCHIVE="" VERSION="latest" SHA256="" BACKUP_DIR=""
YES=0 UNINSTALL=0 PURGE=0 NOSTART=0 SKIP_VERIFY=0 REQUIRE_SIG=0 NO_TIMER=0 ROLLBACK=0

c_ok=$'\e[32m' c_warn=$'\e[33m' c_err=$'\e[31m' c_bold=$'\e[1m' c_off=$'\e[0m'
[ -t 1 ] || { c_ok=""; c_warn=""; c_err=""; c_bold=""; c_off=""; }
info() { printf '%s==>%s %s\n' "$c_bold" "$c_off" "$*"; }
ok()   { printf '%s ✓%s %s\n' "$c_ok" "$c_off" "$*"; }
warn() { printf '%s ! %s%s\n' "$c_warn" "$*" "$c_off"; }
die()  { printf '%s ✗ %s%s\n' "$c_err" "$*" "$c_off" >&2; exit 1; }

# Terminal réellement utilisable (curl | sudo bash : stdin est le script).
has_tty() { [ -r /dev/tty ] && { : </dev/tty; } 2>/dev/null; }

ask() { # question valeur_par_défaut -> réponse
  local q=$1 def=$2 r=""
  if [ "$YES" = 1 ] || ! has_tty; then echo "$def"; return; fi
  read -r -p "$q [$def] : " r </dev/tty || true
  echo "${r:-$def}"
}

# Confirmation explicite : « oui » au terminal, ou --yes (écrit dans la sortie).
# Sans terminal ni --yes : refus.
confirm() { # question
  local r=""
  if [ "$YES" = 1 ]; then info "$1 : oui (--yes)"; return 0; fi
  has_tty || return 1
  read -r -p "$1 [oui/non] : " r </dev/tty || r=""
  case "${r,,}" in o|oui|y|yes) return 0 ;; *) return 1 ;; esac
}

usage() {
  if [ -r "$0" ] && [ -f "$0" ]; then sed -n '2,/^# =\{20,\}/p' "$0" | sed 's/^# \{0,1\}//'
  else echo "Aide complète : téléchargez install.sh puis lancez : bash install.sh --help"; fi
}

need_val() { [ $# -ge 2 ] && [ -n "$2" ] || die "L'option $1 attend une valeur (voir --help)."; }
LISTEN_SET=0 BACKUP_DIR_SET=0
while [ $# -gt 0 ]; do
  case "$1" in
    --mode) need_val "$@"; MODE=$2; shift 2 ;;
    --domain) need_val "$@"; DOMAIN=$2; shift 2 ;;
    --cert) need_val "$@"; CERT=$2; shift 2 ;;
    --key) need_val "$@"; KEY=$2; shift 2 ;;
    --port) need_val "$@"; PORT=$2; shift 2 ;;
    --listen) need_val "$@"; LISTEN=$2; LISTEN_SET=1; shift 2 ;;
    --archive) need_val "$@"; ARCHIVE=$2; shift 2 ;;
    --version) need_val "$@"; VERSION=$2; shift 2 ;;
    --sha256) need_val "$@"; SHA256=$2; shift 2 ;;
    --skip-verify) SKIP_VERIFY=1; shift ;;
    --require-signature) REQUIRE_SIG=1; shift ;;
    --backup-dir) need_val "$@"; BACKUP_DIR=$2; BACKUP_DIR_SET=1; shift 2 ;;
    --no-backup-timer) NO_TIMER=1; shift ;;
    --rollback) ROLLBACK=1; shift ;;
    --yes|-y) YES=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) PURGE=1; shift ;;
    --no-start) NOSTART=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Option inconnue : $1 (voir --help)" ;;
  esac
done

# ----------------------------------------------------------------- Contrôle des options
[[ "$VERSION" = latest || "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] \
  || die "Version invalide : $VERSION (attendu : vX.Y.Z, vX.Y.Z-suffixe ou latest)."
if [ -n "$SHA256" ]; then
  SHA256=${SHA256,,}
  [[ "$SHA256" =~ ^[0-9a-f]{64}$ ]] || die "--sha256 attend 64 caractères hexadécimaux."
fi
LISTEN=${LISTEN#[}; LISTEN=${LISTEN%]}
LISTEN=${LISTEN:-0.0.0.0}
[[ "$LISTEN" =~ ^[0-9A-Fa-f:.]+$ ]] || die "--listen attend une adresse IP (ex. 0.0.0.0, 10.0.0.5, ::) : $LISTEN"
[ "$PURGE" = 0 ] || [ "$UNINSTALL" = 1 ] || die "--purge s'utilise avec --uninstall."
[ "$ROLLBACK" = 0 ] || [ "$UNINSTALL" = 0 ] || die "--rollback et --uninstall s'excluent."

[ "$(id -u)" = 0 ] || die "Lancez ce script en root (sudo)."
[ "$(uname -s)" = Linux ] || die "Ce script s'exécute sur Linux."
case "$(uname -m)" in x86_64|amd64) ;; *) die "Seule l'architecture x86_64 est fournie." ;; esac
has() { command -v "$1" >/dev/null 2>&1; }

# Valeur de CLE dans un fichier CLE=valeur, sans l'exécuter (jamais de source).
env_get() { # fichier clé défaut
  local v=""
  if [ -r "$1" ]; then v=$(sed -n "s/^[[:space:]]*$2=//p" "$1" | tail -n 1); fi
  printf '%s\n' "${v:-$3}"
}
# Exécute une commande sous le compte du service.
as_locksy() {
  if has runuser; then runuser -u locksy -- "$@"
  else setpriv --reuid=locksy --regid=locksy --init-groups -- "$@"; fi
}
# Binaire assez récent pour check, backup et version (une ancienne version
# ignorerait la sous-commande et démarrerait le serveur).
supports_ops() { grep -aq "check ne prend pas d'argument" "$1" 2>/dev/null; }
safe_name() { printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_'; }
bracket() { case "$1" in *:*) printf '[%s]\n' "$1" ;; *) printf '%s\n' "$1" ;; esac; }
probe_host() { case "$1" in 0.0.0.0|"") echo 127.0.0.1 ;; ::) echo ::1 ;; *) echo "$1" ;; esac; }

BACKUP_DIR=${BACKUP_DIR:-$(env_get "$CONF/backup.env" LOCKSY_BACKUP_DIR "$DEFAULT_BACKUP_DIR")}
BACKUP_DIR=${BACKUP_DIR%/}
case "$BACKUP_DIR" in
  /*) ;; *) die "--backup-dir attend un chemin absolu : $BACKUP_DIR" ;;
esac
case "$BACKUP_DIR" in
  ""|/|/var|/var/backups|/var/lib|/tmp|/var/tmp|/home|/root|/etc|/opt|/usr|/srv|/mnt|/media|"$DATA"|"$DATA"/*|"$PREFIX"|"$PREFIX"/*|"$CONF"|"$CONF"/*)
    die "--backup-dir doit être un dossier dédié aux sauvegardes (refusé : ${BACKUP_DIR:-/})." ;;
esac
[[ "$BACKUP_DIR" =~ ^[A-Za-z0-9/._-]+$ ]] || die "--backup-dir : lettres, chiffres, / . _ - uniquement : $BACKUP_DIR"

# ----------------------------------------------------------------- Désinstallation
if [ "$UNINSTALL" = 1 ]; then
  if [ "$PURGE" = 1 ] && [ "$YES" = 0 ]; then
    has_tty || die "--purge sans terminal : ajoutez --yes pour confirmer la suppression définitive des données."
    warn "--purge supprime DÉFINITIVEMENT la base, la clé serveur ($DATA ou le volume Docker $VOLUME) et la configuration $CONF."
    warn "Les sauvegardes de $BACKUP_DIR sont conservées."
    r=""; read -r -p "Tapez SUPPRIMER pour confirmer : " r </dev/tty || r=""
    [ "$r" = SUPPRIMER ] || die "Suppression annulée : rien n'a été modifié."
  fi
  info "Désinstallation de Locksy"
  if has systemctl; then
    for u in locksy-backup.timer locksy-backup.service locksy.service; do
      if [ -f "/etc/systemd/system/$u" ]; then systemctl disable --now "$u" 2>/dev/null || true; fi
    done
  fi
  rm -f "$UNIT" "$BK_UNIT" "$BK_TIMER"
  if has systemctl; then systemctl daemon-reload 2>/dev/null || true; fi
  if has docker && docker inspect "$CONTAINER" >/dev/null 2>&1; then docker rm -f "$CONTAINER" >/dev/null; fi
  CUSTOM_DATA=$(env_get "$CONF/locksy.env" LOCKSY_DATA "$DATA")
  rm -rf "$PREFIX"
  if [ "$PURGE" = 1 ]; then
    rm -rf "$DATA" "$CONF"
    [ "$CUSTOM_DATA" = "$DATA" ] || warn "Dossier de données personnalisé NON supprimé : $CUSTOM_DATA (à supprimer vous-même)."
    if has docker; then
      docker volume rm "$VOLUME" >/dev/null 2>&1 || true
      docker image rm "$IMAGE" "$PREV_IMAGE" >/dev/null 2>&1 || true
    fi
    if id locksy >/dev/null 2>&1; then userdel locksy || true; fi
    ok "Locksy et toutes ses données ont été supprimés."
  else
    ok "Locksy est désinstallé. Données conservées dans $CUSTOM_DATA (ou le volume Docker $VOLUME), configuration dans $CONF."
  fi
  [ -d "$BACKUP_DIR" ] && ok "Sauvegardes conservées dans $BACKUP_DIR (à supprimer vous-même si besoin)."
  exit 0
fi

# ----------------------------------------------------------------- Fonctions communes
# Vérification de santé : $HC_HOST et $HC_PORT.
HC_HOST=127.0.0.1 HC_PORT=443
health_url() { printf 'https://%s:%s/api/health\n' "$(bracket "$HC_HOST")" "$HC_PORT"; }
wait_healthy() { # version
  local up=0
  info "Vérification"
  for _ in $(seq 1 30); do
    if has curl && curl -gfsk "$(health_url)" >/dev/null 2>&1; then up=1; break; fi
    if ! has curl && (exec 3<>"/dev/tcp/$HC_HOST/$HC_PORT") 2>/dev/null; then up=1; break; fi
    sleep 1
  done
  if [ "$up" = 1 ]; then ok "Locksy $1 répond sur le port $HC_PORT"
  else
    warn "Locksy ne répond pas encore. Journal :"
    if [ "$MODE" = native ]; then journalctl -u locksy -n 20 --no-pager || true; else docker logs --tail 20 "$CONTAINER" || true; fi
    exit 1
  fi
}

# Adresse et port d'écoute du mode natif, lus dans locksy.env.
native_probe() {
  local bind host
  bind=$(env_get "$CONF/locksy.env" LOCKSY_BIND "0.0.0.0:${PORT:-443}")
  host=${bind%:*}; host=${host#[}; host=${host%]}
  HC_HOST=$(probe_host "$host"); HC_PORT=${bind##*:}
}

publish_warning() {
  case "$LISTEN" in
    0.0.0.0|::) warn "Docker publie le port $PORT sur TOUTES les interfaces ($LISTEN) et contourne ufw et firewalld : restreignez avec --listen ADDR si besoin." ;;
    *) info "Port $PORT publié sur $LISTEN uniquement (Docker contourne ufw et firewalld)." ;;
  esac
}

# Conteneur Locksy (installation, mise à jour et retour arrière).
run_container() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  publish_warning
  # --stop-timeout : délai de grâce, point de contrôle de la base et vidage syslog.
  docker run -d --name "$CONTAINER" --restart unless-stopped --stop-timeout 25 \
    --env-file "$CONF/docker.env" \
    -p "$(bracket "$LISTEN"):$PORT:8443" -v "$VOLUME:/data" -v "$CONF/tls:/tls:ro" \
    --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true \
    --memory 512m --pids-limit 128 "$IMAGE" >/dev/null
}

# Version de l'image d'un conteneur ou d'une étiquette (étiquette OCI).
image_version() { # conteneur|image
  local ref=$1 img v=""
  img=$(docker container inspect -f '{{.Image}}' "$ref" 2>/dev/null || echo "$ref")
  v=$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.version"}}' "$img" 2>/dev/null || true)
  [ "$v" = "<no value>" ] && v=""
  echo "${v:-inconnue}"
}

# Écrit $CONF/last-upgrade (CLE=valeur).
write_last_upgrade() { # de vers mode sauvegarde
  local tmp="$CONF/last-upgrade.tmp"
  ( umask 077; printf 'FROM_VERSION=%s\nTO_VERSION=%s\nMODE=%s\nBACKUP=%s\nDATE=%s\n' \
      "$1" "$2" "$3" "$4" "$(date -Iseconds)" > "$tmp" )
  mv -f "$tmp" "$CONF/last-upgrade"
}

# ----------------------------------------------------------------- Retour arrière
if [ "$ROLLBACK" = 1 ]; then
  LAST="$CONF/last-upgrade"
  [ -n "$MODE" ] || MODE=$(env_get "$LAST" MODE "")
  if [ -z "$MODE" ]; then
    if [ -x "$PREFIX/locksy-server.prev" ]; then MODE=native
    elif has docker && docker image inspect "$PREV_IMAGE" >/dev/null 2>&1; then MODE=docker
    else die "Aucune version précédente à restaurer (ni $PREFIX/locksy-server.prev ni image $PREV_IMAGE)."; fi
  fi
  case "$MODE" in native|docker) ;; *) die "Mode inconnu : $MODE (native ou docker)." ;; esac
  R_FROM=$(env_get "$LAST" FROM_VERSION inconnue)
  R_TO=$(env_get "$LAST" TO_VERSION inconnue)
  R_BACKUP=$(env_get "$LAST" BACKUP "")
  R_DATE=$(env_get "$LAST" DATE "?")
  [ -f "$LAST" ] || warn "Pas de $LAST : version et sauvegarde d'avant mise à jour inconnues."
  info "Retour arrière de Locksy $R_TO vers $R_FROM (mode $MODE)"
  STAMP=$(date +%Y%m%d-%H%M%S)
  NEWER=0 UNVERIFIED=0 CHECK_OUT=""

  if [ "$MODE" = native ]; then
    [ -x "$PREFIX/locksy-server.prev" ] || die "Aucune version précédente : $PREFIX/locksy-server.prev est absent."
    D=$(env_get "$CONF/locksy.env" LOCKSY_DATA "$DATA")
    KF=$(env_get "$CONF/locksy.env" LOCKSY_SERVER_KEY_FILE "")
    kv=(); [ -z "$KF" ] || kv=("LOCKSY_SERVER_KEY_FILE=$KF")
    if has systemctl && [ -f "$UNIT" ]; then systemctl stop locksy || true; fi
    install -m 0755 "$PREFIX/locksy-server.prev" "$PREFIX/locksy-server.new"
    mv -f "$PREFIX/locksy-server.new" "$PREFIX/locksy-server"
    if [ -d "$PREFIX/web.prev" ]; then
      rm -rf "$PREFIX/web.new"; cp -a "$PREFIX/web.prev" "$PREFIX/web.new"
      rm -rf "$PREFIX/web"; mv "$PREFIX/web.new" "$PREFIX/web"
    else
      warn "Pas d'interface web précédente ($PREFIX/web.prev) : interface actuelle conservée."
    fi
    if [ -f "$PREFIX/VERSION.prev" ]; then cp -f "$PREFIX/VERSION.prev" "$PREFIX/VERSION"; else rm -f "$PREFIX/VERSION"; fi
    ok "Binaire et interface web précédents remis en place"
    if supports_ops "$PREFIX/locksy-server"; then
      rc=0
      CHECK_OUT=$(as_locksy env -i PATH="$SAFE_PATH" LOCKSY_DATA="$D" "${kv[@]}" "$PREFIX/locksy-server" check 2>&1) || rc=$?
      if [ "$rc" = 1 ] && grep -q "plus récent" <<<"$CHECK_OUT"; then NEWER=1
      elif [ "$rc" != 0 ]; then warn "Vérification de la base par l'ancienne version (code $rc) :"; printf '%s\n' "$CHECK_OUT" | sed 's/^/    /'
      fi
    else
      UNVERIFIED=1
    fi
  else
    has docker || die "Docker n'est pas installé."
    docker image inspect "$PREV_IMAGE" >/dev/null 2>&1 || die "Aucune version précédente : image $PREV_IMAGE absente."
    # Adresse et port publiés par le conteneur actuel (sauf --listen/--port).
    if docker inspect "$CONTAINER" >/dev/null 2>&1; then
      read -r cur_ip cur_port <<<"$(docker inspect -f '{{range $p, $b := .HostConfig.PortBindings}}{{range $b}}{{.HostIp}} {{.HostPort}}{{end}}{{end}}' "$CONTAINER" 2>/dev/null || true)" || true
      if [ -z "${cur_port:-}" ] && [ -n "${cur_ip:-}" ]; then cur_port=$cur_ip; cur_ip=""; fi
      [ "$LISTEN_SET" = 1 ] || LISTEN=${cur_ip:-0.0.0.0}
      [ -n "$PORT" ] || PORT=${cur_port:-443}
    fi
    PORT=${PORT:-443}
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    docker tag "$PREV_IMAGE" "$IMAGE"
    ok "Image précédente remise en place ($PREV_IMAGE -> $IMAGE)"
    if docker run --rm --network none --entrypoint /bin/grep "$IMAGE" -aq "check ne prend pas d'argument" /app/locksy-server 2>/dev/null; then
      rc=0
      CHECK_OUT=$(docker run --rm --network none --user 10001 -v "$VOLUME:/data" \
        -e LOCKSY_TLS_CERT= -e LOCKSY_TLS_KEY= -e LOCKSY_SYSLOG= -e LOCKSY_SYSLOG_CA_FILE= "$IMAGE" check 2>&1) || rc=$?
      if [ "$rc" = 1 ] && grep -q "plus récent" <<<"$CHECK_OUT"; then NEWER=1
      elif [ "$rc" != 0 ]; then warn "Vérification de la base par l'ancienne version (code $rc) :"; printf '%s\n' "$CHECK_OUT" | sed 's/^/    /'
      fi
    else
      UNVERIFIED=1
    fi
  fi

  RESTORE=0
  if [ "$NEWER" = 1 ]; then
    warn "La base a été migrée par $R_TO : $R_FROM ne peut pas l'ouvrir (schéma plus récent)."
    [ -n "$R_BACKUP" ] && [ -f "$R_BACKUP" ] \
      || die "Aucune sauvegarde d'avant mise à jour disponible (${R_BACKUP:-non renseignée}). Réinstallez $R_TO, ou restaurez une sauvegarde compatible à la main (docs/Sauvegarde-et-mises-a-jour.md). Le service reste arrêté."
    warn "Restaurer $R_BACKUP fait PERDRE les modifications faites depuis la mise à jour ($R_DATE)."
    confirm "Restaurer la base d'avant mise à jour ($R_BACKUP)" \
      || die "Retour arrière interrompu : base non restaurée, le service reste arrêté. Relancez avec --rollback, ou réinstallez $R_TO."
    RESTORE=1
  elif [ "$UNVERIFIED" = 1 ]; then
    warn "L'ancienne version ne sait pas vérifier la base (pas de sous-commande check)."
    if [ -n "$R_BACKUP" ] && [ -f "$R_BACKUP" ]; then
      warn "Si elle refuse de démarrer, restaurez la base d'avant mise à jour : $R_BACKUP"
      if [ "$YES" = 0 ] && has_tty && confirm "Restaurer dès maintenant cette sauvegarde (modifications depuis $R_DATE perdues)"; then RESTORE=1; fi
    fi
  fi

  if [ "$RESTORE" = 1 ]; then
    if [ "$MODE" = native ]; then
      db="$D/locksy.db"
      warn "RESTAURATION DE LA BASE : $R_BACKUP remplace $db (base actuelle conservée sous $db.avant-retour-$STAMP)."
      for s in "" -wal -shm; do
        if [ -e "$db$s" ]; then mv -f "$db$s" "$db.avant-retour-$STAMP$s"; fi
      done
      install -o locksy -g locksy -m 0600 "$R_BACKUP" "$db"
    else
      warn "RESTAURATION DE LA BASE : $R_BACKUP remplace locksy.db du volume $VOLUME (base actuelle conservée sous locksy.db.avant-retour-$STAMP)."
      # shellcheck disable=SC2016 # développé par le shell du conteneur
      docker run --rm --network none --user 10001 -v "$VOLUME:/data" -v "$(dirname "$R_BACKUP"):/backup:ro" \
        --entrypoint /bin/sh "$IMAGE" -c 'set -e
          for s in "" -wal -shm; do
            if [ -e "/data/locksy.db$s" ]; then mv -f "/data/locksy.db$s" "/data/locksy.db.avant-retour-$2$s"; fi
          done
          cp "/backup/$1" /data/locksy.db; chmod 600 /data/locksy.db' sh "$(basename "$R_BACKUP")" "$STAMP" \
        || die "Restauration impossible dans le volume $VOLUME."
    fi
    ok "Base d'avant mise à jour restaurée (fichiers -wal et -shm écartés)"
  fi

  if [ "$NOSTART" = 1 ]; then
    ok "Retour à $R_FROM effectué (service non démarré : --no-start)."
    exit 0
  fi
  if [ "$MODE" = native ]; then
    if has systemctl; then systemctl daemon-reload; systemctl start locksy; fi
    native_probe
  else
    run_container
    HC_HOST=$(probe_host "$LISTEN") HC_PORT=$PORT
  fi
  wait_healthy "$R_FROM"
  ok "Retour arrière terminé : Locksy $R_FROM est en service."
  exit 0
fi

# ----------------------------------------------------------------- Choix
if [ -z "$MODE" ]; then
  def=native; has docker && def=docker
  MODE=$(ask "Mode d'installation (native = service systemd, docker = conteneur)" "$def")
fi
case "$MODE" in native|docker) ;; *) die "Mode inconnu : $MODE (native ou docker)." ;; esac
[ "$MODE" = docker ] && ! has docker && die "Docker n'est pas installé. Installez-le (paquet docker.io ou docker-ce) ou utilisez --mode native."
[ "$MODE" = native ] && ! has systemctl && [ "$NOSTART" = 0 ] && die "systemd est requis pour le mode native."

[ -n "$DOMAIN" ] || DOMAIN=$(ask "Nom DNS de Locksy (celui que taperont les utilisateurs)" "$(hostname -f 2>/dev/null || hostname)")
[ -n "$PORT" ] || PORT=$(ask "Port HTTPS" "443")
[[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "Port invalide : $PORT"
if [ -z "$CERT" ] && [ "$YES" = 0 ] && has_tty; then
  CERT=$(ask "Certificat (chaîne PEM) émis par votre autorité, vide = autosigné temporaire" "")
  [ -n "$CERT" ] && KEY=$(ask "Clé privée du certificat" "")
fi
if [ -n "$CERT" ] || [ -n "$KEY" ]; then
  [ -r "$CERT" ] || die "Certificat illisible : $CERT"
  [ -r "$KEY" ] || die "Clé illisible : $KEY"
fi

# ----------------------------------------------------------------- Vérification de l'archive
# Empreinte d'un fichier dans SHA256SUMS (format sha256sum, texte ou binaire).
sum_for() { awk -v n="$2" '($2 == n || $2 == "*" n) { print tolower($1); exit }' "$1"; }

# Signature de SHA256SUMS puis empreinte de l'archive. Une signature présente
# mais fausse est toujours fatale ; une signature invérifiable n'est qu'un
# avertissement, sauf avec --require-signature.
verify_release() { # dossier archive nom_d'origine
  local archive=$2 name=$3 sums="$1/SHA256SUMS" signed="" expected="" actual repo_re
  if [ -f "$sums" ]; then
    if has minisign && [ -n "$LOCKSY_MINISIGN_PUBKEY" ] && [ "$LOCKSY_MINISIGN_PUBKEY" != "__""MINISIGN_PUBKEY__" ] \
        && [ -f "$sums.minisig" ]; then
      minisign -Vm "$sums" -x "$sums.minisig" -P "$LOCKSY_MINISIGN_PUBKEY" >/dev/null 2>&1 \
        || die "Signature minisign de SHA256SUMS INVALIDE : fichiers altérés ou signés par une autre clé. Installation refusée."
      signed=minisign
    elif has cosign && [ -f "$sums.sigstore.json" ] && [ "$REPO" != "__""REPO__" ]; then
      repo_re=$(printf '%s' "$REPO" | sed 's/[.]/\\./g')
      cosign verify-blob --bundle "$sums.sigstore.json" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        --certificate-identity-regexp "^https://github\\.com/$repo_re/\\.github/workflows/release\\.yml@refs/tags/v" \
        "$sums" >/dev/null 2>&1 \
        || die "Signature cosign de SHA256SUMS INVALIDE ou invérifiable (attendue : workflow release.yml de $REPO). Hors ligne, cosign a besoin de la racine de confiance Sigstore : préférer minisign, ou ne pas copier SHA256SUMS.sigstore.json à côté de l'archive. Installation refusée."
      signed=cosign
    fi
  fi
  if [ -n "$signed" ]; then ok "SHA256SUMS signé par l'éditeur (vérifié avec $signed)"
  elif [ "$REQUIRE_SIG" = 1 ]; then
    die "Signature de SHA256SUMS non vérifiée (--require-signature) : il faut SHA256SUMS, sa signature (SHA256SUMS.minisig ou SHA256SUMS.sigstore.json) à côté, et l'outil minisign ou cosign."
  else
    warn "Signature non vérifiée (outil minisign ou cosign, clé ou fichier de signature absent) : seule l'empreinte SHA-256 est contrôlée."
  fi

  if [ -n "$SHA256" ]; then expected=$SHA256
  elif [ -f "$sums" ]; then
    expected=$(sum_for "$sums" locksy-server-linux-x86_64.tar.gz)
    [ -n "$expected" ] || expected=$(sum_for "$sums" "$name")
  fi
  if [ -z "$expected" ]; then
    [ "$SKIP_VERIFY" = 1 ] || die "Aucune empreinte pour vérifier l'archive : placez SHA256SUMS à côté de l'archive, ou donnez --sha256 <empreinte>. (--skip-verify installe sans vérification : déconseillé.)"
    warn "Archive NON VÉRIFIÉE (--skip-verify) : son origine et son intégrité ne sont pas contrôlées."
    return 0
  fi
  actual=$(sha256sum "$archive" | cut -d' ' -f1)
  [ "$expected" = "$actual" ] || die "Empreinte SHA-256 incorrecte : archive altérée ou incomplète (attendu $expected, obtenu $actual)."
  ok "Archive vérifiée (SHA-256)"
}

fetch() { # url fichier
  if has curl; then curl -fsSL "$1" -o "$2"
  elif has wget; then wget -qO "$2" "$1"
  else die "curl ou wget est nécessaire (ou utilisez --archive)."; fi
}
fetch_optional() { # url fichier : absence (404) tolérée
  fetch "$1" "$2" 2>/dev/null || true
  [ -s "$2" ] || rm -f "$2"
}

# ----------------------------------------------------------------- Archive
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
if [ -n "$ARCHIVE" ]; then
  [ -r "$ARCHIVE" ] || die "Archive introuvable : $ARCHIVE"
  cp "$ARCHIVE" "$WORK/locksy.tar.gz"
  verify_release "$(cd "$(dirname "$ARCHIVE")" && pwd)" "$WORK/locksy.tar.gz" "$(basename "$ARCHIVE")"
else
  [ "$REPO" != "__""REPO__" ] || die "Indiquez l'archive à installer avec --archive."
  if [ "$VERSION" = latest ]; then base="https://github.com/$REPO/releases/latest/download"
  else base="https://github.com/$REPO/releases/download/$VERSION"; fi
  info "Téléchargement de Locksy ($VERSION)"
  fetch "$base/locksy-server-linux-x86_64.tar.gz" "$WORK/locksy.tar.gz"
  fetch_optional "$base/SHA256SUMS" "$WORK/SHA256SUMS"
  fetch_optional "$base/SHA256SUMS.sigstore.json" "$WORK/SHA256SUMS.sigstore.json"
  fetch_optional "$base/SHA256SUMS.minisig" "$WORK/SHA256SUMS.minisig"
  verify_release "$WORK" "$WORK/locksy.tar.gz" locksy-server-linux-x86_64.tar.gz
fi
tar --no-same-owner -xzf "$WORK/locksy.tar.gz" -C "$WORK"
SRC="$WORK/locksy-server"
[ -x "$SRC/bin/locksy-server" ] && [ -f "$SRC/web/locksy.wasm" ] || die "Archive inattendue (bin/locksy-server ou web/locksy.wasm absent)."
NEWVER=$(head -n 1 "$SRC/VERSION" 2>/dev/null | tr -d '[:space:]' || true)
NEWVER=${NEWVER:-inconnue}
if [ "$VERSION" != latest ] && [ "$NEWVER" != "$VERSION" ]; then
  die "L'archive contient la version $NEWVER, différente de --version $VERSION : installation refusée."
fi

mkdir -p "$PREFIX" "$CONF/tls"
chmod 0755 "$PREFIX"
HAVE_BK_SCRIPT=0
if [ -f "$SRC/scripts/backup-locksy.sh" ]; then
  install -m 0755 "$SRC/scripts/backup-locksy.sh" "$PREFIX/backup-locksy.sh.new"
fi

# ----------------------------------------------------------------- Certificat
if [ -n "$CERT" ]; then
  install -m 0644 "$CERT" "$CONF/tls/locksy.crt"
  install -m 0600 "$KEY" "$CONF/tls/locksy.key"
  ok "Certificat installé"
elif [ ! -f "$CONF/tls/locksy.crt" ]; then
  has openssl || die "openssl est nécessaire pour créer un certificat temporaire (ou fournissez --cert et --key)."
  openssl req -x509 -newkey rsa:3072 -nodes -days 365 -subj "/CN=$DOMAIN" \
    -addext "subjectAltName=DNS:$DOMAIN" -keyout "$CONF/tls/locksy.key" -out "$CONF/tls/locksy.crt" 2>/dev/null
  chmod 600 "$CONF/tls/locksy.key"
  warn "Certificat AUTOSIGNÉ créé pour $DOMAIN : les navigateurs afficheront une alerte."
  warn "Remplacez-le par un certificat de votre autorité (voir docs/Deploiement-Active-Directory.md), puis relancez ce script avec --cert et --key."
fi

UPGRADE=0 FROM="" PREV_SAVED=0 BACKUP_FILE=""
STAMP=$(date +%Y%m%d-%H%M%S)

# Fichier de réglages de la sauvegarde quotidienne (écrit une seule fois).
write_backup_env() { # groupe
  if [ -f "$CONF/backup.env" ]; then
    if [ "$BACKUP_DIR_SET" = 1 ] && [ "$(env_get "$CONF/backup.env" LOCKSY_BACKUP_DIR "")" != "$BACKUP_DIR" ]; then
      sed -i "s#^[[:space:]]*LOCKSY_BACKUP_DIR=.*#LOCKSY_BACKUP_DIR=$BACKUP_DIR#" "$CONF/backup.env"
      ok "Dossier des sauvegardes mis à jour dans $CONF/backup.env : $BACKUP_DIR"
    fi
    return 0
  fi
  cat > "$CONF/backup.env" <<ENV
# Sauvegarde quotidienne de Locksy (locksy-backup.timer, $PREFIX/backup-locksy.sh).
# Une ligne VARIABLE=valeur, sans guillemets ; prise en compte au prochain passage.
# Sauvegarde immédiate : systemctl start locksy-backup ; résultat : journalctl -u locksy-backup
#
# Dossier des sauvegardes. Pour le changer, relancez install.sh --backup-dir DIR
# (le service de sauvegarde n'a le droit d'écrire que là).
LOCKSY_BACKUP_DIR=$BACKUP_DIR
# Nombre de sauvegardes quotidiennes conservées (pre-upgrade-* : 5 dernières).
LOCKSY_BACKUP_KEEP=14
# Chiffrement, recommandé (sauvegardes copiées sur un autre support) :
# age, destinataire public (age1...) ; la clé privée reste HORS de ce serveur.
LOCKSY_BACKUP_AGE_RECIPIENT=
# ... ou GnuPG : empreinte d'une clé publique importée dans le trousseau du
# compte qui sauvegarde (mode natif : $DATA/.gnupg, ou GNUPGHOME ci-dessous).
LOCKSY_BACKUP_GPG_RECIPIENT=
# GNUPGHOME=$DATA/.gnupg
# 1 : copier aussi la clé serveur (exige le chiffrement). Sinon, sauvegardez
# une fois la clé serveur ($DATA/server.key) à part, sur un autre support.
LOCKSY_BACKUP_WITH_KEY=0
ENV
  chown "root:$1" "$CONF/backup.env"; chmod 0640 "$CONF/backup.env"
}

# Durcissement systemd commun au service et à sa sauvegarde.
HARDEN="NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
DevicePolicy=closed
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
ProcSubset=pid
RestrictSUIDSGID=true
RestrictNamespaces=true
RestrictRealtime=true
RemoveIPC=true
LockPersonality=true
# Pas de JIT ni de code généré à l'exécution : compatible.
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
SystemCallErrorNumber=EPERM
UMask=0077"
# PrivateUsers=true est volontairement absent : il annulerait
# CAP_NET_BIND_SERVICE (port 443).

# Timer de sauvegarde quotidienne (ou retrait avec --no-backup-timer).
install_backup_timer() { # contenu_du_service
  if [ "$NO_TIMER" = 1 ] || [ "$HAVE_BK_SCRIPT" = 0 ]; then
    if [ -f "$BK_TIMER" ] && has systemctl; then systemctl disable --now locksy-backup.timer 2>/dev/null || true; fi
    rm -f "$BK_TIMER" "$BK_UNIT"
    if [ "$HAVE_BK_SCRIPT" = 0 ]; then warn "Archive sans scripts/backup-locksy.sh : pas de sauvegarde quotidienne automatique."; fi
    return 0
  fi
  printf '%s\n' "$1" > "$BK_UNIT"
  cat > "$BK_TIMER" <<TIMER
[Unit]
Description=Locksy, sauvegarde quotidienne de la base

[Timer]
OnCalendar=*-*-* 02:30:00
RandomizedDelaySec=30m
Persistent=true

[Install]
WantedBy=timers.target
TIMER
}

start_backup_timer() {
  [ -f "$BK_TIMER" ] || return 0
  if [ "$NOSTART" = 0 ] && has systemctl; then
    systemctl daemon-reload
    systemctl enable --now locksy-backup.timer >/dev/null 2>&1 || warn "Activation de locksy-backup.timer impossible (systemctl status locksy-backup.timer)."
  fi
}

verify_unit() { # fichier
  if has systemd-analyze; then
    systemd-analyze verify "$1" 2>&1 | sed 's/^/    /' || true
  fi
}

# ----------------------------------------------------------------- Mode native
if [ "$MODE" = native ]; then
  id locksy >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin locksy
  mkdir -p "$DATA"; chown locksy:locksy "$DATA"; chmod 700 "$DATA"
  chown root:locksy "$CONF/tls/locksy.key"; chmod 640 "$CONF/tls/locksy.key"
  D=$(env_get "$CONF/locksy.env" LOCKSY_DATA "$DATA")
  KF=$(env_get "$CONF/locksy.env" LOCKSY_SERVER_KEY_FILE "")
  kv=(); [ -z "$KF" ] || kv=("LOCKSY_SERVER_KEY_FILE=$KF")
  mkdir -p "$BACKUP_DIR"; chown locksy:locksy "$BACKUP_DIR"; chmod 0700 "$BACKUP_DIR"

  # Nouveau binaire posé à côté : il sert aussi à la sauvegarde d'avant mise à
  # jour (une ancienne version n'a pas la sous-commande backup).
  install -m 0755 "$SRC/bin/locksy-server" "$PREFIX/locksy-server.new"
  if [ -x "$PREFIX/locksy-server" ]; then
    UPGRADE=1
    if [ -f "$PREFIX/VERSION" ]; then FROM=$(head -n 1 "$PREFIX/VERSION" | tr -d '[:space:]'); fi
    if [ -z "$FROM" ] && supports_ops "$PREFIX/locksy-server"; then
      FROM=$("$PREFIX/locksy-server" version 2>/dev/null | awk '{ print "v" $2; exit }' || true)
    fi
    FROM=${FROM:-inconnue}
    if [ -f "$D/locksy.db" ]; then
      BACKUP_FILE="$BACKUP_DIR/pre-upgrade-$(safe_name "$FROM")-$STAMP.db"
      info "Sauvegarde de la base avant mise à jour : $BACKUP_FILE"
      as_locksy env -i PATH="$SAFE_PATH" LOCKSY_DATA="$D" "${kv[@]}" "$PREFIX/locksy-server.new" backup "$BACKUP_FILE" >/dev/null \
        || { rm -f "$PREFIX/locksy-server.new"; die "Sauvegarde avant mise à jour impossible : mise à jour annulée, Locksy $FROM reste en place."; }
      ok "Base sauvegardée"
    elif [ -f "$D/verrou.db" ]; then
      # Base d'une installation antérieure (reprise au démarrage) : copie à froid.
      BACKUP_FILE="$BACKUP_DIR/pre-upgrade-$(safe_name "$FROM")-$STAMP.db"
      info "Sauvegarde à froid de l'ancienne base $D/verrou.db : $BACKUP_FILE"
      if has systemctl && [ -f "$UNIT" ]; then systemctl stop locksy || true; fi
      install -o locksy -g locksy -m 0600 "$D/verrou.db" "$BACKUP_FILE" \
        || { rm -f "$PREFIX/locksy-server.new"; die "Sauvegarde avant mise à jour impossible : mise à jour annulée."; }
      for s in -wal -shm; do
        if [ -f "$D/verrou.db$s" ]; then install -o locksy -g locksy -m 0600 "$D/verrou.db$s" "$BACKUP_FILE$s"; fi
      done
      ok "Base sauvegardée"
    fi
    if [ "$FROM" != "$NEWVER" ]; then
      cp -pf "$PREFIX/locksy-server" "$PREFIX/locksy-server.prev"
      rm -rf "$PREFIX/web.prev"
      if [ -d "$PREFIX/web" ]; then cp -a "$PREFIX/web" "$PREFIX/web.prev"; fi
      if [ -f "$PREFIX/VERSION" ]; then cp -f "$PREFIX/VERSION" "$PREFIX/VERSION.prev"; else printf '%s\n' "$FROM" > "$PREFIX/VERSION.prev"; fi
      PREV_SAVED=1
    else
      info "Même version ($NEWVER) : la version précédente conservée ne change pas."
    fi
  fi

  info "Installation de Locksy $NEWVER (mode $MODE) dans $PREFIX"
  rm -rf "$PREFIX/web.new"; cp -r "$SRC/web" "$PREFIX/web.new"; chmod -R u=rwX,go=rX "$PREFIX/web.new"
  mv -f "$PREFIX/locksy-server.new" "$PREFIX/locksy-server"
  rm -rf "$PREFIX/web"; mv "$PREFIX/web.new" "$PREFIX/web"
  printf '%s\n' "$NEWVER" > "$PREFIX/VERSION"; chmod 0644 "$PREFIX/VERSION"
  cp "$SRC/LICENSE" "$PREFIX/" 2>/dev/null || true
  if [ -f "$PREFIX/backup-locksy.sh.new" ]; then mv -f "$PREFIX/backup-locksy.sh.new" "$PREFIX/backup-locksy.sh"; fi
  [ -x "$PREFIX/backup-locksy.sh" ] && HAVE_BK_SCRIPT=1
  if [ "$PREV_SAVED" = 1 ]; then
    write_last_upgrade "$FROM" "$NEWVER" native "$BACKUP_FILE"
    ok "Version précédente ($FROM) conservée : retour arrière avec --rollback"
  fi

  if [ ! -f "$CONF/locksy.env" ]; then
    cat > "$CONF/locksy.env" <<ENV
# Configuration de Locksy (relancez : systemctl restart locksy)
LOCKSY_BIND=$(bracket "$LISTEN"):$PORT
LOCKSY_DATA=$DATA
LOCKSY_WEB=$PREFIX/web
LOCKSY_TLS_CERT=$CONF/tls/locksy.crt
LOCKSY_TLS_KEY=$CONF/tls/locksy.key
LOCKSY_HTTP_REDIRECT=$(bracket "$LISTEN"):80
RUST_LOG=info
# Journal d'audit vers votre SIEM : LOCKSY_SYSLOG=udp://syslog.corp.local:514
# Jeton d'installation (premier compte) : tiré au hasard dans $DATA/setup-token,
# ou imposé ici (20 caractères minimum) : LOCKSY_SETUP_TOKEN=...
# Syslog chiffré : LOCKSY_SYSLOG=tcp+tls://siem.corp.local:6514, avec au besoin
# l'autorité interne : LOCKSY_SYSLOG_CA_FILE=$CONF/tls/siem-ca.pem
# Journal au format JSON (collecteur de logs) : LOCKSY_LOG_FORMAT=json
# Délai laissé aux requêtes en cours à l'arrêt (s) : LOCKSY_SHUTDOWN_GRACE_SECS=10
# Une valeur illisible empêche le démarrage (code 2) : voir journalctl -u locksy.
ENV
    chmod 640 "$CONF/locksy.env"; chown root:locksy "$CONF/locksy.env"
  elif [ "$LISTEN_SET" = 1 ]; then
    warn "$CONF/locksy.env existe déjà : --listen ignoré (modifiez LOCKSY_BIND dans ce fichier)."
  fi
  cat > "$UNIT" <<UNIT
[Unit]
Description=Locksy, gestionnaire de mots de passe
After=network-online.target
Wants=network-online.target

[Service]
User=locksy
Group=locksy
EnvironmentFile=$CONF/locksy.env
ExecStart=$PREFIX/locksy-server
Restart=on-failure
RestartSec=3
# Arrêt gracieux : délai de grâce (LOCKSY_SHUTDOWN_GRACE_SECS, 10 s), point de
# contrôle de la base et vidage du journal syslog.
TimeoutStopSec=30
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
$HARDEN
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
# Seul dossier accessible en écriture. Si LOCKSY_SERVER_KEY_FILE pointe hors
# de ce dossier, ajoutez le sien ici pour la création de la clé au premier
# démarrage.
ReadWritePaths=$D

[Install]
WantedBy=multi-user.target
UNIT
  verify_unit "$UNIT"

  if [ "$HAVE_BK_SCRIPT" = 1 ] && [ "$NO_TIMER" = 0 ]; then write_backup_env locksy; fi
  install_backup_timer "[Unit]
Description=Locksy, sauvegarde de la base
After=locksy.service

[Service]
Type=oneshot
User=locksy
Group=locksy
EnvironmentFile=$CONF/locksy.env
EnvironmentFile=$CONF/backup.env
Environment=LOCKSY_SERVER_BIN=$PREFIX/locksy-server
ExecStart=$PREFIX/backup-locksy.sh
Nice=10
IOSchedulingClass=idle
CapabilityBoundingSet=
$HARDEN
PrivateNetwork=true
RestrictAddressFamilies=AF_UNIX
# Lecture à chaud de la base en WAL : écriture du fichier -shm dans $D.
ReadWritePaths=$D $BACKUP_DIR"
  [ -f "$BK_UNIT" ] && verify_unit "$BK_UNIT"

  if [ "$NOSTART" = 0 ]; then
    systemctl daemon-reload
    systemctl enable locksy >/dev/null 2>&1
    systemctl restart locksy
  elif has systemctl; then
    systemctl daemon-reload 2>/dev/null || true
  fi
  start_backup_timer
  native_probe
fi

# ----------------------------------------------------------------- Mode docker
if [ "$MODE" = docker ]; then
  info "Installation de Locksy $NEWVER (mode $MODE) dans $PREFIX"
  rm -rf "$PREFIX/web.new"; cp -r "$SRC/web" "$PREFIX/web.new"
  install -m 0755 "$SRC/bin/locksy-server" "$PREFIX/locksy-server.new"
  mv -f "$PREFIX/locksy-server.new" "$PREFIX/locksy-server"
  rm -rf "$PREFIX/web"; mv "$PREFIX/web.new" "$PREFIX/web"
  printf '%s\n' "$NEWVER" > "$PREFIX/VERSION"
  cp "$SRC/LICENSE" "$PREFIX/" 2>/dev/null || true
  if [ -f "$PREFIX/backup-locksy.sh.new" ]; then mv -f "$PREFIX/backup-locksy.sh.new" "$PREFIX/backup-locksy.sh"; fi
  [ -x "$PREFIX/backup-locksy.sh" ] && HAVE_BK_SCRIPT=1
  cat > "$PREFIX/Dockerfile" <<'DOCKER'
FROM debian:trixie-20261104-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
ARG LOCKSY_VERSION=inconnue
LABEL org.opencontainers.image.title="Locksy" org.opencontainers.image.version="${LOCKSY_VERSION}"
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin locksy && mkdir /data && chown locksy /data
COPY locksy-server /app/locksy-server
COPY web /app/web
USER locksy
ENV MALLOC_ARENA_MAX=2 SQLITE_TMPDIR=/data
ENV LOCKSY_DATA=/data LOCKSY_WEB=/app/web LOCKSY_BIND=0.0.0.0:8443 \
    LOCKSY_TLS_CERT=/tls/locksy.crt LOCKSY_TLS_KEY=/tls/locksy.key RUST_LOG=info
EXPOSE 8443
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s CMD ["/app/locksy-server", "healthcheck"]
ENTRYPOINT ["/app/locksy-server"]
DOCKER
  # Le build n'emporte que le binaire et l'interface web.
  printf '%s\n' '*' '!locksy-server' '!web' > "$PREFIX/.dockerignore"
  # La clé doit être lisible par l'utilisateur du conteneur (uid 10001).
  chown 10001 "$CONF/tls/locksy.key"; chmod 600 "$CONF/tls/locksy.key"
  mkdir -p "$BACKUP_DIR"; chown 10001 "$BACKUP_DIR"; chmod 0700 "$BACKUP_DIR"

  # Image en place : conservée sous locksy:previous (retour arrière).
  if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    UPGRADE=1
    if docker inspect "$CONTAINER" >/dev/null 2>&1; then FROM=$(image_version "$CONTAINER"); else FROM=$(image_version "$IMAGE"); fi
    if [ "$FROM" != "$NEWVER" ]; then
      docker tag "$IMAGE" "$PREV_IMAGE"
      PREV_SAVED=1
    else
      info "Même version ($NEWVER) : l'image précédente conservée ne change pas."
    fi
  fi
  info "Construction de l'image Docker"
  docker build -q --build-arg LOCKSY_VERSION="$NEWVER" -t "$IMAGE" "$PREFIX" >/dev/null \
    || { [ "$PREV_SAVED" = 0 ] || docker tag "$PREV_IMAGE" "$IMAGE"; die "Construction de l'image impossible (image de base debian épinglée absente hors ligne ? voir docs/Installation-du-serveur.md)."; }

  # Sauvegarde avant mise à jour, avec la NOUVELLE image (lecture en WAL
  # pendant que l'ancien conteneur tourne : prévu).
  if [ "$UPGRADE" = 1 ] && docker volume inspect "$VOLUME" >/dev/null 2>&1 \
      && docker run --rm --network none -v "$VOLUME:/data:ro" --entrypoint /bin/sh "$IMAGE" -c 'test -f /data/locksy.db'; then
    BACKUP_FILE="$BACKUP_DIR/pre-upgrade-$(safe_name "$FROM")-$STAMP.db"
    info "Sauvegarde de la base avant mise à jour : $BACKUP_FILE"
    if ! docker run --rm --network none --user 10001 -v "$VOLUME:/data" -v "$BACKUP_DIR:/backup" \
        -e LOCKSY_TLS_CERT= -e LOCKSY_TLS_KEY= -e LOCKSY_SYSLOG= -e LOCKSY_SYSLOG_CA_FILE= \
        "$IMAGE" backup "/backup/$(basename "$BACKUP_FILE")" >/dev/null; then
      if [ "$PREV_SAVED" = 1 ]; then docker tag "$PREV_IMAGE" "$IMAGE"; fi
      die "Sauvegarde avant mise à jour impossible : mise à jour annulée, le conteneur $CONTAINER n'a pas été modifié."
    fi
    ok "Base sauvegardée"
  fi
  if [ "$PREV_SAVED" = 1 ]; then
    write_last_upgrade "$FROM" "$NEWVER" docker "$BACKUP_FILE"
    ok "Version précédente ($FROM) conservée ($PREV_IMAGE) : retour arrière avec --rollback"
  fi

  # Réglages du conteneur, conservés d'une mise à jour à l'autre (mêmes
  # variables que le mode natif ; appliqués en relançant ce script).
  if [ ! -f "$CONF/docker.env" ]; then
    cat > "$CONF/docker.env" <<'ENV'
# Configuration du conteneur Locksy (appliquée en relançant install.sh).
# Une ligne VARIABLE=valeur par réglage, sans guillemets. Exemples :
# LOCKSY_SETUP_TOKEN=au-moins-20-caracteres-aleatoires
# LOCKSY_SYSLOG=udp://syslog.corp.local:514
# LOCKSY_LOG_FORMAT=json
# LOCKSY_SHUTDOWN_GRACE_SECS=10
# LOCKSY_DB_READERS=4
ENV
    chmod 600 "$CONF/docker.env"
  fi

  if [ "$HAVE_BK_SCRIPT" = 1 ] && [ "$NO_TIMER" = 0 ]; then write_backup_env root; fi
  install_backup_timer "[Unit]
Description=Locksy, sauvegarde de la base (conteneur $CONTAINER)
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
# root : accès au socket Docker (docker exec, docker cp, conteneur de test).
User=root
EnvironmentFile=$CONF/backup.env
ExecStart=$PREFIX/backup-locksy.sh --docker $CONTAINER
Nice=10
IOSchedulingClass=idle
NoNewPrivileges=true
PrivateTmp=true
UMask=0077"
  [ -f "$BK_UNIT" ] && verify_unit "$BK_UNIT"

  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  if [ "$NOSTART" = 0 ]; then run_container; else publish_warning; fi
  start_backup_timer
  HC_HOST=$(probe_host "$LISTEN") HC_PORT=$PORT
fi

# ----------------------------------------------------------------- Vérification
URL="https://$DOMAIN$([ "$PORT" = 443 ] || echo ":$PORT")"
if [ "$NOSTART" = 0 ]; then
  wait_healthy "$NEWVER"
fi

# ----------------------------------------------------------------- Jeton d'installation
# Tant qu'aucun compte n'existe, le premier compte (propriétaire) ne peut être
# créé qu'avec le jeton à usage unique écrit par le serveur dans setup-token.
if [ "$MODE" = native ]; then TOKEN_CMD="sudo cat $DATA/setup-token"
else TOKEN_CMD="sudo docker exec $CONTAINER cat /data/setup-token"; fi
read_setup_token() {
  if [ "$MODE" = native ]; then cat "$DATA/setup-token" 2>/dev/null || true
  else docker exec "$CONTAINER" cat /data/setup-token 2>/dev/null || true; fi
}
SETUP_TOKEN="" NEEDS_SETUP=1
if [ "$NOSTART" = 0 ]; then
  if has curl && ! curl -gfsk "$(health_url)" 2>/dev/null | grep -q '"needs_setup":true'; then
    NEEDS_SETUP=0
  fi
  if [ "$NEEDS_SETUP" = 1 ]; then
    # Le serveur écrit le fichier avant d'écouter ; attente bornée par prudence.
    for _ in 1 2 3 4 5; do
      SETUP_TOKEN=$(read_setup_token | tr -d '[:space:]')
      [ -n "$SETUP_TOKEN" ] && break
      sleep 1
    done
  fi
fi
if [ "$NEEDS_SETUP" = 0 ]; then
  SETUP_LINE="  2. Ouvrez $URL et connectez-vous (un compte propriétaire existe déjà)."
elif [ -n "$SETUP_TOKEN" ]; then
  SETUP_LINE="  2. Ouvrez $URL/#/register?setup=$SETUP_TOKEN
     (ou $URL avec le jeton d'installation ci-dessous) : le premier compte créé devient propriétaire.
     Jeton d'installation : $SETUP_TOKEN
     Il reste lisible avec : $TOKEN_CMD
     Il n'existe que tant qu'aucun compte n'a été créé ; gardez-le confidentiel."
else
  SETUP_LINE="  2. Ouvrez $URL : le premier compte créé devient propriétaire. Il faut le jeton
     d'installation, à lire avec : $TOKEN_CMD
     (il n'existe que tant qu'aucun compte n'a été créé). S'il est imposé par
     LOCKSY_SETUP_TOKEN, aucun fichier n'est écrit : utilisez cette valeur."
fi

BK_SUFFIX=""; [ "$MODE" = native ] || BK_SUFFIX=" --docker $CONTAINER"
if [ -f "$BK_TIMER" ]; then
  BACKUP_LINE="quotidienne à 02:30 (locksy-backup.timer) dans $BACKUP_DIR
                 maintenant : sudo systemctl start locksy-backup  (ou sudo $PREFIX/backup-locksy.sh$BK_SUFFIX)
                 réglages et chiffrement : $CONF/backup.env"
elif [ "$HAVE_BK_SCRIPT" = 1 ]; then
  BACKUP_LINE="pas de sauvegarde automatique ; à la main : sudo $PREFIX/backup-locksy.sh --dest $BACKUP_DIR$BK_SUFFIX"
else
  BACKUP_LINE=$([ "$MODE" = native ] && echo "sudo -u locksy LOCKSY_DATA=$DATA $PREFIX/locksy-server backup $BACKUP_DIR/locksy-\$(date +%F).db" || echo "docker exec $CONTAINER /app/locksy-server backup /data/locksy-\$(date +%F).db")
fi

cat <<FIN

${c_bold}Locksy est installé.${c_off}

  Adresse :      $URL
  Mode :         $MODE
  Données :      $([ "$MODE" = native ] && echo "$DATA" || echo "volume Docker $VOLUME")
  Certificat :   $CONF/tls/locksy.crt
$([ "$MODE" = native ] && echo "  Réglages :     $CONF/locksy.env  (puis : systemctl restart locksy)" || echo "  Réglages :     $CONF/docker.env  (puis : relancez ce script)")
  Sauvegarde :   $BACKUP_LINE
  Retour arrière : sudo bash install.sh --rollback$([ "$PREV_SAVED" = 1 ] && echo "  (vers $FROM)")
$([ "$MODE" = native ] && echo "  Durcissement : systemd-analyze security locksy")

Étapes suivantes :
  1. Créez un enregistrement DNS « $DOMAIN » vers ce serveur et ouvrez le port $PORT.
$SETUP_LINE
  3. Active Directory, SSO, sauvegardes : https://github.com/$REPO/tree/main/docs

FIN
