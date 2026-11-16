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
#  Installation hors ligne (réseau isolé) : copiez install.sh et l'archive
#  locksy-server-linux-x86_64.tar.gz sur le serveur, puis :
#    sudo bash install.sh --archive locksy-server-linux-x86_64.tar.gz
#
#  Options :
#    --mode native|docker      mode d'installation (défaut : demandé, ou native)
#    --domain NOM              nom DNS de Locksy, ex. locksy.corp.local
#    --cert FICHIER --key FICHIER
#                              certificat (chaîne PEM) et clé, ex. émis par AD CS.
#                              Sans eux : certificat autosigné temporaire.
#    --port N                  port HTTPS (défaut 443)
#    --archive FICHIER         archive de version locale (installation hors ligne)
#    --version vX.Y.Z          version à télécharger (défaut : la dernière)
#    --yes                     aucune question (valeurs par défaut)
#    --uninstall               désinstaller (les données sont conservées)
#    --purge                   avec --uninstall : supprimer aussi les données
#    --no-start                installer sans démarrer (tests)
#
#  Réinstaller avec une archive plus récente met Locksy à jour ; les données
#  sont conservées.
# =============================================================================
set -euo pipefail

REPO="__REPO__"
PREFIX=/opt/locksy
DATA=/var/lib/locksy
CONF=/etc/locksy
UNIT=/etc/systemd/system/locksy.service
IMAGE=locksy:local
CONTAINER=locksy
VOLUME=locksy-data

MODE="" DOMAIN="" CERT="" KEY="" PORT="" ARCHIVE="" VERSION="latest"
YES=0 UNINSTALL=0 PURGE=0 NOSTART=0

c_ok=$'\e[32m' c_warn=$'\e[33m' c_err=$'\e[31m' c_bold=$'\e[1m' c_off=$'\e[0m'
[ -t 1 ] || { c_ok=""; c_warn=""; c_err=""; c_bold=""; c_off=""; }
info() { printf '%s==>%s %s\n' "$c_bold" "$c_off" "$*"; }
ok()   { printf '%s ✓%s %s\n' "$c_ok" "$c_off" "$*"; }
warn() { printf '%s ! %s%s\n' "$c_warn" "$*" "$c_off"; }
die()  { printf '%s ✗ %s%s\n' "$c_err" "$*" "$c_off" >&2; exit 1; }

ask() { # question valeur_par_défaut -> réponse
  local q=$1 def=$2 r=""
  if [ "$YES" = 1 ] || [ ! -r /dev/tty ]; then echo "$def"; return; fi
  read -r -p "$q [$def] : " r </dev/tty || true
  echo "${r:-$def}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --mode) MODE=${2:-}; shift 2 ;;
    --domain) DOMAIN=${2:-}; shift 2 ;;
    --cert) CERT=${2:-}; shift 2 ;;
    --key) KEY=${2:-}; shift 2 ;;
    --port) PORT=${2:-}; shift 2 ;;
    --archive) ARCHIVE=${2:-}; shift 2 ;;
    --version) VERSION=${2:-}; shift 2 ;;
    --yes|-y) YES=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) PURGE=1; shift ;;
    --no-start) NOSTART=1; shift ;;
    -h|--help) sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "Option inconnue : $1 (voir --help)" ;;
  esac
done

[ "$(id -u)" = 0 ] || die "Lancez ce script en root (sudo)."
[ "$(uname -s)" = Linux ] || die "Ce script s'exécute sur Linux."
case "$(uname -m)" in x86_64|amd64) ;; *) die "Seule l'architecture x86_64 est fournie." ;; esac
has() { command -v "$1" >/dev/null 2>&1; }

# ----------------------------------------------------------------- Désinstallation
if [ "$UNINSTALL" = 1 ]; then
  info "Désinstallation de Locksy"
  if has systemctl && [ -f "$UNIT" ]; then
    systemctl disable --now locksy 2>/dev/null || true
    rm -f "$UNIT"; systemctl daemon-reload
  fi
  if has docker && docker inspect "$CONTAINER" >/dev/null 2>&1; then docker rm -f "$CONTAINER" >/dev/null; fi
  rm -rf "$PREFIX"
  if [ "$PURGE" = 1 ]; then
    rm -rf "$DATA" "$CONF"
    has docker && docker volume rm "$VOLUME" >/dev/null 2>&1 || true
    id locksy >/dev/null 2>&1 && userdel locksy || true
    ok "Locksy et toutes ses données ont été supprimés."
  else
    ok "Locksy est désinstallé. Données conservées dans $DATA (ou le volume Docker $VOLUME), configuration dans $CONF."
  fi
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
[[ "$PORT" =~ ^[0-9]+$ ]] || die "Port invalide : $PORT"
if [ -z "$CERT" ] && [ "$YES" = 0 ] && [ -r /dev/tty ]; then
  CERT=$(ask "Certificat (chaîne PEM) émis par votre autorité, vide = autosigné temporaire" "")
  [ -n "$CERT" ] && KEY=$(ask "Clé privée du certificat" "")
fi
if [ -n "$CERT" ] || [ -n "$KEY" ]; then
  [ -r "$CERT" ] || die "Certificat illisible : $CERT"
  [ -r "$KEY" ] || die "Clé illisible : $KEY"
fi

# ----------------------------------------------------------------- Archive
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
if [ -n "$ARCHIVE" ]; then
  [ -r "$ARCHIVE" ] || die "Archive introuvable : $ARCHIVE"
  cp "$ARCHIVE" "$WORK/locksy.tar.gz"
else
  [ "$REPO" != "__""REPO__" ] || die "Indiquez l'archive à installer avec --archive."
  if [ "$VERSION" = latest ]; then base="https://github.com/$REPO/releases/latest/download"
  else base="https://github.com/$REPO/releases/download/$VERSION"; fi
  info "Téléchargement de Locksy ($VERSION)"
  if has curl; then curl -fsSL "$base/locksy-server-linux-x86_64.tar.gz" -o "$WORK/locksy.tar.gz"
    curl -fsSL "$base/SHA256SUMS" -o "$WORK/SHA256SUMS"
  elif has wget; then wget -qO "$WORK/locksy.tar.gz" "$base/locksy-server-linux-x86_64.tar.gz"
    wget -qO "$WORK/SHA256SUMS" "$base/SHA256SUMS"
  else die "curl ou wget est nécessaire (ou utilisez --archive)."; fi
  expected=$(grep ' locksy-server-linux-x86_64.tar.gz$' "$WORK/SHA256SUMS" | cut -d' ' -f1)
  actual=$(sha256sum "$WORK/locksy.tar.gz" | cut -d' ' -f1)
  [ -n "$expected" ] && [ "$expected" = "$actual" ] || die "Empreinte SHA-256 incorrecte : téléchargement altéré ou incomplet."
  ok "Archive vérifiée (SHA-256)"
fi
tar -xzf "$WORK/locksy.tar.gz" -C "$WORK"
SRC="$WORK/locksy-server"
[ -x "$SRC/bin/locksy-server" ] && [ -f "$SRC/web/locksy.wasm" ] || die "Archive inattendue (bin/locksy-server ou web/locksy.wasm absent)."
NEWVER=$(cat "$SRC/VERSION" 2>/dev/null || echo "?")

# ----------------------------------------------------------------- Fichiers
info "Installation de Locksy $NEWVER (mode $MODE) dans $PREFIX"
mkdir -p "$PREFIX" "$CONF/tls"
rm -rf "$PREFIX/web.new"; cp -r "$SRC/web" "$PREFIX/web.new"
install -m 0755 "$SRC/bin/locksy-server" "$PREFIX/locksy-server.new"
mv -f "$PREFIX/locksy-server.new" "$PREFIX/locksy-server"
rm -rf "$PREFIX/web"; mv "$PREFIX/web.new" "$PREFIX/web"
cp "$SRC/LICENSE" "$PREFIX/" 2>/dev/null || true

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
  warn "Remplacez-le par un certificat de votre autorité (voir le wiki), puis relancez ce script avec --cert et --key."
fi

# ----------------------------------------------------------------- Mode native
if [ "$MODE" = native ]; then
  id locksy >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin locksy
  mkdir -p "$DATA"; chown locksy:locksy "$DATA"; chmod 700 "$DATA"
  chown root:locksy "$CONF/tls/locksy.key"; chmod 640 "$CONF/tls/locksy.key"
  if [ ! -f "$CONF/locksy.env" ]; then
    cat > "$CONF/locksy.env" <<ENV
# Configuration de Locksy (relancez : systemctl restart locksy)
LOCKSY_BIND=0.0.0.0:$PORT
LOCKSY_DATA=$DATA
LOCKSY_WEB=$PREFIX/web
LOCKSY_TLS_CERT=$CONF/tls/locksy.crt
LOCKSY_TLS_KEY=$CONF/tls/locksy.key
LOCKSY_HTTP_REDIRECT=0.0.0.0:80
RUST_LOG=info
# Journal d'audit vers votre SIEM : LOCKSY_SYSLOG=udp://syslog.corp.local:514
ENV
    chmod 640 "$CONF/locksy.env"; chown root:locksy "$CONF/locksy.env"
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
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ReadWritePaths=$DATA
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT
  if [ "$NOSTART" = 0 ]; then
    systemctl daemon-reload
    systemctl enable locksy >/dev/null 2>&1
    systemctl restart locksy
  fi
fi

# ----------------------------------------------------------------- Mode docker
if [ "$MODE" = docker ]; then
  cat > "$PREFIX/Dockerfile" <<'DOCKER'
FROM debian:trixie-slim
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin locksy && mkdir /data && chown locksy /data
COPY locksy-server /app/locksy-server
COPY web /app/web
USER locksy
ENV LOCKSY_DATA=/data LOCKSY_WEB=/app/web LOCKSY_BIND=0.0.0.0:8443 \
    LOCKSY_TLS_CERT=/tls/locksy.crt LOCKSY_TLS_KEY=/tls/locksy.key RUST_LOG=info
EXPOSE 8443
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s CMD ["/app/locksy-server", "healthcheck"]
ENTRYPOINT ["/app/locksy-server"]
DOCKER
  # La clé doit être lisible par l'utilisateur du conteneur (uid 10001).
  chown 10001 "$CONF/tls/locksy.key"; chmod 600 "$CONF/tls/locksy.key"
  info "Construction de l'image Docker"
  docker build -q -t "$IMAGE" "$PREFIX" >/dev/null
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  if [ "$NOSTART" = 0 ]; then
    docker run -d --name "$CONTAINER" --restart unless-stopped \
      -p "$PORT:8443" -v "$VOLUME:/data" -v "$CONF/tls:/tls:ro" \
      --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true \
      --memory 512m --pids-limit 128 "$IMAGE" >/dev/null
  fi
fi

# ----------------------------------------------------------------- Vérification
URL="https://$DOMAIN$([ "$PORT" = 443 ] || echo ":$PORT")"
if [ "$NOSTART" = 0 ]; then
  info "Vérification"
  up=0
  for _ in $(seq 1 30); do
    if has curl && curl -fsk "https://127.0.0.1:$PORT/api/health" >/dev/null 2>&1; then up=1; break; fi
    if ! has curl && (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then up=1; break; fi
    sleep 1
  done
  if [ "$up" = 1 ]; then ok "Locksy $NEWVER répond sur le port $PORT"
  else
    warn "Locksy ne répond pas encore. Journal :"
    if [ "$MODE" = native ]; then journalctl -u locksy -n 20 --no-pager || true; else docker logs --tail 20 "$CONTAINER" || true; fi
    exit 1
  fi
fi

cat <<FIN

${c_bold}Locksy est installé.${c_off}

  Adresse :      $URL
  Mode :         $MODE
  Données :      $([ "$MODE" = native ] && echo "$DATA" || echo "volume Docker $VOLUME")
  Certificat :   $CONF/tls/locksy.crt
$([ "$MODE" = native ] && echo "  Réglages :     $CONF/locksy.env  (puis : systemctl restart locksy)")

Étapes suivantes :
  1. Créez un enregistrement DNS « $DOMAIN » vers ce serveur et ouvrez le port $PORT.
  2. Ouvrez $URL : le premier compte créé devient propriétaire.
  3. Active Directory, SSO, sauvegardes : voir le wiki du projet.

FIN
