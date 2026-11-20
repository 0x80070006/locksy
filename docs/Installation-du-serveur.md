# Installation du serveur

## Prérequis

- Linux x86_64 : Debian 12/13, Ubuntu 22.04+, RHEL/Rocky/Alma 9… (le serveur est un binaire
  autonome, sans dépendance système).
- 1 à 2 vCPU, 1 Go de RAM (2 Go conseillés), 10 Go de disque, plus la place des sauvegardes.
- `systemd` (mode natif) **ou** Docker (mode conteneur).
- `curl` (ou `wget`), `sha256sum` et `openssl` si vous laissez le script créer un certificat
  temporaire.
- Pour vérifier la signature des versions : `cosign` ou `minisign` (facultatif, mais
  recommandé ; obligatoire avec `--require-signature`).
- Un nom DNS, par exemple `locksy.corp.local`, et idéalement un certificat émis par votre
  autorité (AD CS) : voir [Déploiement avec Active Directory](Deploiement-Active-Directory.md).

## Script d'installation

```bash
curl -fsSL https://github.com/0x80070006/locksy/releases/latest/download/install.sh | sudo bash
```

Le script pose quelques questions (mode, nom DNS, port, certificat), télécharge la version,
**vérifie son empreinte et sa signature**, installe, démarre Locksy en HTTPS, contrôle qu'il
répond, puis affiche le **jeton d'installation** et les commandes de sauvegarde.

Pour lire le script avant de l'exécuter (recommandé), téléchargez-le d'abord, avec
`SHA256SUMS` et ses signatures, et vérifiez-le comme indiqué dans
[SECURITY.md](../SECURITY.md#vérifier-une-version).

### Vérification de la version

1. **Empreinte** : l'archive doit correspondre à la ligne `locksy-server-linux-x86_64.tar.gz`
   de `SHA256SUMS`, ou à l'empreinte donnée par `--sha256` (qui prime). Sans empreinte
   vérifiable, l'installation est **refusée**, sauf `--skip-verify` (explicite, avec un
   avertissement).
2. **Signature de `SHA256SUMS`** :
   - cosign : `SHA256SUMS.sigstore.json`, identité du workflow `release.yml` du dépôt sur un
     tag `v*` ;
   - minisign : `SHA256SUMS.minisig`, avec la clé publique inscrite dans `install.sh` à la
     publication.

   Si l'outil, la clé ou l'identité, et le fichier de signature sont présents, la vérification
   est faite et un échec est **fatal**. S'il manque l'un d'eux, le script avertit
   « signature non vérifiée » et continue, sauf avec `--require-signature`, qui refuse.

### Sans accès Internet (réseau isolé)

Téléchargez depuis la page des versions, sur un poste connecté :
`install.sh`, `locksy-server-linux-x86_64.tar.gz`, `SHA256SUMS`, `SHA256SUMS.sigstore.json`
(et `SHA256SUMS.minisig` s'il existe). Vérifiez-les, copiez-les **dans le même dossier** du
serveur, puis :

```bash
sudo bash install.sh --archive locksy-server-linux-x86_64.tar.gz --version v1.1.0 \
  --mode native --domain locksy.corp.local --cert locksy.crt --key locksy.key --yes
```

`SHA256SUMS` et les signatures posés à côté de l'archive sont utilisés hors ligne. Avec
`--version`, la version doit être égale au fichier `VERSION` de l'archive, sinon refus.
minisign vérifie entièrement hors ligne ; il est essayé en premier quand l'outil, la clé
publique et `SHA256SUMS.minisig` sont présents. cosign, lui, a besoin de la racine de
confiance Sigstore, normalement mise en cache lors d'un usage connecté. Sur un serveur qui n'a
jamais eu accès à Internet et où cosign est installé, la vérification cosign échoue et
l'installation est refusée : utilisez minisign, ou vérifiez la signature sur le poste connecté
puis ne copiez sur le serveur que l'archive et `SHA256SUMS` (l'empreinte reste contrôlée, avec
l'avertissement « signature non vérifiée »).

### Options

| Option | Effet |
|---|---|
| `--mode native` | service **systemd**, sans Docker (recommandé sur VM) |
| `--mode docker` | conteneur Docker durci (lecture seule, sans capacités, 512 Mo) |
| `--domain NOM` | nom DNS utilisé par les utilisateurs |
| `--cert F --key F` | certificat (chaîne PEM) et clé ; sinon certificat **autosigné** temporaire |
| `--port N` | port HTTPS (443 par défaut) |
| `--listen ADDR` | adresse d'écoute (défaut `0.0.0.0`, affichée) ; IPv6 acceptée |
| `--archive F` | installation hors ligne depuis une archive locale |
| `--version vX.Y.Z` | épingle la version (`latest` par défaut) ; format `vX.Y.Z` ou `vX.Y.Z-suffixe` |
| `--sha256 HEX` | empreinte attendue de l'archive (prime sur `SHA256SUMS`) |
| `--skip-verify` | installe une archive sans empreinte vérifiable (déconseillé) |
| `--require-signature` | refuse si la signature de `SHA256SUMS` n'est pas vérifiée |
| `--backup-dir DIR` | dossier des sauvegardes (défaut `/var/backups/locksy`) |
| `--no-backup-timer` | n'installe pas la sauvegarde quotidienne |
| `--rollback` | revient à la version précédente (voir [Sauvegarde et mises à jour](Sauvegarde-et-mises-a-jour.md#retour-arrière)) |
| `--no-start` | installe sans démarrer |
| `--yes`, `-y` | aucune question |
| `--uninstall [--purge]` | désinstalle (données et sauvegardes conservées ; `--purge` supprime les données) |
| `-h`, `--help` | aide |

`--purge` efface les données : il demande de taper `SUPPRIMER`, sauf avec `--yes` ; sans
terminal et sans `--yes`, il refuse. Les sauvegardes de `--backup-dir` sont conservées, et leur
emplacement est affiché.

### Adresse d'écoute et pare-feu

Par défaut, Locksy écoute sur **toutes les interfaces** (`0.0.0.0`). Restreignez avec
`--listen`, par exemple `--listen 10.0.0.10` ou `--listen ::1`.

- Mode natif : `LOCKSY_BIND=ADDR:PORT`, écrit seulement à la création de `locksy.env` (une
  réinstallation ne change pas un fichier existant).
- Mode docker : `-p ADDR:PORT:8443` (`[ADDR]` pour IPv6).

> **Docker et pare-feu** : un port publié par Docker est ouvert par ses propres règles
> iptables, **avant** celles d'ufw ou de firewalld. Un pare-feu de l'hôte ne protège donc pas
> un port Docker publié sur `0.0.0.0` : utilisez `--listen`, ou filtrez dans la chaîne
> `DOCKER-USER`.

### Ce que fait le mode natif

| Élément | Emplacement |
|---|---|
| Binaire et interface web | `/opt/locksy/` (version précédente : `locksy-server.prev`, `web.prev/`) |
| Données (base, clé du serveur, jeton d'installation) | `/var/lib/locksy/` (droits 700, utilisateur `locksy`) |
| Réglages | `/etc/locksy/locksy.env` (0640, `root:locksy`) |
| Certificat | `/etc/locksy/tls/locksy.crt` et `locksy.key` |
| Service | `locksy.service` |
| Sauvegarde | `/opt/locksy/backup-locksy.sh`, `/etc/locksy/backup.env`, `locksy-backup.service` et `locksy-backup.timer` |
| Dernière mise à jour | `/etc/locksy/last-upgrade` |

Le service tourne sous l'utilisateur `locksy` avec un systemd durci :
- système de fichiers : `ProtectSystem=strict` (seul le dossier de données est inscriptible,
  `ReadWritePaths`), `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `DevicePolicy=closed`,
  `UMask=0077` ;
- noyau et processus : `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectKernelLogs`,
  `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`, `ProtectProc=invisible`,
  `ProcSubset=pid` ;
- privilèges : `NoNewPrivileges`, `RestrictSUIDSGID`, `RestrictNamespaces`,
  `RestrictRealtime`, `RemoveIPC`, `LockPersonality`, `MemoryDenyWriteExecute`, seule
  capacité `CAP_NET_BIND_SERVICE` (port 443) ;
- appels système et réseau : `SystemCallArchitectures=native`,
  `SystemCallFilter=@system-service` sans `@privileged` ni `@resources`,
  `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` ;
- arrêt gracieux : `TimeoutStopSec=30`.

`PrivateUsers` est volontairement absent (il annulerait `CAP_NET_BIND_SERVICE`). La sauvegarde
planifiée reprend ce durcissement, sans réseau ni capacité. `systemd-analyze security locksy`
donne l'évaluation complète.

Locksy écoute en HTTPS sur le port choisi et redirige le port 80 vers HTTPS.

Le **timer de sauvegarde** (`locksy-backup.timer`) lance chaque jour vers 02:30 (décalage
aléatoire de 30 min au plus, rattrapage après un arrêt) une sauvegarde vérifiée dans
`/var/backups/locksy` : voir [Sauvegarde et mises à jour](Sauvegarde-et-mises-a-jour.md).

```bash
systemctl status locksy                   # état
journalctl -u locksy -f                   # journal
systemctl list-timers locksy-backup.timer # prochaine sauvegarde
sudo nano /etc/locksy/locksy.env && sudo systemctl restart locksy
```

### Ce que fait le mode Docker

Image construite localement à partir de la version (aucun registre externe), sur une base
Debian épinglée par empreinte ; conteneur `locksy` en lecture seule, sans capacités, volume
`locksy-data`, certificat monté depuis `/etc/locksy/tls`, réglages dans
`/etc/locksy/docker.env` (0600), arrêt gracieux (`--stop-timeout 25`). L'image précédente est
gardée sous l'étiquette `locksy:previous` pour le retour arrière. La sauvegarde quotidienne
(`locksy-backup.timer`, `backup-locksy.sh --docker locksy`) et la sauvegarde d'avant mise à
jour sont écrites dans `--backup-dir`.

```bash
docker logs -f locksy
docker exec locksy /app/locksy-server check
```

## Variables de configuration

La table complète des variables, avec leurs bornes, est dans
[Exploitation](Exploitation.md#variables-denvironnement). Les plus courantes :

| Variable | Rôle | Défaut |
|---|---|---|
| `LOCKSY_BIND` | adresse d'écoute | `0.0.0.0:8743` |
| `LOCKSY_TLS_CERT`, `LOCKSY_TLS_KEY` | HTTPS intégré (rechargé toutes les 6 h) | — |
| `LOCKSY_TRUST_PROXY`, `LOCKSY_TRUSTED_PROXIES` | derrière un proxy inverse | `false` |
| `LOCKSY_SETUP_TOKEN` | jeton d'installation imposé (20 caractères minimum) | tiré au hasard dans `<données>/setup-token` |
| `LOCKSY_SYSLOG`, `LOCKSY_SYSLOG_CA_FILE` | journal d'audit vers un SIEM (`udp://`, `tcp://`, `tcp+tls://`) | — |
| `LOCKSY_LOG_FORMAT` | `text` ou `json` | `text` |

Toutes les valeurs sont vérifiées au démarrage : une valeur illisible arrête le serveur avec un
message clair (code de sortie 2). Pour vérifier sans démarrer : `locksy-server check` (code 0
si tout va bien, 1 en cas de problème, 2 si la configuration est invalide). Sondes
(`/api/health`, `/api/ready`), journaux et supervision : [Exploitation](Exploitation.md).

## Premier démarrage

1. Ouvrez `https://locksy.corp.local`. L'écran **« Installation de Locksy »** apparaît.
2. Saisissez le **jeton d'installation** affiché en fin d'installation (sinon :
   `sudo cat /var/lib/locksy/setup-token`, ou `sudo docker exec locksy cat /data/setup-token`).
   Il est à usage unique : le premier compte créé avec lui devient **propriétaire**, puis le
   jeton est effacé.
3. Choisissez un mot de passe maître robuste et rangez la **clé de récupération** hors ligne.
4. Activez la double authentification (Paramètres > Sécurité).
5. Créez un **second propriétaire** : c'est l'accès de secours si l'annuaire est indisponible.
6. Branchez l'annuaire : [Déploiement avec Active Directory](Deploiement-Active-Directory.md).

Les essais de jeton sont plafonnés pour tous les clients à la fois : un tiers qui joint le
serveur peut **retarder** la création du premier compte (de 30 s à 1 h au plus), pas la
prendre. Créez le compte aussitôt après l'installation, depuis un réseau maîtrisé.

## Autres façons d'installer

- **Docker Compose depuis les sources** (poste d'essai) : `docker compose up -d --build`, puis
  <http://localhost:8743> ; jeton : `docker exec locksy cat /data/setup-token`.
- **Derrière un proxy existant** (nginx, Caddy, HAProxy) : laissez Locksy en HTTP sur
  `127.0.0.1:8743`, mettez `LOCKSY_TRUST_PROXY=true`, et terminez le TLS sur le proxy. Le
  proxy doit **ajouter** l'adresse du client à droite de `X-Forwarded-For` (Locksy lit l'entrée
  la plus à droite) ; derrière plusieurs proxys, déclarez-les dans `LOCKSY_TRUSTED_PROXIES`.
  Exemple Caddy durci fourni dans `deploiement/` (voir
  [GUIDE-SUR-SITE](../deploiement/GUIDE-SUR-SITE.md)).
