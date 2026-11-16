# Installation du serveur

## Prérequis

- Linux x86_64 : Debian 12/13, Ubuntu 22.04+, RHEL/Rocky/Alma 9… (le serveur est un binaire
  autonome, sans dépendance système).
- 1 à 2 vCPU, 1 Go de RAM (2 Go conseillés), 10 Go de disque.
- `systemd` (mode natif) **ou** Docker (mode conteneur).
- `curl` (ou `wget`) et `openssl` si vous laissez le script créer un certificat temporaire.
- Un nom DNS, par exemple `locksy.corp.local`, et idéalement un certificat émis par votre
  autorité (AD CS) : voir [Déploiement avec Active Directory](Deploiement-Active-Directory).

## Script d'installation

```bash
curl -fsSL https://github.com/0x80070006/locksy/releases/latest/download/install.sh | sudo bash
```

Le script pose quelques questions (mode, nom DNS, port, certificat), télécharge la dernière
version, **vérifie son empreinte SHA-256**, installe, démarre Locksy en HTTPS et contrôle qu'il
répond.

### Sans accès Internet (réseau isolé)

Téléchargez depuis la page des versions `install.sh` et `locksy-server-linux-x86_64.tar.gz`,
copiez-les sur le serveur, puis :

```bash
sudo bash install.sh --archive locksy-server-linux-x86_64.tar.gz \
  --mode native --domain locksy.corp.local --cert locksy.crt --key locksy.key --yes
```

### Options

| Option | Effet |
|---|---|
| `--mode native` | service **systemd**, sans Docker (recommandé sur VM) |
| `--mode docker` | conteneur Docker durci (lecture seule, sans capacités, 512 Mo) |
| `--domain NOM` | nom DNS utilisé par les utilisateurs |
| `--cert F --key F` | certificat (chaîne PEM) et clé ; sinon certificat **autosigné** temporaire |
| `--port N` | port HTTPS (443 par défaut) |
| `--archive F` | installation hors ligne depuis une archive locale |
| `--version vX.Y.Z` | version précise à télécharger |
| `--yes` | aucune question |
| `--uninstall [--purge]` | désinstaller (données conservées, sauf `--purge`) |

### Ce que fait le mode natif

| Élément | Emplacement |
|---|---|
| Binaire et interface web | `/opt/locksy/` |
| Données (base, clé du serveur) | `/var/lib/locksy/` (droits 700, utilisateur `locksy`) |
| Réglages | `/etc/locksy/locksy.env` |
| Certificat | `/etc/locksy/tls/locksy.crt` et `locksy.key` |
| Service | `locksy.service` (systemd durci : `ProtectSystem=strict`, `NoNewPrivileges`…) |

Locksy écoute en HTTPS sur le port choisi et redirige le port 80 vers HTTPS.

```bash
systemctl status locksy          # état
journalctl -u locksy -f          # journal
sudo nano /etc/locksy/locksy.env && sudo systemctl restart locksy
```

### Ce que fait le mode Docker

Image construite localement à partir de la version (aucun registre externe), conteneur
`locksy` en lecture seule, volume `locksy-data`, certificat monté depuis `/etc/locksy/tls`.

```bash
docker logs -f locksy
```

## Variables de configuration

| Variable | Rôle | Défaut |
|---|---|---|
| `LOCKSY_BIND` | adresse d'écoute | `0.0.0.0:8743` |
| `LOCKSY_DATA` | dossier des données | `/data` |
| `LOCKSY_WEB` | dossier de l'interface web | `/app/web` |
| `LOCKSY_TLS_CERT`, `LOCKSY_TLS_KEY` | HTTPS intégré (rechargé toutes les 6 h) | — |
| `LOCKSY_HTTP_REDIRECT` | écoute HTTP qui redirige vers HTTPS, ex. `0.0.0.0:80` | — |
| `LOCKSY_TRUST_PROXY` | `true` derrière un proxy inverse de confiance | `false` |
| `LOCKSY_SYSLOG` | journal d'audit vers un SIEM : `udp://hôte:514` ou `tcp://…` | — |
| `LOCKSY_SSO_ALLOW_HTTP` | fournisseur SSO en http (essais uniquement) | `false` |
| `RUST_LOG` | niveau de journalisation | `info` |

## Premier démarrage

1. Ouvrez `https://locksy.corp.local`. L'écran **« Installation de Locksy »** apparaît.
2. Le **premier compte créé devient propriétaire**. Choisissez un mot de passe maître robuste
   et rangez la **clé de récupération** hors ligne.
3. Activez la double authentification (Paramètres > Sécurité).
4. Créez un **second propriétaire** : c'est l'accès de secours si l'annuaire est indisponible.
5. Branchez l'annuaire : [Déploiement avec Active Directory](Deploiement-Active-Directory).

## Autres façons d'installer

- **Docker Compose depuis les sources** (poste d'essai) : `docker compose up -d --build`, puis
  <http://localhost:8743>.
- **Derrière un proxy existant** (nginx, Caddy, HAProxy) : laissez Locksy en HTTP sur
  `127.0.0.1:8743`, mettez `LOCKSY_TRUST_PROXY=true`, et terminez le TLS sur le proxy. Exemple
  Caddy fourni dans `deploiement/`.
