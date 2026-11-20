# Déploiement sur site

Le guide complet est dans la documentation du projet :

- [Installation du serveur](../docs/Installation-du-serveur.md) : script `install.sh`
  (service systemd ou Docker), HTTPS intégré.
- [Déploiement avec Active Directory](../docs/Deploiement-Active-Directory.md) : certificat
  AD CS, LDAPS, synchronisation, connexion Windows.
- [Client Windows](../docs/Client-Windows.md) et [Extension](../docs/Extension-navigateur.md) :
  déploiement par GPO.

Ce dossier fournit une variante **avec proxy Caddy** (`docker-compose.onprem.yml`, `Caddyfile`)
pour ceux qui préfèrent terminer le TLS sur un proxy.

## Vérifier ce que l'on installe

`install.sh` contrôle l'archive avant de l'installer :

- **Empreinte SHA-256** : `SHA256SUMS` doit être à côté de l'archive (copiez-le avec elle
  en réseau isolé), ou l'empreinte est donnée par `--sha256 <hex>`. Sans l'un ni l'autre,
  l'installation est refusée (`--skip-verify` passe outre, déconseillé).
- **Signature de `SHA256SUMS`** : vérifiée si `minisign` (clé publique de l'éditeur, inscrite
  dans `install.sh`) ou `cosign` (identité du workflow GitHub `release.yml`) est installé et
  si `SHA256SUMS.minisig` ou `SHA256SUMS.sigstore.json` est présent. Une signature fausse
  arrête tout ; une signature invérifiable n'est qu'un avertissement, sauf avec
  `--require-signature` (recommandé en production).
- **Version** : `--version vX.Y.Z` épingle la version ; avec `--archive`, elle doit
  correspondre au fichier `VERSION` de l'archive.

Mises à jour : la base est sauvegardée avant (`pre-upgrade-*.db` dans `--backup-dir`,
défaut `/var/backups/locksy`), la version précédente est gardée et
`sudo bash install.sh --rollback` y revient. Une sauvegarde quotidienne vérifiée
(`locksy-backup.timer`, script `backup-locksy.sh`, chiffrement age ou GnuPG dans
`/etc/locksy/backup.env`) est installée, sauf `--no-backup-timer`.

## Variante avec proxy Caddy : durcissement

- Image Caddy épinglée par empreinte (`caddy:2.11.9-alpine@sha256:…`), système de fichiers
  en lecture seule (seuls `/data`, `/config` et `/tmp` sont inscriptibles),
  `no-new-privileges`, toutes les capacités retirées sauf `NET_BIND_SERVICE`.
- Caddy reste root **dans** le conteneur : avec `no-new-privileges`, un utilisateur non root
  ne pourrait plus ouvrir les ports 80 et 443.
- HSTS (`max-age=63072000`, comme le serveur) posé une seule fois par Caddy ; celui de
  Locksy est retiré de la réponse pour éviter le doublon.
- `includeSubDomains` : une ligne commentée du `Caddyfile` l'active. Ne le faites que si
  **tous** les sous-domaines du domaine sont servis en HTTPS : sinon les navigateurs les
  refuseront pendant deux ans.
- `X-Forwarded-For` est réécrit avec l'adresse vue par Caddy : Locksy lit l'entrée la plus
  à droite (voir `LOCKSY_TRUSTED_PROXIES`).
