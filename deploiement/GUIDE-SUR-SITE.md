# Déploiement sur site

Le guide complet est dans le wiki du projet :

- [Installation du serveur](../docs/wiki/Installation-du-serveur.md) : script `install.sh`
  (service systemd ou Docker), HTTPS intégré.
- [Déploiement avec Active Directory](../docs/wiki/Deploiement-Active-Directory.md) : certificat
  AD CS, LDAPS, synchronisation, connexion Windows.
- [Client Windows](../docs/wiki/Client-Windows.md) et [Extension](../docs/wiki/Extension-navigateur.md) :
  déploiement par GPO.

Ce dossier fournit une variante **avec proxy Caddy** (`docker-compose.onprem.yml`, `Caddyfile`)
pour ceux qui préfèrent terminer le TLS sur un proxy.
