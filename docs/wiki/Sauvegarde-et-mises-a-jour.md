# Sauvegarde et mises à jour

## Que sauvegarder

Le dossier de données contient tout :

| Fichier | Rôle |
|---|---|
| `locksy.db` (+ `-wal`, `-shm`) | base SQLite (données chiffrées, comptes, journal) |
| `server.key` | clé du serveur : secrets 2FA, secret SSO, mot de passe du compte AD |

Sauvegardez **les deux ensemble**. Sans les mots de passe maîtres, ces fichiers ne permettent
de lire aucun coffre ; `server.key` reste sensible (il protège les secrets 2FA).

## Sauvegarde

Mode natif (`/var/lib/locksy`) :

```bash
sudo systemctl stop locksy
sudo tar czf /sauvegardes/locksy-$(date +%F).tgz -C /var/lib/locksy .
sudo systemctl start locksy
```

Sans interruption, avec SQLite :

```bash
sudo sqlite3 /var/lib/locksy/locksy.db ".backup '/sauvegardes/locksy-$(date +%F).db'"
sudo cp /var/lib/locksy/server.key /sauvegardes/
```

Mode Docker (volume `locksy-data`) :

```bash
docker run --rm -v locksy-data:/data -v /sauvegardes:/b debian:trixie-slim \
  tar czf /b/locksy-$(date +%F).tgz -C /data .
```

Conservez les sauvegardes hors du serveur, et testez une restauration régulièrement.

## Restauration

Arrêtez Locksy, remplacez le contenu du dossier de données par celui de la sauvegarde (en
gardant le propriétaire `locksy` en mode natif), redémarrez.

## Mise à jour

Relancez le script d'installation : il remplace le binaire et l'interface, **conserve les
données et la configuration**, puis redémarre.

```bash
curl -fsSL https://github.com/0x80070006/locksy/releases/latest/download/install.sh | sudo bash -s -- --yes
# ou hors ligne :
sudo bash install.sh --archive locksy-server-linux-x86_64.tar.gz --yes
```

Les évolutions du schéma de base sont appliquées automatiquement au démarrage. Faites une
sauvegarde avant chaque mise à jour.

## Renouvellement du certificat

Remplacez `/etc/locksy/tls/locksy.crt` et `locksy.key` : Locksy recharge le certificat toutes
les 6 heures, ou immédiatement avec `systemctl restart locksy`.

## Surveillance

`https://locksy.corp.local/api/health` renvoie `{"status":"ok",…}`. Journal :
`journalctl -u locksy` (natif) ou `docker logs locksy`.
