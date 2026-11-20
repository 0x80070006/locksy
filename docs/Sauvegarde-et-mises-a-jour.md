# Sauvegarde et mises à jour

## Que sauvegarder

Le dossier de données contient tout :

| Fichier | Rôle |
|---|---|
| `locksy.db` (+ `-wal`, `-shm`) | base SQLite (données chiffrées, comptes, journal) |
| `server.key` | clé du serveur : secrets 2FA, codes de secours, secret SSO, mot de passe du compte AD et SMTP, chaînage du journal d'audit |

Sauvegardez **les deux**, mais **rangez la clé à part** (autre support, accès restreint). Sans
les mots de passe maîtres, ces fichiers ne permettent de lire aucun coffre ; base et clé
ensemble exposent cependant les secrets 2FA, le secret SSO et le mot de passe du compte AD.
Pensez aussi au certificat TLS et à `/etc/locksy/`.

Sans la `server.key` d'origine, le chaînage du journal d'audit ne peut plus être vérifié
(`locksy-server verify-audit`, voir [Exploitation](Exploitation.md#journal-daudit-chaîné)).

> **Ne copiez jamais `locksy.db` à la main**, même service arrêté. La base fonctionne en
> journal WAL : une copie de fichier peut être incomplète ou incohérente, et rien ne la
> vérifie. Utilisez toujours `locksy-server backup` (ou `backup-locksy.sh`, qui l'appelle) :
> la copie est faite à chaud, vérifiée, et n'est jamais partielle.
>
> La perte est **silencieuse** : lors des essais de la 1.1.0, une copie de `locksy.db` seule,
> prise pendant des écritures, perdait les écritures acquittées de la dernière seconde dans
> 1 à 3 copies sur 5, alors que `integrity_check` répondait « ok » et que le serveur
> redémarrait sans rien signaler (`check` = 0).

L'écran Administration > Réglages > Système n'affiche pas encore la date de la dernière
sauvegarde (« Dernière sauvegarde inconnue ») : surveillez-la sur le serveur (voir
[Exploitation](Exploitation.md#supervision-et-alertes)).

## Sauvegarde automatique (timer)

`install.sh` installe une sauvegarde quotidienne, en mode natif comme en mode docker (sauf
`--no-backup-timer`) :

| Élément | Rôle |
|---|---|
| `/opt/locksy/backup-locksy.sh` | script de sauvegarde (aussi dans l'archive : `scripts/backup-locksy.sh`) |
| `/etc/locksy/backup.env` (0640, groupe `locksy` en mode natif, `root` en mode docker) | réglages de la sauvegarde |
| `locksy-backup.service` | exécution unique du script (mode natif : utilisateur `locksy`, systemd durci, sans réseau, écriture limitée aux données et au dossier des sauvegardes ; mode docker : `--docker locksy`) |
| `locksy-backup.timer` | chaque jour à 02:30, décalage aléatoire de 30 min au plus, rattrapé après un arrêt (`Persistent=true`) |

Réglages de `/etc/locksy/backup.env` :

| Variable | Rôle | Défaut |
|---|---|---|
| `LOCKSY_BACKUP_DIR` | dossier des sauvegardes ; pour le changer, relancez `install.sh --backup-dir DIR` (le service n'a le droit d'écrire que là) | `/var/backups/locksy` (ou `--backup-dir`) |
| `LOCKSY_BACKUP_KEEP` | nombre de sauvegardes conservées | `14` |
| `LOCKSY_BACKUP_AGE_RECIPIENT` | destinataire age (clé publique `age1…`) : chiffre la sauvegarde | vide |
| `LOCKSY_BACKUP_GPG_RECIPIENT` | destinataire gpg : clé publique importée dans le trousseau du compte qui sauvegarde (mode natif : `/var/lib/locksy/.gnupg`, ou `GNUPGHOME`) | vide |
| `LOCKSY_BACKUP_WITH_KEY` | `1` : sauvegarde aussi la clé serveur (exige un chiffrement) | `0` |

**Chiffrez vos sauvegardes** : renseignez un destinataire age ou gpg dont la **clé privée
n'est pas sur le serveur** (voir [PRA/PCA](PRA-PCA.md#rançongiciel)). Puis copiez chaque jour
le dossier des sauvegardes hors du serveur.

```bash
systemctl list-timers locksy-backup.timer      # prochaine exécution
sudo systemctl start locksy-backup.service      # sauvegarde immédiate
journalctl -u locksy-backup.service             # résultat
```

## backup-locksy.sh

```
backup-locksy.sh [--dest DIR] [--keep N] [--name NOM] [--with-key]
                 [--age-recipient R | --gpg-recipient R]
                 [--docker CONTENEUR] [--no-restore-test]
```

1. Copie à chaud et vérifiée de la base par `locksy-server backup` (sans arrêt du service).
2. **Test de restauration** : la copie en clair est ouverte dans un dossier temporaire par
   `locksy-server check` (avec la clé sauvegardée, ou la clé de production) ; un code différent
   de 0 fait échouer la sauvegarde. `--no-restore-test` le désactive (déconseillé).
3. Chiffrement par age ou gpg, puis effacement de la copie en clair.
4. Rotation : seules les `N` sauvegardes les plus récentes (`locksy-*.db*`) sont gardées. Une
   sauvegarde nommée par `--name` n'est pas concernée ; les sauvegardes d'avant mise à jour
   (`pre-upgrade-*`, écrites par `install.sh`) sont gardées à part, les 5 dernières.

| Fichier produit | Contenu |
|---|---|
| `locksy-AAAAMMJJ-HHMMSS.db` (ou `<NOM>.db`), suivi de `.age` ou `.gpg` si chiffré | base |
| `<base>.db.server.key[.age|.gpg]` | clé serveur, avec `--with-key` seulement |

`--with-key` **sans chiffrement est refusé** : une clé serveur ne doit jamais dormir en clair
dans un dossier de sauvegardes. Codes de sortie : 0 succès, 1 échec (y compris le test de
restauration), 2 mauvaise utilisation.

Les options l'emportent sur les variables `LOCKSY_BACKUP_*` ; une variable absente de
l'environnement est reprise de `/etc/locksy/backup.env`, puis de `/etc/locksy/locksy.env`. Le
script lit aussi `LOCKSY_SERVER_BIN` (défaut `/opt/locksy/locksy-server`), `LOCKSY_DATA` et
`LOCKSY_SERVER_KEY_FILE`, transmis au serveur. Avec `--docker CONTENEUR`, la base d'un
conteneur Locksy en marche est sauvegardée. Une ligne de résultat (`ÉCHEC …` en cas d'erreur)
est écrite sur la sortie standard, donc dans le journal du timer.

```bash
# Natif, à la main, chiffrée pour une clé age dont la partie privée est hors site
sudo /opt/locksy/backup-locksy.sh --dest /var/backups/locksy \
  --age-recipient "age1<clé publique du destinataire>" --with-key

# Docker
sudo /opt/locksy/backup-locksy.sh --docker locksy --dest /var/backups/locksy \
  --gpg-recipient sauvegarde-locksy@example.com
```

## Sauvegarde à la main (commande intégrée)

`locksy-server backup <fichier> [--with-key] [--force]` copie la base **à chaud**, vérifie la
copie (`integrity_check`, même version de schéma), l'écrit en 0600 puis la renomme : un
fichier de sauvegarde n'est jamais partiel. `--with-key` copie aussi la clé serveur dans
`<fichier>.server.key` ; `--force` remplace une sauvegarde existante. Le dossier de destination
doit exister. Code 0 en cas de succès, 1 en cas d'échec, 2 si la commande est mal écrite. La
base de production n'est jamais modifiée.

```bash
# Mode natif
sudo -u locksy LOCKSY_DATA=/var/lib/locksy /opt/locksy/locksy-server \
  backup /var/lib/locksy/locksy-$(date +%F).db --with-key
sudo mv /var/lib/locksy/locksy-$(date +%F).db* /sauvegardes/

# Mode Docker (conteneur locksy, volume monté sur /data)
docker exec locksy /app/locksy-server backup /data/locksy-$(date +%F).db --with-key
docker cp locksy:/data/locksy-$(date +%F).db /sauvegardes/
docker cp locksy:/data/locksy-$(date +%F).db.server.key /coffre-cles/
docker exec locksy rm /data/locksy-$(date +%F).db /data/locksy-$(date +%F).db.server.key
```

## Vérification

`locksy-server check` contrôle la configuration, le dossier de données, la base (version du
schéma, `integrity_check`, clés étrangères) et la clé serveur, sans rien écrire ni migrer.
Chaque ligne commence par `OK`, `ATTENTION` ou `ERREUR` ; code 0 si tout va bien, 1 en cas de
problème, 2 si la configuration est invalide.

```bash
docker exec locksy /app/locksy-server check
```

## Restauration

1. Arrêtez Locksy (`systemctl stop locksy` ou `docker stop locksy`).
2. Déchiffrez la sauvegarde si besoin, sur une machine qui détient la clé privée :
   `age -d -i cle-privee.txt locksy-….db.age > locksy.db` ou
   `gpg -d locksy-….db.gpg > locksy.db` (de même pour `.server.key`).
3. Remplacez `locksy.db` par la copie, et **supprimez `locksy.db-wal` et `locksy.db-shm`**
   s'ils existent (ils appartiennent à l'ancienne base).
4. Remettez la clé `server.key` d'origine (celle de la sauvegarde) avec les droits 0600 et le
   propriétaire `locksy` en mode natif.
5. Vérifiez avec `locksy-server check`, puis redémarrez.

Si `server.key` est absente alors que la base contient des comptes, le serveur **refuse de
démarrer** (au lieu d'en générer une nouvelle, qui rendrait illisibles les secrets 2FA, SSO et
AD). Restaurez la clé ; si elle est définitivement perdue, `LOCKSY_SERVER_KEY_RESET=true`
génère une nouvelle clé : chaque utilisateur doit alors réactiver sa double authentification,
et l'administrateur ressaisir le secret SSO et le mot de passe du compte AD (procédure :
[Exploitation](Exploitation.md#rotation-de-serverkey)).

## Restaurer sans la clé du serveur

Si la sauvegarde de la base est intacte mais que `server.key` est **définitivement perdue** :

1. Restaurez la base comme ci-dessus (étapes 1 à 3), sans clé.
2. Démarrez **une fois** avec `LOCKSY_SERVER_KEY_RESET=true` : une nouvelle clé est écrite,
   un avertissement est journalisé. Retirez ensuite la variable.
3. Les coffres restent lisibles par leurs membres : ils ne dépendent pas de cette clé.
4. Sont perdus, à refaire : la double authentification de chaque compte (secrets et codes de
   secours illisibles : réinitialisation par un administrateur, puis réactivation par la
   personne), le secret de la connexion d'entreprise, le mot de passe du compte de service
   Active Directory et celui du serveur d'envoi des e-mails.
5. Le journal antérieur n'est plus vérifiable : `verify-audit` commence par « Chaînage
   invérifiable : la clé serveur n'est pas celle qui a écrit le journal », puis détaille les
   lignes (`anchor_invalid`). Notez la date de la réinitialisation dans votre registre
   d'incidents.
6. À la connexion, une personne dont la double authentification est devenue illisible reçoit
   le message « Votre double authentification doit être réactivée : la clé du serveur a
   changé » (code `totp_unreadable`) : réinitialisez sa 2FA dans Administration > Personnes.

Procédure détaillée, y compris quand tous les administrateurs avaient la double
authentification : [Exploitation](Exploitation.md#rotation-de-serverkey).

## Mise à jour

Relancez le script d'installation : il remplace le binaire et l'interface, **conserve les
données et la configuration**, puis redémarre.

```bash
curl -fsSL https://github.com/0x80070006/locksy/releases/latest/download/install.sh | sudo bash -s -- --yes
# version précise, signature exigée :
curl -fsSL https://github.com/0x80070006/locksy/releases/latest/download/install.sh \
  | sudo bash -s -- --version v1.1.0 --require-signature --yes
# ou hors ligne (SHA256SUMS et signatures à côté de l'archive) :
sudo bash install.sh --archive locksy-server-linux-x86_64.tar.gz --yes
```

Avant de remplacer quoi que ce soit, le script :
- fait une **sauvegarde** de la base : `pre-upgrade-<version d'origine>-<AAAAMMJJ-HHMMSS>.db`
  dans le dossier des sauvegardes ;
- garde la version en place : `/opt/locksy/locksy-server.prev` et `/opt/locksy/web.prev/`
  (mode natif), ou l'image `locksy:previous` (mode docker) ;
- note la mise à jour dans `/etc/locksy/last-upgrade` (`FROM_VERSION`, `TO_VERSION`, `MODE`,
  `BACKUP`, `DATE`).

La sauvegarde est faite par le **nouveau** binaire (une version 1.0.0 n'a pas la sous-commande
`backup`) ; si elle échoue, la mise à jour est **annulée** et la version en place est gardée.

Les évolutions du schéma de base sont appliquées automatiquement au démarrage, palier par
palier, chacun dans une transaction (`PRAGMA user_version` ; `locksy-server version` affiche la
version gérée). Un binaire **refuse de démarrer** sur une base d'un schéma plus récent que le
sien.

Lisez le [CHANGELOG](../CHANGELOG.md) avant chaque mise à jour, en particulier la rubrique
« Changements de comportement ».

### Passer de 1.0.0 à 1.1.0

1. Lisez les « Changements de comportement » de la 1.1.0 dans le
   [CHANGELOG](../CHANGELOG.md#110---non-publiée) (jeton d'installation, proxy, double
   authentification après la connexion d'entreprise, extension et client Windows à mettre à
   jour).
2. Faites une **sauvegarde complète, clé comprise**, et copiez-la hors du serveur. La 1.0.0 n'a
   pas la sous-commande `backup` : utilisez celle du binaire 1.1.0 sur les données de la 1.0.0
   (`LOCKSY_DATA=<dossier des données> locksy-server backup <fichier> --with-key`), ou laissez
   `install.sh` la faire (sauvegarde `pre-upgrade-…`). Gardez-la jusqu'à la fin de la
   validation.
3. Mettez à jour le serveur (`install.sh`, ci-dessus). La base est migrée au premier démarrage.
4. Vérifiez : `locksy-server check` répond 0, `/api/ready` répond, une connexion réussit, et
   Administration > Réglages > Système indique « en service ». Vos anciens réglages sont repris
   dans les nouvelles sections.
5. Mettez à jour l'extension et le client Windows : les clients 1.0.0 ne savent pas demander
   le code de vérification après la connexion d'entreprise.

## Retour arrière

```bash
sudo bash install.sh --rollback
```

1. Le service est arrêté.
2. Le binaire et l'interface `.prev` sont remis en place (mode docker : `locksy:previous` est
   réétiqueté `locksy:local` et le conteneur recréé).
3. Si l'ancien binaire **refuse le schéma** (`check` répond 1 avec « plus récent ») parce que la
   mise à jour a migré la base, le script propose de restaurer la sauvegarde `BACKUP` de
   `last-upgrade`, avec confirmation (sauf `--yes`) ; `-wal` et `-shm` sont supprimés. Tout ce
   qui a été modifié depuis la mise à jour est alors **perdu**.
4. Le service redémarre.

Sans sauvegarde d'avant mise à jour disponible, le script s'arrête, service arrêté : réinstallez
la version récente, ou restaurez à la main une sauvegarde compatible. Une version antérieure
qui n'a pas la sous-commande `check` (1.0.0) ne peut pas vérifier la base : le script le
signale et propose, en mode interactif, de restaurer la sauvegarde d'avant mise à jour.

### Revenir de 1.1.0 à 1.0.0

La 1.0.0 **ne sait pas reconnaître une base migrée par la 1.1.0** : elle ne refuse pas de
démarrer et **modifie le fichier** (constaté lors des essais, voir « Repères mesurés »). Le
seul retour arrière sûr est donc la **restauration de la sauvegarde faite juste avant la mise
à jour** :

1. `sudo bash install.sh --rollback` ; à la question, acceptez la restauration de la
   sauvegarde `pre-upgrade-…` (ou restaurez-la à la main, voir [Restauration](#restauration),
   avec la `server.key` de cette sauvegarde).
2. Ne démarrez jamais la 1.0.0 sur la base de la 1.1.0, même « pour voir ».
3. Tout ce qui a été fait depuis la mise à jour est perdu : éléments créés ou modifiés,
   comptes, réglages. Prévenez les utilisateurs et faites-leur ressaisir leurs changements.
4. Revenez aussi aux clients 1.0.0 si vous aviez déjà déployé l'extension ou le client Windows
   1.1.0.

### Repères mesurés

Essais de la 1.1.0 du 19/11 (recettes `ops-tests/`, détail dans
[ops-tests/README.md](../ops-tests/README.md#résultats-après-intégration-1911)), sur un poste partagé : les
durées sont des **ordres de grandeur**, à confirmer sur votre matériel.

| Opération | Jeu d'essai | Mesure |
|---|---|---|
| `locksy-server backup --with-key` à chaud | 95 éléments (base de 4,6 Mio) | 0,1 s |
| `locksy-server backup --with-key` à chaud, pendant des écritures | 500 000 éléments et 2 000 pièces jointes (base de 1,5 Gio) | 63 s pour 1 514,9 Mio, mémoire du conteneur au plus 396 Mio sur 512 |
| Restauration complète (RTO), du volume vide au service vérifié | même jeu de 1,5 Gio | 192 s (3 min 12 s) |
| Restauration complète (RTO) | 95 éléments | 10 à 12 s |
| Indisponibilité de la mise à jour 1.0.0 → 1.1.0 (arrêt, copie, migration, démarrage) | 95 éléments | 6 à 9 s |

Constats :

- **Mémoire pendant la sauvegarde d'une grosse base** : l'image 1.1.0 limite les zones
  d'allocation mémoire (`MALLOC_ARENA_MAX=2`) et écrit les fichiers temporaires de SQLite sur
  le volume de données (`SQLITE_TMPDIR=/data`). Avec 512 Mo pour le conteneur et le jeu de
  1,5 Gio sous écritures, la sauvegarde va à son terme (au plus 396 Mio).
- **Lenteur pendant la sauvegarde d'une grosse base** : la copie de 1,5 Gio occupe le disque ;
  pendant cette minute, le temps de réponse des écritures passait de 20 ms à environ 2 s
  (aucune erreur, aucune perte). Lancez la sauvegarde d'une grosse base hors des heures de
  pointe (le minuteur de `install.sh` la place la nuit).
- **1.0.0 démarrée sur une base migrée en 1.1.0** : elle démarre, répond en bonne santé, ne
  journalise aucune erreur et **modifie le fichier** (empreinte différente, version du schéma
  inchangée). Restaurez toujours la sauvegarde `pre-upgrade-…` avant de relancer la 1.0.0.
- **Base plus récente que le binaire** (retour arrière d'une version 1.2 vers la 1.1.0, par
  exemple) : la 1.1.0 refuse de démarrer (« plus récent »), sans rien écrire.

## Renouvellement du certificat

Remplacez `/etc/locksy/tls/locksy.crt` et `locksy.key` : Locksy recharge le certificat toutes
les 6 heures, ou immédiatement avec `systemctl restart locksy`. Alerte d'expiration :
[Exploitation](Exploitation.md#expiration-du-certificat).

## Surveillance

Sondes `/api/health` et `/api/ready`, journaux, alertes (dont l'âge de la dernière
sauvegarde) : [Exploitation](Exploitation.md).
