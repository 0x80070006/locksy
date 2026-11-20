# Plan de reprise et de continuité (PRA/PCA)

Ce document fixe les objectifs de reprise de Locksy et la conduite à tenir pour chaque
scénario de sinistre. Il complète le runbook [Exploitation](Exploitation.md) et la procédure
[Sauvegarde et mises à jour](Sauvegarde-et-mises-a-jour.md). Adaptez les rôles et les
contacts à votre organisation, puis faites valider le document par la direction.

## Limite d'architecture

Locksy fonctionne en **instance unique** : un serveur, une base SQLite. Il n'y a ni haute
disponibilité, ni réplication, ni bascule automatique. La continuité repose sur des
sauvegardes testées et une réinstallation rapide. Pour une exigence de disponibilité plus
forte, la piste prévue est PostgreSQL avec un limiteur partagé (décision après la version 1.1).

Pendant une indisponibilité, les utilisateurs n'ont **pas** d'accès hors ligne à leurs
secrets : ni le web, ni l'extension, ni le client Windows ne gardent de copie locale du coffre.
Prévoyez, pour les secrets vitaux (comptes d'administration du système d'information, accès
de secours), un export chiffré conservé dans un coffre physique (voir la checklist).

## Objectifs

| Objectif | Valeur | Comment |
|---|---|---|
| **RPO** (perte de données maximale) | **24 h** | sauvegarde quotidienne par `locksy-backup.timer` (02:30, décalage aléatoire de 30 min au plus) |
| **RTO** (durée d'interruption maximale) | **moins d'1 h** | réinstallation par `install.sh` sur une VM saine, puis restauration de la dernière sauvegarde |

Pour abaisser le RPO, ajoutez des passages au timer (exemple : toutes les 4 h) :

```bash
sudo systemctl edit locksy-backup.timer
# [Timer]
# OnCalendar=
# OnCalendar=*-*-* 00/4:30:00
sudo systemctl daemon-reload && sudo systemctl restart locksy-backup.timer
```

Le nombre de sauvegardes conservées (`LOCKSY_BACKUP_KEEP`, 14 par défaut) doit alors être
augmenté pour garder le même historique en jours.

## Rôles

| Rôle | Responsabilité |
|---|---|
| Responsable du service | déclenche le PRA, arbitre (restauration avec perte de données, communication) |
| Exploitant système | réinstallation, restauration, vérifications techniques |
| Détenteur de la clé de sauvegarde | déchiffre les sauvegardes (clé privée age ou gpg, hors site) |
| Propriétaires Locksy (au moins 2) | accès de secours par mot de passe maître, contrôle après reprise |
| RSSI | qualification d'un incident de sécurité, décision de rotation des clés |

Chaque rôle a un suppléant. La clé privée de déchiffrement des sauvegardes et la clé serveur
ne sont jamais détenues par la même personne seule.

## Scénarios

### Perte du disque ou de la VM

1. Nouvelle VM (mêmes prérequis), même nom DNS, même certificat.
2. `install.sh` avec la **même version** que celle de la sauvegarde (`--version vX.Y.Z`),
   option `--no-start`.
3. Restauration de la dernière sauvegarde et de la clé serveur
   ([Restauration](Sauvegarde-et-mises-a-jour.md#restauration)), `locksy-server check`, puis
   démarrage.
4. Contrôle : `/api/ready`, connexion d'un propriétaire, ouverture d'un coffre partagé.

Données perdues : ce qui a été modifié depuis la dernière sauvegarde.

### Corruption de la base

Symptômes : erreurs 500, `check` en `ERREUR` sur `integrity_check`.

1. Arrêt du service ; copie de côté de la base corrompue (avec `-wal` et `-shm`) pour analyse.
2. `locksy-server check` pour confirmer.
3. Restauration de la dernière sauvegarde saine (le test de restauration de
   `backup-locksy.sh` garantit qu'elle passait `check` au moment de sa création).

### Perte de server.key

Les coffres sont **intacts** (la clé serveur ne protège aucun coffre). Sont perdus : les
secrets 2FA, le mot de passe du compte de liaison LDAP et le secret client SSO.

1. Cherchez d'abord la clé dans les sauvegardes (`*.db.server.key[.age|.gpg]`).
2. À défaut : démarrage avec `LOCKSY_SERVER_KEY_RESET=true`, puis reconfiguration
   ([Rotation de server.key](Exploitation.md#rotation-de-serverkey)).

### Compromission de l'hôte

Suivre [Compromission suspectée : serveur](Exploitation.md#serveur). Reprise sur une machine
neuve à partir d'une sauvegarde antérieure à l'intrusion, rotation de la clé serveur, du jeton
SCIM et des secrets de fédération.

### Rançongiciel

- Les sauvegardes doivent être **chiffrées** (`--age-recipient` ou `--gpg-recipient`) et
  **copiées hors ligne** ou sur un stockage immuable, hors de portée des comptes du serveur.
- La **clé privée** age ou gpg est conservée **hors site**, jamais sur le serveur Locksy.
- Reprise : VM neuve, installation vérifiée (signature), restauration de la dernière
  sauvegarde saine, rotation comme pour une compromission de l'hôte.

### Indisponibilité du fournisseur d'identité ou de l'Active Directory

- Le SSO et la connexion avec le compte Windows échouent (`ldap_unavailable`, refus du
  fournisseur). Les **propriétaires** gardent la connexion par mot de passe maître (et leur
  2FA), même quand le SSO est imposé : c'est l'accès de secours.
- Si l'indisponibilité dure, un propriétaire peut désactiver temporairement « Imposer le
  SSO » ou la connexion Windows obligatoire, pour que les utilisateurs se connectent par mot de
  passe maître. À réactiver ensuite.
- La synchronisation AD ne désactive personne si l'annuaire ne renvoie aucun compte.

### Erreur de mise à jour

1. `sudo bash install.sh --rollback` : binaire et interface précédents.
2. Si l'ancien binaire refuse la base (schéma plus récent), accepter la restauration de la
   sauvegarde d'avant mise à jour (`pre-upgrade-…db`). Les modifications faites depuis la mise à
   jour sont perdues.
3. Signaler l'anomalie (avec `X-Request-Id` et journaux) avant de retenter.

### Expiration du certificat

Remplacez les fichiers du certificat : rechargement automatique sous 6 h, ou immédiat par
redémarrage. Prévention : vérification quotidienne `openssl … -checkend`
([Exploitation](Exploitation.md#expiration-du-certificat)).

## Tests

- **À chaque sauvegarde** : `backup-locksy.sh` restaure automatiquement la copie dans un
  dossier temporaire et exécute `locksy-server check` ; un échec rend la sauvegarde en erreur
  (code 1, visible dans `systemctl status locksy-backup.service`).
- **Chaque trimestre** : restauration complète sur une VM de test isolée, à partir d'une
  sauvegarde chiffrée hors site (déchiffrement compris), connexion d'un propriétaire et
  ouverture d'un coffre partagé. Chronométrez : le RTO mesuré doit rester sous 1 h.
- **Chaque année** : exercice sur table du scénario de compromission de l'hôte (rotation de la
  clé serveur, réinitialisation de la 2FA).

Consignez date, durée, sauvegarde utilisée, écarts et actions correctives.

## Checklist

- [ ] Timer de sauvegarde actif (`systemctl list-timers locksy-backup.timer`).
- [ ] Sauvegardes chiffrées (destinataire age ou gpg renseigné dans `/etc/locksy/backup.env`).
- [ ] Copie quotidienne hors du serveur, dont une copie hors ligne ou immuable.
- [ ] Clé privée de déchiffrement hors site, et son détenteur suppléé.
- [ ] Clé serveur sauvegardée **séparément** de la base.
- [ ] Au moins deux propriétaires actifs, avec 2FA, connaissant la procédure de secours.
- [ ] Version installée notée (`locksy-server version`) et archive correspondante disponible
      hors ligne avec `SHA256SUMS` et ses signatures.
- [ ] Certificat et clé TLS sauvegardés ; alerte d'expiration en place.
- [ ] Supervision de `/api/ready` et de l'âge de la dernière sauvegarde.
- [ ] Dernier test trimestriel de restauration réussi et consigné.
- [ ] Export chiffré des secrets vitaux conservé hors ligne, renouvelé à chaque changement.
