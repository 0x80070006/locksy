# Réglages de l'organisation

<!-- Fichier généré par « node tools/gen-settings-doc.mjs » depuis crates/locksy-core/src/settings.rs
     et design/i18n/fr.gen.json : ne le modifiez pas à la main. -->

Cette page décrit les 109 réglages que les propriétaires et les administrateurs
modifient dans **Administration > Réglages** (`#/admin/reglages/<section>`). Elle est générée depuis
le registre unique du serveur : chaque réglage y a sa ligne, avec ses bornes et sa valeur par
défaut. Le parcours de l'écran est décrit dans le [guide administrateur](Administration.md#réglages).

## Qui décide de la valeur

| Niveau | Qui | Où |
|---|---|---|
| Constantes | personne | le code : formats chiffrés, planchers de dérivation, règle du dernier propriétaire |
| Hébergeur | l'exploitant du serveur | variables `LOCKSY_*`, dont `LOCKSY_SETTINGS_FILE` ([Exploitation](Exploitation.md#variables-denvironnement)) |
| Organisation | propriétaires et administrateurs | Administration > Réglages (cette page) |
| Poste de travail | le service informatique | GPO, Intune, stratégies du navigateur ([Extension navigateur](Extension-navigateur.md)) |
| Personne | chaque utilisateur | Paramètres > Préférences, chiffrées et synchronisées entre ses appareils |

Sur le serveur, la valeur appliquée est, dans l'ordre : la valeur fixée par l'hébergeur, sinon
celle de l'organisation, sinon la valeur par défaut du tableau ; elle reste toujours dans les
bornes du tableau et sous le plafond éventuel de l'hébergeur. Le serveur reste la barrière : un
réglage qu'il peut vérifier y est appliqué, même si un poste l'ignore.

## Réglages diffusés aux postes et modes

Les réglages marqués « Diffusé aux postes » sont envoyés à l'interface web et à l'extension après
la connexion. Ceux qui ont des **modes** se règlent en deux temps : la valeur, puis la liberté
laissée aux utilisateurs (« Pour les utilisateurs ») :

- **Libres** : chaque personne choisit dans les bornes du tableau ;
- **Par défaut** : la valeur est proposée ; chacun peut la changer, sans dépasser la limite
  choisie par l'administrateur (« Ils peuvent choisir au plus ») ;
- **Imposé** : la valeur s'applique à tous, sans choix possible.

Sur un poste, une valeur imposée par le service informatique (GPO, Intune) l'emporte quand elle
est plus stricte. Le client Windows 1.1 ne lit pas encore ces réglages : il garde sa politique
locale ([Client Windows](Client-Windows.md#politique-dentreprise)) ; sa refonte arrive en 1.2.

## Réglages fixés par l'hébergeur

`LOCKSY_SETTINGS_FILE` désigne un fichier JSON qui fixe des réglages pour toute l'instance. Chaque
clé du fichier est verrouillée : elle s'affiche avec la mention « Fixé par l'hébergeur » et ne se
modifie plus dans l'interface. Le fichier est vérifié au démarrage contre ce registre : une clé
inconnue, une valeur hors bornes ou un secret (le mot de passe du serveur d'envoi, qui se
saisit dans l'interface) arrêtent le serveur avec un message clair.

```json
{
  "twofa.required": true,
  "session.idle_minutes": 30,
  "client.autolock_minutes": { "value": 5, "mode": "enforced" }
}
```

Pour un réglage à modes, la forme objet précise aussi `mode` (`free`, `default` ou `enforced`),
`min` et `max`. De même, `LOCKSY_SYSLOG` fixe l'adresse du transfert vers l'outil de
supervision. La colonne « Plafond de l'hébergeur » nomme la variable qui borne un réglage par
le haut.

## Lire les tableaux

- **Valeurs admises** et **Défaut** : bornes et valeur d'une organisation neuve.
- **Modes** : réglages dont la liberté laissée aux utilisateurs se choisit (voir plus haut).
- **Diffusé aux postes** : « oui » pour la politique envoyée après connexion, « page de connexion »
  pour les textes et règles affichés avant la connexion, « non » pour un réglage du serveur seul.
- **Propriétaire seulement** : un administrateur voit le réglage mais ne peut pas le modifier.
- **Sens le plus sûr** : changer un réglage dans l'autre sens **abaisse la sécurité**. L'écran le
  signale, demande le mot de passe maître, inscrit l'événement au journal et prévient les
  propriétaires par e-mail quand la notification correspondante est active (section E-mails).
- Les réglages marqués « avancé » sont repliés sous « Réglages avancés » dans leur section.

## Sections

- [Sécurité de connexion](#sécurité-de-connexion) : 12 réglages, `#/admin/reglages/login`
- [Sessions et verrouillage](#sessions-et-verrouillage) : 9 réglages, `#/admin/reglages/sessions`
- [Mots de passe](#mots-de-passe) : 14 réglages, `#/admin/reglages/passwords`
- [Partage et coffres](#partage-et-coffres) : 17 réglages, `#/admin/reglages/sharing`
- [Applications et extension](#applications-et-extension) : 7 réglages, `#/admin/reglages/clients`
- [Conservation des données](#conservation-des-données) : 9 réglages, `#/admin/reglages/retention`
- [Apparence et textes](#apparence-et-textes) : 15 réglages, `#/admin/reglages/branding`
- [E-mails](#e-mails) : 13 réglages, `#/admin/reglages/mail`
- [Avancé](#avancé) : 11 réglages, `#/admin/reglages/advanced`
- [Connexion d'entreprise](#connexion-dentreprise) : 2 réglages, `#/admin/reglages/identity`

## Sécurité de connexion

| Réglage | Clé | Valeurs admises | Défaut | Modes | Diffusé aux postes | Propriétaire seulement | Plafond de l'hébergeur (variable) | Sens le plus sûr |
|---|---|---|---|---|---|---|---|---|
| Double authentification obligatoire pour tous | `twofa.required` | oui ou non | non | — | non | oui | — | activé |
| Double authentification obligatoire pour certains rôles | `twofa.required_roles` | liste de rôles parmi `owner`, `admin`, `user` | (aucun) | — | non | oui | — | plus d'entrées |
| Délai pour activer la double authentification | `twofa.grace_days` | 0 à 30 jours | 7 jours | — | non | non | — | plus bas |
| Méthode de connexion proposée en premier | `auth.primary_method` | « Mot de passe maître » (`password`), « Compte Windows (Active Directory) » (`ldap`), « Connexion d'entreprise (SSO) » (`sso`) | « Mot de passe maître » (`password`) | — | page de connexion | non | — | — |
| Domaines e-mail autorisés | `access.allowed_email_domains` | liste de domaines | (aucun) | — | non | non | — | plus d'entrées |
| Réseaux autorisés (avancé) | `access.ip_allowlist` | liste d'adresses ou de réseaux IP (ex. 192.168.0.0/24) | (aucun) | — | non | oui | — | plus d'entrées |
| Adresses de secours des propriétaires (avancé) | `access.ip_rescue` | liste d'adresses ou de réseaux IP (ex. 192.168.0.0/24) | (aucun) | — | non | oui | — | moins d'entrées |
| Appareils connectés par personne (avancé) | `session.max_per_user` | 0 à 100 ; 0 = sans limite | 0 (sans limite) | — | non | non | — | plus bas (0, sans limite, est le moins sûr) |
| Échecs avant blocage d'une adresse (avancé) | `lockout.pair_threshold` | 3 à 20 | 5 | — | non | oui | — | plus bas |
| Échecs avant blocage d'un compte (avancé) | `lockout.account_threshold` | 10 à 1 000 | 50 | — | non | oui | — | plus bas |
| Durée du premier blocage (avancé) | `lockout.base_delay_seconds` | 5 à 600 s | 30 s | — | non | non | — | plus haut |
| Durée maximale d'un blocage (avancé) | `lockout.max_delay_seconds` | 60 à 86 400 s | 3 600 s (1 heure) | — | non | non | — | plus haut |

En détail :

- **Double authentification obligatoire pour tous** : Chaque personne doit activer un code à usage unique pour se connecter. Après le délai de grâce, un compte sans double authentification n'accède plus qu'à son profil.
- **Double authentification obligatoire pour certains rôles** : Impose la double authentification seulement aux rôles cochés, par exemple aux administrateurs.
- **Délai pour activer la double authentification** : Temps laissé à chacun pour activer sa double authentification une fois la règle en place. À 0, l'accès est bloqué tout de suite. Valeurs proposées : 0 jour, 1 jour, 3 jours, 7 jours, 14 jours, 30 jours.
- **Méthode de connexion proposée en premier** : Méthode mise en avant sur la page de connexion. Les autres méthodes activées restent proposées en dessous.
- **Domaines e-mail autorisés** : Seules les adresses de ces domaines peuvent être invitées ou créer un compte. Vide : tous les domaines sont acceptés.
- **Réseaux autorisés** : Locksy ne répond qu'aux adresses IP de ces réseaux (exemple : 192.168.0.0/16). Vide : aucune restriction. Votre adresse actuelle doit en faire partie.
- **Adresses de secours des propriétaires** : Adresses depuis lesquelles un propriétaire peut toujours se connecter, même hors des réseaux autorisés. Utile pour ne jamais se bloquer dehors.
- **Appareils connectés par personne** : Nombre maximal de sessions ouvertes en même temps par une personne. À 0, aucune limite.
- **Échecs avant blocage d'une adresse** : Nombre de mots de passe faux, pour un même compte et une même adresse, avant de bloquer temporairement les tentatives.
- **Échecs avant blocage d'un compte** : Nombre de mots de passe faux sur un compte, toutes adresses confondues, avant de le bloquer temporairement.
- **Durée du premier blocage** : Temps d'attente imposé après le premier blocage. Il double à chaque nouveau blocage. Valeurs proposées : 5 s, 15 s, 30 s, 60 s (1 minute), 120 s (2 minutes), 300 s (5 minutes), 600 s (10 minutes).
- **Durée maximale d'un blocage** : Temps d'attente le plus long imposé après des échecs répétés. Valeurs proposées : 60 s (1 minute), 300 s (5 minutes), 900 s (15 minutes), 3 600 s (1 heure), 21 600 s (6 heures), 86 400 s (1 jour).

## Sessions et verrouillage

| Réglage | Clé | Valeurs admises | Défaut | Modes | Diffusé aux postes | Propriétaire seulement | Plafond de l'hébergeur (variable) | Sens le plus sûr |
|---|---|---|---|---|---|---|---|---|
| Déconnexion après inactivité | `session.idle_minutes` | 5 à 1 440 min | 60 min (1 heure) | — | non | non | — | plus bas |
| Durée maximale d'une session | `session.max_hours` | 1 à 720 h | 12 h | — | non | non | — | plus bas |
| Verrouillage automatique des applications | `client.autolock_minutes` | 1 à 1 440 min | 10 min | Libres, Par défaut, Imposé ; mode initial : Par défaut | oui | non | — | plus bas |
| Autoriser « Jamais » pour le verrouillage | `client.autolock_allow_never` | oui ou non | oui | — | oui | non | — | désactivé |
| Verrouiller quand l'onglet est caché | `client.lock_on_hide` | oui ou non | non | Libres, Par défaut, Imposé ; mode initial : Par défaut | oui | non | — | activé |
| Verrouiller avec la session Windows | `client.lock_on_os_lock` | oui ou non | oui | Libres, Par défaut, Imposé ; mode initial : Par défaut | oui | non | — | activé |
| Effacement du presse-papiers | `client.clipboard_clear_seconds` | 5 à 600 s | 30 s | Libres, Par défaut, Imposé ; mode initial : Par défaut ; choix des utilisateurs limité à 120 s (2 minutes) au plus | oui | non | — | plus bas |
| Mémoriser l'adresse e-mail | `client.remember_email` | oui ou non | oui | — | oui | non | — | désactivé |
| Raccourcis à une seule touche | `client.single_key_shortcuts` | oui ou non | oui | Libres, Par défaut, Imposé ; mode initial : Par défaut | oui | non | — | — |

En détail :

- **Déconnexion après inactivité** : Une session sans aucune activité pendant cette durée est fermée par le serveur. Il faut alors se reconnecter. Valeurs proposées : 5 min, 10 min, 15 min, 30 min, 60 min (1 heure), 120 min (2 heures), 240 min (4 heures), 480 min (8 heures), 1 440 min (1 jour).
- **Durée maximale d'une session** : Au-delà de cette durée, il faut se reconnecter, même en cas d'activité. Les sessions déjà ouvertes gardent leur durée. Valeurs proposées : 1 h, 4 h, 8 h, 12 h, 24 h (1 jour), 72 h (3 jours), 168 h (7 jours), 720 h (30 jours).
- **Verrouillage automatique des applications** : Délai d'inactivité avant de verrouiller Locksy sur les postes et dans le navigateur. Le mot de passe maître est alors redemandé. Valeurs proposées : 1 min, 5 min, 10 min, 15 min, 30 min, 60 min (1 heure), 240 min (4 heures).
- **Autoriser « Jamais » pour le verrouillage** : Permet aux utilisateurs de désactiver le verrouillage automatique. Désactivé, un délai est toujours appliqué.
- **Verrouiller quand l'onglet est caché** : Verrouille Locksy dès que l'onglet du navigateur passe en arrière-plan.
- **Verrouiller avec la session Windows** : Verrouille l'application de bureau dès que la session Windows est verrouillée ou mise en veille.
- **Effacement du presse-papiers** : Durée après laquelle un mot de passe copié est effacé du presse-papiers. Valeurs proposées : 10 s, 20 s, 30 s, 60 s (1 minute), 120 s (2 minutes), 300 s (5 minutes).
- **Mémoriser l'adresse e-mail** : Propose l'adresse e-mail de la dernière connexion sur l'appareil. Le mot de passe n'est jamais mémorisé.
- **Raccourcis à une seule touche** : Active les raccourcis clavier d'une seule touche (par exemple « / » pour chercher). Les raccourcis avec Ctrl restent toujours actifs.

## Mots de passe

| Réglage | Clé | Valeurs admises | Défaut | Modes | Diffusé aux postes | Propriétaire seulement | Plafond de l'hébergeur (variable) | Sens le plus sûr |
|---|---|---|---|---|---|---|---|---|
| Longueur minimale du mot de passe maître | `master_password.min_length` | 10 à 64 caractères | 12 caractères | — | page de connexion | non | — | plus haut |
| Robustesse minimale du mot de passe maître | `master_password.min_score` | 2 à 4 | 3 | — | page de connexion | non | — | plus haut |
| Interdire le nom et l'e-mail dans le mot de passe maître | `master_password.forbid_identity` | oui ou non | oui | — | page de connexion | non | — | activé |
| Mots interdits dans le mot de passe maître (avancé) | `master_password.banned_words` | liste de mots, 500 au plus | (aucun) | — | page de connexion | non | — | plus d'entrées |
| Longueur des mots de passe générés | `generator.length` | 8 à 128 caractères | 20 caractères | Libres, Par défaut, Imposé ; mode initial : Par défaut | oui | non | — | plus haut |
| Longueur minimale du générateur | `generator.min_length` | 8 à 64 caractères | 12 caractères | — | oui | non | — | plus haut |
| Types de caractères exigés | `generator.require_classes` | 1 à 4 | 3 | — | oui | non | — | plus haut |
| Éviter les caractères ambigus | `generator.avoid_ambiguous` | oui ou non | oui | Libres, Par défaut, Imposé ; mode initial : Par défaut | oui | non | — | — |
| Symboles utilisés par le générateur (avancé) | `generator.symbols` | texte, 40 caractères au plus | `!@#$%^&*()-_=+[]{};:,.?/~` | — | oui | non | — | — |
| Nombre de mots d'une phrase de passe | `generator.words` | 3 à 12 mots | 5 mots | — | oui | non | — | plus haut |
| Nombre minimal de mots d'une phrase de passe | `generator.min_words` | 3 à 12 mots | 4 mots | — | oui | non | — | plus haut |
| Mots de passe uniques dans l'organisation | `passwords.unique_across_users` | oui ou non | non | — | oui | non | — | activé |
| Seuil d'un mot de passe faible | `health.weak_below_score` | 1 à 4 | 3 | — | oui | non | — | plus haut |
| Âge maximal conseillé d'un mot de passe | `health.max_password_age_days` | 30 à 1 825 jours | 365 jours (1 an) | — | oui | non | — | plus bas |

En détail :

- **Longueur minimale du mot de passe maître** : Nombre minimal de caractères exigé à la création ou au changement du mot de passe maître.
- **Robustesse minimale du mot de passe maître** : Niveau de robustesse exigé, de 2 (moyen) à 4 (très fort). Un mot de passe plus faible est refusé.
- **Interdire le nom et l'e-mail dans le mot de passe maître** : Refuse un mot de passe maître qui contient le nom ou l'adresse e-mail de la personne.
- **Mots interdits dans le mot de passe maître** : Mots refusés dans le mot de passe maître, par exemple le nom de l'entreprise ou de la ville. 500 mots au plus.
- **Longueur des mots de passe générés** : Nombre de caractères proposé par le générateur.
- **Longueur minimale du générateur** : Le générateur ne propose jamais moins de caractères que cette valeur.
- **Types de caractères exigés** : Nombre de types de caractères (minuscules, majuscules, chiffres, symboles) présents dans un mot de passe généré.
- **Éviter les caractères ambigus** : Le générateur n'utilise pas les caractères faciles à confondre, comme O et 0 ou l et 1.
- **Symboles utilisés par le générateur** : Liste des symboles que le générateur peut placer dans un mot de passe. Utile si une application en refuse certains.
- **Nombre de mots d'une phrase de passe** : Nombre de mots proposé pour une phrase de passe générée.
- **Nombre minimal de mots d'une phrase de passe** : Une phrase de passe générée ne compte jamais moins de mots.
- **Mots de passe uniques dans l'organisation** : Refuse un mot de passe déjà utilisé par un autre compte de l'organisation. Le serveur compare des empreintes, jamais les mots de passe ; il peut en revanche savoir que deux comptes partagent le même, et ne peut donc pas garantir l'ignorance totale du serveur. À réserver aux organisations qui acceptent ce compromis.
- **Seuil d'un mot de passe faible** : Dans le bilan de sécurité, un mot de passe sous ce niveau de robustesse est signalé comme faible.
- **Âge maximal conseillé d'un mot de passe** : Dans le bilan de sécurité, un mot de passe plus ancien est signalé comme à renouveler. Valeurs proposées : 30 jours, 90 jours, 180 jours, 365 jours (1 an), 730 jours (2 ans), 1 825 jours (5 ans).

## Partage et coffres

| Réglage | Clé | Valeurs admises | Défaut | Modes | Diffusé aux postes | Propriétaire seulement | Plafond de l'hébergeur (variable) | Sens le plus sûr |
|---|---|---|---|---|---|---|---|---|
| Autoriser les liens sécurisés | `share.enabled` | oui ou non | oui | — | oui | non | — | — |
| Durée maximale d'un lien sécurisé | `share.max_expiry_minutes` | 5 à 43 200 min | 43 200 min (30 jours) | — | oui | non | — | plus bas |
| Durée proposée pour un lien sécurisé | `share.default_expiry_minutes` | 5 à 43 200 min | 1 440 min (1 jour) | Libres, Par défaut, Imposé ; mode initial : Par défaut | oui | non | — | plus bas |
| Consultations maximales d'un lien | `share.max_views` | 1 à 100 | 100 | — | oui | non | — | plus bas |
| Consultations proposées pour un lien | `share.default_views` | 1 à 100 | 1 | Libres, Par défaut, Imposé ; mode initial : Par défaut | oui | non | — | plus bas |
| Liens créés par heure et par personne (avancé) | `share.max_per_hour` | 1 à 1 000 | 60 | — | non | non | — | plus bas |
| Les utilisateurs peuvent créer des coffres partagés | `vault.users_can_create_shared` | oui ou non | oui | — | oui | non | — | — |
| Changer la clé d'un coffre au départ d'un membre | `vault.rotate_on_member_removal` | « Ne rien faire » (`off`), « Le proposer » (`suggest`), « L'exiger » (`force`) | « Le proposer » (`suggest`) | — | oui | non | — | vers « L'exiger » (`force`) |
| Coffres personnels | `vault.personal_enabled` | oui ou non | oui | — | oui | oui | — | — |
| Autoriser les pièces jointes | `attachment.enabled` | oui ou non | oui | — | oui | non | — | — |
| Taille maximale d'une pièce jointe | `attachment.max_file_mib` | 1 à 15 Mio | 10 Mio | — | oui | non | `LOCKSY_MAX_ATTACHMENT_MIB` | — |
| Pièces jointes par élément | `attachment.max_per_item` | 1 à 100 | 20 | — | oui | non | — | — |
| Espace de pièces jointes par personne | `attachment.quota_user_mib` | 1 à 102 400 Mio | 1 024 Mio | — | non | non | — | — |
| Espace total des pièces jointes | `attachment.quota_total_mib` | 1 à 1 048 576 Mio | 20 480 Mio | — | non | non | — | — |
| Autoriser l'export des coffres | `export.enabled` | oui ou non | oui | — | oui | non | — | — |
| Longueur minimale du mot de passe d'export | `export.min_password_length` | 12 à 64 caractères | 12 caractères | — | oui | non | — | plus haut |
| Taille maximale d'un fichier importé | `import.max_file_mib` | 1 à 200 Mio | 20 Mio | — | oui | non | — | — |

En détail :

- **Autoriser les liens sécurisés** : Permet d'envoyer un élément à une personne extérieure par un lien à usage limité.
- **Durée maximale d'un lien sécurisé** : Un lien sécurisé ne peut pas rester valable plus longtemps. Valeurs proposées : 5 min, 15 min, 60 min (1 heure), 240 min (4 heures), 1 440 min (1 jour), 4 320 min (3 jours), 10 080 min (7 jours), 43 200 min (30 jours).
- **Durée proposée pour un lien sécurisé** : Durée de validité proposée à la création d'un lien. Valeurs proposées : 5 min, 15 min, 60 min (1 heure), 240 min (4 heures), 1 440 min (1 jour), 4 320 min (3 jours), 10 080 min (7 jours), 43 200 min (30 jours).
- **Consultations maximales d'un lien** : Nombre maximal d'ouvertures permises pour un lien sécurisé.
- **Consultations proposées pour un lien** : Nombre d'ouvertures proposé à la création d'un lien.
- **Liens créés par heure et par personne** : Limite le nombre de liens sécurisés qu'une personne peut créer en une heure.
- **Les utilisateurs peuvent créer des coffres partagés** : Désactivé, seuls les administrateurs créent des coffres partagés.
- **Changer la clé d'un coffre au départ d'un membre** : Que faire quand une personne quitte un coffre partagé : rien, proposer de changer la clé du coffre, ou l'exiger.
- **Coffres personnels** : Chaque personne dispose d'un coffre privé. Désactivé, les coffres personnels existants sont masqués mais conservés.
- **Autoriser les pièces jointes** : Permet d'ajouter des fichiers chiffrés aux éléments.
- **Taille maximale d'une pièce jointe** : Taille maximale d'un fichier joint. L'hébergeur peut fixer un plafond plus bas.
- **Pièces jointes par élément** : Nombre maximal de fichiers joints à un même élément.
- **Espace de pièces jointes par personne** : Espace maximal occupé par les fichiers qu'une personne a ajoutés.
- **Espace total des pièces jointes** : Espace maximal occupé par tous les fichiers joints de l'organisation.
- **Autoriser l'export des coffres** : Permet à chacun d'exporter les éléments auxquels il a accès dans un fichier protégé par mot de passe.
- **Longueur minimale du mot de passe d'export** : Nombre minimal de caractères du mot de passe qui protège un fichier d'export.
- **Taille maximale d'un fichier importé** : Taille maximale d'un fichier d'import venant d'un autre gestionnaire de mots de passe.

## Applications et extension

| Réglage | Clé | Valeurs admises | Défaut | Modes | Diffusé aux postes | Propriétaire seulement | Plafond de l'hébergeur (variable) | Sens le plus sûr |
|---|---|---|---|---|---|---|---|---|
| Remplissage sur un site non sécurisé | `extension.http_fill` | « Avertir » (`warn`), « Refuser » (`block`) | « Refuser » (`block`) | — | oui | non | — | vers « Refuser » (`block`) |
| Remplir sur un site différent de l'élément | `extension.allow_mismatch_fill` | oui ou non | non | — | oui | non | — | désactivé |
| Proposer d'enregistrer les identifiants | `extension.offer_save` | oui ou non | oui | Libres, Par défaut, Imposé ; mode initial : Par défaut | oui | non | — | — |
| Remplir automatiquement à l'ouverture | `extension.autofill` | oui ou non | non | Libres, Par défaut, Imposé ; mode initial : Par défaut | oui | non | — | — |
| Copier le code à usage unique après remplissage | `extension.copy_totp_after_fill` | oui ou non | oui | Libres, Par défaut, Imposé ; mode initial : Par défaut | oui | non | — | — |
| Sites où l'extension ne propose rien | `extension.excluded_sites` | liste de domaines | (aucun) | — | oui | non | — | — |
| Extensions autorisées | `extension.allowed_ids` | liste de mots, 50 au plus | (aucun) | — | non | non | — | moins d'entrées |

En détail :

- **Remplissage sur un site non sécurisé** : Que fait l'extension sur une page en HTTP (non chiffrée) : avertir avant de remplir, ou refuser.
- **Remplir sur un site différent de l'élément** : Permet de remplir un identifiant sur un site qui ne correspond pas à l'adresse enregistrée dans l'élément.
- **Proposer d'enregistrer les identifiants** : L'extension propose d'enregistrer un identifiant saisi sur un site.
- **Remplir automatiquement à l'ouverture** : Quand un seul compte correspond au site ouvert, l'extension le remplit dès l'ouverture de sa fenêtre, sans cliquer sur « Remplir ». Aucun remplissage sur un site exclu ou sur une page non chiffrée interdite.
- **Copier le code à usage unique après remplissage** : Après avoir rempli un identifiant, l'extension copie le code à usage unique de l'élément.
- **Sites où l'extension ne propose rien** : Domaines sur lesquels l'extension ne propose ni de remplir ni d'enregistrer.
- **Extensions autorisées** : Laissez vide : toute extension Locksy est acceptée, sans identifiant à déclarer. Renseignez des identifiants (32 lettres, visibles dans chrome://extensions) pour restreindre l'accès à ces extensions seulement ; la connexion d'entreprise (SSO) n'accepte toujours que les identifiants listés.

## Conservation des données

| Réglage | Clé | Valeurs admises | Défaut | Modes | Diffusé aux postes | Propriétaire seulement | Plafond de l'hébergeur (variable) | Sens le plus sûr |
|---|---|---|---|---|---|---|---|---|
| Conservation de la corbeille | `retention.trash_days` | 1 à 365 jours | 30 jours | — | oui | non | — | — |
| Conservation du journal | `retention.audit_days` | 30 à 3 650 jours | 365 jours (1 an) | — | non | oui | — | plus haut |
| Conservation des invitations expirées | `retention.expired_invites_days` | 1 à 365 jours | 30 jours | — | non | non | — | — |
| Validité d'une invitation | `invite.ttl_days` | 1 à 30 jours | 7 jours | — | non | non | — | plus bas |
| Signaler les comptes inactifs après | `users.inactive_alert_days` | 30 à 730 jours | 90 jours | — | non | non | — | — |
| Désactiver les comptes inactifs après | `users.disable_after_inactive_days` | 0 à 730 jours ; 0 = sans limite | 0 (sans limite) | — | non | non | — | plus bas (0, sans limite, est le moins sûr) |
| Départ d'une personne de l'annuaire | `directory.deprovision` | « Désactiver » (`disable`), « Désactiver, puis supprimer » (`disable_then_delete`) | « Désactiver, puis supprimer » (`disable_then_delete`) | — | non | non | — | — |
| Suppression après le départ | `directory.delete_after_days` | 0 à 365 jours | 30 jours | — | non | non | — | — |
| Garde-fou de l'annuaire (avancé) | `directory.max_deprovision_percent` | 1 à 100 % | 20 % | — | non | non | — | plus bas |

En détail :

- **Conservation de la corbeille** : Durée pendant laquelle un élément supprimé peut être restauré. Ensuite, il est effacé définitivement. Valeurs proposées : 7 jours, 14 jours, 30 jours, 60 jours, 90 jours, 180 jours, 365 jours (1 an).
- **Conservation du journal** : Durée de conservation des événements du journal. Au-delà, ils sont effacés. 180 jours au moins sont recommandés. Valeurs proposées : 30 jours, 90 jours, 180 jours, 365 jours (1 an), 730 jours (2 ans), 1 095 jours (3 ans), 1 825 jours (5 ans), 3 650 jours (10 ans).
- **Conservation des invitations expirées** : Durée pendant laquelle une invitation expirée reste visible avant d'être effacée. Valeurs proposées : 7 jours, 14 jours, 30 jours, 60 jours, 90 jours, 180 jours, 365 jours (1 an).
- **Validité d'une invitation** : Durée pendant laquelle un lien d'invitation permet de créer son compte. Valeurs proposées : 1 jour, 3 jours, 7 jours, 14 jours, 30 jours.
- **Signaler les comptes inactifs après** : Un compte sans connexion depuis cette durée est signalé sur l'accueil de l'administration. Valeurs proposées : 30 jours, 60 jours, 90 jours, 180 jours, 365 jours (1 an), 730 jours (2 ans).
- **Désactiver les comptes inactifs après** : Un compte sans connexion depuis cette durée est désactivé automatiquement. Les propriétaires ne le sont jamais. À 0, jamais. Valeurs proposées : sans limite, 30 jours, 60 jours, 90 jours, 180 jours, 365 jours (1 an), 730 jours (2 ans).
- **Départ d'une personne de l'annuaire** : Que faire d'un compte retiré de l'annuaire de l'entreprise : le désactiver, ou le désactiver puis le supprimer après un délai.
- **Suppression après le départ** : Délai entre la désactivation d'un compte retiré de l'annuaire et sa suppression. Valeurs proposées : 7 jours, 14 jours, 30 jours, 60 jours, 90 jours, 180 jours, 365 jours (1 an).
- **Garde-fou de l'annuaire** : Une synchronisation qui désactiverait plus de ce pourcentage de comptes est refusée, pour éviter une erreur de configuration.

## Apparence et textes

| Réglage | Clé | Valeurs admises | Défaut | Modes | Diffusé aux postes | Propriétaire seulement | Plafond de l'hébergeur (variable) | Sens le plus sûr |
|---|---|---|---|---|---|---|---|---|
| Nom de l'organisation | `branding.org_name` | texte, 60 caractères au plus | (vide) | — | page de connexion | non | — | — |
| Logo | `branding.logo` | image PNG ou WebP, 256 Kio au plus | Logo Locksy | — | page de connexion | non | — | — |
| Couleur de l'organisation | `branding.accent_color` | couleur #rrggbb, lisible sur fond clair et sombre | `#0d6b64` | — | page de connexion | non | — | — |
| Message de la page de connexion | `branding.login_message` | texte sur plusieurs lignes, 500 caractères au plus | (vide) | — | page de connexion | non | — | — |
| Contact du support | `branding.support_contact` | texte, 120 caractères au plus | (vide) | — | page de connexion | non | — | — |
| Nom affiché dans l'application d'authentification | `branding.totp_issuer` | texte, 40 caractères au plus | `Locksy` | — | non | non | — | — |
| Lien des mentions légales | `legal.notice_url` | adresse en https:// | (vide) | — | page de connexion | non | — | — |
| Lien de la politique de confidentialité | `legal.privacy_url` | adresse en https:// | (vide) | — | page de connexion | non | — | — |
| Lien de la déclaration d'accessibilité | `legal.accessibility_url` | adresse en https:// | (vide) | — | page de connexion | non | — | — |
| Avertissement avant connexion | `legal.login_banner` | texte sur plusieurs lignes, 1 000 caractères au plus | (vide) | — | page de connexion | non | — | — |
| Charte d'utilisation | `legal.charter_text` | texte sur plusieurs lignes, 20 000 caractères au plus | (vide) | — | oui | non | — | — |
| Version de la charte | `legal.charter_version` | 0 à 1 000 000 | 0 | — | page de connexion | non | — | — |
| Contact du délégué à la protection des données | `legal.dpo_contact` | texte, 120 caractères au plus | (vide) | — | page de connexion | non | — | — |
| Langue par défaut | `i18n.default_locale` | « Français » (`fr-FR`), « Anglais » (`en-GB`) | « Français » (`fr-FR`) | — | page de connexion | non | — | — |
| Fuseau horaire | `i18n.timezone` | texte, 64 caractères au plus | `Europe/Paris` | — | page de connexion | non | — | — |

En détail :

- **Nom de l'organisation** : Affiché sur la page de connexion, dans les applications et sur les liens sécurisés.
- **Logo** : Image PNG ou WebP de 256 Kio au plus, affichée sur la page de connexion et dans les applications.
- **Couleur de l'organisation** : Couleur des boutons et des liens. Elle doit rester lisible en thème clair comme en thème sombre.
- **Message de la page de connexion** : Court texte affiché sous le formulaire de connexion.
- **Contact du support** : Adresse e-mail, téléphone ou lien vers le support, affiché en cas de problème de connexion.
- **Nom affiché dans l'application d'authentification** : Nom sous lequel Locksy apparaît dans l'application de codes à usage unique. Sans deux-points.
- **Lien des mentions légales** : Adresse https des mentions légales, affichée en bas de la page de connexion.
- **Lien de la politique de confidentialité** : Adresse https de la politique de confidentialité.
- **Lien de la déclaration d'accessibilité** : Adresse https de la déclaration d'accessibilité.
- **Avertissement avant connexion** : Texte affiché avant la connexion, par exemple « Accès réservé au personnel ».
- **Charte d'utilisation** : Texte que chaque personne doit accepter. Changez sa version pour la faire accepter à nouveau.
- **Version de la charte** : À chaque nouvelle version, la charte est présentée de nouveau et doit être acceptée. À 0, aucune charte n'est demandée.
- **Contact du délégué à la protection des données** : Adresse ou téléphone du délégué à la protection des données, affiché dans les mentions.
- **Langue par défaut** : Langue de l'interface pour les personnes qui n'en ont pas choisi.
- **Fuseau horaire** : Fuseau utilisé pour les dates des exports et des e-mails, par exemple Europe/Paris.

## E-mails

| Réglage | Clé | Valeurs admises | Défaut | Modes | Diffusé aux postes | Propriétaire seulement | Plafond de l'hébergeur (variable) | Sens le plus sûr |
|---|---|---|---|---|---|---|---|---|
| Envoyer des e-mails | `mail.enabled` | oui ou non | non | — | non | non | — | — |
| Serveur d'envoi | `mail.smtp.host` | texte, 253 caractères au plus | (vide) | — | non | non | — | — |
| Port du serveur d'envoi | `mail.smtp.port` | 1 à 65 535 | 587 | — | non | non | — | — |
| Chiffrement de l'envoi | `mail.smtp.security` | « Sans chiffrement » (`none`), « STARTTLS » (`starttls`), « TLS » (`tls`) | « STARTTLS » (`starttls`) | — | non | non | — | vers « TLS » (`tls`) |
| Identifiant du serveur d'envoi | `mail.smtp.username` | texte, 254 caractères au plus | (vide) | — | non | non | — | — |
| Mot de passe du serveur d'envoi | `mail.smtp.password` | secret, chiffré par le serveur et jamais réaffiché | (non défini) | — | non | non | — | — |
| Adresse d'expédition | `mail.from` | adresse e-mail | (vide) | — | non | non | — | — |
| Adresse de réponse | `mail.reply_to` | adresse e-mail | (vide) | — | non | non | — | — |
| E-mail d'invitation | `mail.notify.invite` | oui ou non | oui | — | non | non | — | — |
| Alerte de connexion depuis un nouvel appareil | `mail.notify.new_device` | oui ou non | oui | — | non | non | — | activé |
| Alerte de changement de sécurité | `mail.notify.security_change` | oui ou non | oui | — | non | non | — | activé |
| Alerte de sécurité abaissée | `mail.notify.settings_lowered` | oui ou non | oui | — | non | non | — | activé |
| Résumé pour les administrateurs | `mail.notify.admin_digest` | « Jamais » (`off`), « Chaque jour » (`daily`), « Chaque semaine » (`weekly`) | « Chaque jour » (`daily`) | — | non | non | — | — |

En détail :

- **Envoyer des e-mails** : Active l'envoi des invitations et des alertes de sécurité par e-mail.
- **Serveur d'envoi** : Nom ou adresse du serveur SMTP de l'entreprise.
- **Port du serveur d'envoi** : Port du serveur SMTP, souvent 587 (STARTTLS) ou 465 (TLS).
- **Chiffrement de l'envoi** : Protection de la connexion au serveur d'envoi. Sans chiffrement n'est permis que sur un réseau interne.
- **Identifiant du serveur d'envoi** : Compte utilisé pour se connecter au serveur SMTP. Vide si le serveur n'en demande pas.
- **Mot de passe du serveur d'envoi** : Mot de passe du compte SMTP. Il est chiffré et ne s'affiche plus une fois enregistré.
- **Adresse d'expédition** : Adresse qui apparaît comme expéditeur des e-mails de Locksy.
- **Adresse de réponse** : Adresse qui reçoit les réponses aux e-mails de Locksy. Vide : l'adresse d'expédition.
- **E-mail d'invitation** : Envoie le lien d'invitation par e-mail. Sinon, l'administrateur le transmet lui-même.
- **Alerte de connexion depuis un nouvel appareil** : Prévient la personne quand son compte est utilisé depuis un appareil inconnu.
- **Alerte de changement de sécurité** : Prévient la personne quand son mot de passe maître ou sa double authentification change.
- **Alerte de sécurité abaissée** : Prévient les autres propriétaires quand un réglage de sécurité est abaissé.
- **Résumé pour les administrateurs** : Envoie aux administrateurs un résumé des points à traiter.

## Avancé

Changez ces valeurs seulement si vous savez pourquoi.

| Réglage | Clé | Valeurs admises | Défaut | Modes | Diffusé aux postes | Propriétaire seulement | Plafond de l'hébergeur (variable) | Sens le plus sûr |
|---|---|---|---|---|---|---|---|---|
| Adresse publique de Locksy | `instance.public_url` | adresse web | (vide) | — | non | oui | — | — |
| Mémoire de la dérivation du mot de passe | `kdf.memory_mib` | 19 à 1 024 Mio | 64 Mio | — | page de connexion | oui | — | plus haut |
| Passes de la dérivation du mot de passe | `kdf.iterations` | 2 à 10 | 3 | — | page de connexion | oui | — | plus haut |
| Parallélisme de la dérivation du mot de passe | `kdf.parallelism` | 1 à 8 | 1 | — | page de connexion | oui | — | plus haut |
| Mémoire minimale acceptée | `kdf.min_memory_mib` | 19 à 1 024 Mio | 19 Mio | — | non | oui | — | plus haut |
| Passes minimales acceptées | `kdf.min_iterations` | 2 à 10 | 2 | — | non | oui | — | plus haut |
| Renforcer la protection à la connexion | `kdf.upgrade_on_login` | oui ou non | oui | — | page de connexion | non | — | activé |
| Envoi du journal vers un SIEM | `audit.syslog.url` | adresse web | (vide) | — | non | oui | — | — |
| Format des événements envoyés | `audit.syslog.format` | « Syslog (RFC 5424) » (`rfc5424`), « JSON » (`json`) | « Syslog (RFC 5424) » (`rfc5424`) | — | non | non | — | — |
| Séparateur des exports CSV | `audit.csv_separator` | « Point-virgule » (`semicolon`), « Virgule » (`comma`), « Tabulation » (`tab`) | « Point-virgule » (`semicolon`) | — | non | non | — | — |
| Validité du jeton de l'annuaire | `scim.token_ttl_days` | 0 à 730 jours ; 0 = sans limite | 0 (sans limite) | — | non | non | — | plus bas (0, sans limite, est le moins sûr) |

En détail :

- **Adresse publique de Locksy** : Adresse à laquelle les personnes ouvrent Locksy, utilisée dans les e-mails, les liens et la connexion d'entreprise. En https.
- **Mémoire de la dérivation du mot de passe** : Mémoire utilisée pour protéger le mot de passe maître contre les attaques. Plus haut est plus sûr mais plus lent sur les petits postes.
- **Passes de la dérivation du mot de passe** : Nombre de passes du calcul qui protège le mot de passe maître.
- **Parallélisme de la dérivation du mot de passe** : Nombre de calculs menés en parallèle pour protéger le mot de passe maître.
- **Mémoire minimale acceptée** : Le serveur refuse un mot de passe maître protégé avec moins de mémoire.
- **Passes minimales acceptées** : Le serveur refuse un mot de passe maître protégé avec moins de passes.
- **Renforcer la protection à la connexion** : À la connexion, les applications renforcent la protection d'un mot de passe maître créé avec des paramètres plus faibles.
- **Envoi du journal vers un SIEM** : Adresse du collecteur syslog : udp://, tcp:// ou tcp+tls:// suivi de l'hôte et du port.
- **Format des événements envoyés** : Format des événements transmis au collecteur syslog.
- **Séparateur des exports CSV** : Séparateur de colonnes des fichiers CSV. Le point-virgule convient à Excel en français.
- **Validité du jeton de l'annuaire** : Durée de validité du jeton utilisé par l'annuaire de l'entreprise (SCIM). À 0, le jeton n'expire jamais. Valeurs proposées : sans limite, 30 jours, 90 jours, 180 jours, 365 jours (1 an), 730 jours (2 ans).

## Connexion d'entreprise

| Réglage | Clé | Valeurs admises | Défaut | Modes | Diffusé aux postes | Propriétaire seulement | Plafond de l'hébergeur (variable) | Sens le plus sûr |
|---|---|---|---|---|---|---|---|---|
| Imposer la connexion d'entreprise (SSO) | `sso.enforce` | oui ou non | non | — | non | non | — | activé |
| Imposer la connexion avec le compte Windows | `ldap.enforce` | oui ou non | non | — | non | non | — | activé |

En détail :

- **Imposer la connexion d'entreprise (SSO)** : Refuse la connexion par mot de passe maître seul. Les propriétaires gardent un accès de secours. Testez d'abord la connexion avec votre compte.
- **Imposer la connexion avec le compte Windows** : Refuse la connexion par mot de passe maître seul. Les propriétaires gardent un accès de secours. Testez d'abord la connexion avec votre compte.
