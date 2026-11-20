# Journal des modifications

Toutes les évolutions notables de Locksy sont consignées ici.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et les numéros de
version suivent le [versionnage sémantique](https://semver.org/lang/fr/). Les rubriques sont :
Ajouté, Modifié, Sécurité, Corrigé, Supprimé, et « Changements de comportement » quand une
mise à jour demande une action de l'exploitant.

## [1.1.0] - Non publiée

Version « iso-prod » : durcissement du serveur, robustesse des données, clients durcis,
livraison signée et documentation d'exploitation. Aucun libellé cryptographique ne change :
les coffres, les exports et les bases 1.0.0 restent lisibles (la base passe au schéma v2 au
premier démarrage).

### Changements de comportement (à lire avant la mise à jour)

- **Premier compte** : la création du premier compte (propriétaire) exige le **jeton
  d'installation**, lu dans `<données>/setup-token` ou imposé par `LOCKSY_SETUP_TOKEN`
  (20 caractères au moins). Sans effet sur une instance qui a déjà des comptes.
- **Clé serveur** : si `server.key` est absente alors que la base contient des comptes, le
  serveur **refuse de démarrer** (il en générait une nouvelle, ce qui rendait illisibles les
  secrets 2FA, LDAP et SSO). Restaurez la clé, ou utilisez `LOCKSY_SERVER_KEY_RESET=true` en
  dernier recours.
- **Proxy** : avec `LOCKSY_TRUST_PROXY=true`, l'adresse cliente est désormais l'entrée **la plus
  à droite** de `X-Forwarded-For`. Derrière une chaîne de proxys, déclarez-les dans
  `LOCKSY_TRUSTED_PROXIES`, sinon toutes les requêtes sembleront venir du dernier proxy.
- **Double authentification** : le code TOTP est désormais demandé **après le SSO et après la
  connexion avec le compte Windows** (il ne l'était pas en 1.0.0) pour les comptes qui ont
  activé la 2FA. Les clients 1.0.0 ne savent pas le demander : mettez à jour l'extension et le
  client Windows.
- **SCIM** : une suppression par l'annuaire ne fait plus que **désactiver** un administrateur
  ou un propriétaire ; sa suppression définitive se fait dans Locksy.
- **SSO** : `email_verified` est exigé strictement. Un compte existant n'est plus rattaché par
  son adresse si elle n'est pas vérifiée, ou si aucune liste de domaines autorisés n'est
  définie (403 `sso_link_refused`) ; une adresse inconnue non vérifiée ne reçoit pas de ticket
  d'inscription (403 `email_unverified`). Pour Entra ID, qui n'envoie pas ce champ, cochez
  l'option correspondante (`trust_unverified_email`).
- **SSO depuis l'extension** : refusé tant que l'identifiant de l'extension n'est pas déclaré
  dans Administration > Authentification unique (400 `extension_not_allowed`).
- **Client Windows** : un ancien `C:\ProgramData\Locksy\bureau.json` est désormais lu comme
  une **politique** (délais maximaux), et non plus comme des préférences initiales.
- **Extension** : Chrome ou Edge **120** au minimum.
- **install.sh** : `--archive` est refusé sans empreinte vérifiable (`SHA256SUMS` à côté de
  l'archive, ou `--sha256`), sauf `--skip-verify` explicite. `--purge` demande de taper
  `SUPPRIMER` (ou `--yes`).
- **install-client.ps1** : l'installation est refusée sans empreinte (`SHA256SUMS` ou
  `-Sha256`), sauf `-SkipHashCheck` ; `-ExecutionPolicy Bypass` n'est plus utilisé.

### Ajouté

**Serveur : sécurité (phase 1)**
- Jeton d'installation à usage unique pour le premier propriétaire (`<données>/setup-token`
  en 0600, empreinte seule en base, effacé à la création du compte ; `setup.completed` au
  journal ; codes `setup_token_required` et `invalid_setup_token`).
- `LOCKSY_TRUSTED_PROXIES` : IP ou CIDR des proxys autorisés à fournir `X-Forwarded-For`,
  sautés depuis la droite.
- Plafond des calculs Argon2 simultanés et de leur file d'attente (`LOCKSY_ARGON2_CONCURRENCY`,
  `LOCKSY_ARGON2_QUEUE`) : 503 `server_busy` au lieu d'un épuisement de la mémoire.
- En-tête `Strict-Transport-Security` (2 ans) en HTTPS intégré et derrière un proxy.
- Délais de lecture des en-têtes (`LOCKSY_HEADER_TIMEOUT_SECS`, 15 s) et de requête
  (`LOCKSY_REQUEST_TIMEOUT_SECS`, 120 s, 408 au-delà) ; une panique devient un 500 générique.
- Liste blanche des identifiants d'extension pour le retour SSO (`allowed_extension_ids`).
- Option `trust_unverified_email` (fournisseurs qui n'envoient pas `email_verified`).
- LDAP : délai de 10 s par opération et de 5 min par synchronisation.

**Serveur : données et exploitation (phase 2)**
- Schéma de base versionné (`PRAGMA user_version`, schéma v2) : migrations palier par palier,
  chacune dans une transaction ; un binaire refuse une base plus récente que lui.
- SQLite en WAL avec `synchronous = FULL` ; pool de lecteurs (`LOCKSY_DB_READERS`, 1 à 64,
  défaut 4) et écrivain unique.
- Sous-commandes `check` (configuration, base, intégrité, clé ; codes 0, 1, 2), `backup <f>
  [--with-key] [--force]` (copie à chaud vérifiée) et `version`.
- `LOCKSY_SERVER_KEY_FILE` (emplacement de la clé serveur) et `LOCKSY_SERVER_KEY_RESET`.
- Journaux JSON (`LOCKSY_LOG_FORMAT=json`), en-tête `X-Request-Id`, route `/api/ready`
  (503 `not_ready` pendant l'arrêt), arrêt gracieux (`LOCKSY_SHUTDOWN_GRACE_SECS`, 0 à 300,
  défaut 10).
- Syslog `tcp+tls://` avec autorité interne (`LOCKSY_SYSLOG_CA_FILE`).
- Quotas de pièces jointes par utilisateur, pour l'organisation et par élément (413
  `quota_exceeded`), réglables dans Administration > Réglages.

**Clients (phase 3)**
- Client Windows : presse-papiers exclu de l'historique Win+V et de la synchronisation cloud ;
  secrets en `Zeroizing` et purge de l'état de l'interface au verrouillage ; politique machine
  `HKLM\SOFTWARE\Policies\Locksy` (`ServerUrl`, `MaxAutoLockMinutes`, `ClipboardSeconds`,
  `LockOnFocusLossMinutes`) ; verrouillage à la veille et en arrière-plan prolongé (Win+L) ;
  `client_state` du SSO par boucle locale ; épinglage des paramètres de dérivation
  (`kdf_pins`) ; avertissement OneDrive à l'enregistrement d'une pièce jointe ; code 2FA
  demandé après SSO et compte Windows.
- Extension : service worker et alarmes pour un vrai verrouillage automatique, verrouillage
  avec la session Windows (`idle`) ; effacement du presse-papiers par un document offscreen ;
  correspondance stricte (domaine enregistrable, port, schéma) et origine revérifiée dans la
  page ; politique `chrome.storage.managed` (`server_url`, `max_auto_lock_minutes`,
  `clipboard_seconds`) ; zip déterministe avec son `.sha256` (`node extension/build.mjs`).
- Web : effacement robuste du presse-papiers ; épinglage des paramètres de dérivation
  (`locksy.kdfpins`) et des clés publiques (`locksy.keypins`) ; confirmation des membres et de
  leurs empreintes avant chaque scellement d'une clé de coffre ; focus confiné dans les
  modales ; interface des quotas de pièces jointes ; messages clairs pour 413 et 503.
- Serveur : paramètre `client_state` de `/api/sso/start?target=desktop` (16 à 128 caractères
  `[A-Za-z0-9_-]`), renvoyé avec le ticket ou l'erreur.

**Livraison et exploitation (phase 4)**
- Intégration continue (`.github/workflows/ci.yml`) : format, clippy, tests du noyau, du
  serveur et du client Windows, module WebAssembly, tests JavaScript, scripts shell
  (shellcheck), `cargo-deny`, `cargo-audit`, image Docker analysée par Trivy, fuzzing non
  bloquant ; Dependabot hebdomadaire.
- Publication signée (`.github/workflows/release.yml`, sur tag `v*`) : `SHA256SUMS` signé par
  cosign sans clé et en option par minisign, SBOM CycloneDX, attestation de provenance,
  Authenticode facultatif ; publication en brouillon.
- `rust-toolchain.toml` (Rust 1.100.0) et images Docker épinglées par empreinte.
- `install.sh` : `--sha256`, `--skip-verify`, `--require-signature` (vérification cosign ou
  minisign, y compris hors ligne), `--version` contrôlée, `--listen`, `--backup-dir`,
  `--no-backup-timer`, `--rollback` ; sauvegarde automatique avant mise à jour ; timer
  systemd de sauvegarde quotidienne ; service systemd durci.
- `scripts/backup-locksy.sh` : sauvegarde chiffrée (age ou gpg), test de restauration
  automatique, rotation ; livré dans l'archive du serveur.
- Caddy durci (exemple `deploiement/`) ; archives de version reproductibles
  (`SOURCE_DATE_EPOCH`).
- Tests : tests HTTP de bout en bout du serveur (contrôle d'accès, authentification, jeton
  d'installation), vecteurs RFC 7748, RFC 5869, RFC 9106, XChaCha20-Poly1305 et format `v1`
  figé (`v1.`, `s1.`, dérivation, clé de récupération) ; cibles de fuzzing (`decrypt`,
  `open`, `b64d`, `crockford_decode`, `totp_parse`, `parse_recovery_key`, `percent_decode`).
- Documentation : [Exploitation](docs/Exploitation.md), [PRA/PCA](docs/PRA-PCA.md),
  [RGPD](docs/RGPD.md), ce journal, [SECURITY.md](SECURITY.md) refondu.

### Modifié

- Les tentatives de connexion sont **comptées avant** le calcul Argon2 ou la liaison LDAP :
  des requêtes parallèles ne dépassent plus les seuils. Seuils : 5 échecs par couple (compte,
  adresse IP), 50 par compte, 100 tentatives par adresse IP en 10 min ; adresses IPv6
  regroupées par /64.
- La synchronisation LDAP manuelle tourne dans sa propre tâche et va au bout (5 min au plus)
  même si la requête HTTP expire (408).
- L'audit n'est transmis au SIEM qu'**après le commit** : une opération annulée n'y apparaît
  plus.
- Les écritures multiples (élément et pièces jointes, rotation de coffre, administration) sont
  faites dans une seule transaction avec leur ligne d'audit.
- `server.key` est écrite de façon atomique en 0600 ; des droits trop ouverts sont ramenés à
  0600.
- La configuration est validée au démarrage : une valeur illisible arrête le serveur avec le
  code 2 au lieu d'un réglage par défaut silencieux.
- `PUT /api/admin/settings` accepte un envoi partiel : un champ absent garde sa valeur.
- Le web, l'extension et le client Windows partagent les mêmes règles de presse-papiers et de
  verrouillage ; l'extension et le client Windows affichent les valeurs imposées par la
  politique (« imposé par votre organisation »).
- Le zip de l'extension est produit par `node extension/build.mjs --wasm` dans le script de
  publication ; `web/tests` n'est plus dans l'archive du serveur ni dans l'image Docker.

### Sécurité

- Le limiteur de débit n'est plus contournable par un `X-Forwarded-For` forgé (l'entrée la plus
  à gauche, fournie par le client, était lue).
- Un serveur fraîchement installé ne peut plus être pris par la première personne qui le
  joint (jeton d'installation).
- Le TOTP n'est plus contourné par une connexion SSO ou LDAP. Le ticket SSO n'est consommé
  qu'à l'ouverture de la session.
- Le déni de service par calculs Argon2 en parallèle, sans authentification, est borné.
- Les redirections SSO n'acceptent plus n'importe quel `*.chromiumapp.org`.
- LDAP : erreurs génériques (`invalid_credentials`, `ldap_unavailable`) et durée d'échec
  plancher de 1,5 s, contre l'énumération des comptes.
- Les états SSO expirés sont évincés (`sso_busy` 503 si la table est pleine).
- SCIM ne peut plus supprimer un administrateur ni un propriétaire.
- Réponses 404 identiques pour un objet inexistant et un objet d'un coffre dont on n'est pas
  membre (plus de fuite d'existence).
- Export CSV du journal neutralisé contre l'injection de formules.
- `PUT /api/admin/settings` partiel ne remet plus `require_2fa` ni les autres règles à leur
  valeur par défaut.
- Clients : refus d'un abaissement des paramètres Argon2id annoncés par le serveur
  (`kdf_downgrade`) ; clé publique changée signalée et confirmée avant de sceller.
- Client Windows : un autre programme du poste ne peut plus injecter un ticket SSO sur la
  boucle locale ni faire échouer le flux (`client_state`).
- Extension : le verrouillage après inactivité est réel (il était seulement affiché) ; le
  remplissage n'accepte plus un autre schéma, un autre port ni un domaine parent ou frère.
- Releases signées et vérifiées à l'installation (voir [SECURITY.md](SECURITY.md)).

### Corrigé

- 2FA imposée par l'organisation : un compte sans 2FA recevait 403 `2fa_required` aussi sur
  `/api/me`, `/api/me/2fa/*` et `/api/auth/logout` (chemin comparé sans le préfixe `/api`) ;
  il ne pouvait donc ni activer la 2FA ni se déconnecter. Défaut présent en 1.0.0, couvert
  désormais par un test HTTP.
- Web : plus d'en-tête `Authorization: Bearer null` sans session ; fuite d'écouteurs
  d'événements ; message clair pour un 413 sans corps JSON.
- Pluriel du message de quota par élément (« 1 pièce jointe au plus par élément. »).
- Un lien d'installation `#/register?setup=` périmé renvoie vers la connexion quand un compte
  existe déjà.
- Extension : après une erreur, retour au formulaire complet ; gestion de `totp_required` après
  SSO.
- `/api/ready` passe par le pool de lecteurs et n'attend plus l'écrivain.
- `Authorization` : le schéma `Bearer` est reconnu sans tenir compte de la casse (RFC 7235),
  pour l'API comme pour SCIM ; `bearer <jeton>` n'est plus refusé en 401.
- `LOCKSY_SSO_ALLOW_HTTP` est validé au démarrage comme les autres booléens (`true`/`false`,
  `1`/`0`, `yes`/`no`) ; une valeur illisible arrête le serveur (code de sortie 2).
- Un réglage JSON illisible en base (table `settings`) est signalé au journal (niveau ERROR)
  au lieu de retomber en silence sur les valeurs par défaut.
- Journal texte : plus de codes de couleur ANSI hors d'un terminal (`docker logs`, journald).

### Supprimé

- Extension : le « second clic pour forcer » le remplissage hors du site de l'élément.
- Extension : la simulation des API (`dev-fake.js`) et les tests ne sont plus embarqués dans
  le zip de production.
- `install-client.ps1` : l'usage de `-ExecutionPolicy Bypass`.

### Refonte des écrans et du paramétrage (même version)

Interface web et administration redessinées, tous les réglages dans un registre unique
modifiable depuis l'administration, serveur et extension alignés. Base au schéma v3
(migration unique et idempotente au premier démarrage, anciens réglages repris). Aucun
libellé cryptographique ne change ; seule nouveauté : l'AAD `verrou:v1:prefs:<id>` des
préférences chiffrées.

#### Changements de comportement (à lire avant la mise à jour)

- **Session d'un compte désactivé ou échu** : la requête suivante reçoit 403
  `account_disabled` ou `account_expired` (au lieu de 401), et la session est fermée. Les
  comptes dont la date de fin d'accès est passée sont désactivés par la maintenance
  (événement `user.disabled_expired`).
- **Mot de passe maître et clé de récupération** (`POST /me/password`, `/me/recovery`) : une
  preuve actuelle refusée donne 403 (au lieu de 401) ; le code de vérification est exigé dans
  le corps quand la 2FA est active. `POST /auth/recover/finish` répond 200 `{user_id}`.
- **Actions sensibles de l'administration** : un jeton de confirmation d'identité
  (`POST /auth/reauth`, en-tête `X-Locksy-Reauth`) est exigé pour élever un rôle, supprimer
  un compte, réinitialiser une 2FA, les actions groupées, le départ d'un collaborateur et la
  régénération du jeton SCIM.
- **Annuaire (SCIM, AD)** : un compte retiré de l'annuaire suit `directory.deprovision`
  (désactivation, ou désactivation puis suppression différée) ; une synchronisation AD qui
  désactiverait trop de comptes est refusée (`directory.max_deprovision_percent`).
- **SSO** : la découverte OpenID refuse les adresses internes (anti-SSRF). Fournisseur sur le
  réseau interne : `LOCKSY_SSO_ALLOW_PRIVATE=true`.
- **Module WebAssembly** : deux fichiers, `locksy.wasm` (noyau) et `locksy-import.wasm`
  (import KeePass et Bitwarden, chargé à la demande). Une installation par archive doit
  servir les deux depuis `web/`.
- **Réglages** : les anciens réglages (règles de l'organisation, quotas, SSO, annuaire, envoi
  Syslog) sont repris dans le registre au premier démarrage. Les réglages fixés par
  l'hébergeur passent par `LOCKSY_SETTINGS_FILE` et ne se modifient plus depuis
  l'administration. Relisez Administration > Réglages après la mise à jour.
- **Client Windows** : la version 1.1 garde son interface et applique seulement la politique
  locale du poste. Elle ne suit ni les réglages diffusés aux postes ni les préférences
  synchronisées ; le serveur, lui, applique les règles de l'organisation à toutes les
  applications. Sa refonte arrive en 1.2 (voir « Non inclus »).

#### Ajouté

**Interface web**
- Nouvelle coquille : barre latérale (Tout, Favoris, coffres, Bilan de sécurité, Corbeille),
  recherche dans tout le coffre (Ctrl+K), menu du compte, commutateur « Mon coffre » /
  « Administration », tiroir sur petit écran, avertissement avant le verrouillage
  automatique, page « Aide et raccourcis » (`#/aide`).
- Coffre : liste et fiche côte à côte, copie depuis la ligne, favoris personnels, corbeille
  avec « Annuler » et compte à rebours avant la suppression définitive.
- Éditeur dans le panneau : choix du type (mot de passe, note secrète, carte bancaire,
  identité, clé SSH), mot de passe solide proposé d'emblée, code de vérification par QR code
  ou clé collée, garde de sortie sans perte de saisie, conflit d'enregistrement sans perte.
- Partage en une seule fenêtre : avec des collègues (coffre existant ou nouveau coffre, retour
  arrière complet en cas d'échec) ou par lien sécurisé (durée, nombre d'ouvertures, nom
  facultatif) ; page « Liens envoyés » (`#/liens`) avec « Révoquer ».
- Bilan de sécurité (`#/bilan`) : score, mots de passe faibles, réutilisés ou anciens, liens
  actifs, bouton « Corriger » qui ouvre l'élément avec un nouveau mot de passe proposé.
- Paramètres en cinq sections (`#/parametres/<section>`) : Mon compte, Préférences, Appareils
  et sessions, Importer ou exporter, Mon activité.
- Préférences de l'utilisateur chiffrées dans le navigateur et synchronisées entre ses
  appareils ; valeurs imposées ou limitées par l'organisation affichées avec leur limite.
- Administration (`#/admin`) : Accueil avec mise en service et « À traiter », Personnes
  (recherche, filtres dans l'adresse, fiche, actions groupées, export CSV), assistant
  « Départ de l'entreprise » avec simulation et rapport, Réglages générés depuis le registre
  unique (recherche par synonymes, profils de sécurité, « Vérifier et enregistrer » avec
  motif, historique, transfert, page Système), Connexion d'entreprise guidée par une question,
  Journal (filtres, gravité, export CSV, vérification du chaînage).
- Extraits de déploiement des postes générés depuis les réglages (stratégies Chrome et Edge,
  registre Windows, modèle d'administration ADMX et ADML, Intune).
- Accessibilité : navigation complète au clavier, focus visible et confiné dans les fenêtres,
  thème clair ou sombre, contraste renforcé, taille du texte, raccourcis à une touche
  désactivables ; déclaration d'accessibilité (`#/accessibilite`), objectif RGAA 4.1
  niveau AA.

**Serveur, extension et outillage**
- Registre des réglages (`/admin/settings`, schéma, essai à blanc, profils de sécurité,
  historique et retour à une version, import et export), politique client
  (`/settings/policy`) et préférences chiffrées synchronisées (`/me/prefs`).
- Codes de secours de la 2FA (10 codes, utilisables à la connexion), montée des paramètres
  de dérivation à la connexion, trace d'export, blocage progressif réglable (`lockout.*`),
  liste blanche d'adresses et domaines d'adresse autorisés appliqués à la connexion,
  plafonds de sessions, notification de nouvel appareil.
- Synchronisation partielle (`/sync?since=`), preuve de possession des liens de partage
  (`peek`, `open`, aucune lecture sans la clé du lien), liste complète des liens envoyés,
  révocation automatique des liens (corbeille, départ, rotation).
- Administration : personnes (filtres, fiche, actions groupées), invitations par lot,
  assistant Départ avec rapport d'accès, connexion d'entreprise testée avant d'être imposée,
  synchronisation AD à blanc, e-mails (SMTP, file, e-mail de test), journal chaîné et
  vérifiable (`locksy-server verify-audit`), gravité des événements.
- Import KeePass (KDBX 3.1 et 4) et Bitwarden (JSON chiffré ou non) dans le navigateur.
- Extension : remplissage du code de vérification, synchronisation partielle, politique de
  l'organisation lue en priorité dans `chrome.storage.managed`, verrouillage par alarme.
- `LOCKSY_SMTP_CA_FILE`, `LOCKSY_SSO_ALLOW_PRIVATE`, `LOCKSY_SETTINGS_FILE`,
  `LOCKSY_MAX_ATTACHMENT_MIB`, `LOCKSY_MAX_BODY_MIB`, `LOCKSY_RATELIMIT_*`.
- Bancs : criterion (noyau), k6 (`bench/k6`) ; tests de bout en bout Playwright (`e2e/`).
- Extension refondue sur les composants de l'interface web : mêmes libellés,
  préférences du compte partagées avec le web, identifiant de l'extension affiché
  pour l'administrateur ; déploiement imposé par GPO ou Intune documenté.
- Suites de tests : accessibilité des écrans (analyse automatique, parcours au clavier,
  zones annoncées, taille des cibles, 320 px), saisie (aucune perte au changement d'écran ni à
  la fermeture de l'onglet), échecs d'écriture (chaque action de l'interface face à une
  panne du serveur), matrice des réglages (chaque réglage relié à une preuve de son
  application), sécurité (matrice des autorisations par route, absence de secret en clair
  dans la base et le navigateur, limites de débit, analyse dynamique), sauvegarde et
  restauration, mise à jour et retour arrière, budget de poids et rapidité de l'interface.
- Documentation : [guide utilisateur](docs/Guide-utilisateur.md),
  [guide administrateur](docs/Administration.md), [réglages de l'organisation](docs/Reglages.md)
  générés depuis le registre (`node tools/gen-settings-doc.mjs`, `--check` en contrôle),
  déploiement de l'extension par GPO et Intune ([Extension navigateur](docs/Extension-navigateur.md)),
  procédures de [sauvegarde, mise à jour et retour arrière](docs/Sauvegarde-et-mises-a-jour.md).

#### Modifié

- Adresses de l'interface en français : `#/coffre`, `#/element/<id>`, `#/bilan`, `#/liens`,
  `#/parametres/<section>`, `#/admin/personnes`, `#/admin/reglages/<section>`,
  `#/admin/connexion`, `#/admin/journal`. Les anciennes adresses encore présentes dans des
  liens envoyés (`#/vault`, `#/login`, `#/register`, `#/recover`, `#/settings`, `#/shares`,
  `#/generator`, `#/health`) sont redirigées.
- Nouvelles routes de l'API (réglages, politique client, préférences, confirmation
  d'identité, personnes, départ, connexion d'entreprise, e-mails, vérification du journal,
  liens sécurisés) : voir [API](docs/API.md). `PUT /api/admin/settings` (forme historique à
  cinq champs) reste accepté pendant une version : préférez `PATCH` avec `If-Match`.
- Chaque clé de réglage (bornes, valeur par défaut, diffusion aux postes, plafond éventuel
  de l'hébergeur) est décrite dans [Réglages](docs/Reglages.md).
- Tous les textes de l'interface et de l'extension viennent d'un catalogue unique
  (`design/i18n/fr/*.json`, `node tools/gen-i18n.mjs`) ; chaque code d'erreur du serveur y a
  son message en français.
- Couleurs, espacements et thèmes viennent de jetons de design générés
  (`node tools/gen-tokens.mjs`), communs au web et à l'extension ; leur version pour le
  client Windows est prête pour la 1.2.
- La couleur de l'organisation (`branding.accent_color`) colore l'interface web dès l'écran
  de connexion.
- L'envoi du journal au SIEM suit les réglages `audit.syslog.url` et `audit.syslog.format`
  (`rfc5424` ou `json` seul), appliqués sans redémarrage ; `LOCKSY_SYSLOG` reste prioritaire.
- L'interface web (JS, CSS, WebAssembly) est servie compressée en gzip : environ 3 fois moins
  d'octets transférés. L'API n'est pas compressée.
- Image Docker : `MALLOC_ARENA_MAX=2` et `SQLITE_TMPDIR=/data` bornent la mémoire du serveur
  (sauvegarde à chaud d'une grosse base dans 512 Mo) ; correctifs de sécurité de Debian
  appliqués à la construction.
- Une fenêtre en cours de saisie (partage, invitation…) est protégée comme une page : un
  changement d'adresse ou la fermeture de l'onglet demande confirmation.
- Préférences synchronisées : seuls les choix faits par la personne sont enregistrés. Une
  valeur jamais choisie suit la valeur « Par défaut » de l'organisation, même quand celle-ci
  change ensuite.

#### Sécurité

- Codes de secours conservés sous forme d'empreinte (HMAC dérivé de la clé du serveur),
  comparés en temps constant, à usage unique ; supprimés à la réinitialisation de la 2FA.
- Liens sécurisés : le serveur ne livre le contenu chiffré qu'à qui prouve détenir la clé du
  lien. Une preuve fausse reçoit la même réponse qu'un lien inconnu et ne consomme aucune
  ouverture.
- Journal d'audit chaîné par HMAC (clé dérivée de `server.key`) : une ligne modifiée,
  supprimée ou insérée est détectée par l'interface ou par `locksy-server verify-audit`.
- Découverte OpenID protégée contre les requêtes vers le réseau interne (après résolution DNS
  et à chaque redirection).
- Confirmation d'identité à usage unique, liée à une action et à la session, pour les actions
  sensibles ; un réglage de sécurité abaissé exige cette confirmation et est signalé aux
  autres propriétaires.
- Préférences synchronisées chiffrées avec une donnée associée liée au compte : le serveur ne
  les lit pas et ne peut pas les déplacer d'un compte à l'autre.
- L'adresse de la page ne contient jamais le nom d'un élément ni la recherche dans le coffre.
- Envoi d'e-mails sans chiffrement refusé hors du réseau interne (`smtp_insecure`).
- Refus par défaut : toute route de l'API hors de la liste des routes publiques exige une
  session avant même son traitement ; une route inconnue répond `404` en JSON.
- Corps de requête illisibles (JSON invalide, mauvais type de contenu, champ manquant) :
  erreur `invalid_body` en français au lieu du texte technique.
- Un nom fait seulement de caractères invisibles est refusé.
- Secret 2FA illisible après un changement de `server.key` : erreur claire
  `totp_unreadable` (409) au lieu d'une erreur interne.
- `verify-audit` annonce d'abord « Chaînage invérifiable » quand la clé serveur n'est pas
  celle qui a écrit le journal.

#### Supprimé

- Anciennes vues web (coffre, éditeur, pages, administration, SSO, AD), feuille de style
  historique et alias de jetons de couleur.

#### Non inclus (prévu en 1.2)

- **Refonte du client Windows.** Le client 1.1 garde son interface actuelle et sa politique
  locale (`ServerUrl`, `MaxAutoLockMinutes`, `ClipboardSeconds`, `LockOnFocusLossMinutes`).
  La version 1.2 lui apportera les nouveaux écrans, les réglages diffusés aux postes et les
  préférences synchronisées ([Client Windows](docs/Client-Windows.md)).

## [1.0.0] - 2026-11-16

Première version publique.

- Noyau cryptographique Rust commun (Argon2id, XChaCha20-Poly1305, X25519, HKDF-SHA256),
  compilé nativement et en WebAssembly ; données associées sur chaque chiffré.
- Serveur axum + SQLite : coffres personnels et partagés avec rôles, renouvellement de clé au
  retrait d'un membre, pièces jointes chiffrées, liens de partage externes, corbeille,
  historique, double authentification TOTP, clé de récupération.
- Administration sans accès aux secrets : comptes, invitations, règles, journal d'audit avec
  export CSV et envoi Syslog.
- Active Directory sur site (LDAPS), SSO OpenID Connect, provisionnement SCIM 2.0.
- Interface web, client Windows natif, extension Edge et Chrome.
- `install.sh` (systemd ou Docker) et `install-client.ps1`.

[1.1.0]: https://github.com/0x80070006/locksy/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/0x80070006/locksy/releases/tag/v1.0.0
