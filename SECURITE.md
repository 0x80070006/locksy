# Modèle de sécurité de Locksy

> **Signaler une vulnérabilité** : voir [SECURITY.md](SECURITY.md) (canal privé, délais,
> vérification des versions). Ce document-ci décrit le modèle de sécurité et ses limites ; le
> détail cryptographique est dans [docs/Chiffrement-et-securite.md](docs/Chiffrement-et-securite.md).

## Principe

Chiffrement **côté client** (« zero-knowledge ») : le serveur stocke des chiffrés opaques, des
empreintes Argon2id et des métadonnées (dates, rôles, appartenances). Une fuite complète de la
base ne révèle aucun secret sans les mots de passe maîtres.

Le même noyau Rust (`crates/locksy-core`) est utilisé par le serveur, par le client Windows et
par l'interface web (compilé en WebAssembly). Les primitives viennent des bibliothèques
RustCrypto et dalek, sans code `unsafe` dans le noyau.

## Primitives

| Usage | Algorithme |
|---|---|
| Mot de passe maître → clé | Argon2id, 64 Mio, 3 passes (paramètres stockés par compte, bornes min. imposées), normalisation Unicode NFC |
| Séparation des clés | HKDF-SHA256 : clé d'authentification ≠ clé de chiffrement |
| Chiffrement | XChaCha20-Poly1305, nonce aléatoire 192 bits, données associées obligatoires |
| Partage | X25519 éphémère + HKDF-SHA256 + XChaCha20-Poly1305 (ECIES), contexte lié au coffre et au destinataire |
| Vérification serveur | Argon2id sur la preuve d'authentification (déjà dérivée côté client) |
| 2FA | TOTP RFC 6238, fenêtre ±30 s, rejeu interdit |
| Jetons | 256 bits aléatoires, stockés hachés (SHA-256) |

## Hiérarchie des clés

```
mot de passe maître ──Argon2id──► clé maître ──HKDF──┬─► preuve d'authentification → serveur
                                                     └─► clé de chiffrement
clé de chiffrement ──protège──► clé utilisateur (aléatoire, 256 bits)
clé de récupération ──protège──► clé utilisateur (copie de secours)
clé utilisateur ──protège──► clé privée X25519
clé privée X25519 ──ouvre──► clé de chaque coffre (scellée pour chaque membre)
clé de coffre ──chiffre──► éléments et nom du coffre
```

Chaque chiffré est lié à sa place par ses données associées (`verrou:v1:item:<coffre>:<élément>`…) :
le serveur ne peut ni déplacer, ni échanger, ni rejouer un élément ailleurs sans que le
déchiffrement échoue. Au déverrouillage, le client vérifie que la clé publique annoncée par
le serveur correspond à sa clé privée.

## Protections du serveur

- Installation : tant qu'aucun compte n'existe, le premier compte (propriétaire) exige un
  **jeton d'installation** à usage unique, écrit par le serveur dans `<données>/setup-token`
  (droits 0600, seule son empreinte SHA-256 est en base) ou imposé par `LOCKSY_SETUP_TOKEN`
  (20 caractères minimum). Il est effacé dès la création du premier compte (`setup.completed`
  au journal) ; sans lui, la première personne à joindre le serveur en prendrait le contrôle.
  Les essais de jeton sont plafonnés globalement (blocage progressif après 20 échecs, tous
  clients confondus), en plus du plafond par adresse IP.
- Tentatives de connexion **comptées avant** toute vérification (Argon2, liaison LDAP) : des
  requêtes parallèles ne dépassent pas les seuils. Blocage progressif (30 s puis doublement,
  jusqu'à 1 h) après 5 échecs par couple (compte, adresse IP) et 50 par compte, pour qu'un
  tiers ne bloque pas facilement un compte ; plafond de 100 tentatives par adresse IP en
  10 min, qu'une réussite ne remet pas à zéro. Les adresses IPv6 sont regroupées par /64.
  Plafonds de requêtes sur les routes publiques.
- Hachage Argon2 côté serveur borné (`LOCKSY_ARGON2_CONCURRENCY`, file `LOCKSY_ARGON2_QUEUE`) :
  au-delà, réponse 503 `server_busy` au lieu d'un épuisement de la mémoire.
- Délais : lecture des en-têtes (15 s, `LOCKSY_HEADER_TIMEOUT_SECS`, contre les connexions
  lentes) et durée totale d'une requête (120 s, `LOCKSY_REQUEST_TIMEOUT_SECS`, 408 au-delà).
  Une panique d'un traitement devient un 500 générique, sans détail.
- Adresse cliente derrière un proxy (`LOCKSY_TRUST_PROXY=true`) : entrée la plus à **droite**
  de `X-Forwarded-For` (celle qu'ajoute le proxy ; la plus à gauche est fournie par le client
  et falsifiable). Avec `LOCKSY_TRUSTED_PROXIES` (IP ou CIDR), l'en-tête n'est lu que si la
  connexion vient d'un de ces proxys, qui sont sautés depuis la droite.
- Comptes inexistants indiscernables : sel factice stable, même temps de réponse.
- Sessions : expiration après inactivité et durée maximale ; un compte désactivé est coupé
  immédiatement.
- En-têtes : CSP stricte (aucun script en ligne, WebAssembly autorisé), `frame-ancestors 'none'`,
  `no-referrer`, `nosniff`, `no-store` sur l'API. `Strict-Transport-Security` (2 ans) en HTTPS
  intégré et derrière un proxy (`LOCKSY_TRUST_PROXY=true` suppose donc un proxy en HTTPS).
- Concurrence : chaque modification indique la révision lue ; une version périmée est refusée.
- Pas de fuite d'existence : un objet inexistant et un objet d'un coffre dont on n'est pas
  membre donnent la même réponse 404 ; 403 est réservé au membre au rôle insuffisant.
- Transactions : contrôles, écritures et audit d'une opération sont atomiques ; l'événement
  d'audit ne part au SIEM qu'après le commit (une opération annulée n'y apparaît pas).
  Syslog en `udp://`, `tcp://` ou `tcp+tls://` (`LOCKSY_SYSLOG_CA_FILE` : autorité interne).
- Quotas de pièces jointes par utilisateur, pour l'organisation et par élément (413
  `quota_exceeded`). Export CSV du journal neutralisé contre l'injection de formules.
- Clé serveur : absente alors que des comptes existent, le démarrage est **refusé** (restaurer
  la clé, ou `LOCKSY_SERVER_KEY_RESET=true` en dernier recours) ; écrite atomiquement en 0600.
- Configuration validée au démarrage : une variable illisible arrête le serveur (code 2) au
  lieu d'un réglage par défaut silencieux.
- SQLite en WAL, `synchronous = FULL`, `secure_delete`, schéma versionné (un binaire refuse une
  base plus récente) ; conteneur non-root, système de fichiers en lecture seule, aucune
  capacité Linux, port lié à `127.0.0.1`.

## Connexion unique et provisionnement

- Le SSO (OpenID Connect) authentifie la personne auprès du serveur ; il ne donne **aucun**
  accès aux données. Le mot de passe maître reste nécessaire pour dériver la clé qui déchiffre
  le coffre. Un fournisseur d'identité compromis permet d'ouvrir une session, pas de lire un
  coffre.
- Contrôles du jeton d'identité : signature (clés JWKS du fournisseur, RSA/RSA-PSS/ECDSA
  uniquement), émetteur, audience, expiration, `nonce` ; flux protégé par PKCE et `state`.
- Le ticket SSO est à usage unique, valable 5 minutes, lié à une adresse et à un compte.
  Redirections de retour limitées à l'adresse publique de Locksy, à `127.0.0.1` (client de
  bureau, RFC 8252) et à `https://<id>.chromiumapp.org` pour les seules extensions dont
  l'identifiant est déclaré par l'administrateur (sinon 400 `extension_not_allowed`).
  Le client de bureau envoie un `client_state` aléatoire (16 à 128 caractères base64url, sinon
  400), renvoyé avec le ticket sur la boucle locale : le client ignore tout retour qui ne le
  porte pas, un autre programme du poste ne peut donc ni injecter un ticket ni faire échouer
  le flux. Le motif d'un refus du fournisseur n'est jamais affiché par les clients.
- La double authentification Locksy reste exigée après le SSO ou le compte Windows : le ticket
  prouve l'identité d'entreprise, pas la possession du second facteur. Il n'est consommé qu'à
  l'ouverture de la session et reste donc valable le temps de saisir le code.
- Adresse e-mail : seule `email_verified` vraie prouve l'adresse ; absente, elle est refusée
  sauf option explicite de l'administrateur (Entra ID n'envoie pas ce champ). Une identité
  déjà liée (sujet signé par le fournisseur) est toujours reconnue. Un compte Locksy existant
  n'est rattaché automatiquement par son adresse que si elle est vérifiée **et** qu'une liste
  de domaines autorisés est définie (sinon 403 `sso_link_refused`) ; une adresse inconnue non
  vérifiée ne reçoit pas de ticket d'inscription (403 `email_unverified`).
- SCIM : jeton porteur de 256 bits, stocké haché, comparaison en temps constant, blocage
  après 10 échecs. La désactivation supprime toutes les sessions du compte. Une suppression
  par l'annuaire ne fait que **désactiver** un administrateur ou un propriétaire (jamais le
  dernier propriétaire : 409) ; sa suppression définitive reste réservée à un administrateur.
- Accès de secours : quand le SSO est imposé, seuls les propriétaires peuvent encore se
  connecter par mot de passe maître (avec leur double authentification).

## Active Directory

- Transport toujours chiffré (LDAPS ou STARTTLS), certificat du contrôleur vérifié avec
  l'autorité fournie (nom DNS obligatoire dans le certificat) ; LDAP en clair refusé.
- Mot de passe du compte de service chiffré au repos (clé du serveur), jamais réaffiché.
- Connexion Windows : mot de passe vide refusé (une liaison LDAP sans mot de passe
  « réussirait » de façon anonyme), valeurs échappées dans les filtres (RFC 4515), recherche
  limitée aux membres du groupe et aux comptes actifs, un seul résultat exigé, puis liaison au
  nom de la personne. Le mot de passe Windows n'est jamais stocké et est effacé de la mémoire.
- Tentatives comptées avant toute liaison : blocage après 5 échecs par couple (identifiant,
  adresse IP) et 50 par identifiant, avant le verrouillage AD ; plafond de 100 par adresse IP
  en 10 min.
- Réponses génériques : `invalid_credentials` (401) pour tout échec d'identifiants,
  `ldap_unavailable` (503) pour toute panne d'annuaire, le détail n'allant qu'aux journaux du
  serveur ; un échec dure au moins 1,5 s (pas d'énumération des comptes au chronomètre).
  Chaque opération sur l'annuaire est limitée à 10 s, une synchronisation à 5 min.
- Synchronisation : aucune désactivation si l'annuaire ne renvoie aucun compte.

## Clients

- **Épinglage des paramètres de dérivation** : chaque client (web, extension, Windows)
  mémorise par adresse e-mail les paramètres Argon2id les plus forts déjà utilisés avec succès
  sur l'appareil. Des paramètres plus faibles annoncés par le serveur (prelogin, après SSO ou
  compte Windows, déverrouillage) sont refusés avant tout calcul (`kdf_downgrade`) : un
  serveur compromis ne peut pas abaisser le coût d'une attaque par dictionnaire.
- **Épinglage des clés publiques** (web) : clé de chaque membre mémorisée à la première
  rencontre. Avant de sceller une clé de coffre (ajout, retrait, renouvellement), les
  destinataires s'affichent avec leur empreinte et leur état (nouveau, inchangé, CHANGÉ) ; une
  clé changée exige une confirmation explicite. Notre propre clé est recalculée depuis la clé
  privée, jamais reprise du serveur.
- **Presse-papiers** : effacé à l'échéance, au verrouillage et à la déconnexion (web,
  extension, Windows). Sous Windows, un secret copié est exclu de l'historique Win+V et du
  cloud. Dans un navigateur, l'effacement est inconditionnel sauf permission de lecture déjà
  accordée, et l'historique du système n'est pas maîtrisable.
- **Extension** : verrouillage réel par le service worker (alarmes : l'ouverture du popup ne
  prolonge pas la session), au verrouillage de la session Windows et au démarrage du
  navigateur, avec révocation du jeton côté serveur. Remplissage limité au domaine
  enregistrable, au port et au schéma de l'élément, origine revérifiée dans la page. Pour
  survivre à la fermeture du popup, la clé utilisateur et la clé privée sont **exportées** du
  module WebAssembly et gardées dans `chrome.storage.session` (mémoire du navigateur, jamais
  sur disque) jusqu'au verrouillage : voir les limites connues.
- **Client Windows** : verrouillage après inactivité, veille et arrière-plan prolongé (Win+L),
  avec purge de l'état de l'interface ; politique machine (`HKLM\SOFTWARE\Policies\Locksy`)
  et d'extension (`storage.managed`) pour imposer serveur, délai de verrouillage maximal et
  délai d'effacement du presse-papiers.

## Clé du serveur

`server.key` (256 bits, `LOCKSY_SERVER_KEY_FILE`, par défaut `<données>/server.key`) chiffre au
repos les secrets TOTP, le mot de passe du compte de liaison LDAP et le secret client SSO ; elle
sert aussi de clé HMAC aux sels factices des comptes inexistants. Elle ne protège **aucun**
coffre. Il n'existe pas de rotation à chaud : la seule procédure est de mettre la clé de côté
et de démarrer avec `LOCKSY_SERVER_KEY_RESET=true`, puis de ressaisir le mot de passe LDAP et
le secret SSO et de réinitialiser la 2FA de chaque compte qui l'avait activée (voir
[Exploitation](docs/Exploitation.md#rotation-de-serverkey)). À réserver à une compromission.

## Chaîne d'approvisionnement

- Versions construites par la CI (`.github/workflows/release.yml`, sur un tag `v*`) dans des
  images épinglées par empreinte, avec `rust-toolchain.toml` ; archives reproductibles
  (`SOURCE_DATE_EPOCH`).
- `SHA256SUMS` couvre tous les fichiers publiés ; il est signé sans clé par **cosign**
  (`SHA256SUMS.sigstore.json`, identité liée au workflow du dépôt) et, en option, par
  **minisign** (`SHA256SUMS.minisig`). Chaque fichier porte une **attestation de provenance**
  GitHub. Vérification : [SECURITY.md](SECURITY.md#vérifier-une-version).
- SBOM CycloneDX du serveur, du client Windows et du module WebAssembly publiés avec la
  version.
- Contrôles en CI : `cargo-deny` (licences, sources, avis), `cargo-audit`, analyse Trivy de
  l'image Docker (CRITICAL et HIGH corrigeables), Dependabot chaque semaine.
- `install.sh` vérifie l'empreinte de l'archive (refus sans empreinte, sauf `--skip-verify`
  explicite) et la signature quand l'outil et la clé sont disponibles (`--require-signature`
  pour l'exiger) ; `install-client.ps1` vérifie l'empreinte de l'exécutable.
- La signature **Authenticode** du client Windows reste facultative : elle n'est faite que si
  l'éditeur fournit un certificat de signature de code (action humaine).

## Limites connues

Ce que Locksy ne garantit pas, ou garantit seulement en partie, dans l'état actuel du code.

**Serveur compromis.**
- Le serveur peut **refuser, supprimer ou restaurer une ancienne version** des données : le
  chiffrement en garantit la confidentialité et l'intégrité, pas la disponibilité.
- **Intégrité du code web** : l'interface web et son module WebAssembly sont servis par le
  serveur. Un serveur compromis peut servir un JavaScript modifié qui capture le mot de passe
  maître. La CSP empêche l'injection de script par un tiers (XSS), pas un serveur qui modifie
  ses propres fichiers. Le client Windows et l'extension, qui embarquent leur code, n'ont pas
  cette faiblesse.
- **Épinglage en confiance au premier usage** : l'épinglage des paramètres Argon2id
  (`locksy.kdfpins` dans le navigateur, `kdf_pins` dans `bureau.json` sur le poste) et des clés
  publiques (`locksy.keypins`, web seulement) ne protège qu'à partir de la première connexion
  réussie, par navigateur ou par poste. Un nouvel appareil, un navigateur en navigation privée
  ou des données de site effacées repartent sans référence. Les clés publiques ne sont
  épinglées que dans l'interface web, seule à gérer les membres des coffres.
- Les droits « lecteur » sont imposés par le serveur ; un lecteur possède la clé du coffre et
  peut donc lire tout son contenu (comme dans tout gestionnaire chiffré de bout en bout).

**Clients.**
- **Extension et clés exportées** : dans l'interface web, les clés restent dans la mémoire
  WebAssembly et JavaScript ne manipule que des numéros de poignée. L'extension, elle, exporte
  la clé utilisateur et la clé privée en base64 vers JavaScript et les garde dans
  `chrome.storage.session` jusqu'au verrouillage, pour ne pas redemander le mot de passe à
  chaque ouverture du popup. Une autre extension malveillante ne peut pas y accéder, mais un
  logiciel malveillant qui lit la mémoire du navigateur, oui. Les clés de pièces jointes et de
  liens de partage transitent aussi par JavaScript (elles sont dans l'élément chiffré ou après
  le `#` du lien).
- **Presse-papiers « au mieux »** : l'effacement remplace le contenu copié par Locksy. Dans
  l'extension, sans la permission `clipboardRead`, il est inconditionnel, et un repli écrit une
  espace quand le navigateur refuse une chaîne vide. Dans un navigateur, l'historique du
  presse-papiers du système (Win+V) n'est pas maîtrisable ; seul le client Windows l'exclut.
  Un logiciel qui lit le presse-papiers pendant le délai obtient le secret.
- **SSO du client de bureau** : la boucle locale (`127.0.0.1`) lit les connexions l'une après
  l'autre, 2 s au plus chacune. Un programme local lent peut retarder le retour légitime ; il
  ne peut ni injecter un ticket ni faire échouer le flux (`client_state`).
- Le client Windows (egui, ureq) garde des copies transitoires de textes affichés et de
  l'en-tête HTTP qui ne peuvent pas être effacées.

**Fédération.**
- La **double authentification après SSO ou compte Windows** dépend de l'activation de la 2FA
  Locksy : sans elle (ou sans règle « 2FA obligatoire »), le SSO seul et le mot de passe maître
  ouvrent le coffre. Le ticket SSO n'est consommé qu'à l'ouverture de la session ; pendant ses
  5 minutes de validité, il peut servir à plusieurs essais de code, comptés par le limiteur.
- Le mot de passe Windows transite par le serveur (en HTTPS) pour être vérifié auprès de l'AD.
- **Vérification préalable de l'extension** : avant d'ouvrir la fenêtre SSO, l'extension
  appelle `/api/sso/start` pour savoir si elle est autorisée. Cela crée un état SSO en attente
  inutile (purgé après 10 minutes) et compte deux fois sur le plafond `sso-start` (30 par
  minute et par adresse). Une route dédiée « extension autorisée ? » reste à faire.

**Exploitation.**
- **Jeton d'installation** : son limiteur est global. Un tiers qui joint le serveur avant
  l'installation peut, en multipliant les essais faux, retarder la création du premier compte
  (blocage de 30 s, doublé jusqu'à 1 h) ; il ne peut pas la prendre. Installez sur un réseau
  maîtrisé, ou imposez le jeton (`LOCKSY_SETUP_TOKEN`) et créez le compte aussitôt.
- **Adresse cliente derrière un proxy** : avec `LOCKSY_TRUST_PROXY=true`, l'entrée la plus à
  droite de `X-Forwarded-For` est retenue. Derrière plusieurs proxys, il faut déclarer
  `LOCKSY_TRUSTED_PROXIES`, sinon toutes les requêtes semblent venir du dernier proxy (seuils
  par IP partagés). Sans proxy, `LOCKSY_TRUST_PROXY` doit rester à `false`.
- **Syslog TLS** (`tcp+tls://`) : testé unitairement, pas encore de bout en bout contre un vrai
  SIEM.
- **Instance unique** : SQLite sur un seul serveur, sans haute disponibilité ni limiteur
  partagé. La continuité repose sur les sauvegardes et la restauration
  ([PRA/PCA](docs/PRA-PCA.md)).
- **Clé serveur** : pas de rotation à chaud (voir plus haut).
- Le transport doit être protégé par HTTPS dès que le serveur est joignable depuis le réseau.
- Pas d'audit externe ni de qualification (CSPN) à ce jour.
