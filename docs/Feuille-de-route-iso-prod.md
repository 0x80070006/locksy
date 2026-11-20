# Locksy : feuille de route « iso-prod »

Brainstorm issu de l'audit du 17/11/2026, qui couvre le serveur, le noyau crypto, le web, l'extension, le client Windows, l'infrastructure, la CI et la documentation.

## État des lieux

**Les points solides.**
- Le noyau crypto est sain : Argon2id, XChaCha20-Poly1305 avec AAD systématique, ECIES X25519 et HKDF.
- Aucun XSS : le code n'utilise ni `innerHTML` ni `eval`, et la CSP est stricte.
- Le contrôle d'accès (IDOR) est vérifié sur toutes les routes.
- Les requêtes SQL sont paramétrées et les jetons sont stockés hachés.
- Le JWT OIDC est validé correctement, avec PKCE.
- Les conteneurs sont durcis et aucun binaire n'est commité.

**Les points bloquants pour la production.**

| # | Sévérité | Constat | Où | Statut |
|---|---|---|---|---|
| 1 | CRITIQUE | Le limiteur de débit est contournable via `X-Forwarded-For`, qui lit l'IP la plus à gauche, fournie par le client | `server/state.rs:55` | Fait (P1) |
| 2 | CRITIQUE | Le premier compte inscrit devient propriétaire, sans jeton d'installation, alors que le service est exposé sur `0.0.0.0` | `auth.rs:180`, `install.sh:181` | Fait (P1) |
| 3 | CRITIQUE | Il n'existe ni CI/CD, ni scan des dépendances, ni SBOM | — | Fait (P4), à confirmer au premier passage de la CI |
| 4 | CRITIQUE | Les releases ne sont pas signées, l'exe n'a pas de signature Authenticode, `curl \| sudo bash` et le mode `--archive` ne vérifient rien | `install.sh`, `install-client.ps1` | Partiel (P4) : signature cosign/minisign et vérification à l'installation faites ; Authenticode = action humaine (certificat) |
| 5 | CRITIQUE | Le presse-papiers Windows reste dans l'historique Win+V et peut être synchronisé dans le cloud | `desktop/app.rs:344` | Fait (P3) |
| 6 | HAUTE | Le TOTP est contourné après une connexion SSO ou LDAP | `auth.rs:337` | Fait (P1) |
| 7 | HAUTE | Argon2 n'a aucun plafond de concurrence, ce qui permet un déni de service CPU/RAM sans authentification et contourne le seuil des 5 essais | `security.rs`, `auth.rs:271` | Fait (P1) |
| 8 | HAUTE | Une seule connexion SQLite derrière un `Mutex` sérialise toutes les requêtes | `db.rs:11` | Fait (P2) |
| 9 | HAUTE | Les redirections SSO acceptent n'importe quel `*.chromiumapp.org` | `sso.rs:194` | Fait (P1) |
| 10 | HAUTE | Le verrouillage de l'extension après 15 min est fictif, et le presse-papiers n'est jamais vidé | `extension/popup.js` | Fait (P3) |
| 11 | HAUTE | Le remplissage de l'extension ignore le schéma et le port et accepte les sous-domaines dans les deux sens | `popup.js:40` | Fait (P3) |
| 12 | HAUTE | Les secrets restent en mémoire dans le client Windows : clones à chaque image et état egui | `desktop/app.rs` | Fait (P3) ; restent des copies transitoires egui et ureq, documentées |
| 13 | MOYENNE | Les migrations ne sont pas versionnées et `server.key` est rangée dans le dossier de données | `db.rs:164`, `main.rs:45` | Fait (P2) : schéma v2 versionné, clé déplaçable (`LOCKSY_SERVER_KEY_FILE`) |
| 14 | MOYENNE | La supervision se limite à `/health` : ni readiness, ni métriques, ni logs JSON ; la sauvegarde à chaud n'est pas cohérente | — | Fait (P2), sauf les métriques (pas de point `/metrics`) |
| 15 | MOYENNE | Le serveur n'a que 13 tests unitaires, aucun test HTTP, et rien n'est testé côté JS ou extension | — | Fait pour le serveur (P4 : tests HTTP) ; JS en partie (tests node du web et de l'extension) |
| 16 | MOYENNE | La documentation contredit le code : clés exportées vers JS, verrouillage de l'extension | `SECURITE.md`, `Chiffrement-et-securite.md` | Fait (P4) |

## Phases (chaque phase = un orchestrateur et des agents en parallèle sur des fichiers disjoints)

### Phase 1 : sécurité critique du serveur
- **A. Proxy et limiteur** (`state.rs`, `security.rs`, `main.rs`, `Cargo.toml` du serveur) :
  - prendre l'IP la plus à droite, ou utiliser `LOCKSY_TRUSTED_PROXIES` ;
  - ajouter un sémaphore Argon2 ;
  - ajouter HSTS, des timeouts de requête et `CatchPanicLayer`.
- **B. Authentification** (`auth.rs`, `me.rs`, `admin.rs`, écran de connexion web) :
  - jeton d'installation à usage unique pour le premier propriétaire ;
  - TOTP imposé après SSO et LDAP ;
  - compter l'essai avant le calcul Argon2 ;
  - verrouillage par paire (e-mail, IP) pour empêcher le blocage ciblé d'un compte.
- **C. Fédération** (`sso.rs`, `ldap.rs`, `scim.rs`, `admin-sso.js`, remplacé en vague 2 par `web/js/views/admin/identity/`) :
  - liste blanche des ID d'extension ;
  - `email_verified` strict ;
  - timeouts des opérations LDAP ;
  - erreurs LDAP génériques et temps de réponse constant ;
  - éviction des états SSO expirés ;
  - SCIM incapable de supprimer un admin ou un propriétaire.

**Statut P1 : fait** (A, B et C).

### Phase 2 : données et robustesse du serveur
- **A. Base** (`db.rs`, `state.rs`) :
  - migrations versionnées par `PRAGMA user_version`, avec refus d'un schéma plus récent que le binaire ;
  - WAL et pool de lecteurs avec un écrivain unique ;
  - audit envoyé au syslog après le commit.
- **B. Exploitation du serveur** (`main.rs`, `syslog.rs`, nouveaux modules) :
  - sous-commandes `backup` (`VACUUM INTO` + `integrity_check`) et `check` ;
  - `server.key` dans un emplacement dédié, écrit de façon atomique ;
  - logs JSON, identifiant de requête et `/api/ready` ;
  - arrêt gracieux en HTTP ;
  - validation de la configuration ;
  - syslog TCP+TLS.
- **C. Handlers** (`vault.rs`, `admin.rs`, `attachments.rs`, `shares.rs`) :
  - transactions sur les écritures multiples ;
  - quotas sur les pièces jointes ;
  - neutralisation de l'injection CSV ;
  - réponses `forbidden`/`not_found` uniformes.

**Statut P2 : fait** (A, B et C), plus le correctif du PUT partiel de `/admin/settings`.

### Phase 3 : clients
- **A. Windows** :
  - presse-papiers exclu de l'historique et du cloud, et vidé au verrouillage ;
  - `Zeroizing` sur les secrets et purge de l'état egui ;
  - politique machine (HKLM) pour le délai de verrouillage, l'effacement du presse-papiers et le serveur imposé ;
  - verrouillage à la session Windows ;
  - `state` du SSO loopback généré par le client ;
  - pièces jointes déchiffrées hors du dossier OneDrive ;
  - prise en charge du TOTP après SSO.
- **B. Extension** :
  - service worker avec `chrome.alarms` pour un vrai verrouillage automatique ;
  - effacement du presse-papiers ;
  - correspondance stricte (schéma, port, domaine enregistrable) ;
  - vérification de l'origine dans la page ;
  - suppression du mode « fake » en production ;
  - build reproductible avec zip et empreinte.
- **C. Web** :
  - effacement robuste du presse-papiers ;
  - épinglage des paramètres KDF (pas de rétrogradation) ;
  - confirmation des membres lors d'une rotation ;
  - focus confiné dans les modales ;
  - corrections diverses : `Bearer null`, fuite d'écouteurs ;
  - Administration > Réglages : quotas de pièces jointes (`attachment_quota_user_mb`,
    `attachment_quota_total_mb`, `attachment_max_per_item`, espace occupé `attachment_used_mb`) ;
  - message clair sur 413 `quota_exceeded` (web, extension, Windows).

**Statut P3 : fait** (A, B et C, avec l'épinglage KDF aussi sur le poste Windows et
l'épinglage des clés publiques côté web). Serveur : `client_state` du SSO de bureau accepté
et renvoyé. Reste à couvrir en recette (P4) :
- poste Windows réel : dialogue « Enregistrer sous », lecture HKLM, verrouillage à la veille
  et à Win+L, exclusion Win+V, installation en administrateur ;
- extension chargée dans un vrai Chrome ou Edge : service worker, alarmes, effacement par le
  document offscreen, `idle` « locked », remplissage sur une vraie page, SSO puis TOTP ;
- web sur un serveur P2 : PUT partiel des réglages, jauge des quotas, presse-papiers en vrai
  navigateur ;
- TOTP après SSO et LDAP avec un vrai fournisseur et un vrai annuaire.

### Phase 4 : livraison et exploitation
- **A. CI et chaîne d'approvisionnement** :
  - GitHub Actions (tests, clippy, `cargo-deny`, `cargo-audit`, SBOM CycloneDX, Trivy) ;
  - release signée (cosign/minisign) ;
  - `rust-toolchain.toml` et images Docker épinglées.
- **B. Installation et déploiement** :
  - vérification de signature et d'empreinte, y compris hors ligne ;
  - sauvegarde automatique et retour arrière lors des mises à jour ;
  - systemd durci ;
  - timer de sauvegarde ;
  - Caddy durci ;
  - archives reproductibles.
- **C. Tests** :
  - tests d'intégration HTTP (contrôle d'accès, authentification, jeton d'installation) ;
  - vecteurs de test connus : RFC 7748, RFC 5869, RFC 9106, XChaCha, format `v1` figé ;
  - squelette de fuzzing ;
  - recette Docker de bout en bout des clients (voir le statut de P3).
- **E. Reports de P3** :
  - réglage serveur « délai de verrouillage maximal des clients » diffusé dans `/sync`, pour
    piloter aussi le web (qui propose encore « Jamais ») ;
  - route dédiée « extension autorisée ? » pour éviter l'appel préalable à `/api/sso/start`.
- **D. Documentation** :
  - SECURITE.md aligné sur le code ;
  - CHANGELOG ;
  - runbook d'incident ;
  - PRA/PCA (RPO/RTO) ;
  - registre RGPD et rétention ;
  - documentation des nouvelles variables et commandes.

**Statut P4 : A, B, C et D faits** (sous réserve de l'intégration de la phase et du premier
passage réel de la CI) :
- A : `ci.yml`, `release.yml`, `dependabot.yml`, `deny.toml`, `rust-toolchain.toml`, images
  épinglées ;
- B : `install.sh` (empreinte, signature, `--version`, sauvegarde avant mise à jour,
  `--rollback`, systemd durci, timer, `--listen`, confirmation de `--purge`),
  `scripts/backup-locksy.sh`, Caddy durci, archives reproductibles ;
- C : tests HTTP du serveur, vecteurs RFC et format `v1` figé, cibles de fuzzing ;
- D : SECURITE.md et Chiffrement-et-securite.md alignés (limites connues complètes),
  SECURITY.md (signalement), CHANGELOG, Exploitation, PRA/PCA, RGPD, guides mis à jour.

Intégration P4 : défaut 1.0.0 trouvé par les tests HTTP et corrigé (2FA imposée : profil,
activation de la 2FA et déconnexion refusés au compte sans 2FA, voir CHANGELOG) ; `Db::open`
réservé aux tests et clippy `--workspace --all-targets -D warnings` bloquant en CI.

**Reste à faire.**
- **E, non traitée dans cette phase** (aucun agent n'avait les fichiers du serveur et du web) :
  - H5 : délai de verrouillage maximal des clients, réglé sur le serveur et diffusé dans
    `/sync` ; le web propose encore « Jamais » ;
  - route dédiée « extension autorisée ? » : la vérification préalable passe toujours par
    `/api/sso/start` (état en attente inutile, double comptage sur le plafond).
- **Recette réelle**, jamais faite : poste Windows (dialogue « Enregistrer sous », HKLM,
  verrouillage à la veille et à Win+L, exclusion Win+V, installation en administrateur),
  extension dans Chrome et Edge (service worker, alarmes, document offscreen, `idle`,
  remplissage, SSO puis TOTP), fournisseur d'identité et Active Directory réels, syslog
  `tcp+tls://` vers un rsyslog TLS, `install.sh` de bout en bout (natif, docker, mise à jour,
  `--rollback`).
- Reformatage `rustfmt` global, si le job `fmt` (non bloquant) le signale.
- Petites dettes : `auth.rs` et `sso.rs` lisent encore `LOCKSY_SETUP_TOKEN` et
  `LOCKSY_SSO_ALLOW_HTTP` directement (les deux sont désormais validés au démarrage) ;
  dossiers temporaires des tests non nettoyés ; pas de point `/metrics` ; pas de
  sous-commande pour effacer les secrets 2FA après une rotation de la clé serveur (requête
  SQL manuelle, voir Exploitation).

## État final après la revue transverse (17/11/2026)

**Revue du diff complet** (70 fichiers suivis modifiés et une trentaine de nouveaux) :
- contrats serveur, web, extension et poste Windows cohérents : jeton d'installation
  (`setup_token`, `setup_token_required`, `invalid_setup_token`), `totp_required` après SSO et
  LDAP (web et extension via `vault.js`, poste via `LoginOutcome::NeedTotp`),
  `allowed_extension_ids` et `trust_unverified_email` à plat dans `/admin/sso`, champs de
  quota de `/admin/settings`, `client_state` du SSO de bureau, épinglage KDF (web, extension,
  poste) ;
- compatibilité des données : migrations idempotentes v0 → v1 → v2, `serde(default)` sur tous
  les réglages enregistrés (`OrgSettings`, `SsoSettings`, `LdapConfig`, quotas, `bureau.json`),
  libellés crypto inchangés ;
- aucun secret ajouté en clair (seuls des exemples commentés dans les fichiers compose).

**Corrections de la revue** :
- un réglage JSON illisible en base est signalé au journal (ERROR) au lieu de retomber en
  silence sur les valeurs par défaut (test `reglages_lus_de_facon_tolerante`) ;
- schéma `Bearer` insensible à la casse (RFC 7235) pour l'API et SCIM (test
  `schema_bearer_insensible_a_la_casse`, vérifié aussi sur le conteneur) ;
- `LOCKSY_SSO_ALLOW_HTTP` validé au démarrage et lu comme les autres booléens ;
- journal texte sans codes ANSI hors terminal.

**Vérifications** :
- `docker build -f Dockerfile` : noyau 24 + 13 tests, serveur 162 tests, aucun échec ;
- `cargo clippy --workspace --all-targets -- -D warnings` : aucun avertissement ;
- `Dockerfile.desktop` (export) : 26 tests réussis, 3 ignorés, `locksy.exe` produit ;
- wasm `wasm32-unknown-unknown` en release : compile ;
- `node --check` sur les 24 fichiers de `web/js` et `extension/src` ; tests node : web 30/30,
  extension 26/26 ;
- conteneur : `/api/health` 200 (`needs_setup: true`), `/api/ready` 200 (schéma 2),
  inscription refusée sans jeton (403 `setup_token_required`) et avec un mauvais jeton
  (403 `invalid_setup_token`), acceptée avec le jeton de `/data/setup-token` (rôle
  `owner`), `locksy-server check` sans erreur.

**Point d'attention de compilation** : le `Dockerfile` garde `target/` dans un cache de
BuildKit. Si une source est modifiée pendant une compilation, le binaire release peut rester
périmé (empreinte cargo par date de modification). En cas de doute, `docker build --no-cache`.

**Reste à faire (code)** : phase E (H5 « délai de verrouillage maximal » diffusé dans
`/sync`, route « extension autorisée ? ») ; `cargo fmt --all` dans un commit dédié puis job
`fmt` bloquant ; `publish = false` et `wildcards = "deny"` ; rusqlite 0.41
(RUSTSEC-2026-0459) ; `[profile.test.package.argon2] opt-level = 3` ; `/metrics` ;
sous-commande `reset-2fa` ; centraliser la lecture des variables dans `config.rs` ;
bancs de performance et tests E2E navigateur (voir la spécification UX).

**Recette réelle à faire** : poste Windows, Chrome et Edge, IdP et AD réels, syslog TLS,
`install.sh` sur un hôte systemd, premier passage de la CI GitHub.

## Hors périmètre du code : actions humaines

- **Dépôt** : `__REPO__` est remplacé par `package-release.sh` à partir du dépôt qui publie ;
  pour un fork, vérifier les adresses `0x80070006/locksy` de la documentation et l'identité
  cosign (`release.yml` du bon dépôt).
- **Secrets et variables GitHub** : `MINISIGN_SECRET_KEY`, `WINDOWS_CERT_PFX`,
  `WINDOWS_CERT_PASSWORD` (secrets) ; `MINISIGN_PUBLIC_KEY`, `WINDOWS_TIMESTAMP_URL`
  (variables). Voir [Développement](Developpement.md#publier-une-version).
- **Clé minisign** : `minisign -G -W`, clé privée dans le secret, clé publique dans la variable
  et publiée (site, README) ; idéalement une clé gardée hors ligne ou dans un HSM ou KMS.
- **Certificat Authenticode** (OV ou EV) pour signer `locksy.exe`.
- **Premier passage de la CI** à valider : empreintes (SHA) des actions épinglées, règles de
  `cargo-deny` (licences et avis), résultats Trivy.
- **Version** : passer `Cargo.toml` à 1.1.0, dater le CHANGELOG, poser le tag `v1.1.0`, relire
  puis publier la release en brouillon.
- **Avant le commit de livraison** : régénérer `dist/release` avec `Dockerfile.release`
  (`dist/assets` et `locksy.wasm` datent du binaire 1.0.0), recalculer l'empreinte du zip de
  l'extension, `git update-index --chmod=+x scripts/backup-locksy.sh`, passer l'étiquette
  `locksy:1.0.0` de `docker-compose.yml` à la nouvelle version ; `install-client.ps1` sera
  converti en CRLF par git (attribut `eol=crlf`).
- **Chrome Web Store et Edge Add-ons** (compte éditeur) ; une fois l'identifiant fixé,
  l'inscrire dans `OFFICIAL_EXTENSION_IDS` (`sso.rs`) pour éviter la déclaration manuelle.
- **Audit externe** ou test d'intrusion, puis CSPN de l'ANSSI si le produit vise le secteur
  public.
- **Adresse de signalement** : remplacer `securite@<votre-domaine>` dans SECURITY.md et
  activer le signalement privé (Security > Private vulnerability reporting) sur GitHub.
- **DPO** : valider le registre [RGPD](RGPD.md) (base légale, durées, information des
  personnes) et l'AIPD.
- **Exploitant** : chiffrement des sauvegardes (destinataire age ou gpg), copie hors site,
  test de restauration trimestriel ([PRA/PCA](PRA-PCA.md)).
- **Haute disponibilité** : passage à PostgreSQL et à un limiteur partagé, à décider après la
  v1.1. SQLite mono-instance reste acceptable pour une PME avec PRA.
