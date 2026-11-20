# API

API JSON sous `/api`, authentifiée par un jeton de session : `Authorization: Bearer <jeton>`.
Les champs `data`, `enc_name`, `cipher`, `*_key` sont des **chiffrés opaques** produits par le
noyau cryptographique ; un client tiers doit utiliser `locksy-core` (Rust) ou `locksy.wasm`.
Les types exacts sont dans `crates/locksy-core/src/api.rs` et `admin_api.rs`.

Refus par défaut : toute route hors des routes publiques (santé, connexion, inscription,
récupération, invitation, connexion d'entreprise, liens publics, réglages publics, logo)
répond `401 unauthorized` sans en-tête `Authorization: Bearer`, avant tout traitement. Une
route inconnue sous `/api` répond `404 not_found` en JSON.

Toutes les réponses de l'API portent `Cache-Control: no-store`. Erreurs : statut HTTP et corps
`{"error": "code", "message": "texte en français"}`, parfois avec des champs en plus
(`fields`, `retry_after`, `reason`, `max_minutes`…). Les réponses 429 et 503 portent l'en-tête
`Retry-After` (secondes) et le champ `retry_after`. Chaque réponse porte un en-tête
`X-Request-Id` (repris de la requête s'il fait 1 à 64 caractères `A-Z a-z 0-9 . _ : -`,
sinon généré) à citer en cas d'incident. Les champs ajoutés au fil des versions ne retirent
jamais rien : un client plus ancien les ignore.

Chaque code d'erreur a sa traduction dans `design/i18n/fr/errors.*.json` (contrôlé par
`node --test tools/test`). Codes notables :

| Statut | Code | Cas |
|---|---|---|
| 400 | `bad_request`, `invalid_settings` | requête invalide, réglage hors registre ou hors bornes (`fields`) |
| 400, 415 | `invalid_body` | corps illisible : JSON invalide, champ manquant ou de mauvais type (400), corps qui n'est pas du JSON (415) |
| 401 | `unauthorized`, `invalid_credentials` | session absente ou expirée, identifiants refusés |
| 401 | `totp_required`, `invalid_totp` | code de vérification (ou code de secours) à fournir, code incorrect |
| 403 | `forbidden`, `owner_only` | rôle insuffisant ; action réservée aux propriétaires |
| 403 | `account_disabled`, `account_expired` | compte désactivé ; date de fin d'accès passée (connexion, récupération, et toute requête d'une session ouverte : la session est alors fermée) |
| 403 | `2fa_required`, `sso_required`, `ip_not_allowed`, `domain_not_allowed` | 2FA imposée, connexion d'entreprise imposée, réseau non autorisé, domaine d'adresse refusé |
| 403 | `reauth_invalid` | jeton de confirmation d'identité faux, périmé, déjà utilisé ou d'une autre action |
| 403 | `share_disabled`, `attachments_disabled`, `personal_vault_disabled`, `shared_vault_creation_disabled`, `export_disabled`, `item_not_shareable` | fonction désactivée par l'organisation |
| 404 | `not_found` | objet inexistant **ou** inaccessible (même réponse) ; identifiant de chemin mal formé |
| 408 | — | requête plus longue que `LOCKSY_REQUEST_TIMEOUT_SECS` |
| 409 | `conflict`, `settings_conflict`, `prefs_conflict` | révision périmée (`If-Match`) |
| 409 | `rekey_required` | clé du coffre renouvelée entre-temps (`collection_id`, `key_version`) : resynchroniser puis renvoyer |
| 409 | `totp_unreadable` | secret 2FA illisible avec la clé serveur actuelle (`server.key` changée) : la 2FA doit être réinitialisée par un administrateur |
| 409 | `last_owner`, `self_action`, `test_required`, `too_many_deprovisions`, `password_changed_concurrently`, `recovery_already_used`, `totp_not_enabled`, `mail_disabled` | garde-fous métier |
| 410 | `share_ended` | lien terminé (`reason` : revoked, revoked_admin, expired, exhausted, item_deleted, access_lost, owner_disabled, rotated ; `ended_at`) |
| 413 | `quota_exceeded`, `attachment_too_large`, `too_large`, `payload_too_large` | quota atteint, fichier trop gros, document de préférences de plus de 64 Kio, corps de requête au-delà de `LOCKSY_MAX_BODY_MIB` |
| 422 | `share_limit`, `attachment_limit`, `kdf_too_weak`, `ssrf_blocked`, `smtp_insecure`, `not_a_member` | limites et refus de configuration |
| 428 | `reauth_required`, `precondition_required` | confirmation d'identité (`X-Locksy-Reauth`) ou `If-Match` exigés |
| 429 | `rate_limited` | trop de tentatives (`Retry-After`) |
| 500 | `internal` | erreur interne, sans détail (voir le journal avec le `X-Request-Id`) |
| 502 | `email_not_sent` | envoi SMTP refusé (`error_code` : smtp_connect, smtp_tls, smtp_auth, smtp_rejected, smtp_timeout) |
| 503 | `server_busy`, `not_ready`, `ldap_unavailable`, `sso_busy`, `audit_chain_unavailable` | réessayer après `Retry-After` |

Les clients JavaScript ajoutent des codes locaux, sans statut HTTP (statut 0) :
`network`, `kdf_downgrade` (paramètres de dérivation plus faibles que ceux épinglés),
`wrong_password` et `key_mismatch` (clé publique annoncée différente de la clé privée).

Les contrôles d'accès, l'authentification et les codes d'erreur sont couverts par des tests
HTTP de bout en bout du serveur (`crates/locksy-server/src/http_tests.rs` et
`crates/locksy-server/src/tests/`), lancés par la CI.

## Confirmation d'identité (actions sensibles)

Une action sensible exige l'en-tête `X-Locksy-Reauth: rt1.<jeton>`, obtenu par
`POST /auth/reauth` `{ action, auth_key, totp? }` → `{ token, expires_in: 120, action }`.
Le jeton est lié au compte, à la session et à l'action, valable 120 s et à usage unique.
Actions : `settings`, `admin.role`, `admin.offboard`, `admin.delete_user`, `admin.reset_2fa`,
`admin.bulk`, `scim.token`, `vault.export`, `totp.disable`, `totp.recovery_codes`,
`recovery.rotate`. Le second facteur (code ou code de secours) est exigé pour les quatre
dernières quand le compte a la 2FA. Sans en-tête : 428 `reauth_required`. Compatibilité :
pour l'action `settings` seulement, l'en-tête peut porter la forme historique (base64 de
`auth_key`). Cinq preuves refusées, puis 429.

## Authentification

| Méthode | Chemin | Rôle |
|---|---|---|
| GET | `/health` | état, besoin d'installation, modes de connexion proposés |
| GET | `/ready` | disponibilité : 200 `{"status":"ready","version","schema_version"}`, 503 `not_ready` |
| GET | `/settings/public` | réglages publics (connexion, KDF, politique du mot de passe maître, habillage) |
| POST | `/auth/prelogin` | paramètres Argon2id du compte (réponse indiscernable pour une adresse inconnue) |
| POST | `/auth/register` | création de compte (premier compte, invitation ou ticket SSO) ; planchers `kdf.min_*` (422 `kdf_too_weak`) |
| POST | `/auth/login` | connexion (preuve, code TOTP **ou code de secours**, ticket SSO) ; blocage progressif `lockout.*` |
| POST | `/auth/logout` | fin de session |
| POST | `/auth/reauth` | jeton de confirmation d'identité (ci-dessus) |
| POST | `/auth/recover/start`, `/auth/recover/finish` | récupération par clé de récupération ; `finish` répond 200 `{user_id}` et est idempotente 10 min (409 `recovery_already_used` pour une autre demande) |
| GET | `/invites/{jeton}` | informations d'une invitation |
| GET | `/sso/start`, `/sso/callback` | flux OpenID Connect ; `target=web` (défaut), `target=desktop&port=<p>&client_state=<cs>` (`cs` : 16 à 128 caractères `[A-Za-z0-9_-]`, renvoyé avec `ticket` ou `error` sur `http://127.0.0.1:<p>/sso`), `target=extension&redirect=<url>` |
| POST | `/sso/redeem` | informations d'un ticket SSO |
| POST | `/ldap/login` | connexion avec le compte Windows |
| GET | `/extension/allowed?id=<id>` | `{ allowed }` : l'extension est-elle autorisée par l'organisation |

## Compte

| Méthode | Chemin | Rôle |
|---|---|---|
| GET, PUT | `/me` | profil |
| POST | `/me/password` | mot de passe maître : 403 si la preuve actuelle est refusée ; `totp` exigé dans le corps si la 2FA est active ; 409 `password_changed_concurrently` |
| POST | `/me/recovery` | nouvelle clé de récupération (`totp` exigé si 2FA) |
| POST | `/me/kdf` | montée des paramètres de dérivation du client (`kdf.upgrade_on_login`) ; jamais une baisse (422) |
| POST | `/me/export` | trace d'un export (jeton `vault.export`) avant le fichier ; 403 `export_disabled` |
| POST | `/me/2fa/setup`, `/me/2fa/enable`, `/me/2fa/disable` | double authentification ; `enable` renvoie aussi `recovery_codes` (10 codes) |
| GET, POST | `/me/2fa/recovery-codes` | codes de secours : `{remaining, total, generated_at}` ; régénération (jeton `totp.recovery_codes`) |
| GET, PUT | `/me/prefs` | préférences chiffrées (AAD `verrou:v1:prefs:<id>`), `If-Match`, 64 Kio au plus |
| GET, POST | `/me/charter` | charte d'utilisation : état, acceptation |
| GET, DELETE | `/me/sessions`, `/me/sessions/{id}` | appareils connectés |
| GET | `/me/audit` | historique personnel |
| GET | `/settings/policy` | politique effective du client (valeurs, modes, bornes ; `ETag`) |

## Coffres et éléments

| Méthode | Chemin | Rôle |
|---|---|---|
| GET | `/sync` | profil, coffres accessibles (clés scellées), éléments chiffrés |
| GET | `/sync?since=<seq>` | synchronisation partielle : changements depuis `seq`, `removed: {items, collections}` ; `full: true` si la position est trop ancienne. Toujours : `seq`, `policy_revision`, `prefs_revision` ; coffres avec `key_version` et `rotation_suggested_at` ; éléments avec `deleted_by` et `purge_at` |
| GET | `/directory` | personnes de l'organisation et leurs clés publiques |
| POST | `/collections` | créer un coffre (403 `shared_vault_creation_disabled` selon le réglage) |
| PUT, DELETE | `/collections/{id}` | renommer, supprimer |
| GET, POST | `/collections/{id}/members` | membres |
| PUT, DELETE | `/collections/{id}/members/{utilisateur}` | rôle, quitter |
| POST | `/collections/{id}/rotate` | retirer des membres et renouveler la clé |
| POST | `/items`, `/items/batch` | créer (un ou plusieurs) ; `key_version` facultatif (409 `rekey_required`) |
| PUT, DELETE | `/items/{id}` | modifier (avec révision et `key_version`), corbeille |
| POST | `/items/{id}/restore` | restaurer |
| DELETE | `/items/{id}/purge` | supprimer définitivement |
| PUT | `/items/{élément}/attachments/{id}` | ajouter une pièce jointe chiffrée (`data`, `size` en octets clairs) ; corps jusqu'à environ 21 Mo, taille réelle bornée par `attachment.max_file_mib` |
| GET, DELETE | `/attachments/{id}` | télécharger, supprimer |
| GET, POST | `/shares` | liens de partage ; POST `{data, expires_in_minutes, max_views, verifier?, item_id?, collection_id?}` ; GET `?all=1` : tous les liens avec `state`, `ended_reason`, `item_id`, `has_verifier` |
| DELETE | `/shares/{id}` | révoquer un lien (idempotent) |
| POST | `/public/shares/{id}/peek` | état d'un lien avec preuve de possession `{proof}` : `{state, expires_at, views_left}` |
| POST | `/public/shares/{id}/open` | ouverture `{proof, nonce}` : `{data, expires_at, views_left, replayed}` (même nonce : sans décompte) |
| GET | `/public/shares/{id}` | ouverture d'un lien historique sans vérificateur (consomme une vue) |

Preuve de possession d'un lien : `proof` = base64 URL sans bourrage de SHA-256 du fragment
du lien ; le serveur ne garde que `verifier` = hex SHA-256 de la preuve, comparée en temps
constant avant toute lecture du chiffré. Preuve fausse et lien inconnu : même 404.

## Administration

Toutes ces routes exigent le rôle administrateur ou propriétaire.

| Méthode | Chemin | Rôle |
|---|---|---|
| GET | `/admin/stats` | vue d'ensemble (comptes actifs, 2FA, invitations, liens actifs, dernière synchro de l'annuaire, étapes de mise en route) |
| GET | `/admin/people` | personnes et invitations : filtres `q`, `etat`, `role`, `2fa`, `origine`, tri `tri`, pages `page`, `par_page` |
| GET, PATCH | `/admin/users/{id}` | fiche (sessions, coffres, événements récents) ; nom, adresse, date de fin d'accès |
| PUT, DELETE | `/admin/users/{id}` | rôle (élévation : jeton `admin.role`), désactivation ; suppression (jeton `admin.delete_user`) |
| POST | `/admin/users/bulk` | action groupée (`disable`, `enable`, `revoke_sessions`, `reset_2fa`, `set_role`) : `{done, skipped:[{id, reason}]}` |
| DELETE | `/admin/users/{id}/sessions/{session}` | fermer une session |
| POST | `/admin/users/{id}/reset-2fa`, `/admin/users/{id}/revoke-sessions` | 2FA (jeton `admin.reset_2fa`), sessions |
| GET | `/admin/users/{id}/offboard-plan` | préparation d'un départ (coffres, membres, seul gestionnaire) |
| POST | `/admin/users/{id}/offboard?dry_run=true\|false` | départ : désactivation, transferts, rotation conseillée, suppression différée (réel : jeton `admin.offboard`) |
| GET | `/admin/users/{id}/access-report.csv` | rapport d'accès (identifiants de coffres, jamais de nom) |
| POST | `/admin/shares/revoke` | révoquer les liens d'un compte `{owner_id}` → `{revoked}` |
| GET, POST | `/admin/invites` | invitations |
| POST | `/admin/invites/batch` | jusqu'à 200 invitations : `{created, skipped}` |
| POST | `/admin/invites/{id}/resend` | renvoyer (nouveau jeton) |
| DELETE | `/admin/invites/{id}` | révoquer |
| GET | `/admin/audit`, `/admin/audit.csv` | journal (filtres `q`, `action`, `from`, `to`, `severity`, `actor`, `type`, `limit`, `offset`, curseur `before_id`) ; CSV avec BOM, séparateur `audit.csv_separator` |
| GET | `/admin/audit/verify` | vérification du chaînage du journal : `{ok, checked, anchors, breaks:[{id, kind}], unchained_before}` |
| GET, PATCH | `/admin/settings` | registre des réglages (`ETag`, `If-Match` obligatoire en PATCH ; abaissement : jeton `settings`) ; PUT historique (5 champs) gardé une version |
| GET | `/admin/settings/schema` | registre : clés, types, bornes, sections, profils |
| POST | `/admin/settings/validate`, `/admin/settings/reset`, `/admin/settings/profile` | essai à blanc, retour aux défauts, profil de sécurité |
| GET | `/admin/settings/history` · POST `/admin/settings/revert/{révision}` | historique, retour à une version |
| GET | `/admin/settings/export` · POST `/admin/settings/import` | export et import des réglages |
| GET | `/admin/config/effective` | configuration de l'hébergeur (variables, secrets masqués) |
| GET, PUT | `/admin/sso` · POST `/admin/sso/test`, `/admin/sso/test-start` | OpenID Connect ; test réel avec son propre compte (`imposé` exige un test réussi de moins de 24 h : 409 `test_required`) |
| GET, PUT | `/admin/ldap` · POST `/admin/ldap/test`, `/admin/ldap/test-login` | Active Directory ; test avec son compte Windows |
| POST | `/admin/ldap/sync?dry_run=true\|false` · GET `/admin/ldap/history` | synchronisation (à blanc : aucune écriture, comptes ignorés avec leur raison) et historique |
| GET | `/admin/identity/status` | état de la connexion d'entreprise (SSO, annuaire, SCIM) |
| GET | `/admin/scim` · POST, DELETE `/admin/scim/token` · GET `/admin/directory` | SCIM (régénération : jeton `scim.token`) |
| POST | `/admin/mail/test` | e-mail de test immédiat : `{sent}` ou 502 `email_not_sent` |
| GET | `/admin/mail/queue?status=` · POST `/admin/mail/queue/{id}/retry` | file d'e-mails (adresses masquées, jamais le corps) |
| GET | `/branding/logo` | logo de l'organisation (public) |

## SCIM

Sous `/scim/v2`, jeton porteur dédié : voir [SSO et SCIM](SSO-et-SCIM.md).
