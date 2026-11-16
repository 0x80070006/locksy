# API

API JSON sous `/api`, authentifiée par un jeton de session : `Authorization: Bearer <jeton>`.
Les champs `data`, `enc_name`, `*_key` sont des **chiffrés opaques** produits par le noyau
cryptographique ; un client tiers doit utiliser `locksy-core` (Rust) ou `locksy.wasm`.
Les types exacts sont dans `crates/locksy-core/src/api.rs`.

Erreurs : statut HTTP et corps `{"error": "code", "message": "texte en français"}`.

## Authentification

| Méthode | Chemin | Rôle |
|---|---|---|
| GET | `/health` | état, besoin d'installation, modes de connexion proposés |
| POST | `/auth/prelogin` | paramètres Argon2id du compte |
| POST | `/auth/register` | création de compte (premier compte, invitation ou ticket SSO) |
| POST | `/auth/login` | connexion (preuve, code TOTP, ticket SSO) |
| POST | `/auth/logout` | fin de session |
| POST | `/auth/recover/start`, `/auth/recover/finish` | récupération par clé de récupération |
| GET | `/invites/{jeton}` | informations d'une invitation |
| GET | `/sso/start`, `/sso/callback` | flux OpenID Connect |
| POST | `/sso/redeem` | informations d'un ticket SSO |
| POST | `/ldap/login` | connexion avec le compte Windows |

## Compte

| Méthode | Chemin | Rôle |
|---|---|---|
| GET, PUT | `/me` | profil |
| POST | `/me/password`, `/me/recovery` | mot de passe maître, clé de récupération |
| POST | `/me/2fa/setup`, `/me/2fa/enable`, `/me/2fa/disable` | double authentification |
| GET, DELETE | `/me/sessions`, `/me/sessions/{id}` | appareils connectés |
| GET | `/me/audit` | historique personnel |

## Coffres et éléments

| Méthode | Chemin | Rôle |
|---|---|---|
| GET | `/sync` | profil, coffres accessibles (clés scellées), éléments chiffrés |
| GET | `/directory` | personnes de l'organisation et leurs clés publiques |
| POST | `/collections` | créer un coffre |
| PUT, DELETE | `/collections/{id}` | renommer, supprimer |
| GET, POST | `/collections/{id}/members` | membres |
| PUT, DELETE | `/collections/{id}/members/{utilisateur}` | rôle, quitter |
| POST | `/collections/{id}/rotate` | retirer des membres et renouveler la clé |
| POST | `/items`, `/items/batch` | créer (un ou plusieurs) |
| PUT, DELETE | `/items/{id}` | modifier (avec révision), corbeille |
| POST | `/items/{id}/restore` | restaurer |
| DELETE | `/items/{id}/purge` | supprimer définitivement |
| PUT | `/items/{élément}/attachments/{id}` | ajouter une pièce jointe chiffrée |
| GET, DELETE | `/attachments/{id}` | télécharger, supprimer |
| GET, POST | `/shares` | liens de partage |
| DELETE | `/shares/{id}` | désactiver un lien |
| GET | `/public/shares/{id}` | consultation publique (consomme une vue) |

## Administration

| Méthode | Chemin | Rôle |
|---|---|---|
| GET | `/admin/stats` | vue d'ensemble |
| GET | `/admin/users` | comptes |
| PUT, DELETE | `/admin/users/{id}` | rôle, désactivation, suppression |
| POST | `/admin/users/{id}/reset-2fa`, `/admin/users/{id}/revoke-sessions` | 2FA, sessions |
| GET, POST | `/admin/invites` | invitations |
| DELETE | `/admin/invites/{id}` | révoquer |
| GET | `/admin/audit`, `/admin/audit.csv` | journal (filtres `q`, `action`, `from`, `to`, `limit`, `offset`) |
| GET, PUT | `/admin/settings` | règles de sécurité |
| GET, PUT | `/admin/sso` · POST `/admin/sso/test` | OpenID Connect |
| GET, PUT | `/admin/ldap` · POST `/admin/ldap/test`, `/admin/ldap/sync` | Active Directory |
| GET | `/admin/scim` · POST, DELETE `/admin/scim/token` · GET `/admin/directory` | SCIM |

## SCIM

Sous `/scim/v2`, jeton porteur dédié : voir [SSO et SCIM](SSO-et-SCIM).
