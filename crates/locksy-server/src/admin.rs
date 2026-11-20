//! Administration : comptes, invitations, journal d'audit, réglages.
//! Les administrateurs gèrent les accès sans jamais pouvoir lire un secret.
//!
//! Garde-fous communs à toutes les actions sur un compte (ici et dans
//! `admin_people`) : un administrateur n'agit que sur les simples
//! utilisateurs (403 `owner_only`), personne ne se désactive, ne se supprime
//! ni ne se rétrograde soi-même (409 `self_action`), et l'organisation garde
//! toujours un propriétaire actif (409 `last_owner`). Les actions sensibles
//! exigent une confirmation d'identité récente (428 `reauth_required`).

use crate::attachments::{load_quotas, to_mb, used_total, AttachmentQuotas, QUOTAS_KEY};
use crate::db::{self, load_settings};
use crate::error::{ApiError, ApiResult};
use crate::mail::{Notification, Notifier, NotifyOutcome};
use crate::security::{self as sec, sha256_hex};
use crate::state::{audit_user, AdminUser, AppState, AuthUser};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use crate::error::Json;
use locksy_core::admin_api::{self as aa, bulk, AuditRow, AuditRows, LdapSyncSummary, SetupProgress, StatsExtra};
use locksy_core::api::roles::{ADMIN, OWNER, USER};
use locksy_core::api::*;
use locksy_core::crypto::{new_uuid, random_token};
use locksy_core::now_unix;
use locksy_core::settings::Effective;
use rusqlite::types::Value as SqlValue;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

pub fn audit_row(r: &Row) -> rusqlite::Result<AuditEntry> {
    Ok(AuditEntry {
        id: r.get(0)?,
        at: r.get(1)?,
        user_id: r.get(2)?,
        email: r.get(3)?,
        action: r.get(4)?,
        target: r.get(5)?,
        ip: r.get(6)?,
        user_agent: r.get(7)?,
        details: r.get(8)?,
    })
}

// ------------------------------------------------------------ Fragments SQL communs

/// Compte actif (alias `u`, `?1` = maintenant) : ni désactivé, ni arrivé à
/// sa date de fin d'accès.
pub(crate) const ACTIVE_SQL: &str = "u.disabled = 0 AND (u.access_until IS NULL OR u.access_until > ?1)";

/// Dernière activité d'un compte (alias `u`) : dernière connexion ou dernier
/// passage d'une session ouverte ; NULL s'il ne s'est jamais connecté.
pub(crate) const SEEN_SQL: &str = "NULLIF(MAX(COALESCE(u.last_login_at, 0),
    COALESCE((SELECT MAX(s.last_seen_at) FROM sessions s WHERE s.user_id = u.id), 0)), 0)";

/// Conditions SQL assemblées avec leurs paramètres positionnels (`?`).
#[derive(Default)]
pub(crate) struct Filter {
    conds: Vec<String>,
    pub(crate) args: Vec<SqlValue>,
}

impl Filter {
    /// Ajoute une condition ; chaque `?` de `cond` prend la valeur suivante.
    pub(crate) fn push(&mut self, cond: impl Into<String>, args: impl IntoIterator<Item = SqlValue>) {
        self.conds.push(cond.into());
        self.args.extend(args);
    }

    /// Clause `WHERE …` (vide sans condition).
    pub(crate) fn sql(&self) -> String {
        if self.conds.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", self.conds.join(" AND "))
        }
    }
}

/// Motif LIKE « contient » (`%`, `_` et `\` neutralisés ; `ESCAPE '\'`).
pub(crate) fn like_contains(s: &str) -> SqlValue {
    SqlValue::Text(format!("%{}%", like_escape(s)))
}

fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
}

pub(crate) fn text(s: &str) -> SqlValue {
    SqlValue::Text(s.to_string())
}

// ------------------------------------------------------------ Statistiques

/// `GET /admin/stats` : statistiques historiques, plus les champs de
/// l'annexe A.9 (aplatis).
#[derive(Serialize, Debug)]
pub struct StatsOut {
    #[serde(flatten)]
    pub base: AdminStats,
    #[serde(flatten)]
    pub extra: StatsExtra,
}

pub async fn stats(State(state): State<AppState>, AdminUser(admin): AdminUser) -> ApiResult<Json<StatsOut>> {
    let eff = state.effective().await?;
    let inactive_days = eff.int("users.inactive_alert_days");
    let siem_configured = !eff.str("audit.syslog.url").trim().is_empty();
    let scim_ttl = eff.int("scim.token_ttl_days");
    let me = admin.id;
    Ok(Json(
        state
            .db
            .read(move |c| {
                let now = now_unix();
                // `at` : requête paramétrée par l'instant présent (`?1`).
                let at = |sql: &str| -> rusqlite::Result<i64> { c.query_row(sql, [now], |r| r.get(0)) };
                let one = |sql: &str| -> rusqlite::Result<i64> { c.query_row(sql, [], |r| r.get(0)) };
                let exists = |sql: &str| -> rusqlite::Result<bool> { c.query_row(sql, [], |r| r.get(0)) };
                // Taux de double authentification sur les comptes actifs
                // seulement : le numérateur ne dépasse jamais le dénominateur.
                let active_users = at(&format!("SELECT COUNT(*) FROM users u WHERE {ACTIVE_SQL}"))?;
                let active_with_2fa =
                    at(&format!("SELECT COUNT(*) FROM users u WHERE {ACTIVE_SQL} AND u.totp_secret IS NOT NULL"))?;
                let active_shares = at(
                    "SELECT COUNT(*) FROM shares WHERE state = 'active' AND expires_at > ?1 AND views < max_views",
                )?;
                let owners = at(&format!("SELECT COUNT(*) FROM users u WHERE {ACTIVE_SQL} AND u.role = 'owner'"))?;
                let inactive_before = now - inactive_days * 86_400;
                let inactive_users = c.query_row(
                    &format!("SELECT COUNT(*) FROM users u WHERE {ACTIVE_SQL} AND COALESCE({SEEN_SQL}, u.created_at) < ?2"),
                    params![now, inactive_before],
                    |r| r.get(0),
                )?;
                let last_ldap_sync = c
                    .query_row(
                        "SELECT at, error_code IS NULL, found FROM ldap_sync_history WHERE dry_run = 0 ORDER BY id DESC LIMIT 1",
                        [],
                        |r| Ok(LdapSyncSummary { at: r.get(0)?, ok: r.get(1)?, found: r.get(2)? }),
                    )
                    .optional()?;
                let setup = SetupProgress {
                    second_owner: owners >= 2,
                    twofa_self: c.query_row("SELECT totp_secret IS NOT NULL FROM users WHERE id = ?1", [&me], |r| r.get(0))?,
                    login_method_chosen: exists(
                        "SELECT EXISTS (SELECT 1 FROM settings_history
                                         WHERE key IN ('auth.primary_method', 'sso.enforce', 'ldap.enforce'))
                             OR EXISTS (SELECT 1 FROM identity_tests WHERE ok = 1)",
                    )?,
                    profile_chosen: exists(
                        "SELECT EXISTS (SELECT 1 FROM settings_history WHERE source = 'profile')
                             OR EXISTS (SELECT 1 FROM audit WHERE action = 'settings.profile_applied')",
                    )?,
                    invites_sent: exists("SELECT EXISTS (SELECT 1 FROM invites)")?,
                    extension_seen: exists(
                        "SELECT EXISTS (SELECT 1 FROM sessions WHERE device LIKE 'Extension%')
                             OR EXISTS (SELECT 1 FROM audit WHERE action = 'login.success' AND details LIKE 'Extension%')",
                    )?,
                    siem_configured,
                };
                let base = AdminStats {
                    users: one("SELECT COUNT(*) FROM users")?,
                    active_users,
                    // Historique : désormais limité aux comptes actifs (le
                    // taux affiché par les anciens écrans reste ≤ 100 %).
                    users_with_2fa: active_with_2fa,
                    collections: one("SELECT COUNT(*) FROM collections")?,
                    shared_collections: one(
                        "SELECT COUNT(*) FROM collections c
                         WHERE (SELECT COUNT(*) FROM memberships m WHERE m.collection_id = c.id) > 1",
                    )?,
                    items: one("SELECT COUNT(*) FROM items WHERE deleted_at IS NULL")?,
                    active_shares,
                    failed_logins_24h: c.query_row(
                        "SELECT COUNT(*) FROM audit WHERE action = 'login.failed' AND at > ?1",
                        [now - 86_400],
                        |r| r.get(0),
                    )?,
                };
                let extra = StatsExtra {
                    active_with_2fa,
                    admins_without_2fa: at(&format!(
                        "SELECT COUNT(*) FROM users u WHERE {ACTIVE_SQL} AND u.role IN ('owner', 'admin') AND u.totp_secret IS NULL"
                    ))?,
                    owners,
                    inactive_users,
                    pending_invites: at("SELECT COUNT(*) FROM invites WHERE used_at IS NULL AND expires_at > ?1")?,
                    expired_invites: at("SELECT COUNT(*) FROM invites WHERE used_at IS NULL AND expires_at <= ?1")?,
                    active_share_links: active_shares,
                    last_ldap_sync,
                    // Dernière utilisation enregistrée du jeton ; à défaut
                    // (jeton d'avant ce suivi), dernière opération SCIM du journal.
                    scim_last_used_at: match crate::scim::token_info(c, scim_ttl)?.and_then(|t| t.last_used_at) {
                        Some(t) => Some(t),
                        None => c.query_row("SELECT MAX(at) FROM audit WHERE substr(action, 1, 5) = 'scim.'", [], |r| r.get(0))?,
                    },
                    // Aucune trace des sauvegardes (commande hors serveur).
                    last_backup_at: None,
                    pending_deprovision: one("SELECT COUNT(*) FROM users WHERE deprovision_at IS NOT NULL")?,
                    setup,
                };
                Ok(StatsOut { base, extra })
            })
            .await?,
    ))
}

pub async fn list_users(State(state): State<AppState>, _admin: AdminUser) -> ApiResult<Json<Vec<AdminUser2>>> {
    Ok(Json(
        state
            .db
            .read(|c| {
                let mut st = c.prepare(
                    "SELECT u.id, u.email, u.name, u.role, u.disabled, u.totp_secret IS NOT NULL, u.created_at, u.last_login_at,
                            (SELECT COUNT(*) FROM memberships m WHERE m.user_id = u.id)
                     FROM users u ORDER BY u.name COLLATE NOCASE",
                )?;
                let rows = st
                    .query_map([], |r| {
                        Ok(locksy_core::api::AdminUser {
                            id: r.get(0)?,
                            email: r.get(1)?,
                            name: r.get(2)?,
                            role: r.get(3)?,
                            disabled: r.get(4)?,
                            totp_enabled: r.get(5)?,
                            created_at: r.get(6)?,
                            last_login_at: r.get(7)?,
                            collections: r.get(8)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?,
    ))
}

pub type AdminUser2 = locksy_core::api::AdminUser;

// ------------------------------------------------------------ Garde-fous

/// Compte visé par une action d'administration.
#[derive(Debug, Clone)]
pub(crate) struct Target {
    pub email: String,
    pub name: String,
    pub role: String,
    pub disabled: bool,
    pub twofa: bool,
}

pub(crate) fn find_target(c: &Connection, id: &str) -> ApiResult<Option<Target>> {
    Ok(c.query_row(
        "SELECT email, name, role, disabled, totp_secret IS NOT NULL FROM users WHERE id = ?1",
        [id],
        |r| Ok(Target { email: r.get(0)?, name: r.get(1)?, role: r.get(2)?, disabled: r.get(3)?, twofa: r.get(4)? }),
    )
    .optional()?)
}

/// Compte visé, ou 404.
pub(crate) fn target(c: &Connection, id: &str) -> ApiResult<Target> {
    find_target(c, id)?.ok_or_else(|| ApiError::not_found("Utilisateur introuvable."))
}

/// Le compte `id` est-il le seul propriétaire actif ? (Vrai aussi s'il n'en
/// reste aucun autre : l'organisation ne doit jamais en manquer.)
pub(crate) fn is_last_owner(c: &Connection, id: &str) -> ApiResult<bool> {
    let others: i64 = c.query_row(
        "SELECT COUNT(*) FROM users WHERE role = 'owner' AND disabled = 0 AND id <> ?1",
        [id],
        |r| r.get(0),
    )?;
    Ok(others == 0)
}

/// Action d'administration sur un compte, pour les garde-fous communs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Act<'a> {
    Disable,
    Enable,
    Delete,
    SetRole(&'a str),
    /// Sessions, double authentification, fiche : sans effet sur les droits.
    Touch,
}

/// Refus d'une action (raisons ignorées de `POST /admin/users/bulk`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    SelfAction,
    OwnerOnly,
    LastOwner,
}

impl Refusal {
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Refusal::SelfAction => bulk::SKIP_SELF,
            Refusal::OwnerOnly => bulk::SKIP_OWNER_ONLY,
            Refusal::LastOwner => bulk::SKIP_LAST_OWNER,
        }
    }

    pub(crate) fn error(self) -> ApiError {
        match self {
            Refusal::SelfAction => {
                self_action("Cette action n'est pas possible sur votre propre compte. Demandez-la à un autre administrateur.")
            }
            Refusal::OwnerOnly => owner_only(),
            Refusal::LastOwner => last_owner(),
        }
    }
}

/// Garde-fous d'une action de `actor` sur le compte `id` (rôle `target_role`).
pub(crate) fn refusal(c: &Connection, actor: &AuthUser, id: &str, target_role: &str, act: Act) -> ApiResult<Option<Refusal>> {
    let changes_rights = matches!(act, Act::Disable | Act::Delete | Act::SetRole(_));
    if id == actor.id && changes_rights {
        return Ok(Some(Refusal::SelfAction));
    }
    // Seul un propriétaire agit sur un administrateur ou un propriétaire,
    // et nomme un administrateur ou un propriétaire.
    let elevates = matches!(act, Act::SetRole(r) if r != USER);
    if actor.role != OWNER && (target_role != USER || elevates) {
        return Ok(Some(Refusal::OwnerOnly));
    }
    let loses_owner = match act {
        Act::Disable | Act::Delete => true,
        Act::SetRole(r) => r != OWNER,
        Act::Enable | Act::Touch => false,
    };
    if loses_owner && target_role == OWNER && is_last_owner(c, id)? {
        return Ok(Some(Refusal::LastOwner));
    }
    Ok(None)
}

/// Garde-fous sous forme d'erreur (actions unitaires).
pub(crate) fn guard(c: &Connection, actor: &AuthUser, id: &str, target_role: &str, act: Act) -> ApiResult<()> {
    match refusal(c, actor, id, target_role, act)? {
        Some(r) => Err(r.error()),
        None => Ok(()),
    }
}

fn rank(role: &str) -> u8 {
    match role {
        OWNER => 2,
        ADMIN => 1,
        _ => 0,
    }
}

/// Passage à un rôle plus élevé (confirmation d'identité « admin.role »).
pub(crate) fn is_elevation(from: &str, to: &str) -> bool {
    rank(to) > rank(from)
}

/// 403 : action réservée aux propriétaires.
pub(crate) fn owner_only() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "owner_only",
        "Seul un propriétaire peut gérer un administrateur ou un propriétaire, ou nommer un administrateur.",
    )
}

/// 409 : l'organisation garde toujours au moins un propriétaire actif.
pub(crate) fn last_owner() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        "last_owner",
        "L'organisation doit garder au moins un propriétaire actif.",
    )
}

/// 409 : action interdite sur son propre compte.
pub(crate) fn self_action(message: &str) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, "self_action", message.to_string())
}

/// 409 : le compte a changé entre la vérification et l'enregistrement.
fn changed_meanwhile() -> ApiError {
    ApiError::conflict("Ce compte a été modifié entre-temps. Rechargez la page puis réessayez.")
}

// ------------------------------------------------------------ Comptes

pub async fn update_user(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<UpdateUserRequest>,
) -> ApiResult<StatusCode> {
    sec::uuid_path(&id, "Utilisateur")?;
    if let Some(r) = &req.role {
        if !roles::ORG_ROLES.contains(&r.as_str()) {
            return Err(ApiError::bad_request("Rôle inconnu."));
        }
    }
    // Contrôles avant la confirmation d'identité : un refus ne consomme pas
    // le jeton de réauthentification.
    let (a, i, r) = (admin.clone(), id.clone(), req.clone());
    let elevation = state
        .db
        .read(move |c| {
            let t = target(c, &i)?;
            check_update(c, &a, &i, &t, &r)?;
            Ok(r.role.as_deref().is_some_and(|new| is_elevation(&t.role, new)))
        })
        .await?;
    if elevation {
        sec::require_step_up(&state, &admin, &headers, "admin.role").await?;
    }
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let t = target(&tx, &id)?;
            check_update(&tx, &admin, &id, &t, &req)?;
            if let Some(new_role) = req.role.as_deref().filter(|r| *r != t.role) {
                if is_elevation(&t.role, new_role) && !elevation {
                    return Err(changed_meanwhile());
                }
                tx.execute("UPDATE users SET role = ?1, updated_at = ?2 WHERE id = ?3", params![new_role, now_unix(), id])?;
                audit_user(&tx, &admin, "admin.user_role", &t.email, &format!("{} → {new_role}", t.role))?;
            }
            if let Some(disabled) = req.disabled.filter(|d| *d != t.disabled) {
                // Accès coupé immédiatement, sur tous les appareils.
                set_disabled(&tx, &id, &t.role, disabled)?;
                audit_user(&tx, &admin, if disabled { "admin.user_disabled" } else { "admin.user_enabled" }, &t.email, "")?;
            }
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn check_update(c: &Connection, admin: &AuthUser, id: &str, t: &Target, req: &UpdateUserRequest) -> ApiResult<()> {
    if let Some(new_role) = req.role.as_deref().filter(|r| *r != t.role) {
        guard(c, admin, id, &t.role, Act::SetRole(new_role))?;
    }
    match req.disabled {
        Some(true) => guard(c, admin, id, &t.role, Act::Disable),
        Some(false) => guard(c, admin, id, &t.role, Act::Enable),
        None => guard(c, admin, id, &t.role, Act::Touch),
    }
}

/// Supprime un compte (administration ou SCIM). Renvoie le nombre de coffres
/// devenus sans membre, donc détruits.
pub fn remove_user(tx: &Connection, id: &str, role: &str) -> ApiResult<usize> {
    if role == OWNER && is_last_owner(tx, id)? {
        return Err(last_owner());
    }
    // Coffres dont cette personne est le seul gestionnaire et qui ont d'autres
    // membres : on promeut le membre le plus ancien.
    let orphaned: Vec<String> = tx
        .prepare(
            "SELECT m.collection_id FROM memberships m
             WHERE m.user_id = ?1 AND m.role = 'manager'
               AND (SELECT COUNT(*) FROM memberships x WHERE x.collection_id = m.collection_id AND x.role = 'manager') = 1",
        )?
        .query_map([id], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    for cid in &orphaned {
        tx.execute(
            "UPDATE memberships SET role = 'manager' WHERE collection_id = ?1 AND user_id = (
                SELECT user_id FROM memberships WHERE collection_id = ?1 AND user_id <> ?2 ORDER BY created_at LIMIT 1)",
            params![cid, id],
        )?;
    }
    tx.execute("DELETE FROM users WHERE id = ?1", [id])?;
    // Coffres sans plus aucun membre : personne ne peut plus les lire.
    Ok(tx.execute(
        "DELETE FROM collections WHERE NOT EXISTS (SELECT 1 FROM memberships m WHERE m.collection_id = collections.id)",
        [],
    )?)
}

/// Active ou désactive un compte depuis l'administration (motif « admin »).
pub fn set_disabled(tx: &Connection, id: &str, role: &str, disabled: bool) -> ApiResult<()> {
    set_disabled_reason(tx, id, role, disabled, "admin")
}

/// Motifs de désactivation enregistrés dans `users.disabled_reason`.
pub const DISABLED_REASONS: [&str; 6] = ["admin", "directory", "scim", "inactive", "offboard", "expired"];

/// Active ou désactive un compte en notant le motif. La désactivation pose
/// `disabled_at`, ferme toutes les sessions et révoque les liens de partage
/// du compte ; la réactivation efface le motif et annule une suppression
/// programmée. Le dernier propriétaire actif n'est jamais désactivé.
pub fn set_disabled_reason(tx: &Connection, id: &str, role: &str, disabled: bool, reason: &str) -> ApiResult<()> {
    debug_assert!(DISABLED_REASONS.contains(&reason), "motif de désactivation inconnu : {reason}");
    if disabled && role == OWNER && is_last_owner(tx, id)? {
        return Err(last_owner());
    }
    let now = now_unix();
    if disabled {
        tx.execute(
            "UPDATE users SET disabled = 1, disabled_at = COALESCE(disabled_at, ?1), disabled_reason = ?2, updated_at = ?1
             WHERE id = ?3",
            params![now, reason, id],
        )?;
        tx.execute("DELETE FROM sessions WHERE user_id = ?1", [id])?;
        crate::shares::revoke_for_user(tx, id, crate::shares::reason::OWNER_DISABLED, None)?;
    } else {
        tx.execute(
            "UPDATE users SET disabled = 0, disabled_at = NULL, disabled_reason = NULL, deprovision_at = NULL, updated_at = ?1
             WHERE id = ?2",
            params![now, id],
        )?;
    }
    Ok(())
}

pub async fn delete_user(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    sec::uuid_path(&id, "Utilisateur")?;
    let (a, i) = (admin.clone(), id.clone());
    state.db.read(move |c| guard(c, &a, &i, &target(c, &i)?.role, Act::Delete)).await?;
    sec::require_step_up(&state, &admin, &headers, "admin.delete_user").await?;
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let t = target(&tx, &id)?;
            guard(&tx, &admin, &id, &t.role, Act::Delete)?;
            let removed = remove_user(&tx, &id, &t.role)?;
            audit_user(&tx, &admin, "admin.user_deleted", &t.email, &format!("{removed} coffre(s) sans membre supprimé(s)"))?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Retire la double authentification d'un compte (secret, codes de secours,
/// sessions) et prévient la personne. Dans la transaction de l'appelant.
pub(crate) fn clear_2fa(
    tx: &Connection,
    notifier: &dyn Notifier,
    eff: &Effective,
    admin: &AuthUser,
    id: &str,
    email: &str,
) -> ApiResult<()> {
    let now = now_unix();
    tx.execute(
        "UPDATE users SET totp_secret = NULL, totp_pending = NULL, totp_last_step = NULL,
                          totp_recovery_generated_at = NULL, updated_at = ?1
         WHERE id = ?2",
        params![now, id],
    )?;
    tx.execute("DELETE FROM totp_recovery_codes WHERE user_id = ?1", [id])?;
    tx.execute("DELETE FROM sessions WHERE user_id = ?1", [id])?;
    notifier.enqueue(tx, eff, &Notification::SecurityChange { user_id: id.to_string(), event: "admin.2fa_reset", at: now })?;
    audit_user(tx, admin, "admin.2fa_reset", email, "")
}

pub async fn reset_2fa(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    sec::uuid_path(&id, "Utilisateur")?;
    let (a, i) = (admin.clone(), id.clone());
    state.db.read(move |c| guard(c, &a, &i, &target(c, &i)?.role, Act::Touch)).await?;
    sec::require_step_up(&state, &admin, &headers, "admin.reset_2fa").await?;
    let eff = state.effective().await?;
    let notifier = state.notifier.clone();
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let t = target(&tx, &id)?;
            guard(&tx, &admin, &id, &t.role, Act::Touch)?;
            clear_2fa(&tx, notifier.as_ref(), &eff, &admin, &id, &t.email)?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn revoke_sessions(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    sec::uuid_path(&id, "Utilisateur")?;
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let t = target(&tx, &id)?;
            guard(&tx, &admin, &id, &t.role, Act::Touch)?;
            let n = tx.execute("DELETE FROM sessions WHERE user_id = ?1", [&id])?;
            audit_user(&tx, &admin, "admin.sessions_revoked", &t.email, &format!("{n} session(s)"))?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ------------------------------------------------------------ Invitations

pub async fn list_invites(State(state): State<AppState>, _admin: AdminUser) -> ApiResult<Json<Vec<InviteView>>> {
    Ok(Json(
        state
            .db
            .read(|c| {
                let mut st = c.prepare(
                    "SELECT id, email, role, created_at, expires_at, used_at FROM invites ORDER BY created_at DESC LIMIT 200",
                )?;
                let rows = st
                    .query_map([], |r| {
                        Ok(InviteView {
                            id: r.get(0)?,
                            email: r.get(1)?,
                            role: r.get(2)?,
                            created_at: r.get(3)?,
                            expires_at: r.get(4)?,
                            used_at: r.get(5)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?,
    ))
}

/// Contexte d'émission des invitations : auteur, adresse publique, réglages
/// et notificateur (e-mail si `mail.enabled`).
pub(crate) struct InviteCtx {
    pub admin: AuthUser,
    pub inviter: String,
    pub base_url: String,
    pub eff: std::sync::Arc<Effective>,
    pub notifier: std::sync::Arc<dyn Notifier>,
}

impl InviteCtx {
    pub(crate) async fn new(state: &AppState, admin: AuthUser, headers: &HeaderMap) -> ApiResult<Self> {
        let eff = state.effective().await?;
        let base_url = crate::sso::public_base(state, &eff, headers);
        let uid = admin.id.clone();
        let inviter = state
            .db
            .read(move |c| Ok(c.query_row("SELECT name FROM users WHERE id = ?1", [uid], |r| r.get(0)).optional()?))
            .await?
            .unwrap_or_default();
        Ok(Self { admin, inviter, base_url, eff, notifier: state.notifier.clone() })
    }

    /// Fin de validité d'une invitation émise maintenant (`invite.ttl_days`).
    pub(crate) fn expires_at(&self, now: i64) -> i64 {
        now + self.eff.int("invite.ttl_days") * 86_400
    }

    pub(crate) fn link(&self, token: &str) -> String {
        format!("{}/#/inscription/{token}", self.base_url)
    }

    /// Envoie (met en file) l'e-mail d'invitation ; `true` si parti en file.
    pub(crate) fn notify(&self, tx: &Connection, invite_id: &str, email: &str, name: &str, link: &str, expires_at: i64) -> ApiResult<bool> {
        let n = Notification::Invite {
            invite_id: invite_id.to_string(),
            email: email.to_string(),
            name: name.to_string(),
            link: link.to_string(),
            expires_at,
            inviter: self.inviter.clone(),
        };
        Ok(self.notifier.enqueue(tx, &self.eff, &n)? == NotifyOutcome::Queued)
    }
}

/// Invitation émise : le jeton n'est connu que de la réponse (empreinte en base).
pub(crate) struct NewInvite {
    pub id: String,
    pub token: String,
    pub link: String,
    pub expires_at: i64,
    pub mailed: bool,
}

/// Rôle d'invitation permis à cet auteur.
pub(crate) fn check_invite_role(admin: &AuthUser, role: &str) -> ApiResult<()> {
    if role != USER && role != ADMIN {
        return Err(ApiError::bad_request("Rôle d'invitation : user ou admin."));
    }
    if role == ADMIN && admin.role != OWNER {
        return Err(owner_only());
    }
    Ok(())
}

/// Fin d'accès facultative : forcément dans le futur.
pub(crate) fn check_access_until(access_until: Option<i64>, now: i64) -> ApiResult<()> {
    match access_until {
        Some(t) if t <= now => Err(ApiError::bad_request("La date de fin d'accès doit être dans le futur.")),
        _ => Ok(()),
    }
}

/// Enregistre une invitation (une émission), l'annonce par e-mail et la journalise.
pub(crate) fn insert_invite(
    tx: &Connection,
    ctx: &InviteCtx,
    email: &str,
    name: &str,
    role: &str,
    access_until: Option<i64>,
) -> ApiResult<NewInvite> {
    let now = now_unix();
    let (id, token) = (new_uuid(), random_token());
    let expires_at = ctx.expires_at(now);
    tx.execute(
        "INSERT INTO invites (id, token_hash, email, role, created_by, created_at, expires_at, sent_count, last_sent_at, access_until, name)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?6, ?8, ?9)",
        params![id, sha256_hex(&token), email, role, ctx.admin.id, now, expires_at, access_until, name],
    )?;
    let link = ctx.link(&token);
    let mailed = ctx.notify(tx, &id, email, name, &link, expires_at)?;
    audit_user(tx, &ctx.admin, "admin.invite_created", email, role)?;
    Ok(NewInvite { id, token, link, expires_at, mailed })
}

/// 409 : adresse déjà utilisée par un compte.
pub(crate) fn email_taken() -> ApiError {
    ApiError::new(StatusCode::CONFLICT, "email_taken", "Cette adresse e-mail est déjà utilisée par un autre compte.")
}

pub(crate) fn email_in_use(c: &Connection, email: &str, except: &str) -> ApiResult<bool> {
    Ok(c.query_row("SELECT COUNT(*) FROM users WHERE email = ?1 AND id <> ?2", params![email, except], |r| r.get::<_, i64>(0))? > 0)
}

/// `POST /admin/invites` : invitation unitaire (corps historique, plus
/// `access_until` facultatif).
#[derive(Deserialize, Debug)]
pub struct CreateInviteIn {
    #[serde(flatten)]
    pub base: CreateInviteRequest,
    #[serde(default)]
    pub access_until: Option<i64>,
}

/// Réponse historique (`token`) complétée du lien et de l'envoi.
#[derive(Serialize, Debug)]
pub struct InviteCreatedOut {
    #[serde(flatten)]
    pub base: InviteCreated,
    pub link: String,
    pub mailed: bool,
}

pub async fn create_invite(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    headers: HeaderMap,
    Json(req): Json<CreateInviteIn>,
) -> ApiResult<Json<InviteCreatedOut>> {
    let email = sec::normalize_email(&req.base.email)?;
    let role = req.base.role;
    let name = sec::clean_optional_name(&req.base.name)?;
    check_invite_role(&admin, &role)?;
    check_access_until(req.access_until, now_unix())?;
    let ctx = InviteCtx::new(&state, admin, &headers).await?;
    sec::require_email_domain(&ctx.eff, &email)?;
    let inv = state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            if email_in_use(&tx, &email, "")? {
                return Err(email_taken());
            }
            // Une nouvelle invitation remplace celle encore en attente.
            tx.execute("DELETE FROM invites WHERE email = ?1 AND used_at IS NULL", [&email])?;
            let inv = insert_invite(&tx, &ctx, &email, &name, &role, req.access_until)?;
            tx.commit()?;
            Ok(inv)
        })
        .await?;
    Ok(Json(InviteCreatedOut {
        base: InviteCreated { id: inv.id, token: inv.token, expires_at: inv.expires_at },
        link: inv.link,
        mailed: inv.mailed,
    }))
}

pub async fn delete_invite(State(state): State<AppState>, AdminUser(admin): AdminUser, Path(id): Path<String>) -> ApiResult<StatusCode> {
    sec::uuid_path(&id, "Invitation")?;
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let email: Option<String> = tx.query_row("SELECT email FROM invites WHERE id = ?1", [&id], |r| r.get(0)).optional()?;
            let email = email.ok_or_else(|| ApiError::not_found("Invitation introuvable."))?;
            tx.execute("DELETE FROM invites WHERE id = ?1", [&id])?;
            audit_user(&tx, &admin, "admin.invite_revoked", &email, "")?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ------------------------------------------------------------ Journal

/// Paramètres du journal. `action` et `type` : préfixe d'action ;
/// `actor` : identifiant ou adresse de l'auteur ; `before_id` : curseur
/// (lignes plus anciennes que cet identifiant).
#[derive(Deserialize, Default)]
pub struct AuditQuery {
    #[serde(default)]
    q: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    from: Option<i64>,
    #[serde(default)]
    to: Option<i64>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    actor: String,
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    before_id: Option<i64>,
}

/// Gravité d'une ligne en SQL, dérivée de la table unique du noyau
/// (`admin_api::SEVERITY_RULES`, mêmes règles que `entry_severity`).
static SEVERITY_SQL: LazyLock<String> = LazyLock::new(|| {
    let lit = |s: &str| format!("'{}'", s.replace('\'', "''"));
    let mut sql = String::from("CASE");
    for r in aa::SEVERITY_RULES {
        let action = if r.is_prefix() {
            format!("substr(action, 1, {}) = {}", r.action.chars().count(), lit(r.action))
        } else {
            format!("action = {}", lit(r.action))
        };
        let details = r.details.map(|d| format!(" AND details = {}", lit(d))).unwrap_or_default();
        sql.push_str(&format!(" WHEN {action}{details} THEN {}", lit(r.severity)));
    }
    sql + " ELSE 'info' END"
});

fn audit_filter(q: &AuditQuery) -> ApiResult<Filter> {
    let mut f = Filter::default();
    f.push("at BETWEEN ? AND ?", [SqlValue::Integer(q.from.unwrap_or(0)), SqlValue::Integer(q.to.unwrap_or(i64::MAX))]);
    let action = q.action.trim();
    if !action.is_empty() {
        f.push("action LIKE ? ESCAPE '\\'", [SqlValue::Text(format!("{}%", like_escape(action)))]);
    }
    let search = q.q.trim();
    if !search.is_empty() {
        let v = like_contains(search);
        f.push(
            "(email LIKE ? ESCAPE '\\' OR target LIKE ? ESCAPE '\\' OR ip LIKE ? ESCAPE '\\' OR details LIKE ? ESCAPE '\\')",
            [v.clone(), v.clone(), v.clone(), v],
        );
    }
    let severity = q.severity.trim();
    if !severity.is_empty() {
        if !aa::SEVERITIES.contains(&severity) {
            return Err(ApiError::bad_request("Gravité inconnue : info, warning ou critical."));
        }
        f.push(format!("({}) = ?", *SEVERITY_SQL), [text(severity)]);
    }
    let actor = q.actor.trim();
    if !actor.is_empty() {
        f.push("(user_id = ? OR email = ? COLLATE NOCASE)", [text(actor), text(actor)]);
    }
    let kind = q.kind.trim().trim_end_matches('.');
    if !kind.is_empty() {
        f.push("(action = ? OR substr(action, 1, length(?) + 1) = ? || '.')", [text(kind), text(kind), text(kind)]);
    }
    Ok(f)
}

fn query_audit(c: &Connection, q: &AuditQuery, max: i64) -> ApiResult<AuditRows> {
    let mut f = audit_filter(q)?;
    let total: i64 = c.query_row(&format!("SELECT COUNT(*) FROM audit {}", f.sql()), params_from_iter(&f.args), |r| r.get(0))?;
    if let Some(before) = q.before_id {
        f.push("id < ?", [SqlValue::Integer(before)]);
    }
    let limit = q.limit.unwrap_or(100).clamp(1, max);
    let offset = q.offset.unwrap_or(0).max(0);
    let mut args = f.args.clone();
    // Une ligne de plus que demandé : indique s'il existe une page suivante.
    args.extend([SqlValue::Integer(limit + 1), SqlValue::Integer(offset)]);
    let mut st = c.prepare(&format!(
        "SELECT id, at, user_id, email, action, target, ip, user_agent, details FROM audit {}
         ORDER BY id DESC LIMIT ? OFFSET ?",
        f.sql()
    ))?;
    let mut entries = st.query_map(params_from_iter(&args), audit_row)?.collect::<Result<Vec<_>, _>>()?;
    let more = entries.len() as i64 > limit;
    entries.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
    let next_cursor = if more { entries.last().map(|e| e.id) } else { None };
    let entries = entries
        .into_iter()
        .map(|e| AuditRow { severity: aa::entry_severity(&e.action, &e.details).to_string(), entry: e })
        .collect();
    Ok(AuditRows { entries, total, next_cursor })
}

pub async fn audit_log(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<AuditRows>> {
    Ok(Json(state.db.read(move |c| query_audit(c, &q, 500)).await?))
}

/// Caractères qu'un tableur interprète en tête de cellule (formule, DDE,
/// saut de champ).
fn formula_trigger(c: char) -> bool {
    matches!(c, '=' | '+' | '-' | '@' | '\t' | '\r' | '\n')
}

pub(crate) fn csv_field(s: &str) -> String {
    // Neutralise les formules quand le fichier est ouvert dans un tableur,
    // y compris derrière des espaces de tête (« =1+1 » précédé d'espaces).
    let risky = s.starts_with(formula_trigger) || s.trim_start().starts_with(formula_trigger);
    let s = if risky { format!("'{s}") } else { s.to_string() };
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// Format des exports CSV : séparateur `audit.csv_separator`, dates dans le
/// fuseau `i18n.timezone` (UTC si la table du noyau ne le connaît pas).
pub(crate) struct CsvFormat {
    pub sep: &'static str,
    tz: String,
    tz_known: bool,
}

impl CsvFormat {
    pub(crate) fn new(eff: &Effective) -> Self {
        let tz = eff.str("i18n.timezone").trim().to_string();
        let tz_known = aa::tz_offset(&tz, 0).is_some();
        if !tz_known {
            tracing::warn!(fuseau = %tz, "fuseau horaire inconnu de la table : dates des exports en UTC");
        }
        Self { sep: aa::csv_separator(eff.str("audit.csv_separator")), tz, tz_known }
    }

    /// Date lisible dans le fuseau de l'organisation (UTC si inconnu).
    pub(crate) fn local(&self, ts: i64) -> String {
        format_utc(ts + aa::tz_offset(&self.tz, ts).unwrap_or(0))
    }

    /// Nom de la colonne de date locale (`date_locale_utc` si le fuseau est inconnu).
    pub(crate) fn local_column(&self) -> &'static str {
        if self.tz_known {
            "date_locale"
        } else {
            "date_locale_utc"
        }
    }

    /// Ligne terminée par CRLF ; chaque champ est déjà prêt (`csv_field` ou nombre).
    pub(crate) fn line(&self, fields: &[String]) -> String {
        let mut l = fields.join(self.sep);
        l.push_str("\r\n");
        l
    }
}

/// Réponse CSV (UTF-8 avec BOM, téléchargée sous `filename`).
pub(crate) fn csv_response(filename: &'static str, body: String) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{filename}\"")),
        ],
        body,
    )
}

pub async fn audit_csv(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Query(q): Query<AuditQuery>,
) -> ApiResult<impl IntoResponse> {
    let fmt = CsvFormat::new(&*state.effective().await?);
    // Requête (jusqu'à 100 000 lignes) sur un lecteur : l'écrivain n'est pas
    // bloqué. L'export est ensuite journalisé ; sans trace, pas de fichier.
    let page = state.db.read(move |c| query_audit(c, &q, 100_000)).await?;
    let lines = page.entries.len();
    state
        .db
        .call(move |c| audit_user(c, &admin, "admin.audit_exported", "", &format!("{lines} ligne(s)")))
        .await?;
    let mut header: Vec<String> = aa::AUDIT_CSV_COLUMNS.iter().map(|c| c.to_string()).collect();
    header[0] = fmt.local_column().to_string();
    let mut out = String::from("\u{feff}");
    out.push_str(&fmt.line(&header));
    for AuditRow { entry: e, severity } in page.entries {
        out.push_str(&fmt.line(&[
            csv_field(&fmt.local(e.at)),
            csv_field(&format_utc(e.at)),
            e.at.to_string(),
            csv_field(&e.email),
            csv_field(&e.action),
            csv_field(&severity),
            csv_field(&e.target),
            csv_field(&e.ip),
            csv_field(&e.user_agent),
            csv_field(&e.details),
        ]));
    }
    Ok(csv_response("locksy-journal.csv", out))
}

/// Date UTC lisible sans dépendance (algorithme des jours civils).
pub fn format_utc(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}", secs / 3600, secs % 3600 / 60, secs % 60)
}

// ------------------------------------------------------------ Réglages

/// Réglages vus par l'administration : ceux de l'organisation, à plat, et
/// les quotas de pièces jointes avec l'espace déjà occupé.
#[derive(Serialize, Debug)]
pub struct AdminSettingsView {
    #[serde(flatten)]
    pub org: OrgSettings,
    pub attachment_quota_user_mb: i64,
    pub attachment_quota_total_mb: i64,
    pub attachment_max_per_item: i64,
    /// Lecture seule : ignoré à l'enregistrement.
    pub attachment_used_mb: i64,
}

/// Réglages envoyés par l'administration. Chaque champ est facultatif : un
/// champ absent conserve la valeur actuelle. Ainsi un client qui n'envoie
/// qu'une partie des réglages (anciens clients web : les cinq règles sans les
/// quotas ; ou les quotas seuls) ne remet jamais une règle de sécurité, comme
/// la 2FA obligatoire, à sa valeur par défaut.
#[derive(Deserialize, Default)]
pub struct AdminSettingsUpdate {
    #[serde(default)]
    pub require_2fa: Option<bool>,
    #[serde(default)]
    pub session_idle_minutes: Option<i64>,
    #[serde(default)]
    pub session_max_hours: Option<i64>,
    #[serde(default)]
    pub audit_retention_days: Option<i64>,
    #[serde(default)]
    pub trash_retention_days: Option<i64>,
    #[serde(default)]
    pub attachment_quota_user_mb: Option<i64>,
    #[serde(default)]
    pub attachment_quota_total_mb: Option<i64>,
    #[serde(default)]
    pub attachment_max_per_item: Option<i64>,
}

impl AdminSettingsUpdate {
    /// Règles de l'organisation : valeurs envoyées, sinon valeurs actuelles.
    fn merge_org(&self, current: OrgSettings) -> OrgSettings {
        OrgSettings {
            require_2fa: self.require_2fa.unwrap_or(current.require_2fa),
            session_idle_minutes: self.session_idle_minutes.unwrap_or(current.session_idle_minutes),
            session_max_hours: self.session_max_hours.unwrap_or(current.session_max_hours),
            audit_retention_days: self.audit_retention_days.unwrap_or(current.audit_retention_days),
            trash_retention_days: self.trash_retention_days.unwrap_or(current.trash_retention_days),
        }
    }
}

fn settings_view(c: &Connection) -> ApiResult<AdminSettingsView> {
    let q = load_quotas(c)?;
    Ok(AdminSettingsView {
        org: load_settings(c)?,
        attachment_quota_user_mb: q.per_user_mb,
        attachment_quota_total_mb: q.total_mb,
        attachment_max_per_item: q.max_per_item,
        attachment_used_mb: to_mb(used_total(c)?),
    })
}

fn validate_org(s: &OrgSettings) -> ApiResult<()> {
    if !(5..=1440).contains(&s.session_idle_minutes) {
        return Err(ApiError::bad_request("Inactivité : entre 5 minutes et 24 heures."));
    }
    if !(1..=720).contains(&s.session_max_hours) {
        return Err(ApiError::bad_request("Durée maximale de session : entre 1 heure et 30 jours."));
    }
    if !(30..=3650).contains(&s.audit_retention_days) {
        return Err(ApiError::bad_request("Conservation du journal : entre 30 jours et 10 ans."));
    }
    if !(1..=365).contains(&s.trash_retention_days) {
        return Err(ApiError::bad_request("Conservation de la corbeille : entre 1 et 365 jours."));
    }
    Ok(())
}

/// Bornes des quotas, vérifiées avant toute écriture.
fn validate_quotas(u: &AdminSettingsUpdate) -> ApiResult<()> {
    let check = |v: Option<i64>, max: i64, msg: &str| match v {
        Some(v) if !(1..=max).contains(&v) => Err(ApiError::bad_request(msg)),
        _ => Ok(()),
    };
    check(u.attachment_quota_user_mb, 102_400, "Quota de pièces jointes par utilisateur : entre 1 Mo et 100 Go.")?;
    check(u.attachment_quota_total_mb, 1_048_576, "Espace total des pièces jointes : entre 1 Mo et 1 To.")?;
    check(u.attachment_max_per_item, 100, "Pièces jointes par élément : entre 1 et 100.")
}

pub async fn get_settings(State(state): State<AppState>, _admin: AdminUser) -> ApiResult<Json<AdminSettingsView>> {
    Ok(Json(state.db.read(settings_view).await?))
}

pub async fn put_settings(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Json(u): Json<AdminSettingsUpdate>,
) -> ApiResult<Json<AdminSettingsView>> {
    validate_quotas(&u)?;
    Ok(Json(
        state
            .db
            .call(move |c| {
                // Réglages, quotas et audit ensemble, ou rien.
                let tx = c.transaction()?;
                let org = u.merge_org(load_settings(&tx)?);
                // Bornes vérifiées sur le résultat fusionné, avant toute écriture.
                validate_org(&org)?;
                if org.require_2fa && admin.role != OWNER && admin.role != ADMIN {
                    return Err(ApiError::forbidden("Réservé aux administrateurs."));
                }
                let current = load_quotas(&tx)?;
                let q = AttachmentQuotas {
                    per_user_mb: u.attachment_quota_user_mb.unwrap_or(current.per_user_mb),
                    total_mb: u.attachment_quota_total_mb.unwrap_or(current.total_mb),
                    max_per_item: u.attachment_max_per_item.unwrap_or(current.max_per_item),
                };
                let s = &org;
                db::save_settings(&tx, s)?;
                db::save_json(&tx, QUOTAS_KEY, &q)?;
                audit_user(
                    &tx,
                    &admin,
                    "admin.settings_updated",
                    "",
                    &format!(
                        "2FA obligatoire : {}, inactivité {} min, session {} h, journal {} j, corbeille {} j, \
                         pièces jointes {} Mo par utilisateur, {} Mo au total, {} par élément",
                        if s.require_2fa { "oui" } else { "non" },
                        s.session_idle_minutes,
                        s.session_max_hours,
                        s.audit_retention_days,
                        s.trash_retention_days,
                        q.per_user_mb,
                        q.total_mb,
                        q.max_per_item
                    ),
                )?;
                let view = settings_view(&tx)?;
                tx.commit()?;
                Ok(view)
            })
            .await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_state;
    use crate::vault::testing::{count, user};

    /// En-têtes portant un jeton de réauthentification valide pour `action`.
    fn step_up(u: &AuthUser, action: &'static str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(sec::REAUTH_HEADER, sec::issue_step_up(&u.id, &u.session_id, action).parse().unwrap());
        h
    }

    #[tokio::test]
    async fn gravite_sql_identique_au_noyau() {
        let st = test_state().await;
        let cases = [
            ("settings.lowered", ""),
            ("admin.user_role", "user → admin"),
            ("2fa.disabled", "imposée"),
            ("2fa.disabled", ""),
            ("recovery.completed", ""),
            ("recoveryX", ""),
            ("share.ended", "revoked_admin"),
            ("share.ended", "expired"),
            ("login.success", ""),
            ("admin.user_offboarded", "x"),
        ];
        let got = st
            .db
            .call(move |c| {
                let mut out = Vec::new();
                for (action, details) in cases {
                    let sev: String = c.query_row(
                        &format!("SELECT {} FROM (SELECT ?1 AS action, ?2 AS details)", *SEVERITY_SQL),
                        params![action, details],
                        |r| r.get(0),
                    )?;
                    out.push((action, details, sev));
                }
                Ok(out)
            })
            .await
            .unwrap();
        for (action, details, sev) in got {
            assert_eq!(sev, aa::entry_severity(action, details), "{action} / {details}");
        }
    }

    #[tokio::test]
    async fn format_des_exports() {
        let st = test_state().await;
        let fmt = CsvFormat::new(&st.effective().await.unwrap());
        // Défauts : point-virgule, Europe/Paris (UTC+1 en hiver).
        assert_eq!((fmt.sep, fmt.local_column()), (";", "date_locale"));
        assert_eq!(fmt.local(0), "1970-01-01 01:00:00");
        assert_eq!(fmt.line(&["\"a\"".into(), "1".into()]), "\"a\";1\r\n");
        let inconnu = CsvFormat { sep: ",", tz: "America/New_York".into(), tz_known: false };
        assert_eq!((inconnu.local_column(), inconnu.local(0).as_str()), ("date_locale_utc", "1970-01-01 00:00:00"));
    }

    #[test]
    fn utc_formatting() {
        assert_eq!(super::format_utc(0), "1970-01-01 00:00:00");
        assert_eq!(super::format_utc(1_700_000_000), "2023-11-14 22:13:20");
    }

    #[test]
    fn csv_neutralizes_formulas() {
        assert_eq!(super::csv_field("=cmd"), "\"'=cmd\"");
        assert_eq!(super::csv_field("a\"b"), "\"a\"\"b\"");
    }

    #[test]
    fn csv_neutralise_chaque_caractere_de_tete() {
        for lead in ['=', '+', '-', '@', '\t', '\r', '\n'] {
            let field = format!("{lead}1+1");
            assert_eq!(csv_field(&field), format!("\"'{field}\""), "{lead:?}");
        }
        // Derrière des espaces de tête.
        assert_eq!(csv_field("  =1+1"), "\"'  =1+1\"");
        assert_eq!(csv_field(" @SUM(A1)"), "\"' @SUM(A1)\"");
        // Guillemets doublés après neutralisation.
        assert_eq!(csv_field("=\"x\""), "\"'=\"\"x\"\"\"");
        // Texte ordinaire inchangé, formule au milieu comprise.
        assert_eq!(csv_field("login.failed"), "\"login.failed\"");
        assert_eq!(csv_field("a=b"), "\"a=b\"");
        assert_eq!(csv_field(""), "\"\"");
        assert_eq!(csv_field(&format_utc(0)), "\"1970-01-01 00:00:00\"");
    }

    fn update(json: serde_json::Value) -> Json<AdminSettingsUpdate> {
        Json(serde_json::from_value(json).unwrap())
    }

    fn org_json() -> serde_json::Value {
        serde_json::json!({
            "require_2fa": false,
            "session_idle_minutes": 30,
            "session_max_hours": 8,
            "audit_retention_days": 400,
            "trash_retention_days": 15
        })
    }

    #[tokio::test]
    async fn reglages_et_quotas() {
        let st = test_state().await;
        let admin = st.db.call(|c| Ok(user(c, "admin", OWNER))).await.unwrap();
        let get = || get_settings(State(st.clone()), AdminUser(admin.clone()));

        // Valeurs par défaut, à plat.
        let v = serde_json::to_value(get().await.unwrap().0).unwrap();
        assert_eq!(v["session_idle_minutes"], 60);
        assert_eq!(v["attachment_quota_user_mb"], 1024);
        assert_eq!(v["attachment_quota_total_mb"], 20_480);
        assert_eq!(v["attachment_max_per_item"], 20);
        assert_eq!(v["attachment_used_mb"], 0);

        // Quotas modifiés.
        let mut body = org_json();
        body["attachment_quota_user_mb"] = 50.into();
        body["attachment_quota_total_mb"] = 500.into();
        body["attachment_max_per_item"] = 5.into();
        body["attachment_used_mb"] = 999.into(); // ignoré
        let r = put_settings(State(st.clone()), AdminUser(admin.clone()), update(body)).await.unwrap().0;
        assert_eq!((r.attachment_quota_user_mb, r.attachment_quota_total_mb, r.attachment_max_per_item), (50, 500, 5));
        assert_eq!(r.attachment_used_mb, 0);

        // Client web actuel : les cinq champs seulement. Quotas conservés.
        let r = put_settings(State(st.clone()), AdminUser(admin.clone()), update(org_json())).await.unwrap().0;
        assert_eq!((r.attachment_quota_user_mb, r.attachment_quota_total_mb, r.attachment_max_per_item), (50, 500, 5));
        assert_eq!(r.org.session_idle_minutes, 30);
        let q = st.db.call(|c| load_quotas(c)).await.unwrap();
        assert_eq!(q, AttachmentQuotas { per_user_mb: 50, total_mb: 500, max_per_item: 5 });

        // Hors bornes : 400, rien n'est modifié.
        for (field, value) in [
            ("attachment_quota_user_mb", 0),
            ("attachment_quota_user_mb", 102_401),
            ("attachment_quota_total_mb", 1_048_577),
            ("attachment_max_per_item", 101),
            ("attachment_max_per_item", -1),
        ] {
            let mut body = org_json();
            body["session_idle_minutes"] = 90.into();
            body[field] = value.into();
            let e = put_settings(State(st.clone()), AdminUser(admin.clone()), update(body)).await.unwrap_err();
            assert_eq!((e.status, e.code), (StatusCode::BAD_REQUEST, "bad_request"), "{field}={value}");
        }
        let v = get().await.unwrap().0;
        assert_eq!((v.org.session_idle_minutes, v.attachment_quota_user_mb), (30, 50));
        // Règle d'organisation hors bornes : 400 également.
        let mut body = org_json();
        body["session_idle_minutes"] = 2.into();
        let e = put_settings(State(st.clone()), AdminUser(admin.clone()), update(body)).await.unwrap_err();
        assert_eq!(e.code, "bad_request");
        let audits = st
            .db
            .call(|c| Ok(count(c, "SELECT COUNT(*) FROM audit WHERE action = ?1", "admin.settings_updated")))
            .await
            .unwrap();
        assert_eq!(audits, 2);

        // Espace occupé arrondi au Mo supérieur.
        st.db
            .call(|c| {
                c.execute("INSERT INTO users (id, email, name, role, kdf, auth_hash, wrapped_user_key, recovery_wrapped_user_key, recovery_auth_hash, public_key, wrapped_private_key, created_at, updated_at) VALUES ('u', 'u@x.fr', 'u', 'user', '{}', '', '', '', '', '', '', 0, 0)", [])?;
                c.execute("INSERT INTO collections (id, enc_name, created_at, updated_at) VALUES ('c', 'n', 0, 0)", [])?;
                c.execute("INSERT INTO items (id, collection_id, data, created_at, updated_at) VALUES ('i', 'c', 'd', 0, 0)", [])?;
                c.execute("INSERT INTO attachments (id, item_id, data, size, created_at, created_by) VALUES ('a', 'i', 'x', 1572864, 0, 'u')", [])?;
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(get().await.unwrap().0.attachment_used_mb, 2);
    }

    /// Un envoi partiel (quotas seuls, ou une seule règle) ne remet aucune
    /// règle de sécurité à sa valeur par défaut, en particulier la 2FA obligatoire.
    #[tokio::test]
    async fn envoi_partiel_conserve_les_autres_reglages() {
        let st = test_state().await;
        let admin = st.db.call(|c| Ok(user(c, "admin", OWNER))).await.unwrap();
        let put = |body| put_settings(State(st.clone()), AdminUser(admin.clone()), update(body));

        let mut body = org_json();
        body["require_2fa"] = true.into();
        let _ = put(body).await.unwrap();

        // Quotas seuls : règles de l'organisation intactes.
        let r = put(serde_json::json!({ "attachment_quota_user_mb": 7 })).await.unwrap().0;
        assert!(r.org.require_2fa);
        assert_eq!((r.org.session_idle_minutes, r.org.session_max_hours), (30, 8));
        assert_eq!((r.org.audit_retention_days, r.org.trash_retention_days), (400, 15));
        assert_eq!(r.attachment_quota_user_mb, 7);

        // Une seule règle : les autres et les quotas sont conservés.
        let r = put(serde_json::json!({ "trash_retention_days": 60 })).await.unwrap().0;
        assert!(r.org.require_2fa);
        assert_eq!((r.org.session_idle_minutes, r.org.trash_retention_days), (30, 60));
        assert_eq!(r.attachment_quota_user_mb, 7);

        // Corps vide : rien ne change (mais l'enregistrement est journalisé).
        let r = put(serde_json::json!({})).await.unwrap().0;
        assert!(r.org.require_2fa);
        assert_eq!(r.org.trash_retention_days, 60);

        // Désactivation explicite : prise en compte.
        let r = put(serde_json::json!({ "require_2fa": false })).await.unwrap().0;
        assert!(!r.org.require_2fa);
        let stored = st.db.read(load_settings).await.unwrap();
        assert!(!stored.require_2fa);
        assert_eq!(stored.audit_retention_days, 400);
    }

    #[tokio::test]
    async fn reset_2fa_cible_inconnue_ne_change_rien() {
        let st = test_state().await;
        let (admin, target) = st
            .db
            .call(|c| {
                let admin = user(c, "admin", OWNER);
                let target = user(c, "jean", USER);
                c.execute("UPDATE users SET totp_secret = 'secret' WHERE id = ?1", [&target.id])?;
                c.execute(
                    "INSERT INTO totp_recovery_codes (id, user_id, code_hash, created_at) VALUES ('r1', ?1, 'h', 0)",
                    [&target.id],
                )?;
                Ok((admin, target))
            })
            .await
            .unwrap();
        let e = reset_2fa(State(st.clone()), AdminUser(admin.clone()), Path("inconnu".into()), HeaderMap::new()).await.unwrap_err();
        assert_eq!(e.status, StatusCode::NOT_FOUND);
        let tid = target.id.clone();
        let (totp, sessions, audits) = st
            .db
            .call(move |c| {
                Ok((
                    count(c, "SELECT COUNT(*) FROM users WHERE totp_secret IS NOT NULL AND id = ?1", &tid),
                    count(c, "SELECT COUNT(*) FROM sessions WHERE user_id = ?1", &tid),
                    count(c, "SELECT COUNT(*) FROM audit WHERE action = ?1", "admin.2fa_reset"),
                ))
            })
            .await
            .unwrap();
        assert_eq!((totp, sessions, audits), (1, 1, 0));

        // Cible connue, sans confirmation d'identité : 428, rien ne change.
        let e = reset_2fa(State(st.clone()), AdminUser(admin.clone()), Path(target.id.clone()), HeaderMap::new())
            .await
            .unwrap_err();
        assert_eq!((e.status, e.code), (StatusCode::PRECONDITION_REQUIRED, "reauth_required"));
        // Avec confirmation : secret et codes de secours effacés, sessions
        // coupées, audit écrit, d'un bloc.
        let h = step_up(&admin, "admin.reset_2fa");
        reset_2fa(State(st.clone()), AdminUser(admin), Path(target.id.clone()), h).await.unwrap();
        let tid = target.id.clone();
        let (totp, sessions, audits) = st
            .db
            .call(move |c| {
                Ok((
                    count(c, "SELECT COUNT(*) FROM users WHERE totp_secret IS NOT NULL AND id = ?1", &tid),
                    count(c, "SELECT COUNT(*) FROM sessions WHERE user_id = ?1", &tid),
                    count(c, "SELECT COUNT(*) FROM audit WHERE action = ?1", "admin.2fa_reset"),
                ))
            })
            .await
            .unwrap();
        assert_eq!((totp, sessions, audits), (0, 0, 1));
        let tid = target.id.clone();
        let codes = st.db.call(move |c| Ok(count(c, "SELECT COUNT(*) FROM totp_recovery_codes WHERE user_id = ?1", &tid))).await.unwrap();
        assert_eq!(codes, 0);
    }

    #[tokio::test]
    async fn un_admin_ne_reinitialise_pas_un_proprietaire() {
        let st = test_state().await;
        let (admin, owner) = st.db.call(|c| Ok((user(c, "admin", ADMIN), user(c, "patron", OWNER)))).await.unwrap();
        let h = step_up(&admin, "admin.reset_2fa");
        let e = reset_2fa(State(st.clone()), AdminUser(admin), Path(owner.id.clone()), h).await.unwrap_err();
        assert_eq!((e.status, e.code), (StatusCode::FORBIDDEN, "owner_only"));
        let sessions = st.db.call(move |c| Ok(count(c, "SELECT COUNT(*) FROM sessions WHERE user_id = ?1", &owner.id))).await.unwrap();
        assert_eq!(sessions, 1);
    }
}
