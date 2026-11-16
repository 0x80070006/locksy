//! Administration : comptes, invitations, journal d'audit, réglages.
//! Les administrateurs gèrent les accès sans jamais pouvoir lire un secret.

use crate::db::{self, load_settings};
use crate::error::{ApiError, ApiResult};
use crate::security::{self as sec, sha256_hex};
use crate::state::{audit_user, AdminUser, AppState};
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::Deserialize;
use locksy_core::api::roles::{ADMIN, OWNER, USER};
use locksy_core::api::*;
use locksy_core::crypto::{new_uuid, random_token};
use locksy_core::now_unix;

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

pub async fn stats(State(state): State<AppState>, _admin: AdminUser) -> ApiResult<Json<AdminStats>> {
    Ok(Json(
        state
            .db
            .call(|c| {
                let now = now_unix();
                let one = |sql: &str| -> rusqlite::Result<i64> { c.query_row(sql, [], |r| r.get(0)) };
                Ok(AdminStats {
                    users: one("SELECT COUNT(*) FROM users")?,
                    active_users: one("SELECT COUNT(*) FROM users WHERE disabled = 0")?,
                    users_with_2fa: one("SELECT COUNT(*) FROM users WHERE totp_secret IS NOT NULL")?,
                    collections: one("SELECT COUNT(*) FROM collections")?,
                    shared_collections: one(
                        "SELECT COUNT(*) FROM collections c WHERE (SELECT COUNT(*) FROM memberships m WHERE m.collection_id = c.id) > 1",
                    )?,
                    items: one("SELECT COUNT(*) FROM items WHERE deleted_at IS NULL")?,
                    active_shares: c.query_row(
                        "SELECT COUNT(*) FROM shares WHERE expires_at > ?1 AND views < max_views",
                        [now],
                        |r| r.get(0),
                    )?,
                    failed_logins_24h: c.query_row(
                        "SELECT COUNT(*) FROM audit WHERE action = 'login.failed' AND at > ?1",
                        [now - 86_400],
                        |r| r.get(0),
                    )?,
                })
            })
            .await?,
    ))
}

pub async fn list_users(State(state): State<AppState>, _admin: AdminUser) -> ApiResult<Json<Vec<AdminUser2>>> {
    Ok(Json(
        state
            .db
            .call(|c| {
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

fn target_user(c: &Connection, id: &str) -> ApiResult<(String, String)> {
    c.query_row("SELECT email, role FROM users WHERE id = ?1", [id], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?
        .ok_or_else(|| ApiError::not_found("Utilisateur introuvable."))
}

fn owner_count(c: &Connection) -> ApiResult<i64> {
    Ok(c.query_row("SELECT COUNT(*) FROM users WHERE role = 'owner' AND disabled = 0", [], |r| r.get(0))?)
}

/// Un administrateur ne peut agir que sur les simples utilisateurs ; seul un
/// propriétaire agit sur les administrateurs et les propriétaires.
fn check_authority(actor_role: &str, target_role: &str) -> ApiResult<()> {
    if actor_role == ADMIN && target_role != USER {
        return Err(ApiError::forbidden("Seul un propriétaire peut gérer un administrateur ou un propriétaire."));
    }
    Ok(())
}

pub async fn update_user(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> ApiResult<StatusCode> {
    if let Some(r) = &req.role {
        if !roles::ORG_ROLES.contains(&r.as_str()) {
            return Err(ApiError::bad_request("Rôle inconnu."));
        }
    }
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let (email, role) = target_user(&tx, &id)?;
            check_authority(&admin.role, &role)?;
            if id == admin.id {
                return Err(ApiError::bad_request("Vous ne pouvez pas modifier votre propre rôle ni désactiver votre compte."));
            }
            if let Some(new_role) = &req.role {
                if admin.role != OWNER && new_role != USER {
                    return Err(ApiError::forbidden("Seul un propriétaire peut nommer un administrateur."));
                }
                if role == OWNER && new_role != OWNER && owner_count(&tx)? <= 1 {
                    return Err(ApiError::bad_request("L'organisation doit garder au moins un propriétaire."));
                }
                tx.execute("UPDATE users SET role = ?1, updated_at = ?2 WHERE id = ?3", params![new_role, now_unix(), id])?;
                audit_user(&tx, &admin, "admin.user_role", &email, &format!("{role} → {new_role}"))?;
            }
            if let Some(disabled) = req.disabled {
                // Accès coupé immédiatement, sur tous les appareils.
                set_disabled(&tx, &id, &role, disabled)?;
                audit_user(&tx, &admin, if disabled { "admin.user_disabled" } else { "admin.user_enabled" }, &email, "")?;
            }
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Supprime un compte (administration ou SCIM). Renvoie le nombre de coffres
/// devenus sans membre, donc détruits.
pub fn remove_user(tx: &Connection, id: &str, role: &str) -> ApiResult<usize> {
    if role == OWNER && owner_count(tx)? <= 1 {
        return Err(ApiError::bad_request("Impossible de supprimer le dernier propriétaire."));
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

/// Active ou désactive un compte ; la désactivation coupe toutes ses sessions.
pub fn set_disabled(tx: &Connection, id: &str, role: &str, disabled: bool) -> ApiResult<()> {
    if disabled && role == OWNER && owner_count(tx)? <= 1 {
        return Err(ApiError::bad_request("Impossible de désactiver le dernier propriétaire."));
    }
    tx.execute("UPDATE users SET disabled = ?1, updated_at = ?2 WHERE id = ?3", params![disabled, now_unix(), id])?;
    if disabled {
        tx.execute("DELETE FROM sessions WHERE user_id = ?1", [id])?;
    }
    Ok(())
}

pub async fn delete_user(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let (email, role) = target_user(&tx, &id)?;
            check_authority(&admin.role, &role)?;
            if id == admin.id {
                return Err(ApiError::bad_request("Vous ne pouvez pas supprimer votre propre compte."));
            }
            let removed = remove_user(&tx, &id, &role)?;
            audit_user(&tx, &admin, "admin.user_deleted", &email, &format!("{removed} coffre(s) sans membre supprimé(s)"))?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn reset_2fa(State(state): State<AppState>, AdminUser(admin): AdminUser, Path(id): Path<String>) -> ApiResult<StatusCode> {
    state
        .db
        .call(move |c| {
            let (email, role) = target_user(c, &id)?;
            check_authority(&admin.role, &role)?;
            c.execute("UPDATE users SET totp_secret = NULL, totp_pending = NULL, totp_last_step = NULL WHERE id = ?1", [&id])?;
            c.execute("DELETE FROM sessions WHERE user_id = ?1", [&id])?;
            audit_user(c, &admin, "admin.2fa_reset", &email, "")
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn revoke_sessions(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    state
        .db
        .call(move |c| {
            let (email, role) = target_user(c, &id)?;
            check_authority(&admin.role, &role)?;
            let n = c.execute("DELETE FROM sessions WHERE user_id = ?1", [&id])?;
            audit_user(c, &admin, "admin.sessions_revoked", &email, &format!("{n} session(s)"))
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ------------------------------------------------------------ Invitations

pub async fn list_invites(State(state): State<AppState>, _admin: AdminUser) -> ApiResult<Json<Vec<InviteView>>> {
    Ok(Json(
        state
            .db
            .call(|c| {
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

pub async fn create_invite(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Json(req): Json<CreateInviteRequest>,
) -> ApiResult<Json<InviteCreated>> {
    let email = sec::normalize_email(&req.email)?;
    if req.role != USER && req.role != ADMIN {
        return Err(ApiError::bad_request("Rôle d'invitation : user ou admin."));
    }
    if req.role == ADMIN && admin.role != OWNER {
        return Err(ApiError::forbidden("Seul un propriétaire peut inviter un administrateur."));
    }
    let token = random_token();
    let hash = sha256_hex(&token);
    let id = new_uuid();
    let expires_at = now_unix() + 7 * 86_400;
    let iid = id.clone();
    state
        .db
        .call(move |c| {
            let exists: bool = c.query_row("SELECT COUNT(*) FROM users WHERE email = ?1", [&email], |r| r.get::<_, i64>(0))? > 0;
            if exists {
                return Err(ApiError::conflict("Un compte existe déjà avec cette adresse."));
            }
            c.execute(
                "INSERT INTO invites (id, token_hash, email, role, created_by, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![iid, hash, email, req.role, admin.id, now_unix(), expires_at],
            )?;
            audit_user(c, &admin, "admin.invite_created", &email, &req.role)
        })
        .await?;
    Ok(Json(InviteCreated { id, token, expires_at }))
}

pub async fn delete_invite(State(state): State<AppState>, AdminUser(admin): AdminUser, Path(id): Path<String>) -> ApiResult<StatusCode> {
    state
        .db
        .call(move |c| {
            let email: Option<String> = c.query_row("SELECT email FROM invites WHERE id = ?1", [&id], |r| r.get(0)).optional()?;
            let email = email.ok_or_else(|| ApiError::not_found("Invitation introuvable."))?;
            c.execute("DELETE FROM invites WHERE id = ?1", [&id])?;
            audit_user(c, &admin, "admin.invite_revoked", &email, "")
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ------------------------------------------------------------ Journal

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
}

fn query_audit(c: &Connection, q: &AuditQuery, max: i64) -> ApiResult<AuditPage> {
    let like = format!("%{}%", q.q.replace('%', "").replace('_', ""));
    let action = format!("{}%", q.action.replace('%', "").replace('_', ""));
    let from = q.from.unwrap_or(0);
    let to = q.to.unwrap_or(i64::MAX);
    let limit = q.limit.unwrap_or(100).clamp(1, max);
    let offset = q.offset.unwrap_or(0).max(0);
    let filter = "WHERE at BETWEEN ?1 AND ?2 AND action LIKE ?3
                  AND (email LIKE ?4 OR target LIKE ?4 OR ip LIKE ?4 OR details LIKE ?4)";
    let total: i64 = c.query_row(
        &format!("SELECT COUNT(*) FROM audit {filter}"),
        params![from, to, action, like],
        |r| r.get(0),
    )?;
    let mut st = c.prepare(&format!(
        "SELECT id, at, user_id, email, action, target, ip, user_agent, details FROM audit {filter}
         ORDER BY id DESC LIMIT ?5 OFFSET ?6"
    ))?;
    let entries = st
        .query_map(params![from, to, action, like, limit, offset], audit_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(AuditPage { entries, total })
}

pub async fn audit_log(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<AuditPage>> {
    Ok(Json(state.db.call(move |c| query_audit(c, &q, 500)).await?))
}

fn csv_field(s: &str) -> String {
    // Neutralise les formules quand le fichier est ouvert dans un tableur.
    let s = if s.starts_with(['=', '+', '-', '@']) { format!("'{s}") } else { s.to_string() };
    format!("\"{}\"", s.replace('"', "\"\""))
}

pub async fn audit_csv(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Query(q): Query<AuditQuery>,
) -> ApiResult<impl IntoResponse> {
    let page = state
        .db
        .call(move |c| {
            let page = query_audit(c, &q, 100_000)?;
            audit_user(c, &admin, "admin.audit_exported", "", &format!("{} ligne(s)", page.entries.len()))?;
            Ok(page)
        })
        .await?;
    let mut out = String::from("\u{feff}date_utc;horodatage;utilisateur;action;cible;adresse_ip;navigateur;details\r\n");
    for e in page.entries {
        out.push_str(
            &[
                csv_field(&format_utc(e.at)),
                e.at.to_string(),
                csv_field(&e.email),
                csv_field(&e.action),
                csv_field(&e.target),
                csv_field(&e.ip),
                csv_field(&e.user_agent),
                csv_field(&e.details),
            ]
            .join(";"),
        );
        out.push_str("\r\n");
    }
    Ok((
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"locksy-journal.csv\""),
        ],
        out,
    ))
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

pub async fn get_settings(State(state): State<AppState>, _admin: AdminUser) -> ApiResult<Json<OrgSettings>> {
    Ok(Json(state.db.call(|c| load_settings(c)).await?))
}

pub async fn put_settings(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Json(s): Json<OrgSettings>,
) -> ApiResult<Json<OrgSettings>> {
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
    Ok(Json(
        state
            .db
            .call(move |c| {
                if s.require_2fa && admin.role != OWNER && admin.role != ADMIN {
                    return Err(ApiError::forbidden("Réservé aux administrateurs."));
                }
                db::save_settings(c, &s)?;
                audit_user(
                    c,
                    &admin,
                    "admin.settings_updated",
                    "",
                    &format!(
                        "2FA obligatoire : {}, inactivité {} min, session {} h, journal {} j, corbeille {} j",
                        if s.require_2fa { "oui" } else { "non" },
                        s.session_idle_minutes,
                        s.session_max_hours,
                        s.audit_retention_days,
                        s.trash_retention_days
                    ),
                )?;
                Ok(s)
            })
            .await?,
    ))
}

#[cfg(test)]
mod tests {
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
}
