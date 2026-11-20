//! Administration des personnes : liste unifiée, fiche, actions de masse,
//! invitations par lot, départ de l'entreprise (annexes A.6 à A.9).
//!
//! Noms de paramètres imposés : `/admin/users/:id`,
//! `/admin/users/:id/sessions/:sid`, `/admin/invites/:id`.
//!
//! Aucune réponse ne porte de nom de coffre ni d'élément : ils sont chiffrés
//! et illisibles pour l'administration (identifiants et compteurs seulement).
//! Le départ d'une personne ne transmet jamais de clé : un repreneur doit
//! déjà être membre du coffre, il est seulement promu gestionnaire.

use crate::admin::{
    check_access_until, check_invite_role, clear_2fa, csv_field, csv_response, email_in_use, email_taken, find_target,
    guard, insert_invite, like_contains, owner_only, refusal, remove_user, set_disabled_reason, target, text, Act,
    CsvFormat, Filter, InviteCtx, Refusal, SEEN_SQL,
};
use crate::error::{ApiError, ApiResult};
use crate::security::{self as sec, sha256_hex};
use crate::state::{audit_user, AdminUser, AppState, AuthUser};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::Router;
use crate::error::Json;
use locksy_core::admin_api::people::{PeopleFilter, Sort};
use locksy_core::admin_api::{
    self as aa, bulk, invites, BulkRequest, BulkResponse, InviteBatchRequest, InviteBatchResponse, InviteLink, InviteResent,
    InviteSkipped, OffboardCollection, OffboardMember, OffboardPlan, OffboardReport, OffboardRequest, OffboardResponse,
    OffboardUser, Orphaned, PeoplePage, PeopleQuery, PeopleRow, PersonCollection, PersonDetail, PersonEvent, PersonInvite,
    PersonPatch, PersonSession, PersonUser, Skipped,
};
use locksy_core::api::roles::{self, MANAGER, OWNER};
use locksy_core::crypto::{is_uuid, random_token};
use locksy_core::now_unix;
use rusqlite::types::Value as SqlValue;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension, Row};
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::LazyLock;

/// Routes du lot, fusionnées dans l'API (sous `/api`).
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/people", get(people))
        .route("/admin/users/bulk", post(bulk_action))
        .route("/admin/users/:id", get(person).patch(patch_person))
        .route("/admin/users/:id/sessions/:sid", delete(close_session))
        .route("/admin/users/:id/offboard-plan", get(offboard_plan))
        .route("/admin/users/:id/offboard", post(offboard))
        .route("/admin/users/:id/access-report.csv", get(access_report))
        .route("/admin/invites/batch", post(invite_batch))
        .route("/admin/invites/:id/resend", post(invite_resend))
}

// ------------------------------------------------------------ Liste des personnes (A.6)

/// Comptes et invitations en attente, avec le statut et l'origine calculés.
/// Paramètres : `?1` = maintenant, `?2` = seuil d'inactivité.
///
/// Statut, du plus au moins prioritaire : suppression programmée, fin
/// d'accès passée, désactivé, inactif (aucune connexion depuis
/// `users.inactive_alert_days`, création comprise), actif. Origine : SSO,
/// annuaire (LDAP, sinon SCIM), invitation acceptée, sinon locale.
static PEOPLE_SQL: LazyLock<String> = LazyLock::new(|| {
    format!(
        "WITH base AS (SELECT u.*, {SEEN_SQL} AS seen FROM users u),
         p AS (
           SELECT 'user' AS kind, id, name, email, role,
                  CASE WHEN deprovision_at IS NOT NULL THEN 'pending_deprovision'
                       WHEN access_until IS NOT NULL AND access_until <= ?1 THEN 'expired'
                       WHEN disabled <> 0 THEN 'disabled'
                       WHEN COALESCE(seen, created_at) < ?2 THEN 'inactive'
                       ELSE 'active' END AS status,
                  totp_secret IS NOT NULL AS twofa,
                  CASE WHEN sso_subject IS NOT NULL THEN 'sso'
                       WHEN EXISTS (SELECT 1 FROM directory_users d WHERE d.user_id = base.id AND d.source = 'ldap') THEN 'ldap'
                       WHEN EXISTS (SELECT 1 FROM directory_users d WHERE d.user_id = base.id) THEN 'scim'
                       WHEN EXISTS (SELECT 1 FROM invites i WHERE i.email = base.email AND i.used_at IS NOT NULL) THEN 'invite'
                       ELSE 'local' END AS origin,
                  seen AS last_seen_at, created_at, access_until, deprovision_at, disabled_reason,
                  NULL AS expires_at, 0 AS sent_count, NULL AS last_sent_at
           FROM base
           UNION ALL
           SELECT 'invite', id, NULL, email, role,
                  CASE WHEN expires_at > ?1 THEN 'invited' ELSE 'invite_expired' END,
                  0, 'invite', NULL, created_at, access_until, NULL, NULL, expires_at, sent_count, last_sent_at
           FROM invites WHERE used_at IS NULL)"
    )
});

const PEOPLE_COLUMNS: &str = "kind, id, name, email, role, status, twofa, origin, last_seen_at, created_at, access_until,
                              deprovision_at, disabled_reason, expires_at, sent_count, last_sent_at";

fn people_row(r: &Row, me: &str) -> rusqlite::Result<PeopleRow> {
    let kind: String = r.get(0)?;
    let id: String = r.get(1)?;
    Ok(if kind == "user" {
        PeopleRow::User(PersonUser {
            is_self: id == me,
            id,
            name: r.get(2)?,
            email: r.get(3)?,
            role: r.get(4)?,
            status: r.get(5)?,
            twofa: r.get(6)?,
            origin: r.get(7)?,
            last_seen_at: r.get(8)?,
            created_at: r.get(9)?,
            access_until: r.get(10)?,
            deprovision_at: r.get(11)?,
            disabled_reason: r.get(12)?,
        })
    } else {
        PeopleRow::Invite(PersonInvite {
            id,
            email: r.get(3)?,
            role: r.get(4)?,
            status: r.get(5)?,
            expires_at: r.get(13)?,
            created_at: r.get(9)?,
            sent_count: r.get(14)?,
            last_sent_at: r.get(15)?,
            access_until: r.get(10)?,
            origin: "invite".into(),
        })
    })
}

/// Filtre de base de la liste : les deux paramètres de `PEOPLE_SQL`.
fn people_filter(now: i64, inactive_days: i64) -> Filter {
    let mut f = Filter::default();
    f.args.extend([SqlValue::Integer(now), SqlValue::Integer(now - inactive_days * 86_400)]);
    f
}

fn order_by(sort: Sort) -> String {
    let key = match sort.column {
        "nom" => "COALESCE(NULLIF(name, ''), email) COLLATE NOCASE",
        "email" => "email COLLATE NOCASE",
        "role" => "CASE role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END",
        "derniere_connexion" => "last_seen_at",
        _ => "created_at",
    };
    // L'identifiant départage les égalités : pagination stable.
    format!("ORDER BY {key} {}, id", if sort.desc { "DESC" } else { "ASC" })
}

fn select_people(c: &Connection, f: &Filter, order: &str, limit: i64, offset: i64, me: &str) -> ApiResult<Vec<PeopleRow>> {
    let mut args = f.args.clone();
    args.extend([SqlValue::Integer(limit), SqlValue::Integer(offset)]);
    let sql = format!("{} SELECT {PEOPLE_COLUMNS} FROM p {} {order} LIMIT ? OFFSET ?", *PEOPLE_SQL, f.sql());
    let rows = c.prepare(&sql)?.query_map(params_from_iter(&args), |r| people_row(r, me))?.collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Ligne A.6 d'un compte.
fn person_row(c: &Connection, id: &str, me: &str, now: i64, inactive_days: i64) -> ApiResult<PersonUser> {
    let mut f = people_filter(now, inactive_days);
    f.push("kind = 'user' AND id = ?", [text(id)]);
    match select_people(c, &f, "", 1, 0, me)?.pop() {
        Some(PeopleRow::User(u)) => Ok(u),
        _ => Err(ApiError::not_found("Utilisateur introuvable.")),
    }
}

fn apply_filter(f: &mut Filter, p: &PeopleFilter) {
    if !p.q.is_empty() {
        let v = like_contains(&p.q);
        f.push("(email LIKE ? ESCAPE '\\' OR COALESCE(name, '') LIKE ? ESCAPE '\\')", [v.clone(), v]);
    }
    if let Some(s) = p.status {
        f.push("status = ?", [text(s)]);
    }
    if let Some(r) = p.role {
        f.push("role = ?", [text(r)]);
    }
    if let Some(t) = p.twofa {
        f.push("kind = 'user' AND twofa = ?", [SqlValue::Integer(i64::from(t))]);
    }
    if let Some(o) = p.origin {
        f.push("origin = ?", [text(o)]);
    }
}

/// `GET /admin/people` : comptes et invitations, filtrés, triés, paginés.
async fn people(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Query(q): Query<PeopleQuery>,
) -> ApiResult<Json<PeoplePage>> {
    let p = q.parse().map_err(ApiError::bad_request)?;
    let inactive_days = state.effective().await?.int("users.inactive_alert_days");
    Ok(Json(
        state
            .db
            .read(move |c| {
                let mut f = people_filter(now_unix(), inactive_days);
                apply_filter(&mut f, &p);
                let total: i64 = c.query_row(
                    &format!("{} SELECT COUNT(*) FROM p {}", *PEOPLE_SQL, f.sql()),
                    params_from_iter(&f.args),
                    |r| r.get(0),
                )?;
                let offset = (p.page - 1).saturating_mul(p.per_page);
                let rows = select_people(c, &f, &order_by(p.sort), p.per_page, offset, &admin.id)?;
                Ok(PeoplePage { total, page: p.page, per_page: p.per_page, rows })
            })
            .await?,
    ))
}

// ------------------------------------------------------------ Fiche

/// Appartenance d'une personne à un coffre (métadonnées seulement).
struct Membership {
    id: String,
    role: String,
    personal: bool,
    members: i64,
    managers: i64,
    items: i64,
    rotation_suggested_at: Option<i64>,
}

impl Membership {
    fn sole_manager(&self) -> bool {
        self.role == MANAGER && self.managers == 1
    }

    fn shared(&self) -> bool {
        self.members > 1
    }
}

fn memberships(c: &Connection, user_id: &str) -> ApiResult<Vec<Membership>> {
    let rows = c
        .prepare(
            "SELECT c.id, m.role, c.personal,
                    (SELECT COUNT(*) FROM memberships x WHERE x.collection_id = c.id),
                    (SELECT COUNT(*) FROM memberships x WHERE x.collection_id = c.id AND x.role = 'manager'),
                    (SELECT COUNT(*) FROM items i WHERE i.collection_id = c.id AND i.deleted_at IS NULL),
                    c.rotation_suggested_at
             FROM memberships m JOIN collections c ON c.id = m.collection_id
             WHERE m.user_id = ?1
             ORDER BY c.personal DESC, c.created_at, c.id",
        )?
        .query_map([user_id], |r| {
            Ok(Membership {
                id: r.get(0)?,
                role: r.get(1)?,
                personal: r.get(2)?,
                members: r.get(3)?,
                managers: r.get(4)?,
                items: r.get(5)?,
                rotation_suggested_at: r.get(6)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Événements récents : actions de la personne et actions qui la visent.
const RECENT_EVENTS: i64 = 20;

/// `GET /admin/users/:id` : ligne A.6, sessions, coffres, activité récente.
async fn person(State(state): State<AppState>, AdminUser(admin): AdminUser, Path(id): Path<String>) -> ApiResult<Json<PersonDetail>> {
    sec::uuid_path(&id, "Utilisateur")?;
    let inactive_days = state.effective().await?.int("users.inactive_alert_days");
    Ok(Json(
        state
            .db
            .read(move |c| {
                let person = person_row(c, &id, &admin.id, now_unix(), inactive_days)?;
                let sessions = c
                    .prepare(
                        "SELECT id, device, ip, last_seen_at, created_at FROM sessions
                         WHERE user_id = ?1 ORDER BY last_seen_at DESC, id",
                    )?
                    .query_map([&id], |r| {
                        let sid: String = r.get(0)?;
                        Ok(PersonSession {
                            current: sid == admin.session_id,
                            id: sid,
                            device: r.get(1)?,
                            ip: r.get(2)?,
                            last_seen_at: r.get(3)?,
                            created_at: r.get(4)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                let collections = memberships(c, &id)?
                    .into_iter()
                    .map(|m| PersonCollection {
                        sole_manager: m.sole_manager(),
                        shared: m.shared(),
                        id: m.id,
                        role: m.role,
                        personal: m.personal,
                        members_count: m.members,
                        managers_count: m.managers,
                        items_count: m.items,
                        rotation_suggested_at: m.rotation_suggested_at,
                    })
                    .collect();
                let recent_events = c
                    .prepare(
                        "SELECT at, action, details, target FROM audit
                         WHERE user_id = ?1 OR target = ?2 ORDER BY id DESC LIMIT ?3",
                    )?
                    .query_map(params![id, person.email, RECENT_EVENTS], |r| {
                        let (action, details): (String, String) = (r.get(1)?, r.get(2)?);
                        Ok(PersonEvent {
                            at: r.get(0)?,
                            severity: aa::entry_severity(&action, &details).to_string(),
                            action,
                            target: r.get(3)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                let recovery_codes_remaining = if person.twofa {
                    Some(c.query_row(
                        "SELECT COUNT(*) FROM totp_recovery_codes WHERE user_id = ?1 AND used_at IS NULL",
                        [&id],
                        |r| r.get(0),
                    )?)
                } else {
                    None
                };
                Ok(PersonDetail { person, sessions, collections, recent_events, recovery_codes_remaining })
            })
            .await?,
    ))
}

/// `PATCH /admin/users/:id` : nom, adresse e-mail, date de fin d'accès.
async fn patch_person(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
    Json(p): Json<PersonPatch>,
) -> ApiResult<Json<PeopleRow>> {
    sec::uuid_path(&id, "Utilisateur")?;
    let name = p.name.as_deref().map(sec::clean_name).transpose()?;
    let email = p.email.as_deref().map(sec::normalize_email).transpose()?;
    if let Some(Some(t)) = p.access_until {
        if t <= 0 {
            return Err(ApiError::bad_request("Date de fin d'accès invalide."));
        }
    }
    let eff = state.effective().await?;
    let inactive_days = eff.int("users.inactive_alert_days");
    let row = state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let now = now_unix();
            let t = target(&tx, &id)?;
            // Toucher un administrateur ou un propriétaire (dont changer son
            // adresse) est réservé aux propriétaires.
            guard(&tx, &admin, &id, &t.role, Act::Touch)?;
            let mut changed = Vec::new();
            if let Some(name) = name.filter(|n| *n != t.name) {
                tx.execute("UPDATE users SET name = ?1 WHERE id = ?2", params![name, id])?;
                changed.push("nom");
            }
            if let Some(email) = email.filter(|e| !e.eq_ignore_ascii_case(&t.email)) {
                sec::require_email_domain(&eff, &email)?;
                if email_in_use(&tx, &email, &id)? {
                    return Err(email_taken());
                }
                tx.execute("UPDATE users SET email = ?1 WHERE id = ?2", params![email, id])?;
                changed.push("e-mail");
            }
            if let Some(until) = p.access_until {
                let current: Option<i64> = tx.query_row("SELECT access_until FROM users WHERE id = ?1", [&id], |r| r.get(0))?;
                if until != current {
                    if id == admin.id {
                        return Err(Refusal::SelfAction.error());
                    }
                    tx.execute("UPDATE users SET access_until = ?1 WHERE id = ?2", params![until, id])?;
                    // Fin d'accès déjà passée : déconnexion immédiate.
                    if until.is_some_and(|u| u <= now) {
                        tx.execute("DELETE FROM sessions WHERE user_id = ?1", [&id])?;
                    }
                    changed.push("fin d'accès");
                }
            }
            if !changed.is_empty() {
                tx.execute("UPDATE users SET updated_at = ?1 WHERE id = ?2", params![now, id])?;
                audit_user(&tx, &admin, "admin.user_updated", &t.email, &format!("champs : {}", changed.join(", ")))?;
            }
            let row = person_row(&tx, &id, &admin.id, now, inactive_days)?;
            tx.commit()?;
            Ok(row)
        })
        .await?;
    Ok(Json(PeopleRow::User(row)))
}

/// `DELETE /admin/users/:id/sessions/:sid` : ferme une session de la personne.
async fn close_session(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path((id, sid)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    sec::uuid_path(&id, "Utilisateur")?;
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let t = target(&tx, &id)?;
            guard(&tx, &admin, &id, &t.role, Act::Touch)?;
            if tx.execute("DELETE FROM sessions WHERE id = ?1 AND user_id = ?2", params![sid, id])? == 0 {
                return Err(ApiError::not_found("Session introuvable."));
            }
            audit_user(&tx, &admin, "admin.user_session_closed", &t.email, "")?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ------------------------------------------------------------ Actions de masse (A.7)

/// `POST /admin/users/bulk` : une transaction ; chaque compte est traité ou
/// ignoré avec sa raison (soi-même, dernier propriétaire, réservé aux
/// propriétaires, introuvable, déjà dans l'état demandé).
async fn bulk_action(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    headers: HeaderMap,
    Json(req): Json<BulkRequest>,
) -> ApiResult<Json<BulkResponse>> {
    if req.ids.is_empty() {
        return Err(ApiError::bad_request("Aucun compte sélectionné."));
    }
    if req.ids.len() > bulk::MAX_IDS {
        return Err(ApiError::bad_request(format!("{} comptes au plus par action.", bulk::MAX_IDS)));
    }
    let action = bulk::ACTIONS
        .iter()
        .copied()
        .find(|a| *a == req.action)
        .ok_or_else(|| ApiError::bad_request("Action inconnue : disable, enable, revoke_sessions, reset_2fa ou set_role."))?;
    let role = match (action, req.role.as_deref()) {
        ("set_role", Some(r)) if roles::ORG_ROLES.contains(&r) => Some(r.to_string()),
        ("set_role", _) => return Err(ApiError::bad_request("Rôle inconnu : owner, admin ou user.")),
        _ => None,
    };
    // Confirmation d'identité : nomination d'administrateurs ou de
    // propriétaires (« admin.role »), réinitialisation de la double
    // authentification (« admin.bulk », comme l'action unitaire).
    match (action, role.as_deref()) {
        ("set_role", Some(r)) if r != roles::USER => sec::require_step_up(&state, &admin, &headers, "admin.role").await?,
        ("reset_2fa", _) => sec::require_step_up(&state, &admin, &headers, "admin.bulk").await?,
        _ => {}
    }
    let eff = state.effective().await?;
    let notifier = state.notifier.clone();
    let ids = req.ids;
    Ok(Json(
        state
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                let mut out = BulkResponse::default();
                let mut seen = HashSet::new();
                for id in ids {
                    if !seen.insert(id.clone()) {
                        continue;
                    }
                    let skip = |out: &mut BulkResponse, reason: &str| {
                        out.skipped.push(Skipped { id: id.clone(), reason: reason.to_string() })
                    };
                    let Some(t) = is_uuid(&id).then(|| find_target(&tx, &id)).transpose()?.flatten() else {
                        skip(&mut out, bulk::SKIP_NOT_FOUND);
                        continue;
                    };
                    if id == admin.id {
                        skip(&mut out, bulk::SKIP_SELF);
                        continue;
                    }
                    let act = match (action, role.as_deref()) {
                        ("disable", _) => Act::Disable,
                        ("enable", _) => Act::Enable,
                        ("set_role", Some(r)) => Act::SetRole(r),
                        _ => Act::Touch,
                    };
                    if let Some(r) = refusal(&tx, &admin, &id, &t.role, act)? {
                        skip(&mut out, r.reason());
                        continue;
                    }
                    let done = match act {
                        Act::Disable if !t.disabled => {
                            set_disabled_reason(&tx, &id, &t.role, true, "admin")?;
                            audit_user(&tx, &admin, "admin.user_disabled", &t.email, "")?;
                            true
                        }
                        Act::Enable if t.disabled => {
                            set_disabled_reason(&tx, &id, &t.role, false, "admin")?;
                            audit_user(&tx, &admin, "admin.user_enabled", &t.email, "")?;
                            true
                        }
                        Act::SetRole(r) if r != t.role => {
                            tx.execute("UPDATE users SET role = ?1, updated_at = ?2 WHERE id = ?3", params![r, now_unix(), id])?;
                            audit_user(&tx, &admin, "admin.user_role", &t.email, &format!("{} → {r}", t.role))?;
                            true
                        }
                        Act::Touch if action == "reset_2fa" && t.twofa => {
                            clear_2fa(&tx, notifier.as_ref(), &eff, &admin, &id, &t.email)?;
                            true
                        }
                        Act::Touch if action == "revoke_sessions" => {
                            let n = tx.execute("DELETE FROM sessions WHERE user_id = ?1", [&id])?;
                            if n > 0 {
                                audit_user(&tx, &admin, "admin.sessions_revoked", &t.email, &format!("{n} session(s)"))?;
                            }
                            n > 0
                        }
                        _ => false,
                    };
                    if done {
                        out.done.push(id);
                    } else {
                        skip(&mut out, bulk::SKIP_UNCHANGED);
                    }
                }
                let summary = format!("{action} : {} effectuée(s), {} ignorée(s)", out.done.len(), out.skipped.len());
                audit_user(&tx, &admin, "admin.bulk_action", action, &summary)?;
                tx.commit()?;
                Ok(out)
            })
            .await?,
    ))
}

// ------------------------------------------------------------ Invitations (A.9)

/// `POST /admin/invites/batch` : une invitation par adresse valide.
async fn invite_batch(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    headers: HeaderMap,
    Json(req): Json<InviteBatchRequest>,
) -> ApiResult<Json<InviteBatchResponse>> {
    if req.emails.is_empty() {
        return Err(ApiError::bad_request("Aucune adresse à inviter."));
    }
    if req.emails.len() > invites::MAX_BATCH {
        return Err(ApiError::bad_request(format!("{} adresses au plus par envoi.", invites::MAX_BATCH)));
    }
    check_invite_role(&admin, &req.role)?;
    check_access_until(req.access_until, now_unix())?;
    let ctx = InviteCtx::new(&state, admin, &headers).await?;
    Ok(Json(
        state
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                let now = now_unix();
                let mut out = InviteBatchResponse::default();
                let mut seen = HashSet::new();
                for (index, raw) in req.emails.iter().enumerate() {
                    // Nom facultatif au même rang que l'adresse ; illisible : ignoré.
                    let name = req.names.get(index).and_then(|n| sec::clean_optional_name(n).ok()).unwrap_or_default();
                    let skip = |out: &mut InviteBatchResponse, email: &str, reason: &str| {
                        out.skipped.push(InviteSkipped { email: email.to_string(), reason: reason.to_string() })
                    };
                    let Ok(email) = sec::normalize_email(raw) else {
                        skip(&mut out, &raw.trim().chars().take(254).collect::<String>(), invites::SKIP_INVALID);
                        continue;
                    };
                    let pending: bool = tx.query_row(
                        "SELECT COUNT(*) > 0 FROM invites WHERE email = ?1 AND used_at IS NULL AND expires_at > ?2",
                        params![email, now],
                        |r| r.get(0),
                    )?;
                    let reason = if !seen.insert(email.clone()) || pending {
                        Some(invites::SKIP_INVITED)
                    } else if !sec::email_domain_allowed(&ctx.eff, &email) {
                        Some(invites::SKIP_DOMAIN)
                    } else if email_in_use(&tx, &email, "")? {
                        Some(invites::SKIP_EXISTS)
                    } else {
                        None
                    };
                    if let Some(reason) = reason {
                        skip(&mut out, &email, reason);
                        continue;
                    }
                    // Une invitation expirée pour la même adresse est remplacée.
                    tx.execute("DELETE FROM invites WHERE email = ?1 AND used_at IS NULL", [&email])?;
                    let inv = insert_invite(&tx, &ctx, &email, &name, &req.role, req.access_until)?;
                    out.created.push(InviteLink { id: inv.id, email, link: inv.link, mailed: inv.mailed, expires_at: inv.expires_at });
                }
                tx.commit()?;
                Ok(out)
            })
            .await?,
    ))
}

/// `POST /admin/invites/:id/resend` : nouveau lien (l'ancien ne vaut plus),
/// validité recalculée, nouvel envoi.
async fn invite_resend(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<InviteResent>> {
    sec::uuid_path(&id, "Invitation")?;
    let ctx = InviteCtx::new(&state, admin, &headers).await?;
    Ok(Json(
        state
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                let found: Option<(String, String, Option<i64>, String)> = tx
                    .query_row("SELECT email, role, used_at, name FROM invites WHERE id = ?1", [&id], |r| {
                        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                    })
                    .optional()?;
                let (email, role, used_at, name) = found.ok_or_else(|| ApiError::not_found("Invitation introuvable."))?;
                if used_at.is_some() {
                    return Err(ApiError::conflict("Cette invitation a déjà été utilisée : le compte existe."));
                }
                if role != roles::USER && ctx.admin.role != OWNER {
                    return Err(owner_only());
                }
                sec::require_email_domain(&ctx.eff, &email)?;
                let now = now_unix();
                let token = random_token();
                let expires_at = ctx.expires_at(now);
                tx.execute(
                    "UPDATE invites SET token_hash = ?1, expires_at = ?2, sent_count = sent_count + 1, last_sent_at = ?3
                     WHERE id = ?4",
                    params![sha256_hex(&token), expires_at, now, id],
                )?;
                let link = ctx.link(&token);
                let mailed = ctx.notify(&tx, &id, &email, &name, &link, expires_at)?;
                audit_user(&tx, &ctx.admin, "admin.invite_resent", &email, "")?;
                tx.commit()?;
                Ok(InviteResent { id, link, mailed, expires_at })
            })
            .await?,
    ))
}

// ------------------------------------------------------------ Départ de l'entreprise (A.8)

/// Bornes de `delete_after_days` (mêmes que `directory.delete_after_days`).
const MAX_DELETE_AFTER_DAYS: i64 = 365;

fn not_a_member() -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "not_a_member",
        "Le repreneur choisi n'est pas membre de ce coffre : choisissez une personne qui y a déjà accès.",
    )
}

fn invalid_transfer() -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid_transfer",
        "Transfert impossible : coffre inconnu de cette personne, repreneur en double, désactivé ou identique.",
    )
}

/// `GET /admin/users/:id/offboard-plan` : coffres de la personne et
/// repreneurs possibles (membres existants), sans aucun nom de coffre.
async fn offboard_plan(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
) -> ApiResult<Json<OffboardPlan>> {
    sec::uuid_path(&id, "Utilisateur")?;
    let eff = state.effective().await?;
    let (inactive_days, delete_after_days) = (eff.int("users.inactive_alert_days"), eff.int("directory.delete_after_days"));
    Ok(Json(
        state
            .db
            .read(move |c| {
                let p = person_row(c, &id, &admin.id, now_unix(), inactive_days)?;
                let sessions = c.query_row("SELECT COUNT(*) FROM sessions WHERE user_id = ?1", [&id], |r| r.get(0))?;
                let mut collections = Vec::new();
                for m in memberships(c, &id)? {
                    let members = c
                        .prepare(
                            "SELECT m.user_id, u.name, u.email, m.role FROM memberships m JOIN users u ON u.id = m.user_id
                             WHERE m.collection_id = ?1 AND m.user_id <> ?2
                             ORDER BY u.name COLLATE NOCASE, u.id",
                        )?
                        .query_map(params![m.id, id], |r| {
                            Ok(OffboardMember { user_id: r.get(0)?, name: r.get(1)?, email: r.get(2)?, role: r.get(3)? })
                        })?
                        .collect::<Result<Vec<_>, _>>()?;
                    collections.push(OffboardCollection {
                        sole_manager: m.sole_manager(),
                        shared: m.shared(),
                        id: m.id,
                        personal: m.personal,
                        items_count: m.items,
                        members,
                    });
                }
                Ok(OffboardPlan {
                    user: OffboardUser { id: p.id, name: p.name, email: p.email, role: p.role, status: p.status },
                    sessions,
                    collections,
                    delete_after_days,
                })
            })
            .await?,
    ))
}

#[derive(Deserialize, Debug, Default)]
struct OffboardParams {
    #[serde(default)]
    dry_run: Option<bool>,
}

/// Départ, dans la transaction `tx` (validée par l'appelant, ou annulée pour
/// une simulation : mêmes contrôles, même rapport, aucune écriture).
fn offboard_tx(tx: &Connection, actor: &AuthUser, id: &str, req: &OffboardRequest, days: i64, now: i64) -> ApiResult<OffboardReport> {
    let t = target(tx, id)?;
    if id == actor.id {
        return Err(Refusal::SelfAction.error());
    }
    guard(tx, actor, id, &t.role, if req.disable { Act::Disable } else { Act::Touch })?;
    let cols = memberships(tx, id)?;
    let mut report = OffboardReport::default();

    // Repreneurs : promotion d'un membre existant, aucune clé transmise.
    let mut transferred = HashSet::new();
    for tr in &req.transfers {
        let Some(m) = cols.iter().find(|m| m.id == tr.collection_id) else {
            return Err(invalid_transfer());
        };
        if tr.new_manager_id == id || !transferred.insert(m.id.as_str()) {
            return Err(invalid_transfer());
        }
        let disabled: Option<bool> = tx
            .query_row(
                "SELECT u.disabled FROM memberships m JOIN users u ON u.id = m.user_id
                 WHERE m.collection_id = ?1 AND m.user_id = ?2",
                params![m.id, tr.new_manager_id],
                |r| r.get(0),
            )
            .optional()?;
        match disabled {
            None => return Err(not_a_member()),
            Some(true) => return Err(invalid_transfer()),
            Some(false) => {}
        }
        tx.execute(
            "UPDATE memberships SET role = 'manager' WHERE collection_id = ?1 AND user_id = ?2",
            params![m.id, tr.new_manager_id],
        )?;
        audit_user(tx, actor, "admin.collection_manager_transferred", &m.id, &format!("{id} → {}", tr.new_manager_id))?;
    }
    report.transferred = transferred.len() as i64;

    // Coffres sans autre membre : illisibles après le départ (zéro connaissance).
    report.orphaned = cols
        .iter()
        .filter(|m| !m.shared())
        .map(|m| Orphaned { collection_id: m.id.clone(), items_count: m.items })
        .collect();

    // Mots de passe connus : rotation conseillée aux autres membres.
    if req.suggest_rotation {
        for m in cols.iter().filter(|m| m.shared()) {
            tx.execute("UPDATE collections SET rotation_suggested_at = ?1 WHERE id = ?2", params![now, m.id])?;
            audit_user(tx, actor, "admin.rotation_suggested", &m.id, id)?;
            report.rotation_suggested += 1;
        }
    }

    let sessions: i64 = tx.query_row("SELECT COUNT(*) FROM sessions WHERE user_id = ?1", [id], |r| r.get(0))?;
    if req.disable {
        report.shares_revoked = crate::shares::revoke_for_user(tx, id, crate::shares::reason::OWNER_DISABLED, Some(&actor.id))? as i64;
        set_disabled_reason(tx, id, &t.role, true, "offboard")?;
        report.disabled = true;
        report.sessions_closed = sessions;
        report.deprovision_at = Some(now + days * 86_400);
    } else if req.revoke_sessions {
        tx.execute("DELETE FROM sessions WHERE user_id = ?1", [id])?;
        report.sessions_closed = sessions;
    }
    let summary = format!(
        "désactivé : {}, sessions fermées : {}, repreneurs : {}, coffres orphelins : {}, rotations conseillées : {}, liens révoqués : {}, suppression : {}",
        if report.disabled { "oui" } else { "non" },
        report.sessions_closed,
        report.transferred,
        report.orphaned.len(),
        report.rotation_suggested,
        report.shares_revoked,
        match report.deprovision_at {
            None => "aucune".to_string(),
            Some(_) if days == 0 => "immédiate".to_string(),
            Some(_) => format!("dans {days} jour(s)"),
        }
    );
    audit_user(tx, actor, "admin.user_offboarded", &t.email, &summary)?;
    if req.disable {
        if days == 0 {
            let removed = remove_user(tx, id, &t.role)?;
            audit_user(tx, actor, "admin.user_deleted", &t.email, &format!("départ : {removed} coffre(s) sans membre supprimé(s)"))?;
        } else {
            tx.execute("UPDATE users SET deprovision_at = ?1 WHERE id = ?2", params![report.deprovision_at, id])?;
        }
    }
    Ok(report)
}

/// `POST /admin/users/:id/offboard?dry_run=true|false`. La simulation fait
/// exactement les mêmes opérations dans une transaction annulée. Le départ
/// réel exige une confirmation d'identité « admin.offboard », ou
/// « admin.delete_user » quand la suppression est immédiate (0 jour).
async fn offboard(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
    Query(params): Query<OffboardParams>,
    headers: HeaderMap,
    Json(req): Json<OffboardRequest>,
) -> ApiResult<Json<OffboardResponse>> {
    sec::uuid_path(&id, "Utilisateur")?;
    let days = match req.delete_after_days {
        Some(d) if !(0..=MAX_DELETE_AFTER_DAYS).contains(&d) => {
            return Err(ApiError::bad_request(format!(
                "Délai avant suppression : entre 0 et {MAX_DELETE_AFTER_DAYS} jours."
            )))
        }
        Some(d) => d,
        None => state.effective().await?.int("directory.delete_after_days"),
    };
    let dry_run = params.dry_run.unwrap_or(false);
    let simulate = |state: AppState, admin: AuthUser, id: String, req: OffboardRequest| async move {
        state
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                offboard_tx(&tx, &admin, &id, &req, days, now_unix())
                // `tx` abandonnée : annulation, aucune écriture.
            })
            .await
    };
    // Simulation d'abord : un refus ne consomme pas la confirmation d'identité.
    let simulated = simulate(state.clone(), admin.clone(), id.clone(), req.clone()).await?;
    let report = if dry_run {
        simulated
    } else {
        let action = if req.disable && days == 0 { "admin.delete_user" } else { "admin.offboard" };
        sec::require_step_up(&state, &admin, &headers, action).await?;
        let uid = id.clone();
        state
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                let report = offboard_tx(&tx, &admin, &uid, &req, days, now_unix())?;
                tx.commit()?;
                Ok(report)
            })
            .await?
    };
    Ok(Json(OffboardResponse { report, report_csv: format!("/api/admin/users/{id}/access-report.csv") }))
}

/// Actions de départ consignées au journal pour un coffre de la personne.
fn collection_actions(c: &Connection, user_id: &str, m: &Membership) -> ApiResult<Vec<String>> {
    let mut actions: Vec<String> = c
        .prepare(
            "SELECT action, details FROM audit
             WHERE target = ?1
               AND ((action = 'admin.rotation_suggested' AND details = ?2)
                 OR (action = 'admin.collection_manager_transferred' AND substr(details, 1, length(?2) + 3) = ?2 || ' → '))
             ORDER BY id",
        )?
        .query_map(params![m.id, user_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .map(|row| {
            row.map(|(action, details)| match details.split_once(" → ") {
                Some((_, to)) if action == "admin.collection_manager_transferred" => format!("repreneur : {to}"),
                _ => "rotation conseillée".to_string(),
            })
        })
        .collect::<Result<_, _>>()?;
    if !m.shared() {
        actions.push("aucun autre membre : supprimé avec le compte".into());
    }
    Ok(actions)
}

/// `GET /admin/users/:id/access-report.csv` : un coffre par ligne
/// (identifiant, jamais de nom), séparateur et fuseau de l'organisation.
async fn access_report(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    sec::uuid_path(&id, "Utilisateur")?;
    let fmt = CsvFormat::new(&*state.effective().await?);
    let uid = id.clone();
    let (email, seen, rows) = state
        .db
        .read(move |c| {
            let t = target(c, &uid)?;
            let seen: Option<i64> =
                c.query_row(&format!("SELECT {SEEN_SQL} FROM users u WHERE u.id = ?1"), [&uid], |r| r.get(0))?;
            let mut rows = Vec::new();
            for m in memberships(c, &uid)? {
                let actions = collection_actions(c, &uid, &m)?;
                rows.push((m, actions));
            }
            Ok((t.email, seen, rows))
        })
        .await?;
    let n = rows.len();
    let target_email = email.clone();
    state
        .db
        .call(move |c| audit_user(c, &admin, "admin.access_report_exported", &target_email, &format!("{n} coffre(s)")))
        .await?;
    let seen = seen.map(|s| fmt.local(s)).unwrap_or_default();
    let header: Vec<String> = aa::ACCESS_REPORT_COLUMNS.iter().map(|c| c.to_string()).collect();
    let mut out = String::from("\u{feff}");
    out.push_str(&fmt.line(&header));
    for (m, actions) in rows {
        out.push_str(&fmt.line(&[
            csv_field(&m.id),
            csv_field(&m.role),
            m.members.to_string(),
            m.items.to_string(),
            csv_field(if m.sole_manager() { "oui" } else { "non" }),
            csv_field(&seen),
            csv_field(&actions.join(", ")),
        ]));
    }
    Ok(csv_response("locksy-rapport-acces.csv", out))
}
