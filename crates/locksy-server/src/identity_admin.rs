//! Connexion d'entreprise côté administration : tests enregistrés par
//! acteur (`identity_tests`), état des méthodes (SSO, Active Directory,
//! SCIM), historique des synchronisations, désinscription différée des
//! comptes de l'annuaire et route publique « extension autorisée ? ».
//!
//! Garde-fou G-14 : imposer le SSO ou le compte Windows exige un test réussi
//! de moins de 24 h par l'administrateur qui enregistre.

use crate::admin::{remove_user, set_disabled_reason};
use crate::error::ApiResult;
use crate::state::{audit, audit_user, AdminUser, AppState, AuthUser, ClientMeta};
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::Router;
use crate::error::Json;
use locksy_core::api::roles;
use locksy_core::now_unix;
use locksy_core::settings::Effective;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const DAY: i64 = 86_400;

/// Routes du lot, fusionnées dans l'API (préfixe `/api`).
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/sso/test-start", post(crate::sso::test_start))
        .route("/admin/ldap/test-login", post(crate::ldap::test_login))
        .route("/admin/ldap/history", get(ldap_history))
        .route("/admin/identity/status", get(status))
        .route("/extension/allowed", get(extension_allowed))
}

// ------------------------------------------------------------ Tests enregistrés

/// Méthodes de connexion d'entreprise qui se testent avec le compte de
/// l'administrateur.
const TEST_KINDS: [&str; 2] = ["sso", "ldap"];

/// Enregistre le résultat d'un test de connexion réel de `actor`
/// (`code` : `None` en cas de réussite, sinon le code d'échec stable) et le
/// journalise (`sso.tested` ou `ldap.tested`).
pub(crate) fn record_test(c: &Connection, kind: &str, actor: &AuthUser, code: Option<&str>) -> ApiResult<()> {
    debug_assert!(TEST_KINDS.contains(&kind), "type de test inconnu : {kind}");
    c.execute(
        "INSERT INTO identity_tests (kind, at, user_id, ok, error_code) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![kind, now_unix(), actor.id, code.is_none(), code],
    )?;
    let action = if kind == "sso" { "sso.tested" } else { "ldap.tested" };
    audit_user(c, actor, action, kind, code.unwrap_or("réussi"))
}

/// L'administrateur `user_id` a-t-il réussi un test de ce type depuis moins
/// de 24 h ? Le test d'un autre administrateur ne compte pas.
pub(crate) fn recent_test_ok(c: &Connection, kind: &str, user_id: &str, now: i64) -> ApiResult<bool> {
    let n: i64 = c.query_row(
        "SELECT COUNT(*) FROM identity_tests WHERE kind = ?1 AND user_id = ?2 AND ok = 1 AND at > ?3",
        params![kind, user_id, now - crate::sso::TEST_VALIDITY_SECS],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

#[derive(Serialize)]
struct LastTest {
    at: i64,
    ok: bool,
    error_code: Option<String>,
    by_me: bool,
}

#[derive(Serialize)]
struct LastError {
    at: i64,
    code: String,
}

/// Derniers tests d'un type : le plus récent (tout administrateur), la
/// dernière réussite de l'acteur, le dernier échec.
fn test_summary(c: &Connection, kind: &str, me: &str) -> ApiResult<(Option<LastTest>, Option<i64>, Option<LastError>)> {
    let last = c
        .query_row(
            "SELECT at, ok, error_code, user_id FROM identity_tests WHERE kind = ?1 ORDER BY at DESC, id DESC LIMIT 1",
            [kind],
            |r| {
                Ok(LastTest {
                    at: r.get(0)?,
                    ok: r.get(1)?,
                    error_code: r.get(2)?,
                    by_me: r.get::<_, String>(3)? == me,
                })
            },
        )
        .optional()?;
    let mine: Option<i64> = c.query_row(
        "SELECT MAX(at) FROM identity_tests WHERE kind = ?1 AND user_id = ?2 AND ok = 1",
        params![kind, me],
        |r| r.get(0),
    )?;
    let error = c
        .query_row(
            "SELECT at, COALESCE(error_code, 'unknown') FROM identity_tests WHERE kind = ?1 AND ok = 0
             ORDER BY at DESC, id DESC LIMIT 1",
            [kind],
            |r| Ok(LastError { at: r.get(0)?, code: r.get(1)? }),
        )
        .optional()?;
    Ok((last, mine, error))
}

// ------------------------------------------------------------ État des méthodes

/// `GET /admin/identity/status` : état du SSO, de l'annuaire et de SCIM
/// pour les écrans de connexion d'entreprise.
async fn status(State(state): State<AppState>, AdminUser(admin): AdminUser, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let eff = state.effective().await?;
    let scim_base = crate::scim::base_url(&crate::sso::public_base(&state, &eff, &headers));
    let ttl = eff.int("scim.token_ttl_days");
    let (sso_enforce, ldap_enforce) = (eff.bool("sso.enforce"), eff.bool("ldap.enforce"));
    let me = admin.id.clone();
    let body = state
        .db
        .read(move |c| {
            let sso_cfg = crate::sso::load_config(c)?;
            let ldap_cfg = crate::ldap::load_config(c)?;
            let (sso_last, sso_mine, sso_error) = test_summary(c, "sso", &me)?;
            let (ldap_last, ldap_mine, _) = test_summary(c, "ldap", &me)?;
            let token = crate::scim::token_info(c, ttl)?;
            Ok(json!({
                "sso": {
                    "configured": crate::sso::is_configured(&sso_cfg),
                    "enabled": sso_cfg.enabled,
                    "enforce": sso_enforce,
                    "last_test": sso_last,
                    "last_ok_by_me_at": sso_mine,
                    "last_error": sso_error,
                },
                "ldap": {
                    "configured": crate::ldap::is_configured(&ldap_cfg),
                    "enabled": ldap_cfg.enabled,
                    "allow_login": ldap_cfg.allow_login,
                    "enforce": ldap_enforce,
                    "last_test": ldap_last,
                    "last_ok_by_me_at": ldap_mine,
                    "last_sync": crate::ldap::history(c, 1)?.into_iter().next(),
                },
                "scim": {
                    "token_set": token.is_some(),
                    "token_created_at": token.as_ref().map(|t| t.created_at),
                    "token_expires_at": token.as_ref().and_then(|t| t.expires_at),
                    "last_used_at": token.as_ref().and_then(|t| t.last_used_at),
                    "base_url": scim_base,
                },
            }))
        })
        .await?;
    Ok(Json(body))
}

#[derive(Deserialize)]
struct HistoryQuery {
    #[serde(default)]
    limit: Option<i64>,
}

/// `GET /admin/ldap/history?limit=20` : synchronisations récentes (à blanc
/// comprises), la plus récente d'abord.
async fn ldap_history(
    State(state): State<AppState>,
    _a: AdminUser,
    Query(q): Query<HistoryQuery>,
) -> ApiResult<Json<Vec<crate::ldap::SyncHistory>>> {
    let limit = q.limit.unwrap_or(20).clamp(1, 200);
    Ok(Json(state.db.read(move |c| crate::ldap::history(c, limit)).await?))
}

// ------------------------------------------------------------ Extension autorisée

#[derive(Deserialize)]
struct ExtensionQuery {
    #[serde(default)]
    id: String,
}

/// Requêtes « extension autorisée ? » tolérées par adresse IP et par minute
/// (avant le facteur de l'hébergeur).
const EXTENSION_CHECK_PER_MIN: u32 = 30;

/// `GET /extension/allowed?id=<id>` (public) : l'extension de navigateur
/// d'identifiant `id` est-elle autorisée par l'organisation ? Remplace l'essai
/// d'un démarrage SSO par l'extension.
async fn extension_allowed(
    State(state): State<AppState>,
    meta: ClientMeta,
    Query(q): Query<ExtensionQuery>,
) -> ApiResult<Json<Value>> {
    let max = state.host.rate.scaled(EXTENSION_CHECK_PER_MIN);
    state.limiter.hit(&format!("ext-allowed:{}", meta.rate_key()), max, 60)?;
    let eff = state.effective().await?;
    Ok(Json(json!({ "allowed": crate::sso::extension_allowed(&eff, &q.id) })))
}

// ------------------------------------------------------------ Désinscription

/// Politique de désinscription d'un compte qui quitte l'annuaire
/// (`directory.deprovision`, `directory.delete_after_days`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Deprovision {
    /// Suppression programmée après la désactivation.
    pub then_delete: bool,
    /// Délai avant suppression, en jours (0 : immédiate).
    pub delete_after_days: i64,
}

impl Deprovision {
    pub(crate) fn from_eff(eff: &Effective) -> Self {
        Self {
            then_delete: eff.str("directory.deprovision") == "disable_then_delete",
            delete_after_days: eff.int("directory.delete_after_days").max(0),
        }
    }
}

/// Sort d'un compte qui quitte l'annuaire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Departure {
    /// Désactivé seulement (politique, ou compte d'administration).
    Disabled,
    /// Désactivé, suppression programmée à cette date.
    Scheduled(i64),
    /// Supprimé immédiatement (délai de 0 jour).
    Purged,
}

/// Méta des opérations sans client HTTP (maintenance, annuaire).
fn system_meta(origin: &str) -> ClientMeta {
    ClientMeta { ip: origin.into(), user_agent: "Désinscription de l'annuaire".into() }
}

/// Applique la politique de désinscription au compte `user_id` (motif
/// `reason` : « scim » ou « directory »), dans la transaction de l'appelant.
/// Un propriétaire ou un administrateur est seulement désactivé : sa
/// suppression reste une décision d'un administrateur Locksy. Le dernier
/// propriétaire n'est jamais désactivé (409 `last_owner`).
pub(crate) fn depart(
    c: &Connection,
    user_id: &str,
    role: &str,
    reason: &str,
    policy: Deprovision,
    meta: &ClientMeta,
    now: i64,
) -> ApiResult<Departure> {
    directory_disable(c, user_id, role, reason)?;
    if !policy.then_delete || role == roles::OWNER || role == roles::ADMIN {
        return Ok(Departure::Disabled);
    }
    let email: String = c.query_row("SELECT email FROM users WHERE id = ?1", [user_id], |r| r.get(0))?;
    if policy.delete_after_days == 0 {
        let removed = remove_user(c, user_id, role)?;
        let details = format!("suppression immédiate ({reason}), {removed} coffre(s) sans membre supprimé(s)");
        audit(c, Some(user_id), &email, "directory.user_purged", &email, meta, &details)?;
        return Ok(Departure::Purged);
    }
    let at = now + policy.delete_after_days * DAY;
    c.execute("UPDATE users SET deprovision_at = ?1 WHERE id = ?2", params![at, user_id])?;
    let details = format!("suppression dans {} jour(s) ({reason})", policy.delete_after_days);
    audit(c, Some(user_id), &email, "directory.deprovision_scheduled", &email, meta, &details)?;
    Ok(Departure::Scheduled(at))
}

/// Désactive un compte à la demande de l'annuaire (motif `reason`), sauf
/// s'il l'est déjà : le motif d'une désactivation décidée dans Locksy est
/// conservé (l'annuaire ne pourra donc pas la défaire). Le dernier
/// propriétaire actif n'est jamais désactivé (409 `last_owner`).
pub(crate) fn directory_disable(c: &Connection, user_id: &str, role: &str, reason: &str) -> ApiResult<()> {
    let disabled: bool = c.query_row("SELECT disabled FROM users WHERE id = ?1", [user_id], |r| r.get(0))?;
    if disabled {
        return Ok(());
    }
    set_disabled_reason(c, user_id, role, true, reason)
}

/// Réactive un compte désactivé par l'annuaire (SCIM, Active Directory, ou un
/// ancien Locksy sans motif) ; une désactivation décidée dans Locksy
/// (administration, départ, inactivité…) n'est pas défaite par l'annuaire.
/// La réactivation annule une suppression programmée.
pub(crate) fn reactivate(c: &Connection, user_id: &str) -> ApiResult<bool> {
    let row: Option<(bool, Option<String>, String)> = c
        .query_row("SELECT disabled, disabled_reason, role FROM users WHERE id = ?1", [user_id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .optional()?;
    match row {
        Some((true, reason, role)) if matches!(reason.as_deref(), None | Some("directory") | Some("scim")) => {
            set_disabled_reason(c, user_id, &role, false, "directory")?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// Exécute `f` dans un point de sauvegarde : tout ou rien, que l'appelant
/// soit dans une transaction ou non.
fn in_savepoint<T>(c: &Connection, f: impl FnOnce(&Connection) -> ApiResult<T>) -> ApiResult<T> {
    c.execute_batch("SAVEPOINT desinscription")?;
    match f(c) {
        Ok(v) => {
            c.execute_batch("RELEASE desinscription")?;
            Ok(v)
        }
        Err(e) => {
            if let Err(err) = c.execute_batch("ROLLBACK TO desinscription; RELEASE desinscription") {
                tracing::error!(error = %err, "annulation d'une désinscription impossible");
            }
            Err(e)
        }
    }
}

/// Supprime les comptes désactivés dont la date de suppression programmée
/// (`deprovision_at`) est passée ; renvoie leur nombre. Appelée par la
/// maintenance. Chaque compte est traité à part : un refus (dernier
/// propriétaire) n'empêche pas les autres et annule seulement sa propre
/// suppression (la date est alors effacée).
pub fn purge_deprovisioned(c: &Connection, now: i64) -> ApiResult<usize> {
    let due: Vec<(String, String, String)> = c
        .prepare(
            "SELECT id, role, email FROM users
             WHERE deprovision_at IS NOT NULL AND deprovision_at <= ?1 AND disabled = 1
             ORDER BY deprovision_at",
        )?
        .query_map([now], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<Result<_, _>>()?;
    let meta = system_meta("maintenance");
    let mut purged = 0;
    for (id, role, email) in due {
        let r = in_savepoint(c, |c| {
            let removed = remove_user(c, &id, &role)?;
            let details = format!("suppression programmée échue, {removed} coffre(s) sans membre supprimé(s)");
            audit(c, Some(&id), &email, "directory.user_purged", &email, &meta, &details)
        });
        match r {
            Ok(()) => purged += 1,
            Err(e) => {
                tracing::warn!(code = e.code, "suppression programmée refusée : date effacée");
                c.execute("UPDATE users SET deprovision_at = NULL WHERE id = ?1", [&id])?;
            }
        }
    }
    Ok(purged)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn add_user(c: &Connection, id: &str, role: &str, deprovision_at: Option<i64>) {
        c.execute(
            "INSERT INTO users (id, email, name, role, disabled, kdf, auth_hash, wrapped_user_key, recovery_wrapped_user_key,
                                recovery_auth_hash, public_key, wrapped_private_key, created_at, updated_at, deprovision_at)
             VALUES (?1, ?1 || '@corp.fr', 'Test', ?2, ?3, '{}', '', '', '', '', '', '', 0, 0, ?4)",
            params![id, role, deprovision_at.is_some(), deprovision_at],
        )
        .unwrap();
    }

    fn exists(c: &Connection, id: &str) -> bool {
        c.query_row("SELECT COUNT(*) FROM users WHERE id = ?1", [id], |r| r.get::<_, i64>(0)).unwrap() == 1
    }

    #[tokio::test]
    async fn purge_supprime_les_comptes_echus_seulement() {
        let st = crate::state::test_state().await;
        st.db
            .call(|c| {
                add_user(c, "patron", roles::OWNER, None);
                add_user(c, "echu", roles::USER, Some(100));
                add_user(c, "futur", roles::USER, Some(10_000));
                assert_eq!(purge_deprovisioned(c, 5_000)?, 1);
                assert!(!exists(c, "echu") && exists(c, "futur") && exists(c, "patron"));
                let n: i64 =
                    c.query_row("SELECT COUNT(*) FROM audit WHERE action = 'directory.user_purged'", [], |r| r.get(0))?;
                assert_eq!(n, 1);
                Ok(())
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn purge_ne_supprime_jamais_le_dernier_proprietaire() {
        let st = crate::state::test_state().await;
        st.db
            .call(|c| {
                // État incohérent (seul propriétaire, désactivé, suppression
                // programmée) : la purge refuse et efface la date.
                add_user(c, "seul", roles::OWNER, Some(100));
                assert_eq!(purge_deprovisioned(c, 5_000)?, 0);
                assert!(exists(c, "seul"));
                let at: Option<i64> = c.query_row("SELECT deprovision_at FROM users WHERE id = 'seul'", [], |r| r.get(0))?;
                assert_eq!(at, None);
                Ok(())
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn purge_dans_une_transaction_de_l_appelant() {
        let st = crate::state::test_state().await;
        st.db
            .call(|c| {
                add_user(c, "echu", roles::USER, Some(1));
                let tx = c.transaction()?;
                assert_eq!(purge_deprovisioned(&tx, 10)?, 1);
                tx.rollback()?;
                assert!(exists(c, "echu"), "annulée avec la transaction englobante");
                Ok(())
            })
            .await
            .unwrap();
    }
}
