//! Liens de partage externes. Le contenu est chiffré dans le navigateur avec
//! une clé placée après le `#` du lien : elle n'est jamais envoyée au serveur.
//!
//! Cycle de vie : un lien est `active`, puis passe dans un état terminal
//! (`revoked`, `expired` ou `exhausted`) avec son motif, son auteur et sa
//! date. Le contenu chiffré est effacé dans la transaction de la transition :
//! seule la trace (dates, compteurs) reste, jusqu'à la purge de la maintenance.
//!
//! Preuve de possession (contrat C5) : à la création, le client envoie
//! `verifier` = hex SHA-256(proof), avec proof = SHA-256(texte du fragment).
//! À l'ouverture, il présente `proof` (base64 URL) ; le serveur la compare en
//! temps constant AVANT de lire le chiffré ou de décompter une vue. Sans la
//! clé, on ne peut ni lire ni épuiser un lien. Les liens historiques (sans
//! `verifier`) restent servis par `GET /public/shares/:id`.

use crate::error::{ApiError, ApiResult};
use crate::security::{self as sec, sha256_hex};
use crate::state::{audit, audit_user, AdminUser, AppState, AuthUser, ClientMeta};
use crate::vault::{require_role, DataError, Missing, ANY};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use crate::error::Json;
use locksy_core::api::roles::OWNER;
use locksy_core::api::*;
use locksy_core::crypto::random_token;
use locksy_core::encoding::b64d_array;
use locksy_core::now_unix;
use rusqlite::{params, Connection, OptionalExtension, ToSql};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Motifs de fin d'un lien (`shares.ended_reason`, champ `reason` du 410).
pub(crate) mod reason {
    /// Révoqué par son créateur.
    pub const REVOKED: &str = "revoked";
    /// Révoqué en masse par un administrateur.
    pub const REVOKED_ADMIN: &str = "revoked_admin";
    pub const EXPIRED: &str = "expired";
    /// Nombre maximal de consultations atteint.
    pub const EXHAUSTED: &str = "exhausted";
    /// Élément mis à la corbeille ou supprimé.
    pub const ITEM_DELETED: &str = "item_deleted";
    /// Le créateur n'a plus accès au coffre de l'élément.
    pub const ACCESS_LOST: &str = "access_lost";
    /// Compte du créateur désactivé (passé par `admin::set_disabled`, lot L5).
    pub const OWNER_DISABLED: &str = "owner_disabled";
    /// Clé du coffre renouvelée.
    pub const ROTATED: &str = "rotated";
}

/// Réponse uniforme d'un lien inconnu ou d'une preuve fausse.
fn unknown_link() -> ApiError {
    ApiError::not_found("Ce lien n'existe pas ou n'est plus valide.")
}

// ------------------------------------------------------------ Fins de liens

/// Termine les liens actifs choisis par `filter` (clause SQL sur `shares`,
/// paramètres à partir de `?5`) : état terminal, motif, auteur, date,
/// contenu effacé. Renvoie le nombre de liens terminés.
fn end_where(
    c: &Connection,
    filter: &str,
    filter_args: &[&dyn ToSql],
    state: &str,
    reason: &str,
    by: Option<&str>,
) -> ApiResult<usize> {
    let sql = format!(
        "UPDATE shares SET state = ?1, ended_reason = ?2, ended_by = ?3, ended_at = ?4, data = ''
         WHERE state = 'active' AND ({filter})"
    );
    let now = now_unix();
    let mut args: Vec<&dyn ToSql> = vec![&state, &reason, &by, &now];
    args.extend_from_slice(filter_args);
    Ok(c.execute(&sql, args.as_slice())?)
}

/// Révoque des liens et journalise une ligne (si au moins un lien est
/// touché) : `share.revoked_auto` pour une révocation automatique,
/// `share.ended` pour une révocation par un administrateur.
fn revoke_where(
    c: &Connection,
    filter: &str,
    filter_args: &[&dyn ToSql],
    reason: &'static str,
    by: Option<&str>,
    target: &str,
) -> ApiResult<usize> {
    let n = end_where(c, filter, filter_args, "revoked", reason, by)?;
    if n > 0 {
        let email: String = match by {
            Some(id) => c.query_row("SELECT email FROM users WHERE id = ?1", [id], |r| r.get(0)).optional()?.unwrap_or_default(),
            None => String::new(),
        };
        let meta = ClientMeta { ip: String::new(), user_agent: String::new() };
        let (action, details) = if reason == reason::REVOKED_ADMIN {
            ("share.ended", reason.to_string())
        } else {
            ("share.revoked_auto", format!("{reason} : {n} lien(s)"))
        };
        audit(c, by, &email, action, target, &meta, &details)?;
    }
    Ok(n)
}

/// Révoque tous les liens actifs créés par `owner_id` (compte désactivé,
/// départ, révocation par un administrateur). Contrat C2.6.
pub(crate) fn revoke_for_user(c: &Connection, owner_id: &str, reason: &'static str, by: Option<&str>) -> ApiResult<usize> {
    revoke_where(c, "owner_id = ?5", &[&owner_id], reason, by, owner_id)
}

/// Révoque tous les liens actifs rattachés à un élément (corbeille,
/// suppression). Contrat C2.6.
pub(crate) fn revoke_for_item(c: &Connection, item_id: &str, reason: &'static str, by: Option<&str>) -> ApiResult<usize> {
    revoke_where(c, "item_id = ?5", &[&item_id], reason, by, item_id)
}

/// Liens d'un coffre : rattachés au coffre ou à l'un de ses éléments.
const IN_COLLECTION: &str = "collection_id = ?5 OR item_id IN (SELECT id FROM items WHERE collection_id = ?5)";

/// Révoque les liens rattachés à un coffre ou à ses éléments (rotation de
/// la clé, suppression du coffre).
pub(crate) fn revoke_for_collection(c: &Connection, collection_id: &str, reason: &'static str, by: Option<&str>) -> ApiResult<usize> {
    revoke_where(c, IN_COLLECTION, &[&collection_id], reason, by, collection_id)
}

/// Révoque les liens qu'un membre a créés sur un coffre qu'il quitte ou dont
/// il est retiré (`access_lost`).
pub(crate) fn revoke_for_member(c: &Connection, collection_id: &str, user_id: &str, by: Option<&str>) -> ApiResult<usize> {
    let filter = format!("owner_id = ?6 AND ({IN_COLLECTION})");
    revoke_where(c, &filter, &[&collection_id, &user_id], reason::ACCESS_LOST, by, collection_id)
}

/// Élément déplacé vers `collection_id` : les liens des créateurs qui n'ont
/// pas accès au nouveau coffre sont révoqués (`access_lost`), les autres
/// suivent l'élément.
pub(crate) fn item_moved(c: &Connection, item_id: &str, collection_id: &str, by: Option<&str>) -> ApiResult<usize> {
    let n = revoke_where(
        c,
        "item_id = ?5 AND owner_id NOT IN (SELECT user_id FROM memberships WHERE collection_id = ?6)",
        &[&item_id, &collection_id],
        reason::ACCESS_LOST,
        by,
        item_id,
    )?;
    c.execute(
        "UPDATE shares SET collection_id = ?1 WHERE item_id = ?2 AND state = 'active'",
        params![collection_id, item_id],
    )?;
    Ok(n)
}

// ------------------------------------------------------------ Création

/// Corps de `POST /shares` : le corps historique plus le rattachement et le
/// vérificateur de la preuve (tous facultatifs).
#[derive(Deserialize)]
pub struct NewShare {
    #[serde(flatten)]
    base: CreateShareRequest,
    #[serde(default)]
    verifier: Option<String>,
    #[serde(default)]
    item_id: Option<String>,
    #[serde(default)]
    collection_id: Option<String>,
}

/// Vérificateur bien formé : 64 caractères hexadécimaux (rendu en minuscules).
fn parse_verifier(v: &str) -> ApiResult<String> {
    if v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(v.to_ascii_lowercase())
    } else {
        Err(ApiError::bad_request("Vérificateur du lien invalide (64 caractères hexadécimaux)."))
    }
}

/// Octets d'un vérificateur enregistré (déjà validé à la création).
fn verifier_bytes(hex: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Coffre auquel le lien est rattaché, après contrôle d'éligibilité :
/// l'utilisateur doit voir l'élément ou le coffre (sinon 404), et un coffre
/// personnel bloqué par la politique ne se partage pas (403).
fn share_target(
    c: &Connection,
    user_id: &str,
    item_id: Option<&str>,
    collection_id: Option<&str>,
    personal_enabled: bool,
) -> ApiResult<Option<String>> {
    let (cid, missing, trashed) = match (item_id, collection_id) {
        (Some(item), _) => {
            let row: Option<(String, Option<i64>)> = c
                .query_row("SELECT collection_id, deleted_at FROM items WHERE id = ?1", [item], |r| Ok((r.get(0)?, r.get(1)?)))
                .optional()?;
            let (cid, deleted_at) = row.ok_or_else(|| Missing::Item.error())?;
            (cid, Missing::Item, deleted_at.is_some())
        }
        (None, Some(cid)) => (cid.to_string(), Missing::Collection, false),
        (None, None) => return Ok(None),
    };
    require_role(c, &cid, user_id, ANY, missing)?;
    let personal: bool = c.query_row("SELECT personal FROM collections WHERE id = ?1", [&cid], |r| r.get(0))?;
    if trashed || (personal && !personal_enabled) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "item_not_shareable",
            "Cet élément ne peut pas être partagé par lien.",
        ));
    }
    Ok(Some(cid))
}

pub async fn create_share(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<NewShare>,
) -> Result<Json<CreateShareResponse>, DataError> {
    let eff = state.effective().await?;
    if !eff.bool("share.enabled") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "share_disabled",
            "Votre organisation a désactivé les liens de partage.",
        )
        .into());
    }
    let NewShare { base, verifier, item_id, collection_id } = req;
    sec::cipher(&base.data, sec::SHARE_CIPHER_MAX, "partage")?;
    if base.expires_in_minutes < 5 {
        return Err(ApiError::bad_request("Durée de validité de 5 minutes au moins.").into());
    }
    if base.max_views < 1 {
        return Err(ApiError::bad_request("Au moins une consultation.").into());
    }
    let (max_minutes, max_views) = (eff.int("share.max_expiry_minutes"), eff.int("share.max_views"));
    if base.expires_in_minutes > max_minutes || base.max_views > max_views {
        return Err(DataError::with(
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "share_limit",
                format!("Votre organisation limite les liens à {max_minutes} minutes et {max_views} consultation(s)."),
            ),
            json!({ "max_minutes": max_minutes, "max_views": max_views }),
        ));
    }
    let verifier = verifier.as_deref().map(parse_verifier).transpose()?;
    for id in item_id.iter().chain(collection_id.iter()) {
        sec::uuid(id, "de l'élément ou du coffre")?;
    }
    let per_hour = u32::try_from(eff.int("share.max_per_hour")).unwrap_or(u32::MAX);
    state.limiter.hit(&format!("share-create:{}", user.id), per_hour, 3600)?;
    let personal_enabled = eff.bool("vault.personal_enabled");
    let id = random_token();
    let expires_at = now_unix() + base.expires_in_minutes * 60;
    let sid = id.clone();
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let cid = share_target(&tx, &user.id, item_id.as_deref(), collection_id.as_deref(), personal_enabled)?;
            tx.execute(
                "INSERT INTO shares (id, owner_id, data, created_at, expires_at, max_views, verifier, item_id, collection_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![sid, user.id, base.data, now_unix(), expires_at, base.max_views, verifier, item_id, cid],
            )?;
            audit_user(
                &tx,
                &user,
                "share.created",
                &sid[..8],
                &format!("{} consultation(s), {} min", base.max_views, base.expires_in_minutes),
            )?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(Json(CreateShareResponse { id, expires_at }))
}

// ------------------------------------------------------------ Liste et révocation

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    all: Option<String>,
}

/// Ligne de la liste des liens : les champs historiques plus l'état.
#[derive(Serialize)]
pub struct ShareRow {
    #[serde(flatten)]
    base: ShareSummary,
    state: String,
    ended_at: Option<i64>,
    ended_reason: Option<String>,
    item_id: Option<String>,
    has_verifier: bool,
}

/// État constaté d'un lien : un lien encore marqué actif mais échu ou épuisé
/// (la maintenance passe toutes les 10 minutes) est présenté terminé.
fn observed_state(state: String, expires_at: i64, views: i64, max_views: i64, now: i64) -> (String, Option<&'static str>) {
    if state != "active" {
        return (state, None);
    }
    if views >= max_views {
        ("exhausted".into(), Some(reason::EXHAUSTED))
    } else if expires_at <= now {
        ("expired".into(), Some(reason::EXPIRED))
    } else {
        (state, None)
    }
}

/// Liens créés par l'utilisateur. Sans `all` : liens actifs seulement (forme
/// historique compatible) ; avec `all=1` : tous, états terminaux compris.
pub async fn list_shares(
    State(state): State<AppState>,
    user: AuthUser,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Vec<ShareRow>>> {
    let all = matches!(q.all.as_deref(), Some("1" | "true"));
    Ok(Json(
        state
            .db
            .read(move |c| {
                let now = now_unix();
                let mut st = c.prepare(
                    "SELECT id, created_at, expires_at, max_views, views, state, ended_at, ended_reason, item_id,
                            verifier IS NOT NULL
                     FROM shares WHERE owner_id = ?1
                       AND (?2 OR (state = 'active' AND expires_at > ?3 AND views < max_views))
                     ORDER BY created_at DESC",
                )?;
                let rows = st
                    .query_map(params![user.id, all, now], |r| {
                        let base = ShareSummary {
                            id: r.get(0)?,
                            created_at: r.get(1)?,
                            expires_at: r.get(2)?,
                            max_views: r.get(3)?,
                            views: r.get(4)?,
                        };
                        let (state, implied) = observed_state(r.get(5)?, base.expires_at, base.views, base.max_views, now);
                        let (ended_at, ended_reason) = match implied {
                            Some(why) => ((why == reason::EXPIRED).then_some(base.expires_at), Some(why.to_string())),
                            None => (r.get(6)?, r.get(7)?),
                        };
                        Ok(ShareRow { base, state, ended_at, ended_reason, item_id: r.get(8)?, has_verifier: r.get(9)? })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?,
    ))
}

/// Révocation par le créateur : état `revoked` (motif, auteur, date),
/// contenu effacé. Idempotente : révoquer un lien déjà terminé renvoie 204.
/// Le lien d'autrui donne le même 404 qu'un lien inexistant.
pub async fn delete_share(State(state): State<AppState>, user: AuthUser, Path(id): Path<String>) -> ApiResult<StatusCode> {
    if id.len() > 64 {
        return Err(ApiError::not_found("Lien introuvable."));
    }
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let exists: Option<String> = tx
                .query_row("SELECT state FROM shares WHERE id = ?1 AND owner_id = ?2", params![id, user.id], |r| r.get(0))
                .optional()?;
            if exists.is_none() {
                return Err(ApiError::not_found("Lien introuvable."));
            }
            if end_where(&tx, "id = ?5", &[&id], "revoked", reason::REVOKED, Some(&user.id))? > 0 {
                audit_user(&tx, &user, "share.revoked", id.get(..8).unwrap_or(""), "")?;
            }
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct AdminRevokeRequest {
    owner_id: String,
}

#[derive(Serialize)]
pub struct AdminRevokeResponse {
    revoked: usize,
}

/// Révocation par un administrateur de tous les liens actifs d'un compte
/// (`revoked_admin`). Les liens d'un propriétaire : propriétaire seulement.
pub async fn admin_revoke(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Json(req): Json<AdminRevokeRequest>,
) -> ApiResult<Json<AdminRevokeResponse>> {
    sec::uuid(&req.owner_id, "du compte")?;
    let revoked = state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let role: Option<String> =
                tx.query_row("SELECT role FROM users WHERE id = ?1", [&req.owner_id], |r| r.get(0)).optional()?;
            let Some(role) = role else {
                return Err(ApiError::not_found("Utilisateur introuvable."));
            };
            if role == OWNER && admin.role != OWNER {
                return Err(ApiError::new(
                    StatusCode::FORBIDDEN,
                    "owner_only",
                    "Seul un propriétaire peut révoquer les liens d'un propriétaire.",
                ));
            }
            let n = revoke_for_user(&tx, &req.owner_id, reason::REVOKED_ADMIN, Some(&admin.id))?;
            audit_user(&tx, &admin, "admin.shares_revoked", &req.owner_id, &format!("{n} lien(s)"))?;
            tx.commit()?;
            Ok(n)
        })
        .await?;
    Ok(Json(AdminRevokeResponse { revoked }))
}

// ------------------------------------------------------------ Consultation

/// Ligne d'un lien lue SANS son contenu chiffré.
struct LinkState {
    owner_id: String,
    verifier: Option<String>,
    state: String,
    expires_at: i64,
    max_views: i64,
    views: i64,
    ended_reason: Option<String>,
    ended_at: Option<i64>,
}

fn link_state(c: &Connection, id: &str) -> ApiResult<Option<LinkState>> {
    Ok(c.query_row(
        "SELECT owner_id, verifier, state, expires_at, max_views, views, ended_reason, ended_at FROM shares WHERE id = ?1",
        [id],
        |r| {
            Ok(LinkState {
                owner_id: r.get(0)?,
                verifier: r.get(1)?,
                state: r.get(2)?,
                expires_at: r.get(3)?,
                max_views: r.get(4)?,
                views: r.get(5)?,
                ended_reason: r.get(6)?,
                ended_at: r.get(7)?,
            })
        },
    )
    .optional()?)
}

/// Passe un lien échu ou épuisé (encore marqué actif) dans son état
/// terminal. Renvoie le motif s'il est terminé, ancien ou nouveau.
fn settle(c: &Connection, id: &str, link: &mut LinkState, meta: &ClientMeta) -> ApiResult<Option<String>> {
    if link.state != "active" {
        return Ok(Some(link.ended_reason.clone().unwrap_or_else(|| link.state.clone())));
    }
    let now = now_unix();
    let (state, implied) = observed_state(link.state.clone(), link.expires_at, link.views, link.max_views, now);
    let Some(why) = implied else { return Ok(None) };
    end_where(c, "id = ?5", &[&id], &state, why, None)?;
    audit(c, Some(&link.owner_id), "", "share.ended", &id[..8.min(id.len())], meta, why)?;
    link.state = state;
    link.ended_reason = Some(why.to_string());
    link.ended_at = Some(now);
    Ok(Some(why.to_string()))
}

/// Preuve de possession conforme au vérificateur enregistré, comparée en
/// temps constant. Un lien sans vérificateur (ou inconnu) est comparé à une
/// valeur factice : le temps de réponse ne distingue pas les cas.
fn proof_matches(proof: Option<&[u8; 32]>, verifier: Option<&str>) -> bool {
    let expected = verifier.and_then(verifier_bytes);
    let known = expected.is_some() && proof.is_some();
    let digest: [u8; 32] = Sha256::digest(proof.copied().unwrap_or([0u8; 32])).into();
    let equal: bool = digest.ct_eq(&expected.unwrap_or([0xffu8; 32])).into();
    known & equal
}

/// Réponse 410 d'un lien terminé, après une preuve valide.
fn ended(reason: String, ended_at: Option<i64>) -> DataError {
    DataError::with(
        ApiError::new(StatusCode::GONE, "share_ended", "Ce lien n'est plus valide."),
        json!({ "reason": reason, "ended_at": ended_at }),
    )
}

/// Contrôles communs à l'aperçu et à l'ouverture : limite par adresse,
/// identifiant plausible, preuve décodée (une preuve mal formée vaut une
/// preuve fausse : même 404).
fn public_checks(state: &AppState, meta: &ClientMeta, id: &str, proof: &str) -> ApiResult<Option<[u8; 32]>> {
    state.limiter.hit(&format!("share-open:{}", meta.rate_key()), state.host.rate.share_open_ip, 60)?;
    if id.len() > 64 {
        return Err(unknown_link());
    }
    Ok(b64d_array::<32>(proof).ok())
}

#[derive(Deserialize)]
pub struct PeekRequest {
    proof: String,
}

#[derive(Serialize)]
pub struct PeekResponse {
    state: &'static str,
    expires_at: i64,
    views_left: i64,
}

/// Aperçu d'un lien sécurisé : état et consultations restantes, sans lire
/// le contenu ni décompter de vue.
pub async fn peek_share(
    State(state): State<AppState>,
    meta: ClientMeta,
    Path(id): Path<String>,
    Json(req): Json<PeekRequest>,
) -> Result<Json<PeekResponse>, DataError> {
    let proof = public_checks(&state, &meta, &id, &req.proof)?;
    let outcome = state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let mut link = link_state(&tx, &id)?;
            if !proof_matches(proof.as_ref(), link.as_ref().and_then(|l| l.verifier.as_deref())) {
                return Err(unknown_link());
            }
            let link = link.as_mut().ok_or_else(unknown_link)?;
            if let Some(why) = settle(&tx, &id, link, &meta)? {
                tx.commit()?;
                return Ok(Err(ended(why, link.ended_at)));
            }
            Ok(Ok(PeekResponse { state: "active", expires_at: link.expires_at, views_left: link.max_views - link.views }))
        })
        .await??;
    Ok(Json(outcome))
}

#[derive(Deserialize)]
pub struct RevealRequest {
    proof: String,
    nonce: String,
}

#[derive(Serialize)]
pub struct RevealResponse {
    data: String,
    expires_at: i64,
    views_left: i64,
    replayed: bool,
}

/// Ouverture d'un lien sécurisé. Idempotente par `nonce` : la même
/// consultation rejouée (rechargement de la page) renvoie le contenu sans
/// décompter de vue tant que le lien est actif. La dernière vue termine le
/// lien (`exhausted`) et efface son contenu dans la même transaction.
pub async fn reveal_share(
    State(state): State<AppState>,
    meta: ClientMeta,
    Path(id): Path<String>,
    Json(req): Json<RevealRequest>,
) -> Result<Json<RevealResponse>, DataError> {
    let proof = public_checks(&state, &meta, &id, &req.proof)?;
    if b64d_array::<16>(&req.nonce).is_err() {
        return Err(ApiError::bad_request("Identifiant de consultation invalide.").into());
    }
    let nonce_hash = sha256_hex(&req.nonce);
    let outcome = state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let mut link = link_state(&tx, &id)?;
            // Preuve vérifiée avant toute lecture du contenu et tout décompte.
            if !proof_matches(proof.as_ref(), link.as_ref().and_then(|l| l.verifier.as_deref())) {
                return Err(unknown_link());
            }
            let link = link.as_mut().ok_or_else(unknown_link)?;
            if let Some(why) = settle(&tx, &id, link, &meta)? {
                tx.commit()?;
                return Ok(Err(ended(why, link.ended_at)));
            }
            let now = now_unix();
            let replayed = tx
                .query_row(
                    "SELECT 1 FROM share_reveals WHERE share_id = ?1 AND nonce_hash = ?2 AND counted = 1",
                    params![id, nonce_hash],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            let data: String = tx.query_row("SELECT data FROM shares WHERE id = ?1", [&id], |r| r.get(0))?;
            let target = &id[..8.min(id.len())];
            if replayed {
                tx.execute(
                    "INSERT INTO share_reveals (share_id, at, ip, user_agent, nonce_hash, counted) VALUES (?1, ?2, ?3, ?4, NULL, 0)",
                    params![id, now, meta.ip, meta.user_agent],
                )?;
            } else {
                link.views += 1;
                tx.execute(
                    "INSERT INTO share_reveals (share_id, at, ip, user_agent, nonce_hash, counted) VALUES (?1, ?2, ?3, ?4, ?5, 1)",
                    params![id, now, meta.ip, meta.user_agent, nonce_hash],
                )?;
                tx.execute("UPDATE shares SET views = ?1 WHERE id = ?2", params![link.views, id])?;
                audit(
                    &tx,
                    Some(&link.owner_id),
                    "",
                    "share.revealed",
                    target,
                    &meta,
                    &format!("consultation {}/{}", link.views, link.max_views),
                )?;
                if link.views >= link.max_views {
                    end_where(&tx, "id = ?5", &[&id], "exhausted", reason::EXHAUSTED, None)?;
                    audit(&tx, Some(&link.owner_id), "", "share.ended", target, &meta, reason::EXHAUSTED)?;
                }
            }
            tx.commit()?;
            Ok(Ok(RevealResponse { data, expires_at: link.expires_at, views_left: link.max_views - link.views, replayed }))
        })
        .await??;
    Ok(Json(outcome))
}

/// Consultation historique (liens SANS vérificateur) : chaque appel consomme
/// une vue. Un lien avec vérificateur n'est servi que par la preuve (404 ici,
/// comme un lien inconnu).
pub async fn open_share(
    State(state): State<AppState>,
    meta: ClientMeta,
    Path(id): Path<String>,
) -> ApiResult<Json<ShareView>> {
    state.limiter.hit(&format!("share-open:{}", meta.rate_key()), state.host.rate.share_open_ip, 60)?;
    if id.len() > 64 {
        return Err(unknown_link());
    }
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let mut link = match link_state(&tx, &id)? {
                Some(l) if l.verifier.is_none() => l,
                _ => return Err(unknown_link()),
            };
            if settle(&tx, &id, &mut link, &meta)?.is_some() {
                tx.commit()?;
                return Err(unknown_link());
            }
            let data: String = tx.query_row("SELECT data FROM shares WHERE id = ?1", [&id], |r| r.get(0))?;
            let views = link.views + 1;
            let target = &id[..8.min(id.len())];
            tx.execute("UPDATE shares SET views = ?1 WHERE id = ?2", params![views, id])?;
            tx.execute(
                "INSERT INTO share_reveals (share_id, at, ip, user_agent, nonce_hash, counted) VALUES (?1, ?2, ?3, ?4, NULL, 1)",
                params![id, now_unix(), meta.ip, meta.user_agent],
            )?;
            audit(&tx, Some(&link.owner_id), "", "share.opened", target, &meta, &format!("consultation {views}/{}", link.max_views))?;
            if views >= link.max_views {
                end_where(&tx, "id = ?5", &[&id], "exhausted", reason::EXHAUSTED, None)?;
                audit(&tx, Some(&link.owner_id), "", "share.ended", target, &meta, reason::EXHAUSTED)?;
            }
            tx.commit()?;
            Ok(Json(ShareView { data, expires_at: link.expires_at, views_left: link.max_views - views }))
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verificateur_et_preuve() {
        assert_eq!(parse_verifier(&"AB".repeat(32)).unwrap(), "ab".repeat(32));
        assert!(parse_verifier("ab").is_err());
        assert!(parse_verifier(&"zz".repeat(32)).is_err());
        let proof: [u8; 32] = Sha256::digest(b"cle-du-fragment").into();
        let verifier: String = Sha256::digest(proof).iter().map(|b| format!("{b:02x}")).collect();
        assert!(proof_matches(Some(&proof), Some(&verifier)));
        assert!(!proof_matches(Some(&[0u8; 32]), Some(&verifier)));
        assert!(!proof_matches(None, Some(&verifier)));
        assert!(!proof_matches(Some(&proof), None));
        assert!(!proof_matches(None, None));
    }

    #[test]
    fn etat_constate() {
        assert_eq!(observed_state("active".into(), 100, 0, 1, 50), ("active".into(), None));
        assert_eq!(observed_state("active".into(), 100, 1, 1, 50), ("exhausted".into(), Some(reason::EXHAUSTED)));
        assert_eq!(observed_state("active".into(), 100, 0, 1, 100), ("expired".into(), Some(reason::EXPIRED)));
        assert_eq!(observed_state("revoked".into(), 100, 0, 1, 500), ("revoked".into(), None));
    }
}
