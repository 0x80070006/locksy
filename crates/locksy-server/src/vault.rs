//! Coffres, membres et éléments. Le serveur contrôle les droits mais ne
//! peut rien lire : il ne manipule que des chiffrés.
//!
//! Politique appliquée ici (registre) : `vault.users_can_create_shared`,
//! `vault.personal_enabled`, `retention.trash_days` (date de purge annoncée
//! par `/sync`). Les liens de partage rattachés à un élément ou à un coffre
//! sont révoqués automatiquement (corbeille, rotation, perte d'accès).

use crate::auth::load_profile_with;
use crate::db::collection_role;
use crate::error::{ApiError, ApiResult};
use crate::security as sec;
use crate::shares;
use crate::state::{audit_user, AppState, AuthUser};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use crate::error::Json;
use locksy_core::api::roles::{EDITOR, MANAGER, READER, USER};
use locksy_core::api::*;
use locksy_core::now_unix;
use locksy_core::settings::Effective;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashSet;

const DAY: i64 = 86_400;

/// Routes nouvelles des coffres, des liens et des pièces jointes (lot L7b).
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/public/shares/:id/peek", post(shares::peek_share))
        .route("/public/shares/:id/open", post(shares::reveal_share))
        .route("/admin/shares/revoke", post(shares::admin_revoke))
}

// ------------------------------------------------------------ Erreurs enrichies

/// Erreur dont le corps porte des champs en plus de `{error, message}`
/// (`share_limit`, `share_ended`, `rekey_required`). Même forme que les
/// autres erreurs de l'API, `Retry-After` compris.
#[derive(Debug)]
pub(crate) struct DataError {
    err: ApiError,
    extra: Map<String, Value>,
}

impl DataError {
    /// `extra` : objet JSON dont les champs s'ajoutent au corps.
    pub(crate) fn with(err: ApiError, extra: Value) -> Self {
        let extra = match extra {
            Value::Object(m) => m,
            _ => Map::new(),
        };
        Self { err, extra }
    }
}

impl From<ApiError> for DataError {
    fn from(err: ApiError) -> Self {
        Self { err, extra: Map::new() }
    }
}

impl IntoResponse for DataError {
    fn into_response(self) -> Response {
        if self.extra.is_empty() {
            return self.err.into_response();
        }
        let mut body = self.extra;
        body.insert("error".into(), Value::String(self.err.code.into()));
        body.insert("message".into(), Value::String(self.err.message));
        if let Some(secs) = self.err.retry_after {
            body.insert("retry_after".into(), secs.into());
        }
        let mut res = (self.err.status, Json(Value::Object(body))).into_response();
        if let Some(secs) = self.err.retry_after {
            res.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from(secs));
        }
        res
    }
}

/// Écriture refusée dans l'espace personnel bloqué par la politique.
pub(crate) fn personal_disabled() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "personal_vault_disabled",
        "Votre organisation a désactivé l'espace personnel : rangez cet élément dans un coffre partagé.",
    )
}

/// Refuse l'écriture dans un coffre personnel quand `vault.personal_enabled`
/// est désactivé. À appeler APRÈS le contrôle des droits (un non-membre
/// reçoit d'abord le 404 uniforme).
fn personal_guard(c: &Connection, collection_id: &str, personal_enabled: bool) -> ApiResult<()> {
    if !personal_enabled && is_personal(c, collection_id)? {
        return Err(personal_disabled());
    }
    Ok(())
}

/// Ce que l'appelant cherchait quand l'utilisateur n'est pas membre du coffre.
///
/// Un objet inexistant et un objet rangé dans un coffre dont on n'est pas
/// membre donnent strictement le même 404 : l'erreur ne révèle pas
/// l'existence d'un élément, d'une pièce jointe ou d'un coffre étranger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Missing {
    Collection,
    Item,
    Attachment,
}

impl Missing {
    pub(crate) fn error(self) -> ApiError {
        ApiError::not_found(match self {
            Missing::Collection => "Coffre introuvable.",
            Missing::Item => "Élément introuvable.",
            Missing::Attachment => "Pièce jointe introuvable.",
        })
    }
}

/// Rôle de l'utilisateur sur le coffre, s'il fait partie de `allowed`.
/// - non membre : 404 selon `missing` (même réponse qu'un objet inexistant) ;
/// - membre au rôle insuffisant : 403 (il connaît déjà l'existence du coffre).
///
/// À appeler dans la transaction qui fait l'écriture (pas de TOCTOU).
pub(crate) fn require_role(
    c: &Connection,
    collection_id: &str,
    user_id: &str,
    allowed: &[&str],
    missing: Missing,
) -> ApiResult<String> {
    match collection_role(c, collection_id, user_id)? {
        Some(r) if allowed.contains(&r.as_str()) => Ok(r),
        Some(_) => Err(ApiError::forbidden("Vos droits sur ce coffre ne permettent pas cette action.")),
        None => Err(missing.error()),
    }
}

pub(crate) const WRITE: &[&str] = &[MANAGER, EDITOR];
pub(crate) const MANAGE: &[&str] = &[MANAGER];
pub(crate) const ANY: &[&str] = &[MANAGER, EDITOR, READER];

fn is_personal(c: &Connection, collection_id: &str) -> ApiResult<bool> {
    Ok(c.query_row("SELECT personal FROM collections WHERE id = ?1", [collection_id], |r| r.get(0))?)
}

fn touch_collection(c: &Connection, collection_id: &str) -> ApiResult<()> {
    c.execute("UPDATE collections SET updated_at = ?1 WHERE id = ?2", params![now_unix(), collection_id])?;
    Ok(())
}

fn valid_role(role: &str) -> ApiResult<()> {
    if roles::COLLECTION_ROLES.contains(&role) {
        Ok(())
    } else {
        Err(ApiError::bad_request("Rôle inconnu (manager, editor ou reader)."))
    }
}

// ------------------------------------------------------------ Synchronisation

#[derive(Deserialize)]
pub struct SyncQuery {
    /// Dernier `seq` reçu par le client. Absent ou illisible : réponse complète.
    #[serde(default)]
    since: Option<String>,
}

/// Coffre vu par la synchronisation : la forme historique plus la version
/// de clé et la date de la rotation conseillée.
#[derive(Serialize)]
pub struct CollectionOut {
    #[serde(flatten)]
    base: CollectionView,
    key_version: i64,
    rotation_suggested_at: Option<i64>,
}

/// Élément vu par la synchronisation : la forme historique plus l'auteur de
/// la mise à la corbeille et la date de purge prévue.
#[derive(Serialize)]
pub struct ItemOut {
    #[serde(flatten)]
    base: ItemView,
    deleted_by: Option<String>,
    purge_at: Option<i64>,
}

/// Objets que le client doit oublier depuis `since` (réponse partielle).
/// Retirer un coffre retire aussi tous ses éléments.
#[derive(Serialize, Default, Debug)]
pub struct Removed {
    items: Vec<String>,
    collections: Vec<String>,
}

/// `GET /sync` : les champs historiques de `SyncResponse` (un client ancien
/// ignore le reste) plus la synchronisation incrémentale.
#[derive(Serialize)]
pub struct SyncOut {
    profile: Profile,
    collections: Vec<CollectionOut>,
    items: Vec<ItemOut>,
    server_time: i64,
    /// Position de la base à rappeler dans `since` au prochain appel.
    seq: i64,
    /// Réponse complète (le client remplace tout) ou partielle (il fusionne).
    full: bool,
    #[serde(flatten)]
    revisions: SyncRevisions,
    removed: Removed,
}

/// Ce que lit la synchronisation dans un seul instantané de la base.
struct SyncSnapshot {
    profile: Profile,
    collections: Vec<CollectionOut>,
    items: Vec<ItemOut>,
    seq: i64,
    full: bool,
    removed: Removed,
}

/// Coffres visibles : tous (réponse complète, `from` < 0) ou ceux qui ont
/// changé depuis `from` (nom, clé, membres ajoutés, modifiés ou retirés).
const SYNC_COLLECTIONS: &str = "
    SELECT c.id, c.enc_name, c.personal, m.role, m.sealed_key, c.updated_at,
           (SELECT COUNT(*) FROM memberships x WHERE x.collection_id = c.id),
           c.key_version, c.rotation_suggested_at
    FROM memberships m JOIN collections c ON c.id = m.collection_id
    WHERE m.user_id = ?1 AND (?3 OR c.personal = 0)
      AND (?2 < 0 OR c.change_seq > ?2
           OR EXISTS (SELECT 1 FROM memberships x WHERE x.collection_id = c.id AND x.change_seq > ?2)
           OR EXISTS (SELECT 1 FROM sync_tombstones t
                      WHERE t.collection_id = c.id AND t.seq > ?2 AND t.kind = 'membership'))
    ORDER BY c.personal DESC, c.created_at";

/// Éléments des coffres visibles : tous, ou ceux qui ont changé depuis `from`
/// (et tous ceux d'un coffre devenu visible ou dont la clé a changé).
const SYNC_ITEMS: &str = "
    SELECT i.id, i.collection_id, i.data, i.revision, i.created_at, i.updated_at, i.deleted_at, i.deleted_by,
           CASE WHEN i.deleted_at IS NULL THEN NULL ELSE COALESCE(i.purge_at, i.deleted_at + ?4) END
    FROM memberships m JOIN collections c ON c.id = m.collection_id
         JOIN items i ON i.collection_id = m.collection_id
    WHERE m.user_id = ?1 AND (?3 OR c.personal = 0)
      AND (?2 < 0 OR i.change_seq > ?2 OR m.change_seq > ?2)";

/// Coffres visibles (pour écarter des retraits ce qui est de nouveau visible).
const SYNC_VISIBLE: &str = "
    SELECT m.collection_id, c.personal FROM memberships m JOIN collections c ON c.id = m.collection_id
    WHERE m.user_id = ?1";

/// Coffres dont l'utilisateur a perdu l'accès depuis `from` (départ, retrait,
/// suppression du coffre : la cascade laisse une pierre tombale d'appartenance).
const SYNC_REMOVED_COLLECTIONS: &str = "
    SELECT DISTINCT object_id FROM sync_tombstones
    WHERE kind = 'membership' AND user_id = ?1 AND seq > ?2";

/// Éléments supprimés ou sortis d'un coffre encore visible depuis `from`.
const SYNC_REMOVED_ITEMS: &str = "
    SELECT DISTINCT t.object_id FROM memberships m
         JOIN sync_tombstones t ON t.collection_id = m.collection_id
    WHERE m.user_id = ?1 AND t.kind = 'item' AND t.seq > ?2";

fn column<T: rusqlite::types::FromSql>(c: &Connection, sql: &str, p: impl rusqlite::Params) -> ApiResult<Vec<T>> {
    let mut st = c.prepare_cached(sql)?;
    let rows = st.query_map(p, |r| r.get(0))?.collect::<Result<Vec<T>, _>>()?;
    Ok(rows)
}

/// Lecture de la synchronisation dans une transaction de lecture : la
/// position `seq` renvoyée correspond exactement aux données lues.
fn read_sync(c: &Connection, eff: &Effective, user_id: &str, since: Option<i64>) -> ApiResult<SyncSnapshot> {
    let personal_enabled = eff.bool("vault.personal_enabled");
    let trash_secs = eff.int("retention.trash_days").saturating_mul(DAY);
    let tx = c.unchecked_transaction()?;
    let (seq, purged_before): (i64, i64) =
        tx.query_row("SELECT seq, purged_before FROM sync_state WHERE id = 1", [], |r| Ok((r.get(0)?, r.get(1)?)))?;
    // Partiel seulement si toutes les pierres tombales depuis `since` existent
    // encore et que `since` vient bien de cette base.
    let delta = since.filter(|&s| s >= purged_before && s <= seq);
    let from = delta.unwrap_or(-1);
    let profile = load_profile_with(&tx, eff, user_id)?;

    let mut st = tx.prepare_cached(SYNC_COLLECTIONS)?;
    let collections = st
        .query_map(params![user_id, from, personal_enabled], |r| {
            Ok(CollectionOut {
                base: CollectionView {
                    id: r.get(0)?,
                    enc_name: r.get(1)?,
                    personal: r.get(2)?,
                    role: r.get(3)?,
                    sealed_key: r.get(4)?,
                    updated_at: r.get(5)?,
                    member_count: r.get(6)?,
                },
                key_version: r.get(7)?,
                rotation_suggested_at: r.get(8)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(st);

    let mut st = tx.prepare_cached(SYNC_ITEMS)?;
    let items = st
        .query_map(params![user_id, from, personal_enabled, trash_secs], |r| {
            Ok(ItemOut {
                base: ItemView {
                    id: r.get(0)?,
                    collection_id: r.get(1)?,
                    data: r.get(2)?,
                    revision: r.get(3)?,
                    created_at: r.get(4)?,
                    updated_at: r.get(5)?,
                    deleted_at: r.get(6)?,
                },
                deleted_by: r.get(7)?,
                purge_at: r.get(8)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(st);

    let mut removed = Removed::default();
    if delta.is_some() {
        let mut visible = HashSet::new();
        let mut hidden = Vec::new();
        let mut st = tx.prepare_cached(SYNC_VISIBLE)?;
        for row in st.query_map([user_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?)))? {
            let (id, personal) = row?;
            if personal && !personal_enabled {
                hidden.push(id);
            } else {
                visible.insert(id);
            }
        }
        drop(st);
        let mut gone: Vec<String> = column(&tx, SYNC_REMOVED_COLLECTIONS, params![user_id, from])?;
        gone.extend(hidden);
        gone.retain(|id| !visible.contains(id));
        let sent: HashSet<&str> = items.iter().map(|i| i.base.id.as_str()).collect();
        let mut gone_items: Vec<String> = column(&tx, SYNC_REMOVED_ITEMS, params![user_id, from])?;
        gone_items.retain(|id| !sent.contains(id.as_str()));
        gone.sort();
        gone.dedup();
        gone_items.sort();
        removed = Removed { items: gone_items, collections: gone };
    }
    Ok(SyncSnapshot { profile, collections, items, seq, full: delta.is_none(), removed })
}

/// `GET /sync?since=<seq>` : coffres et éléments visibles, complets ou
/// depuis la position `since` (avec les objets à oublier), plus les
/// révisions de la politique et des préférences.
pub async fn sync(State(state): State<AppState>, user: AuthUser, Query(q): Query<SyncQuery>) -> ApiResult<Json<SyncOut>> {
    let eff = state.effective().await?;
    let since = q.since.as_deref().and_then(|s| s.trim().parse::<i64>().ok());
    let revisions = crate::settings_api::revisions_for(&state, &user.id).await?;
    let uid = user.id.clone();
    let snap = state.db.read(move |c| read_sync(c, &eff, &uid, since)).await?;
    Ok(Json(SyncOut {
        profile: snap.profile,
        collections: snap.collections,
        items: snap.items,
        server_time: now_unix(),
        seq: snap.seq,
        full: snap.full,
        revisions,
        removed: snap.removed,
    }))
}

pub async fn directory(State(state): State<AppState>, _user: AuthUser) -> ApiResult<Json<Vec<DirectoryUser>>> {
    Ok(Json(
        state
            .db
            .read(|c| {
                let mut st = c.prepare("SELECT id, email, name, public_key FROM users WHERE disabled = 0 ORDER BY name COLLATE NOCASE")?;
                let rows = st
                    .query_map([], |r| Ok(DirectoryUser { id: r.get(0)?, email: r.get(1)?, name: r.get(2)?, public_key: r.get(3)? }))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?,
    ))
}

// ------------------------------------------------------------ Coffres

pub async fn create_collection(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<NewCollection>,
) -> ApiResult<StatusCode> {
    sec::uuid(&req.id, "coffre")?;
    sec::cipher(&req.enc_name, sec::NAME_CIPHER_MAX, "nom du coffre")?;
    sec::sealed(&req.sealed_key)?;
    if user.role == USER && !state.effective().await?.bool("vault.users_can_create_shared") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "shared_vault_creation_disabled",
            "Dans votre organisation, seuls les administrateurs créent les coffres partagés. Demandez-leur d'en créer un.",
        ));
    }
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let now = now_unix();
            let n = tx.execute(
                "INSERT OR IGNORE INTO collections (id, enc_name, personal, created_by, created_at, updated_at)
                 VALUES (?1, ?2, 0, ?3, ?4, ?4)",
                params![req.id, req.enc_name, user.id, now],
            )?;
            if n == 0 {
                return Err(ApiError::conflict("Ce coffre existe déjà."));
            }
            tx.execute(
                "INSERT INTO memberships (collection_id, user_id, role, sealed_key, created_at) VALUES (?1, ?2, 'manager', ?3, ?4)",
                params![req.id, user.id, req.sealed_key, now],
            )?;
            audit_user(&tx, &user, "collection.created", &req.id, "")?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::CREATED)
}

pub async fn rename_collection(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateCollectionRequest>,
) -> ApiResult<StatusCode> {
    sec::uuid_path(&id, "Coffre")?;
    sec::cipher(&req.enc_name, sec::NAME_CIPHER_MAX, "nom du coffre")?;
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            require_role(&tx, &id, &user.id, MANAGE, Missing::Collection)?;
            tx.execute(
                "UPDATE collections SET enc_name = ?1, updated_at = ?2 WHERE id = ?3",
                params![req.enc_name, now_unix(), id],
            )?;
            audit_user(&tx, &user, "collection.renamed", &id, "")?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_collection(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    sec::uuid_path(&id, "Coffre")?;
    state
        .db
        .call(move |c| {
            // Contrôles et suppression dans la même transaction.
            let tx = c.transaction()?;
            require_role(&tx, &id, &user.id, MANAGE, Missing::Collection)?;
            if is_personal(&tx, &id)? {
                return Err(ApiError::bad_request("Le coffre personnel ne peut pas être supprimé."));
            }
            let items: i64 = tx.query_row("SELECT COUNT(*) FROM items WHERE collection_id = ?1", [&id], |r| r.get(0))?;
            // Avant la suppression : les liens se retrouvent par les éléments.
            shares::revoke_for_collection(&tx, &id, shares::reason::ITEM_DELETED, Some(&user.id))?;
            tx.execute("DELETE FROM collections WHERE id = ?1", [&id])?;
            audit_user(&tx, &user, "collection.deleted", &id, &format!("{items} élément(s) supprimé(s)"))?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ------------------------------------------------------------ Membres

pub async fn list_members(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Vec<MemberView>>> {
    sec::uuid_path(&id, "Coffre")?;
    Ok(Json(
        state
            .db
            .read(move |c| {
                require_role(c, &id, &user.id, ANY, Missing::Collection)?;
                let mut st = c.prepare(
                    "SELECT u.id, u.email, u.name, m.role, u.public_key FROM memberships m
                     JOIN users u ON u.id = m.user_id WHERE m.collection_id = ?1 ORDER BY u.name COLLATE NOCASE",
                )?;
                let rows = st
                    .query_map([&id], |r| {
                        Ok(MemberView { user_id: r.get(0)?, email: r.get(1)?, name: r.get(2)?, role: r.get(3)?, public_key: r.get(4)? })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?,
    ))
}

pub async fn add_member(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<AddMemberRequest>,
) -> ApiResult<StatusCode> {
    sec::uuid_path(&id, "Coffre")?;
    valid_role(&req.role)?;
    sec::sealed(&req.sealed_key)?;
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            require_role(&tx, &id, &user.id, MANAGE, Missing::Collection)?;
            if is_personal(&tx, &id)? {
                return Err(ApiError::bad_request("Le coffre personnel ne se partage pas. Créez un coffre partagé."));
            }
            let target: Option<(String, bool)> = tx
                .query_row("SELECT email, disabled FROM users WHERE id = ?1", [&req.user_id], |r| Ok((r.get(0)?, r.get(1)?)))
                .optional()?;
            let Some((email, disabled)) = target else {
                return Err(ApiError::not_found("Utilisateur introuvable."));
            };
            if disabled {
                return Err(ApiError::bad_request("Ce compte est désactivé."));
            }
            let n = tx.execute(
                "INSERT OR IGNORE INTO memberships (collection_id, user_id, role, sealed_key, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![id, req.user_id, req.role, req.sealed_key, now_unix()],
            )?;
            if n == 0 {
                return Err(ApiError::conflict("Cette personne a déjà accès au coffre."));
            }
            touch_collection(&tx, &id)?;
            audit_user(&tx, &user, "collection.member_added", &id, &format!("{email} ({})", req.role))?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::CREATED)
}

fn manager_count(c: &Connection, collection_id: &str) -> ApiResult<i64> {
    Ok(c.query_row(
        "SELECT COUNT(*) FROM memberships WHERE collection_id = ?1 AND role = 'manager'",
        [collection_id],
        |r| r.get(0),
    )?)
}

pub async fn update_member(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, member_id)): Path<(String, String)>,
    Json(req): Json<UpdateMemberRequest>,
) -> ApiResult<StatusCode> {
    sec::uuid_path(&id, "Coffre")?;
    sec::uuid_path(&member_id, "Membre")?;
    valid_role(&req.role)?;
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            require_role(&tx, &id, &user.id, MANAGE, Missing::Collection)?;
            let current = collection_role(&tx, &id, &member_id)?.ok_or_else(|| ApiError::not_found("Membre introuvable."))?;
            if current == MANAGER && req.role != MANAGER && manager_count(&tx, &id)? <= 1 {
                return Err(ApiError::bad_request("Un coffre doit garder au moins un gestionnaire."));
            }
            tx.execute(
                "UPDATE memberships SET role = ?1 WHERE collection_id = ?2 AND user_id = ?3",
                params![req.role, id, member_id],
            )?;
            touch_collection(&tx, &id)?;
            audit_user(&tx, &user, "collection.member_role", &id, &format!("{member_id} : {current} → {}", req.role))?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Quitter un coffre partagé. Retirer quelqu'un d'autre passe par la
/// rotation de clé, pour que la personne retirée ne puisse plus rien lire.
pub async fn leave_collection(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, member_id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    sec::uuid_path(&id, "Coffre")?;
    sec::uuid_path(&member_id, "Membre")?;
    if member_id != user.id {
        return Err(ApiError::bad_request("Pour retirer un membre, utilisez « Retirer et renouveler la clé »."));
    }
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let role = require_role(&tx, &id, &user.id, ANY, Missing::Collection)?;
            if is_personal(&tx, &id)? {
                return Err(ApiError::bad_request("Vous ne pouvez pas quitter votre coffre personnel."));
            }
            if role == MANAGER && manager_count(&tx, &id)? <= 1 {
                return Err(ApiError::bad_request("Nommez un autre gestionnaire avant de quitter ce coffre."));
            }
            // Ses liens vers les éléments du coffre ne survivent pas à son départ.
            shares::revoke_for_member(&tx, &id, &user.id, Some(&user.id))?;
            tx.execute("DELETE FROM memberships WHERE collection_id = ?1 AND user_id = ?2", params![id, user.id])?;
            touch_collection(&tx, &id)?;
            audit_user(&tx, &user, "collection.left", &id, "")?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn rotate_collection(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<RotateCollectionRequest>,
) -> ApiResult<StatusCode> {
    sec::uuid_path(&id, "Coffre")?;
    sec::cipher(&req.enc_name, sec::NAME_CIPHER_MAX, "nom du coffre")?;
    for m in &req.members {
        sec::sealed(&m.sealed_key)?;
    }
    for i in &req.items {
        sec::cipher(&i.data, sec::ITEM_CIPHER_MAX, "élément")?;
    }
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            require_role(&tx, &id, &user.id, MANAGE, Missing::Collection)?;
            if req.remove_user_ids.contains(&user.id) {
                return Err(ApiError::bad_request("Vous ne pouvez pas vous retirer vous-même ainsi."));
            }
            for uid in &req.remove_user_ids {
                // Liens des personnes retirées : motif « perte d'accès ».
                shares::revoke_for_member(&tx, &id, uid, Some(&user.id))?;
                tx.execute("DELETE FROM memberships WHERE collection_id = ?1 AND user_id = ?2", params![id, uid])?;
            }
            // L'ensemble des membres restants et des éléments doit être fourni
            // en entier : aucune donnée ne peut rester sous l'ancienne clé.
            let current: HashSet<String> = tx
                .prepare("SELECT user_id FROM memberships WHERE collection_id = ?1")?
                .query_map([&id], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            let provided: HashSet<String> = req.members.iter().map(|m| m.user_id.clone()).collect();
            if current != provided || provided.len() != req.members.len() {
                return Err(ApiError::conflict("La liste des membres a changé. Rechargez puis recommencez."));
            }
            let items: HashSet<String> = tx
                .prepare("SELECT id FROM items WHERE collection_id = ?1")?
                .query_map([&id], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            let provided_items: HashSet<String> = req.items.iter().map(|i| i.id.clone()).collect();
            if items != provided_items || provided_items.len() != req.items.len() {
                return Err(ApiError::conflict("Le contenu du coffre a changé. Rechargez puis recommencez."));
            }
            let now = now_unix();
            for m in &req.members {
                tx.execute(
                    "UPDATE memberships SET sealed_key = ?1 WHERE collection_id = ?2 AND user_id = ?3",
                    params![m.sealed_key, id, m.user_id],
                )?;
            }
            for i in &req.items {
                tx.execute(
                    "UPDATE items SET data = ?1, revision = revision + 1, updated_at = ?2, updated_by = ?3 WHERE id = ?4",
                    params![i.data, now, user.id, i.id],
                )?;
            }
            // La rotation conseillée (départ d'un membre) est faite : l'alerte
            // disparaît, et les liens restants du coffre sont révoqués.
            tx.execute(
                "UPDATE collections SET enc_name = ?1, key_version = key_version + 1, updated_at = ?2,
                        rotation_suggested_at = NULL
                 WHERE id = ?3",
                params![req.enc_name, now, id],
            )?;
            shares::revoke_for_collection(&tx, &id, shares::reason::ROTATED, Some(&user.id))?;
            audit_user(
                &tx,
                &user,
                "collection.key_rotated",
                &id,
                &format!("{} membre(s) retiré(s), {} élément(s) rechiffré(s)", req.remove_user_ids.len(), req.items.len()),
            )?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ------------------------------------------------------------ Éléments

/// Corps de `POST /items` : la forme historique plus, facultative, la version
/// de la clé du coffre sous laquelle le client a chiffré.
#[derive(Deserialize)]
pub struct NewItem {
    #[serde(flatten)]
    base: CreateItemRequest,
    #[serde(default)]
    key_version: Option<i64>,
}

/// Corps de `POST /items/batch` (import).
#[derive(Deserialize)]
pub struct NewItems {
    items: Vec<NewItem>,
}

/// Corps de `PUT /items/:id` : la forme historique plus la version de clé.
#[derive(Deserialize)]
pub struct ItemUpdate {
    #[serde(flatten)]
    base: UpdateItemRequest,
    #[serde(default)]
    key_version: Option<i64>,
}

/// Version de clé annoncée par le client. Différente de celle du coffre (une
/// rotation a eu lieu depuis son chargement) : refus `rekey_required` avec la
/// version attendue, tracé dans le journal (`item.rekey_refused`). Le refus
/// est renvoyé dans `Ok(Err(…))` : l'appelant valide la transaction pour
/// garder la trace, sans rien écrire d'autre.
fn check_key(
    c: &Connection,
    user: &AuthUser,
    item_id: &str,
    collection_id: &str,
    sent: Option<i64>,
) -> ApiResult<Result<(), DataError>> {
    let Some(sent) = sent else { return Ok(Ok(())) };
    let current: i64 = c.query_row("SELECT key_version FROM collections WHERE id = ?1", [collection_id], |r| r.get(0))?;
    if sent == current {
        return Ok(Ok(()));
    }
    audit_user(c, user, "item.rekey_refused", item_id, &format!("coffre {collection_id} : version {sent}, attendue {current}"))?;
    Ok(Err(DataError::with(
        ApiError::new(
            StatusCode::CONFLICT,
            "rekey_required",
            "La clé de ce coffre vient d'être renouvelée. Rechargez le coffre puis enregistrez de nouveau.",
        ),
        serde_json::json!({ "collection_id": collection_id, "key_version": current }),
    )))
}

/// Contrôles d'un nouvel élément : droits sur le coffre (404 uniforme pour
/// un non-membre), espace personnel, version de clé.
fn check_new_item(c: &Connection, user: &AuthUser, i: &NewItem, personal_enabled: bool) -> ApiResult<Result<(), DataError>> {
    require_role(c, &i.base.collection_id, &user.id, WRITE, Missing::Collection)?;
    personal_guard(c, &i.base.collection_id, personal_enabled)?;
    check_key(c, user, &i.base.id, &i.base.collection_id, i.key_version)
}

fn insert_item(c: &Connection, user: &AuthUser, item: &CreateItemRequest, now: i64) -> ApiResult<()> {
    let n = c.execute(
        "INSERT OR IGNORE INTO items (id, collection_id, data, revision, created_at, updated_at, updated_by)
         VALUES (?1, ?2, ?3, 1, ?4, ?4, ?5)",
        params![item.id, item.collection_id, item.data, now, user.id],
    )?;
    if n == 0 {
        return Err(ApiError::conflict("Cet élément existe déjà."));
    }
    Ok(())
}

fn validate_new_item(i: &CreateItemRequest) -> ApiResult<()> {
    sec::uuid(&i.id, "élément")?;
    sec::uuid(&i.collection_id, "coffre")?;
    sec::cipher(&i.data, sec::ITEM_CIPHER_MAX, "élément")
}

pub async fn create_item(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<NewItem>,
) -> Result<StatusCode, DataError> {
    validate_new_item(&req.base)?;
    let personal_enabled = state.effective().await?.bool("vault.personal_enabled");
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            if let Err(e) = check_new_item(&tx, &user, &req, personal_enabled)? {
                tx.commit()?;
                return Ok(Err(e));
            }
            let item = &req.base;
            insert_item(&tx, &user, item, now_unix())?;
            touch_collection(&tx, &item.collection_id)?;
            audit_user(&tx, &user, "item.created", &item.id, &format!("coffre {}", item.collection_id))?;
            tx.commit()?;
            Ok(Ok(()))
        })
        .await??;
    Ok(StatusCode::CREATED)
}

pub async fn create_items_batch(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<NewItems>,
) -> Result<StatusCode, DataError> {
    if req.items.is_empty() || req.items.len() > 2000 {
        return Err(ApiError::bad_request("Entre 1 et 2 000 éléments par import.").into());
    }
    for i in &req.items {
        validate_new_item(&i.base)?;
    }
    let personal_enabled = state.effective().await?.bool("vault.personal_enabled");
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            // Tous les contrôles avant la première insertion : un refus de
            // version de clé ne laisse que sa trace. Droits et espace
            // personnel : une fois par coffre.
            let mut collections = HashSet::new();
            for i in &req.items {
                if collections.insert(i.base.collection_id.clone()) || i.key_version.is_some() {
                    if let Err(e) = check_new_item(&tx, &user, i, personal_enabled)? {
                        tx.commit()?;
                        return Ok(Err(e));
                    }
                }
            }
            let now = now_unix();
            for i in &req.items {
                insert_item(&tx, &user, &i.base, now)?;
            }
            for cid in &collections {
                touch_collection(&tx, cid)?;
            }
            audit_user(&tx, &user, "item.imported", "", &format!("{} élément(s)", req.items.len()))?;
            tx.commit()?;
            Ok(Ok(()))
        })
        .await??;
    Ok(StatusCode::CREATED)
}

/// Emplacement d'un élément : coffre, révision et date de mise à la corbeille.
struct ItemLocation {
    collection_id: String,
    revision: i64,
    deleted_at: Option<i64>,
}

/// Élément accessible en écriture par l'utilisateur. Inexistant ou rangé dans
/// un coffre dont il n'est pas membre : même 404 « Élément introuvable. ».
fn writable_item(c: &Connection, id: &str, user_id: &str) -> ApiResult<ItemLocation> {
    let loc = c
        .query_row("SELECT collection_id, revision, deleted_at FROM items WHERE id = ?1", [id], |r| {
            Ok(ItemLocation { collection_id: r.get(0)?, revision: r.get(1)?, deleted_at: r.get(2)? })
        })
        .optional()?
        .ok_or_else(|| Missing::Item.error())?;
    require_role(c, &loc.collection_id, user_id, WRITE, Missing::Item)?;
    Ok(loc)
}

pub async fn update_item(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<ItemUpdate>,
) -> Result<Json<i64>, DataError> {
    sec::uuid_path(&id, "Élément")?;
    let ItemUpdate { base: req, key_version } = req;
    sec::uuid(&req.collection_id, "coffre")?;
    sec::cipher(&req.data, sec::ITEM_CIPHER_MAX, "élément")?;
    let personal_enabled = state.effective().await?.bool("vault.personal_enabled");
    let revision = state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let loc = writable_item(&tx, &id, &user.id)?;
            let current_collection = loc.collection_id;
            let moved = req.collection_id != current_collection;
            if moved {
                require_role(&tx, &req.collection_id, &user.id, WRITE, Missing::Collection)?;
            }
            // Sortir un élément de l'espace personnel bloqué reste permis ;
            // y écrire ne l'est pas.
            personal_guard(&tx, &req.collection_id, personal_enabled)?;
            if let Err(e) = check_key(&tx, &user, &id, &req.collection_id, key_version)? {
                tx.commit()?;
                return Ok(Err(e));
            }
            if req.revision != loc.revision {
                return Err(ApiError::conflict(
                    "Cet élément a été modifié entre-temps par quelqu'un d'autre. Rechargez pour voir la dernière version.",
                ));
            }
            let now = now_unix();
            tx.execute(
                "UPDATE items SET collection_id = ?1, data = ?2, revision = revision + 1, updated_at = ?3, updated_by = ?4 WHERE id = ?5",
                params![req.collection_id, req.data, now, user.id, id],
            )?;
            touch_collection(&tx, &current_collection)?;
            let details = if moved {
                touch_collection(&tx, &req.collection_id)?;
                // Les liens des créateurs sans accès au nouveau coffre tombent.
                shares::item_moved(&tx, &id, &req.collection_id, Some(&user.id))?;
                format!("déplacé de {current_collection} vers {}", req.collection_id)
            } else {
                String::new()
            };
            audit_user(&tx, &user, "item.updated", &id, &details)?;
            tx.commit()?;
            Ok(Ok(loc.revision + 1))
        })
        .await??;
    Ok(Json(revision))
}

pub async fn trash_item(State(state): State<AppState>, user: AuthUser, Path(id): Path<String>) -> ApiResult<StatusCode> {
    set_deleted(state, user, id, true).await
}

pub async fn restore_item(State(state): State<AppState>, user: AuthUser, Path(id): Path<String>) -> ApiResult<StatusCode> {
    set_deleted(state, user, id, false).await
}

/// Mise à la corbeille (auteur noté, liens de l'élément révoqués) ou
/// restauration. La date de purge suit `retention.trash_days` tant que
/// `purge_at` n'est pas fixé.
async fn set_deleted(state: AppState, user: AuthUser, id: String, deleted: bool) -> ApiResult<StatusCode> {
    sec::uuid_path(&id, "Élément")?;
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let loc = writable_item(&tx, &id, &user.id)?;
            let now = now_unix();
            tx.execute(
                "UPDATE items SET deleted_at = ?1, deleted_by = ?2, purge_at = NULL, updated_at = ?3, revision = revision + 1
                 WHERE id = ?4",
                params![deleted.then_some(now), deleted.then_some(user.id.as_str()), now, id],
            )?;
            if deleted {
                shares::revoke_for_item(&tx, &id, shares::reason::ITEM_DELETED, Some(&user.id))?;
            }
            touch_collection(&tx, &loc.collection_id)?;
            audit_user(&tx, &user, if deleted { "item.trashed" } else { "item.restored" }, &id, "")?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn purge_item(State(state): State<AppState>, user: AuthUser, Path(id): Path<String>) -> ApiResult<StatusCode> {
    sec::uuid_path(&id, "Élément")?;
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            // Droits vérifiés avant l'état de la corbeille : un non-membre
            // n'apprend rien de l'élément.
            let loc = writable_item(&tx, &id, &user.id)?;
            if loc.deleted_at.is_none() {
                return Err(ApiError::bad_request("Placez d'abord l'élément dans la corbeille."));
            }
            shares::revoke_for_item(&tx, &id, shares::reason::ITEM_DELETED, Some(&user.id))?;
            tx.execute("DELETE FROM items WHERE id = ?1 AND deleted_at IS NOT NULL", [&id])?;
            touch_collection(&tx, &loc.collection_id)?;
            audit_user(&tx, &user, "item.purged", &id, "")?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ------------------------------------------------------------ Tests

/// Outils d'insertion directe pour les tests de handlers (coffres, pièces
/// jointes, administration).
#[cfg(test)]
pub(crate) mod testing {
    use crate::state::{AuthUser, ClientMeta};
    use locksy_core::crypto::{encrypt_str, new_uuid, SecretKey};
    use rusqlite::{params, Connection};

    const KDF: &str = r#"{"alg":"argon2id","m_kib":65536,"t":3,"p":1,"salt":"c2Vs"}"#;

    /// Crée un compte (avec une session) et renvoie l'utilisateur connecté.
    pub fn user(c: &Connection, name: &str, role: &str) -> AuthUser {
        let id = new_uuid();
        let email = format!("{name}@exemple.fr");
        c.execute(
            "INSERT INTO users (id, email, name, role, kdf, auth_hash, wrapped_user_key, recovery_wrapped_user_key,
                                recovery_auth_hash, public_key, wrapped_private_key, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, '', '', '', '', '', '', 0, 0)",
            params![id, email, name, role, KDF],
        )
        .unwrap();
        c.execute(
            "INSERT INTO sessions (id, token_hash, user_id, created_at, last_seen_at, expires_at, ip, device)
             VALUES (?1, ?2, ?3, 0, 0, 9999999999, '', '')",
            params![format!("s-{id}"), format!("h-{id}"), id],
        )
        .unwrap();
        AuthUser {
            session_id: format!("s-{id}"),
            id,
            email,
            role: role.into(),
            meta: ClientMeta { ip: "203.0.113.7".into(), user_agent: "test".into() },
        }
    }

    /// Coffre (partagé, sauf `personal`) dont `owner` est gestionnaire.
    pub fn collection(c: &Connection, owner: &AuthUser, personal: bool) -> String {
        let id = new_uuid();
        c.execute(
            "INSERT INTO collections (id, enc_name, personal, created_by, created_at, updated_at) VALUES (?1, 'nom', ?2, ?3, 0, 0)",
            params![id, personal, owner.id],
        )
        .unwrap();
        member(c, &id, owner, "manager");
        id
    }

    pub fn member(c: &Connection, collection_id: &str, user: &AuthUser, role: &str) {
        c.execute(
            "INSERT INTO memberships (collection_id, user_id, role, sealed_key, created_at) VALUES (?1, ?2, ?3, 'scellée', 0)",
            params![collection_id, user.id, role],
        )
        .unwrap();
    }

    pub fn item(c: &Connection, collection_id: &str) -> String {
        let id = new_uuid();
        c.execute(
            "INSERT INTO items (id, collection_id, data, revision, created_at, updated_at) VALUES (?1, ?2, ?3, 1, 0, 0)",
            params![id, collection_id, cipher("élément")],
        )
        .unwrap();
        id
    }

    /// Chiffré bien formé (accepté par `security::cipher`).
    pub fn cipher(text: &str) -> String {
        encrypt_str(&SecretKey::generate(), text, "aad")
    }

    pub fn count(c: &Connection, sql: &str, arg: &str) -> i64 {
        c.query_row(sql, [arg], |r| r.get(0)).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use crate::state::test_state;
    use locksy_core::api::roles::USER;
    use locksy_core::crypto::new_uuid;

    /// Un propriétaire, un étranger et un lecteur autour d'un coffre partagé
    /// qui contient un élément.
    struct Fixture {
        state: AppState,
        owner: AuthUser,
        stranger: AuthUser,
        reader: AuthUser,
        collection: String,
        item: String,
    }

    async fn fixture() -> Fixture {
        let state = test_state().await;
        let (owner, stranger, reader, collection, item) = state
            .db
            .call(|c| {
                let owner = user(c, "alice", USER);
                let stranger = user(c, "bob", USER);
                let reader = user(c, "carole", USER);
                let col = collection(c, &owner, false);
                member(c, &col, &reader, READER);
                let it = item(c, &col);
                Ok((owner, stranger, reader, col, it))
            })
            .await
            .unwrap();
        Fixture { state, owner, stranger, reader, collection, item }
    }

    fn update_req(collection_id: &str, revision: i64) -> Json<ItemUpdate> {
        Json(ItemUpdate { base: UpdateItemRequest { collection_id: collection_id.into(), data: cipher("nouveau"), revision }, key_version: None })
    }

    fn same(a: &ApiError, b: &ApiError) {
        assert_eq!((a.status, a.code, a.message.as_str()), (b.status, b.code, b.message.as_str()));
    }

    async fn sql_count(st: &AppState, sql: &'static str, arg: &str) -> i64 {
        let arg = arg.to_string();
        st.db.call(move |c| Ok(count(c, sql, &arg))).await.unwrap()
    }

    async fn audits(st: &AppState, action: &str) -> i64 {
        sql_count(st, "SELECT COUNT(*) FROM audit WHERE action = ?1", action).await
    }

    #[tokio::test]
    async fn inexistant_et_coffre_etranger_donnent_le_meme_404() {
        let f = fixture().await;
        let ghost = new_uuid();
        let st = || State(f.state.clone());

        let foreign = update_item(st(), f.stranger.clone(), Path(f.item.clone()), update_req(&f.collection, 1)).await.unwrap_err().err;
        let missing = update_item(st(), f.stranger.clone(), Path(ghost.clone()), update_req(&f.collection, 1)).await.unwrap_err().err;
        same(&foreign, &missing);
        assert_eq!((foreign.status, foreign.code), (StatusCode::NOT_FOUND, "not_found"));
        assert_eq!(foreign.message, "Élément introuvable.");

        let foreign = trash_item(st(), f.stranger.clone(), Path(f.item.clone())).await.unwrap_err();
        let missing = trash_item(st(), f.stranger.clone(), Path(ghost.clone())).await.unwrap_err();
        same(&foreign, &missing);
        assert_eq!(foreign.message, "Élément introuvable.");

        let foreign = purge_item(st(), f.stranger.clone(), Path(f.item.clone())).await.unwrap_err();
        let missing = purge_item(st(), f.stranger.clone(), Path(ghost.clone())).await.unwrap_err();
        same(&foreign, &missing);
        assert_eq!(foreign.message, "Élément introuvable.");

        // L'élément d'autrui n'a pas bougé, aucun audit n'est écrit.
        assert_eq!(sql_count(&f.state, "SELECT revision FROM items WHERE id = ?1", &f.item).await, 1);
        assert_eq!(sql_count(&f.state, "SELECT COUNT(*) FROM audit WHERE ?1 <> ''", "x").await, 0);
    }

    #[tokio::test]
    async fn lecteur_recoit_403() {
        let f = fixture().await;
        let st = || State(f.state.clone());
        for e in [
            update_item(st(), f.reader.clone(), Path(f.item.clone()), update_req(&f.collection, 1)).await.unwrap_err().err,
            trash_item(st(), f.reader.clone(), Path(f.item.clone())).await.unwrap_err(),
            purge_item(st(), f.reader.clone(), Path(f.item.clone())).await.unwrap_err(),
        ] {
            assert_eq!((e.status, e.code), (StatusCode::FORBIDDEN, "forbidden"));
            assert_eq!(e.message, "Vos droits sur ce coffre ne permettent pas cette action.");
        }
    }

    #[tokio::test]
    async fn deplacement_vers_un_coffre_inaccessible() {
        let f = fixture().await;
        let s = f.stranger.clone();
        let other = f.state.db.call(move |c| Ok(collection(c, &s, false))).await.unwrap();
        let e = update_item(State(f.state.clone()), f.owner.clone(), Path(f.item.clone()), update_req(&other, 1)).await.unwrap_err().err;
        assert_eq!((e.status, e.message.as_str()), (StatusCode::NOT_FOUND, "Coffre introuvable."));
        // Modification sur place toujours possible.
        let rev = update_item(State(f.state.clone()), f.owner.clone(), Path(f.item.clone()), update_req(&f.collection, 1)).await.unwrap();
        assert_eq!(rev.0, 2);
    }

    #[tokio::test]
    async fn purge_hors_corbeille_refusee_sans_audit() {
        let f = fixture().await;
        let st = || State(f.state.clone());
        let e = purge_item(st(), f.owner.clone(), Path(f.item.clone())).await.unwrap_err();
        assert_eq!((e.status, e.code), (StatusCode::BAD_REQUEST, "bad_request"));
        assert_eq!(audits(&f.state, "item.purged").await, 0);
        assert_eq!(sql_count(&f.state, "SELECT COUNT(*) FROM items WHERE id = ?1", &f.item).await, 1);

        trash_item(st(), f.owner.clone(), Path(f.item.clone())).await.unwrap();
        purge_item(st(), f.owner.clone(), Path(f.item.clone())).await.unwrap();
        assert_eq!(audits(&f.state, "item.purged").await, 1);
        assert_eq!(sql_count(&f.state, "SELECT COUNT(*) FROM items WHERE id = ?1", &f.item).await, 0);
    }

    #[tokio::test]
    async fn coffre_personnel_jamais_supprime() {
        let f = fixture().await;
        let o = f.owner.clone();
        let personal = f
            .state
            .db
            .call(move |c| {
                let p = collection(c, &o, true);
                item(c, &p);
                Ok(p)
            })
            .await
            .unwrap();
        let e = delete_collection(State(f.state.clone()), f.owner.clone(), Path(personal.clone())).await.unwrap_err();
        assert_eq!(e.status, StatusCode::BAD_REQUEST);
        assert_eq!(sql_count(&f.state, "SELECT COUNT(*) FROM collections WHERE id = ?1", &personal).await, 1);
        assert_eq!(sql_count(&f.state, "SELECT COUNT(*) FROM items WHERE collection_id = ?1", &personal).await, 1);
        assert_eq!(audits(&f.state, "collection.deleted").await, 0);
        // Un étranger ne distingue pas un coffre inexistant d'un coffre d'autrui.
        let foreign = delete_collection(State(f.state.clone()), f.stranger.clone(), Path(f.collection.clone())).await.unwrap_err();
        let missing = delete_collection(State(f.state.clone()), f.stranger.clone(), Path(new_uuid())).await.unwrap_err();
        same(&foreign, &missing);
        assert_eq!(foreign.message, "Coffre introuvable.");
    }

    #[tokio::test]
    async fn sync_voit_l_element_cree_juste_avant() {
        let f = fixture().await;
        let id = new_uuid();
        let req = CreateItemRequest { id: id.clone(), collection_id: f.collection.clone(), data: cipher("x") };
        assert_eq!(create_item(State(f.state.clone()), f.owner.clone(), Json(NewItem { base: req, key_version: None })).await.unwrap(), StatusCode::CREATED);
        let r = sync(State(f.state.clone()), f.owner.clone(), Query(SyncQuery { since: None })).await.unwrap().0;
        assert!(r.items.iter().any(|i| i.base.id == id), "élément visible par la lecture");
        assert_eq!(r.collections.len(), 1);
        // L'étranger ne voit rien.
        let r = sync(State(f.state.clone()), f.stranger.clone(), Query(SyncQuery { since: None })).await.unwrap().0;
        assert!(r.items.is_empty() && r.collections.is_empty());
        assert_eq!(audits(&f.state, "item.created").await, 1);
    }

    /// Les requêtes de la synchronisation passent toutes par un index : aucun
    /// parcours complet d'une table (le coût suit les objets visibles, pas
    /// la taille de la base).
    #[tokio::test]
    async fn plans_de_la_synchronisation_indexes() {
        use rusqlite::types::Value as Sql;
        let st = test_state().await;
        let requetes = [
            ("coffres", SYNC_COLLECTIONS, 3),
            ("éléments", SYNC_ITEMS, 4),
            ("coffres visibles", SYNC_VISIBLE, 1),
            ("coffres retirés", SYNC_REMOVED_COLLECTIONS, 2),
            ("éléments retirés", SYNC_REMOVED_ITEMS, 2),
        ];
        let plans = st
            .db
            .read(move |c| {
                let mut out = Vec::new();
                for (nom, sql, n) in requetes {
                    let args = [Sql::Text("u".into()), Sql::Integer(5), Sql::Integer(1), Sql::Integer(86_400)];
                    let mut q = c.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?;
                    let lignes = q
                        .query_map(rusqlite::params_from_iter(&args[..n]), |r| r.get::<_, String>(3))?
                        .collect::<Result<Vec<_>, _>>()?;
                    out.push((nom, lignes));
                }
                Ok(out)
            })
            .await
            .unwrap();
        for (nom, lignes) in plans {
            assert!(!lignes.iter().any(|l| l.starts_with("SCAN ")), "parcours complet pour {nom} : {lignes:?}");
        }
    }
}
