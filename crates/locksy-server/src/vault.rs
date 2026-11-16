//! Coffres, membres et éléments. Le serveur contrôle les droits mais ne
//! peut rien lire : il ne manipule que des chiffrés.

use crate::auth::load_profile;
use crate::db::collection_role;
use crate::error::{ApiError, ApiResult};
use crate::security as sec;
use crate::state::{audit_user, AppState, AuthUser};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashSet;
use locksy_core::api::roles::{EDITOR, MANAGER, READER};
use locksy_core::api::*;
use locksy_core::now_unix;

fn require_role(c: &Connection, collection_id: &str, user_id: &str, allowed: &[&str]) -> ApiResult<String> {
    match collection_role(c, collection_id, user_id)? {
        Some(r) if allowed.contains(&r.as_str()) => Ok(r),
        Some(_) => Err(ApiError::forbidden("Vos droits sur ce coffre ne permettent pas cette action.")),
        None => Err(ApiError::not_found("Coffre introuvable.")),
    }
}

const WRITE: &[&str] = &[MANAGER, EDITOR];
const MANAGE: &[&str] = &[MANAGER];
const ANY: &[&str] = &[MANAGER, EDITOR, READER];

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

pub async fn sync(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<SyncResponse>> {
    Ok(Json(
        state
            .db
            .call(move |c| {
                let profile = load_profile(c, &user.id)?;
                let mut st = c.prepare(
                    "SELECT c.id, c.enc_name, c.personal, m.role, m.sealed_key, c.updated_at,
                            (SELECT COUNT(*) FROM memberships x WHERE x.collection_id = c.id)
                     FROM memberships m JOIN collections c ON c.id = m.collection_id
                     WHERE m.user_id = ?1 ORDER BY c.personal DESC, c.created_at",
                )?;
                let collections = st
                    .query_map([&user.id], |r| {
                        Ok(CollectionView {
                            id: r.get(0)?,
                            enc_name: r.get(1)?,
                            personal: r.get(2)?,
                            role: r.get(3)?,
                            sealed_key: r.get(4)?,
                            updated_at: r.get(5)?,
                            member_count: r.get(6)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                let mut st = c.prepare(
                    "SELECT i.id, i.collection_id, i.data, i.revision, i.created_at, i.updated_at, i.deleted_at
                     FROM items i JOIN memberships m ON m.collection_id = i.collection_id
                     WHERE m.user_id = ?1",
                )?;
                let items = st
                    .query_map([&user.id], |r| {
                        Ok(ItemView {
                            id: r.get(0)?,
                            collection_id: r.get(1)?,
                            data: r.get(2)?,
                            revision: r.get(3)?,
                            created_at: r.get(4)?,
                            updated_at: r.get(5)?,
                            deleted_at: r.get(6)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(SyncResponse { profile, collections, items, server_time: now_unix() })
            })
            .await?,
    ))
}

pub async fn directory(State(state): State<AppState>, _user: AuthUser) -> ApiResult<Json<Vec<DirectoryUser>>> {
    Ok(Json(
        state
            .db
            .call(|c| {
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
    sec::cipher(&req.enc_name, sec::NAME_CIPHER_MAX, "nom du coffre")?;
    state
        .db
        .call(move |c| {
            require_role(c, &id, &user.id, MANAGE)?;
            c.execute(
                "UPDATE collections SET enc_name = ?1, updated_at = ?2 WHERE id = ?3",
                params![req.enc_name, now_unix(), id],
            )?;
            audit_user(c, &user, "collection.renamed", &id, "")
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_collection(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    state
        .db
        .call(move |c| {
            require_role(c, &id, &user.id, MANAGE)?;
            if is_personal(c, &id)? {
                return Err(ApiError::bad_request("Le coffre personnel ne peut pas être supprimé."));
            }
            let tx = c.transaction()?;
            let items: i64 = tx.query_row("SELECT COUNT(*) FROM items WHERE collection_id = ?1", [&id], |r| r.get(0))?;
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
    Ok(Json(
        state
            .db
            .call(move |c| {
                require_role(c, &id, &user.id, ANY)?;
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
    valid_role(&req.role)?;
    sec::sealed(&req.sealed_key)?;
    state
        .db
        .call(move |c| {
            require_role(c, &id, &user.id, MANAGE)?;
            if is_personal(c, &id)? {
                return Err(ApiError::bad_request("Le coffre personnel ne se partage pas. Créez un coffre partagé."));
            }
            let target: Option<(String, bool)> = c
                .query_row("SELECT email, disabled FROM users WHERE id = ?1", [&req.user_id], |r| Ok((r.get(0)?, r.get(1)?)))
                .optional()?;
            let Some((email, disabled)) = target else {
                return Err(ApiError::not_found("Utilisateur introuvable."));
            };
            if disabled {
                return Err(ApiError::bad_request("Ce compte est désactivé."));
            }
            let n = c.execute(
                "INSERT OR IGNORE INTO memberships (collection_id, user_id, role, sealed_key, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![id, req.user_id, req.role, req.sealed_key, now_unix()],
            )?;
            if n == 0 {
                return Err(ApiError::conflict("Cette personne a déjà accès au coffre."));
            }
            touch_collection(c, &id)?;
            audit_user(c, &user, "collection.member_added", &id, &format!("{email} ({})", req.role))
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
    valid_role(&req.role)?;
    state
        .db
        .call(move |c| {
            require_role(c, &id, &user.id, MANAGE)?;
            let current = collection_role(c, &id, &member_id)?.ok_or_else(|| ApiError::not_found("Membre introuvable."))?;
            if current == MANAGER && req.role != MANAGER && manager_count(c, &id)? <= 1 {
                return Err(ApiError::bad_request("Un coffre doit garder au moins un gestionnaire."));
            }
            c.execute(
                "UPDATE memberships SET role = ?1 WHERE collection_id = ?2 AND user_id = ?3",
                params![req.role, id, member_id],
            )?;
            touch_collection(c, &id)?;
            audit_user(c, &user, "collection.member_role", &id, &format!("{member_id} : {current} → {}", req.role))
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
    if member_id != user.id {
        return Err(ApiError::bad_request("Pour retirer un membre, utilisez « Retirer et renouveler la clé »."));
    }
    state
        .db
        .call(move |c| {
            let role = require_role(c, &id, &user.id, ANY)?;
            if is_personal(c, &id)? {
                return Err(ApiError::bad_request("Vous ne pouvez pas quitter votre coffre personnel."));
            }
            if role == MANAGER && manager_count(c, &id)? <= 1 {
                return Err(ApiError::bad_request("Nommez un autre gestionnaire avant de quitter ce coffre."));
            }
            c.execute("DELETE FROM memberships WHERE collection_id = ?1 AND user_id = ?2", params![id, user.id])?;
            touch_collection(c, &id)?;
            audit_user(c, &user, "collection.left", &id, "")
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
            require_role(&tx, &id, &user.id, MANAGE)?;
            if req.remove_user_ids.iter().any(|u| *u == user.id) {
                return Err(ApiError::bad_request("Vous ne pouvez pas vous retirer vous-même ainsi."));
            }
            for uid in &req.remove_user_ids {
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
            tx.execute(
                "UPDATE collections SET enc_name = ?1, key_version = key_version + 1, updated_at = ?2 WHERE id = ?3",
                params![req.enc_name, now, id],
            )?;
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

fn insert_item(c: &Connection, user: &AuthUser, item: &CreateItemRequest, now: i64) -> ApiResult<()> {
    require_role(c, &item.collection_id, &user.id, WRITE)?;
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
    Json(req): Json<CreateItemRequest>,
) -> ApiResult<StatusCode> {
    validate_new_item(&req)?;
    state
        .db
        .call(move |c| {
            insert_item(c, &user, &req, now_unix())?;
            touch_collection(c, &req.collection_id)?;
            audit_user(c, &user, "item.created", &req.id, &format!("coffre {}", req.collection_id))
        })
        .await?;
    Ok(StatusCode::CREATED)
}

pub async fn create_items_batch(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<BatchCreateItemsRequest>,
) -> ApiResult<StatusCode> {
    if req.items.is_empty() || req.items.len() > 2000 {
        return Err(ApiError::bad_request("Entre 1 et 2 000 éléments par import."));
    }
    for i in &req.items {
        validate_new_item(i)?;
    }
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let now = now_unix();
            let mut collections = HashSet::new();
            for i in &req.items {
                insert_item(&tx, &user, i, now)?;
                collections.insert(i.collection_id.clone());
            }
            for cid in &collections {
                touch_collection(&tx, cid)?;
            }
            audit_user(&tx, &user, "item.imported", "", &format!("{} élément(s)", req.items.len()))?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::CREATED)
}

fn item_location(c: &Connection, id: &str) -> ApiResult<(String, i64)> {
    c.query_row("SELECT collection_id, revision FROM items WHERE id = ?1", [id], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?
        .ok_or_else(|| ApiError::not_found("Élément introuvable."))
}

pub async fn update_item(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateItemRequest>,
) -> ApiResult<Json<i64>> {
    sec::uuid(&req.collection_id, "coffre")?;
    sec::cipher(&req.data, sec::ITEM_CIPHER_MAX, "élément")?;
    let revision = state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let (current_collection, revision) = item_location(&tx, &id)?;
            require_role(&tx, &current_collection, &user.id, WRITE)?;
            if req.collection_id != current_collection {
                require_role(&tx, &req.collection_id, &user.id, WRITE)?;
            }
            if req.revision != revision {
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
            touch_collection(&tx, &req.collection_id)?;
            let details = if req.collection_id != current_collection {
                format!("déplacé de {current_collection} vers {}", req.collection_id)
            } else {
                String::new()
            };
            audit_user(&tx, &user, "item.updated", &id, &details)?;
            tx.commit()?;
            Ok(revision + 1)
        })
        .await?;
    Ok(Json(revision))
}

pub async fn trash_item(State(state): State<AppState>, user: AuthUser, Path(id): Path<String>) -> ApiResult<StatusCode> {
    set_deleted(state, user, id, true).await
}

pub async fn restore_item(State(state): State<AppState>, user: AuthUser, Path(id): Path<String>) -> ApiResult<StatusCode> {
    set_deleted(state, user, id, false).await
}

async fn set_deleted(state: AppState, user: AuthUser, id: String, deleted: bool) -> ApiResult<StatusCode> {
    state
        .db
        .call(move |c| {
            let (cid, _) = item_location(c, &id)?;
            require_role(c, &cid, &user.id, WRITE)?;
            let now = now_unix();
            c.execute(
                "UPDATE items SET deleted_at = ?1, updated_at = ?2, revision = revision + 1 WHERE id = ?3",
                params![if deleted { Some(now) } else { None }, now, id],
            )?;
            touch_collection(c, &cid)?;
            audit_user(c, &user, if deleted { "item.trashed" } else { "item.restored" }, &id, "")
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn purge_item(State(state): State<AppState>, user: AuthUser, Path(id): Path<String>) -> ApiResult<StatusCode> {
    state
        .db
        .call(move |c| {
            let (cid, _) = item_location(c, &id)?;
            require_role(c, &cid, &user.id, WRITE)?;
            c.execute("DELETE FROM items WHERE id = ?1 AND deleted_at IS NOT NULL", [&id])?;
            touch_collection(c, &cid)?;
            audit_user(c, &user, "item.purged", &id, "")
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
