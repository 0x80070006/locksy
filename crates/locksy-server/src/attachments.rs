//! Pièces jointes chiffrées. Chaque fichier est chiffré dans le navigateur
//! avec une clé aléatoire, elle-même rangée dans l'élément chiffré : le serveur
//! ne voit ni le nom, ni le type, ni le contenu. L'accès suit l'élément :
//! seuls les membres de son coffre peuvent télécharger le fichier.

use crate::db::collection_role;
use crate::error::{ApiError, ApiResult};
use crate::security as sec;
use crate::state::{audit_user, AppState, AuthUser};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use locksy_core::api::roles::{EDITOR, MANAGER};
use locksy_core::now_unix;

/// 10 Mio de fichier, une fois chiffré et encodé en base64.
pub const MAX_CIPHER_LEN: usize = 14_500_000;
const MAX_PER_ITEM: i64 = 20;

#[derive(Deserialize)]
pub struct UploadRequest {
    pub data: String,
}

#[derive(Serialize)]
pub struct DownloadResponse {
    pub data: String,
}

fn item_collection(c: &Connection, item_id: &str) -> ApiResult<String> {
    c.query_row("SELECT collection_id FROM items WHERE id = ?1", [item_id], |r| r.get(0))
        .optional()?
        .ok_or_else(|| ApiError::not_found("Élément introuvable."))
}

fn attachment_collection(c: &Connection, id: &str) -> ApiResult<(String, String)> {
    c.query_row(
        "SELECT a.item_id, i.collection_id FROM attachments a JOIN items i ON i.id = a.item_id WHERE a.id = ?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()?
    .ok_or_else(|| ApiError::not_found("Pièce jointe introuvable."))
}

fn require(c: &Connection, collection_id: &str, user_id: &str, write: bool) -> ApiResult<()> {
    match collection_role(c, collection_id, user_id)? {
        Some(r) if !write || r == MANAGER || r == EDITOR => Ok(()),
        Some(_) => Err(ApiError::forbidden("Vos droits sur ce coffre ne permettent pas cette action.")),
        None => Err(ApiError::not_found("Pièce jointe introuvable.")),
    }
}

pub async fn upload(
    State(state): State<AppState>,
    user: AuthUser,
    Path((item_id, id)): Path<(String, String)>,
    Json(req): Json<UploadRequest>,
) -> ApiResult<StatusCode> {
    sec::uuid(&id, "pièce jointe")?;
    sec::cipher(&req.data, MAX_CIPHER_LEN, "pièce jointe (10 Mo au plus)")?;
    state
        .db
        .call(move |c| {
            let cid = item_collection(c, &item_id)?;
            require(c, &cid, &user.id, true)?;
            let count: i64 = c.query_row("SELECT COUNT(*) FROM attachments WHERE item_id = ?1", [&item_id], |r| r.get(0))?;
            if count >= MAX_PER_ITEM {
                return Err(ApiError::bad_request("20 pièces jointes au plus par élément."));
            }
            let n = c.execute(
                "INSERT OR IGNORE INTO attachments (id, item_id, data, size, created_at, created_by) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![id, item_id, req.data, req.data.len() as i64, now_unix(), user.id],
            )?;
            if n == 0 {
                return Err(ApiError::conflict("Cette pièce jointe existe déjà."));
            }
            audit_user(c, &user, "attachment.added", &item_id, &format!("{} Ko chiffrés", req.data.len() / 1024))
        })
        .await?;
    Ok(StatusCode::CREATED)
}

pub async fn download(State(state): State<AppState>, user: AuthUser, Path(id): Path<String>) -> ApiResult<Json<DownloadResponse>> {
    Ok(Json(
        state
            .db
            .call(move |c| {
                let (item_id, cid) = attachment_collection(c, &id)?;
                require(c, &cid, &user.id, false)?;
                let data: String = c.query_row("SELECT data FROM attachments WHERE id = ?1", [&id], |r| r.get(0))?;
                audit_user(c, &user, "attachment.downloaded", &item_id, "")?;
                Ok(DownloadResponse { data })
            })
            .await?,
    ))
}

pub async fn remove(State(state): State<AppState>, user: AuthUser, Path(id): Path<String>) -> ApiResult<StatusCode> {
    state
        .db
        .call(move |c| {
            let (item_id, cid) = attachment_collection(c, &id)?;
            require(c, &cid, &user.id, true)?;
            c.execute("DELETE FROM attachments WHERE id = ?1", [&id])?;
            audit_user(c, &user, "attachment.removed", &item_id, "")
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
