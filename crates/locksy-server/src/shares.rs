//! Liens de partage externes. Le contenu est chiffré dans le navigateur avec
//! une clé placée après le `#` du lien : elle n'est jamais envoyée au serveur.

use crate::error::{ApiError, ApiResult};
use crate::security as sec;
use crate::state::{audit, audit_user, AppState, AuthUser, ClientMeta};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use rusqlite::{params, OptionalExtension};
use locksy_core::api::*;
use locksy_core::crypto::random_token;
use locksy_core::now_unix;

pub async fn create_share(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateShareRequest>,
) -> ApiResult<Json<CreateShareResponse>> {
    sec::cipher(&req.data, sec::SHARE_CIPHER_MAX, "partage")?;
    if !(5..=43_200).contains(&req.expires_in_minutes) {
        return Err(ApiError::bad_request("Durée de validité entre 5 minutes et 30 jours."));
    }
    if !(1..=100).contains(&req.max_views) {
        return Err(ApiError::bad_request("Entre 1 et 100 consultations."));
    }
    state.limiter.hit(&format!("share-create:{}", user.id), 60, 3600)?;
    let id = random_token();
    let expires_at = now_unix() + req.expires_in_minutes * 60;
    let sid = id.clone();
    state
        .db
        .call(move |c| {
            c.execute(
                "INSERT INTO shares (id, owner_id, data, created_at, expires_at, max_views) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![sid, user.id, req.data, now_unix(), expires_at, req.max_views],
            )?;
            audit_user(
                c,
                &user,
                "share.created",
                &sid[..8],
                &format!("{} consultation(s), {} min", req.max_views, req.expires_in_minutes),
            )
        })
        .await?;
    Ok(Json(CreateShareResponse { id, expires_at }))
}

pub async fn list_shares(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Vec<ShareSummary>>> {
    Ok(Json(
        state
            .db
            .call(move |c| {
                let mut st = c.prepare(
                    "SELECT id, created_at, expires_at, max_views, views FROM shares
                     WHERE owner_id = ?1 AND expires_at > ?2 AND views < max_views ORDER BY created_at DESC",
                )?;
                let rows = st
                    .query_map(params![user.id, now_unix()], |r| {
                        Ok(ShareSummary {
                            id: r.get(0)?,
                            created_at: r.get(1)?,
                            expires_at: r.get(2)?,
                            max_views: r.get(3)?,
                            views: r.get(4)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?,
    ))
}

pub async fn delete_share(State(state): State<AppState>, user: AuthUser, Path(id): Path<String>) -> ApiResult<StatusCode> {
    state
        .db
        .call(move |c| {
            let n = c.execute("DELETE FROM shares WHERE id = ?1 AND owner_id = ?2", params![id, user.id])?;
            if n == 0 {
                return Err(ApiError::not_found("Lien introuvable."));
            }
            audit_user(c, &user, "share.revoked", id.get(..8).unwrap_or(""), "")
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Consultation publique : chaque appel consomme une vue ; le lien est
/// détruit à la dernière consultation ou à l'expiration.
pub async fn open_share(
    State(state): State<AppState>,
    meta: ClientMeta,
    Path(id): Path<String>,
) -> ApiResult<Json<ShareView>> {
    state.limiter.hit(&format!("share-open:{}", meta.ip), 30, 60)?;
    if id.len() > 64 {
        return Err(ApiError::not_found("Ce lien n'existe pas ou n'est plus valide."));
    }
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let now = now_unix();
            let row: Option<(String, String, i64, i64, i64)> = tx
                .query_row(
                    "SELECT owner_id, data, expires_at, max_views, views FROM shares WHERE id = ?1",
                    [&id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .optional()?;
            let Some((owner, data, expires_at, max_views, views)) = row else {
                return Err(ApiError::not_found("Ce lien n'existe pas ou n'est plus valide."));
            };
            if expires_at <= now || views >= max_views {
                tx.execute("DELETE FROM shares WHERE id = ?1", [&id])?;
                tx.commit()?;
                return Err(ApiError::not_found("Ce lien n'existe pas ou n'est plus valide."));
            }
            let views = views + 1;
            if views >= max_views {
                tx.execute("DELETE FROM shares WHERE id = ?1", [&id])?;
            } else {
                tx.execute("UPDATE shares SET views = ?1 WHERE id = ?2", params![views, id])?;
            }
            audit(&tx, Some(&owner), "", "share.opened", &id[..8.min(id.len())], &meta, &format!("consultation {views}/{max_views}"))?;
            tx.commit()?;
            Ok(Json(ShareView { data, expires_at, views_left: max_views - views }))
        })
        .await
}
