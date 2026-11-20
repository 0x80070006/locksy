//! Préférences synchronisées et charte d'utilisation.
//!
//! Le document de préférences est chiffré par le client avec sa clé
//! utilisateur (AAD `verrou:v1:prefs:<user_id>`) : le serveur le stocke
//! opaque, avec une révision pour détecter les écritures concurrentes.

use crate::error::{ApiError, ApiResult};
use crate::settings_api::ExtError;
use crate::state::{audit_user, AppState, AuthUser};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use crate::error::Json;
use locksy_core::api::{AcceptCharterRequest, CharterStatus, PrefsDocument, PutPrefsRequest, PutPrefsResponse};
use locksy_core::crypto::is_well_formed_cipher;
use locksy_core::now_unix;
use rusqlite::{params, OptionalExtension};

/// Taille maximale du document chiffré (caractères).
pub const MAX_PREFS_CIPHER: usize = 65_536;

/// Limite de corps de la route `PUT /me/prefs` (le JSON enveloppe le chiffré).
pub const PREFS_BODY_LIMIT: usize = 128 * 1024;

/// `GET /me/prefs` : 404 tant qu'aucun document n'a été enregistré.
pub async fn get_prefs(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<PrefsDocument>> {
    let doc = state
        .db
        .read(move |c| {
            Ok(c.query_row(
                "SELECT revision, cipher, updated_at FROM user_prefs WHERE user_id = ?1",
                [&user.id],
                |r| Ok(PrefsDocument { revision: r.get(0)?, cipher: r.get(1)?, updated_at: r.get(2)? }),
            )
            .optional()?)
        })
        .await?;
    doc.map(Json).ok_or_else(|| ApiError::not_found("Aucune préférence enregistrée."))
}

/// Révision attendue d'un `If-Match` de préférences : `"7"`, `7`, `"0"` (création).
fn expected_revision(headers: &HeaderMap) -> Option<Option<i64>> {
    let raw = headers.get(header::IF_MATCH)?;
    Some(raw.to_str().ok().map(|v| v.trim().trim_start_matches("W/").trim_matches('"')).and_then(|v| v.parse().ok()))
}

/// `PUT /me/prefs` : remplace le document si la révision attendue est la
/// révision actuelle (0 à la création).
pub async fn put_prefs(
    State(state): State<AppState>,
    user: AuthUser,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<PutPrefsResponse>, ExtError> {
    let Some(expected) = expected_revision(&headers) else {
        return Err(ExtError::new(
            StatusCode::PRECONDITION_REQUIRED,
            "precondition_required",
            "En-tête If-Match obligatoire : indiquez la révision des préférences (0 à la création).",
        ));
    };
    let req: PutPrefsRequest =
        serde_json::from_slice(&body).map_err(|_| ApiError::bad_request("Requête illisible : JSON attendu."))?;
    if req.cipher.len() > MAX_PREFS_CIPHER {
        return Err(ExtError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_large",
            "Préférences trop volumineuses (64 Kio au plus).",
        )
        .with("max", MAX_PREFS_CIPHER as i64));
    }
    if !is_well_formed_cipher(&req.cipher, MAX_PREFS_CIPHER) {
        return Err(ExtError::new(
            StatusCode::BAD_REQUEST,
            "invalid_prefs",
            "Préférences refusées : le document doit être chiffré par l'application.",
        ));
    }
    let Some(expected) = expected else {
        // If-Match illisible : la révision connue ne peut pas être la bonne.
        return Err(prefs_conflict(current_revision(&state, &user.id).await?));
    };
    let uid = user.id.clone();
    let outcome = state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let current: i64 = tx
                .query_row("SELECT revision FROM user_prefs WHERE user_id = ?1", [&uid], |r| r.get(0))
                .optional()?
                .unwrap_or(0);
            if current != expected {
                return Ok(Err(current));
            }
            let revision = current + 1;
            tx.execute(
                "INSERT INTO user_prefs (user_id, cipher, revision, updated_at) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(user_id) DO UPDATE SET cipher = excluded.cipher, revision = excluded.revision,
                     updated_at = excluded.updated_at",
                params![uid, req.cipher, revision, now_unix()],
            )?;
            tx.commit()?;
            Ok(Ok(revision))
        })
        .await?;
    match outcome {
        Ok(revision) => Ok(Json(PutPrefsResponse { revision })),
        Err(current) => Err(prefs_conflict(current)),
    }
}

async fn current_revision(state: &AppState, user_id: &str) -> ApiResult<i64> {
    let uid = user_id.to_string();
    Ok(state
        .db
        .read(move |c| Ok(c.query_row("SELECT revision FROM user_prefs WHERE user_id = ?1", [uid], |r| r.get(0)).optional()?))
        .await?
        .unwrap_or(0))
}

fn prefs_conflict(current: i64) -> ExtError {
    ExtError::new(
        StatusCode::CONFLICT,
        "prefs_conflict",
        "Vos préférences ont été modifiées sur un autre appareil. Rechargez-les puis réessayez.",
    )
    .with("current_revision", current)
}

/// `GET /me/charter` : version exigée par l'organisation et version acceptée.
pub async fn get_charter(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<CharterStatus>> {
    let required_version = state.effective().await?.int("legal.charter_version");
    let accepted_version = state
        .db
        .read(move |c| {
            Ok(c.query_row("SELECT COALESCE(charter_accepted_version, 0) FROM users WHERE id = ?1", [&user.id], |r| r.get(0))?)
        })
        .await?;
    Ok(Json(CharterStatus { required_version, accepted_version }))
}

/// `POST /me/charter` : acceptation de la version en vigueur, journalisée.
pub async fn accept_charter(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<AcceptCharterRequest>,
) -> ApiResult<Json<CharterStatus>> {
    let required = state.effective().await?.int("legal.charter_version");
    if required == 0 || req.version != required {
        return Err(ApiError::conflict("Cette version de la charte n'est plus en vigueur. Rechargez la page."));
    }
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            tx.execute(
                "UPDATE users SET charter_accepted_version = ?1, charter_accepted_at = ?2 WHERE id = ?3",
                params![required, now_unix(), user.id],
            )?;
            audit_user(&tx, &user, "user.charter_accepted", &format!("v{required}"), "")?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(Json(CharterStatus { required_version: required, accepted_version: required }))
}
