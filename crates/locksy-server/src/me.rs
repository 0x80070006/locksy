//! Compte de l'utilisateur connecté : profil, mot de passe maître, clé de
//! récupération, double authentification, sessions et journal personnel.

use crate::auth::{decrypt_totp_secret, encrypt_totp_secret, load_profile};
use crate::db;
use crate::error::{ApiError, ApiResult};
use crate::security::{self as sec, hash_secret, verify_secret};
use crate::state::{audit_user, AppState, AuthUser};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use rusqlite::params;
use locksy_core::api::*;
use locksy_core::encoding::b64d;
use locksy_core::{now_unix, totp};

pub async fn get_me(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Profile>> {
    Ok(Json(state.db.call(move |c| load_profile(c, &user.id)).await?))
}

pub async fn update_me(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<UpdateProfileRequest>,
) -> ApiResult<Json<Profile>> {
    let name = sec::clean_name(&req.name)?;
    Ok(Json(
        state
            .db
            .call(move |c| {
                c.execute("UPDATE users SET name = ?1, updated_at = ?2 WHERE id = ?3", params![name, now_unix(), user.id])?;
                audit_user(c, &user, "profile.updated", "", "")?;
                load_profile(c, &user.id)
            })
            .await?,
    ))
}

async fn check_current_auth(state: &AppState, user: &AuthUser, current_auth_key: &str) -> ApiResult<()> {
    let key = format!("reauth:{}", user.id);
    state.limiter.check(&key)?;
    let proof = b64d(current_auth_key).map_err(|_| ApiError::bad_request("Preuve invalide."))?;
    let uid = user.id.clone();
    let hash: String = state.db.call(move |c| Ok(c.query_row("SELECT auth_hash FROM users WHERE id = ?1", [uid], |r| r.get(0))?)).await?;
    if !verify_secret(proof, hash).await {
        state.limiter.fail(&key, 5);
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "invalid_credentials", "Mot de passe maître actuel incorrect."));
    }
    state.limiter.success(&key);
    Ok(())
}

pub async fn change_password(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<ChangePasswordRequest>,
) -> ApiResult<StatusCode> {
    sec::kdf(&req.kdf)?;
    sec::cipher(&req.wrapped_user_key, sec::KEY_CIPHER_MAX, "clé utilisateur")?;
    let new_key = sec::key32(&req.auth_key, "Nouvelle preuve")?;
    check_current_auth(&state, &user, &req.current_auth_key).await?;
    let hash = hash_secret(new_key).await?;
    let kdf = serde_json::to_string(&req.kdf).map_err(|_| ApiError::internal("kdf"))?;
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            tx.execute(
                "UPDATE users SET auth_hash = ?1, kdf = ?2, wrapped_user_key = ?3, updated_at = ?4 WHERE id = ?5",
                params![hash, kdf, req.wrapped_user_key, now_unix(), user.id],
            )?;
            tx.execute("DELETE FROM sessions WHERE user_id = ?1 AND id <> ?2", params![user.id, user.session_id])?;
            audit_user(&tx, &user, "password.changed", "", "autres sessions fermées")?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn rotate_recovery(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<RotateRecoveryRequest>,
) -> ApiResult<StatusCode> {
    sec::cipher(&req.recovery_wrapped_user_key, sec::KEY_CIPHER_MAX, "clé de récupération")?;
    let proof = sec::key32(&req.recovery_auth, "Preuve de récupération")?;
    check_current_auth(&state, &user, &req.current_auth_key).await?;
    let hash = hash_secret(proof).await?;
    state
        .db
        .call(move |c| {
            c.execute(
                "UPDATE users SET recovery_wrapped_user_key = ?1, recovery_auth_hash = ?2, updated_at = ?3 WHERE id = ?4",
                params![req.recovery_wrapped_user_key, hash, now_unix(), user.id],
            )?;
            audit_user(c, &user, "recovery_key.rotated", "", "")
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ------------------------------------------------------------ 2FA

pub async fn totp_setup(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<TotpSetupResponse>> {
    let secret = totp::generate_secret();
    let uri = totp::provisioning_uri(&secret, &user.email, "Locksy");
    let qr_svg = qrcode::QrCode::new(uri.as_bytes())
        .map_err(|_| ApiError::internal("QR code"))?
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(220, 220)
        .dark_color(qrcode::render::svg::Color("#111111"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build();
    let enc = encrypt_totp_secret(&state, &user.id, &secret);
    state
        .db
        .call(move |c| {
            let enabled: bool =
                c.query_row("SELECT totp_secret IS NOT NULL FROM users WHERE id = ?1", [&user.id], |r| r.get(0))?;
            if enabled {
                return Err(ApiError::conflict("La double authentification est déjà active."));
            }
            c.execute("UPDATE users SET totp_pending = ?1 WHERE id = ?2", params![enc, user.id])?;
            Ok(())
        })
        .await?;
    Ok(Json(TotpSetupResponse { secret, uri, qr_svg }))
}

pub async fn totp_enable(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<TotpCodeRequest>,
) -> ApiResult<Json<Profile>> {
    let key = format!("totp:{}", user.id);
    state.limiter.check(&key)?;
    let server_key = state.server_key.clone();
    let limiter = state.limiter.clone();
    Ok(Json(
        state
            .db
            .call(move |c| {
                let pending: Option<String> =
                    c.query_row("SELECT totp_pending FROM users WHERE id = ?1", [&user.id], |r| r.get(0))?;
                let pending = pending.ok_or_else(|| ApiError::bad_request("Commencez par générer un nouveau secret."))?;
                let secret = decrypt_totp_secret(&server_key, &user.id, &pending)?;
                let Some(step) = totp::verify(&secret, &req.code, now_unix() as u64, None) else {
                    limiter.fail(&key, 5);
                    return Err(ApiError::bad_request("Code incorrect. Vérifiez l'heure de votre téléphone."));
                };
                limiter.success(&key);
                c.execute(
                    "UPDATE users SET totp_secret = totp_pending, totp_pending = NULL, totp_last_step = ?1 WHERE id = ?2",
                    params![step as i64, user.id],
                )?;
                audit_user(c, &user, "2fa.enabled", "", "")?;
                load_profile(c, &user.id)
            })
            .await?,
    ))
}

pub async fn totp_disable(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<TotpCodeRequest>,
) -> ApiResult<Json<Profile>> {
    let key = format!("totp:{}", user.id);
    state.limiter.check(&key)?;
    let server_key = state.server_key.clone();
    let limiter = state.limiter.clone();
    Ok(Json(
        state
            .db
            .call(move |c| {
                if db::load_settings(c)?.require_2fa {
                    return Err(ApiError::forbidden("Votre organisation impose la double authentification."));
                }
                let (secret, last): (Option<String>, Option<i64>) = c.query_row(
                    "SELECT totp_secret, totp_last_step FROM users WHERE id = ?1",
                    [&user.id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                let secret = secret.ok_or_else(|| ApiError::bad_request("La double authentification n'est pas active."))?;
                let secret = decrypt_totp_secret(&server_key, &user.id, &secret)?;
                if totp::verify(&secret, &req.code, now_unix() as u64, last.map(|s| s as u64)).is_none() {
                    limiter.fail(&key, 5);
                    return Err(ApiError::bad_request("Code incorrect."));
                }
                limiter.success(&key);
                c.execute(
                    "UPDATE users SET totp_secret = NULL, totp_pending = NULL, totp_last_step = NULL WHERE id = ?1",
                    [&user.id],
                )?;
                audit_user(c, &user, "2fa.disabled", "", "")?;
                load_profile(c, &user.id)
            })
            .await?,
    ))
}

// ------------------------------------------------------------ Sessions

pub async fn list_sessions(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Vec<SessionView>>> {
    Ok(Json(
        state
            .db
            .call(move |c| {
                let mut st = c.prepare(
                    "SELECT id, created_at, last_seen_at, expires_at, ip, device FROM sessions
                     WHERE user_id = ?1 ORDER BY last_seen_at DESC",
                )?;
                let rows = st
                    .query_map([&user.id], |r| {
                        let id: String = r.get(0)?;
                        Ok(SessionView {
                            current: id == user.session_id,
                            id,
                            created_at: r.get(1)?,
                            last_seen_at: r.get(2)?,
                            expires_at: r.get(3)?,
                            ip: r.get(4)?,
                            device: r.get(5)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?,
    ))
}

pub async fn revoke_session(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    state
        .db
        .call(move |c| {
            let n = c.execute("DELETE FROM sessions WHERE id = ?1 AND user_id = ?2", params![id, user.id])?;
            if n == 0 {
                return Err(ApiError::not_found("Session introuvable."));
            }
            audit_user(c, &user, "session.revoked", &id, "")
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn my_audit(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Vec<AuditEntry>>> {
    Ok(Json(
        state
            .db
            .call(move |c| {
                let mut st = c.prepare(
                    "SELECT id, at, user_id, email, action, target, ip, user_agent, details FROM audit
                     WHERE user_id = ?1 ORDER BY id DESC LIMIT 200",
                )?;
                let rows = st.query_map([&user.id], crate::admin::audit_row)?.collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?,
    ))
}
