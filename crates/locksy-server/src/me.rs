//! Compte de l'utilisateur connecté : profil, mot de passe maître, clé de
//! récupération, double authentification et codes de secours, sessions,
//! export et journal personnel.

use crate::auth::{
    decrypt_totp_secret, encrypt_totp_secret, factor_attempt, has_totp, load_profile_with, settle_factor,
    take_second_factor, totp_required, SecCtx,
};
use crate::error::{ApiError, ApiResult};
use crate::security::{self as sec, hash_secret};
use crate::state::{audit_user, AppState, AuthUser};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use crate::error::Json;
use locksy_core::api::*;
use locksy_core::crypto::{new_uuid, KdfParams, SecretKey};
use locksy_core::settings::twofa_applies;
use locksy_core::{now_unix, totp};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

pub async fn get_me(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Profile>> {
    let eff = state.effective().await?;
    Ok(Json(state.db.read(move |c| load_profile_with(c, &eff, &user.id)).await?))
}

pub async fn update_me(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<UpdateProfileRequest>,
) -> ApiResult<Json<Profile>> {
    let name = sec::clean_name(&req.name)?;
    let eff = state.effective().await?;
    Ok(Json(
        state
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                tx.execute("UPDATE users SET name = ?1, updated_at = ?2 WHERE id = ?3", params![name, now_unix(), user.id])?;
                audit_user(&tx, &user, "profile.updated", "", "")?;
                let profile = load_profile_with(&tx, &eff, &user.id)?;
                tx.commit()?;
                Ok(profile)
            })
            .await?,
    ))
}

/// Le mot de passe maître a changé depuis la vérification de la preuve
/// (autre appareil, récupération) : la mise à jour n'est pas appliquée (409).
fn password_changed_concurrently() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        "password_changed_concurrently",
        "Votre mot de passe maître vient d'être modifié depuis un autre appareil. Reconnectez-vous puis recommencez.",
    )
}

/// Remplace la preuve du mot de passe maître et ce qui en dépend, à
/// condition que l'empreinte soit encore celle vérifiée (`verified`) : sinon
/// le mot de passe a changé entre-temps (409 `password_changed_concurrently`).
pub(crate) fn update_secret(
    c: &Connection,
    user_id: &str,
    verified: &str,
    new_hash: &str,
    kdf_json: &str,
    wrapped_user_key: &str,
) -> ApiResult<()> {
    let n = c.execute(
        "UPDATE users SET auth_hash = ?1, kdf = ?2, wrapped_user_key = ?3, updated_at = ?4
         WHERE id = ?5 AND auth_hash = ?6",
        params![new_hash, kdf_json, wrapped_user_key, now_unix(), user_id, verified],
    )?;
    if n == 0 {
        return Err(password_changed_concurrently());
    }
    Ok(())
}

/// La requête porte-t-elle un en-tête de réauthentification ?
fn has_reauth(headers: &HeaderMap) -> bool {
    headers.contains_key(sec::REAUTH_HEADER)
}

/// Code du second facteur exigé d'un compte doté de la 2FA, avant tout
/// calcul coûteux : 401 `totp_required` s'il manque.
async fn require_factor_code(state: &AppState, user_id: &str, code: Option<&str>) -> ApiResult<bool> {
    let on = has_totp(state, user_id).await?;
    if on && code.map(str::trim).filter(|c| !c.is_empty()).is_none() {
        return Err(totp_required());
    }
    Ok(on)
}

/// Corps de `POST /me/password` : la requête commune, plus le code du second
/// facteur (ou un code de secours) exigé quand la 2FA est active.
#[derive(Deserialize)]
pub struct ChangePasswordBody {
    #[serde(flatten)]
    base: ChangePasswordRequest,
    #[serde(default)]
    totp: Option<String>,
}

/// `POST /me/password` : preuve actuelle (403 si refusée), second facteur
/// si la 2FA est active, paramètres de dérivation au moins égaux aux
/// planchers (422), mise à jour conditionnelle (409 si le mot de passe a
/// changé entre-temps). Les autres sessions sont fermées.
pub async fn change_password(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<ChangePasswordBody>,
) -> ApiResult<StatusCode> {
    let ChangePasswordBody { base: req, totp } = body;
    let ctx = SecCtx::of(&state).await?;
    sec::kdf(&req.kdf)?;
    sec::kdf_policy(&ctx.eff, &req.kdf)?;
    sec::cipher(&req.wrapped_user_key, sec::KEY_CIPHER_MAX, "clé utilisateur")?;
    let new_key = sec::key32(&req.auth_key, "Nouvelle preuve")?;
    let totp_on = require_factor_code(&state, &user.id, totp.as_deref()).await?;
    let verified = sec::check_password_proof(&state, &user.id, &req.current_auth_key, sec::wrong_password).await?;
    let hash = hash_secret(new_key).await?;
    let kdf = serde_json::to_string(&req.kdf).map_err(|_| ApiError::internal("kdf"))?;
    let code = if totp_on { Some(factor_attempt(&state, &user.id, totp.as_deref())?) } else { None };
    let u = user.clone();
    let res = state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            if let Some(code) = &code {
                take_second_factor(&tx, &ctx, &u.id, &u.email, &u.meta, code)?;
            }
            update_secret(&tx, &u.id, &verified, &hash, &kdf, &req.wrapped_user_key)?;
            tx.execute("DELETE FROM sessions WHERE user_id = ?1 AND id <> ?2", params![u.id, u.session_id])?;
            audit_user(&tx, &u, "password.changed", "", "autres sessions fermées")?;
            ctx.notify(&tx, &u.id, "password.changed")?;
            tx.commit()?;
            Ok(())
        })
        .await;
    if totp_on {
        settle_factor(&state, &user.id, &res);
    }
    res.map(|_| StatusCode::NO_CONTENT)
}

/// Corps de `POST /me/recovery`, plus le code du second facteur.
#[derive(Deserialize)]
pub struct RotateRecoveryBody {
    #[serde(flatten)]
    base: RotateRecoveryRequest,
    #[serde(default)]
    totp: Option<String>,
}

/// `POST /me/recovery` : nouvelle clé de récupération. Confirmation par un
/// jeton « recovery.rotate » (`X-Locksy-Reauth`), ou, à défaut, par la
/// preuve du mot de passe maître (403 si refusée) et le second facteur.
pub async fn rotate_recovery(
    State(state): State<AppState>,
    user: AuthUser,
    headers: HeaderMap,
    Json(body): Json<RotateRecoveryBody>,
) -> ApiResult<StatusCode> {
    let RotateRecoveryBody { base: req, totp } = body;
    sec::cipher(&req.recovery_wrapped_user_key, sec::KEY_CIPHER_MAX, "clé de récupération")?;
    let proof = sec::key32(&req.recovery_auth, "Preuve de récupération")?;
    let ctx = SecCtx::of(&state).await?;
    let totp_on = if has_reauth(&headers) {
        sec::require_step_up(&state, &user, &headers, "recovery.rotate").await?;
        false
    } else {
        let on = require_factor_code(&state, &user.id, totp.as_deref()).await?;
        sec::check_password_proof(&state, &user.id, &req.current_auth_key, sec::wrong_password).await?;
        on
    };
    let hash = hash_secret(proof).await?;
    let code = if totp_on { Some(factor_attempt(&state, &user.id, totp.as_deref())?) } else { None };
    let u = user.clone();
    let res = state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            if let Some(code) = &code {
                take_second_factor(&tx, &ctx, &u.id, &u.email, &u.meta, code)?;
            }
            tx.execute(
                "UPDATE users SET recovery_wrapped_user_key = ?1, recovery_auth_hash = ?2, updated_at = ?3 WHERE id = ?4",
                params![req.recovery_wrapped_user_key, hash, now_unix(), u.id],
            )?;
            audit_user(&tx, &u, "recovery_key.rotated", "", "")?;
            ctx.notify(&tx, &u.id, "recovery_key.rotated")?;
            tx.commit()?;
            Ok(())
        })
        .await;
    if totp_on {
        settle_factor(&state, &user.id, &res);
    }
    res.map(|_| StatusCode::NO_CONTENT)
}

// ------------------------------------------------------------ Paramètres de dérivation

/// Corps de `POST /me/kdf` : preuve actuelle, nouveaux paramètres et ce qui
/// en découle (nouvelle preuve, clé utilisateur ré-enveloppée).
#[derive(Deserialize)]
pub struct UpgradeKdfBody {
    current_auth_key: String,
    kdf: KdfParams,
    auth_key: String,
    wrapped_user_key: String,
}

/// `POST /me/kdf` : montée des paramètres de dérivation du mot de passe
/// maître (même mot de passe) quand la politique s'est durcie. Une baisse
/// est refusée (422 `kdf_too_weak`) ; les autres sessions restent ouvertes.
pub async fn upgrade_kdf(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<UpgradeKdfBody>,
) -> ApiResult<Json<Profile>> {
    let eff = state.effective().await?;
    if !eff.bool("kdf.upgrade_on_login") {
        return Err(ApiError::conflict(
            "La mise à niveau de la protection du mot de passe maître est désactivée par votre organisation.",
        ));
    }
    sec::kdf(&req.kdf)?;
    sec::kdf_policy(&eff, &req.kdf)?;
    sec::cipher(&req.wrapped_user_key, sec::KEY_CIPHER_MAX, "clé utilisateur")?;
    let new_key = sec::key32(&req.auth_key, "Nouvelle preuve")?;
    let uid = user.id.clone();
    let current: KdfParams = state
        .db
        .read(move |c| {
            let k: String = c.query_row("SELECT kdf FROM users WHERE id = ?1", [uid], |r| r.get(0))?;
            serde_json::from_str(&k).map_err(|_| ApiError::internal("paramètres KDF illisibles"))
        })
        .await?;
    if req.kdf.m_kib < current.m_kib || req.kdf.t < current.t || req.kdf.p < current.p {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "kdf_too_weak",
            "Les nouveaux paramètres de protection ne peuvent pas être plus faibles que les actuels.",
        ));
    }
    let verified = sec::check_password_proof(&state, &user.id, &req.current_auth_key, sec::wrong_password).await?;
    let hash = hash_secret(new_key).await?;
    let kdf = serde_json::to_string(&req.kdf).map_err(|_| ApiError::internal("kdf"))?;
    let details = format!("{} Mio, {} passes, {} voie(s)", req.kdf.m_kib / 1024, req.kdf.t, req.kdf.p);
    Ok(Json(
        state
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                update_secret(&tx, &user.id, &verified, &hash, &kdf, &req.wrapped_user_key)?;
                audit_user(&tx, &user, "login.kdf_upgraded", "", &details)?;
                let profile = load_profile_with(&tx, &eff, &user.id)?;
                tx.commit()?;
                Ok(profile)
            })
            .await?,
    ))
}

// ------------------------------------------------------------ Export

/// Corps de `POST /me/export` : ce que le client s'apprête à exporter.
#[derive(Deserialize)]
pub struct ExportBody {
    scope: String,
    #[serde(default)]
    items: u64,
    #[serde(default)]
    attachments: bool,
    format: String,
}

/// `POST /me/export` : autorise et journalise l'export d'un coffre (le
/// déchiffrement se fait sur le poste). Export désactivé : 403
/// `export_disabled` ; jeton de réauthentification « vault.export » exigé.
pub async fn record_export(
    State(state): State<AppState>,
    user: AuthUser,
    headers: HeaderMap,
    Json(req): Json<ExportBody>,
) -> ApiResult<StatusCode> {
    let eff = state.effective().await?;
    if !eff.bool("export.enabled") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "export_disabled",
            "Votre organisation a désactivé l'export des coffres.",
        ));
    }
    if !["all", "personal", "shared"].contains(&req.scope.as_str()) {
        return Err(ApiError::bad_request("Portée d'export inconnue."));
    }
    if !["locksy", "csv"].contains(&req.format.as_str()) {
        return Err(ApiError::bad_request("Format d'export inconnu."));
    }
    sec::require_step_up(&state, &user, &headers, "vault.export").await?;
    let details = format!(
        "portée : {}, format : {}, {} élément(s), pièces jointes : {}",
        req.scope,
        req.format,
        req.items,
        if req.attachments { "oui" } else { "non" }
    );
    state.db.call(move |c| audit_user(c, &user, "vault.exported", "", &details)).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ------------------------------------------------------------ 2FA

pub async fn totp_setup(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<TotpSetupResponse>> {
    let eff = state.effective().await?;
    let issuer = match eff.str("branding.totp_issuer").trim() {
        "" => "Locksy",
        s => s,
    };
    let secret = totp::generate_secret();
    let uri = totp::provisioning_uri(&secret, &user.email, issuer);
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

/// Réponse de `POST /me/2fa/enable` : le profil, plus les codes de secours
/// générés à l'activation (affichés une seule fois).
#[derive(Serialize)]
pub struct TotpEnabled {
    #[serde(flatten)]
    profile: Profile,
    recovery_codes: Vec<String>,
}

pub async fn totp_enable(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<TotpCodeRequest>,
) -> ApiResult<Json<TotpEnabled>> {
    let key = format!("totp:{}", user.id);
    let ctx = SecCtx::of(&state).await?;
    // Tentative comptée avant la vérification ; annulée si la demande n'est
    // pas un essai de code (aucun secret en attente).
    state.limiter.attempt(&key, 5)?;
    let limiter = state.limiter.clone();
    Ok(Json(
        state
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                let pending: Option<String> =
                    tx.query_row("SELECT totp_pending FROM users WHERE id = ?1", [&user.id], |r| r.get(0))?;
                let Some(pending) = pending else {
                    limiter.release(&key);
                    return Err(ApiError::bad_request("Commencez par générer un nouveau secret."));
                };
                let secret = decrypt_totp_secret(&ctx.server_key, &user.id, &pending)?;
                let Some(step) = totp::verify(&secret, &req.code, now_unix() as u64, None) else {
                    return Err(ApiError::bad_request("Code incorrect. Vérifiez l'heure de votre téléphone."));
                };
                limiter.success(&key);
                tx.execute(
                    "UPDATE users SET totp_secret = totp_pending, totp_pending = NULL, totp_last_step = ?1 WHERE id = ?2",
                    params![step as i64, user.id],
                )?;
                let (recovery_codes, _) = replace_recovery_codes(&tx, &ctx.server_key, &user.id)?;
                audit_user(&tx, &user, "2fa.enabled", "", &format!("{} codes de secours générés", recovery_codes.len()))?;
                ctx.notify(&tx, &user.id, "2fa.enabled")?;
                let profile = load_profile_with(&tx, &ctx.eff, &user.id)?;
                tx.commit()?;
                Ok(TotpEnabled { profile, recovery_codes })
            })
            .await?,
    ))
}

/// Corps de `POST /me/2fa/disable` : le code est facultatif quand la demande
/// porte un jeton « totp.disable ».
#[derive(Deserialize)]
pub struct TotpDisableBody {
    #[serde(default)]
    code: String,
}

/// `POST /me/2fa/disable` : interdit si l'organisation impose la 2FA au
/// compte (403). Confirmation par un jeton « totp.disable »
/// (`X-Locksy-Reauth`) ou, à défaut, par un code (TOTP ou code de secours).
/// Les codes de secours sont supprimés.
pub async fn totp_disable(
    State(state): State<AppState>,
    user: AuthUser,
    headers: HeaderMap,
    Json(req): Json<TotpDisableBody>,
) -> ApiResult<Json<Profile>> {
    let ctx = SecCtx::of(&state).await?;
    // Règle du registre : organisation entière ou rôle listé.
    if twofa_applies(&ctx.eff, &user.role) {
        return Err(ApiError::forbidden("Votre organisation impose la double authentification."));
    }
    if !has_totp(&state, &user.id).await? {
        return Err(totp_not_enabled());
    }
    let code = if has_reauth(&headers) {
        sec::require_step_up(&state, &user, &headers, "totp.disable").await?;
        None
    } else {
        Some(factor_attempt(&state, &user.id, Some(&req.code))?)
    };
    let (u, with_code) = (user.clone(), code.is_some());
    let res = state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            if let Some(code) = &code {
                take_second_factor(&tx, &ctx, &u.id, &u.email, &u.meta, code)?;
            }
            tx.execute(
                "UPDATE users SET totp_secret = NULL, totp_pending = NULL, totp_last_step = NULL WHERE id = ?1",
                [&u.id],
            )?;
            clear_recovery_codes(&tx, &u.id)?;
            audit_user(&tx, &u, "2fa.disabled", "", "")?;
            ctx.notify(&tx, &u.id, "2fa.disabled")?;
            let profile = load_profile_with(&tx, &ctx.eff, &u.id)?;
            tx.commit()?;
            Ok(profile)
        })
        .await;
    if with_code {
        settle_factor(&state, &user.id, &res);
    }
    res.map(Json)
}

/// Double authentification inactive : rien à retirer ni à régénérer (409).
fn totp_not_enabled() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        "totp_not_enabled",
        "La double authentification n'est pas activée sur ce compte. Activez-la d'abord.",
    )
}

// ------------------------------------------------------------ Codes de secours

/// Remplace les codes de secours d'un compte par une nouvelle série ;
/// renvoie les codes en clair (affichés une seule fois) et leur date.
pub(crate) fn replace_recovery_codes(
    c: &Connection,
    server_key: &SecretKey,
    user_id: &str,
) -> ApiResult<(Vec<String>, i64)> {
    let codes = sec::new_recovery_codes();
    let now = now_unix();
    c.execute("DELETE FROM totp_recovery_codes WHERE user_id = ?1", [user_id])?;
    for code in &codes {
        c.execute(
            "INSERT INTO totp_recovery_codes (id, user_id, code_hash, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![new_uuid(), user_id, sec::recovery_code_hash(server_key, user_id, code), now],
        )?;
    }
    c.execute("UPDATE users SET totp_recovery_generated_at = ?1 WHERE id = ?2", params![now, user_id])?;
    Ok((codes, now))
}

/// Supprime les codes de secours d'un compte (2FA retirée).
pub(crate) fn clear_recovery_codes(c: &Connection, user_id: &str) -> ApiResult<()> {
    c.execute("DELETE FROM totp_recovery_codes WHERE user_id = ?1", [user_id])?;
    c.execute("UPDATE users SET totp_recovery_generated_at = NULL WHERE id = ?1", [user_id])?;
    Ok(())
}

/// Consomme un code de secours d'un compte doté de la 2FA. Toutes les
/// empreintes inutilisées sont comparées en temps constant. Renvoie le
/// nombre de codes restants, ou `None` si le code est inconnu ou déjà utilisé.
pub(crate) fn consume_recovery_code(
    c: &Connection,
    server_key: &SecretKey,
    user_id: &str,
    code: &str,
) -> ApiResult<Option<i64>> {
    let given = sec::recovery_code_hash(server_key, user_id, code);
    let rows: Vec<(String, String)> = c
        .prepare(
            "SELECT r.id, r.code_hash FROM totp_recovery_codes r JOIN users u ON u.id = r.user_id
             WHERE r.user_id = ?1 AND r.used_at IS NULL AND u.totp_secret IS NOT NULL",
        )?
        .query_map([user_id], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    let mut found = None;
    for (id, hash) in &rows {
        if bool::from(hash.as_bytes().ct_eq(given.as_bytes())) {
            found = Some(id.clone());
        }
    }
    let Some(id) = found else { return Ok(None) };
    let n = c.execute(
        "UPDATE totp_recovery_codes SET used_at = ?1 WHERE id = ?2 AND used_at IS NULL",
        params![now_unix(), id],
    )?;
    if n == 0 {
        return Ok(None);
    }
    let remaining: i64 = c.query_row(
        "SELECT COUNT(*) FROM totp_recovery_codes WHERE user_id = ?1 AND used_at IS NULL",
        [user_id],
        |r| r.get(0),
    )?;
    Ok(Some(remaining))
}

/// État des codes de secours d'un compte.
#[derive(Serialize)]
pub struct RecoveryCodesStatus {
    remaining: i64,
    total: i64,
    generated_at: Option<i64>,
}

/// `GET /me/2fa/recovery-codes` : codes restants, total de la série et date
/// de génération (jamais les codes eux-mêmes).
pub async fn recovery_codes_status(
    State(state): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<RecoveryCodesStatus>> {
    Ok(Json(
        state
            .db
            .read(move |c| {
                let generated_at: Option<i64> = c
                    .query_row(
                        "SELECT totp_recovery_generated_at FROM users WHERE id = ?1 AND totp_secret IS NOT NULL",
                        [&user.id],
                        |r| r.get(0),
                    )
                    .optional()?
                    .flatten();
                let (total, remaining): (i64, i64) = match generated_at {
                    None => (0, 0),
                    Some(_) => c.query_row(
                        "SELECT COUNT(*), COALESCE(SUM(used_at IS NULL), 0)
                         FROM totp_recovery_codes WHERE user_id = ?1",
                        [&user.id],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )?,
                };
                Ok(RecoveryCodesStatus { remaining, total, generated_at })
            })
            .await?,
    ))
}

/// Nouvelle série de codes de secours.
#[derive(Serialize)]
pub struct RecoveryCodesIssued {
    codes: Vec<String>,
    generated_at: i64,
}

/// `POST /me/2fa/recovery-codes` : remplace les codes de secours (les
/// anciens ne valent plus). 2FA active (sinon 409 `totp_not_enabled`) et
/// jeton de réauthentification « totp.recovery_codes » exigés.
pub async fn regenerate_recovery_codes(
    State(state): State<AppState>,
    user: AuthUser,
    headers: HeaderMap,
) -> ApiResult<Json<RecoveryCodesIssued>> {
    if !has_totp(&state, &user.id).await? {
        return Err(totp_not_enabled());
    }
    sec::require_step_up(&state, &user, &headers, "totp.recovery_codes").await?;
    let ctx = SecCtx::of(&state).await?;
    Ok(Json(
        state
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                let (codes, generated_at) = replace_recovery_codes(&tx, &ctx.server_key, &user.id)?;
                audit_user(&tx, &user, "2fa.recovery_codes_generated", "", &format!("{} codes", codes.len()))?;
                ctx.notify(&tx, &user.id, "2fa.recovery_codes_generated")?;
                tx.commit()?;
                Ok(RecoveryCodesIssued { codes, generated_at })
            })
            .await?,
    ))
}

// ------------------------------------------------------------ Sessions

pub async fn list_sessions(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Vec<SessionView>>> {
    Ok(Json(
        state
            .db
            .read(move |c| {
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
    sec::uuid_path(&id, "Session")?;
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let n = tx.execute("DELETE FROM sessions WHERE id = ?1 AND user_id = ?2", params![id, user.id])?;
            if n == 0 {
                return Err(ApiError::not_found("Session introuvable."));
            }
            audit_user(&tx, &user, "session.revoked", &id, "")?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn my_audit(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Vec<AuditEntry>>> {
    Ok(Json(
        state
            .db
            .read(move |c| {
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
