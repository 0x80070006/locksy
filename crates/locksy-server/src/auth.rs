//! Inscription, connexion, double authentification et récupération de compte.

use crate::db;
use crate::error::{ApiError, ApiResult};
use crate::security::{self as sec, hash_secret, sha256_hex, verify_secret};
use crate::state::{audit, AppState, AuthUser, ClientMeta};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use hmac::{Hmac, Mac};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::Sha256;
use locksy_core::api::*;
use locksy_core::crypto::{self, KdfParams, SecretKey};
use locksy_core::encoding::{b64d, b64e};
use locksy_core::{aad, now_unix, totp};

pub fn load_profile(c: &Connection, user_id: &str) -> ApiResult<Profile> {
    let settings = db::load_settings(c)?;
    let p = c
        .query_row(
            "SELECT id, email, name, role, totp_secret IS NOT NULL, kdf, wrapped_user_key, public_key,
                    wrapped_private_key, created_at
             FROM users WHERE id = ?1",
            [user_id],
            |r| {
                let kdf: String = r.get(5)?;
                let totp_enabled: bool = r.get(4)?;
                Ok((
                    Profile {
                        id: r.get(0)?,
                        email: r.get(1)?,
                        name: r.get(2)?,
                        role: r.get(3)?,
                        totp_enabled,
                        must_setup_2fa: false,
                        kdf: KdfParams::with_salt(String::new()),
                        wrapped_user_key: r.get(6)?,
                        public_key: r.get(7)?,
                        wrapped_private_key: r.get(8)?,
                        created_at: r.get(9)?,
                    },
                    kdf,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| ApiError::not_found("Compte introuvable."))?;
    let (mut profile, kdf) = p;
    profile.kdf = serde_json::from_str(&kdf).map_err(|_| ApiError::internal("paramètres KDF illisibles"))?;
    profile.must_setup_2fa = settings.require_2fa && !profile.totp_enabled;
    Ok(profile)
}

pub fn create_session(c: &Connection, user_id: &str, meta: &ClientMeta, device: &str) -> ApiResult<String> {
    let settings = db::load_settings(c)?;
    let token = crypto::random_token();
    let now = now_unix();
    let device: String = if device.trim().is_empty() { meta.user_agent.clone() } else { device.to_string() };
    c.execute(
        "INSERT INTO sessions (id, token_hash, user_id, created_at, last_seen_at, expires_at, ip, device)
         VALUES (?1, ?2, ?3, ?4, ?4, ?5, ?6, ?7)",
        params![
            crypto::new_uuid(),
            sha256_hex(&token),
            user_id,
            now,
            now + settings.session_max_hours * 3600,
            meta.ip,
            device.chars().take(120).collect::<String>()
        ],
    )?;
    Ok(token)
}

fn fake_kdf(server_key: &SecretKey, email: &str) -> KdfParams {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(server_key.as_bytes()).expect("clé HMAC valide");
    mac.update(b"verrou:fake-salt:");
    mac.update(email.as_bytes());
    let out = mac.finalize().into_bytes();
    KdfParams::with_salt(b64e(&out[..16]))
}

pub fn encrypt_totp_secret(state: &AppState, user_id: &str, secret_b32: &str) -> String {
    crypto::encrypt_str(&state.server_key, secret_b32, &aad::server_totp(user_id))
}

pub fn decrypt_totp_secret(server_key: &SecretKey, user_id: &str, data: &str) -> ApiResult<Vec<u8>> {
    let b32 = crypto::decrypt_string(server_key, data, &aad::server_totp(user_id))
        .map_err(|_| ApiError::internal("secret 2FA illisible"))?;
    locksy_core::encoding::base32_decode(&b32).map_err(|_| ApiError::internal("secret 2FA illisible"))
}

// ------------------------------------------------------------ Routes publiques

pub async fn health(State(state): State<AppState>) -> ApiResult<Json<HealthResponse>> {
    let (needs_setup, sso) = state
        .db
        .call(|c| Ok((c.query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, i64>(0))? == 0, (crate::sso::public_info(c)?, crate::ldap::public_info(c)?))))
        .await?;
    let (sso, ldap) = sso;
    Ok(Json(HealthResponse { status: "ok".into(), version: env!("CARGO_PKG_VERSION").into(), needs_setup, sso, ldap }))
}

pub async fn prelogin(
    State(state): State<AppState>,
    meta: ClientMeta,
    Json(req): Json<PreloginRequest>,
) -> ApiResult<Json<PreloginResponse>> {
    state.limiter.hit(&format!("prelogin:{}", meta.ip), 60, 60)?;
    let email = sec::normalize_email(&req.email)?;
    let lookup = email.clone();
    let kdf: Option<String> = state
        .db
        .call(move |c| Ok(c.query_row("SELECT kdf FROM users WHERE email = ?1", [lookup], |r| r.get(0)).optional()?))
        .await?;
    let kdf = match kdf.and_then(|k| serde_json::from_str(&k).ok()) {
        Some(k) => k,
        None => fake_kdf(&state.server_key, &email),
    };
    Ok(Json(PreloginResponse { kdf }))
}

pub async fn invite_info(
    State(state): State<AppState>,
    meta: ClientMeta,
    Path(token): Path<String>,
) -> ApiResult<Json<InviteInfo>> {
    state.limiter.hit(&format!("invite:{}", meta.ip), 20, 60)?;
    let hash = sha256_hex(&token);
    state
        .db
        .call(move |c| {
            c.query_row(
                "SELECT email, role FROM invites WHERE token_hash = ?1 AND used_at IS NULL AND expires_at > ?2",
                params![hash, now_unix()],
                |r| Ok(InviteInfo { email: r.get(0)?, role: r.get(1)? }),
            )
            .optional()?
            .map(Json)
            .ok_or_else(|| ApiError::not_found("Invitation inconnue, expirée ou déjà utilisée."))
        })
        .await
}

pub async fn register(
    State(state): State<AppState>,
    meta: ClientMeta,
    Json(req): Json<RegisterRequest>,
) -> ApiResult<Json<LoginResponse>> {
    state.limiter.hit(&format!("register:{}", meta.ip), 10, 3600)?;
    let email = sec::normalize_email(&req.email)?;
    let name = sec::clean_name(&req.name)?;
    sec::uuid(&req.user_id, "utilisateur")?;
    sec::uuid(&req.personal_collection.id, "coffre")?;
    sec::kdf(&req.kdf)?;
    let auth_key = sec::key32(&req.auth_key, "Preuve d'authentification")?;
    let recovery_auth = sec::key32(&req.recovery_auth, "Preuve de récupération")?;
    sec::key32(&req.public_key, "Clé publique")?;
    sec::cipher(&req.wrapped_user_key, sec::KEY_CIPHER_MAX, "clé utilisateur")?;
    sec::cipher(&req.recovery_wrapped_user_key, sec::KEY_CIPHER_MAX, "clé de récupération")?;
    sec::cipher(&req.wrapped_private_key, sec::KEY_CIPHER_MAX, "clé privée")?;
    sec::cipher(&req.personal_collection.enc_name, sec::NAME_CIPHER_MAX, "nom du coffre")?;
    sec::sealed(&req.personal_collection.sealed_key)?;

    let auth_hash = hash_secret(auth_key).await?;
    let recovery_hash = hash_secret(recovery_auth).await?;
    let kdf_json = serde_json::to_string(&req.kdf).map_err(|_| ApiError::internal("kdf"))?;
    let invite_hash = req.invite_token.as_deref().filter(|t| !t.is_empty()).map(sha256_hex);
    let sso_ticket = req.sso_ticket.clone().filter(|t| !t.is_empty());
    let meta2 = meta.clone();

    let resp = state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let now = now_unix();
            let users: i64 = tx.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
            let mut sso_subject: Option<String> = None;
            let role = if users == 0 {
                roles::OWNER.to_string()
            } else if let (None, Some(ticket)) = (&invite_hash, &sso_ticket) {
                let t = crate::sso::take_ticket(&tx, ticket, &email)?;
                if t.user_id.is_some() {
                    return Err(ApiError::conflict("Un compte existe déjà pour cette identité. Connectez-vous."));
                }
                if !crate::sso::may_self_register(&tx, &email)? {
                    return Err(ApiError::forbidden(
                        "Votre compte n'a pas été ouvert dans Locksy par l'annuaire. Demandez une invitation à votre administrateur.",
                    ));
                }
                sso_subject = Some(t.subject);
                roles::USER.to_string()
            } else {
                let Some(hash) = invite_hash else {
                    return Err(ApiError::forbidden("L'inscription se fait uniquement sur invitation."));
                };
                let invite: Option<(String, String)> = tx
                    .query_row(
                        "SELECT id, role FROM invites
                         WHERE token_hash = ?1 AND email = ?2 AND used_at IS NULL AND expires_at > ?3",
                        params![hash, email, now],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                let Some((invite_id, role)) = invite else {
                    return Err(ApiError::forbidden(
                        "Invitation invalide, expirée, déjà utilisée ou destinée à une autre adresse.",
                    ));
                };
                tx.execute("UPDATE invites SET used_at = ?1 WHERE id = ?2", params![now, invite_id])?;
                role
            };
            let exists: bool =
                tx.query_row("SELECT COUNT(*) FROM users WHERE email = ?1 OR id = ?2", params![email, req.user_id], |r| {
                    r.get::<_, i64>(0)
                })? > 0;
            if exists {
                return Err(ApiError::conflict("Un compte existe déjà avec cette adresse."));
            }
            tx.execute(
                "INSERT INTO users (id, email, name, role, kdf, auth_hash, wrapped_user_key,
                    recovery_wrapped_user_key, recovery_auth_hash, public_key, wrapped_private_key,
                    created_at, updated_at, last_login_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12, ?12)",
                params![
                    req.user_id,
                    email,
                    name,
                    role,
                    kdf_json,
                    auth_hash,
                    req.wrapped_user_key,
                    req.recovery_wrapped_user_key,
                    recovery_hash,
                    req.public_key,
                    req.wrapped_private_key,
                    now
                ],
            )?;
            tx.execute("UPDATE users SET sso_subject = ?1 WHERE id = ?2", params![sso_subject, req.user_id])?;
            tx.execute("UPDATE directory_users SET user_id = ?1, updated_at = ?2 WHERE email = ?3", params![req.user_id, now, email])?;
            tx.execute(
                "INSERT INTO collections (id, enc_name, personal, created_by, created_at, updated_at)
                 VALUES (?1, ?2, 1, ?3, ?4, ?4)",
                params![req.personal_collection.id, req.personal_collection.enc_name, req.user_id, now],
            )?;
            tx.execute(
                "INSERT INTO memberships (collection_id, user_id, role, sealed_key, created_at)
                 VALUES (?1, ?2, 'manager', ?3, ?4)",
                params![req.personal_collection.id, req.user_id, req.personal_collection.sealed_key, now],
            )?;
            audit(&tx, Some(&req.user_id), &email, "account.created", &email, &meta2, &format!("rôle : {role}"))?;
            let token = create_session(&tx, &req.user_id, &meta2, "")?;
            let profile = load_profile(&tx, &req.user_id)?;
            tx.commit()?;
            Ok(LoginResponse { token, profile })
        })
        .await?;
    Ok(Json(resp))
}

pub async fn login(
    State(state): State<AppState>,
    meta: ClientMeta,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    let email = sec::normalize_email(&req.email)?;
    let email_key = format!("login-email:{email}");
    let ip_key = format!("login-ip:{}", meta.ip);
    state.limiter.check(&email_key)?;
    state.limiter.check(&ip_key)?;
    let auth_key = b64d(&req.auth_key).map_err(|_| ApiError::bad_request("Preuve d'authentification invalide."))?;

    let lookup = email.clone();
    let (row, (sso_cfg, ldap_cfg)): (Option<(String, String, bool, Option<String>, Option<i64>, String)>, (SsoConfig, LdapConfig)) = state
        .db
        .call(move |c| {
            let row = c
                .query_row(
                    "SELECT id, auth_hash, disabled, totp_secret, totp_last_step, role FROM users WHERE email = ?1",
                    [lookup],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
                )
                .optional()?;
            Ok((row, (crate::sso::load_config(c)?, crate::ldap::load_config(c)?)))
        })
        .await?;

    let hash = row.as_ref().map(|r| r.1.clone()).unwrap_or_else(|| state.dummy_hash.to_string());
    let valid = verify_secret(auth_key, hash).await && row.is_some();
    let fail_meta = meta.clone();
    if !valid {
        state.limiter.fail(&email_key, 5);
        state.limiter.fail(&ip_key, 20);
        let e = email.clone();
        state.db.call(move |c| audit(c, None, &e, "login.failed", &e, &fail_meta, "mot de passe incorrect")).await?;
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "Adresse e-mail ou mot de passe maître incorrect.",
        ));
    }
    let (user_id, _, disabled, totp_secret, last_step, role) = row.expect("vérifié ci-dessus");
    if disabled {
        let (e, u) = (email.clone(), user_id.clone());
        state.db.call(move |c| audit(c, Some(&u), &e, "login.refused", &e, &fail_meta, "compte désactivé")).await?;
        return Err(ApiError::new(StatusCode::FORBIDDEN, "account_disabled", "Ce compte est désactivé."));
    }
    // Ticket SSO : vérifié ici, consommé à la création de la session.
    let sso_ticket = req.sso_ticket.clone().filter(|t| !t.is_empty());
    if let Some(t) = &sso_ticket {
        let (t, e, u) = (t.clone(), email.clone(), user_id.clone());
        state
            .db
            .call(move |c| {
                let hash = sha256_hex(&t);
                let ok: bool = c
                    .query_row(
                        "SELECT COUNT(*) FROM sso_tickets WHERE ticket_hash = ?1 AND used = 0 AND expires_at > ?2 AND email = ?3 AND user_id = ?4",
                        params![hash, now_unix(), e, u],
                        |r| r.get::<_, i64>(0),
                    )? > 0;
                if ok { Ok(()) } else { Err(ApiError::unauthorized("Connexion SSO expirée. Recommencez.")) }
            })
            .await?;
    } else if role != roles::OWNER {
        if ldap_cfg.allow_login && ldap_cfg.enforce {
            return Err(crate::sso::sso_required_error(&ldap_cfg.label));
        }
        if sso_cfg.enabled && sso_cfg.enforce {
            return Err(crate::sso::sso_required_error(&sso_cfg.label));
        }
    }
    let mut new_step = None;
    // Avec le SSO, la double authentification est assurée par le fournisseur d'identité.
    if let Some(enc) = totp_secret.filter(|_| sso_ticket.is_none()) {
        let Some(code) = req.totp.as_deref().filter(|c| !c.trim().is_empty()) else {
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "totp_required",
                "Saisissez le code de votre application d'authentification.",
            ));
        };
        let secret = decrypt_totp_secret(&state.server_key, &user_id, &enc)?;
        match totp::verify(&secret, code, now_unix() as u64, last_step.map(|s| s as u64)) {
            Some(step) => new_step = Some(step as i64),
            None => {
                state.limiter.fail(&email_key, 5);
                let (e, u) = (email.clone(), user_id.clone());
                state.db.call(move |c| audit(c, Some(&u), &e, "login.failed", &e, &fail_meta, "code 2FA incorrect")).await?;
                return Err(ApiError::new(StatusCode::UNAUTHORIZED, "invalid_totp", "Code de double authentification incorrect."));
            }
        }
    }
    state.limiter.success(&email_key);
    state.limiter.success(&ip_key);
    let device = req.device.unwrap_or_default();
    let resp = state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let now = now_unix();
            tx.execute(
                "UPDATE users SET last_login_at = ?1, totp_last_step = COALESCE(?2, totp_last_step) WHERE id = ?3",
                params![now, new_step, user_id],
            )?;
            if let Some(t) = &sso_ticket {
                crate::sso::take_ticket(&tx, t, &email)?;
            }
            let token = create_session(&tx, &user_id, &meta, &device)?;
            let how = if sso_ticket.is_some() { format!("{device} (SSO)") } else { device.clone() };
            audit(&tx, Some(&user_id), &email, "login.success", &email, &meta, &how)?;
            let profile = load_profile(&tx, &user_id)?;
            tx.commit()?;
            Ok(LoginResponse { token, profile })
        })
        .await?;
    Ok(Json(resp))
}

pub async fn logout(State(state): State<AppState>, user: AuthUser) -> ApiResult<StatusCode> {
    state
        .db
        .call(move |c| {
            c.execute("DELETE FROM sessions WHERE id = ?1", [&user.session_id])?;
            crate::state::audit_user(c, &user, "logout", "", "")
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn recover_start(
    State(state): State<AppState>,
    meta: ClientMeta,
    Json(req): Json<RecoverStartRequest>,
) -> ApiResult<Json<RecoverStartResponse>> {
    let email = sec::normalize_email(&req.email)?;
    let key = format!("recover:{email}");
    state.limiter.check(&key)?;
    state.limiter.hit(&format!("recover-ip:{}", meta.ip), 10, 3600)?;
    let proof = b64d(&req.recovery_auth).map_err(|_| ApiError::bad_request("Clé de récupération invalide."))?;
    let lookup = email.clone();
    let row: Option<(String, String, String, bool)> = state
        .db
        .call(move |c| {
            Ok(c.query_row(
                "SELECT id, recovery_auth_hash, recovery_wrapped_user_key, disabled FROM users WHERE email = ?1",
                [lookup],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?)
        })
        .await?;
    let hash = row.as_ref().map(|r| r.1.clone()).unwrap_or_else(|| state.dummy_hash.to_string());
    let valid = verify_secret(proof, hash).await && row.as_ref().is_some_and(|r| !r.3);
    if !valid {
        state.limiter.fail(&key, 5);
        let e = email.clone();
        state.db.call(move |c| audit(c, None, &e, "recovery.failed", &e, &meta, "")).await?;
        return Err(ApiError::unauthorized("Adresse ou clé de récupération incorrecte."));
    }
    state.limiter.success(&key);
    let (user_id, _, wrapped, _) = row.expect("vérifié ci-dessus");
    let token = crypto::random_token();
    let hash = sha256_hex(&token);
    let uid = user_id.clone();
    state
        .db
        .call(move |c| {
            c.execute("DELETE FROM recovery_tokens WHERE user_id = ?1", [&uid])?;
            c.execute(
                "INSERT INTO recovery_tokens (token_hash, user_id, expires_at) VALUES (?1, ?2, ?3)",
                params![hash, uid, now_unix() + 600],
            )?;
            audit(c, Some(&uid), &email, "recovery.started", &email, &meta, "")
        })
        .await?;
    Ok(Json(RecoverStartResponse { recovery_token: token, user_id, recovery_wrapped_user_key: wrapped }))
}

pub async fn recover_finish(
    State(state): State<AppState>,
    meta: ClientMeta,
    Json(req): Json<RecoverFinishRequest>,
) -> ApiResult<StatusCode> {
    sec::kdf(&req.kdf)?;
    sec::cipher(&req.wrapped_user_key, sec::KEY_CIPHER_MAX, "clé utilisateur")?;
    let auth_hash = hash_secret(sec::key32(&req.auth_key, "Preuve d'authentification")?).await?;
    let kdf_json = serde_json::to_string(&req.kdf).map_err(|_| ApiError::internal("kdf"))?;
    let token_hash = sha256_hex(&req.recovery_token);
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let user: Option<(String, String)> = tx
                .query_row(
                    "SELECT t.user_id, u.email FROM recovery_tokens t JOIN users u ON u.id = t.user_id
                     WHERE t.token_hash = ?1 AND t.expires_at > ?2",
                    params![token_hash, now_unix()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((uid, email)) = user else {
                return Err(ApiError::unauthorized("Procédure de récupération expirée. Recommencez."));
            };
            tx.execute(
                "UPDATE users SET auth_hash = ?1, kdf = ?2, wrapped_user_key = ?3, updated_at = ?4 WHERE id = ?5",
                params![auth_hash, kdf_json, req.wrapped_user_key, now_unix(), uid],
            )?;
            tx.execute("DELETE FROM recovery_tokens WHERE user_id = ?1", [&uid])?;
            tx.execute("DELETE FROM sessions WHERE user_id = ?1", [&uid])?;
            audit(&tx, Some(&uid), &email, "recovery.completed", &email, &meta, "mot de passe maître remplacé")?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
