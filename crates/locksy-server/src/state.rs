use crate::db::{self, Db};
use crate::error::{ApiError, ApiResult};
use crate::security::{sha256_hex, Limiter};
use axum::async_trait;
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::StatusCode;
use rusqlite::{params, Connection, OptionalExtension};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use locksy_core::api::roles;
use locksy_core::crypto::SecretKey;
use locksy_core::now_unix;

pub struct Config {
    pub bind: String,
    pub data_dir: PathBuf,
    pub web_dir: PathBuf,
    pub trust_proxy: bool,
}

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    /// Clé du serveur : protège les secrets 2FA au repos et dérive les sels
    /// factices qui empêchent de deviner quels comptes existent.
    pub server_key: Arc<SecretKey>,
    pub limiter: Arc<Limiter>,
    pub config: Arc<Config>,
    /// Empreinte Argon2id factice : une connexion sur un compte inexistant
    /// prend le même temps qu'une vraie.
    pub dummy_hash: Arc<String>,
    /// État du SSO : demandes en cours, découverte et clés du fournisseur.
    pub sso: Arc<crate::sso::SsoRuntime>,
}

// ------------------------------------------------------------ Contexte client

#[derive(Clone, Debug)]
pub struct ClientMeta {
    pub ip: String,
    pub user_agent: String,
}

fn truncate(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

#[async_trait]
impl FromRequestParts<AppState> for ClientMeta {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        let forwarded = if state.config.trust_proxy {
            parts
                .headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
                .map(|v| v.trim().to_string())
        } else {
            None
        };
        let ip = forwarded
            .or_else(|| parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip().to_string()))
            .unwrap_or_else(|| "inconnue".into());
        let ua = parts.headers.get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("");
        Ok(ClientMeta { ip: truncate(&ip, 64), user_agent: truncate(ua, 200) })
    }
}

// ------------------------------------------------------------ Utilisateur connecté

#[derive(Clone, Debug)]
pub struct AuthUser {
    pub id: String,
    pub email: String,
    pub role: String,
    pub session_id: String,
    pub meta: ClientMeta,
}

impl AuthUser {
    pub fn is_admin(&self) -> bool {
        self.role == roles::OWNER || self.role == roles::ADMIN
    }
}

#[async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        let meta = ClientMeta::from_request_parts(parts, state).await?;
        let token = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim)
            .filter(|t| !t.is_empty() && t.len() <= 128)
            .ok_or_else(|| ApiError::unauthorized("Connexion requise."))?;
        let hash = sha256_hex(token);
        let path = parts.uri.path().to_string();
        state
            .db
            .call(move |c| {
                let row = c
                    .query_row(
                        "SELECT s.id, s.user_id, s.last_seen_at, s.expires_at, u.email, u.role, u.disabled,
                                u.totp_secret IS NOT NULL
                         FROM sessions s JOIN users u ON u.id = s.user_id
                         WHERE s.token_hash = ?1",
                        [&hash],
                        |r| {
                            Ok((
                                r.get::<_, String>(0)?,
                                r.get::<_, String>(1)?,
                                r.get::<_, i64>(2)?,
                                r.get::<_, i64>(3)?,
                                r.get::<_, String>(4)?,
                                r.get::<_, String>(5)?,
                                r.get::<_, bool>(6)?,
                                r.get::<_, bool>(7)?,
                            ))
                        },
                    )
                    .optional()?;
                let Some((sid, uid, last_seen, expires, email, role, disabled, totp)) = row else {
                    return Err(ApiError::unauthorized("Session expirée. Reconnectez-vous."));
                };
                let settings = db::load_settings(c)?;
                let now = now_unix();
                if disabled || expires < now || now - last_seen > settings.session_idle_minutes * 60 {
                    c.execute("DELETE FROM sessions WHERE id = ?1", [&sid])?;
                    return Err(ApiError::unauthorized("Session expirée. Reconnectez-vous."));
                }
                if now - last_seen > 30 {
                    c.execute("UPDATE sessions SET last_seen_at = ?1 WHERE id = ?2", params![now, sid])?;
                }
                let allowed_without_2fa = path.starts_with("/api/me") || path == "/api/auth/logout";
                if settings.require_2fa && !totp && !allowed_without_2fa {
                    return Err(ApiError::new(
                        StatusCode::FORBIDDEN,
                        "2fa_required",
                        "Votre organisation impose la double authentification. Activez-la dans vos paramètres.",
                    ));
                }
                Ok(AuthUser { id: uid, email, role, session_id: sid, meta })
            })
            .await
    }
}

/// Utilisateur connecté avec le rôle propriétaire ou administrateur.
#[derive(Clone, Debug)]
pub struct AdminUser(pub AuthUser);

#[async_trait]
impl FromRequestParts<AppState> for AdminUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        let user = AuthUser::from_request_parts(parts, state).await?;
        if !user.is_admin() {
            return Err(ApiError::forbidden("Réservé aux administrateurs."));
        }
        Ok(AdminUser(user))
    }
}

// ------------------------------------------------------------ Journal d'audit

pub fn audit(
    c: &Connection,
    user_id: Option<&str>,
    email: &str,
    action: &str,
    target: &str,
    meta: &ClientMeta,
    details: &str,
) -> ApiResult<()> {
    let at = now_unix();
    c.execute(
        "INSERT INTO audit (at, user_id, email, action, target, ip, user_agent, details)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![at, user_id, email, action, target, meta.ip, meta.user_agent, details],
    )?;
    crate::syslog::emit(at, user_id, email, action, target, &meta.ip, &meta.user_agent, details);
    Ok(())
}

pub fn audit_user(c: &Connection, user: &AuthUser, action: &str, target: &str, details: &str) -> ApiResult<()> {
    audit(c, Some(&user.id), &user.email, action, target, &user.meta, details)
}
