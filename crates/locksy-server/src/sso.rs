//! Connexion unique OpenID Connect (Entra ID, Okta, Google, Keycloak, ADFS…).
//!
//! Flux « authorization code » avec PKCE (S256), `state` et `nonce` à usage
//! unique ; le jeton d'identité est vérifié (signature via les clés publiées
//! par le fournisseur, émetteur, audience, expiration, nonce). Le serveur
//! remet ensuite un ticket à usage unique de 5 minutes.
//!
//! Le SSO prouve l'identité ; il ne remplace pas le mot de passe maître, seul
//! capable de déchiffrer le coffre (chiffrement de bout en bout).

use crate::db;
use crate::error::{ApiError, ApiResult};
use crate::security::sha256_hex;
use crate::state::{audit, audit_user, AdminUser, AppState, ClientMeta};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Redirect;
use axum::Json;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use locksy_core::api::*;
use locksy_core::crypto::{self, KdfParams};
use locksy_core::encoding::{b64e, percent_encode};
use locksy_core::now_unix;

const SETTINGS_KEY: &str = "sso";
const PENDING_TTL: Duration = Duration::from_secs(600);
const TICKET_TTL: i64 = 300;

// ------------------------------------------------------------ Configuration

pub fn load_config(c: &Connection) -> ApiResult<SsoConfig> {
    let mut cfg: SsoConfig = db::load_json(c, SETTINGS_KEY)?;
    if cfg.public_url.is_empty() {
        cfg.public_url = "http://localhost:8743".into();
    }
    if cfg.label.is_empty() {
        cfg.label = "SSO de l'entreprise".into();
    }
    cfg.has_secret = !cfg.client_secret.is_empty();
    cfg.redirect_uri = format!("{}/api/sso/callback", cfg.public_url.trim_end_matches('/'));
    Ok(cfg)
}

pub fn public_info(c: &Connection) -> ApiResult<Option<SsoPublic>> {
    let cfg = load_config(c)?;
    Ok(cfg.enabled.then(|| SsoPublic { label: cfg.label, enforced: cfg.enforce }))
}

fn allow_http() -> bool {
    std::env::var("LOCKSY_SSO_ALLOW_HTTP").map(|v| v == "true").unwrap_or(false)
}

fn check_url(url: &str, what: &str) -> ApiResult<()> {
    let u = url::Url::parse(url).map_err(|_| ApiError::bad_request(format!("{what} : adresse invalide.")))?;
    match u.scheme() {
        "https" => Ok(()),
        "http" if allow_http() => Ok(()),
        _ => Err(ApiError::bad_request(format!("{what} : une adresse https:// est obligatoire."))),
    }
}

// ------------------------------------------------------------ Découverte et clés

#[derive(Deserialize, Clone)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

enum ReturnTo {
    Web,
    Desktop(u16),
    Extension(String),
}

struct Pending {
    nonce: String,
    verifier: String,
    return_to: ReturnTo,
    created: Instant,
}

pub struct SsoRuntime {
    http: reqwest::Client,
    pending: Mutex<HashMap<String, Pending>>,
    discovery: Mutex<Option<(String, Instant, Discovery)>>,
    jwks: Mutex<Option<(String, Instant, JwkSet)>>,
}

impl Default for SsoRuntime {
    fn default() -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::limited(3))
                .user_agent(concat!("Locksy/", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("client HTTP"),
            pending: Mutex::new(HashMap::new()),
            discovery: Mutex::new(None),
            jwks: Mutex::new(None),
        }
    }
}

impl SsoRuntime {
    async fn discover(&self, issuer: &str) -> ApiResult<Discovery> {
        if let Some((iss, at, d)) = self.discovery.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            if iss == issuer && at.elapsed() < Duration::from_secs(3600) {
                return Ok(d.clone());
            }
        }
        let url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
        let d: Discovery = self
            .http
            .get(&url)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| ApiError::bad_request(format!("Fournisseur d'identité injoignable ({e}).")))?
            .json()
            .await
            .map_err(|_| ApiError::bad_request("Document de découverte OpenID illisible."))?;
        if d.issuer.trim_end_matches('/') != issuer.trim_end_matches('/') {
            return Err(ApiError::bad_request(format!(
                "L'émetteur annoncé ({}) ne correspond pas à celui configuré.",
                d.issuer
            )));
        }
        for (u, what) in [(&d.authorization_endpoint, "Point d'autorisation"), (&d.token_endpoint, "Point de jeton"), (&d.jwks_uri, "Clés publiques")] {
            check_url(u, what)?;
        }
        *self.discovery.lock().unwrap_or_else(|p| p.into_inner()) = Some((issuer.to_string(), Instant::now(), d.clone()));
        Ok(d)
    }

    async fn keys(&self, jwks_uri: &str, force: bool) -> ApiResult<JwkSet> {
        if !force {
            if let Some((uri, at, k)) = self.jwks.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
                if uri == jwks_uri && at.elapsed() < Duration::from_secs(3600) {
                    return Ok(k.clone());
                }
            }
        }
        let k: JwkSet = self
            .http
            .get(jwks_uri)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|_| ApiError::bad_request("Clés publiques du fournisseur injoignables."))?
            .json()
            .await
            .map_err(|_| ApiError::bad_request("Clés publiques du fournisseur illisibles."))?;
        *self.jwks.lock().unwrap_or_else(|p| p.into_inner()) = Some((jwks_uri.to_string(), Instant::now(), k.clone()));
        Ok(k)
    }

    fn put_pending(&self, state: String, p: Pending) {
        let mut map = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        map.retain(|_, v| v.created.elapsed() < PENDING_TTL);
        if map.len() < 10_000 {
            map.insert(state, p);
        }
    }

    fn take_pending(&self, state: &str) -> Option<Pending> {
        let mut map = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        map.remove(state).filter(|p| p.created.elapsed() < PENDING_TTL)
    }
}

// ------------------------------------------------------------ Démarrage du flux

#[derive(Deserialize)]
pub struct StartQuery {
    #[serde(default)]
    target: String,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    redirect: Option<String>,
}

fn extension_redirect_ok(r: &str) -> bool {
    url::Url::parse(r).is_ok_and(|u| {
        u.scheme() == "https"
            && u.port().is_none()
            && u.host_str().is_some_and(|h| h.ends_with(".chromiumapp.org") && h.len() > ".chromiumapp.org".len())
    })
}

pub async fn start(State(state): State<AppState>, meta: ClientMeta, Query(q): Query<StartQuery>) -> ApiResult<Redirect> {
    state.limiter.hit(&format!("sso-start:{}", meta.ip), 30, 60)?;
    let cfg = state.db.call(|c| load_config(c)).await?;
    if !cfg.enabled || cfg.issuer.is_empty() || cfg.client_id.is_empty() {
        return Err(ApiError::not_found("La connexion unique n'est pas configurée."));
    }
    let return_to = match q.target.as_str() {
        "desktop" => ReturnTo::Desktop(q.port.filter(|p| *p >= 1024).ok_or_else(|| ApiError::bad_request("Port local invalide."))?),
        "extension" => {
            let r = q.redirect.filter(|r| extension_redirect_ok(r)).ok_or_else(|| ApiError::bad_request("Redirection d'extension refusée."))?;
            ReturnTo::Extension(r)
        }
        _ => ReturnTo::Web,
    };
    let d = state.sso.discover(&cfg.issuer).await?;
    let st = crypto::random_token();
    let nonce = crypto::random_token();
    let verifier = crypto::random_token();
    let challenge = b64e(&Sha256::digest(verifier.as_bytes()));
    let mut url = url::Url::parse(&d.authorization_endpoint).map_err(|_| ApiError::internal("point d'autorisation"))?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &cfg.client_id)
        .append_pair("redirect_uri", &cfg.redirect_uri)
        .append_pair("scope", "openid email profile")
        .append_pair("state", &st)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("prompt", "select_account");
    state.sso.put_pending(st, Pending { nonce, verifier, return_to, created: Instant::now() });
    Ok(Redirect::to(url.as_str()))
}

// ------------------------------------------------------------ Retour du fournisseur

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

#[derive(Deserialize)]
struct Claims {
    sub: String,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<serde_json::Value>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    upn: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

fn finish_url(cfg: &SsoConfig, to: &ReturnTo, result: Result<String, String>) -> String {
    let (key, value) = match &result {
        Ok(t) => ("ticket", t.as_str()),
        Err(e) => ("error", e.as_str()),
    };
    let value = percent_encode(value);
    match to {
        ReturnTo::Web => format!("{}/#/sso?{key}={value}", cfg.public_url.trim_end_matches('/')),
        ReturnTo::Desktop(port) => format!("http://127.0.0.1:{port}/sso?{key}={value}"),
        ReturnTo::Extension(r) => format!("{}#{key}={value}", r.split('#').next().unwrap_or(r)),
    }
}

pub async fn callback(State(state): State<AppState>, meta: ClientMeta, Query(q): Query<CallbackQuery>) -> Redirect {
    let cfg = match state.db.call(|c| load_config(c)).await {
        Ok(c) => c,
        Err(e) => return Redirect::to(&format!("/#/sso?error={}", percent_encode(&e.message))),
    };
    let Some(pending) = q.state.as_deref().and_then(|s| state.sso.take_pending(s)) else {
        return Redirect::to(&finish_url(&cfg, &ReturnTo::Web, Err("Demande de connexion expirée ou inconnue. Recommencez.".into())));
    };
    let result = match (&q.error, &q.code) {
        (Some(e), _) => Err(format!(
            "Le fournisseur d'identité a refusé la connexion : {}",
            q.error_description.clone().unwrap_or_else(|| e.clone())
        )),
        (None, Some(code)) => authenticate(&state, &cfg, &pending, code, &meta).await.map_err(|e| e.message),
        (None, None) => Err("Réponse du fournisseur incomplète.".into()),
    };
    Redirect::to(&finish_url(&cfg, &pending.return_to, result))
}

async fn authenticate(state: &AppState, cfg: &SsoConfig, pending: &Pending, code: &str, meta: &ClientMeta) -> ApiResult<String> {
    let d = state.sso.discover(&cfg.issuer).await?;
    let secret = if cfg.client_secret.is_empty() {
        String::new()
    } else {
        crypto::decrypt_string(&state.server_key, &cfg.client_secret, "verrou:v1:sso-client-secret")
            .map_err(|_| ApiError::internal("secret SSO illisible"))?
    };
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", cfg.redirect_uri.as_str()),
        ("client_id", cfg.client_id.as_str()),
        ("code_verifier", pending.verifier.as_str()),
    ];
    if !secret.is_empty() {
        form.push(("client_secret", secret.as_str()));
    }
    let resp = state
        .sso
        .http
        .post(&d.token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|_| ApiError::bad_request("Point de jeton du fournisseur injoignable."))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        tracing::warn!(%status, body = %body.chars().take(300).collect::<String>(), "échange de code SSO refusé");
        return Err(ApiError::bad_request("Le fournisseur d'identité a refusé l'échange du code (vérifiez l'identifiant client, le secret et l'URI de redirection)."));
    }
    let tokens: TokenResponse = resp.json().await.map_err(|_| ApiError::bad_request("Réponse du fournisseur sans jeton d'identité."))?;

    // Vérification du jeton d'identité.
    let header = jsonwebtoken::decode_header(&tokens.id_token).map_err(|_| ApiError::bad_request("Jeton d'identité malformé."))?;
    const ALLOWED: [Algorithm; 8] = [
        Algorithm::RS256, Algorithm::RS384, Algorithm::RS512, Algorithm::PS256,
        Algorithm::PS384, Algorithm::PS512, Algorithm::ES256, Algorithm::ES384,
    ];
    if !ALLOWED.contains(&header.alg) {
        return Err(ApiError::bad_request("Algorithme de signature refusé."));
    }
    let mut keys = state.sso.keys(&d.jwks_uri, false).await?;
    let find = |k: &JwkSet| match &header.kid {
        Some(kid) => k.find(kid).cloned(),
        None => (k.keys.len() == 1).then(|| k.keys[0].clone()),
    };
    let jwk = match find(&keys) {
        Some(j) => j,
        None => {
            keys = state.sso.keys(&d.jwks_uri, true).await?; // rotation des clés
            find(&keys).ok_or_else(|| ApiError::bad_request("Clé de signature inconnue."))?
        }
    };
    let key = DecodingKey::from_jwk(&jwk).map_err(|_| ApiError::bad_request("Clé de signature inutilisable."))?;
    let mut v = Validation::new(header.alg);
    v.set_issuer(&[d.issuer.as_str()]);
    v.set_audience(&[cfg.client_id.as_str()]);
    v.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    v.leeway = 60;
    let claims = jsonwebtoken::decode::<Claims>(&tokens.id_token, &key, &v)
        .map_err(|e| ApiError::bad_request(format!("Jeton d'identité refusé ({e}).")))?
        .claims;
    if claims.nonce.as_deref() != Some(pending.nonce.as_str()) {
        return Err(ApiError::bad_request("Jeton d'identité rejoué ou détourné (nonce invalide)."));
    }
    let verified = match &claims.email_verified {
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::String(s)) => s == "true",
        _ => true, // Entra ID n'envoie pas ce champ : l'adresse vient de l'annuaire.
    };
    if !verified {
        return Err(ApiError::forbidden("Adresse e-mail non vérifiée chez le fournisseur d'identité."));
    }
    let email = claims
        .email
        .or(claims.preferred_username)
        .or(claims.upn)
        .filter(|e| e.contains('@'))
        .ok_or_else(|| ApiError::forbidden("Le fournisseur n'a pas transmis d'adresse e-mail (ajoutez l'étendue « email »)."))?;
    let email = crate::security::normalize_email(&email)?;
    if !cfg.allowed_domains.is_empty() {
        let domain = email.rsplit('@').next().unwrap_or_default();
        if !cfg.allowed_domains.iter().any(|d| d.trim().eq_ignore_ascii_case(domain)) {
            let (e, m) = (email.clone(), meta.clone());
            state.db.call(move |c| audit(c, None, &e, "sso.denied", &e, &m, "domaine non autorisé")).await?;
            return Err(ApiError::forbidden("Votre domaine de messagerie n'est pas autorisé."));
        }
    }
    let subject = format!("{}|{}", d.issuer, claims.sub);
    let name = claims.name.unwrap_or_default();
    let meta = meta.clone();
    state.db.call(move |c| issue_ticket(c, &email, &name, &subject, &meta)).await
}

/// Retrouve ou rattache le compte de cette identité vérifiée, applique les
/// refus (compte ou annuaire désactivé) et émet un ticket à usage unique.
/// Commun au SSO OpenID Connect et à la connexion par compte Windows.
pub fn issue_ticket(c: &Connection, email: &str, name: &str, subject: &str, meta: &ClientMeta) -> ApiResult<String> {
    let (email, name, subject, meta) = (email.to_string(), name.to_string(), subject.to_string(), meta.clone());
    let by_subject: Option<(String, bool)> = c
        .query_row("SELECT id, disabled FROM users WHERE sso_subject = ?1", [&subject], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?;
    let user = match by_subject {
        Some(u) => Some(u),
        None => {
            let by_email: Option<(String, bool, Option<String>)> = c
                .query_row("SELECT id, disabled, sso_subject FROM users WHERE email = ?1", [&email], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })
                .optional()?;
            match by_email {
                Some((_, _, Some(other))) if other != subject => {
                    audit(c, None, &email, "sso.denied", &email, &meta, "compte lié à une autre identité")?;
                    return Err(ApiError::forbidden("Ce compte Locksy est lié à une autre identité SSO."));
                }
                Some((id, disabled, None)) => {
                    c.execute("UPDATE users SET sso_subject = ?1 WHERE id = ?2", params![subject, id])?;
                    Some((id, disabled))
                }
                Some((id, disabled, Some(_))) => Some((id, disabled)),
                None => None,
            }
        }
    };
    if user.as_ref().is_some_and(|u| u.1) {
        audit(c, None, &email, "sso.denied", &email, &meta, "compte désactivé")?;
        return Err(ApiError::forbidden("Ce compte est désactivé."));
    }
    let dir_inactive: bool = c
        .query_row("SELECT active = 0 FROM directory_users WHERE email = ?1", [&email], |r| r.get(0))
        .optional()?
        .unwrap_or(false);
    if dir_inactive {
        audit(c, None, &email, "sso.denied", &email, &meta, "désactivé dans l'annuaire")?;
        return Err(ApiError::forbidden("Ce compte est désactivé dans l'annuaire de l'entreprise."));
    }
    let ticket = crypto::random_token();
    c.execute("DELETE FROM sso_tickets WHERE expires_at < ?1 OR used = 1", [now_unix()])?;
    c.execute(
        "INSERT INTO sso_tickets (ticket_hash, email, name, subject, user_id, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![sha256_hex(&ticket), email, name, subject, user.as_ref().map(|u| u.0.clone()), now_unix() + TICKET_TTL],
    )?;
    audit(c, user.as_ref().map(|u| u.0.as_str()), &email, "sso.authenticated", &email, &meta, "")?;
    Ok(ticket)
}

// ------------------------------------------------------------ Tickets

pub struct Ticket {
    pub email: String,
    pub subject: String,
    pub user_id: Option<String>,
}

fn find_ticket(c: &Connection, ticket: &str) -> ApiResult<(Ticket, String)> {
    let hash = sha256_hex(ticket);
    let row: Option<(String, String, String, Option<String>)> = c
        .query_row(
            "SELECT email, name, subject, user_id FROM sso_tickets WHERE ticket_hash = ?1 AND used = 0 AND expires_at > ?2",
            params![hash, now_unix()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let (email, name, subject, user_id) = row.ok_or_else(|| ApiError::unauthorized("Connexion SSO expirée. Recommencez."))?;
    Ok((Ticket { email, subject, user_id }, name))
}

/// Vérifie puis consomme un ticket pour l'adresse donnée.
pub fn take_ticket(c: &Connection, ticket: &str, email: &str) -> ApiResult<Ticket> {
    let (t, _) = find_ticket(c, ticket)?;
    if !t.email.eq_ignore_ascii_case(email) {
        return Err(ApiError::forbidden("Ce ticket SSO appartient à une autre adresse."));
    }
    c.execute("UPDATE sso_tickets SET used = 1 WHERE ticket_hash = ?1", [sha256_hex(ticket)])?;
    Ok(t)
}

/// Un compte peut-il être créé via SSO pour cette adresse ?
pub fn may_self_register(c: &Connection, email: &str) -> ApiResult<bool> {
    let cfg = load_config(c)?;
    let provisioned: bool = c
        .query_row("SELECT active FROM directory_users WHERE email = ?1", [email], |r| r.get(0))
        .optional()?
        .unwrap_or(false);
    // Une personne poussée par l'annuaire (SCIM ou Active Directory) peut toujours
    // créer son coffre ; sans annuaire, seulement si la création SSO est permise.
    Ok(provisioned || (cfg.enabled && cfg.auto_provision))
}

pub async fn redeem(State(state): State<AppState>, meta: ClientMeta, Json(req): Json<SsoRedeemRequest>) -> ApiResult<Json<SsoRedeemResponse>> {
    state.limiter.hit(&format!("sso-redeem:{}", meta.ip), 30, 60)?;
    Ok(Json(state.db.call(move |c| redeem_info(c, &req.ticket)).await?))
}

/// Ce qu'un client doit savoir d'un ticket (sans le consommer).
pub fn redeem_info(c: &Connection, ticket: &str) -> ApiResult<SsoRedeemResponse> {
    {
        {
            let (t, name) = find_ticket(c, ticket)?;
            let kdf: Option<KdfParams> = match &t.user_id {
                Some(id) => c
                    .query_row("SELECT kdf FROM users WHERE id = ?1", [id], |r| r.get::<_, String>(0))
                    .optional()?
                    .and_then(|k| serde_json::from_str(&k).ok()),
                None => None,
            };
            let registered = kdf.is_some();
            let can_register = !registered && may_self_register(c, &t.email)?;
            Ok(SsoRedeemResponse { email: t.email, name, registered, can_register, kdf })
        }
    }
}

// ------------------------------------------------------------ Administration

pub async fn get_config(State(state): State<AppState>, _admin: AdminUser) -> ApiResult<Json<SsoConfig>> {
    let mut cfg = state.db.call(|c| load_config(c)).await?;
    cfg.client_secret = String::new();
    Ok(Json(cfg))
}

pub async fn put_config(State(state): State<AppState>, AdminUser(admin): AdminUser, Json(mut req): Json<SsoConfig>) -> ApiResult<Json<SsoConfig>> {
    req.issuer = req.issuer.trim().trim_end_matches('/').to_string();
    req.public_url = req.public_url.trim().trim_end_matches('/').to_string();
    req.client_id = req.client_id.trim().to_string();
    req.label = req.label.trim().chars().take(60).collect();
    req.allowed_domains = req.allowed_domains.iter().map(|d| d.trim().trim_start_matches('@').to_lowercase()).filter(|d| !d.is_empty()).collect();
    if req.enabled {
        if req.issuer.is_empty() || req.client_id.is_empty() {
            return Err(ApiError::bad_request("Renseignez l'émetteur et l'identifiant client."));
        }
        check_url(&req.issuer, "Émetteur")?;
        let base = url::Url::parse(&req.public_url).map_err(|_| ApiError::bad_request("Adresse publique de Locksy invalide."))?;
        if base.scheme() != "https" && !allow_http() && !matches!(base.host_str(), Some("localhost" | "127.0.0.1")) {
            return Err(ApiError::bad_request("L'adresse publique de Locksy doit être en https://."));
        }
        // Vérifie que le fournisseur répond avant d'activer.
        state.sso.discover(&req.issuer).await?;
    }
    let key = state.server_key.clone();
    let cfg = state
        .db
        .call(move |c| {
            let old = load_config(c)?;
            if req.client_secret.trim().is_empty() {
                req.client_secret = old.client_secret;
            } else {
                req.client_secret = crypto::encrypt_str(&key, req.client_secret.trim(), "verrou:v1:sso-client-secret");
            }
            if req.enforce && !req.enabled {
                req.enforce = false;
            }
            req.has_secret = false;
            req.redirect_uri = String::new();
            db::save_json(c, SETTINGS_KEY, &req)?;
            audit_user(
                c,
                &admin,
                "admin.sso_updated",
                &req.issuer,
                &format!(
                    "actif : {}, imposé : {}, création automatique : {}",
                    if req.enabled { "oui" } else { "non" },
                    if req.enforce { "oui" } else { "non" },
                    if req.auto_provision { "oui" } else { "non" }
                ),
            )?;
            let mut cfg = load_config(c)?;
            cfg.client_secret = String::new();
            Ok(cfg)
        })
        .await?;
    Ok(Json(cfg))
}

#[derive(serde::Serialize)]
pub struct SsoTestResult {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    keys: usize,
}

pub async fn test_config(State(state): State<AppState>, _admin: AdminUser, Json(req): Json<SsoConfig>) -> ApiResult<Json<SsoTestResult>> {
    let issuer = req.issuer.trim().trim_end_matches('/').to_string();
    check_url(&issuer, "Émetteur")?;
    let d = state.sso.discover(&issuer).await?;
    let keys = state.sso.keys(&d.jwks_uri, true).await?;
    Ok(Json(SsoTestResult { issuer: d.issuer, authorization_endpoint: d.authorization_endpoint, token_endpoint: d.token_endpoint, keys: keys.keys.len() }))
}

pub fn sso_required_error(label: &str) -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "sso_required",
        format!("Votre organisation impose la connexion via « {label} »."),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_redirects_are_restricted() {
        assert!(extension_redirect_ok("https://abcdefghijklmnop.chromiumapp.org/"));
        assert!(!extension_redirect_ok("https://chromiumapp.org/"));
        assert!(!extension_redirect_ok("https://evil.com/?x=.chromiumapp.org"));
        assert!(!extension_redirect_ok("http://abc.chromiumapp.org/"));
        assert!(!extension_redirect_ok("https://abc.chromiumapp.org:8443/"));
        assert!(!extension_redirect_ok("https://abc.chromiumapp.org.evil.com/"));
    }

    #[test]
    fn finish_urls_carry_the_ticket_out_of_server_logs() {
        let cfg = SsoConfig { public_url: "https://coffre.exemple.fr".into(), ..Default::default() };
        assert_eq!(finish_url(&cfg, &ReturnTo::Web, Ok("T".into())), "https://coffre.exemple.fr/#/sso?ticket=T");
        assert_eq!(finish_url(&cfg, &ReturnTo::Desktop(50123), Ok("T".into())), "http://127.0.0.1:50123/sso?ticket=T");
        assert_eq!(
            finish_url(&cfg, &ReturnTo::Extension("https://x.chromiumapp.org/cb".into()), Err("refus é".into())),
            "https://x.chromiumapp.org/cb#error=refus%20%C3%A9"
        );
    }
}
