//! Inscription, connexion, double authentification, réauthentification et
//! récupération de compte.

use crate::db::{self, Db};
use crate::error::{ApiError, ApiResult};
use crate::mail::{Notification, Notifier};
use crate::security::{self as sec, hash_secret, sha256_hex, verify_secret, Limiter};
use crate::state::{audit, AppState, AuthUser, ClientMeta};
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use crate::error::Json;
use hmac::{Hmac, Mac};
use locksy_core::api::*;
use locksy_core::crypto::{self, KdfParams, SecretKey};
use locksy_core::encoding::{b64d, b64e};
use locksy_core::settings::{ip_allowed, twofa_gate, Effective, TwofaGate};
use locksy_core::{aad, now_unix, totp};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path as FsPath;
use std::sync::{Arc, Mutex, OnceLock};
use subtle::ConstantTimeEq;

/// Routes de l'authentification et du compte ajoutées en vague 2 (handlers
/// de ce module et de `me.rs`).
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/reauth", post(reauth))
        .route(
            "/me/2fa/recovery-codes",
            get(crate::me::recovery_codes_status).post(crate::me::regenerate_recovery_codes),
        )
        .route("/me/kdf", post(crate::me::upgrade_kdf))
        .route("/me/export", post(crate::me::record_export))
}

// ------------------------------------------------------------ Profil et sessions

/// Profil d'un compte selon les réglages effectifs `eff` : la mise en place
/// de la 2FA est exigée quand la règle vise le compte (organisation ou rôle)
/// et que le délai de grâce est écoulé.
pub fn load_profile_with(c: &Connection, eff: &Effective, user_id: &str) -> ApiResult<Profile> {
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
    profile.must_setup_2fa =
        twofa_gate(eff, &profile.role, profile.totp_enabled, profile.created_at, now_unix()) == TwofaGate::Required;
    Ok(profile)
}

/// Ouvre une session de `session.max_hours` heures. Au-delà de
/// `session.max_per_user` sessions (0 : illimité), les plus anciennes sont
/// fermées (audit `session.evicted`). Renvoie le jeton en clair.
pub fn create_session_with(
    c: &Connection,
    eff: &Effective,
    user_id: &str,
    meta: &ClientMeta,
    device: &str,
) -> ApiResult<String> {
    let token = crypto::random_token();
    let now = now_unix();
    let device = device_label(meta, device);
    let max_hours = eff.int("session.max_hours").max(1);
    c.execute(
        "INSERT INTO sessions (id, token_hash, user_id, created_at, last_seen_at, expires_at, ip, device)
         VALUES (?1, ?2, ?3, ?4, ?4, ?5, ?6, ?7)",
        params![crypto::new_uuid(), sha256_hex(&token), user_id, now, now + max_hours * 3600, meta.ip, device],
    )?;
    let max = eff.int("session.max_per_user");
    if max > 0 {
        let evicted: Vec<String> = c
            .prepare(
                "SELECT id FROM sessions WHERE user_id = ?1
                 ORDER BY created_at DESC, rowid DESC LIMIT -1 OFFSET ?2",
            )?
            .query_map(params![user_id, max], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        if !evicted.is_empty() {
            let email: String = c.query_row("SELECT email FROM users WHERE id = ?1", [user_id], |r| r.get(0))?;
            let details = format!("limite de {max} session(s) par compte atteinte");
            for sid in &evicted {
                c.execute("DELETE FROM sessions WHERE id = ?1", [sid])?;
                audit(c, Some(user_id), &email, "session.evicted", sid, meta, &details)?;
            }
        }
    }
    Ok(token)
}

/// Nom d'appareil d'une session : celui envoyé par le client, sinon le
/// navigateur, tronqué à 120 caractères.
fn device_label(meta: &ClientMeta, device: &str) -> String {
    let d = if device.trim().is_empty() { meta.user_agent.as_str() } else { device };
    d.chars().take(120).collect()
}

/// Connexion depuis un appareil (nom et adresse IP) jamais vu pour ce
/// compte, ni dans ses sessions ni dans ses connexions journalisées ? La
/// toute première connexion d'un compte n'est pas signalée.
fn is_new_device(c: &Connection, user_id: &str, device: &str, ip: &str) -> ApiResult<bool> {
    let (known, history): (bool, bool) = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sessions WHERE user_id = ?1 AND device = ?2 AND ip = ?3)
             OR EXISTS(SELECT 1 FROM audit WHERE user_id = ?1 AND action = 'login.success' AND ip = ?3
                       AND (details = ?2 OR details = ?2 || ' (SSO)')),
                EXISTS(SELECT 1 FROM audit WHERE user_id = ?1 AND action = 'login.success')",
        params![user_id, device, ip],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok(!known && history)
}

/// Paramètres de dérivation proposés à une adresse inconnue : ceux de la
/// politique en vigueur (`kdf.*`), avec un sel stable dérivé de la clé du
/// serveur et de l'adresse. La réponse ne se distingue pas de celle d'un
/// compte créé sous cette politique.
fn fake_kdf(server_key: &SecretKey, eff: &Effective, email: &str) -> KdfParams {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(server_key.as_bytes()).expect("clé HMAC valide");
    mac.update(b"verrou:fake-salt:");
    mac.update(email.as_bytes());
    let out = mac.finalize().into_bytes();
    let to_u32 = |v: i64, lo: u32, hi: u32| u32::try_from(v).unwrap_or(lo).clamp(lo, hi);
    KdfParams {
        m_kib: to_u32(eff.int("kdf.memory_mib"), 19, 1024) * 1024,
        t: to_u32(eff.int("kdf.iterations"), 2, 10),
        p: to_u32(eff.int("kdf.parallelism"), 1, 8),
        ..KdfParams::with_salt(b64e(&out[..16]))
    }
}

pub fn encrypt_totp_secret(state: &AppState, user_id: &str, secret_b32: &str) -> String {
    crypto::encrypt_str(&state.server_key, secret_b32, &aad::server_totp(user_id))
}

/// Secret 2FA en clair. Illisible (clé serveur régénérée par
/// `LOCKSY_SERVER_KEY_RESET`, restauration sans la clé) : 409
/// `totp_unreadable`, une erreur claire pour la personne et non un 500.
pub fn decrypt_totp_secret(server_key: &SecretKey, user_id: &str, data: &str) -> ApiResult<Vec<u8>> {
    crypto::decrypt_string(server_key, data, &aad::server_totp(user_id))
        .ok()
        .and_then(|b32| locksy_core::encoding::base32_decode(&b32).ok())
        .ok_or_else(|| {
            tracing::warn!(user_id, "secret 2FA illisible avec la clé serveur actuelle (clé changée ?)");
            totp_unreadable()
        })
}

/// Secret 2FA indéchiffrable avec la clé serveur actuelle (409).
pub(crate) fn totp_unreadable() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        "totp_unreadable",
        "Votre double authentification doit être réactivée : la clé du serveur a changé. \
         Demandez à un administrateur de la réinitialiser.",
    )
}

// ------------------------------------------------------------ Second facteur

/// Ce qu'il faut pour écrire un événement de sécurité dans une transaction :
/// clé du serveur, notifications, réglages effectifs.
#[derive(Clone)]
pub(crate) struct SecCtx {
    pub server_key: Arc<SecretKey>,
    pub notifier: Arc<dyn Notifier>,
    pub eff: Arc<Effective>,
}

impl SecCtx {
    pub(crate) async fn of(state: &AppState) -> ApiResult<Self> {
        Ok(Self { server_key: state.server_key.clone(), notifier: state.notifier.clone(), eff: state.effective().await? })
    }

    /// Notification de sécurité au titulaire du compte, mise en file dans la
    /// transaction `c` (partie avec son commit).
    pub(crate) fn notify(&self, c: &Connection, user_id: &str, event: &'static str) -> ApiResult<()> {
        let n = Notification::SecurityChange { user_id: user_id.to_string(), event, at: now_unix() };
        self.notifier.enqueue(c, &self.eff, &n).map(|_| ())
    }
}

/// Code de double authentification manquant (401).
pub(crate) fn totp_required() -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, "totp_required", "Saisissez le code de votre application d'authentification.")
}

/// Code de double authentification ou code de secours refusé (401).
pub(crate) fn invalid_totp() -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, "invalid_totp", "Code de double authentification incorrect.")
}

/// Le compte a-t-il la double authentification active ?
pub(crate) async fn has_totp(state: &AppState, user_id: &str) -> ApiResult<bool> {
    let uid = user_id.to_string();
    state
        .db
        .read(move |c| {
            Ok(c.query_row("SELECT totp_secret IS NOT NULL FROM users WHERE id = ?1", [uid], |r| r.get(0))
                .optional()?
                .unwrap_or(false))
        })
        .await
}

/// Clé du limiteur des essais de code d'un compte.
fn totp_key(user_id: &str) -> String {
    format!("totp:{user_id}")
}

/// Avant la transaction d'une action protégée par le second facteur : code
/// présent (sinon 401 `totp_required`), puis essai compté (`totp:<id>`, 5
/// essais). Le compte rendu se fait avec [`settle_factor`].
pub(crate) fn factor_attempt(state: &AppState, user_id: &str, code: Option<&str>) -> ApiResult<String> {
    let code = code.map(str::trim).filter(|c| !c.is_empty()).ok_or_else(totp_required)?;
    state.limiter.attempt(&totp_key(user_id), 5)?;
    Ok(code.to_string())
}

/// Après la transaction : un code juste remet le compteur à zéro, un code
/// faux reste compté, toute autre issue rend l'essai.
pub(crate) fn settle_factor<T>(state: &AppState, user_id: &str, res: &ApiResult<T>) {
    match res {
        Ok(_) => state.limiter.success(&totp_key(user_id)),
        Err(e) if e.code == "invalid_totp" => {}
        Err(_) => state.limiter.release(&totp_key(user_id)),
    }
}

/// Vérifie un second facteur et le consomme dans la transaction `c` : un
/// code TOTP fait avancer le dernier pas accepté (pas de rejeu) ; un code de
/// secours est marqué utilisé, journalisé (`2fa.recovery_code_used`) et
/// notifié. Code refusé : 401 `invalid_totp`, rien n'est écrit.
pub(crate) fn take_second_factor(
    c: &Connection,
    ctx: &SecCtx,
    user_id: &str,
    email: &str,
    meta: &ClientMeta,
    code: &str,
) -> ApiResult<()> {
    if sec::looks_like_recovery_code(code) {
        let Some(remaining) = crate::me::consume_recovery_code(c, &ctx.server_key, user_id, code)? else {
            return Err(invalid_totp());
        };
        audit(c, Some(user_id), email, "2fa.recovery_code_used", "", meta, &format!("{remaining} code(s) restant(s)"))?;
        return ctx.notify(c, user_id, "2fa.recovery_code_used");
    }
    let (secret, last): (Option<String>, Option<i64>) =
        c.query_row("SELECT totp_secret, totp_last_step FROM users WHERE id = ?1", [user_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
    let Some(enc) = secret else { return Err(invalid_totp()) };
    let secret = decrypt_totp_secret(&ctx.server_key, user_id, &enc)?;
    let step = totp::verify(&secret, code, now_unix() as u64, last.map(|s| s as u64)).ok_or_else(invalid_totp)?;
    c.execute("UPDATE users SET totp_last_step = ?1 WHERE id = ?2", params![step as i64, user_id])?;
    Ok(())
}

// ------------------------------------------------------------ Jeton d'installation

/// Clé de la table `settings` qui garde l'empreinte du jeton d'installation.
const SETUP_TOKEN_KEY: &str = "setup_token";
/// Nom du fichier, dans le dossier de données, qui contient le jeton en clair.
pub const SETUP_TOKEN_FILE: &str = "setup-token";
/// Longueur minimale d'un jeton imposé par `LOCKSY_SETUP_TOKEN`.
const SETUP_TOKEN_MIN_LEN: usize = 20;
/// Clé du limiteur pour les essais de jeton d'installation (tous clients confondus).
const SETUP_ATTEMPT_KEY: &str = "setup-token";

/// Empreinte du jeton d'installation, tant qu'aucun compte n'existe.
#[derive(Serialize, Deserialize, Default)]
struct SetupTokenRecord {
    #[serde(default)]
    hash: String,
    #[serde(default)]
    created_at: i64,
}

/// Au démarrage : tant qu'aucun compte n'existe, la création du premier
/// compte (propriétaire) exige un jeton à usage unique. Sans lui, la première
/// personne à joindre un serveur fraîchement installé en prendrait le contrôle.
///
/// Le jeton vient de `LOCKSY_SETUP_TOKEN`, ou est tiré au hasard et écrit dans
/// `<data>/setup-token` (lisible par le seul compte de service). Seule son
/// empreinte SHA-256 est gardée en base ; sa valeur n'est jamais journalisée.
pub async fn init_setup_token(db: &Db, data_dir: &FsPath) -> ApiResult<()> {
    let provided = std::env::var("LOCKSY_SETUP_TOKEN").ok().map(|t| t.trim().to_string()).filter(|t| !t.is_empty());
    init_setup_token_with(db, data_dir, provided).await
}

async fn init_setup_token_with(db: &Db, data_dir: &FsPath, provided: Option<String>) -> ApiResult<()> {
    let path = data_dir.join(SETUP_TOKEN_FILE);
    let users: i64 = db.call(|c| Ok(c.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?)).await?;
    if users > 0 {
        // Installation terminée : plus de jeton.
        db.call(|c| {
            c.execute("DELETE FROM settings WHERE key = ?1", [SETUP_TOKEN_KEY])?;
            Ok(())
        })
        .await?;
        remove_setup_file(&path);
        return Ok(());
    }
    if let Some(token) = provided {
        if token.chars().count() < SETUP_TOKEN_MIN_LEN {
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid_config",
                format!("LOCKSY_SETUP_TOKEN doit faire au moins {SETUP_TOKEN_MIN_LEN} caractères."),
            ));
        }
        store_setup_hash(db, sha256_hex(&token)).await?;
        remove_setup_file(&path);
        tracing::info!("aucun compte : jeton d'installation fourni par LOCKSY_SETUP_TOKEN");
        return Ok(());
    }
    // Même jeton d'un redémarrage à l'autre, tant que le fichier correspond à l'empreinte.
    let stored: SetupTokenRecord = db.call(|c| db::load_json(c, SETUP_TOKEN_KEY)).await?;
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let existing = existing.trim();
        if !existing.is_empty() && !stored.hash.is_empty() && sha256_hex(existing) == stored.hash {
            tracing::info!("aucun compte : jeton d'installation dans {}", path.display());
            return Ok(());
        }
    }
    let token = crypto::random_token();
    write_setup_file(&path, &token).map_err(|e| {
        tracing::error!(error = %e, path = %path.display(), "écriture du jeton d'installation");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            format!("Impossible d'écrire le jeton d'installation dans {}.", path.display()),
        )
    })?;
    store_setup_hash(db, sha256_hex(&token)).await?;
    tracing::info!("aucun compte : jeton d'installation dans {}", path.display());
    Ok(())
}

async fn store_setup_hash(db: &Db, hash: String) -> ApiResult<()> {
    db.call(move |c| db::save_json(c, SETUP_TOKEN_KEY, &SetupTokenRecord { hash, created_at: now_unix() })).await
}

/// Écrit le jeton dans un fichier temporaire créé directement en 0600 (sous
/// Unix), puis le renomme : le fichier n'est jamais lisible par d'autres, ni
/// visible à moitié écrit.
fn write_setup_file(path: &FsPath, token: &str) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_file_name(format!("{SETUP_TOKEN_FILE}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(format!("{token}\n").as_bytes())?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

/// Supprime le fichier du jeton (meilleur effort).
fn remove_setup_file(path: &FsPath) {
    match std::fs::remove_file(path) {
        Ok(()) => tracing::info!("fichier du jeton d'installation supprimé : {}", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(error = %e, "suppression du fichier {} impossible", path.display()),
    }
}

/// Vérifie le jeton d'installation présenté pour le premier compte, dans la
/// transaction de création, puis l'efface : il ne sert qu'une fois.
fn consume_setup_token(c: &Connection, given: Option<&str>) -> ApiResult<()> {
    let Some(given) = given.map(str::trim).filter(|t| !t.is_empty()) else {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "setup_token_required",
            "Saisissez le jeton d'installation : il figure dans le fichier setup-token du dossier de données du serveur.",
        ));
    };
    let stored: SetupTokenRecord = db::load_json(c, SETUP_TOKEN_KEY)?;
    let ok = !stored.hash.is_empty() && bool::from(sha256_hex(given).as_bytes().ct_eq(stored.hash.as_bytes()));
    if !ok {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "invalid_setup_token", "Jeton d'installation incorrect."));
    }
    c.execute("DELETE FROM settings WHERE key = ?1", [SETUP_TOKEN_KEY])?;
    Ok(())
}

/// Corps de `POST /auth/register` : la requête commune, plus le jeton
/// d'installation exigé pour le tout premier compte.
#[derive(Deserialize)]
pub struct RegisterBody {
    #[serde(flatten)]
    inner: RegisterRequest,
    #[serde(default)]
    setup_token: Option<String>,
}

/// Annule le pré-comptage de tentatives qui ne se sont pas révélées être des échecs.
fn release_all(limiter: &Limiter, keys: &[&str]) {
    for k in keys {
        limiter.release(k);
    }
}

/// Compte désactivé (403), quelle que soit la méthode de connexion.
pub(crate) fn account_disabled() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "account_disabled",
        "Ce compte est désactivé. Contactez votre administrateur pour le réactiver.",
    )
}

/// Date de fin d'accès dépassée (403).
pub(crate) fn account_expired() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "account_expired",
        "L'accès de ce compte a expiré. Contactez votre administrateur pour le prolonger.",
    )
}

/// Connexion refusée hors des réseaux autorisés (403).
fn ip_not_allowed() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "ip_not_allowed",
        "Connexion refusée depuis ce réseau : votre organisation limite l'accès à certaines adresses.",
    )
}

/// L'adresse du client est-elle dans la liste blanche (secours des
/// propriétaires compris) ? Liste vide : tout passe ; adresse illisible
/// face à une liste : refus.
fn client_ip_allowed(eff: &Effective, meta: &ClientMeta, role: &str) -> bool {
    eff.list("access.ip_allowlist").is_empty() || meta.ip.parse::<IpAddr>().is_ok_and(|ip| ip_allowed(eff, ip, role))
}

/// Ligne `users` lue à la connexion.
struct LoginRow {
    id: String,
    auth_hash: String,
    disabled: bool,
    has_totp: bool,
    role: String,
    access_until: Option<i64>,
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
    state.limiter.hit(&format!("prelogin:{}", meta.rate_key()), state.host.rate.prelogin_ip, 60)?;
    let email = sec::normalize_email(&req.email)?;
    let eff = state.effective().await?;
    let lookup = email.clone();
    let kdf: Option<String> = state
        .db
        .read(move |c| Ok(c.query_row("SELECT kdf FROM users WHERE email = ?1", [lookup], |r| r.get(0)).optional()?))
        .await?;
    let kdf = match kdf.and_then(|k| serde_json::from_str(&k).ok()) {
        Some(k) => k,
        None => fake_kdf(&state.server_key, &eff, &email),
    };
    Ok(Json(PreloginResponse { kdf }))
}

pub async fn invite_info(
    State(state): State<AppState>,
    meta: ClientMeta,
    Path(token): Path<String>,
) -> ApiResult<Json<InviteInfo>> {
    state.limiter.hit(&format!("invite:{}", meta.rate_key()), state.host.rate.invite_ip, 60)?;
    let hash = sha256_hex(&token);
    state
        .db
        .call(move |c| {
            c.query_row(
                "SELECT email, role, name FROM invites WHERE token_hash = ?1 AND used_at IS NULL AND expires_at > ?2",
                params![hash, now_unix()],
                |r| Ok(InviteInfo { email: r.get(0)?, role: r.get(1)?, name: r.get(2)? }),
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
    Json(body): Json<RegisterBody>,
) -> ApiResult<Json<LoginResponse>> {
    let RegisterBody { inner: req, setup_token } = body;
    state.limiter.hit(&format!("register:{}", meta.rate_key()), state.host.rate.register_ip, 3600)?;
    let eff = state.effective().await?;
    let email = sec::normalize_email(&req.email)?;
    let name = sec::clean_name(&req.name)?;
    sec::uuid(&req.user_id, "utilisateur")?;
    sec::uuid(&req.personal_collection.id, "coffre")?;
    sec::kdf(&req.kdf)?;
    sec::kdf_policy(&eff, &req.kdf)?;
    sec::require_email_domain(&eff, &email)?;
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
    let limiter = state.limiter.clone();

    let (resp, first_setup) = state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let now = now_unix();
            let users: i64 = tx.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
            let mut sso_subject: Option<String> = None;
            let mut invite_access_until: Option<i64> = None;
            let role = if users == 0 {
                // Premier compte : jeton d'installation obligatoire. Les essais sont
                // plafonnés globalement, en plus du plafond par adresse IP ci-dessus.
                if setup_token.as_deref().is_some_and(|t| !t.trim().is_empty()) {
                    limiter.attempt(SETUP_ATTEMPT_KEY, 20)?;
                }
                consume_setup_token(&tx, setup_token.as_deref())?;
                limiter.success(SETUP_ATTEMPT_KEY);
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
                let invite: Option<(String, String, Option<i64>)> = tx
                    .query_row(
                        "SELECT id, role, access_until FROM invites
                         WHERE token_hash = ?1 AND email = ?2 AND used_at IS NULL AND expires_at > ?3",
                        params![hash, email, now],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )
                    .optional()?;
                let Some((invite_id, role, access_until)) = invite else {
                    return Err(ApiError::forbidden(
                        "Invitation invalide, expirée, déjà utilisée ou destinée à une autre adresse.",
                    ));
                };
                tx.execute("UPDATE invites SET used_at = ?1 WHERE id = ?2", params![now, invite_id])?;
                // L'accès limité dans le temps prévu par l'invitation passe au compte.
                invite_access_until = access_until;
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
            tx.execute(
                "UPDATE users SET sso_subject = ?1, access_until = ?2 WHERE id = ?3",
                params![sso_subject, invite_access_until, req.user_id],
            )?;
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
            if users == 0 {
                audit(&tx, Some(&req.user_id), &email, "setup.completed", &email, &meta2, "jeton d'installation utilisé")?;
            }
            let token = create_session_with(&tx, &eff, &req.user_id, &meta2, "")?;
            let profile = load_profile_with(&tx, &eff, &req.user_id)?;
            tx.commit()?;
            Ok((LoginResponse { token, profile }, users == 0))
        })
        .await?;
    if first_setup {
        remove_setup_file(&state.config.data_dir.join(SETUP_TOKEN_FILE));
    }
    Ok(Json(resp))
}

pub async fn login(
    State(state): State<AppState>,
    meta: ClientMeta,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    let email = sec::normalize_email(&req.email)?;
    let auth_key = b64d(&req.auth_key).map_err(|_| ApiError::bad_request("Preuve d'authentification invalide."))?;
    let ctx = SecCtx::of(&state).await?;
    let lock = sec::lockout(&ctx.eff);
    // Chaque tentative est comptée AVANT la lecture en base et le calcul
    // Argon2 : des requêtes parallèles ne peuvent pas dépasser les seuils.
    //  - plafond par adresse (ou préfixe /64), fixé par l'hébergeur, jamais
    //    remis à zéro par une réussite ;
    //  - blocage court par paire (adresse e-mail, adresse IP) ;
    //  - blocage par adresse e-mail, seuil bien plus haut, pour qu'un tiers
    //    ne puisse pas bloquer un compte facilement depuis une seule adresse.
    let rate_key = meta.rate_key();
    state.limiter.hit(&format!("login-ip:{rate_key}"), state.host.rate.login_ip, 600)?;
    let pair_key = format!("login-pair:{email}|{rate_key}");
    let email_key = format!("login-email:{email}");
    state.limiter.attempt_with(&pair_key, lock.pair, &lock)?;
    if let Err(e) = state.limiter.attempt_with(&email_key, lock.account, &lock) {
        state.limiter.release(&pair_key);
        return Err(e);
    }
    let counted = [pair_key.as_str(), email_key.as_str()];

    let lookup = email.clone();
    let (row, (sso_cfg, ldap_cfg)): (Option<LoginRow>, (SsoConfig, LdapConfig)) = state
        .db
        .call(move |c| {
            let row = c
                .query_row(
                    "SELECT id, auth_hash, disabled, totp_secret IS NOT NULL, role, access_until
                     FROM users WHERE email = ?1",
                    [lookup],
                    |r| {
                        Ok(LoginRow {
                            id: r.get(0)?,
                            auth_hash: r.get(1)?,
                            disabled: r.get(2)?,
                            has_totp: r.get(3)?,
                            role: r.get(4)?,
                            access_until: r.get(5)?,
                        })
                    },
                )
                .optional()?;
            Ok((row, (crate::sso::load_config(c)?, crate::ldap::load_config(c)?)))
        })
        .await?;

    let hash = row.as_ref().map(|r| r.auth_hash.clone()).unwrap_or_else(|| state.dummy_hash.to_string());
    let valid = match verify_secret(auth_key.clone(), hash).await {
        Ok(v) => v && row.is_some(),
        Err(e) => {
            // Serveur saturé : rien n'a été vérifié, la tentative ne compte pas.
            release_all(&state.limiter, &counted);
            return Err(e);
        }
    };
    if !valid {
        // La tentative est déjà comptée par `attempt_with`.
        let uid = row.map(|r| r.id);
        login_failed(&state, &ctx, &meta, &email, uid, "mot de passe incorrect", &counted).await?;
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "Adresse e-mail ou mot de passe maître incorrect.",
        ));
    }
    let user = row.expect("vérifié ci-dessus");
    // À partir d'ici, le mot de passe maître est correct : les refus qui suivent
    // (compte fermé, réseau non autorisé, ticket expiré, SSO imposé, code 2FA
    // manquant) ne sont pas des devinettes et ne rapprochent pas le compte du
    // blocage. Un code 2FA FAUX, lui, reste compté.
    let refusal = if user.disabled {
        Some((account_disabled(), "compte désactivé"))
    } else if user.access_until.is_some_and(|t| t <= now_unix()) {
        Some((account_expired(), "accès expiré"))
    } else if !client_ip_allowed(&ctx.eff, &meta, &user.role) {
        Some((ip_not_allowed(), "adresse IP non autorisée"))
    } else {
        None
    };
    if let Some((err, why)) = refusal {
        release_all(&state.limiter, &counted);
        let (e, u, m) = (email.clone(), user.id.clone(), meta.clone());
        state.db.call(move |c| audit(c, Some(&u), &e, "login.refused", &e, &m, why)).await?;
        return Err(err);
    }
    // Ticket SSO : vérifié ici, consommé seulement à la création de la session
    // (il reste donc valable si le code 2FA est demandé ensuite).
    let sso_ticket = req.sso_ticket.clone().filter(|t| !t.is_empty());
    if let Some(t) = &sso_ticket {
        let (t, e, u) = (t.clone(), email.clone(), user.id.clone());
        let checked = state
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
            .await;
        if let Err(e) = checked {
            release_all(&state.limiter, &counted);
            return Err(e);
        }
    } else if user.role != roles::OWNER {
        if ldap_cfg.allow_login && ldap_cfg.enforce {
            release_all(&state.limiter, &counted);
            return Err(crate::sso::sso_required_error(&ldap_cfg.label));
        }
        if sso_cfg.enabled && sso_cfg.enforce {
            release_all(&state.limiter, &counted);
            return Err(crate::sso::sso_required_error(&sso_cfg.label));
        }
    }
    // La 2FA Locksy reste exigée même après le SSO ou le compte Windows : le
    // ticket prouve l'identité d'entreprise, pas la possession du second facteur.
    // Un code envoyé à un compte sans 2FA est ignoré.
    let code = req.totp.as_deref().map(str::trim).filter(|c| user.has_totp && !c.is_empty()).map(str::to_string);
    if user.has_totp && code.is_none() {
        release_all(&state.limiter, &counted);
        return Err(totp_required());
    }
    // Empreinte calculée avec d'autres paramètres que ceux du serveur :
    // recalculée maintenant que la preuve est connue (serveur saturé : ce
    // sera pour la prochaine connexion).
    let rehash = if sec::needs_rehash(&user.auth_hash) { hash_secret(auth_key).await.ok() } else { None };
    let device = device_label(&meta, req.device.as_deref().unwrap_or_default());
    let (uid, e, m, c2, old_hash) = (user.id.clone(), email.clone(), meta.clone(), ctx.clone(), user.auth_hash.clone());
    let resp = state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let now = now_unix();
            if let Some(code) = &code {
                match take_second_factor(&tx, &c2, &uid, &e, &m, code) {
                    // Transaction abandonnée : rien n'est écrit.
                    Err(err) if err.code == "invalid_totp" => return Ok(None),
                    other => other?,
                }
            }
            tx.execute("UPDATE users SET last_login_at = ?1 WHERE id = ?2", params![now, uid])?;
            if let Some(new_hash) = rehash {
                let n = tx.execute(
                    "UPDATE users SET auth_hash = ?1 WHERE id = ?2 AND auth_hash = ?3",
                    params![new_hash, uid, old_hash],
                )?;
                if n == 1 {
                    audit(&tx, Some(&uid), &e, "login.rehashed", &e, &m, "empreinte recalculée aux paramètres du serveur")?;
                }
            }
            if let Some(t) = &sso_ticket {
                crate::sso::take_ticket(&tx, t, &e)?;
            }
            let new_device = is_new_device(&tx, &uid, &device, &m.ip)?;
            let token = create_session_with(&tx, &c2.eff, &uid, &m, &device)?;
            let how = if sso_ticket.is_some() { format!("{device} (SSO)") } else { device.clone() };
            audit(&tx, Some(&uid), &e, "login.success", &e, &m, &how)?;
            if new_device {
                let n = Notification::NewDevice { user_id: uid.clone(), device: device.clone(), ip: m.ip.clone(), at: now };
                c2.notifier.enqueue(&tx, &c2.eff, &n)?;
            }
            let profile = load_profile_with(&tx, &c2.eff, &uid)?;
            tx.commit()?;
            Ok(Some(LoginResponse { token, profile }))
        })
        .await?;
    let Some(resp) = resp else {
        // Code faux : la tentative pré-comptée le reste.
        login_failed(&state, &ctx, &meta, &email, Some(user.id), "code 2FA incorrect", &counted).await?;
        return Err(invalid_totp());
    };
    // Réussite complète : la paire et l'adresse repartent de zéro (pas le plafond par IP).
    state.limiter.success(&pair_key);
    state.limiter.success(&email_key);
    Ok(Json(resp))
}

/// Journalise un échec de connexion (`login.failed`). Si cet échec vient de
/// poser un blocage (paire ou compte), journalise aussi `login.locked` et
/// prévient le titulaire du compte.
async fn login_failed(
    state: &AppState,
    ctx: &SecCtx,
    meta: &ClientMeta,
    email: &str,
    user_id: Option<String>,
    why: &'static str,
    keys: &[&str; 2],
) -> ApiResult<()> {
    let [pair, account] = *keys;
    let locked = match (state.limiter.check(pair), state.limiter.check(account)) {
        (_, Err(e)) => Some(format!("compte bloqué {} s (toutes adresses)", e.retry_after.unwrap_or(0))),
        (Err(e), _) => Some(format!("adresse IP bloquée {} s pour ce compte", e.retry_after.unwrap_or(0))),
        _ => None,
    };
    let (e, m, c2) = (email.to_string(), meta.clone(), ctx.clone());
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            audit(&tx, user_id.as_deref(), &e, "login.failed", &e, &m, why)?;
            if let Some(details) = locked {
                audit(&tx, user_id.as_deref(), &e, "login.locked", &e, &m, &details)?;
                if let Some(uid) = &user_id {
                    c2.notify(&tx, uid, "login.locked")?;
                }
            }
            tx.commit()?;
            Ok(())
        })
        .await
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

// ------------------------------------------------------------ Réauthentification

/// Corps de `POST /auth/reauth`.
#[derive(Deserialize)]
pub struct ReauthBody {
    action: String,
    auth_key: String,
    #[serde(default)]
    totp: Option<String>,
}

/// Jeton de réauthentification délivré.
#[derive(Serialize)]
pub struct ReauthToken {
    token: String,
    expires_in: i64,
    action: &'static str,
}

/// `POST /auth/reauth` : confirme l'identité (mot de passe maître, et second
/// facteur pour les actions qui touchent à la 2FA, à la récupération ou à
/// l'export) et délivre un jeton court, à usage unique, lié au compte, à la
/// session et à l'action.
pub async fn reauth(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<ReauthBody>,
) -> ApiResult<Json<ReauthToken>> {
    let action =
        sec::step_up_action(&req.action).ok_or_else(|| ApiError::bad_request("Action à confirmer inconnue."))?;
    let needs_factor = sec::STEP_UP_SECOND_FACTOR.contains(&action) && has_totp(&state, &user.id).await?;
    if needs_factor && req.totp.as_deref().map(str::trim).filter(|c| !c.is_empty()).is_none() {
        return Err(totp_required());
    }
    sec::check_password_proof(&state, &user.id, &req.auth_key, sec::wrong_password).await?;
    let code = if needs_factor { Some(factor_attempt(&state, &user.id, req.totp.as_deref())?) } else { None };
    let ctx = SecCtx::of(&state).await?;
    let u = user.clone();
    let res = state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            if let Some(code) = &code {
                take_second_factor(&tx, &ctx, &u.id, &u.email, &u.meta, code)?;
            }
            crate::state::audit_user(&tx, &u, "auth.step_up", action, "")?;
            tx.commit()?;
            Ok(())
        })
        .await;
    if needs_factor {
        settle_factor(&state, &user.id, &res);
    }
    res?;
    let token = sec::issue_step_up(&user.id, &user.session_id, action);
    Ok(Json(ReauthToken { token, expires_in: sec::STEP_UP_TTL_SECS, action }))
}

// ------------------------------------------------------------ Récupération

pub async fn recover_start(
    State(state): State<AppState>,
    meta: ClientMeta,
    Json(req): Json<RecoverStartRequest>,
) -> ApiResult<Json<RecoverStartResponse>> {
    let email = sec::normalize_email(&req.email)?;
    let key = format!("recover:{email}");
    state.limiter.hit(&format!("recover-ip:{}", meta.rate_key()), state.host.rate.recover_ip, 3600)?;
    let proof = b64d(&req.recovery_auth).map_err(|_| ApiError::bad_request("Clé de récupération invalide."))?;
    // Tentative comptée avant le calcul Argon2 (voir `login`).
    state.limiter.attempt(&key, 5)?;
    let lookup = email.clone();
    let row: Option<(String, String, String, bool, Option<i64>)> = state
        .db
        .call(move |c| {
            Ok(c.query_row(
                "SELECT id, recovery_auth_hash, recovery_wrapped_user_key, disabled, access_until
                 FROM users WHERE email = ?1",
                [lookup],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?)
        })
        .await?;
    let hash = row.as_ref().map(|r| r.1.clone()).unwrap_or_else(|| state.dummy_hash.to_string());
    let valid = match verify_secret(proof, hash).await {
        Ok(v) => v && row.is_some(),
        Err(e) => {
            state.limiter.release(&key);
            return Err(e);
        }
    };
    if !valid {
        let e = email.clone();
        state.db.call(move |c| audit(c, None, &e, "recovery.failed", &e, &meta, "")).await?;
        return Err(ApiError::unauthorized("Adresse ou clé de récupération incorrecte."));
    }
    state.limiter.success(&key);
    let (user_id, _, wrapped, disabled, access_until) = row.expect("vérifié ci-dessus");
    // Clé de récupération correcte : le compte fermé est signalé comme tel,
    // comme à la connexion.
    if disabled || access_until.is_some_and(|t| t <= now_unix()) {
        let (e, u) = (email.clone(), user_id.clone());
        let why = if disabled { "compte désactivé" } else { "accès expiré" };
        state.db.call(move |c| audit(c, Some(&u), &e, "recovery.failed", &e, &meta, why)).await?;
        return Err(if disabled { account_disabled() } else { account_expired() });
    }
    let token = crypto::random_token();
    let hash = sha256_hex(&token);
    let uid = user_id.clone();
    state
        .db
        .call(move |c| {
            c.execute("DELETE FROM recovery_tokens WHERE user_id = ?1", [&uid])?;
            c.execute(
                "INSERT INTO recovery_tokens (token_hash, user_id, expires_at) VALUES (?1, ?2, ?3)",
                params![hash, uid, now_unix() + RECOVERY_TOKEN_SECS],
            )?;
            audit(c, Some(&uid), &email, "recovery.started", &email, &meta, "")
        })
        .await?;
    Ok(Json(RecoverStartResponse { recovery_token: token, user_id, recovery_wrapped_user_key: wrapped }))
}

/// Durée de validité d'un jeton de récupération, et durée pendant laquelle
/// une récupération terminée peut être rejouée à l'identique.
const RECOVERY_TOKEN_SECS: i64 = 600;

/// Nombre maximal de récupérations terminées gardées en mémoire.
const RECOVERIES_MAX: usize = 10_000;

/// Récupération terminée : empreinte de la demande, compte, fin de la
/// fenêtre de rejeu.
struct Recovered {
    request_hash: String,
    user_id: String,
    until: i64,
}

/// Récupérations terminées récemment, par empreinte du jeton : une demande
/// rejouée à l'identique (réponse perdue, double envoi) reçoit la même
/// réponse ; une autre demande avec le même jeton est refusée (409). Gardées
/// en mémoire seulement : après un redémarrage, le jeton est simplement inconnu.
static RECOVERED: OnceLock<Mutex<HashMap<String, Recovered>>> = OnceLock::new();

fn recovered() -> std::sync::MutexGuard<'static, HashMap<String, Recovered>> {
    RECOVERED.get_or_init(Mutex::default).lock().unwrap_or_else(|p| p.into_inner())
}

/// Réponse d'une récupération terminée (identique en cas de rejeu).
#[derive(Serialize)]
pub struct RecoverFinished {
    user_id: String,
}

/// Issue d'une récupération déjà terminée avec ce jeton, s'il y en a une.
fn replay_recovery(token_hash: &str, request_hash: &str) -> Option<ApiResult<RecoverFinished>> {
    let map = recovered();
    let r = map.get(token_hash).filter(|r| r.until > now_unix())?;
    Some(if bool::from(r.request_hash.as_bytes().ct_eq(request_hash.as_bytes())) {
        Ok(RecoverFinished { user_id: r.user_id.clone() })
    } else {
        Err(ApiError::new(
            StatusCode::CONFLICT,
            "recovery_already_used",
            "Cette procédure de récupération a déjà servi. Recommencez la récupération depuis le début.",
        ))
    })
}

/// `POST /auth/recover/finish` : remplace le mot de passe maître. Idempotent :
/// la même demande rejouée dans les 10 minutes reçoit la même réponse.
pub async fn recover_finish(
    State(state): State<AppState>,
    meta: ClientMeta,
    body: Bytes,
) -> ApiResult<Json<RecoverFinished>> {
    let req: RecoverFinishRequest =
        serde_json::from_slice(&body).map_err(|_| ApiError::bad_request("Demande de récupération illisible."))?;
    let request_hash: String = <Sha256 as sha2::Digest>::digest(&body).iter().map(|b| format!("{b:02x}")).collect::<String>();
    let token_hash = sha256_hex(&req.recovery_token);
    if let Some(done) = replay_recovery(&token_hash, &request_hash) {
        return done.map(Json);
    }
    let ctx = SecCtx::of(&state).await?;
    sec::kdf(&req.kdf)?;
    sec::kdf_policy(&ctx.eff, &req.kdf)?;
    sec::cipher(&req.wrapped_user_key, sec::KEY_CIPHER_MAX, "clé utilisateur")?;
    let auth_hash = hash_secret(sec::key32(&req.auth_key, "Preuve d'authentification")?).await?;
    let kdf_json = serde_json::to_string(&req.kdf).map_err(|_| ApiError::internal("kdf"))?;
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let now = now_unix();
            let user: Option<(String, String)> = tx
                .query_row(
                    "SELECT t.user_id, u.email FROM recovery_tokens t JOIN users u ON u.id = t.user_id
                     WHERE t.token_hash = ?1 AND t.expires_at > ?2",
                    params![token_hash, now],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((uid, email)) = user else {
                // Une demande identique a pu aboutir entre-temps (les écritures
                // sont sérialisées) : même réponse, ou 409 si elle diffère.
                if let Some(done) = replay_recovery(&token_hash, &request_hash) {
                    return done;
                }
                return Err(ApiError::unauthorized("Procédure de récupération expirée. Recommencez."));
            };
            tx.execute(
                "UPDATE users SET auth_hash = ?1, kdf = ?2, wrapped_user_key = ?3, updated_at = ?4 WHERE id = ?5",
                params![auth_hash, kdf_json, req.wrapped_user_key, now, uid],
            )?;
            tx.execute("DELETE FROM recovery_tokens WHERE user_id = ?1", [&uid])?;
            tx.execute("DELETE FROM sessions WHERE user_id = ?1", [&uid])?;
            audit(&tx, Some(&uid), &email, "recovery.completed", &email, &meta, "mot de passe maître remplacé")?;
            ctx.notify(&tx, &uid, "recovery.completed")?;
            tx.commit()?;
            let mut map = recovered();
            map.retain(|_, r| r.until > now);
            if map.len() < RECOVERIES_MAX {
                map.insert(token_hash, Recovered { request_hash, user_id: uid.clone(), until: now + RECOVERY_TOKEN_SECS });
            }
            Ok(RecoverFinished { user_id: uid })
        })
        .await
        .map(Json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_state;
    use serde_json::json;

    const IP_A: &str = "203.0.113.7";
    const IP_B: &str = "198.51.100.20";

    fn meta(ip: &str) -> ClientMeta {
        ClientMeta { ip: ip.into(), user_agent: "test".into() }
    }

    fn code<T>(r: ApiResult<T>) -> &'static str {
        match r {
            Ok(_) => "ok",
            Err(e) => e.code,
        }
    }

    /// Corps d'inscription bien formé (clés générées pour l'occasion).
    fn register_body(email: &str, setup_token: Option<&str>) -> RegisterBody {
        let user_id = crypto::new_uuid();
        let cid = crypto::new_uuid();
        let user_key = SecretKey::generate();
        let (private, public) = crypto::generate_keypair();
        let ck = SecretKey::generate();
        serde_json::from_value(json!({
            "user_id": user_id,
            "email": email,
            "name": "Propriétaire",
            "auth_key": b64e(&[7u8; 32]),
            "kdf": KdfParams::recommended(),
            "wrapped_user_key": crypto::wrap_key(&user_key, &user_key, "test:user"),
            "recovery_wrapped_user_key": crypto::wrap_key(&user_key, &user_key, "test:recovery"),
            "recovery_auth": b64e(&[8u8; 32]),
            "public_key": b64e(&public),
            "wrapped_private_key": crypto::wrap_key(&user_key, &private, "test:private"),
            "personal_collection": {
                "id": cid,
                "enc_name": crypto::encrypt_str(&ck, "Personnel", "test:name"),
                "sealed_key": crypto::seal_key(&public, &ck, "test:collection").unwrap(),
            },
            "setup_token": setup_token,
        }))
        .expect("corps d'inscription valide")
    }

    async fn setup_record(st: &AppState) -> Option<String> {
        st.db
            .call(|c| Ok(c.query_row("SELECT value FROM settings WHERE key = 'setup_token'", [], |r| r.get(0)).optional()?))
            .await
            .unwrap()
    }

    /// Crée directement en base un compte dont la preuve d'authentification est
    /// `key`, avec (ou sans) double authentification. Renvoie l'id et le secret 2FA.
    async fn make_user(st: &AppState, email: &str, key: [u8; 32], with_totp: bool) -> (String, Option<String>) {
        let uid = crypto::new_uuid();
        let auth_hash = hash_secret(key.to_vec()).await.unwrap();
        let secret = with_totp.then(totp::generate_secret);
        let enc = secret.as_ref().map(|s| encrypt_totp_secret(st, &uid, s));
        let kdf = serde_json::to_string(&KdfParams::recommended()).unwrap();
        let (u, e) = (uid.clone(), email.to_string());
        st.db
            .call(move |c| {
                c.execute(
                    "INSERT INTO users (id, email, name, role, kdf, auth_hash, wrapped_user_key,
                        recovery_wrapped_user_key, recovery_auth_hash, public_key, wrapped_private_key,
                        totp_secret, created_at, updated_at)
                     VALUES (?1, ?2, 'Test', 'user', ?3, ?4, 'x', 'x', 'x', 'x', 'x', ?5, ?6, ?6)",
                    params![u, e, kdf, auth_hash, enc, now_unix()],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        (uid, secret)
    }

    fn login_req(email: &str, key: [u8; 32], totp: Option<String>, ticket: Option<&str>) -> LoginRequest {
        LoginRequest { email: email.into(), auth_key: b64e(&key), totp, device: None, sso_ticket: ticket.map(str::to_string) }
    }

    async fn try_login(st: &AppState, ip: &str, req: LoginRequest) -> &'static str {
        code(login(State(st.clone()), meta(ip), Json(req)).await)
    }

    async fn ticket_used(st: &AppState, ticket: &str) -> i64 {
        let h = sha256_hex(ticket);
        st.db
            .call(move |c| Ok(c.query_row("SELECT used FROM sso_tickets WHERE ticket_hash = ?1", [h], |r| r.get(0))?))
            .await
            .unwrap()
    }

    // ------------------------------------------------------------ Jeton d'installation

    #[tokio::test]
    async fn premier_compte_exige_le_jeton_d_installation() {
        let st = test_state().await;
        init_setup_token_with(&st.db, &st.config.data_dir, None).await.unwrap();
        let path = st.config.data_dir.join(SETUP_TOKEN_FILE);
        let token = std::fs::read_to_string(&path).unwrap().trim().to_string();
        assert!(token.len() >= 32);
        let record = setup_record(&st).await.expect("empreinte enregistrée");
        assert!(record.contains(&sha256_hex(&token)));
        assert!(!record.contains(&token), "le jeton en clair n'est jamais stocké en base");

        // Un redémarrage conserve le même jeton.
        init_setup_token_with(&st.db, &st.config.data_dir, None).await.unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), token);

        let reg = |t: Option<&str>| register_body("owner@example.com", t);
        assert_eq!(code(register(State(st.clone()), meta(IP_A), Json(reg(None))).await), "setup_token_required");
        assert_eq!(code(register(State(st.clone()), meta(IP_A), Json(reg(Some("  ")))).await), "setup_token_required");
        assert_eq!(
            code(register(State(st.clone()), meta(IP_A), Json(reg(Some("mauvais-jeton-xxxxxxxxxxxx")))).await),
            "invalid_setup_token"
        );
        let ok = register(State(st.clone()), meta(IP_A), Json(reg(Some(&token)))).await;
        assert_eq!(code(ok), "ok");

        // Jeton consommé : empreinte et fichier effacés, action journalisée.
        assert!(setup_record(&st).await.is_none());
        assert!(!path.exists());
        let audited: i64 = st
            .db
            .call(|c| Ok(c.query_row("SELECT COUNT(*) FROM audit WHERE action = 'setup.completed'", [], |r| r.get(0))?))
            .await
            .unwrap();
        assert_eq!(audited, 1);

        // Au redémarrage suivant, plus aucun jeton n'est créé.
        init_setup_token_with(&st.db, &st.config.data_dir, None).await.unwrap();
        assert!(!path.exists());
        assert!(setup_record(&st).await.is_none());
    }

    #[tokio::test]
    async fn jeton_d_installation_impose_par_l_environnement() {
        let st = test_state().await;
        let path = st.config.data_dir.join(SETUP_TOKEN_FILE);
        std::fs::write(&path, "ancien\n").unwrap();

        let short = init_setup_token_with(&st.db, &st.config.data_dir, Some("trop-court".into())).await;
        assert_eq!(code(short), "invalid_config");

        let token = "jeton-impose-par-l-administrateur";
        init_setup_token_with(&st.db, &st.config.data_dir, Some(token.into())).await.unwrap();
        assert!(!path.exists(), "aucun fichier quand le jeton vient de l'environnement");
        assert!(setup_record(&st).await.unwrap().contains(&sha256_hex(token)));

        let ok = register(State(st.clone()), meta(IP_A), Json(register_body("owner@example.com", Some(token)))).await;
        assert_eq!(code(ok), "ok");
        assert!(setup_record(&st).await.is_none());
    }

    #[tokio::test]
    async fn jeton_d_installation_efface_si_un_compte_existe() {
        let st = test_state().await;
        let path = st.config.data_dir.join(SETUP_TOKEN_FILE);
        init_setup_token_with(&st.db, &st.config.data_dir, None).await.unwrap();
        assert!(path.exists());
        make_user(&st, "someone@example.com", [1u8; 32], false).await;
        init_setup_token_with(&st.db, &st.config.data_dir, None).await.unwrap();
        assert!(!path.exists());
        assert!(setup_record(&st).await.is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fichier_du_jeton_en_0600() {
        use std::os::unix::fs::PermissionsExt;
        let st = test_state().await;
        init_setup_token_with(&st.db, &st.config.data_dir, None).await.unwrap();
        let mode = std::fs::metadata(st.config.data_dir.join(SETUP_TOKEN_FILE)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // ------------------------------------------------------------ 2FA après SSO

    #[tokio::test]
    async fn totp_exige_apres_un_ticket_sso_sans_le_consommer() {
        let st = test_state().await;
        let email = "alice@example.com";
        let key = [3u8; 32];
        let (uid, secret) = make_user(&st, email, key, true).await;
        let ticket = crypto::random_token();
        let (h, e, u) = (sha256_hex(&ticket), email.to_string(), uid.clone());
        st.db
            .call(move |c| {
                c.execute(
                    "INSERT INTO sso_tickets (ticket_hash, email, name, subject, user_id, expires_at)
                     VALUES (?1, ?2, '', 'sujet', ?3, ?4)",
                    params![h, e, u, now_unix() + 300],
                )?;
                Ok(())
            })
            .await
            .unwrap();

        // Ticket valide, pas de code : la 2FA est demandée et le ticket reste utilisable.
        assert_eq!(try_login(&st, IP_A, login_req(email, key, None, Some(&ticket))).await, "totp_required");
        assert_eq!(ticket_used(&st, &ticket).await, 0);

        // Code faux : refusé, ticket toujours intact.
        let cfg = totp::parse(&secret.unwrap()).unwrap();
        let now = now_unix() as u64;
        let valid: Vec<String> = [now - 30, now, now + 30].iter().map(|t| totp::code_at(&cfg, *t)).collect();
        let bad = (0..10).map(|d| format!("{d}{d}{d}{d}{d}{d}")).find(|c| !valid.contains(c)).unwrap();
        assert_eq!(try_login(&st, IP_A, login_req(email, key, Some(bad), Some(&ticket))).await, "invalid_totp");
        assert_eq!(ticket_used(&st, &ticket).await, 0);

        // Bon code : connexion, ticket consommé.
        let good = totp::code_at(&cfg, now_unix() as u64);
        assert_eq!(try_login(&st, IP_A, login_req(email, key, Some(good), Some(&ticket))).await, "ok");
        assert_eq!(ticket_used(&st, &ticket).await, 1);
    }

    #[tokio::test]
    async fn code_totp_manquant_ne_compte_pas_comme_un_echec() {
        let st = test_state().await;
        let email = "bob@example.com";
        let key = [4u8; 32];
        make_user(&st, email, key, true).await;
        for _ in 0..8 {
            assert_eq!(try_login(&st, IP_A, login_req(email, key, None, None)).await, "totp_required");
        }
    }

    // ------------------------------------------------------------ Verrouillage

    /// Blocages de 10 minutes : ils ne doivent pas expirer pendant le test,
    /// même sur une machine chargée.
    async fn long_lock(st: &AppState) {
        crate::tests::set_setting(st, "lockout.base_delay_seconds", json!(600)).await;
    }

    #[tokio::test]
    async fn blocage_par_paire_email_ip() {
        let st = test_state().await;
        let email = "carol@example.com";
        let key = [5u8; 32];
        make_user(&st, email, key, false).await;
        long_lock(&st).await;
        let wrong = [6u8; 32];
        for _ in 0..5 {
            assert_eq!(try_login(&st, IP_A, login_req(email, wrong, None, None)).await, "invalid_credentials");
        }
        // L'adresse A est bloquée pour ce compte, même avec le bon mot de passe.
        assert_eq!(try_login(&st, IP_A, login_req(email, key, None, None)).await, "rate_limited");
        // Une autre adresse peut encore tenter, et se connecter.
        assert_eq!(try_login(&st, IP_B, login_req(email, wrong, None, None)).await, "invalid_credentials");
        assert_eq!(try_login(&st, IP_B, login_req(email, key, None, None)).await, "ok");
        // La réussite depuis B ne lève pas le blocage de la paire A.
        assert_eq!(try_login(&st, IP_A, login_req(email, key, None, None)).await, "rate_limited");
    }

    #[tokio::test]
    async fn recuperation_comptee_avant_la_verification() {
        let st = test_state().await;
        let email = "frank@example.com";
        make_user(&st, email, [11u8; 32], false).await;
        let req = || RecoverStartRequest { email: email.into(), recovery_auth: b64e(&[12u8; 32]) };
        for i in 0..5 {
            let r = recover_start(State(st.clone()), meta(IP_A), Json(req())).await;
            assert_eq!(code(r), "unauthorized", "essai {i}");
        }
        // Le seuil est atteint : la sixième demande est refusée sans calcul.
        assert_eq!(code(recover_start(State(st.clone()), meta(IP_B), Json(req())).await), "rate_limited");
    }

    #[tokio::test]
    async fn blocage_par_email_a_un_seuil_plus_haut() {
        let st = test_state().await;
        let email = "dave@example.com";
        let key = [9u8; 32];
        make_user(&st, email, key, false).await;
        long_lock(&st).await;
        let wrong = [10u8; 32];
        // 50 échecs, chacun depuis une adresse différente : aucune paire n'est
        // bloquée, mais le seuil par adresse e-mail est atteint.
        for i in 0..50 {
            let ip = format!("192.0.2.{}", i + 1);
            assert_eq!(try_login(&st, &ip, login_req(email, wrong, None, None)).await, "invalid_credentials", "essai {i}");
        }
        assert_eq!(try_login(&st, "192.0.2.200", login_req(email, key, None, None)).await, "rate_limited");
        // Un autre compte n'est pas touché.
        let other = "erin@example.com";
        make_user(&st, other, key, false).await;
        assert_eq!(try_login(&st, "192.0.2.200", login_req(other, key, None, None)).await, "ok");
    }
}
