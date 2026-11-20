//! Connexion unique OpenID Connect (Entra ID, Okta, Google, Keycloak, ADFS…).
//!
//! Flux « authorization code » avec PKCE (S256), `state` et `nonce` à usage
//! unique ; le jeton d'identité est vérifié (signature via les clés publiées
//! par le fournisseur, émetteur, audience, expiration, nonce). Le serveur
//! remet ensuite un ticket à usage unique de 5 minutes.
//!
//! Les appels sortants vers le fournisseur (découverte, clés, jeton) passent
//! par un filtre anti-SSRF : adresses internes refusées après résolution DNS
//! et à chaque redirection, sauf dérogation explicite de l'hébergeur
//! (`LOCKSY_SSO_ALLOW_PRIVATE`, pour un fournisseur d'identité interne).
//!
//! Le SSO prouve l'identité ; il ne remplace pas le mot de passe maître, seul
//! capable de déchiffrer le coffre (chiffrement de bout en bout).

use crate::db;
use crate::error::{ApiError, ApiResult};
use crate::identity_admin;
use crate::security::sha256_hex;
use crate::state::{audit, audit_user, AdminUser, AppState, AuthUser, ClientMeta};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use crate::error::Json;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use locksy_core::api::*;
use locksy_core::crypto::{self, KdfParams};
use locksy_core::encoding::{b64e, percent_encode};
use locksy_core::now_unix;
use locksy_core::settings::Effective;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SETTINGS_KEY: &str = "sso";
const PENDING_TTL: Duration = Duration::from_secs(600);
const TICKET_TTL: i64 = 300;
/// Nombre maximal de demandes de connexion SSO en cours (après purge des expirées).
const PENDING_MAX: usize = 10_000;
/// Redirections suivies au plus lors d'un appel au fournisseur.
const MAX_REDIRECTS: usize = 3;
/// Préfixe des `state` d'un test de connexion : un retour expiré est alors
/// reconnu comme un test (et non comme une connexion ordinaire). Le point
/// n'apparaît jamais dans un jeton base64url.
const TEST_STATE_PREFIX: &str = "t.";
/// Page de l'administration qui reçoit le résultat d'un test SSO.
const TEST_RETURN: &str = "/#/admin/connexion/sso";
/// Tests de connexion d'entreprise (configuration et parcours réel) : au plus
/// 10 par administrateur et par fenêtre de 10 minutes (#56).
pub(crate) const IDENTITY_TEST_MAX: u32 = 10;
pub(crate) const IDENTITY_TEST_WINDOW: i64 = 600;

/// Identifiants des extensions de navigateur publiées par Locksy, toujours
/// acceptées comme destination de retour SSO. Le manifeste de l'extension n'a
/// pas de clé fixe : son identifiant dépend de l'installation, il n'y a donc
/// pas d'ID officiel. À renseigner si l'extension est publiée avec une clé.
pub(crate) const OFFICIAL_EXTENSION_IDS: &[&str] = &[];

// ------------------------------------------------------------ Configuration

/// Configuration SSO complète, telle qu'enregistrée sous la clé `"sso"` :
/// les champs de `SsoConfig` (à plat) et les réglages propres au serveur.
/// Une configuration enregistrée avant l'ajout de ces réglages se relit avec
/// leurs valeurs par défaut (aucune extension autorisée, e-mail vérifié exigé).
///
/// `enforce`, `public_url` et `allowed_extension_ids` sont des miroirs du
/// registre (`sso.enforce`, `instance.public_url`, `extension.allowed_ids`) :
/// les routes les lisent dans les réglages effectifs.
#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct SsoSettings {
    #[serde(flatten)]
    pub base: SsoConfig,
    /// Identifiants (32 lettres a à p) des extensions de navigateur autorisées
    /// à recevoir le résultat d'une connexion SSO.
    pub allowed_extension_ids: Vec<String>,
    /// Accepte une adresse e-mail que le fournisseur ne déclare pas vérifiée
    /// (Entra ID n'envoie pas `email_verified`).
    pub trust_unverified_email: bool,
}

/// Configuration enregistrée. L'URI de redirection n'est calculée que si
/// l'adresse publique est connue ; les routes la recalculent avec
/// [`public_base`] (adresse publique ou, à défaut, origine de la requête).
pub fn load_full_config(c: &Connection) -> ApiResult<SsoSettings> {
    let mut s: SsoSettings = db::load_json(c, SETTINGS_KEY)?;
    let cfg = &mut s.base;
    if cfg.label.is_empty() {
        cfg.label = "SSO de l'entreprise".into();
    }
    cfg.has_secret = !cfg.client_secret.is_empty();
    cfg.public_url = cfg.public_url.trim().trim_end_matches('/').to_string();
    cfg.redirect_uri = if cfg.public_url.is_empty() { String::new() } else { redirect_uri(&cfg.public_url) };
    Ok(s)
}

pub fn load_config(c: &Connection) -> ApiResult<SsoConfig> {
    Ok(load_full_config(c)?.base)
}

/// Le fournisseur est-il renseigné (émetteur et identifiant client) ?
pub(crate) fn is_configured(cfg: &SsoConfig) -> bool {
    !cfg.issuer.trim().is_empty() && !cfg.client_id.trim().is_empty()
}

fn redirect_uri(base: &str) -> String {
    format!("{}/api/sso/callback", base.trim_end_matches('/'))
}

/// Normalise et valide les identifiants d'extension saisis par l'administrateur.
fn clean_extension_ids(ids: &[String]) -> ApiResult<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for id in ids {
        let id = id.trim().to_ascii_lowercase();
        if id.is_empty() {
            continue;
        }
        if !extension_id_ok(&id) {
            return Err(ApiError::bad_request(
                "Identifiant d'extension invalide : 32 lettres a à p, visible dans chrome://extensions",
            ));
        }
        if !out.contains(&id) {
            out.push(id);
        }
    }
    Ok(out)
}

/// Forme d'un identifiant d'extension Chromium : 32 lettres de a à p.
pub(crate) fn extension_id_ok(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b))
}

/// Extension autorisée par l'organisation. Liste `extension.allowed_ids` VIDE :
/// toute extension Locksy est acceptée (aucun identifiant à déclarer). Liste
/// renseignée : seuls l'identifiant officiel et ceux de la liste, sans
/// distinction de casse. Un identifiant absent reste refusé.
/// (La connexion d'entreprise garde sa propre règle : `extension_redirect_ok`.)
pub(crate) fn extension_allowed(eff: &Effective, id: &str) -> bool {
    let id = id.trim();
    if id.is_empty() {
        return false;
    }
    let listed = eff.list("extension.allowed_ids");
    listed.is_empty()
        || OFFICIAL_EXTENSION_IDS.iter().any(|o| o.eq_ignore_ascii_case(id))
        || listed.iter().any(|a| a.eq_ignore_ascii_case(id))
}

pub fn public_info(c: &Connection) -> ApiResult<Option<SsoPublic>> {
    let cfg = load_config(c)?;
    Ok(cfg.enabled.then_some(SsoPublic { label: cfg.label, enforced: cfg.enforce }))
}

/// Booléen d'une variable de l'hébergeur, lu comme la validation de
/// démarrage (`config.rs`) ; une valeur illisible vaut « non » (dérogation
/// jamais accordée par erreur).
fn env_flag(name: &str) -> bool {
    std::env::var(name).ok().and_then(|v| crate::config::parse_bool(v.trim())).unwrap_or(false)
}

// ------------------------------------------------------------ Adresse publique

static ORIGIN_WARNED: AtomicBool = AtomicBool::new(false);

/// Adresse publique de Locksy : `instance.public_url`, sinon l'origine de la
/// requête (avec un avertissement unique dans les journaux : derrière un
/// proxy mal configuré, cette origine peut être fausse).
pub(crate) fn public_base(state: &AppState, eff: &Effective, headers: &HeaderMap) -> String {
    let configured = eff.str("instance.public_url").trim().trim_end_matches('/');
    if !configured.is_empty() {
        return configured.to_string();
    }
    if !ORIGIN_WARNED.swap(true, Ordering::Relaxed) {
        tracing::warn!("adresse publique (instance.public_url) non renseignée : origine de la requête utilisée");
    }
    request_origin(state, headers)
}

/// Origine de la requête : en-tête Host (et X-Forwarded-Proto derrière un
/// proxy de confiance). Un en-tête Host inattendu est ignoré.
fn request_origin(state: &AppState, headers: &HeaderMap) -> String {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).map(str::trim);
    let host_ok = |h: &&str| {
        !h.is_empty() && h.len() <= 255 && h.bytes().all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
    };
    let forwarded = state.config.trust_proxy.then(|| header("x-forwarded-host")).flatten();
    let host = forwarded
        .and_then(|h| h.split(',').next().map(str::trim))
        .filter(host_ok)
        .or_else(|| header("host").filter(host_ok))
        .map(str::to_string)
        .unwrap_or_else(|| state.config.bind.clone());
    let proto = state.config.trust_proxy.then(|| header("x-forwarded-proto")).flatten();
    let scheme = match proto.map(str::to_ascii_lowercase).as_deref() {
        Some("https") => "https",
        Some("http") => "http",
        _ if state.config.hsts => "https",
        _ => "http",
    };
    format!("{scheme}://{host}")
}

// ------------------------------------------------------------ Filtre anti-SSRF

/// Adresse interdite comme destination d'un appel au fournisseur d'identité :
/// boucle locale, réseaux privés et partagés, lien local, non spécifiée,
/// multidiffusion, réservée, et IPv4 transportée dans IPv6.
pub(crate) fn ip_forbidden(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_forbidden(v4),
        IpAddr::V6(v6) => v6_forbidden(v6),
    }
}

fn v4_forbidden(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    a == 0 // 0.0.0.0/8 (non spécifiée, « ce réseau »)
        || ip.is_loopback() // 127.0.0.0/8
        || ip.is_private() // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local() // 169.254/16 (métadonnées des clouds)
        || (a == 100 && (64..128).contains(&b)) // 100.64/10 (CGNAT)
        || (a == 192 && b == 0 && c == 0) // 192.0.0.0/24
        || (a == 198 && (b == 18 || b == 19)) // 198.18/15 (bancs d'essai)
        || ip.is_multicast() // 224/4
        || a >= 240 // 240/4 réservé et diffusion
}

fn v6_forbidden(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    let embedded = |hi: u16, lo: u16| Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo));
    s[..6] == [0; 6] // ::/96 : non spécifiée, boucle locale, IPv4 compatible
        || ip.to_ipv4_mapped().is_some() // ::ffff:0:0/96
        || ip.is_multicast() // ff00::/8
        || (s[0] & 0xfe00) == 0xfc00 // fc00::/7 (adresses locales uniques)
        || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 (lien local)
        || (s[0] & 0xffc0) == 0xfec0 // fec0::/10 (site local, obsolète)
        || (s[0] == 0x64 && s[1] == 0xff9b && v4_forbidden(embedded(s[6], s[7]))) // NAT64
        || (s[0] == 0x2002 && v4_forbidden(embedded(s[1], s[2]))) // 6to4
}

/// Refus du filtre, reconnu dans la chaîne d'erreurs de reqwest.
#[derive(Debug)]
struct SsrfBlocked(String);

const SSRF_MARK: &str = "filtre anti-SSRF";

impl std::fmt::Display for SsrfBlocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "adresse interne refusée ({SSRF_MARK}) : {}", self.0)
    }
}

impl std::error::Error for SsrfBlocked {}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Résolution DNS filtrée : le nom est refusé si UNE de ses adresses est
/// interdite (un enregistrement mixte ne permet pas d'atteindre le réseau
/// interne). La connexion utilise exactement les adresses vérifiées, ce qui
/// ferme la porte au « DNS rebinding ».
async fn resolve_checked(host: &str) -> Result<Vec<SocketAddr>, BoxError> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, 0)).await?.collect();
    if addrs.is_empty() {
        return Err(format!("aucune adresse pour {host}").into());
    }
    if let Some(bad) = addrs.iter().find(|a| ip_forbidden(a.ip())) {
        return Err(Box::new(SsrfBlocked(format!("{host} ({})", bad.ip()))));
    }
    Ok(addrs)
}

struct GuardedResolver;

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs = resolve_checked(&host).await?;
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Cible directe d'un appel : une adresse IP littérale ou un nom local
/// échappent au résolveur, ils sont donc contrôlés ici.
fn target_blocked(url: &url::Url) -> Option<SsrfBlocked> {
    match url.host() {
        Some(url::Host::Ipv4(ip)) if v4_forbidden(ip) => Some(SsrfBlocked(ip.to_string())),
        Some(url::Host::Ipv6(ip)) if v6_forbidden(ip) => Some(SsrfBlocked(ip.to_string())),
        Some(url::Host::Domain(d)) => {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            (d == "localhost" || d.ends_with(".localhost")).then_some(SsrfBlocked(d))
        }
        Some(_) => None,
        None => Some(SsrfBlocked("adresse sans hôte".into())),
    }
}

/// Décision pour une redirection du fournisseur (`previous` : adresses déjà
/// demandées, la première comprise) : au plus `MAX_REDIRECTS` sauts, https
/// seulement, et la cible refiltrée.
fn redirect_refused(url: &url::Url, previous: usize) -> Option<BoxError> {
    if previous > MAX_REDIRECTS {
        return Some(format!("plus de {MAX_REDIRECTS} redirections").into());
    }
    if url.scheme() != "https" {
        return Some(format!("redirection non chiffrée refusée : {}", url.scheme()).into());
    }
    target_blocked(url).map(|b| Box::new(b) as BoxError)
}

// ------------------------------------------------------------ Échecs du fournisseur

/// Échec d'un échange avec le fournisseur d'identité ou l'annuaire Active
/// Directory : code stable (traduit dans `errors.identity.json`) et détail
/// technique, qui ne va que dans les journaux et dans les « Détails
/// techniques » des routes d'administration.
#[derive(Debug)]
pub(crate) struct IdpFail {
    pub code: &'static str,
    pub technical: String,
}

impl IdpFail {
    pub(crate) fn new(code: &'static str, technical: impl Into<String>) -> Self {
        Self { code, technical: technical.into() }
    }

    /// Erreur d'API correspondante : message français, jamais le texte du fournisseur.
    pub(crate) fn to_api(&self) -> ApiError {
        match self.code {
            "ssrf_blocked" => ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "ssrf_blocked",
                "Adresse du fournisseur d'identité refusée : elle désigne le réseau interne du serveur.",
            ),
            "idp_insecure_url" => ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "idp_insecure_url",
                "Le fournisseur d'identité doit être joint en https://.",
            ),
            "idp_issuer_mismatch" => ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "idp_issuer_mismatch",
                "L'émetteur annoncé par le fournisseur ne correspond pas à celui configuré.",
            ),
            "idp_invalid_response" => ApiError::new(
                StatusCode::BAD_GATEWAY,
                "idp_invalid_response",
                "Réponse du fournisseur d'identité illisible.",
            ),
            "idp_token_refused" => ApiError::new(
                StatusCode::BAD_GATEWAY,
                "idp_token_refused",
                "Le fournisseur d'identité a refusé l'échange du code (vérifiez l'identifiant client, le secret et l'URI de redirection).",
            ),
            "id_token_invalid" => ApiError::new(
                StatusCode::BAD_GATEWAY,
                "id_token_invalid",
                "Jeton d'identité du fournisseur refusé.",
            ),
            "idp_denied" => ApiError::new(
                StatusCode::FORBIDDEN,
                "idp_denied",
                "Le fournisseur d'identité a refusé la connexion.",
            ),
            "invalid_config" => ApiError::new(
                StatusCode::CONFLICT,
                "invalid_config",
                "Configuration de la connexion d'entreprise incomplète ou illisible.",
            ),
            "sso_busy" => ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "sso_busy",
                "Trop de connexions SSO en cours. Réessayez dans un instant.",
            )
            .with_retry_after(5),
            "ldap_unreachable" => ApiError::new(
                StatusCode::BAD_GATEWAY,
                "ldap_unreachable",
                "Contrôleur de domaine injoignable ou certificat refusé.",
            ),
            "ldap_timeout" => ApiError::new(
                StatusCode::GATEWAY_TIMEOUT,
                "ldap_timeout",
                "L'annuaire n'a pas répondu à temps.",
            ),
            "ldap_bind_refused" => ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "ldap_bind_refused",
                "Le compte de service a été refusé par l'annuaire (identifiant ou mot de passe).",
            ),
            "ldap_search_failed" => ApiError::new(
                StatusCode::BAD_GATEWAY,
                "ldap_search_failed",
                "La recherche dans l'annuaire a échoué (racine de recherche, groupe ou droits du compte de service).",
            ),
            _ => ApiError::new(StatusCode::BAD_GATEWAY, "idp_unreachable", "Fournisseur d'identité injoignable."),
        }
    }
}

/// Erreur d'une route de test : code et message stables, détail du
/// fournisseur dans `technical` (affiché dans « Détails techniques »).
pub(crate) struct TestError {
    pub(crate) err: ApiError,
    pub(crate) technical: Option<String>,
}

impl From<ApiError> for TestError {
    fn from(err: ApiError) -> Self {
        Self { err, technical: None }
    }
}

impl From<IdpFail> for TestError {
    fn from(f: IdpFail) -> Self {
        Self { err: f.to_api(), technical: Some(f.technical) }
    }
}

impl IntoResponse for TestError {
    fn into_response(self) -> Response {
        let Some(t) = self.technical else { return self.err.into_response() };
        let mut body = json!({ "error": self.err.code, "message": self.err.message, "technical": t });
        if let Some(s) = self.err.retry_after {
            body["retry_after"] = s.into();
        }
        let mut res = (self.err.status, Json(body)).into_response();
        if let Some(s) = self.err.retry_after {
            res.headers_mut().insert(axum::http::header::RETRY_AFTER, axum::http::HeaderValue::from(s));
        }
        res
    }
}

/// Code d'une erreur de reqwest : refus du filtre (redirection ou
/// résolution DNS) ou fournisseur injoignable.
fn classify(e: &reqwest::Error) -> IdpFail {
    let mut src: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(s) = src {
        if s.downcast_ref::<SsrfBlocked>().is_some() || s.to_string().contains(SSRF_MARK) {
            return IdpFail::new("ssrf_blocked", s.to_string());
        }
        src = s.source();
    }
    let mut detail = e.to_string();
    let mut src = std::error::Error::source(e);
    while let Some(s) = src {
        detail.push_str(" : ");
        detail.push_str(&s.to_string());
        src = s.source();
    }
    IdpFail::new("idp_unreachable", detail)
}

/// Journalise un échec du fournisseur ; un refus du filtre anti-SSRF est en
/// plus inscrit au journal d'audit (`sso.discovery_blocked`, critique).
pub(crate) async fn note_failure(state: &AppState, fail: &IdpFail, actor: Option<&AuthUser>, meta: &ClientMeta) {
    tracing::warn!(code = fail.code, detail = %fail.technical, "échange avec le fournisseur d'identité en échec");
    if fail.code != "ssrf_blocked" {
        return;
    }
    let (uid, email) = actor.map(|a| (Some(a.id.clone()), a.email.clone())).unwrap_or((None, String::new()));
    let (meta, detail) = (meta.clone(), fail.technical.chars().take(200).collect::<String>());
    let r = state
        .db
        .call(move |c| audit(c, uid.as_deref(), &email, "sso.discovery_blocked", "", &meta, &detail))
        .await;
    if let Err(e) = r {
        tracing::warn!(message = %e.message, "journalisation du refus anti-SSRF impossible");
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
    /// Port de la boucle locale et `client_state` tiré par le client de bureau
    /// (renvoyé tel quel au retour : le client ignore tout retour qui ne le
    /// porte pas, un tiers local ne peut donc ni injecter un ticket ni faire
    /// échouer le flux). Absent pour les anciens clients.
    Desktop(u16, Option<String>),
    Extension(String),
}

struct Pending {
    nonce: String,
    verifier: String,
    return_to: ReturnTo,
    /// Adresse publique au démarrage : URI de redirection et page de retour.
    base: String,
    /// Test de connexion lancé par cet administrateur (aucun ticket émis).
    test_by: Option<AuthUser>,
    created: Instant,
}

pub struct SsoRuntime {
    /// Client filtré (anti-SSRF) : cas général.
    http: reqwest::Client,
    /// Client sans filtre, avec la dérogation de l'hébergeur.
    http_open: reqwest::Client,
    pending: Mutex<HashMap<String, Pending>>,
    discovery: Mutex<Option<(String, Instant, Discovery)>>,
    jwks: Mutex<Option<(String, Instant, JwkSet)>>,
    /// Dérogation explicite : fournisseur d'identité sur le réseau interne
    /// (`LOCKSY_SSO_ALLOW_PRIVATE`, impliquée par `LOCKSY_SSO_ALLOW_HTTP`).
    pub(crate) allow_private: bool,
    /// Fournisseur joint en HTTP clair (`LOCKSY_SSO_ALLOW_HTTP`, essais seulement).
    pub(crate) allow_http: bool,
}

impl Default for SsoRuntime {
    fn default() -> Self {
        let allow_http = env_flag("LOCKSY_SSO_ALLOW_HTTP");
        Self::new(allow_http, allow_http || env_flag("LOCKSY_SSO_ALLOW_PRIVATE"))
    }
}

impl SsoRuntime {
    /// État sans lecture de l'environnement (tests et démarrage).
    pub(crate) fn new(allow_http: bool, allow_private: bool) -> Self {
        let builder = || {
            reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .user_agent(concat!("Locksy/", env!("CARGO_PKG_VERSION")))
        };
        let http = builder()
            .dns_resolver(Arc::new(GuardedResolver))
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                match redirect_refused(attempt.url(), attempt.previous().len()) {
                    None => attempt.follow(),
                    Some(e) => attempt.error(e),
                }
            }))
            .build()
            .expect("client HTTP");
        let http_open =
            builder().redirect(reqwest::redirect::Policy::limited(MAX_REDIRECTS)).build().expect("client HTTP");
        Self {
            http,
            http_open,
            pending: Mutex::new(HashMap::new()),
            discovery: Mutex::new(None),
            jwks: Mutex::new(None),
            allow_private,
            allow_http,
        }
    }

    /// Client HTTP à utiliser, et contrôle de la cible directe.
    fn client_for(&self, url: &str) -> Result<&reqwest::Client, IdpFail> {
        let u = url::Url::parse(url).map_err(|e| IdpFail::new("invalid_config", format!("adresse invalide : {e}")))?;
        if self.allow_private {
            return Ok(&self.http_open);
        }
        match target_blocked(&u) {
            Some(b) => Err(IdpFail::new("ssrf_blocked", b.to_string())),
            None => Ok(&self.http),
        }
    }

    /// Adresse d'un point du fournisseur : https obligatoire (sauf dérogation
    /// d'essai `LOCKSY_SSO_ALLOW_HTTP`).
    fn check_url(&self, url: &str) -> Result<(), IdpFail> {
        let u = url::Url::parse(url).map_err(|e| IdpFail::new("invalid_config", format!("{url} : {e}")))?;
        match u.scheme() {
            "https" => Ok(()),
            "http" if self.allow_http => Ok(()),
            s => Err(IdpFail::new("idp_insecure_url", format!("{url} : schéma {s}"))),
        }
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T, IdpFail> {
        let resp = self.client_for(url)?.get(url).send().await.map_err(|e| classify(&e))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(IdpFail::new("idp_unreachable", format!("{url} : HTTP {status}")));
        }
        resp.json().await.map_err(|e| IdpFail::new("idp_invalid_response", format!("{url} : {e}")))
    }

    async fn discover(&self, issuer: &str) -> Result<Discovery, IdpFail> {
        if let Some((iss, at, d)) = self.discovery.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            if iss == issuer && at.elapsed() < Duration::from_secs(3600) {
                return Ok(d.clone());
            }
        }
        self.check_url(issuer)?;
        let url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
        let d: Discovery = self.get_json(&url).await?;
        if d.issuer.trim_end_matches('/') != issuer.trim_end_matches('/') {
            return Err(IdpFail::new("idp_issuer_mismatch", format!("émetteur annoncé : {}", d.issuer)));
        }
        for u in [&d.authorization_endpoint, &d.token_endpoint, &d.jwks_uri] {
            self.check_url(u)?;
        }
        *self.discovery.lock().unwrap_or_else(|p| p.into_inner()) = Some((issuer.to_string(), Instant::now(), d.clone()));
        Ok(d)
    }

    async fn keys(&self, jwks_uri: &str, force: bool) -> Result<JwkSet, IdpFail> {
        if !force {
            if let Some((uri, at, k)) = self.jwks.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
                if uri == jwks_uri && at.elapsed() < Duration::from_secs(3600) {
                    return Ok(k.clone());
                }
            }
        }
        let k: JwkSet = self.get_json(jwks_uri).await?;
        *self.jwks.lock().unwrap_or_else(|p| p.into_inner()) = Some((jwks_uri.to_string(), Instant::now(), k.clone()));
        Ok(k)
    }

    /// Échange du code d'autorisation contre le jeton d'identité.
    async fn exchange(&self, token_endpoint: &str, form: &[(&str, &str)]) -> Result<TokenResponse, IdpFail> {
        let resp = self.client_for(token_endpoint)?.post(token_endpoint).form(form).send().await.map_err(|e| classify(&e))?;
        let status = resp.status();
        if !status.is_success() {
            let body: String = resp.text().await.unwrap_or_default().chars().take(300).collect();
            return Err(IdpFail::new("idp_token_refused", format!("HTTP {status} : {body}")));
        }
        resp.json().await.map_err(|e| IdpFail::new("idp_invalid_response", format!("réponse sans jeton d'identité : {e}")))
    }

    /// Mémorise une demande en cours. Les demandes expirées sont purgées
    /// d'abord ; si la table reste pleine, la demande est refusée (et non
    /// silencieusement perdue, ce qui donnait un « état inconnu » au retour).
    fn put_pending(&self, state: String, p: Pending) -> ApiResult<()> {
        let mut map = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        map.retain(|_, v| v.created.elapsed() < PENDING_TTL);
        if map.len() >= PENDING_MAX {
            tracing::warn!(pending = map.len(), "table des connexions SSO en cours saturée");
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "sso_busy",
                "Trop de connexions SSO en cours. Réessayez dans un instant.",
            ));
        }
        map.insert(state, p);
        Ok(())
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
    /// Valeur aléatoire du client de bureau, renvoyée sur la boucle locale.
    #[serde(default)]
    client_state: Option<String>,
}

/// `client_state` : 16 à 128 caractères base64url, rien d'autre (la valeur est
/// recopiée dans une adresse de redirection).
fn client_state_ok(s: &str) -> bool {
    (16..=128).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Une redirection d'extension n'est acceptée que vers
/// `https://<id>.chromiumapp.org/…`, pour un identifiant déclaré par
/// l'administrateur (ou officiel) : sans cela, n'importe quelle extension
/// installée pourrait se faire remettre un ticket SSO.
fn extension_redirect_ok(r: &str, allowed: &[String]) -> bool {
    let Ok(u) = url::Url::parse(r) else { return false };
    if u.scheme() != "https" || u.port().is_some() || !u.username().is_empty() || u.password().is_some() {
        return false;
    }
    let Some(host) = u.host_str().map(str::to_ascii_lowercase) else { return false };
    let Some(id) = host.strip_suffix(".chromiumapp.org") else { return false };
    !id.is_empty() && (allowed.iter().any(|a| a.eq_ignore_ascii_case(id)) || OFFICIAL_EXTENSION_IDS.contains(&id))
}

/// Adresse d'autorisation chez le fournisseur et demande en cours associée.
async fn begin(state: &AppState, cfg: &SsoConfig, base: String, return_to: ReturnTo, test_by: Option<AuthUser>) -> Result<String, IdpFail> {
    let d = state.sso.discover(&cfg.issuer).await?;
    let st = if test_by.is_some() { format!("{TEST_STATE_PREFIX}{}", crypto::random_token()) } else { crypto::random_token() };
    let nonce = crypto::random_token();
    let verifier = crypto::random_token();
    let challenge = b64e(&Sha256::digest(verifier.as_bytes()));
    let mut url = url::Url::parse(&d.authorization_endpoint)
        .map_err(|e| IdpFail::new("idp_invalid_response", format!("point d'autorisation : {e}")))?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &cfg.client_id)
        .append_pair("redirect_uri", &redirect_uri(&base))
        .append_pair("scope", "openid email profile")
        .append_pair("state", &st)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("prompt", "select_account");
    let pending = Pending { nonce, verifier, return_to, base, test_by, created: Instant::now() };
    state.sso.put_pending(st, pending).map_err(|e| IdpFail::new("sso_busy", e.message))?;
    Ok(url.into())
}

pub async fn start(
    State(state): State<AppState>,
    meta: ClientMeta,
    headers: HeaderMap,
    Query(q): Query<StartQuery>,
) -> ApiResult<Redirect> {
    state.limiter.hit(&format!("sso-start:{}", meta.rate_key()), 30, 60)?;
    let cfg = state.db.call(|c| load_config(c)).await?;
    if !cfg.enabled || !is_configured(&cfg) {
        return Err(ApiError::not_found("La connexion unique n'est pas configurée."));
    }
    let eff = state.effective().await?;
    let return_to = match q.target.as_str() {
        "desktop" => {
            let port = q.port.filter(|p| *p >= 1024).ok_or_else(|| ApiError::bad_request("Port local invalide."))?;
            if q.client_state.as_deref().is_some_and(|cs| !client_state_ok(cs)) {
                return Err(ApiError::bad_request("Paramètre client_state invalide."));
            }
            ReturnTo::Desktop(port, q.client_state)
        }
        "extension" => {
            let allowed = eff.list("extension.allowed_ids");
            let r = q.redirect.filter(|r| extension_redirect_ok(r, &allowed)).ok_or_else(|| {
                ApiError::new(StatusCode::BAD_REQUEST, "extension_not_allowed", "Cette extension n'est pas autorisée par votre administrateur.")
            })?;
            ReturnTo::Extension(r)
        }
        _ => ReturnTo::Web,
    };
    let base = public_base(&state, &eff, &headers);
    match begin(&state, &cfg, base, return_to, None).await {
        Ok(url) => Ok(Redirect::to(&url)),
        Err(f) if f.code == "sso_busy" => Err(f.to_api()),
        Err(f) => {
            note_failure(&state, &f, None, &meta).await;
            Err(f.to_api())
        }
    }
}

/// Démarre un VRAI parcours SSO en mode test pour l'administrateur
/// (`POST /admin/sso/test-start`) : le retour enregistre le résultat dans
/// `identity_tests` sans émettre de ticket.
pub async fn test_start(State(state): State<AppState>, AdminUser(admin): AdminUser, headers: HeaderMap) -> Result<Json<serde_json::Value>, TestError> {
    state.limiter.hit(&format!("idtest-sso:{}", admin.id), IDENTITY_TEST_MAX, IDENTITY_TEST_WINDOW)?;
    let cfg = state.db.call(|c| load_config(c)).await?;
    if !is_configured(&cfg) {
        return Err(IdpFail::new("invalid_config", "émetteur ou identifiant client manquant").into());
    }
    let eff = state.effective().await?;
    let base = public_base(&state, &eff, &headers);
    let meta = admin.meta.clone();
    match begin(&state, &cfg, base, ReturnTo::Web, Some(admin.clone())).await {
        Ok(url) => Ok(Json(json!({ "url": url }))),
        Err(f) => {
            note_failure(&state, &f, Some(&admin), &meta).await;
            Err(f.into())
        }
    }
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

fn finish_url(base: &str, to: &ReturnTo, result: Result<String, String>) -> String {
    let (key, value) = match &result {
        Ok(t) => ("ticket", t.as_str()),
        Err(e) => ("error", e.as_str()),
    };
    let value = percent_encode(value);
    match to {
        ReturnTo::Web => format!("{}/#/sso?{key}={value}", base.trim_end_matches('/')),
        ReturnTo::Desktop(port, None) => format!("http://127.0.0.1:{port}/sso?{key}={value}"),
        ReturnTo::Desktop(port, Some(cs)) => {
            format!("http://127.0.0.1:{port}/sso?{key}={value}&client_state={}", percent_encode(cs))
        }
        ReturnTo::Extension(r) => format!("{}#{key}={value}", r.split('#').next().unwrap_or(r)),
    }
}

/// Page de résultat d'un test : `?test=ok` ou `?test=erreur&code=<code>`.
fn test_url(base: &str, result: Result<(), &str>) -> String {
    let base = base.trim_end_matches('/');
    match result {
        Ok(()) => format!("{base}{TEST_RETURN}?test=ok"),
        Err(code) => format!("{base}{TEST_RETURN}?test=erreur&code={}", percent_encode(code)),
    }
}

pub async fn callback(State(state): State<AppState>, meta: ClientMeta, headers: HeaderMap, Query(q): Query<CallbackQuery>) -> Redirect {
    let state_param = q.state.clone().unwrap_or_default();
    let Some(pending) = state.sso.take_pending(&state_param) else {
        let base = match state.effective().await {
            Ok(eff) => public_base(&state, &eff, &headers),
            Err(_) => request_origin(&state, &headers),
        };
        if state_param.starts_with(TEST_STATE_PREFIX) {
            return Redirect::to(&test_url(&base, Err("identity_test_expired")));
        }
        return Redirect::to(&finish_url(&base, &ReturnTo::Web, Err("Demande de connexion expirée ou inconnue. Recommencez.".into())));
    };
    if let Some(actor) = pending.test_by.clone() {
        let result = run_test(&state, &pending, &q, &actor).await;
        return Redirect::to(&test_url(&pending.base, result));
    }
    let result = match state.db.call(|c| load_full_config(c)).await {
        Err(e) => Err(e.message),
        Ok(full) => match (&q.error, &q.code) {
            (Some(e), _) => {
                let detail = q.error_description.clone().unwrap_or_else(|| e.clone());
                tracing::warn!(error = %e, detail = %detail.chars().take(300).collect::<String>(), "connexion refusée par le fournisseur d'identité");
                Err(IdpFail::new("idp_denied", detail).to_api().message)
            }
            (None, Some(code)) => authenticate(&state, &full, &pending, code, &meta).await.map_err(|e| e.message),
            (None, None) => Err("Réponse du fournisseur incomplète.".into()),
        },
    };
    Redirect::to(&finish_url(&pending.base, &pending.return_to, result))
}

/// Retour d'un test : identité vérifiée comme une vraie connexion, puis
/// comparée au compte de l'administrateur. Résultat enregistré
/// (`identity_tests`, audit `sso.tested`) ; renvoie le code d'échec.
async fn run_test(state: &AppState, pending: &Pending, q: &CallbackQuery, actor: &AuthUser) -> Result<(), &'static str> {
    let outcome: Result<(), IdpFail> = async {
        let full = state.db.call(|c| load_full_config(c)).await.map_err(|e| IdpFail::new("invalid_config", e.message))?;
        let code = match (&q.error, &q.code) {
            (Some(e), _) => return Err(IdpFail::new("idp_denied", q.error_description.clone().unwrap_or_else(|| e.clone()))),
            (None, Some(code)) => code,
            (None, None) => return Err(IdpFail::new("idp_invalid_response", "retour sans code d'autorisation")),
        };
        let id = verify_identity(state, &full, pending, code).await?;
        let email = id.email.as_deref().map(crate::security::normalize_email).and_then(Result::ok);
        match email {
            None => Err(IdpFail::new("email_missing", "aucune adresse e-mail dans le jeton d'identité")),
            Some(e) if !e.eq_ignore_ascii_case(&actor.email) => {
                Err(IdpFail::new("email_mismatch", "l'adresse du fournisseur n'est pas celle de l'administrateur"))
            }
            Some(_) => Ok(()),
        }
    }
    .await;
    if let Err(f) = &outcome {
        note_failure(state, f, Some(actor), &actor.meta).await;
    }
    let code = outcome.as_ref().err().map(|f| f.code);
    let a = actor.clone();
    let recorded = state.db.call(move |c| identity_admin::record_test(c, "sso", &a, code)).await;
    if let Err(e) = recorded {
        tracing::warn!(message = %e.message, "enregistrement du test SSO impossible");
    }
    outcome.map_err(|f| f.code)
}

/// Interprète la revendication `email_verified` : seule une valeur vraie
/// explicite (booléen ou chaîne « true ») prouve la vérification. Absente ou
/// autre, on applique le choix de l'administrateur (`trust_unverified_email`).
fn email_verified(v: Option<&serde_json::Value>, trust_unverified: bool) -> bool {
    match v {
        Some(serde_json::Value::Bool(true)) => true,
        Some(serde_json::Value::String(s)) if s.eq_ignore_ascii_case("true") => true,
        _ => trust_unverified,
    }
}

/// Identité prouvée par le fournisseur.
struct Identity {
    email: Option<String>,
    verified: bool,
    subject: String,
    name: String,
}

/// Échange le code et vérifie le jeton d'identité.
async fn verify_identity(state: &AppState, full: &SsoSettings, pending: &Pending, code: &str) -> Result<Identity, IdpFail> {
    let cfg = &full.base;
    let d = state.sso.discover(&cfg.issuer).await?;
    let secret = if cfg.client_secret.is_empty() {
        String::new()
    } else {
        crypto::decrypt_string(&state.server_key, &cfg.client_secret, "verrou:v1:sso-client-secret")
            .map_err(|_| IdpFail::new("invalid_config", "secret SSO illisible"))?
    };
    let redirect = redirect_uri(&pending.base);
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect.as_str()),
        ("client_id", cfg.client_id.as_str()),
        ("code_verifier", pending.verifier.as_str()),
    ];
    if !secret.is_empty() {
        form.push(("client_secret", secret.as_str()));
    }
    let tokens = state.sso.exchange(&d.token_endpoint, &form).await?;

    // Vérification du jeton d'identité.
    let invalid = |what: String| IdpFail::new("id_token_invalid", what);
    let header = jsonwebtoken::decode_header(&tokens.id_token).map_err(|e| invalid(format!("jeton malformé : {e}")))?;
    const ALLOWED: [Algorithm; 8] = [
        Algorithm::RS256, Algorithm::RS384, Algorithm::RS512, Algorithm::PS256,
        Algorithm::PS384, Algorithm::PS512, Algorithm::ES256, Algorithm::ES384,
    ];
    if !ALLOWED.contains(&header.alg) {
        return Err(invalid(format!("algorithme refusé : {:?}", header.alg)));
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
            find(&keys).ok_or_else(|| invalid("clé de signature inconnue".into()))?
        }
    };
    let key = DecodingKey::from_jwk(&jwk).map_err(|e| invalid(format!("clé inutilisable : {e}")))?;
    let mut v = Validation::new(header.alg);
    v.set_issuer(&[d.issuer.as_str()]);
    v.set_audience(&[cfg.client_id.as_str()]);
    v.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    v.leeway = 60;
    let claims = jsonwebtoken::decode::<Claims>(&tokens.id_token, &key, &v).map_err(|e| invalid(e.to_string()))?.claims;
    if claims.nonce.as_deref() != Some(pending.nonce.as_str()) {
        return Err(invalid("nonce invalide (jeton rejoué ou détourné)".into()));
    }
    let email = claims.email.or(claims.preferred_username).or(claims.upn).filter(|e| e.contains('@'));
    Ok(Identity {
        email,
        verified: email_verified(claims.email_verified.as_ref(), full.trust_unverified_email),
        subject: format!("{}|{}", d.issuer, claims.sub),
        name: claims.name.unwrap_or_default(),
    })
}

async fn authenticate(state: &AppState, full: &SsoSettings, pending: &Pending, code: &str, meta: &ClientMeta) -> ApiResult<String> {
    let cfg = &full.base;
    let id = match verify_identity(state, full, pending, code).await {
        Ok(id) => id,
        Err(f) => {
            note_failure(state, &f, None, meta).await;
            return Err(f.to_api());
        }
    };
    // Entra ID n'envoie pas `email_verified` : l'administrateur doit alors
    // cocher « Accepter les adresses e-mail non vérifiées ». Le refus d'une
    // adresse non vérifiée est appliqué par `issue_ticket`, uniquement quand
    // l'adresse sert à trouver ou créer un compte (pas pour un compte déjà lié).
    let email = id.email.ok_or_else(|| {
        ApiError::new(
            StatusCode::FORBIDDEN,
            "email_missing",
            "Le fournisseur n'a pas transmis d'adresse e-mail (ajoutez l'étendue « email »).",
        )
    })?;
    let email = crate::security::normalize_email(&email)?;
    let eff = state.effective().await?;
    let domain = email.rsplit('@').next().unwrap_or_default();
    let sso_domain_ok = cfg.allowed_domains.is_empty() || cfg.allowed_domains.iter().any(|d| d.trim().eq_ignore_ascii_case(domain));
    if !sso_domain_ok || !crate::security::email_domain_allowed(&eff, &email) {
        let (e, m) = (email.clone(), meta.clone());
        state.db.call(move |c| audit(c, None, &e, "sso.denied", &e, &m, "domaine non autorisé")).await?;
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "domain_not_allowed",
            "Votre domaine de messagerie n'est pas autorisé par votre organisation.",
        ));
    }
    let meta = meta.clone();
    // Rattachement automatique d'un compte existant par son adresse : seulement
    // si l'adresse est vérifiée ET restreinte aux domaines de l'entreprise.
    // Sans liste de domaines, n'importe quel compte du fournisseur (Google,
    // locataire Entra multi-organisation…) pourrait revendiquer l'adresse.
    let restricted = !cfg.allowed_domains.is_empty() || !eff.list("access.allowed_email_domains").is_empty();
    let trust = IdentityTrust { email_verified: id.verified, link_by_email: id.verified && restricted };
    let (name, subject) = (id.name, id.subject);
    state.db.call(move |c| issue_ticket(c, &email, &name, &subject, &meta, trust)).await
}

/// Degré de confiance accordé à l'adresse e-mail d'une identité fédérée.
#[derive(Clone, Copy, Debug)]
pub struct IdentityTrust {
    /// L'adresse est prouvée : un ticket d'inscription peut être émis pour elle.
    pub email_verified: bool,
    /// Un compte existant non lié peut être rattaché à cette identité par l'adresse.
    pub link_by_email: bool,
}

/// Refus d'un compte désactivé ou dont l'accès a expiré (`access_until`).
fn account_gate(c: &Connection, user_id: &str) -> ApiResult<()> {
    let row: Option<(bool, Option<i64>)> = c
        .query_row("SELECT disabled, access_until FROM users WHERE id = ?1", [user_id], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?;
    match row {
        Some((true, _)) => Err(ApiError::new(StatusCode::FORBIDDEN, "account_disabled", "Ce compte est désactivé.")),
        Some((false, Some(until))) if until <= now_unix() => Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "account_expired",
            "L'accès de ce compte a expiré. Contactez votre administrateur.",
        )),
        _ => Ok(()),
    }
}

/// Retrouve ou rattache le compte de cette identité, applique les refus
/// (adresse non vérifiée, rattachement interdit, compte désactivé ou expiré,
/// annuaire désactivé) et émet un ticket à usage unique.
/// Commun au SSO OpenID Connect et à la connexion par compte Windows.
///
/// Un compte déjà lié par son sujet (`sso_subject`) est reconnu même si
/// l'adresse n'est pas vérifiée : le sujet, signé par le fournisseur, suffit.
pub fn issue_ticket(c: &Connection, email: &str, name: &str, subject: &str, meta: &ClientMeta, trust: IdentityTrust) -> ApiResult<String> {
    let (email, name, subject, meta) = (email.to_string(), name.to_string(), subject.to_string(), meta.clone());
    let by_subject: Option<String> =
        c.query_row("SELECT id FROM users WHERE sso_subject = ?1", [&subject], |r| r.get(0)).optional()?;
    let user = match by_subject {
        Some(u) => Some(u),
        None => {
            let by_email: Option<(String, Option<String>)> = c
                .query_row("SELECT id, sso_subject FROM users WHERE email = ?1", [&email], |r| Ok((r.get(0)?, r.get(1)?)))
                .optional()?;
            match by_email {
                Some((_, Some(other))) if other != subject => {
                    audit(c, None, &email, "sso.denied", &email, &meta, "compte lié à une autre identité")?;
                    return Err(ApiError::forbidden("Ce compte Locksy est lié à une autre identité SSO."));
                }
                Some((id, None)) => {
                    if !trust.link_by_email {
                        audit(c, None, &email, "sso.denied", &email, &meta, "rattachement automatique désactivé")?;
                        return Err(ApiError::new(
                            StatusCode::FORBIDDEN,
                            "sso_link_refused",
                            "Un compte Locksy existe déjà pour cette adresse mais n'est pas lié à cette identité. Connectez-vous avec votre mot de passe maître ou demandez à votre administrateur de restreindre les domaines autorisés.",
                        ));
                    }
                    c.execute("UPDATE users SET sso_subject = ?1 WHERE id = ?2", params![subject, id])?;
                    Some(id)
                }
                Some((id, Some(_))) => Some(id),
                None => {
                    // Pas de ticket d'inscription sur une adresse non prouvée.
                    if !trust.email_verified {
                        audit(c, None, &email, "sso.denied", &email, &meta, "adresse e-mail non vérifiée")?;
                        return Err(ApiError::new(
                            StatusCode::FORBIDDEN,
                            "email_unverified",
                            "Adresse e-mail non vérifiée chez le fournisseur d'identité.",
                        ));
                    }
                    None
                }
            }
        }
    };
    if let Some(uid) = &user {
        if let Err(e) = account_gate(c, uid) {
            let why = if e.code == "account_expired" { "accès expiré" } else { "compte désactivé" };
            audit(c, Some(uid), &email, "sso.denied", &email, &meta, why)?;
            return Err(e);
        }
    }
    let dir_inactive: bool = c
        .query_row("SELECT active = 0 FROM directory_users WHERE email = ?1", [&email], |r| r.get(0))
        .optional()?
        .unwrap_or(false);
    if dir_inactive {
        audit(c, None, &email, "sso.denied", &email, &meta, "désactivé dans l'annuaire")?;
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "account_disabled",
            "Ce compte est désactivé dans l'annuaire de l'entreprise.",
        ));
    }
    let ticket = crypto::random_token();
    c.execute("DELETE FROM sso_tickets WHERE expires_at < ?1 OR used = 1", [now_unix()])?;
    c.execute(
        "INSERT INTO sso_tickets (ticket_hash, email, name, subject, user_id, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![sha256_hex(&ticket), email, name, subject, user, now_unix() + TICKET_TTL],
    )?;
    audit(c, user.as_deref(), &email, "sso.authenticated", &email, &meta, "")?;
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
    state.limiter.hit(&format!("sso-redeem:{}", meta.rate_key()), 30, 60)?;
    Ok(Json(state.db.call(move |c| redeem_info(c, &req.ticket)).await?))
}

/// Ce qu'un client doit savoir d'un ticket (sans le consommer). Un compte
/// désactivé ou expiré depuis l'émission du ticket est refusé
/// (`account_disabled`, `account_expired`).
pub fn redeem_info(c: &Connection, ticket: &str) -> ApiResult<SsoRedeemResponse> {
    let (t, name) = find_ticket(c, ticket)?;
    let kdf: Option<KdfParams> = match &t.user_id {
        Some(id) => {
            account_gate(c, id)?;
            c.query_row("SELECT kdf FROM users WHERE id = ?1", [id], |r| r.get::<_, String>(0))
                .optional()?
                .and_then(|k| serde_json::from_str(&k).ok())
        }
        None => None,
    };
    let registered = kdf.is_some();
    let can_register = !registered && may_self_register(c, &t.email)?;
    Ok(SsoRedeemResponse { email: t.email, name, registered, can_register, kdf })
}

// ------------------------------------------------------------ Administration

/// Configuration telle que l'affichent les écrans : secret masqué, valeurs
/// du registre (imposition, adresse publique, extensions) et URI de
/// redirection calculée.
fn view(mut cfg: SsoSettings, eff: &Effective, base: &str) -> SsoSettings {
    cfg.base.client_secret = String::new();
    cfg.base.enforce = eff.bool("sso.enforce");
    cfg.base.public_url = eff.str("instance.public_url").to_string();
    cfg.base.redirect_uri = redirect_uri(base);
    cfg.allowed_extension_ids = eff.list("extension.allowed_ids");
    cfg
}

pub async fn get_config(State(state): State<AppState>, _admin: AdminUser, headers: HeaderMap) -> ApiResult<Json<SsoSettings>> {
    let cfg = state.db.call(|c| load_full_config(c)).await?;
    let eff = state.effective().await?;
    let base = public_base(&state, &eff, &headers);
    Ok(Json(view(cfg, &eff, &base)))
}

/// Délai de validité d'un test réussi pour imposer une méthode (G-14).
pub(crate) const TEST_VALIDITY_SECS: i64 = 24 * 3600;

/// Erreur d'imposition sans test réussi récent de l'administrateur (G-14).
pub(crate) fn test_required_error() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        "test_required",
        "Testez d'abord cette connexion avec votre compte (test réussi de moins de 24 h) avant de l'imposer.",
    )
}

pub async fn put_config(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    headers: HeaderMap,
    Json(settings): Json<SsoSettings>,
) -> ApiResult<Json<SsoSettings>> {
    // On enregistre toujours `SsoSettings` en entier : réécrire la clé `"sso"`
    // avec un `SsoConfig` seul effacerait les réglages propres au serveur.
    let SsoSettings { base: mut req, allowed_extension_ids, trust_unverified_email } = settings;
    let allowed_extension_ids = clean_extension_ids(&allowed_extension_ids)?;
    req.issuer = req.issuer.trim().trim_end_matches('/').to_string();
    req.public_url = req.public_url.trim().trim_end_matches('/').to_string();
    req.client_id = req.client_id.trim().to_string();
    req.label = req.label.trim().chars().take(60).collect();
    req.allowed_domains = req.allowed_domains.iter().map(|d| d.trim().trim_start_matches('@').to_lowercase()).filter(|d| !d.is_empty()).collect();
    if req.enforce && !req.enabled {
        req.enforce = false;
    }
    let eff = state.effective().await?;
    // L'adresse publique (`instance.public_url`) est un réglage de propriétaire.
    if req.public_url != eff.str("instance.public_url").trim_end_matches('/') && admin.role != roles::OWNER {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "owner_only",
            "L'adresse publique de Locksy ne peut être modifiée que par un propriétaire.",
        ));
    }
    if req.enabled {
        if req.issuer.is_empty() || req.client_id.is_empty() {
            return Err(ApiError::bad_request("Renseignez l'émetteur et l'identifiant client."));
        }
        if let Err(f) = state.sso.check_url(&req.issuer) {
            return Err(f.to_api());
        }
        let public = if req.public_url.is_empty() { public_base(&state, &eff, &headers) } else { req.public_url.clone() };
        let base = url::Url::parse(&public).map_err(|_| ApiError::bad_request("Adresse publique de Locksy invalide."))?;
        if base.scheme() != "https" && !state.sso.allow_http && !matches!(base.host_str(), Some("localhost" | "127.0.0.1")) {
            return Err(ApiError::bad_request("L'adresse publique de Locksy doit être en https://."));
        }
        // Vérifie que le fournisseur répond avant d'activer.
        if let Err(f) = state.sso.discover(&req.issuer).await {
            note_failure(&state, &f, Some(&admin), &admin.meta).await;
            return Err(f.to_api());
        }
    }
    let key = state.server_key.clone();
    let turns_on_enforce = req.enforce && !eff.bool("sso.enforce");
    let base = public_base(&state, &eff, &headers);
    let actor = admin.clone();
    state
        .db
        .call(move |c| {
            // Imposer le SSO exige un test réussi de cet administrateur (G-14).
            if turns_on_enforce && !identity_admin::recent_test_ok(c, "sso", &actor.id, now_unix())? {
                return Err(test_required_error());
            }
            let old = load_config(c)?;
            if req.client_secret.trim().is_empty() {
                req.client_secret = old.client_secret;
            } else {
                req.client_secret = crypto::encrypt_str(&key, req.client_secret.trim(), "verrou:v1:sso-client-secret");
            }
            req.has_secret = false;
            req.redirect_uri = String::new();
            let saved = SsoSettings { base: req, allowed_extension_ids, trust_unverified_email };
            db::save_json(c, SETTINGS_KEY, &saved)?;
            let req = &saved.base;
            audit_user(
                c,
                &actor,
                "admin.sso_updated",
                &req.issuer,
                &format!(
                    "actif : {}, imposé : {}, création automatique : {}, extensions autorisées : {}, e-mails non vérifiés acceptés : {}",
                    if req.enabled { "oui" } else { "non" },
                    if req.enforce { "oui" } else { "non" },
                    if req.auto_provision { "oui" } else { "non" },
                    saved.allowed_extension_ids.len(),
                    if saved.trust_unverified_email { "oui" } else { "non" }
                ),
            )?;
            Ok(())
        })
        .await?;
    let cfg = state.db.call(|c| load_full_config(c)).await?;
    let eff = state.effective().await?;
    Ok(Json(view(cfg, &eff, &base)))
}

#[derive(serde::Serialize)]
pub struct SsoTestResult {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    keys: usize,
}

/// Test de configuration (`POST /admin/sso/test`) : découverte et clés du
/// fournisseur saisi, sans enregistrer. En échec : code stable, détail du
/// fournisseur dans `technical`.
pub async fn test_config(State(state): State<AppState>, AdminUser(admin): AdminUser, Json(req): Json<SsoConfig>) -> Result<Json<SsoTestResult>, TestError> {
    state.limiter.hit(&format!("idtest-sso:{}", admin.id), IDENTITY_TEST_MAX, IDENTITY_TEST_WINDOW)?;
    let issuer = req.issuer.trim().trim_end_matches('/').to_string();
    let result = async {
        let d = state.sso.discover(&issuer).await?;
        let keys = state.sso.keys(&d.jwks_uri, true).await?;
        Ok::<_, IdpFail>(SsoTestResult { issuer: d.issuer, authorization_endpoint: d.authorization_endpoint, token_endpoint: d.token_endpoint, keys: keys.keys.len() })
    }
    .await;
    match result {
        Ok(r) => Ok(Json(r)),
        Err(f) => {
            note_failure(&state, &f, Some(&admin), &admin.meta).await;
            Err(f.into())
        }
    }
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

    const EXT: &str = "abcdefghijklmnopabcdefghijklmnop";

    fn allowed() -> Vec<String> {
        vec![EXT.to_string()]
    }

    #[test]
    fn extension_redirects_are_restricted() {
        let ok = |r: &str| extension_redirect_ok(r, &allowed());
        assert!(ok(&format!("https://{EXT}.chromiumapp.org/")));
        assert!(ok(&format!("https://{EXT}.chromiumapp.org/cb?x=1")));
        assert!(!ok("https://chromiumapp.org/"));
        assert!(!ok("https://.chromiumapp.org/"));
        assert!(!ok("https://evil.com/?x=.chromiumapp.org"));
        assert!(!ok(&format!("http://{EXT}.chromiumapp.org/")));
        assert!(!ok(&format!("https://{EXT}.chromiumapp.org:8443/")));
        assert!(!ok(&format!("https://{EXT}.chromiumapp.org.evil.com/")));
        assert!(!ok(&format!("https://x.{EXT}.chromiumapp.org/")), "sous-domaine refusé");
        assert!(!ok(&format!("https://user@{EXT}.chromiumapp.org/")));
    }

    #[test]
    fn unlisted_extension_is_refused() {
        assert!(!extension_redirect_ok("https://pppppppppppppppppppppppppppppppp.chromiumapp.org/", &allowed()));
        assert!(!extension_redirect_ok("https://abc.chromiumapp.org/", &allowed()));
    }

    #[test]
    fn empty_allow_list_refuses_every_extension() {
        assert!(!extension_redirect_ok(&format!("https://{EXT}.chromiumapp.org/"), &[]));
        assert!(!extension_redirect_ok("https://abc.chromiumapp.org/", &[]));
    }

    #[test]
    fn extension_host_is_case_insensitive() {
        let upper = format!("https://{}.CHROMIUMAPP.ORG/", EXT.to_uppercase());
        assert!(extension_redirect_ok(&upper, &allowed()));
        assert!(extension_redirect_ok(&format!("https://{EXT}.chromiumapp.org/"), &[EXT.to_uppercase()]));
    }

    #[test]
    fn extension_ids_are_validated() {
        let ids = clean_extension_ids(&[format!(" {} ", EXT.to_uppercase()), EXT.into(), String::new()]).unwrap();
        assert_eq!(ids, vec![EXT.to_string()], "normalisé et dédoublonné");
        assert!(clean_extension_ids(&["abc".into()]).is_err());
        assert!(clean_extension_ids(&["qbcdefghijklmnopabcdefghijklmnop".into()]).is_err(), "lettre hors a-p");
        assert!(clean_extension_ids(&[format!("{EXT}.chromiumapp.org")]).is_err());
    }

    #[test]
    fn old_settings_are_read_with_safe_defaults() {
        let old = serde_json::json!({ "enabled": true, "issuer": "https://idp", "client_id": "x", "allowed_domains": ["corp.fr"] });
        let s: SsoSettings = serde_json::from_value(old).unwrap();
        assert!(s.base.enabled);
        assert_eq!(s.base.allowed_domains, vec!["corp.fr".to_string()]);
        assert!(s.allowed_extension_ids.is_empty());
        assert!(!s.trust_unverified_email);
        // Les nouveaux champs sont enregistrés à plat, à côté des anciens.
        let v = serde_json::to_value(SsoSettings { allowed_extension_ids: vec![EXT.into()], trust_unverified_email: true, ..s }).unwrap();
        assert_eq!(v["issuer"], "https://idp");
        assert_eq!(v["allowed_extension_ids"][0], EXT);
        assert_eq!(v["trust_unverified_email"], true);
    }

    /// Plus d'adresse « http://localhost:8743 » inventée : sans adresse
    /// publique, l'URI de redirection est calculée par les routes.
    #[tokio::test]
    async fn no_hardcoded_public_url() {
        let st = crate::state::test_state().await;
        let cfg = st
            .db
            .call(|c| {
                db::save_json(c, SETTINGS_KEY, &serde_json::json!({ "enabled": false, "issuer": "https://idp" }))?;
                load_config(c)
            })
            .await
            .unwrap();
        assert_eq!(cfg.public_url, "");
        assert_eq!(cfg.redirect_uri, "");
        let mut headers = HeaderMap::new();
        headers.insert("host", "coffre.exemple.fr:8443".parse().unwrap());
        let eff = st.effective().await.unwrap();
        assert_eq!(public_base(&st, &eff, &headers), "http://coffre.exemple.fr:8443");
        headers.insert("host", "evil.fr/<script>".parse().unwrap());
        assert_eq!(public_base(&st, &eff, &headers), "http://127.0.0.1:0", "Host inattendu ignoré");
    }

    #[test]
    fn email_verified_is_strict_by_default() {
        use serde_json::json;
        assert!(email_verified(Some(&json!(true)), false));
        assert!(email_verified(Some(&json!("true")), false));
        assert!(!email_verified(None, false), "absent : non vérifié par défaut");
        assert!(!email_verified(Some(&json!(false)), false));
        assert!(!email_verified(Some(&json!("false")), false));
        assert!(!email_verified(Some(&json!(1)), false));
        assert!(email_verified(None, true), "option de l'administrateur (Entra ID)");
    }

    fn pending(created: Instant) -> Pending {
        Pending {
            nonce: String::new(),
            verifier: String::new(),
            return_to: ReturnTo::Web,
            base: String::new(),
            test_by: None,
            created,
        }
    }

    #[test]
    fn expired_states_are_purged_before_refusing() {
        let rt = SsoRuntime::new(false, false);
        let old = Instant::now()
            .checked_sub(PENDING_TTL + Duration::from_secs(1))
            .expect("horloge monotone suffisante");
        for i in 0..PENDING_MAX {
            rt.put_pending(format!("old{i}"), pending(old)).unwrap();
        }
        rt.put_pending("nouveau".into(), pending(Instant::now())).expect("purge des états expirés");
        assert_eq!(rt.pending.lock().unwrap().len(), 1);
    }

    #[test]
    fn full_state_table_is_reported() {
        let rt = SsoRuntime::new(false, false);
        for i in 0..PENDING_MAX {
            rt.put_pending(format!("s{i}"), pending(Instant::now())).unwrap();
        }
        let e = rt.put_pending("de trop".into(), pending(Instant::now())).unwrap_err();
        assert_eq!(e.code, "sso_busy");
        assert_eq!(e.status, StatusCode::SERVICE_UNAVAILABLE);
    }

    // ---------------------------------------------------- Filtre anti-SSRF

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn ssrf_filter_refuses_internal_addresses() {
        for bad in [
            "127.0.0.1", "127.8.9.10", "::1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
            "169.254.169.254", "100.64.0.1", "100.127.255.255", "0.0.0.0", "0.1.2.3", "::", "fe80::1",
            "fc00::1", "fd12:3456::1", "::ffff:127.0.0.1", "::ffff:8.8.8.8", "224.0.0.1", "ff02::1",
            "255.255.255.255", "240.0.0.1", "::127.0.0.1", "64:ff9b::a00:1", "2002:c0a8:101::1", "fec0::1",
        ] {
            assert!(ip_forbidden(ip(bad)), "{bad} doit être refusée");
        }
        for good in ["8.8.8.8", "1.1.1.1", "203.0.113.7", "172.32.0.1", "100.128.0.1", "2001:4860:4860::8888", "64:ff9b::808:808"] {
            assert!(!ip_forbidden(ip(good)), "{good} doit être acceptée");
        }
    }

    #[test]
    fn literal_targets_are_checked() {
        let blocked = |u: &str| target_blocked(&url::Url::parse(u).unwrap()).is_some();
        assert!(blocked("https://127.0.0.1/.well-known/openid-configuration"));
        assert!(blocked("https://[::1]:8443/"));
        assert!(blocked("http://169.254.169.254/latest/meta-data/"));
        assert!(blocked("https://[::ffff:7f00:1]/"));
        assert!(blocked("https://localhost/"));
        assert!(blocked("https://idp.localhost./"));
        assert!(!blocked("https://login.microsoftonline.com/x/v2.0"));
        assert!(!blocked("https://8.8.8.8/"));
    }

    #[test]
    fn redirects_are_refiltered_and_bounded() {
        let u = |s: &str| url::Url::parse(s).unwrap();
        assert!(redirect_refused(&u("https://idp.exemple.fr/jwks"), 1).is_none());
        assert!(redirect_refused(&u("https://idp.exemple.fr/jwks"), MAX_REDIRECTS).is_none());
        assert!(redirect_refused(&u("https://idp.exemple.fr/jwks"), MAX_REDIRECTS + 1).is_some(), "trop de sauts");
        let e = redirect_refused(&u("https://10.0.0.5/jwks"), 1).expect("adresse privée");
        assert!(e.to_string().contains(SSRF_MARK));
        assert!(redirect_refused(&u("http://idp.exemple.fr/jwks"), 1).is_some(), "pas de retour au HTTP clair");
    }

    #[tokio::test]
    async fn resolver_refuses_local_names() {
        let e = resolve_checked("localhost").await.expect_err("boucle locale refusée");
        assert!(e.to_string().contains(SSRF_MARK), "{e}");
    }

    #[tokio::test]
    async fn literal_internal_issuer_is_refused_before_any_request() {
        let rt = SsoRuntime::new(true, false);
        let e = rt.discover("http://127.0.0.1:9").await.err().expect("refus");
        assert_eq!(e.code, "ssrf_blocked");
        assert_eq!(e.to_api().status, StatusCode::UNPROCESSABLE_ENTITY);
        let rt = SsoRuntime::new(false, true);
        assert_eq!(rt.discover("http://127.0.0.1:9").await.err().unwrap().code, "idp_insecure_url");
    }

    #[test]
    fn provider_text_never_reaches_the_message() {
        let f = IdpFail::new("idp_token_refused", "HTTP 400 : AADSTS7000215 secret invalide");
        let e = f.to_api();
        assert_eq!(e.code, "idp_token_refused");
        assert!(!e.message.contains("AADSTS"));
        assert_eq!(IdpFail::new("inconnu", "x").to_api().code, "idp_unreachable");
    }

    #[tokio::test]
    async fn test_errors_keep_technical_detail_and_retry_after() {
        let r = TestError::from(IdpFail::new("sso_busy", "table pleine")).into_response();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(r.headers()["retry-after"], "5");
        let body = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!((v["error"].as_str(), v["technical"].as_str(), v["retry_after"].as_i64()), (Some("sso_busy"), Some("table pleine"), Some(5)));
    }

    // ---------------------------------------------------- Rattachement des identités

    fn meta() -> ClientMeta {
        ClientMeta { ip: "203.0.113.7".into(), user_agent: "test".into() }
    }

    fn add_user(c: &Connection, id: &str, email: &str, subject: Option<&str>) {
        c.execute(
            "INSERT INTO users (id, email, name, role, kdf, auth_hash, wrapped_user_key, recovery_wrapped_user_key,
                                recovery_auth_hash, public_key, wrapped_private_key, created_at, updated_at, sso_subject)
             VALUES (?1, ?2, 'Test', 'user', '{}', '', '', '', '', '', '', 0, 0, ?3)",
            params![id, email, subject],
        )
        .unwrap();
    }

    fn subject_of(c: &Connection, id: &str) -> Option<String> {
        c.query_row("SELECT sso_subject FROM users WHERE id = ?1", [id], |r| r.get(0)).unwrap()
    }

    const UNVERIFIED_OIDC: IdentityTrust = IdentityTrust { email_verified: false, link_by_email: false };

    #[tokio::test]
    async fn linked_subject_works_without_verified_email() {
        let st = crate::state::test_state().await;
        let r = st
            .db
            .call(|c| {
                add_user(c, "u1", "jean@corp.fr", Some("https://idp|42"));
                issue_ticket(c, "jean@corp.fr", "Jean", "https://idp|42", &meta(), UNVERIFIED_OIDC)
            })
            .await;
        assert!(r.is_ok(), "compte déjà lié par son sujet : ticket émis");
    }

    #[tokio::test]
    async fn disabled_or_expired_accounts_get_no_ticket() {
        let st = crate::state::test_state().await;
        let (disabled, expired, redeemed) = st
            .db
            .call(|c| {
                add_user(c, "u1", "jean@corp.fr", Some("https://idp|1"));
                add_user(c, "u2", "paul@corp.fr", Some("https://idp|2"));
                c.execute("UPDATE users SET disabled = 1 WHERE id = 'u1'", [])?;
                c.execute("UPDATE users SET access_until = 1 WHERE id = 'u2'", [])?;
                let d = issue_ticket(c, "jean@corp.fr", "", "https://idp|1", &meta(), UNVERIFIED_OIDC).unwrap_err();
                let e = issue_ticket(c, "paul@corp.fr", "", "https://idp|2", &meta(), UNVERIFIED_OIDC).unwrap_err();
                // Ticket émis puis compte expiré : refusé à l'échange.
                c.execute("UPDATE users SET access_until = NULL WHERE id = 'u2'", [])?;
                let t = issue_ticket(c, "paul@corp.fr", "", "https://idp|2", &meta(), UNVERIFIED_OIDC).unwrap();
                c.execute("UPDATE users SET access_until = 1 WHERE id = 'u2'", [])?;
                let r = redeem_info(c, &t).unwrap_err();
                Ok((d.code, e.code, r.code))
            })
            .await
            .unwrap();
        assert_eq!((disabled, expired, redeemed), ("account_disabled", "account_expired", "account_expired"));
    }

    #[tokio::test]
    async fn no_email_linking_without_domain_restriction() {
        let st = crate::state::test_state().await;
        // OpenID Connect, e-mail vérifié mais aucune liste de domaines.
        let trust = IdentityTrust { email_verified: true, link_by_email: false };
        let (r, subject) = st
            .db
            .call(move |c| {
                add_user(c, "u1", "jean@corp.fr", None);
                let r = issue_ticket(c, "jean@corp.fr", "Jean", "https://idp|attaquant", &meta(), trust);
                Ok((r, subject_of(c, "u1")))
            })
            .await
            .unwrap();
        assert_eq!(r.unwrap_err().code, "sso_link_refused");
        assert_eq!(subject, None, "aucun lien posé");
    }

    #[tokio::test]
    async fn email_linking_with_domains_and_verified_email() {
        let st = crate::state::test_state().await;
        let trust = IdentityTrust { email_verified: true, link_by_email: true };
        let (r, subject) = st
            .db
            .call(move |c| {
                add_user(c, "u1", "jean@corp.fr", None);
                let r = issue_ticket(c, "jean@corp.fr", "Jean", "https://idp|42", &meta(), trust);
                Ok((r, subject_of(c, "u1")))
            })
            .await
            .unwrap();
        assert!(r.is_ok());
        assert_eq!(subject.as_deref(), Some("https://idp|42"));
    }

    #[tokio::test]
    async fn unknown_unverified_address_gets_no_ticket() {
        let st = crate::state::test_state().await;
        let r = st.db.call(|c| issue_ticket(c, "inconnu@corp.fr", "", "https://idp|7", &meta(), UNVERIFIED_OIDC)).await;
        assert_eq!(r.unwrap_err().code, "email_unverified");
        let tickets: i64 = st.db.call(|c| Ok(c.query_row("SELECT COUNT(*) FROM sso_tickets", [], |r| r.get(0))?)).await.unwrap();
        assert_eq!(tickets, 0);
    }

    #[tokio::test]
    async fn ldap_identity_links_by_email() {
        let st = crate::state::test_state().await;
        // Confiance accordée par ldap::login : l'annuaire de l'entreprise fait autorité.
        let trust = crate::ldap::DIRECTORY_TRUST;
        assert!(trust.email_verified && trust.link_by_email);
        let (r, subject) = st
            .db
            .call(move |c| {
                add_user(c, "u1", "jean@corp.fr", None);
                let r = issue_ticket(c, "jean@corp.fr", "Jean", "ldap|00ff", &meta(), trust);
                Ok((r, subject_of(c, "u1")))
            })
            .await
            .unwrap();
        assert!(r.is_ok());
        assert_eq!(subject.as_deref(), Some("ldap|00ff"));
    }

    #[test]
    fn finish_urls_carry_the_ticket_out_of_server_logs() {
        let base = "https://coffre.exemple.fr";
        assert_eq!(finish_url(base, &ReturnTo::Web, Ok("T".into())), "https://coffre.exemple.fr/#/sso?ticket=T");
        assert_eq!(finish_url(base, &ReturnTo::Desktop(50123, None), Ok("T".into())), "http://127.0.0.1:50123/sso?ticket=T");
        let cs = "AbCd_efGh-ijKlmnop0123".to_string();
        assert_eq!(
            finish_url(base, &ReturnTo::Desktop(50123, Some(cs.clone())), Ok("T".into())),
            format!("http://127.0.0.1:50123/sso?ticket=T&client_state={cs}")
        );
        assert_eq!(
            finish_url(base, &ReturnTo::Desktop(50123, Some(cs.clone())), Err("refusé".into())),
            format!("http://127.0.0.1:50123/sso?error=refus%C3%A9&client_state={cs}")
        );
        assert_eq!(
            finish_url(base, &ReturnTo::Extension("https://x.chromiumapp.org/cb".into()), Err("refus é".into())),
            "https://x.chromiumapp.org/cb#error=refus%20%C3%A9"
        );
    }

    #[test]
    fn test_results_return_to_the_admin_page() {
        let base = "https://coffre.exemple.fr/";
        assert_eq!(test_url(base, Ok(())), "https://coffre.exemple.fr/#/admin/connexion/sso?test=ok");
        assert_eq!(
            test_url(base, Err("email_mismatch")),
            "https://coffre.exemple.fr/#/admin/connexion/sso?test=erreur&code=email_mismatch"
        );
    }

    #[test]
    fn client_state_format_is_checked() {
        assert!(client_state_ok(&"a".repeat(16)));
        assert!(client_state_ok("AbCd_efGh-ijKlmnop0123456789abcdefghijklmno"));
        assert!(client_state_ok(&"Z".repeat(128)));
        assert!(!client_state_ok(&"a".repeat(15)), "trop court");
        assert!(!client_state_ok(&"a".repeat(129)), "trop long");
        assert!(!client_state_ok("abcdefghijklmnop&ticket=x"), "caractère hors base64url");
        assert!(!client_state_ok("abcdefghijklmnop%20"));
        assert!(!client_state_ok("abcdefghijklmnop/q"));
    }

    #[tokio::test]
    async fn invalid_client_state_is_refused_before_the_provider() {
        let st = crate::state::test_state().await;
        st.db
            .call(|c| {
                let cfg = serde_json::json!({ "enabled": true, "issuer": "https://idp.invalid", "client_id": "x" });
                db::save_json(c, SETTINGS_KEY, &cfg)
            })
            .await
            .unwrap();
        let q = StartQuery {
            target: "desktop".into(),
            port: Some(50123),
            redirect: None,
            client_state: Some("abcdefghijklmnop&ticket=volé".into()),
        };
        let Err(e) = start(State(st), meta(), HeaderMap::new(), Query(q)).await else { panic!("client_state invalide accepté") };
        assert_eq!(e.status, StatusCode::BAD_REQUEST);
        assert_eq!(e.message, "Paramètre client_state invalide.");
    }
}
