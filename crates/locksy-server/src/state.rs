use crate::config::HostConfig;
use crate::db::{self, Db};
use crate::error::{ApiError, ApiResult};
use crate::security::{sha256_hex, Limiter};
use axum::async_trait;
use axum::extract::{ConnectInfo, FromRequestParts, OriginalUri};
use axum::http::request::Parts;
use axum::http::StatusCode;
use rusqlite::{params, Connection, OptionalExtension};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use locksy_core::api::roles;
use locksy_core::crypto::SecretKey;
use locksy_core::now_unix;
use locksy_core::settings::{ip_allowed, twofa_gate, Effective, TwofaGate};

/// Réseau IP, défini dans le registre des réglages (liste blanche) et
/// réutilisé pour les proxys de confiance.
pub use locksy_core::settings::Cidr;

pub struct Config {
    pub bind: String,
    pub data_dir: PathBuf,
    pub web_dir: PathBuf,
    /// L'adresse cliente est lue dans X-Forwarded-For (proxy inverse devant).
    pub trust_proxy: bool,
    /// Proxys de confiance sautés depuis la droite de X-Forwarded-For. Vide :
    /// un seul proxy, dont on prend l'entrée la plus à droite.
    pub trusted_proxies: Vec<Cidr>,
    /// En-tête Strict-Transport-Security (TLS intégré ou proxy TLS).
    pub hsts: bool,
    /// Délai global d'une requête (408 au-delà).
    pub request_timeout: Duration,
    /// Délai de lecture des en-têtes HTTP d'une requête.
    pub header_timeout: Duration,
    /// Calculs Argon2 simultanés et file d'attente maximale.
    pub argon2_concurrency: usize,
    pub argon2_queue: usize,
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
    /// Réglages effectifs en cache (rechargés seulement après une écriture).
    pub settings: Arc<crate::settings_api::SettingsCache>,
    /// Contraintes de l'hébergeur : réglages verrouillés, plafonds, limites.
    pub host: Arc<HostConfig>,
    /// Envoi des notifications : mise en file SMTP (`mail::SmtpNotifier`),
    /// selon les réglages mail.*.
    pub notifier: Arc<dyn crate::mail::Notifier>,
}

impl AppState {
    /// Réglages effectifs. Aucune requête SQL tant qu'aucun réglage n'a été
    /// écrit depuis le dernier chargement.
    pub async fn effective(&self) -> ApiResult<Arc<Effective>> {
        Ok(self.settings.loaded(self).await?.eff.clone())
    }
}

// ------------------------------------------------------------ Contexte client

#[derive(Clone, Debug)]
pub struct ClientMeta {
    pub ip: String,
    pub user_agent: String,
}

impl ClientMeta {
    /// Clé de limitation par adresse : l'IPv4 telle quelle, le préfixe /64
    /// pour une IPv6 (un poste dispose couramment de tout un /64 et
    /// changerait d'adresse à volonté pour contourner le limiteur).
    pub fn rate_key(&self) -> String {
        match self.ip.parse::<IpAddr>().map(|ip| ip.to_canonical()) {
            Ok(IpAddr::V6(v6)) => {
                let s = v6.segments();
                format!("{}/64", Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
            Ok(IpAddr::V4(v4)) => v4.to_string(),
            Err(_) => self.ip.clone(),
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

/// Lit une entrée de X-Forwarded-For : adresse nue, IPv6 entre crochets
/// (avec ou sans port) ou IPv4 suivie d'un port.
fn parse_forwarded(entry: &str) -> Option<IpAddr> {
    let e = entry.trim();
    if let Some(rest) = e.strip_prefix('[') {
        let (inner, _) = rest.split_once(']')?;
        return inner.parse::<Ipv6Addr>().ok().map(IpAddr::V6);
    }
    if let Ok(ip) = e.parse::<IpAddr>() {
        return Some(ip);
    }
    match e.split_once(':') {
        Some((host, port)) if !port.contains(':') && port.parse::<u16>().is_ok() => {
            host.parse::<std::net::Ipv4Addr>().ok().map(IpAddr::V4)
        }
        _ => None,
    }
}

/// Adresse du client.
///
/// Chaque proxy AJOUTE à droite de X-Forwarded-For l'adresse de son propre
/// client : seules les entrées de droite, écrites par nos proxys, sont
/// fiables ; la plus à gauche est fournie par le client et falsifiable.
/// - sans `trust_proxy`, l'en-tête est ignoré ;
/// - avec une liste `trusted`, le pair doit en faire partie, puis on saute
///   depuis la droite les proxys de confiance ;
/// - sans liste, on prend l'entrée la plus à droite (proxy unique).
///
/// Une entrée illisible arrête le parcours : on garde le dernier saut sûr.
pub(crate) fn client_ip(peer: Option<IpAddr>, xff: &[&str], trust_proxy: bool, trusted: &[Cidr]) -> Option<IpAddr> {
    let peer = peer.map(|p| p.to_canonical());
    if !trust_proxy {
        return peer;
    }
    let is_trusted = |ip: IpAddr| trusted.iter().any(|c| c.contains(ip));
    if !trusted.is_empty() && !peer.is_some_and(is_trusted) {
        // La connexion ne vient pas d'un proxy de confiance : en-tête ignoré.
        return peer;
    }
    let mut last = peer;
    let entries = xff.iter().flat_map(|h| h.split(',')).map(str::trim).filter(|e| !e.is_empty());
    for entry in entries.collect::<Vec<_>>().into_iter().rev() {
        let Some(ip) = parse_forwarded(entry).map(|ip| ip.to_canonical()) else {
            return last;
        };
        if trusted.is_empty() || !is_trusted(ip) {
            return Some(ip);
        }
        last = Some(ip);
    }
    last
}

#[async_trait]
impl FromRequestParts<AppState> for ClientMeta {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        // Un en-tête non ASCII devient une entrée illisible : il arrête le parcours.
        let xff: Vec<&str> =
            parts.headers.get_all("x-forwarded-for").iter().map(|v| v.to_str().unwrap_or("?")).collect();
        let peer = parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip());
        let ip = client_ip(peer, &xff, state.config.trust_proxy, &state.config.trusted_proxies)
            .map(|ip| ip.to_string())
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

/// Routes accessibles à un compte sans 2FA quand l'organisation l'impose :
/// son profil (/api/me et /api/me/…, dont l'activation de la 2FA) et la
/// déconnexion. Comparaison exacte sur le chemin complet (préfixe /api
/// compris) : « /api/members » ou « /me » seul ne passent pas.
fn allowed_without_2fa(path: &str) -> bool {
    path == "/api/me" || path.starts_with("/api/me/") || path == "/api/auth/logout"
}

/// Jeton d'un en-tête `Authorization: Bearer <jeton>`, espaces retirés. Le
/// nom du schéma est insensible à la casse (RFC 7235) : « bearer » est
/// accepté comme « Bearer ». Tout autre schéma donne `None`.
pub fn bearer_token(value: &str) -> Option<&str> {
    let (scheme, rest) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then_some(rest.trim())
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
            .and_then(bearer_token)
            .filter(|t| !t.is_empty() && t.len() <= 128)
            .ok_or_else(|| ApiError::unauthorized("Connexion requise."))?;
        let hash = sha256_hex(token);
        // Chemin complet de la requête : sous `Router::nest("/api", …)`, axum
        // retire le préfixe de `parts.uri` (« /me » au lieu de « /api/me ») ;
        // `OriginalUri` garde le chemin reçu. Repli sur `parts.uri` si
        // l'extension manque (routeur non imbriqué, tests).
        let path = parts
            .extensions
            .get::<OriginalUri>()
            .map(|u| u.0.path().to_string())
            .unwrap_or_else(|| parts.uri.path().to_string());
        // Réglages en cache : aucune lecture SQL des réglages par requête.
        let settings = state.effective().await?;
        // Lecture sur le pool (chemin de chaque requête authentifiée) ;
        // l'écrivain n'est sollicité que pour purger ou rafraîchir la session.
        let found = state
            .db
            .read(move |c| {
                Ok(c.query_row(
                    "SELECT s.id, s.user_id, s.last_seen_at, s.expires_at, u.email, u.role, u.disabled,
                            u.totp_secret IS NOT NULL, u.created_at, u.access_until
                     FROM sessions s JOIN users u ON u.id = s.user_id
                     WHERE s.token_hash = ?1",
                    [&hash],
                    |r| {
                        Ok(SessionRow {
                            sid: r.get(0)?,
                            uid: r.get(1)?,
                            last_seen: r.get(2)?,
                            expires: r.get(3)?,
                            email: r.get(4)?,
                            role: r.get(5)?,
                            disabled: r.get(6)?,
                            totp: r.get(7)?,
                            created_at: r.get(8)?,
                            access_until: r.get(9)?,
                        })
                    },
                )
                .optional()?)
            })
            .await?;
        let Some(row) = found else {
            return Err(ApiError::unauthorized("Session expirée. Reconnectez-vous."));
        };
        let now = now_unix();
        let sid = row.sid;
        let idle = settings.int("session.idle_minutes") * 60;
        let expired_access = row.access_until.is_some_and(|t| t <= now);
        if row.disabled || expired_access || row.expires < now || now - row.last_seen > idle {
            let purge = sid.clone();
            state
                .db
                .call(move |c| {
                    c.execute("DELETE FROM sessions WHERE id = ?1", [&purge])?;
                    Ok(())
                })
                .await?;
            // Compte désactivé ou accès échu : la raison est donnée (403), pour
            // que le client vide la session et l'explique (#50).
            if row.disabled {
                return Err(crate::auth::account_disabled());
            }
            if expired_access {
                return Err(crate::auth::account_expired());
            }
            return Err(ApiError::unauthorized("Session expirée. Reconnectez-vous."));
        }
        if now - row.last_seen > 30 {
            let touch = sid.clone();
            state
                .db
                .call(move |c| {
                    c.execute("UPDATE sessions SET last_seen_at = ?1 WHERE id = ?2", params![now, touch])?;
                    Ok(())
                })
                .await?;
        }
        // Liste blanche d'adresses : la session reste ouverte (la déconnexion
        // passe), mais rien d'autre n'est servi hors des réseaux permis.
        let ip_ok = settings.list("access.ip_allowlist").is_empty()
            || meta.ip.parse::<IpAddr>().is_ok_and(|ip| ip_allowed(&settings, ip, &row.role));
        if !ip_ok && path != "/api/auth/logout" {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "ip_not_allowed",
                "Connexion refusée depuis ce réseau : votre organisation limite l'accès à certaines adresses.",
            ));
        }
        // Double authentification exigée : pendant le délai de grâce, la
        // requête passe ; ensuite seules les routes du profil restent ouvertes.
        let gate = twofa_gate(&settings, &row.role, row.totp, row.created_at, now);
        if gate == TwofaGate::Required && !allowed_without_2fa(&path) {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "2fa_required",
                "Votre organisation impose la double authentification. Activez-la dans vos paramètres.",
            ));
        }
        Ok(AuthUser { id: row.uid, email: row.email, role: row.role, session_id: sid, meta })
    }
}

/// Session et compte associés à un jeton.
struct SessionRow {
    sid: String,
    uid: String,
    last_seen: i64,
    expires: i64,
    email: String,
    role: String,
    disabled: bool,
    totp: bool,
    created_at: i64,
    access_until: Option<i64>,
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
    let rowid = c.last_insert_rowid();
    // Journal chaîné (lot L17) : empreinte de la ligne, même transaction.
    crate::audit_chain::on_insert(c, rowid)?;
    // Le syslog ne reçoit l'événement qu'une fois la ligne commitée : dans
    // une transaction, l'envoi attend la fin de `Db::call` (annulée : jeté).
    let ev = db::AuditEvent {
        at,
        user_id: user_id.map(str::to_owned),
        email: email.to_owned(),
        action: action.to_owned(),
        target: target.to_owned(),
        ip: meta.ip.clone(),
        user_agent: meta.user_agent.clone(),
        details: details.to_owned(),
    };
    db::defer_or_emit(c, rowid, ev);
    Ok(())
}

pub fn audit_user(c: &Connection, user: &AuthUser, action: &str, target: &str, details: &str) -> ApiResult<()> {
    audit(c, Some(&user.id), &user.email, action, target, &user.meta, details)
}

// ------------------------------------------------------------ Tests

/// État complet pour les tests de handlers : base fichier (WAL, écrivain et
/// deux lecteurs, comme en production) dans un dossier de données temporaire
/// unique, pas de proxy.
#[cfg(test)]
pub async fn test_state() -> AppState {
    use locksy_core::crypto::{new_uuid, random_bytes};
    let data_dir = std::env::temp_dir().join(format!("locksy-test-{}", new_uuid()));
    std::fs::create_dir_all(&data_dir).expect("dossier temporaire");
    let db = Db::open_with(&data_dir.join("locksy.db"), db::DbOptions { readers: 2 }).expect("base de test");
    let dummy_hash = crate::security::hash_secret(random_bytes(32)).await.expect("hachage");
    AppState {
        db,
        server_key: Arc::new(SecretKey::generate()),
        limiter: Arc::new(Limiter::default()),
        config: Arc::new(Config {
            bind: "127.0.0.1:0".into(),
            web_dir: data_dir.join("web"),
            data_dir,
            trust_proxy: false,
            trusted_proxies: Vec::new(),
            hsts: false,
            request_timeout: Duration::from_secs(120),
            header_timeout: Duration::from_secs(15),
            argon2_concurrency: crate::security::default_argon2_concurrency(),
            argon2_queue: crate::security::default_argon2_concurrency() * 8,
        }),
        dummy_hash: Arc::new(dummy_hash),
        sso: Arc::new(crate::sso::SsoRuntime::default()),
        settings: Arc::new(crate::settings_api::SettingsCache::default()),
        host: Arc::new(HostConfig::default()),
        notifier: crate::mail::build_notifier(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn cidrs(list: &[&str]) -> Vec<Cidr> {
        list.iter().map(|s| Cidr::parse(s).unwrap()).collect()
    }

    #[test]
    fn routes_permises_sans_2fa() {
        for p in ["/api/me", "/api/me/2fa/setup", "/api/me/2fa/enable", "/api/auth/logout"] {
            assert!(allowed_without_2fa(p), "{p}");
        }
        for p in ["/api/members", "/api/meX", "/me", "/auth/logout", "/api/sync", "/api/admin/settings", "/api/auth/logout/x"] {
            assert!(!allowed_without_2fa(p), "{p}");
        }
    }

    #[test]
    fn schema_bearer_insensible_a_la_casse() {
        for v in ["Bearer abc", "bearer abc", "BEARER  abc ", "bEaReR abc"] {
            assert_eq!(bearer_token(v), Some("abc"), "{v}");
        }
        assert_eq!(bearer_token("Bearer "), Some(""));
        for v in ["Bearer", "Basic abc", "Bearerabc", "Token abc", ""] {
            assert_eq!(bearer_token(v), None, "{v}");
        }
    }

    #[test]
    fn sans_trust_proxy_xff_ignore() {
        let peer = Some(ip("192.0.2.1"));
        assert_eq!(client_ip(peer, &["1.2.3.4"], false, &[]), peer);
        assert_eq!(client_ip(peer, &["1.2.3.4"], false, &cidrs(&["192.0.2.0/24"])), peer);
    }

    #[test]
    fn proxy_unique_prend_l_entree_la_plus_a_droite() {
        // Le client a forgé « 1.2.3.4 » ; le proxy a ajouté l'adresse réelle.
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(client_ip(peer, &["1.2.3.4, 9.9.9.9"], true, &[]), Some(ip("9.9.9.9")));
        assert_eq!(client_ip(peer, &["9.9.9.9"], true, &[]), Some(ip("9.9.9.9")));
    }

    #[test]
    fn proxys_de_confiance_sautes_depuis_la_droite() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(client_ip(peer, &["6.6.6.6, 5.5.5.5, 10.0.0.2"], true, &trusted), Some(ip("5.5.5.5")));
        // Que des proxys de confiance : le plus à gauche d'entre eux.
        assert_eq!(client_ip(peer, &["10.0.0.3, 10.0.0.2"], true, &trusted), Some(ip("10.0.0.3")));
    }

    #[test]
    fn pair_hors_confiance_xff_ignore() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        let peer = Some(ip("203.0.113.9"));
        assert_eq!(client_ip(peer, &["5.5.5.5"], true, &trusted), peer);
        assert_eq!(client_ip(None, &["5.5.5.5"], true, &trusted), None);
    }

    #[test]
    fn xff_absent_ou_vide() {
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(client_ip(peer, &[], true, &[]), peer);
        assert_eq!(client_ip(peer, &["", " , "], true, &[]), peer);
    }

    #[test]
    fn en_tetes_multiples_dans_l_ordre() {
        let peer = Some(ip("10.0.0.1"));
        // Le client envoie son propre en-tête, le proxy en ajoute un second.
        assert_eq!(client_ip(peer, &["1.2.3.4", "8.8.8.8"], true, &[]), Some(ip("8.8.8.8")));
        let trusted = cidrs(&["10.0.0.0/8"]);
        assert_eq!(
            client_ip(peer, &["1.2.3.4, 7.7.7.7", "10.1.1.1"], true, &trusted),
            Some(ip("7.7.7.7"))
        );
    }

    #[test]
    fn ipv6_entre_crochets_et_ports() {
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(client_ip(peer, &["[2001:db8::7]:443"], true, &[]), Some(ip("2001:db8::7")));
        assert_eq!(client_ip(peer, &["[2001:db8::7]"], true, &[]), Some(ip("2001:db8::7")));
        assert_eq!(client_ip(peer, &["2001:db8::7"], true, &[]), Some(ip("2001:db8::7")));
        assert_eq!(client_ip(peer, &["198.51.100.4:5555"], true, &[]), Some(ip("198.51.100.4")));
        let trusted = cidrs(&["2001:db8:ffff::/48", "10.0.0.0/8"]);
        assert_eq!(
            client_ip(peer, &["2001:db8::1, [2001:db8:ffff::2]:80"], true, &trusted),
            Some(ip("2001:db8::1"))
        );
    }

    #[test]
    fn ipv4_mappee_normalisee() {
        // Pair et entrée en IPv4 mappée, liste de confiance en IPv4 pure.
        let trusted = cidrs(&["10.0.0.0/8"]);
        let peer = Some(ip("::ffff:10.0.0.1"));
        assert_eq!(client_ip(peer, &["::ffff:5.5.5.5"], true, &trusted), Some(ip("5.5.5.5")));
        assert_eq!(client_ip(peer, &[], false, &[]), Some(ip("10.0.0.1")));
        assert_eq!(Cidr::parse("::ffff:10.0.0.0/104"), Cidr::parse("10.0.0.0/8"));
    }

    #[test]
    fn entree_illisible_arrete_le_parcours() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        let peer = Some(ip("10.0.0.1"));
        // L'entrée illisible est à gauche du dernier proxy de confiance.
        assert_eq!(client_ip(peer, &["5.5.5.5, unknown, 10.0.0.2"], true, &trusted), Some(ip("10.0.0.2")));
        // Illisible tout de suite : on garde le pair.
        assert_eq!(client_ip(peer, &["5.5.5.5, n'importe quoi"], true, &[]), peer);
        assert_eq!(client_ip(peer, &["?"], true, &trusted), peer);
    }

    #[test]
    fn rate_key_par_prefixe_ipv6() {
        let m = |ip: &str| ClientMeta { ip: ip.into(), user_agent: String::new() };
        assert_eq!(m("2001:db8:1:2:3:4:5:6").rate_key(), "2001:db8:1:2::/64");
        assert_eq!(m("2001:db8:1:2::9").rate_key(), m("2001:db8:1:2:ffff::1").rate_key());
        assert_eq!(m("203.0.113.7").rate_key(), "203.0.113.7");
        assert_eq!(m("::ffff:203.0.113.7").rate_key(), "203.0.113.7");
        assert_eq!(m("inconnue").rate_key(), "inconnue");
    }

    #[tokio::test]
    async fn etat_de_test_utilisable() {
        let st = test_state().await;
        assert!(st.config.data_dir.is_dir());
        let n: i64 = st.db.call(|c| Ok(c.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?)).await.unwrap();
        assert_eq!(n, 0);
        let n: i64 = st.db.read(|c| Ok(c.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?)).await.unwrap();
        assert_eq!(n, 0);
        let v = st.db.read(|c| Ok(db::schema_version(c)?)).await.unwrap();
        assert_eq!(v, db::SCHEMA_VERSION);
    }

    /// Crée un compte et une session (jeton renvoyé), avec les instants donnés.
    async fn session(st: &AppState, last_seen: i64, expires: i64, disabled: bool) -> (String, String) {
        session_as(st, "user", 0, last_seen, expires, disabled).await
    }

    /// Compte d'un rôle donné, créé à `created_at`, avec une session.
    async fn session_as(
        st: &AppState,
        role: &'static str,
        created_at: i64,
        last_seen: i64,
        expires: i64,
        disabled: bool,
    ) -> (String, String) {
        let uid = locksy_core::crypto::new_uuid();
        let sid = locksy_core::crypto::new_uuid();
        let token = format!("jeton-{sid}");
        let (u, s, h) = (uid.clone(), sid.clone(), sha256_hex(&token));
        st.db
            .call(move |c| {
                c.execute(
                    "INSERT INTO users (id, email, name, role, disabled, kdf, auth_hash, wrapped_user_key,
                         recovery_wrapped_user_key, recovery_auth_hash, public_key, wrapped_private_key,
                         created_at, updated_at)
                     VALUES (?1, ?2, 'Test', ?3, ?4, 'k', 'h', 'w', 'rw', 'rh', 'p', 'wp', ?5, 0)",
                    params![u, format!("{u}@example.com"), role, disabled, created_at],
                )?;
                c.execute(
                    "INSERT INTO sessions (id, token_hash, user_id, created_at, last_seen_at, expires_at, ip, device)
                     VALUES (?1, ?2, ?3, 0, ?4, ?5, '', '')",
                    params![s, h, u, last_seen, expires],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        (sid, token)
    }

    async fn extract(st: &AppState, token: &str) -> ApiResult<AuthUser> {
        extract_from(st, token, None, "/api/vault").await
    }

    /// Extraction depuis une adresse cliente et un chemin donnés.
    async fn extract_from(st: &AppState, token: &str, peer: Option<&str>, path: &str) -> ApiResult<AuthUser> {
        let req = axum::http::Request::builder()
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();
        if let Some(p) = peer {
            parts.extensions.insert(ConnectInfo(SocketAddr::new(ip(p), 4000)));
        }
        AuthUser::from_request_parts(&mut parts, st).await
    }

    /// Écrit des réglages en base (clé, valeur JSON, date de modification),
    /// comme le ferait une révision.
    async fn reglages(st: &AppState, rows: Vec<(&'static str, &'static str, i64)>) {
        st.db
            .call(move |c| {
                for (key, value, at) in &rows {
                    c.execute(
                        "INSERT OR REPLACE INTO org_settings (key, value, updated_at) VALUES (?1, ?2, ?3)",
                        params![key, value, at],
                    )?;
                }
                c.execute("UPDATE settings_meta SET revision = revision + 1 WHERE id = 1", [])?;
                db::mark_settings_changed();
                Ok(())
            })
            .await
            .unwrap();
    }

    async fn last_seen_of(st: &AppState, sid: &str) -> Option<i64> {
        let sid = sid.to_string();
        st.db
            .read(move |c| {
                Ok(c.query_row("SELECT last_seen_at FROM sessions WHERE id = ?1", [sid], |r| r.get(0)).optional()?)
            })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn session_expiree_supprimee() {
        let st = test_state().await;
        let now = now_unix();
        let (sid, token) = session(&st, now, now - 1, false).await;
        let err = extract(&st, &token).await.unwrap_err();
        assert_eq!((err.status, err.code), (StatusCode::UNAUTHORIZED, "unauthorized"));
        assert_eq!(err.message, "Session expirée. Reconnectez-vous.");
        assert_eq!(last_seen_of(&st, &sid).await, None);

        // Compte désactivé : session supprimée, raison donnée (403), puis 401.
        let (sid, token) = session(&st, now, now + 3600, true).await;
        let err = extract(&st, &token).await.unwrap_err();
        assert_eq!((err.status, err.code), (StatusCode::FORBIDDEN, "account_disabled"));
        assert_eq!(last_seen_of(&st, &sid).await, None);
        assert_eq!(extract(&st, &token).await.unwrap_err().code, "unauthorized");

        // Jeton inconnu.
        assert_eq!(extract(&st, "inconnu").await.unwrap_err().code, "unauthorized");
    }

    #[tokio::test]
    async fn last_seen_rafraichi_au_dela_de_30_s() {
        let st = test_state().await;
        let now = now_unix();
        let (sid, token) = session(&st, now - 10, now + 3600, false).await;
        let user = extract(&st, &token).await.unwrap();
        assert_eq!(user.session_id, sid);
        assert_eq!(last_seen_of(&st, &sid).await, Some(now - 10), "pas d'écriture sous 30 s");

        let (sid, token) = session(&st, now - 120, now + 3600, false).await;
        extract(&st, &token).await.unwrap();
        assert!(last_seen_of(&st, &sid).await.unwrap() >= now, "rafraîchie au-delà de 30 s");
    }

    #[tokio::test]
    async fn deux_fa_exigee_inchangee() {
        let st = test_state().await;
        st.db
            .call(|c| {
                let mut s = db::load_settings(c)?;
                s.require_2fa = true;
                db::save_settings(c, &s)
            })
            .await
            .unwrap();
        let now = now_unix();
        let (_, token) = session(&st, now, now + 3600, false).await;
        let err = extract(&st, &token).await.unwrap_err();
        assert_eq!((err.status, err.code), (StatusCode::FORBIDDEN, "2fa_required"));
    }

    #[tokio::test]
    async fn deux_fa_pendant_le_delai_de_grace() {
        let st = test_state().await;
        let now = now_unix();
        // Règle posée maintenant, délai de 7 jours par défaut : la requête passe.
        reglages(&st, vec![("twofa.required", "true", now)]).await;
        let (_, token) = session(&st, now, now + 3600, false).await;
        assert!(extract(&st, &token).await.is_ok());
    }

    #[tokio::test]
    async fn deux_fa_apres_l_echeance() {
        let st = test_state().await;
        let now = now_unix();
        reglages(&st, vec![("twofa.required", "true", now - 8 * 86_400), ("twofa.grace_days", "7", 0)]).await;
        let (_, token) = session(&st, now, now + 3600, false).await;
        let err = extract(&st, &token).await.unwrap_err();
        assert_eq!((err.status, err.code), (StatusCode::FORBIDDEN, "2fa_required"));
        // Un compte créé après la règle a son propre délai.
        let (_, recent) = session_as(&st, "user", now - 86_400, now, now + 3600, false).await;
        assert!(extract(&st, &recent).await.is_ok());
        // Le profil reste accessible pour activer la 2FA.
        assert!(extract_from(&st, &token, None, "/api/me/2fa/setup").await.is_ok());
    }

    #[tokio::test]
    async fn deux_fa_exigee_par_role() {
        let st = test_state().await;
        let now = now_unix();
        reglages(&st, vec![("twofa.required_roles", r#"["admin"]"#, now - 30 * 86_400), ("twofa.grace_days", "0", 0)]).await;
        let (_, user) = session_as(&st, "user", 0, now, now + 3600, false).await;
        let (_, admin) = session_as(&st, "admin", 0, now, now + 3600, false).await;
        assert!(extract(&st, &user).await.is_ok());
        assert_eq!(extract(&st, &admin).await.unwrap_err().code, "2fa_required");
    }

    #[tokio::test]
    async fn adresse_hors_liste_blanche() {
        let st = test_state().await;
        let now = now_unix();
        reglages(&st, vec![("access.ip_allowlist", r#"["10.0.0.0/8"]"#, now), ("access.ip_rescue", r#"["203.0.113.7"]"#, now)])
            .await;
        let (sid, user) = session(&st, now, now + 3600, false).await;
        assert!(extract_from(&st, &user, Some("10.1.2.3"), "/api/vault").await.is_ok());
        let err = extract_from(&st, &user, Some("192.0.2.1"), "/api/vault").await.unwrap_err();
        assert_eq!((err.status, err.code), (StatusCode::FORBIDDEN, "ip_not_allowed"));
        // Adresse inconnue : refusée aussi. La session n'est pas purgée et la
        // déconnexion passe.
        assert_eq!(extract(&st, &user).await.unwrap_err().code, "ip_not_allowed");
        assert!(last_seen_of(&st, &sid).await.is_some());
        assert!(extract_from(&st, &user, Some("192.0.2.1"), "/api/auth/logout").await.is_ok());
        // L'adresse de secours ne vaut que pour un propriétaire.
        assert_eq!(extract_from(&st, &user, Some("203.0.113.7"), "/api/vault").await.unwrap_err().code, "ip_not_allowed");
        let (_, owner) = session_as(&st, "owner", 0, now, now + 3600, false).await;
        assert!(extract_from(&st, &owner, Some("203.0.113.7"), "/api/vault").await.is_ok());
        assert_eq!(extract_from(&st, &owner, Some("192.0.2.1"), "/api/vault").await.unwrap_err().code, "ip_not_allowed");
    }

    #[tokio::test]
    async fn inactivite_lue_dans_le_registre() {
        let st = test_state().await;
        let now = now_unix();
        reglages(&st, vec![("session.idle_minutes", "5", now)]).await;
        let (sid, token) = session(&st, now - 6 * 60, now + 3600, false).await;
        assert_eq!(extract(&st, &token).await.unwrap_err().code, "unauthorized");
        assert_eq!(last_seen_of(&st, &sid).await, None);
        let (_, token) = session(&st, now - 4 * 60, now + 3600, false).await;
        assert!(extract(&st, &token).await.is_ok());
    }
}
