//! Serveur Locksy.
//!
//! Variables d'environnement :
//! - `LOCKSY_BIND`        adresse d'écoute (défaut `0.0.0.0:8743`)
//! - `LOCKSY_DATA`        dossier des données (défaut `/data`)
//! - `LOCKSY_WEB`         dossier de l'interface web (défaut `/app/web`)
//! - `LOCKSY_TRUST_PROXY` `true` derrière un proxy inverse TLS de confiance
//! - `LOCKSY_TLS_CERT` / `LOCKSY_TLS_KEY` certificat (chaîne PEM) et clé : HTTPS intégré
//! - `LOCKSY_HTTP_REDIRECT` adresse d'écoute HTTP qui redirige vers HTTPS (ex. `0.0.0.0:8080`)
//! - `LOCKSY_SYSLOG`      envoi du journal d'audit vers un SIEM (`udp://hote:514` ou `tcp://hote:514`)

#![forbid(unsafe_code)]

mod admin;
mod attachments;
mod auth;
mod db;
mod error;
mod ldap;
mod me;
mod security;
mod scim;
mod shares;
mod sso;
mod state;
mod syslog;
mod vault;

use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderName, HeaderValue};
use axum::response::Html;
use axum::routing::{delete, get, post, put};
use axum::Router;
use security::Limiter;
use state::{AppState, Config};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;
use locksy_core::crypto::SecretKey;
use locksy_core::now_unix;

fn load_or_create_server_key(dir: &Path) -> std::io::Result<SecretKey> {
    let path = dir.join("server.key");
    if path.exists() {
        let raw = std::fs::read(&path)?;
        return SecretKey::from_slice(&raw)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "server.key corrompue"));
    }
    let key = SecretKey::generate();
    std::fs::write(&path, key.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    tracing::info!("nouvelle clé serveur générée");
    Ok(key)
}

fn security_headers(router: Router<AppState>) -> Router<AppState> {
    let headers: [(&str, &str); 9] = [
        (
            "content-security-policy",
            "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; \
             connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; \
             frame-ancestors 'none'",
        ),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        ("permissions-policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
        ("x-robots-tag", "noindex, nofollow"),
        // L'interface est revalidée à chaque chargement : une mise à jour du
        // serveur est prise en compte immédiatement (l'API impose no-store).
        ("cache-control", "no-cache"),
    ];
    headers.into_iter().fold(router, |r, (name, value)| {
        r.layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        ))
    })
}

fn api_router() -> Router<AppState> {
    Router::new()
        .route("/health", get(auth::health))
        .route("/auth/prelogin", post(auth::prelogin))
        .route("/auth/register", post(auth::register))
        .route("/auth/login", post(auth::login))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/recover/start", post(auth::recover_start))
        .route("/auth/recover/finish", post(auth::recover_finish))
        .route("/invites/:token", get(auth::invite_info))
        .route("/sso/start", get(sso::start))
        .route("/sso/callback", get(sso::callback))
        .route("/sso/redeem", post(sso::redeem))
        .route("/ldap/login", post(ldap::login))
        .route("/admin/ldap", get(ldap::get_config).put(ldap::put_config))
        .route("/admin/ldap/test", post(ldap::test))
        .route("/admin/ldap/sync", post(ldap::sync_now))
        .route("/admin/sso", get(sso::get_config).put(sso::put_config))
        .route("/admin/sso/test", post(sso::test_config))
        .route("/admin/scim", get(scim::status))
        .route("/admin/scim/token", post(scim::create_token).delete(scim::revoke_token))
        .route("/admin/directory", get(scim::directory))
        .route("/me", get(me::get_me).put(me::update_me))
        .route("/me/password", post(me::change_password))
        .route("/me/recovery", post(me::rotate_recovery))
        .route("/me/2fa/setup", post(me::totp_setup))
        .route("/me/2fa/enable", post(me::totp_enable))
        .route("/me/2fa/disable", post(me::totp_disable))
        .route("/me/sessions", get(me::list_sessions))
        .route("/me/sessions/:id", delete(me::revoke_session))
        .route("/me/audit", get(me::my_audit))
        .route("/sync", get(vault::sync))
        .route("/directory", get(vault::directory))
        .route("/collections", post(vault::create_collection))
        .route("/collections/:id", put(vault::rename_collection).delete(vault::delete_collection))
        .route("/collections/:id/members", get(vault::list_members).post(vault::add_member))
        .route(
            "/collections/:id/members/:user_id",
            put(vault::update_member).delete(vault::leave_collection),
        )
        .route("/collections/:id/rotate", post(vault::rotate_collection))
        .route("/items", post(vault::create_item))
        .route("/items/batch", post(vault::create_items_batch))
        .route("/items/:id", put(vault::update_item).delete(vault::trash_item))
        .route("/items/:id/restore", post(vault::restore_item))
        .route("/items/:id/purge", delete(vault::purge_item))
        .route("/items/:item_id/attachments/:id", put(attachments::upload))
        .route("/attachments/:id", get(attachments::download).delete(attachments::remove))
        .route("/shares", get(shares::list_shares).post(shares::create_share))
        .route("/shares/:id", delete(shares::delete_share))
        .route("/public/shares/:id", get(shares::open_share))
        .route("/admin/stats", get(admin::stats))
        .route("/admin/users", get(admin::list_users))
        .route("/admin/users/:id", put(admin::update_user).delete(admin::delete_user))
        .route("/admin/users/:id/reset-2fa", post(admin::reset_2fa))
        .route("/admin/users/:id/revoke-sessions", post(admin::revoke_sessions))
        .route("/admin/invites", get(admin::list_invites).post(admin::create_invite))
        .route("/admin/invites/:id", delete(admin::delete_invite))
        .route("/admin/audit", get(admin::audit_log))
        .route("/admin/audit.csv", get(admin::audit_csv))
        .route("/admin/settings", get(admin::get_settings).put(admin::put_settings))
        .layer(SetResponseHeaderLayer::overriding(header::CACHE_CONTROL, HeaderValue::from_static("no-store")))
        .layer(DefaultBodyLimit::max(16 * 1024 * 1024))
}

fn build_app(state: AppState) -> Router {
    let web_dir = state.config.web_dir.clone();
    let share_page = web_dir.join("share.html");
    let router = Router::new()
        .nest("/api", api_router())
        .nest(
            "/scim/v2",
            scim::router()
                .layer(SetResponseHeaderLayer::overriding(header::CACHE_CONTROL, HeaderValue::from_static("no-store")))
                .layer(DefaultBodyLimit::max(1024 * 1024)),
        )
        .route(
            "/s/:id",
            get(move || {
                let page = share_page.clone();
                async move { Html(tokio::fs::read_to_string(page).await.unwrap_or_default()) }
            }),
        )
        .fallback_service(ServeDir::new(web_dir).append_index_html_on_directories(true));
    security_headers(router).with_state(state)
}

/// Purge périodique : sessions et liens expirés, corbeille et journal anciens.
async fn housekeeping(state: AppState) {
    let mut tick = tokio::time::interval(Duration::from_secs(600));
    loop {
        tick.tick().await;
        state.limiter.cleanup();
        let res = state
            .db
            .call(|c| {
                let s = db::load_settings(c)?;
                let now = now_unix();
                c.execute("DELETE FROM sessions WHERE expires_at < ?1 OR last_seen_at < ?2", [now, now - s.session_idle_minutes * 60])?;
                c.execute("DELETE FROM recovery_tokens WHERE expires_at < ?1", [now])?;
                c.execute("DELETE FROM shares WHERE expires_at < ?1 OR views >= max_views", [now])?;
                c.execute("DELETE FROM invites WHERE used_at IS NULL AND expires_at < ?1", [now - 30 * 86_400])?;
                c.execute(
                    "DELETE FROM items WHERE deleted_at IS NOT NULL AND deleted_at < ?1",
                    [now - s.trash_retention_days * 86_400],
                )?;
                c.execute("DELETE FROM audit WHERE at < ?1", [now - s.audit_retention_days * 86_400])?;
                Ok(())
            })
            .await;
        if let Err(e) = res {
            tracing::warn!(message = %e.message, "maintenance périodique en échec");
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("signal");
        tokio::select! { _ = ctrl_c => {}, _ = term.recv() => {} }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
    tracing::info!("arrêt demandé");
}

fn tls_files() -> Option<(String, String)> {
    match (std::env::var("LOCKSY_TLS_CERT"), std::env::var("LOCKSY_TLS_KEY")) {
        (Ok(c), Ok(k)) if !c.trim().is_empty() && !k.trim().is_empty() => Some((c, k)),
        _ => None,
    }
}

/// Reprend la base d'une installation antérieure (nom de fichier d'avant Locksy).
fn migrate_data_files(dir: &Path) {
    let new = dir.join("locksy.db");
    let old = dir.join("verrou.db");
    if !new.exists() && old.exists() {
        for suffix in ["", "-wal", "-shm"] {
            let from = dir.join(format!("verrou.db{suffix}"));
            if from.exists() {
                if let Err(e) = std::fs::rename(&from, dir.join(format!("locksy.db{suffix}"))) {
                    panic!("reprise de l'ancienne base impossible : {e}");
                }
            }
        }
        tracing::info!("base de données d'une installation antérieure reprise");
    }
}

/// Petit serveur HTTP qui renvoie vers la même adresse en HTTPS.
async fn http_redirect(bind: String) {
    use axum::extract::Request;
    use axum::response::{IntoResponse, Redirect};
    let app = Router::new().fallback(|req: Request| async move {
        let host = req
            .headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .map(|h| h.split(':').next().unwrap_or(h).to_string())
            .filter(|h| h.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'))
            .unwrap_or_else(|| "localhost".into());
        let path = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
        Redirect::permanent(&format!("https://{host}{path}")).into_response()
    });
    match tokio::net::TcpListener::bind(&bind).await {
        Ok(l) => {
            tracing::info!("redirection HTTP vers HTTPS sur {bind}");
            let _ = axum::serve(l, app).await;
        }
        Err(e) => tracing::warn!("redirection HTTP impossible sur {bind} : {e}"),
    }
}

/// Sous-commande `healthcheck` pour Docker (image sans curl).
fn healthcheck(bind: &str) -> ! {
    use std::io::{Read, Write};
    let port = bind.rsplit(':').next().unwrap_or("8743");
    let addr = format!("127.0.0.1:{port}").parse().expect("adresse locale valide");
    if tls_files().is_some() {
        // En HTTPS, un port qui accepte la connexion suffit.
        let ok = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(3)).is_ok();
        std::process::exit(if ok { 0 } else { 1 })
    }
    let ok = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(3))
    .and_then(|mut s| {
        s.set_read_timeout(Some(Duration::from_secs(3)))?;
        s.write_all(b"GET /api/health HTTP/1.0\r\nHost: localhost\r\n\r\n")?;
        let mut buf = String::new();
        s.read_to_string(&mut buf)?;
        Ok(buf.starts_with("HTTP/1.0 200") || buf.starts_with("HTTP/1.1 200"))
    })
    .unwrap_or(false);
    std::process::exit(if ok { 0 } else { 1 })
}

#[tokio::main]
async fn main() {
    let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
    let config = Config {
        bind: env("LOCKSY_BIND", "0.0.0.0:8743"),
        data_dir: PathBuf::from(env("LOCKSY_DATA", "/data")),
        web_dir: PathBuf::from(env("LOCKSY_WEB", "/app/web")),
        trust_proxy: env("LOCKSY_TRUST_PROXY", "false") == "true",
    };
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        healthcheck(&config.bind);
    }
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    syslog::init_from_env();
    std::fs::create_dir_all(&config.data_dir).expect("dossier de données inaccessible");
    migrate_data_files(&config.data_dir);
    let server_key = load_or_create_server_key(&config.data_dir).expect("clé serveur illisible");
    let db = db::Db::open(&config.data_dir.join("locksy.db")).expect("base de données illisible");
    let dummy_hash = security::hash_secret(locksy_core::crypto::random_bytes(32)).await.expect("hachage");

    let state = AppState {
        db,
        server_key: Arc::new(server_key),
        limiter: Arc::new(Limiter::default()),
        config: Arc::new(config),
        dummy_hash: Arc::new(dummy_hash),
        sso: Arc::new(sso::SsoRuntime::default()),
    };
    tokio::spawn(housekeeping(state.clone()));
    tokio::spawn(ldap::sync_loop(state.clone()));

    let bind = state.config.bind.clone();
    let app = build_app(state);
    if let Ok(redirect) = std::env::var("LOCKSY_HTTP_REDIRECT") {
        if !redirect.trim().is_empty() {
            tokio::spawn(http_redirect(redirect));
        }
    }
    let make = app.into_make_service_with_connect_info::<SocketAddr>();

    if let Some((cert, key)) = tls_files() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key)
            .await
            .expect("certificat ou clé TLS illisible (LOCKSY_TLS_CERT / LOCKSY_TLS_KEY)");
        // Rechargement régulier : un certificat renouvelé est pris en compte sans redémarrage.
        let reload = tls.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(6 * 3600));
            tick.tick().await;
            loop {
                tick.tick().await;
                if let Err(e) = reload.reload_from_pem_file(&cert, &key).await {
                    tracing::warn!("rechargement du certificat TLS impossible : {e}");
                }
            }
        });
        let handle = axum_server::Handle::new();
        let stopper = handle.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            stopper.graceful_shutdown(Some(Duration::from_secs(10)));
        });
        let addr: SocketAddr = bind.parse().expect("LOCKSY_BIND doit être de la forme 0.0.0.0:8443");
        tracing::info!("Locksy {} à l'écoute en HTTPS sur {bind}", env!("CARGO_PKG_VERSION"));
        axum_server::bind_rustls(addr, tls).handle(handle).serve(make).await.expect("serveur");
    } else {
        let listener = tokio::net::TcpListener::bind(&bind).await.expect("adresse d'écoute indisponible");
        tracing::info!("Locksy {} à l'écoute sur {bind}", env!("CARGO_PKG_VERSION"));
        axum::serve(listener, make).with_graceful_shutdown(shutdown_signal()).await.expect("serveur");
    }
}
