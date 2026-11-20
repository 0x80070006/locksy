//! Serveur Locksy.
//!
//! Sous-commandes :
//! - `locksy-server` ou `locksy-server serve` : démarre le serveur ;
//! - `locksy-server healthcheck` : sonde /api/health en local (Docker) ;
//! - `locksy-server check` : vérifie configuration, base, intégrité et clé serveur
//!   sans rien modifier (code 0 = tout va bien, 1 = problème, 2 = configuration invalide) ;
//! - `locksy-server backup <fichier> [--with-key] [--force]` : sauvegarde à chaud,
//!   vérifiée, de la base (et de la clé serveur avec `--with-key`) ;
//! - `locksy-server verify-audit` : vérifie le chaînage du journal d'audit ;
//! - `locksy-server version`, `locksy-server help`.
//!
//! Variables d'environnement (validées au démarrage : une valeur illisible
//! arrête le serveur avec un message clair et le code de sortie 2) :
//! - `LOCKSY_BIND`        adresse d'écoute `hote:port` (défaut `0.0.0.0:8743`)
//! - `LOCKSY_DATA`        dossier des données (défaut `/data`)
//! - `LOCKSY_WEB`         dossier de l'interface web (défaut `/app/web`)
//! - `LOCKSY_TRUST_PROXY` `true` derrière un proxy inverse TLS de confiance (défaut `false` ;
//!   accepte true/false, 1/0, yes/no) : l'adresse cliente est l'entrée la plus à DROITE
//!   de X-Forwarded-For (celle qu'ajoute le proxy ; la plus à gauche est fournie par le client)
//! - `LOCKSY_TRUSTED_PROXIES` IP ou CIDR des proxys de confiance, séparés par des
//!   virgules (ex. `10.0.0.0/8,192.168.1.10`) ; sans effet si `LOCKSY_TRUST_PROXY`
//!   n'est pas `true`. Les connexions d'autres pairs voient leur X-Forwarded-For
//!   ignoré, et ces proxys sont sautés depuis la droite (chaîne de proxys).
//! - `LOCKSY_TLS_CERT` / `LOCKSY_TLS_KEY` certificat (chaîne PEM) et clé : HTTPS intégré
//!   (les deux ensemble, ou aucun)
//! - `LOCKSY_HTTP_REDIRECT` adresse d'écoute HTTP qui redirige vers HTTPS (ex. `0.0.0.0:8080`)
//! - `LOCKSY_SYSLOG`      envoi du journal d'audit vers un SIEM (`udp://hote:514`,
//!   `tcp://hote:514` ou `tcp+tls://hote:6514`)
//! - `LOCKSY_SYSLOG_CA_FILE` autorité de certification PEM supplémentaire pour `tcp+tls://`
//! - `LOCKSY_SMTP_CA_FILE` autorité de certification PEM supplémentaire du relais SMTP (e-mails)
//! - `LOCKSY_ARGON2_CONCURRENCY` calculs Argon2 simultanés, 1 à 1024 (défaut : nombre de processeurs)
//! - `LOCKSY_ARGON2_QUEUE` requêtes en attente d'un calcul Argon2 au-delà desquelles le
//!   serveur répond 503 `server_busy`, 0 à 100000 (défaut : 8 × la valeur précédente)
//! - `LOCKSY_REQUEST_TIMEOUT_SECS` délai global d'une requête, 408 au-delà, 1 à 3600 (défaut `120` ;
//!   doit couvrir l'envoi d'une pièce jointe de 16 Mo ; une synchronisation LDAP
//!   manuelle plus longue continue en tâche de fond, dans sa limite propre de 5 min)
//! - `LOCKSY_HEADER_TIMEOUT_SECS` délai de lecture des en-têtes HTTP, 1 à 300 (défaut `15`)
//! - `LOCKSY_SETUP_TOKEN` jeton d'installation imposé (au moins 20 caractères) exigé pour
//!   créer le premier compte ; sinon un jeton est généré dans `<LOCKSY_DATA>/setup-token`
//! - `LOCKSY_SERVER_KEY_FILE` chemin de la clé serveur (défaut `<LOCKSY_DATA>/server.key`)
//! - `LOCKSY_SERVER_KEY_RESET` `true` autorise à générer une nouvelle clé serveur alors que
//!   la base contient déjà des comptes (sinon le démarrage est refusé) ; dernier recours
//! - `LOCKSY_DB_READERS` connexions SQLite de lecture, 1 à 64 (défaut `4`)
//! - `LOCKSY_LOG_FORMAT` `text` (défaut) ou `json` ; le filtre vient de `RUST_LOG` (défaut `info`)
//! - `LOCKSY_SHUTDOWN_GRACE_SECS` délai laissé aux requêtes en cours à l'arrêt, 0 à 300 (défaut `10`)
//! - `LOCKSY_SSO_ALLOW_HTTP` autorise un fournisseur SSO en HTTP clair (tests uniquement)
//! - `LOCKSY_SSO_ALLOW_PRIVATE` autorise un fournisseur SSO sur un réseau interne (adresses
//!   privées ou locales) : dérogation au filtre anti-SSRF de la découverte OIDC
//! - `LOCKSY_SETTINGS_FILE` fichier JSON `{ "<clé>": valeur | {value, mode, min, max} }` validé
//!   contre le registre des réglages ; chaque clé du fichier est fixée par l'hébergeur et ne se
//!   modifie plus dans l'interface (les secrets en sont exclus)
//! - `LOCKSY_MAX_ATTACHMENT_MIB` plafond de la taille d'une pièce jointe, 1 à 15 Mio (défaut `10`)
//! - `LOCKSY_MAX_BODY_MIB` taille maximale d'une requête, 1 à 64 Mio (défaut `16`)
//! - `LOCKSY_RATELIMIT_FACTOR` multiplie les plafonds de requêtes par adresse IP, 0.1 à 100 (défaut `1`)
//! - `LOCKSY_RATELIMIT_{LOGIN,PRELOGIN,REGISTER,RECOVER,SHARE_OPEN,INVITE}_IP` plafond explicite
//!   par adresse IP, 1 à 1000000 (prioritaire sur le facteur)
//! - `LOCKSY_ENV` `production` (défaut) ou `test` (compteurs de test exposés, adresse publique
//!   en HTTP permise)
//!
//! `LOCKSY_SYSLOG` fixe aussi le réglage `audit.syslog.url` (verrouillé) ; sans
//! elle, la cible et le format de l'envoi au SIEM se règlent dans l'administration.
//!
//! L'en-tête Strict-Transport-Security est envoyé en HTTPS intégré ou derrière un proxy
//! (`LOCKSY_TRUST_PROXY=true`, qui suppose un proxy TLS).
//!
//! Chaque réponse porte un en-tête `X-Request-Id` (repris de la requête s'il est valide),
//! présent aussi dans le journal de la requête. `/api/ready` répond 503 dès que l'arrêt
//! est demandé ; les requêtes en cours disposent alors de `LOCKSY_SHUTDOWN_GRACE_SECS`.

#![forbid(unsafe_code)]

mod admin;
mod admin_people;
mod attachments;
mod audit_chain;
mod auth;
mod config;
mod db;
mod error;
mod identity_admin;
mod ldap;
mod mail;
mod me;
mod ops;
mod passwords;
mod prefs;
mod security;
mod scim;
mod settings_api;
mod shares;
mod sso;
mod state;
mod syslog;
mod vault;
#[cfg(test)] mod http_tests;
#[cfg(test)]
mod tests;

use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderName, HeaderValue, StatusCode};
use axum::response::Html;
use axum::routing::{delete, get, post, put};
use axum::Router;
use config::ServerConfig;
use locksy_core::settings::Effective;
use rusqlite::Connection;
use security::Limiter;
use state::{AppState, Config};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::compression::CompressionLayer;
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::{RequestBodyTimeoutLayer, TimeoutLayer};
use tower_http::trace::TraceLayer;
use locksy_core::now_unix;

/// En-têtes de sécurité de toutes les réponses. `hsts` ajoute
/// Strict-Transport-Security (jamais sur le serveur de redirection HTTP).
fn security_headers(router: Router<AppState>, hsts: bool) -> Router<AppState> {
    // Deux ans. Pas de `includeSubDomains` : il imposerait HTTPS à tous les
    // sous-domaines du nom d'hôte, ce qui peut casser des services intranet.
    let router = if hsts {
        router.layer(SetResponseHeaderLayer::if_not_present(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=63072000"),
        ))
    } else {
        router
    };
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

/// Routes de l'API. `max_body_mib` : taille maximale d'une requête
/// (`LOCKSY_MAX_BODY_MIB`).
fn api_router(max_body_mib: i64) -> Router<AppState> {
    let max_body = usize::try_from(max_body_mib.max(1)).unwrap_or(16) * 1024 * 1024;
    Router::new()
        .route("/health", get(auth::health))
        .route("/ready", get(ops::ready))
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
        .route("/passwords/pepper", get(passwords::pepper_info))
        .route("/passwords/fingerprints", post(passwords::claim))
        .route("/items", post(vault::create_item))
        .route("/items/batch", post(vault::create_items_batch))
        .route("/items/:id", put(vault::update_item).delete(vault::trash_item))
        .route("/items/:id/restore", post(vault::restore_item))
        .route("/items/:id/purge", delete(vault::purge_item))
        .route(
            "/items/:item_id/attachments/:id",
            put(attachments::upload).layer(DefaultBodyLimit::max(attachments::upload_body_limit(max_body))),
        )
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
        // Réglages : le PUT historique (5 champs) reste servi par admin.rs
        // pendant une version ; ses écritures passent par le pont du registre.
        .route(
            "/admin/settings",
            get(settings_api::get_settings).put(admin::put_settings).patch(settings_api::patch_settings),
        )
        .route("/admin/settings/schema", get(settings_api::get_schema))
        .route("/admin/settings/validate", post(settings_api::validate_settings))
        .route("/admin/settings/reset", post(settings_api::reset_settings))
        .route("/admin/settings/profile", post(settings_api::apply_profile))
        .route("/admin/settings/history", get(settings_api::history))
        .route("/admin/settings/revert/:revision", post(settings_api::revert))
        .route("/admin/settings/export", get(settings_api::export))
        .route("/admin/settings/import", post(settings_api::import))
        .route("/admin/config/effective", get(settings_api::config_effective))
        .route("/settings/public", get(settings_api::get_public))
        .route("/settings/policy", get(settings_api::get_policy))
        .route("/branding/logo", get(settings_api::get_logo))
        .route(
            "/me/prefs",
            get(prefs::get_prefs).put(prefs::put_prefs).layer(DefaultBodyLimit::max(prefs::PREFS_BODY_LIMIT)),
        )
        .route("/me/charter", get(prefs::get_charter).post(prefs::accept_charter))
        .route("/test/counters", get(settings_api::test_counters))
        // ---- Routes L7 (vague 2) : début ----
        // Authentification et compte (auth.rs et me.rs), coffres, liens et
        // pièces jointes (vault.rs, shares.rs), journal chaîné (audit_chain.rs).
        .merge(auth::router())
        .merge(vault::router())
        .merge(audit_chain::router())
        // ---- Routes L7 (vague 2) : fin ----
        // Routes des lots de la vague 2, déclarées dans leur module.
        .merge(admin_people::router())
        .merge(identity_admin::router())
        .merge(mail::router())
        // Refus par défaut (constat #54) : toute route hors de
        // security::PUBLIQUES exige un jeton avant son handler.
        .route_layer(axum::middleware::from_fn(security::refus_par_defaut))
        // Route d'API inconnue : erreur JSON (et no-store), pas la page statique.
        .fallback(|| async { error::ApiError::not_found("Ressource introuvable.") })
        .layer(SetResponseHeaderLayer::overriding(header::CACHE_CONTROL, HeaderValue::from_static("no-store")))
        .layer(DefaultBodyLimit::max(max_body))
}

/// Réponse à une panique d'un handler : 500 générique. Le contenu de la
/// panique n'est ni renvoyé ni journalisé (il peut contenir des données).
fn panic_response(_err: Box<dyn std::any::Any + Send + 'static>) -> axum::response::Response {
    use axum::response::IntoResponse;
    tracing::error!("panique dans le traitement d'une requête");
    error::ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "Erreur interne du serveur.").into_response()
}

fn build_app(state: AppState) -> Router {
    let config = state.config.clone();
    let web_dir = state.config.web_dir.clone();
    let share_page = web_dir.join("share.html");
    let router = Router::new()
        .nest("/api", api_router(state.host.caps.max_body_mib))
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
        // Interface web compressée (gzip) : environ 3 fois moins d'octets pour
        // le JS et le wasm. L'API n'est pas compressée (réponses chiffrées,
        // peu compressibles, et rien à gagner à mêler secrets et compression).
        .fallback_service(
            Router::new()
                .fallback_service(ServeDir::new(web_dir).append_index_html_on_directories(true))
                .layer(CompressionLayer::new().gzip(true)),
        );
    harden(router, &config).with_state(state)
}

/// Couches communes à toutes les routes, de l'intérieur vers l'extérieur.
fn harden(router: Router<AppState>, config: &Config) -> Router<AppState> {
    let trace = TraceLayer::new_for_http()
        .make_span_with(ops::MakeRequestSpan)
        .on_request(())
        .on_response(ops::LogResponse)
        .on_body_chunk(())
        .on_eos(())
        .on_failure(ops::LogFailure);
    let router = router
        // Délai global (408) et délai de réception du corps : une requête
        // lente ne retient pas indéfiniment une connexion ni un fil.
        .layer(RequestBodyTimeoutLayer::new(config.request_timeout))
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, config.request_timeout))
        // Une panique devient un 500 au lieu de couper la connexion.
        .layer(CatchPanicLayer::custom(panic_response))
        // Journal des requêtes : route générique, statut et latence (jamais
        // l'URI réelle). Il voit aussi les 408 et les 500 de panique.
        .layer(trace)
        // Identifiant de requête : enveloppe tout ce qui précède, pour que les
        // réponses 408 et 500 le portent et que le journal le connaisse.
        .layer(axum::middleware::from_fn(ops::request_id));
    // Les en-têtes de sécurité (sans logique pouvant paniquer) restent les
    // plus externes : toutes les réponses les portent.
    security_headers(router, config.hsts)
}

/// Purge périodique (toutes les 10 minutes), réglages lus dans le cache.
async fn housekeeping(state: AppState) {
    let mut tick = tokio::time::interval(Duration::from_secs(600));
    loop {
        tick.tick().await;
        state.limiter.cleanup();
        let eff = match state.effective().await {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(message = %e.message, "maintenance périodique : réglages illisibles");
                continue;
            }
        };
        let res = state
            .db
            .call(move |c| {
                maintenance(c, &eff, now_unix());
                Ok(())
            })
            .await;
        if let Err(e) = res {
            tracing::warn!(message = %e.message, "maintenance périodique en échec");
        }
    }
}

/// Une étape de maintenance : un échec est journalisé sans empêcher les suivantes.
fn step(name: &'static str, f: impl FnOnce() -> error::ApiResult<usize>) {
    match f() {
        Ok(0) => {}
        Ok(n) => tracing::info!(etape = name, lignes = n, "maintenance"),
        Err(e) => tracing::warn!(etape = name, message = %e.message, "étape de maintenance en échec"),
    }
}

/// Maintenance : sessions, jetons, liens, invitations, corbeille, journal,
/// comptes inactifs, désinscriptions de l'annuaire, file d'e-mails, pierres
/// tombales de la synchronisation.
pub(crate) fn maintenance(c: &mut Connection, eff: &Effective, now: i64) {
    const DAY: i64 = 86_400;
    let idle = eff.int("session.idle_minutes") * 60;
    step("sessions", || Ok(c.execute("DELETE FROM sessions WHERE expires_at < ?1 OR last_seen_at < ?2", [now, now - idle])?));
    step("recuperation", || Ok(c.execute("DELETE FROM recovery_tokens WHERE expires_at < ?1", [now])?));
    // Liens : état terminal (expiré ou épuisé) au lieu de la suppression,
    // puis purge avec leurs révélations après la durée de conservation du journal.
    // Le contenu chiffré d'un lien terminé est effacé tout de suite : seule
    // sa trace (dates, compteurs) est conservée.
    step("liens", || {
        Ok(c.execute(
            "UPDATE shares SET state = CASE WHEN views >= max_views THEN 'exhausted' ELSE 'expired' END,
                 ended_at = ?1,
                 ended_reason = CASE WHEN views >= max_views THEN 'exhausted' ELSE 'expired' END,
                 data = ''
             WHERE state = 'active' AND (expires_at < ?1 OR views >= max_views)",
            [now],
        )?)
    });
    let audit_cutoff = now - eff.int("retention.audit_days") * DAY;
    step("liens_termines", || {
        let tx = c.transaction()?;
        tx.execute(
            "DELETE FROM share_reveals WHERE share_id IN (SELECT id FROM shares WHERE state <> 'active' AND ended_at < ?1)",
            [audit_cutoff],
        )?;
        let n = tx.execute("DELETE FROM shares WHERE state <> 'active' AND ended_at < ?1", [audit_cutoff])?;
        tx.commit()?;
        Ok(n)
    });
    step("invitations", || {
        let cutoff = now - eff.int("retention.expired_invites_days") * DAY;
        Ok(c.execute("DELETE FROM invites WHERE used_at IS NULL AND expires_at < ?1", [cutoff])?)
    });
    step("corbeille", || {
        Ok(c.execute(
            "DELETE FROM items WHERE deleted_at IS NOT NULL AND COALESCE(purge_at, deleted_at + ?1) < ?2",
            [eff.int("retention.trash_days") * DAY, now],
        )?)
    });
    step("journal", || {
        let tx = c.transaction()?;
        audit_chain::before_purge(&tx, audit_cutoff)?;
        let n = tx.execute("DELETE FROM audit WHERE at < ?1", [audit_cutoff])?;
        tx.commit()?;
        Ok(n)
    });
    let inactive_days = eff.int("users.disable_after_inactive_days");
    if inactive_days > 0 {
        step("comptes_inactifs", || disable_inactive(c, now, inactive_days));
    }
    step("acces_echus", || disable_expired(c, now));
    step("desinscriptions", || identity_admin::purge_deprovisioned(c, now));
    step("e-mails", || mail::housekeeping(c, now).map(|()| 0));
    step("pierres_tombales", || {
        let cutoff = now - 90 * DAY;
        let tx = c.transaction()?;
        tx.execute(
            "UPDATE sync_state SET purged_before = MAX(purged_before,
                 COALESCE((SELECT MAX(seq) FROM sync_tombstones WHERE at < ?1), 0)) WHERE id = 1",
            [cutoff],
        )?;
        let n = tx.execute("DELETE FROM sync_tombstones WHERE at < ?1", [cutoff])?;
        tx.commit()?;
        Ok(n)
    });
}

/// Désactive les comptes (sauf propriétaires) sans connexion depuis `days`
/// jours : sessions fermées, événement `user.disabled_inactive`.
fn disable_inactive(c: &mut Connection, now: i64, days: i64) -> error::ApiResult<usize> {
    let tx = c.transaction()?;
    let users: Vec<(String, String)> = {
        let mut st = tx.prepare(
            "SELECT id, email FROM users WHERE disabled = 0 AND role <> 'owner'
             AND COALESCE(last_login_at, created_at) < ?1",
        )?;
        let rows = st.query_map([now - days * 86_400], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<Vec<_>, _>>()?;
        rows
    };
    let meta = state::ClientMeta { ip: String::new(), user_agent: "locksy-server".into() };
    for (id, email) in &users {
        tx.execute(
            "UPDATE users SET disabled = 1, disabled_at = ?1, disabled_reason = 'inactive', updated_at = ?1 WHERE id = ?2",
            rusqlite::params![now, id],
        )?;
        tx.execute("DELETE FROM sessions WHERE user_id = ?1", [id])?;
        state::audit(&tx, Some(id), email, "user.disabled_inactive", id, &meta, &format!("aucune connexion depuis {days} jours"))?;
    }
    tx.commit()?;
    Ok(users.len())
}

/// Désactive les comptes dont la date de fin d'accès (`access_until`) est
/// passée (motif « expired ») : sessions fermées, liens révoqués, événement
/// `user.disabled_expired`. Le dernier propriétaire actif est épargné.
fn disable_expired(c: &mut Connection, now: i64) -> error::ApiResult<usize> {
    let tx = c.transaction()?;
    let users: Vec<(String, String, String)> = {
        let mut st = tx.prepare(
            "SELECT id, email, role FROM users WHERE disabled = 0 AND access_until IS NOT NULL AND access_until <= ?1",
        )?;
        let rows = st.query_map([now], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<Result<Vec<_>, _>>()?;
        rows
    };
    let meta = state::ClientMeta { ip: String::new(), user_agent: "locksy-server".into() };
    let mut n = 0;
    for (id, email, role) in &users {
        match admin::set_disabled_reason(&tx, id, role, true, "expired") {
            Ok(()) => {
                state::audit(&tx, Some(id), email, "user.disabled_expired", id, &meta, "date de fin d'accès dépassée")?;
                n += 1;
            }
            Err(e) if e.code == "last_owner" => {}
            Err(e) => return Err(e),
        }
    }
    tx.commit()?;
    Ok(n)
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! { _ = ctrl_c => {}, _ = term.recv() => {} }
            }
            Err(e) => {
                tracing::warn!("signal SIGTERM non surveillé : {e}");
                let _ = ctrl_c.await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
    tracing::info!("arrêt demandé");
}

/// Reprend la base d'une installation antérieure (nom de fichier d'avant Locksy).
fn migrate_data_files(dir: &Path) -> Result<(), String> {
    let new = dir.join("locksy.db");
    let old = dir.join("verrou.db");
    if !new.exists() && old.exists() {
        for suffix in ["", "-wal", "-shm"] {
            let from = dir.join(format!("verrou.db{suffix}"));
            let to = dir.join(format!("locksy.db{suffix}"));
            if from.exists() {
                std::fs::rename(&from, &to).map_err(|e| {
                    format!(
                        "reprise de l'ancienne base impossible ({} vers {}) : {e}. Vérifiez les droits du dossier de données.",
                        from.display(),
                        to.display()
                    )
                })?;
            }
        }
        tracing::info!("base de données d'une installation antérieure reprise");
    }
    Ok(())
}

/// Petit serveur HTTP qui renvoie vers la même adresse en HTTPS. Il s'arrête
/// avec le serveur principal (`stop` passe à vrai).
async fn http_redirect(bind: String, mut stop: tokio::sync::watch::Receiver<bool>) {
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
            let stopped = async move {
                let _ = stop.wait_for(|s| *s).await;
            };
            if let Err(e) = axum::serve(l, app).with_graceful_shutdown(stopped).await {
                tracing::warn!("redirection HTTP interrompue : {e}");
            }
        }
        Err(e) => tracing::warn!("redirection HTTP impossible sur {bind} : {e}"),
    }
}

/// Sous-commande `healthcheck` pour Docker (image sans curl).
fn healthcheck(bind: &str, tls: bool) -> ! {
    use std::io::{Read, Write};
    let port = bind.rsplit(':').next().and_then(|p| p.parse::<u16>().ok()).unwrap_or(8743);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    if tls {
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

const USAGE: &str = "\
Usage : locksy-server [commande]

Commandes :
  serve                                  démarre le serveur (par défaut)
  healthcheck                            sonde /api/health en local (Docker)
  check                                  vérifie configuration, base et clé serveur, sans rien modifier
                                         (code 0 : tout va bien, 1 : problème, 2 : configuration invalide)
  backup <fichier> [--with-key] [--force]
                                         sauvegarde à chaud et vérifiée de la base ; --with-key copie
                                         aussi la clé serveur dans <fichier>.server.key ; --force
                                         remplace une sauvegarde existante
  verify-audit                           vérifie le chaînage du journal d'audit
  version                                affiche la version
  help                                   affiche cette aide

La configuration se fait par variables d'environnement (LOCKSY_DATA, LOCKSY_BIND, ...).";

/// Arguments de `backup` : fichier, `--with-key`, `--force` (dans n'importe quel ordre).
fn parse_backup_args(args: &[String]) -> Result<(std::path::PathBuf, bool, bool), String> {
    let (mut file, mut with_key, mut force) = (None, false, false);
    for a in args {
        match a.as_str() {
            "--with-key" => with_key = true,
            "--force" => force = true,
            s if s.starts_with('-') => return Err(format!("option inconnue : « {s} »")),
            s if file.is_none() => file = Some(std::path::PathBuf::from(s)),
            s => return Err(format!("argument en trop : « {s} »")),
        }
    }
    let file = file.ok_or("indiquez le fichier de sauvegarde, par exemple : locksy-server backup /sauvegardes/locksy.db")?;
    Ok((file, with_key, force))
}

fn usage_error(msg: &str) -> ! {
    eprintln!("Erreur : {msg}\n\n{USAGE}");
    std::process::exit(2)
}

/// Erreur fatale au démarrage : message clair sur la sortie d'erreur, code 1.
fn fatal(msg: impl std::fmt::Display) -> ! {
    tracing::error!("démarrage impossible");
    eprintln!("Erreur : {msg}");
    std::process::exit(1)
}

fn init_logs(json: bool) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    if json {
        tracing_subscriber::fmt().json().with_current_span(true).with_span_list(false).with_env_filter(filter).init();
    } else {
        // Couleurs seulement dans un terminal : sous Docker ou journald, les
        // codes ANSI pollueraient `docker logs` et le SIEM.
        let ansi = std::io::IsTerminal::is_terminal(&std::io::stdout());
        tracing_subscriber::fmt().with_ansi(ansi).with_env_filter(filter).init();
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("serve");
    match command {
        // Tolérante : seules LOCKSY_BIND et la présence du TLS comptent.
        "healthcheck" => {
            let (bind, tls) = config::healthcheck_target(|k| std::env::var(k).ok());
            healthcheck(&bind, tls)
        }
        "version" | "--version" | "-V" => {
            println!("locksy-server {} (schéma de base v{})", env!("CARGO_PKG_VERSION"), db::SCHEMA_VERSION);
            return;
        }
        "help" | "--help" | "-h" => {
            println!("{USAGE}");
            return;
        }
        "check" => {
            if args.len() > 1 {
                usage_error("check ne prend pas d'argument");
            }
            std::process::exit(ops::check(&config::from_env()));
        }
        "verify-audit" => std::process::exit(audit_chain::verify_command(&args[1..])),
        "serve" | "backup" => {}
        other => usage_error(&format!("commande inconnue : « {other} »")),
    }
    let backup_args = if command == "backup" {
        Some(parse_backup_args(&args[1..]).unwrap_or_else(|e| usage_error(&e)))
    } else {
        if args.len() > 1 {
            usage_error("serve ne prend pas d'argument");
        }
        None
    };

    let cfg = match config::from_env() {
        Ok(c) => c,
        Err(errors) => {
            eprintln!("Configuration invalide :");
            for e in errors {
                eprintln!("  - {e}");
            }
            std::process::exit(2)
        }
    };
    init_logs(cfg.log_json);

    if let Some((file, with_key, force)) = backup_args {
        match ops::backup(&cfg, &file, with_key, force) {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("Erreur : {e}");
                std::process::exit(1)
            }
        }
    }
    serve(cfg).await
}

/// Démarrage complet, service, puis arrêt ordonné.
async fn serve(cfg: ServerConfig) {
    let ServerConfig {
        app: config,
        db_path,
        server_key_file,
        server_key_reset,
        db_readers,
        tls,
        http_redirect: redirect,
        syslog: syslog_target,
        syslog_ca_file,
        log_json: _,
        shutdown_grace,
        host,
    } = cfg;

    syslog::init(syslog_target.as_deref(), syslog_ca_file.as_deref());
    if let Err(e) = ops::create_private_dir(&config.data_dir) {
        fatal(format!("dossier de données {} inaccessible : {e}", config.data_dir.display()));
    }
    if let Err(e) = migrate_data_files(&config.data_dir) {
        fatal(e);
    }
    let db = db::Db::open_with(&db_path, db::DbOptions { readers: db_readers })
        .unwrap_or_else(|e| fatal(format!("base de données {} : {e}", db_path.display())));
    let users: i64 = db
        .call(|c| Ok(c.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?))
        .await
        .unwrap_or_else(|e| fatal(format!("lecture de la base impossible : {}", e.message)));
    let server_key = match ops::load_or_create_server_key(&server_key_file, users > 0, server_key_reset) {
        Ok(k) => k,
        Err(e) => fatal(e),
    };
    // Clé du journal chaîné : avant toute écriture d'audit et avant la maintenance.
    audit_chain::install_key(&server_key);

    // Avant tout hachage (dont l'empreinte factice ci-dessous).
    security::init_argon2_limits(config.argon2_concurrency, config.argon2_queue);
    if config.trust_proxy && config.trusted_proxies.is_empty() {
        tracing::info!("proxy inverse : adresse cliente = entrée la plus à droite de X-Forwarded-For");
    }
    let dummy_hash = security::hash_secret(locksy_core::crypto::random_bytes(32))
        .await
        .unwrap_or_else(|e| fatal(format!("calcul de l'empreinte factice : {}", e.message)));

    let state = AppState {
        db,
        server_key: Arc::new(server_key),
        limiter: Arc::new(Limiter::default()),
        config: Arc::new(config),
        dummy_hash: Arc::new(dummy_hash),
        sso: Arc::new(sso::SsoRuntime::default()),
        settings: Arc::new(settings_api::SettingsCache::default()),
        host: Arc::new(host),
        notifier: mail::build_notifier(),
    };
    if let Err(e) = auth::init_setup_token(&state.db, &state.config.data_dir).await {
        fatal(format!("jeton d'installation : {}", e.message));
    }
    // Réglages fixés par l'hébergeur : journalisés et reportés dans les
    // anciens blocs lus par les modules qui n'ont pas encore basculé.
    settings_api::set_bridge_host(state.host.caps.clone());
    if let Err(e) = settings_api::record_host_overrides(&state).await {
        tracing::warn!(message = %e.message, "réglages fixés par l'hébergeur non journalisés");
    }
    // Envoi au SIEM selon les réglages de l'organisation (audit.syslog.url
    // et audit.syslog.format), réappliqués ensuite à chaque révision.
    match state.effective().await {
        Ok(eff) => syslog::apply(&eff),
        Err(e) => tracing::warn!(message = %e.message, "réglages illisibles : envoi au SIEM selon LOCKSY_SYSLOG seul"),
    }
    let mut tasks = vec![
        tokio::spawn(housekeeping(state.clone())),
        tokio::spawn(ldap::sync_loop(state.clone())),
        tokio::spawn(mail::worker(state.clone())),
    ];

    // Au signal : /api/ready passe à 503, les requêtes en cours ont le délai
    // de grâce, la redirection HTTP s'arrête aussi.
    let handle = axum_server::Handle::new();
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    {
        let handle = handle.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            ops::SHUTTING_DOWN.store(true, Ordering::SeqCst);
            handle.graceful_shutdown(Some(shutdown_grace));
            let _ = stop_tx.send(true);
        });
    }
    if let Some(r) = redirect {
        tasks.push(tokio::spawn(http_redirect(r, stop_rx)));
    }

    let bind = state.config.bind.clone();
    let header_timeout = state.config.header_timeout;
    let make = build_app(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    // Écoute ouverte ici : LOCKSY_BIND peut être un nom d'hôte (`localhost:8743`).
    let listener = std::net::TcpListener::bind(&bind)
        .and_then(|l| l.set_nonblocking(true).map(|_| l))
        .unwrap_or_else(|e| fatal(format!("adresse d'écoute {bind} indisponible : {e}")));

    let result = if let Some((cert, key)) = tls {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key).await.unwrap_or_else(|e| {
            fatal(format!("certificat ou clé TLS illisible (LOCKSY_TLS_CERT / LOCKSY_TLS_KEY) : {e}"))
        });
        // Rechargement régulier : un certificat renouvelé est pris en compte sans redémarrage.
        let reload = tls.clone();
        tasks.push(tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(6 * 3600));
            tick.tick().await;
            loop {
                tick.tick().await;
                if let Err(e) = reload.reload_from_pem_file(&cert, &key).await {
                    tracing::warn!("rechargement du certificat TLS impossible : {e}");
                }
            }
        }));
        let mut server = axum_server::tls_rustls::from_tcp_rustls(listener, tls);
        limit_header_read(server.http_builder(), header_timeout);
        tracing::info!("Locksy {} à l'écoute en HTTPS sur {bind}", env!("CARGO_PKG_VERSION"));
        server.handle(handle).serve(make).await
    } else {
        let mut server = axum_server::from_tcp(listener);
        limit_header_read(server.http_builder(), header_timeout);
        tracing::info!("Locksy {} à l'écoute sur {bind}", env!("CARGO_PKG_VERSION"));
        server.handle(handle).serve(make).await
    };

    // Arrêt ordonné. Une écriture SQLite déjà lancée (fil bloquant) va à son
    // terme : le point de contrôle attend le verrou de l'écrivain.
    ops::SHUTTING_DOWN.store(true, Ordering::SeqCst);
    for t in &tasks {
        t.abort();
    }
    if let Err(e) = state.db.checkpoint().await {
        tracing::warn!(message = %e.message, "point de contrôle WAL à l'arrêt en échec");
    }
    if !tokio::task::spawn_blocking(|| syslog::flush(Duration::from_secs(5))).await.unwrap_or(false) {
        tracing::warn!("file syslog non vidée dans le délai : des événements peuvent manquer au SIEM");
    }
    match result {
        Ok(()) => tracing::info!("arrêt terminé"),
        Err(e) => {
            tracing::error!("serveur arrêté sur erreur : {e}");
            std::process::exit(1)
        }
    }
}

/// Délai de lecture des en-têtes HTTP/1 (protection contre les connexions
/// lentes de type « slowloris ») ; s'applique aussi à l'attente de la
/// requête suivante sur une connexion maintenue ouverte.
fn limit_header_read(
    builder: &mut hyper_util::server::conn::auto::Builder<hyper_util::rt::TokioExecutor>,
    timeout: Duration,
) {
    builder.http1().timer(hyper_util::rt::TokioTimer::new()).header_read_timeout(timeout);
}

#[cfg(test)]
mod tests_demarrage {
    use super::*;

    /// Copie de la configuration de test avec HSTS et délai modifiés.
    fn config_with(base: &Config, hsts: bool, request_timeout: Duration) -> Config {
        Config {
            bind: base.bind.clone(),
            data_dir: base.data_dir.clone(),
            web_dir: base.web_dir.clone(),
            trust_proxy: base.trust_proxy,
            trusted_proxies: base.trusted_proxies.clone(),
            hsts,
            request_timeout,
            header_timeout: base.header_timeout,
            argon2_concurrency: base.argon2_concurrency,
            argon2_queue: base.argon2_queue,
        }
    }

    /// Sert `app` sur un port local libre et renvoie son adresse.
    async fn serve(app: Router) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await;
        });
        addr
    }

    fn request_id_of(res: &reqwest::Response) -> String {
        res.headers().get("x-request-id").expect("x-request-id absent").to_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn hsts_selon_configuration() {
        for hsts in [false, true] {
            let mut st = state::test_state().await;
            st.config = Arc::new(config_with(&st.config, hsts, Duration::from_secs(120)));
            let addr = serve(build_app(st)).await;
            let res = reqwest::get(format!("http://{addr}/api/health")).await.unwrap();
            assert_eq!(res.status(), 200);
            assert_eq!(res.headers().get("x-frame-options").unwrap(), "DENY");
            let got = res.headers().get("strict-transport-security").map(|v| v.to_str().unwrap().to_string());
            assert_eq!(got.as_deref(), hsts.then_some("max-age=63072000"));
        }
    }

    #[tokio::test]
    async fn panique_et_delai_depasse() {
        let st = state::test_state().await;
        let config = config_with(&st.config, true, Duration::from_millis(300));
        let router = Router::new()
            .route("/panique", get(|| async { panic!("donnée secrète") }))
            .route(
                "/lent",
                get(|| async {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    "trop tard"
                }),
            );
        let addr = serve(harden(router, &config).with_state(st)).await;

        let res = reqwest::get(format!("http://{addr}/panique")).await.unwrap();
        assert_eq!(res.status(), 500);
        // Les en-têtes de sécurité et l'identifiant enveloppent aussi la réponse de panique.
        assert!(res.headers().get("strict-transport-security").is_some());
        assert!(res.headers().get("content-security-policy").is_some());
        assert_eq!(request_id_of(&res).len(), 36);
        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(body["error"], "internal");
        assert!(!body.to_string().contains("secrète"));

        let client = reqwest::Client::new();
        let res = client.get(format!("http://{addr}/lent")).header("x-request-id", "lent-1").send().await.unwrap();
        assert_eq!(res.status(), 408);
        assert_eq!(request_id_of(&res), "lent-1");
    }

    #[tokio::test]
    async fn identifiant_de_requete() {
        let st = state::test_state().await;
        let addr = serve(build_app(st)).await;
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/api/health");

        // Généré : un UUID, différent à chaque requête.
        let a = request_id_of(&client.get(&url).send().await.unwrap());
        let b = request_id_of(&client.get(&url).send().await.unwrap());
        assert_eq!(a.len(), 36);
        assert_ne!(a, b);

        // Repris tel quel s'il est valide (proxy ou client qui trace).
        let res = client.get(&url).header("x-request-id", "proxy-42.a_b:c").send().await.unwrap();
        assert_eq!(request_id_of(&res), "proxy-42.a_b:c");

        // Remplacé s'il est trop long ou contient des caractères interdits.
        for bad in ["a".repeat(200), "a b".into(), "<script>".into(), "x\ty".into()] {
            let res = client.get(&url).header("x-request-id", bad.as_str()).send().await.unwrap();
            let got = request_id_of(&res);
            assert_ne!(got, bad);
            assert_eq!(got.len(), 36, "{bad:?} -> {got}");
        }

        // Tentative d'injection d'en-tête : la ligne est coupée au CRLF, la
        // valeur non ASCII est refusée ; aucune réponse ne recopie l'injection.
        let raw = tokio::task::spawn_blocking(move || {
            use std::io::{Read, Write};
            let mut s = std::net::TcpStream::connect(addr).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            s.write_all("GET /api/health HTTP/1.0\r\nHost: x\r\nX-Request-Id: \u{e9}t\u{e9}\r\n\r\n".as_bytes()).unwrap();
            let mut buf = String::new();
            s.read_to_string(&mut buf).unwrap();
            buf
        })
        .await
        .unwrap();
        let line = raw.lines().find(|l| l.to_ascii_lowercase().starts_with("x-request-id:")).expect("en-tête absent");
        assert_eq!(line.split_once(':').unwrap().1.trim().len(), 36, "{line}");

        // Fichiers statiques et route inconnue aussi.
        let res = client.get(format!("http://{addr}/inexistant.js")).send().await.unwrap();
        assert_eq!(request_id_of(&res).len(), 36);
    }

    #[tokio::test]
    async fn disponibilite_routee() {
        let st = state::test_state().await;
        let addr = serve(build_app(st)).await;
        let res = reqwest::get(format!("http://{addr}/api/ready")).await.unwrap();
        // Le statique SHUTTING_DOWN n'est jamais modifié par les tests.
        assert_eq!(res.status(), 200);
        assert_eq!(res.headers().get("cache-control").unwrap(), "no-store");
        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(body["status"], "ready");
        assert_eq!(body["schema_version"], db::SCHEMA_VERSION);
    }

    #[tokio::test]
    async fn route_d_api_inconnue_en_json() {
        let st = state::test_state().await;
        let addr = serve(build_app(st)).await;
        for chemin in ["/api/introuvable", "/api/admin/introuvable/1"] {
            let res = reqwest::get(format!("http://{addr}{chemin}")).await.unwrap();
            assert_eq!(res.status(), 404, "{chemin}");
            assert_eq!(res.headers().get("cache-control").unwrap(), "no-store", "{chemin}");
            let body: serde_json::Value = res.json().await.unwrap();
            assert_eq!(body["error"], "not_found", "{chemin}");
        }
    }

    /// L'interface web est servie compressée à qui l'accepte, avec les mêmes
    /// en-têtes de sécurité ; l'API ne l'est jamais.
    #[tokio::test]
    async fn interface_web_compressee() {
        let st = state::test_state().await;
        std::fs::create_dir_all(&st.config.web_dir).unwrap();
        std::fs::write(st.config.web_dir.join("app.js"), "export const x = 1;\n".repeat(200)).unwrap();
        let addr = serve(build_app(st)).await;
        let http = reqwest::Client::new();
        let res = http.get(format!("http://{addr}/app.js")).header("accept-encoding", "gzip").send().await.unwrap();
        assert_eq!(res.status(), 200);
        assert_eq!(res.headers().get("content-encoding").unwrap(), "gzip");
        assert_eq!(res.headers().get("cache-control").unwrap(), "no-cache");
        assert!(res.headers().get("content-security-policy").is_some());
        let compresse = res.bytes().await.unwrap().len();
        assert!(compresse < 400, "{compresse} octets compressés pour 4 000");
        // Sans Accept-Encoding : contenu brut.
        let res = http.get(format!("http://{addr}/app.js")).send().await.unwrap();
        assert!(res.headers().get("content-encoding").is_none());
        assert_eq!(res.bytes().await.unwrap().len(), 4000);
        // API : jamais compressée.
        let res = http.get(format!("http://{addr}/api/health")).header("accept-encoding", "gzip").send().await.unwrap();
        assert!(res.headers().get("content-encoding").is_none());
    }

    #[test]
    fn arguments_de_sauvegarde() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let (f, k, force) = parse_backup_args(&args(&["/b/x.db", "--with-key"])).unwrap();
        assert_eq!((f, k, force), (std::path::PathBuf::from("/b/x.db"), true, false));
        let (f, k, force) = parse_backup_args(&args(&["--force", "x.db"])).unwrap();
        assert_eq!((f, k, force), (std::path::PathBuf::from("x.db"), false, true));
        assert!(parse_backup_args(&args(&[])).is_err());
        assert!(parse_backup_args(&args(&["a.db", "b.db"])).is_err());
        assert!(parse_backup_args(&args(&["a.db", "--forcer"])).is_err());
    }

    #[test]
    fn reprise_de_l_ancienne_base() {
        let dir = std::env::temp_dir().join(format!("locksy-migr-{}", locksy_core::crypto::new_uuid()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("verrou.db"), b"x").unwrap();
        migrate_data_files(&dir).unwrap();
        assert!(dir.join("locksy.db").exists() && !dir.join("verrou.db").exists());
        // Rien à faire ensuite.
        migrate_data_files(&dir).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn delai_de_lecture_des_en_tetes() {
        let st = state::test_state().await;
        let app = build_app(st);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let mut server = axum_server::from_tcp(listener);
        limit_header_read(server.http_builder(), Duration::from_millis(300));
        tokio::spawn(async move {
            let _ = server.serve(app.into_make_service_with_connect_info::<SocketAddr>()).await;
        });
        tokio::task::spawn_blocking(move || {
            use std::io::{Read, Write};
            // Client lent : des en-têtes jamais terminés. Le serveur doit
            // fermer la connexion avant le délai de lecture du client.
            let mut s = std::net::TcpStream::connect(addr).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            s.write_all(b"GET /api/health HTTP/1.1\r\nHost: x\r\n").unwrap();
            let mut buf = Vec::new();
            let read = s.read_to_end(&mut buf);
            assert!(read.is_ok(), "la connexion lente doit être fermée par le serveur : {read:?}");

            // Une requête normale passe toujours (comme le healthcheck, en HTTP/1.0).
            let mut s = std::net::TcpStream::connect(addr).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            s.write_all(b"GET /api/health HTTP/1.0\r\nHost: localhost\r\n\r\n").unwrap();
            let mut buf = String::new();
            s.read_to_string(&mut buf).unwrap();
            assert!(buf.starts_with("HTTP/1.0 200") || buf.starts_with("HTTP/1.1 200"), "{buf}");
        })
        .await
        .unwrap();
    }
}
