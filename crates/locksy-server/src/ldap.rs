//! Connecteur Active Directory sur site (LDAP), sans aucun service cloud.
//!
//! - **Synchronisation** : Locksy lit l'annuaire avec un compte de service en
//!   lecture seule. Les membres d'un groupe (groupes imbriqués compris)
//!   obtiennent un compte en attente ; un compte désactivé dans l'AD ou sorti
//!   du groupe perd l'accès immédiatement sur tous ses appareils.
//! - **Connexion avec le compte Windows** : identifiant et mot de passe AD
//!   vérifiés par une liaison LDAP auprès d'un contrôleur de domaine. Le mot de
//!   passe Windows n'est jamais conservé. Le mot de passe maître reste
//!   nécessaire pour déchiffrer le coffre.
//!
//! Le transport est toujours chiffré (LDAPS ou STARTTLS) et le certificat du
//! contrôleur est vérifié avec l'autorité fournie (AD CS en général).

use crate::admin::set_disabled;
use crate::db;
use crate::error::{ApiError, ApiResult};
use crate::state::{audit, audit_user, AdminUser, AppState, ClientMeta};
use axum::extract::State;
use axum::Json;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use rusqlite::{params, Connection, OptionalExtension};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use std::sync::Arc;
use std::time::Duration;
use locksy_core::api::*;
use locksy_core::crypto::{self, new_uuid};
use locksy_core::now_unix;
use zeroize::Zeroize;

const SETTINGS_KEY: &str = "ldap";
const SECRET_AAD: &str = "verrou:v1:ldap-bind-password";
/// Bit ACCOUNTDISABLE de userAccountControl.
const UAC_DISABLED: i64 = 0x2;

pub fn load_config(c: &Connection) -> ApiResult<LdapConfig> {
    let mut cfg: LdapConfig = db::load_json(c, SETTINGS_KEY)?;
    cfg.has_password = !cfg.bind_password.is_empty();
    if cfg.login_attribute.is_empty() {
        cfg.login_attribute = "sAMAccountName".into();
    }
    if cfg.email_attribute.is_empty() {
        cfg.email_attribute = "mail".into();
    }
    if cfg.label.is_empty() {
        cfg.label = "Compte Windows".into();
    }
    Ok(cfg)
}

pub fn public_info(c: &Connection) -> ApiResult<Option<SsoPublic>> {
    let cfg = load_config(c)?;
    Ok(cfg.allow_login.then(|| SsoPublic { label: cfg.label, enforced: cfg.enforce }))
}

/// Échappement des valeurs dans un filtre LDAP (RFC 4515).
pub fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\\' => out.push_str("\\5c"),
            '\0' => out.push_str("\\00"),
            c => out.push(c),
        }
    }
    out
}

fn group_clause(cfg: &LdapConfig) -> String {
    if cfg.group_dn.trim().is_empty() {
        String::new()
    } else {
        // LDAP_MATCHING_RULE_IN_CHAIN : appartenance directe ou via des groupes imbriqués.
        format!("(memberOf:1.2.840.113556.1.4.1941:={})", escape(cfg.group_dn.trim()))
    }
}

fn users_filter(cfg: &LdapConfig) -> String {
    format!("(&(objectCategory=person)(objectClass=user){})", group_clause(cfg))
}

// ------------------------------------------------------------ Connexion

fn tls_config(ca_pem: &str) -> ApiResult<Option<Arc<rustls::ClientConfig>>> {
    if ca_pem.trim().is_empty() {
        return Ok(None);
    }
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        let cert = cert.map_err(|_| ApiError::bad_request("Certificat d'autorité illisible (format PEM attendu)."))?;
        roots.add(cert).map_err(|_| ApiError::bad_request("Certificat d'autorité refusé."))?;
    }
    if roots.is_empty() {
        return Err(ApiError::bad_request("Aucun certificat trouvé dans le PEM fourni."));
    }
    Ok(Some(Arc::new(rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth())))
}

fn check_transport(cfg: &LdapConfig) -> ApiResult<()> {
    let url = cfg.url.trim().to_ascii_lowercase();
    if url.starts_with("ldaps://") || (url.starts_with("ldap://") && cfg.starttls) {
        if cfg.ca_pem.trim().is_empty() {
            return Err(ApiError::bad_request(
                "Fournissez le certificat de l'autorité (AD CS) qui a signé le certificat des contrôleurs de domaine.",
            ));
        }
        Ok(())
    } else {
        Err(ApiError::bad_request("Connexion non chiffrée refusée : utilisez ldaps:// ou activez STARTTLS."))
    }
}

async fn connect(cfg: &LdapConfig) -> ApiResult<ldap3::Ldap> {
    check_transport(cfg)?;
    let mut settings = LdapConnSettings::new().set_conn_timeout(Duration::from_secs(10)).set_starttls(cfg.starttls);
    if let Some(tls) = tls_config(&cfg.ca_pem)? {
        settings = settings.set_config(tls);
    }
    let (conn, ldap) = LdapConnAsync::with_settings(settings, cfg.url.trim())
        .await
        .map_err(|e| ApiError::bad_request(format!("Contrôleur de domaine injoignable ou certificat refusé : {e}")))?;
    ldap3::drive!(conn);
    Ok(ldap)
}

/// Liaison avec le compte de service.
async fn service_bind(cfg: &LdapConfig, server_key: &crypto::SecretKey) -> ApiResult<ldap3::Ldap> {
    let mut password = if cfg.bind_password.is_empty() {
        return Err(ApiError::bad_request("Mot de passe du compte de service manquant."));
    } else {
        crypto::decrypt_string(server_key, &cfg.bind_password, SECRET_AAD).map_err(|_| ApiError::internal("mot de passe LDAP illisible"))?
    };
    let mut ldap = connect(cfg).await?;
    let res = ldap.simple_bind(cfg.bind_dn.trim(), &password).await;
    password.zeroize();
    res.and_then(|r| r.success())
        .map_err(|_| ApiError::bad_request("Le compte de service a été refusé par l'annuaire (identifiant ou mot de passe)."))?;
    Ok(ldap)
}

// ------------------------------------------------------------ Lecture de l'annuaire

#[derive(Debug, Clone)]
pub struct AdUser {
    pub guid: String,
    pub dn: String,
    pub login: String,
    pub email: Option<String>,
    pub name: String,
    pub disabled: bool,
}

fn first(e: &SearchEntry, attr: &str) -> Option<String> {
    e.attrs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(attr))
        .and_then(|(_, v)| v.first().cloned())
        .filter(|v| !v.trim().is_empty())
}

fn guid_of(e: &SearchEntry) -> Option<String> {
    let raw = e
        .bin_attrs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("objectGUID"))
        .and_then(|(_, v)| v.first().cloned())
        .or_else(|| first(e, "objectGUID").map(|s| s.into_bytes()))?;
    (raw.len() == 16).then(|| raw.iter().map(|b| format!("{b:02x}")).collect())
}

fn to_ad_user(e: SearchEntry, cfg: &LdapConfig) -> Option<AdUser> {
    let guid = guid_of(&e)?;
    let login = first(&e, &cfg.login_attribute).or_else(|| first(&e, "sAMAccountName")).unwrap_or_default();
    let email = first(&e, &cfg.email_attribute).or_else(|| first(&e, "userPrincipalName")).map(|m| m.trim().to_lowercase());
    let name = first(&e, "displayName")
        .or_else(|| {
            let full = format!("{} {}", first(&e, "givenName").unwrap_or_default(), first(&e, "sn").unwrap_or_default());
            let full = full.trim().to_string();
            (!full.is_empty()).then_some(full)
        })
        .unwrap_or_else(|| login.clone());
    let uac: i64 = first(&e, "userAccountControl").and_then(|v| v.parse().ok()).unwrap_or(0);
    Some(AdUser { guid, dn: e.dn, login, email, name, disabled: uac & UAC_DISABLED != 0 })
}

fn attributes(cfg: &LdapConfig) -> Vec<String> {
    let mut a: Vec<String> = ["objectGUID", "sAMAccountName", "userPrincipalName", "mail", "displayName", "givenName", "sn", "userAccountControl"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    for extra in [&cfg.login_attribute, &cfg.email_attribute] {
        if !a.iter().any(|x| x.eq_ignore_ascii_case(extra)) {
            a.push(extra.clone());
        }
    }
    a
}

async fn search_users(ldap: &mut ldap3::Ldap, cfg: &LdapConfig, filter: &str) -> ApiResult<Vec<AdUser>> {
    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![Box::new(EntriesOnly::new()), Box::new(PagedResults::new(500))];
    let mut stream = ldap
        .streaming_search_with(adapters, cfg.base_dn.trim(), Scope::Subtree, filter, attributes(cfg))
        .await
        .map_err(|e| ApiError::bad_request(format!("Recherche dans l'annuaire refusée : {e}")))?;
    let mut out = Vec::new();
    while let Some(entry) = stream.next().await.map_err(|e| ApiError::bad_request(format!("Lecture de l'annuaire interrompue : {e}")))? {
        if let Some(u) = to_ad_user(SearchEntry::construct(entry), cfg) {
            out.push(u);
        }
    }
    stream
        .finish()
        .await
        .success()
        .map_err(|e| ApiError::bad_request(format!("Recherche dans l'annuaire en erreur : {e}")))?;
    Ok(out)
}

// ------------------------------------------------------------ Synchronisation

fn sync_meta() -> ClientMeta {
    ClientMeta { ip: "annuaire".into(), user_agent: "Synchronisation Active Directory".into() }
}

/// Applique l'état de l'annuaire à la base. Refuse de tout désactiver si la
/// recherche ne renvoie aucun compte (erreur de configuration ou panne).
pub fn apply_sync(c: &Connection, users: &[AdUser]) -> ApiResult<LdapSyncReport> {
    let meta = sync_meta();
    let mut report = LdapSyncReport { found: users.len(), ..Default::default() };
    let known: i64 = c.query_row("SELECT COUNT(*) FROM directory_users WHERE source = 'ldap'", [], |r| r.get(0))?;
    if users.is_empty() && known > 0 {
        return Err(ApiError::bad_request(
            "L'annuaire n'a renvoyé aucun compte : synchronisation interrompue par sécurité (aucune désactivation).",
        ));
    }
    let now = now_unix();
    let mut seen: Vec<String> = Vec::new();
    for u in users {
        let Some(email) = u.email.clone().filter(|e| e.contains('@')) else {
            report.skipped.push(format!("{} : pas d'adresse e-mail", u.login));
            continue;
        };
        let ext = format!("ad:{}", u.guid);
        seen.push(ext.clone());
        let active = !u.disabled;
        let existing: Option<(String, String, String, bool, Option<String>)> = c
            .query_row(
                "SELECT id, email, display_name, active, user_id FROM directory_users WHERE external_id = ?1 OR (external_id IS NULL AND email = ?2)",
                params![ext, email],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;
        match existing {
            None => {
                let user_id: Option<String> = c.query_row("SELECT id FROM users WHERE email = ?1", [&email], |r| r.get(0)).optional()?;
                let clash: bool = c.query_row("SELECT COUNT(*) FROM directory_users WHERE email = ?1", [&email], |r| r.get::<_, i64>(0))? > 0;
                if clash {
                    report.skipped.push(format!("{email} : adresse déjà utilisée par un autre compte de l'annuaire"));
                    continue;
                }
                c.execute(
                    "INSERT INTO directory_users (id, external_id, email, display_name, active, user_id, created_at, updated_at, source)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, 'ldap')",
                    params![new_uuid(), ext, email, u.name, active, user_id, now],
                )?;
                if let Some(uid) = &user_id {
                    let role: String = c.query_row("SELECT role FROM users WHERE id = ?1", [uid], |r| r.get(0))?;
                    if !active {
                        set_disabled(c, uid, &role, true)?;
                    }
                }
                audit(c, user_id.as_deref(), &email, "ldap.user_created", &email, &meta, if user_id.is_some() { "rattaché à un compte existant" } else { "en attente de première connexion" })?;
                report.created += 1;
            }
            Some((id, old_email, old_name, old_active, user_id)) => {
                let mut changed = false;
                if !old_email.eq_ignore_ascii_case(&email) || old_name != u.name {
                    let taken: bool = c.query_row(
                        "SELECT COUNT(*) FROM directory_users WHERE email = ?1 AND id <> ?2",
                        params![email, id],
                        |r| r.get::<_, i64>(0),
                    )? > 0;
                    if taken {
                        report.skipped.push(format!("{email} : adresse déjà utilisée"));
                    } else {
                        c.execute(
                            "UPDATE directory_users SET email = ?1, display_name = ?2, external_id = ?3, source = 'ldap', updated_at = ?4 WHERE id = ?5",
                            params![email, u.name, ext, now, id],
                        )?;
                        if let Some(uid) = &user_id {
                            let _ = c.execute("UPDATE users SET email = ?1, name = ?2, updated_at = ?3 WHERE id = ?4", params![email, u.name, now, uid]);
                        }
                        changed = true;
                    }
                }
                if old_active != active {
                    c.execute("UPDATE directory_users SET active = ?1, updated_at = ?2 WHERE id = ?3", params![active, now, id])?;
                    if let Some(uid) = &user_id {
                        let role: String = c.query_row("SELECT role FROM users WHERE id = ?1", [uid], |r| r.get(0))?;
                        set_disabled(c, uid, &role, !active)?;
                    }
                    audit(c, user_id.as_deref(), &email, if active { "ldap.user_enabled" } else { "ldap.user_disabled" }, &email, &meta, "compte désactivé dans l'annuaire")?;
                    if active { report.enabled += 1 } else { report.disabled += 1 }
                } else if changed {
                    report.updated += 1;
                }
            }
        }
    }
    // Comptes qui ne sont plus dans le groupe (ou supprimés de l'AD) : désactivés.
    let mut st = c.prepare("SELECT id, email, user_id, external_id FROM directory_users WHERE source = 'ldap' AND active = 1")?;
    let gone: Vec<(String, String, Option<String>)> = st
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get::<_, Option<String>>(3)?)))?
        .filter_map(|r| r.ok())
        .filter(|(_, _, _, ext)| ext.as_ref().is_none_or(|e| !seen.contains(e)))
        .map(|(id, email, uid, _)| (id, email, uid))
        .collect();
    for (id, email, user_id) in gone {
        c.execute("UPDATE directory_users SET active = 0, updated_at = ?1 WHERE id = ?2", params![now, id])?;
        if let Some(uid) = &user_id {
            if let Some(role) = c.query_row("SELECT role FROM users WHERE id = ?1", [uid], |r| r.get::<_, String>(0)).optional()? {
                set_disabled(c, uid, &role, true)?;
            }
        }
        audit(c, user_id.as_deref(), &email, "ldap.user_disabled", &email, &meta, "retiré du groupe Locksy ou supprimé de l'annuaire")?;
        report.disabled += 1;
    }
    Ok(report)
}

pub async fn run_sync(state: &AppState) -> ApiResult<LdapSyncReport> {
    let cfg = state.db.call(|c| load_config(c)).await?;
    if cfg.base_dn.trim().is_empty() {
        return Err(ApiError::bad_request("Racine de recherche (base DN) manquante."));
    }
    let result = async {
        let mut ldap = service_bind(&cfg, &state.server_key).await?;
        let users = search_users(&mut ldap, &cfg, &users_filter(&cfg)).await?;
        let _ = ldap.unbind().await;
        state
            .db
            .call(move |c| {
                let tx = c.unchecked_transaction()?;
                let r = apply_sync(&tx, &users)?;
                tx.commit()?;
                Ok(r)
            })
            .await
    }
    .await;
    let summary = match &result {
        Ok(r) => format!(
            "{} compte(s) lu(s) : {} créé(s), {} mis à jour, {} désactivé(s), {} réactivé(s){}",
            r.found,
            r.created,
            r.updated,
            r.disabled,
            r.enabled,
            if r.skipped.is_empty() { String::new() } else { format!(", {} ignoré(s)", r.skipped.len()) }
        ),
        Err(e) => format!("Échec : {}", e.message),
    };
    let ok = result.is_ok();
    state
        .db
        .call(move |c| {
            let mut cfg = load_config(c)?;
            cfg.last_sync = now_unix();
            cfg.last_result = summary.clone();
            db::save_json(c, SETTINGS_KEY, &cfg)?;
            audit(c, None, "", if ok { "ldap.sync" } else { "ldap.sync_failed" }, "", &sync_meta(), &summary)
        })
        .await?;
    result
}

/// Synchronisation périodique, selon l'intervalle configuré.
pub async fn sync_loop(state: AppState) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tick.tick().await;
        let Ok(cfg) = state.db.call(|c| load_config(c)).await else { continue };
        if !cfg.enabled || cfg.sync_minutes <= 0 || now_unix() - cfg.last_sync < cfg.sync_minutes * 60 {
            continue;
        }
        if let Err(e) = run_sync(&state).await {
            tracing::warn!(message = %e.message, "synchronisation Active Directory en échec");
        }
    }
}

// ------------------------------------------------------------ Connexion avec le compte Windows

/// `DOMAINE\jdupont`, `jdupont@domaine.local` ou `jdupont` → valeur à chercher.
fn normalize_login(input: &str) -> String {
    let s = input.trim();
    match s.rsplit_once('\\') {
        Some((_, user)) => user.to_string(),
        None => s.to_string(),
    }
}

pub async fn login(State(state): State<AppState>, meta: ClientMeta, Json(mut req): Json<LdapLoginRequest>) -> ApiResult<Json<LdapLoginResponse>> {
    let cfg = state.db.call(|c| load_config(c)).await?;
    if !cfg.allow_login {
        return Err(ApiError::not_found("La connexion avec le compte Windows n'est pas activée."));
    }
    let login = normalize_login(&req.username).to_lowercase();
    let user_key = format!("ldap-login:{login}");
    let ip_key = format!("ldap-ip:{}", meta.ip);
    state.limiter.check(&user_key)?;
    state.limiter.check(&ip_key)?;
    // Mot de passe vide : une liaison « non authentifiée » réussirait. Refus immédiat.
    if login.is_empty() || login.len() > 256 || req.password.is_empty() {
        req.password.zeroize();
        return Err(ApiError::unauthorized("Identifiant ou mot de passe Windows incorrect."));
    }
    let outcome = async {
        let mut ldap = service_bind(&cfg, &state.server_key).await?;
        let v = escape(&login);
        let filter = format!(
            "(&(objectCategory=person)(objectClass=user)(|({}={v})(sAMAccountName={v})(userPrincipalName={v})(mail={v})){})",
            cfg.login_attribute,
            group_clause(&cfg)
        );
        let found = search_users(&mut ldap, &cfg, &filter).await?;
        let _ = ldap.unbind().await;
        let [user] = found.as_slice() else {
            return Ok(None); // inconnu, hors du groupe, ou ambigu
        };
        if user.disabled {
            return Ok(None);
        }
        // Vérification du mot de passe par une liaison au nom de la personne.
        let mut conn = connect(&cfg).await?;
        let ok = conn.simple_bind(&user.dn, &req.password).await.and_then(|r| r.success()).is_ok();
        let _ = conn.unbind().await;
        Ok::<_, ApiError>(ok.then(|| user.clone()))
    }
    .await;
    req.password.zeroize();
    let user = match outcome? {
        Some(u) => u,
        None => {
            state.limiter.fail(&user_key, 5);
            state.limiter.fail(&ip_key, 20);
            let (l, m) = (login.clone(), meta.clone());
            state.db.call(move |c| audit(c, None, &l, "ldap.login_failed", &l, &m, "")).await?;
            return Err(ApiError::unauthorized("Identifiant ou mot de passe Windows incorrect, ou compte non autorisé pour Locksy."));
        }
    };
    state.limiter.success(&user_key);
    let email = user
        .email
        .clone()
        .filter(|e| e.contains('@'))
        .ok_or_else(|| ApiError::forbidden("Votre compte n'a pas d'adresse e-mail dans l'annuaire : contactez votre administrateur."))?;
    let subject = format!("ldap|{}", user.guid);
    let ticket = state.db.call(move |c| crate::sso::issue_ticket(c, &email, &user.name, &subject, &meta)).await?;
    let t = ticket.clone();
    let info = state
        .db
        .call(move |c| crate::sso::redeem_info(c, &t))
        .await?;
    Ok(Json(LdapLoginResponse { ticket, info }))
}

// ------------------------------------------------------------ Administration

pub async fn get_config(State(state): State<AppState>, _a: AdminUser) -> ApiResult<Json<LdapConfig>> {
    let mut cfg = state.db.call(|c| load_config(c)).await?;
    cfg.bind_password = String::new();
    Ok(Json(cfg))
}

fn sanitize(mut req: LdapConfig, old: &LdapConfig, key: &crypto::SecretKey) -> ApiResult<LdapConfig> {
    req.url = req.url.trim().to_string();
    req.bind_dn = req.bind_dn.trim().to_string();
    req.base_dn = req.base_dn.trim().to_string();
    req.group_dn = req.group_dn.trim().to_string();
    req.label = req.label.trim().chars().take(60).collect();
    for attr in [&req.login_attribute, &req.email_attribute] {
        if !attr.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(ApiError::bad_request("Nom d'attribut LDAP invalide."));
        }
    }
    req.sync_minutes = req.sync_minutes.clamp(0, 1440);
    req.bind_password = if req.bind_password.is_empty() {
        old.bind_password.clone()
    } else {
        crypto::encrypt_str(key, &req.bind_password, SECRET_AAD)
    };
    req.last_sync = old.last_sync;
    req.last_result = old.last_result.clone();
    if !req.allow_login {
        req.enforce = false;
    }
    if req.enabled || req.allow_login {
        check_transport(&req)?;
        tls_config(&req.ca_pem)?;
        if req.base_dn.is_empty() || req.bind_dn.is_empty() || req.bind_password.is_empty() {
            return Err(ApiError::bad_request("Renseignez le compte de service, son mot de passe et la racine de recherche."));
        }
    }
    Ok(req)
}

pub async fn put_config(State(state): State<AppState>, AdminUser(admin): AdminUser, Json(req): Json<LdapConfig>) -> ApiResult<Json<LdapConfig>> {
    let key = state.server_key.clone();
    let cfg = state
        .db
        .call(move |c| {
            let old = load_config(c)?;
            let cfg = sanitize(req, &old, &key)?;
            db::save_json(c, SETTINGS_KEY, &cfg)?;
            audit_user(
                c,
                &admin,
                "admin.ldap_updated",
                &cfg.url,
                &format!(
                    "synchronisation : {}, connexion Windows : {}, imposée : {}",
                    if cfg.enabled { "oui" } else { "non" },
                    if cfg.allow_login { "oui" } else { "non" },
                    if cfg.enforce { "oui" } else { "non" }
                ),
            )?;
            let mut out = load_config(c)?;
            out.bind_password = String::new();
            Ok(out)
        })
        .await?;
    Ok(Json(cfg))
}

/// Teste la connexion avec les valeurs saisies (avant enregistrement).
pub async fn test(State(state): State<AppState>, _a: AdminUser, Json(req): Json<LdapConfig>) -> ApiResult<Json<LdapTestResult>> {
    let key = state.server_key.clone();
    let cfg = state
        .db
        .call(move |c| {
            let old = load_config(c)?;
            let mut cfg = sanitize(req, &old, &key)?;
            cfg.enabled = true;
            check_transport(&cfg)?;
            Ok(cfg)
        })
        .await?;
    let mut ldap = service_bind(&cfg, &state.server_key).await?;
    let users = search_users(&mut ldap, &cfg, &users_filter(&cfg)).await?;
    let _ = ldap.unbind().await;
    Ok(Json(LdapTestResult {
        users: users.len(),
        sample: users
            .iter()
            .take(5)
            .map(|u| format!("{} ({}){}", u.name, u.email.clone().unwrap_or_else(|| "sans e-mail".into()), if u.disabled { " — désactivé" } else { "" }))
            .collect(),
    }))
}

pub async fn sync_now(State(state): State<AppState>, AdminUser(admin): AdminUser) -> ApiResult<Json<LdapSyncReport>> {
    let report = run_sync(&state).await?;
    state.db.call(move |c| audit_user(c, &admin, "admin.ldap_sync_requested", "", "")).await?;
    Ok(Json(report))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_values_are_escaped() {
        assert_eq!(escape("j*)(uid=*"), "j\\2a\\29\\28uid=\\2a");
        assert_eq!(escape("a\\b"), "a\\5cb");
    }

    #[test]
    fn login_forms() {
        assert_eq!(normalize_login("CORP\\jdupont"), "jdupont");
        assert_eq!(normalize_login(" jdupont@corp.local "), "jdupont@corp.local");
    }

    #[test]
    fn plain_ldap_is_refused() {
        let mut cfg = LdapConfig { url: "ldap://dc:389".into(), ..Default::default() };
        assert!(check_transport(&cfg).is_err());
        cfg.starttls = true;
        assert!(check_transport(&cfg).is_err(), "autorité obligatoire");
        cfg.ca_pem = "x".into();
        assert!(check_transport(&cfg).is_ok());
    }

    #[test]
    fn group_filter_uses_nested_membership() {
        let cfg = LdapConfig { group_dn: "CN=GG_Locksy,OU=Groupes,DC=corp,DC=local".into(), ..Default::default() };
        assert_eq!(
            users_filter(&cfg),
            "(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=CN=GG_Locksy,OU=Groupes,DC=corp,DC=local))"
        );
    }
}
