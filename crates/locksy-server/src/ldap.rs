//! Connecteur Active Directory sur site (LDAP), sans aucun service cloud.
//!
//! - **Synchronisation** : Locksy lit l'annuaire avec un compte de service en
//!   lecture seule. Les membres d'un groupe (groupes imbriqués compris)
//!   obtiennent un compte en attente ; un compte désactivé dans l'AD perd
//!   l'accès immédiatement sur tous ses appareils ; un compte sorti du groupe
//!   suit la politique de désinscription (`directory.deprovision`). Une
//!   synchronisation peut tourner « à blanc » (aucune écriture) et elle est
//!   refusée si elle désactiverait trop de comptes d'un coup
//!   (`directory.max_deprovision_percent`).
//! - **Connexion avec le compte Windows** : identifiant et mot de passe AD
//!   vérifiés par une liaison LDAP auprès d'un contrôleur de domaine. Le mot de
//!   passe Windows n'est jamais conservé. Le mot de passe maître reste
//!   nécessaire pour déchiffrer le coffre.
//!
//! Le transport est toujours chiffré (LDAPS ou STARTTLS) et le certificat du
//! contrôleur est vérifié avec l'autorité fournie (AD CS en général).

use crate::db;
use crate::error::{ApiError, ApiResult};
use crate::identity_admin::{self, Deprovision};
use crate::security::{self, normalize_email};
use crate::sso::{IdpFail, TestError, IDENTITY_TEST_MAX, IDENTITY_TEST_WINDOW};
use crate::state::{audit, audit_user, AdminUser, AppState, AuthUser, ClientMeta};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use crate::error::Json;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use locksy_core::api::*;
use locksy_core::crypto::{self, new_uuid};
use locksy_core::now_unix;
use locksy_core::settings::Effective;
use rusqlite::{params, Connection, OptionalExtension};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fmt::Display;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroize;

const SETTINGS_KEY: &str = "ldap";
const SECRET_AAD: &str = "verrou:v1:ldap-bind-password";
/// Bit ACCOUNTDISABLE de userAccountControl.
const UAC_DISABLED: i64 = 0x2;
/// Délai maximal de chaque opération LDAP (liaison, recherche, lecture d'une
/// page, fin de recherche, déliaison) : un contrôleur qui ne répond plus ne
/// doit pas bloquer indéfiniment une requête ou la synchronisation.
const LDAP_OP_TIMEOUT: Duration = Duration::from_secs(10);
/// Budget global de la lecture de l'annuaire lors d'une synchronisation.
const SYNC_BUDGET: Duration = Duration::from_secs(300);
/// Durée minimale d'une réponse en échec sur `/ldap/login` : un compte
/// inconnu (aucune liaison utilisateur tentée) répond aussi lentement qu'un
/// mot de passe incorrect, ce qui empêche d'énumérer les comptes au chronomètre.
const LDAP_LOGIN_FLOOR: Duration = Duration::from_millis(1500);
/// Synchronisations manuelles par administrateur et par fenêtre de 10 minutes (#56).
const SYNC_MAX: u32 = 6;
const SYNC_WINDOW: i64 = 600;
/// Lignes d'historique de synchronisation conservées.
const HISTORY_KEEP: i64 = 500;

/// Confiance accordée à une identité prouvée par l'annuaire Active Directory :
/// l'adresse vient de l'annuaire de l'entreprise, qui fait autorité ; elle est
/// donc considérée comme vérifiée et peut rattacher un compte existant.
pub(crate) const DIRECTORY_TRUST: crate::sso::IdentityTrust =
    crate::sso::IdentityTrust { email_verified: true, link_by_email: true };

/// Exécute une opération LDAP avec un délai maximal. Échec : code stable
/// `code`, détail de l'annuaire dans la partie technique.
async fn timed<T, E: Display>(code: &'static str, what: &str, fut: impl Future<Output = Result<T, E>>) -> Result<T, IdpFail> {
    timed_for(LDAP_OP_TIMEOUT, code, what, fut).await
}

async fn timed_for<T, E: Display>(
    limit: Duration,
    code: &'static str,
    what: &str,
    fut: impl Future<Output = Result<T, E>>,
) -> Result<T, IdpFail> {
    match tokio::time::timeout(limit, fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(IdpFail::new(code, format!("{what} : {e}"))),
        Err(_) => Err(IdpFail::new(
            "ldap_timeout",
            format!("{what} : pas de réponse de l'annuaire en {} s", limit.as_secs_f32()),
        )),
    }
}

/// Erreur renvoyée par la route publique quand l'annuaire est en cause
/// (injoignable, délai dépassé, compte de service refusé…). Le détail
/// n'est écrit que dans les journaux du serveur (par l'appelant).
fn public_ldap_error() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "ldap_unavailable",
        "Connexion avec le compte Windows momentanément indisponible. Réessayez ou utilisez votre mot de passe maître.",
    )
}

fn invalid_credentials() -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        "invalid_credentials",
        "Identifiant ou mot de passe Windows incorrect, ou compte non autorisé pour Locksy.",
    )
}

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

/// L'annuaire est-il renseigné (adresse, compte de service et racine) ?
pub(crate) fn is_configured(cfg: &LdapConfig) -> bool {
    !cfg.url.trim().is_empty() && !cfg.bind_dn.trim().is_empty() && cfg.has_password && !cfg.base_dn.trim().is_empty()
}

pub fn public_info(c: &Connection) -> ApiResult<Option<SsoPublic>> {
    let cfg = load_config(c)?;
    Ok(cfg.allow_login.then_some(SsoPublic { label: cfg.label, enforced: cfg.enforce }))
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

/// Filtre d'une personne par son identifiant (`login` déjà normalisé),
/// limité au groupe Locksy si `in_group`.
fn login_filter(cfg: &LdapConfig, login: &str, in_group: bool) -> String {
    let v = escape(login);
    format!(
        "(&(objectCategory=person)(objectClass=user)(|({}={v})(sAMAccountName={v})(userPrincipalName={v})(mail={v})){})",
        cfg.login_attribute,
        if in_group { group_clause(cfg) } else { String::new() }
    )
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

/// Configuration inutilisable : code `invalid_config`, message en détail.
fn config_fail(e: ApiError) -> IdpFail {
    IdpFail::new("invalid_config", e.message)
}

async fn connect(cfg: &LdapConfig) -> Result<ldap3::Ldap, IdpFail> {
    check_transport(cfg).map_err(config_fail)?;
    let mut settings = LdapConnSettings::new().set_conn_timeout(Duration::from_secs(10)).set_starttls(cfg.starttls);
    if let Some(tls) = tls_config(&cfg.ca_pem).map_err(config_fail)? {
        settings = settings.set_config(tls);
    }
    // Le délai de connexion de ldap3 ne couvre pas toute la négociation TLS :
    // on borne l'ensemble.
    let (conn, ldap) = timed_for(
        LDAP_OP_TIMEOUT + Duration::from_secs(5),
        "ldap_unreachable",
        "Contrôleur de domaine injoignable ou certificat refusé",
        LdapConnAsync::with_settings(settings, cfg.url.trim()),
    )
    .await?;
    ldap3::drive!(conn);
    Ok(ldap)
}

/// Liaison avec le compte de service.
async fn service_bind(cfg: &LdapConfig, server_key: &crypto::SecretKey) -> Result<ldap3::Ldap, IdpFail> {
    if cfg.bind_password.is_empty() {
        return Err(IdpFail::new("invalid_config", "mot de passe du compte de service manquant"));
    }
    let mut password = crypto::decrypt_string(server_key, &cfg.bind_password, SECRET_AAD)
        .map_err(|_| IdpFail::new("invalid_config", "mot de passe du compte de service illisible"))?;
    let mut ldap = match connect(cfg).await {
        Ok(l) => l,
        Err(e) => {
            password.zeroize();
            return Err(e);
        }
    };
    let res = tokio::time::timeout(LDAP_OP_TIMEOUT, ldap.simple_bind(cfg.bind_dn.trim(), &password)).await;
    password.zeroize();
    match res {
        Err(_) => Err(IdpFail::new("ldap_timeout", "liaison du compte de service : pas de réponse en 10 s")),
        Ok(r) => r
            .and_then(|r| r.success())
            .map(|_| ldap)
            .map_err(|e| IdpFail::new("ldap_bind_refused", format!("liaison du compte de service : {e}"))),
    }
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

async fn search_users(ldap: &mut ldap3::Ldap, cfg: &LdapConfig, filter: &str) -> Result<Vec<AdUser>, IdpFail> {
    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![Box::new(EntriesOnly::new()), Box::new(PagedResults::new(500))];
    let mut stream = timed(
        "ldap_search_failed",
        "Recherche dans l'annuaire refusée",
        ldap.streaming_search_with(adapters, cfg.base_dn.trim(), Scope::Subtree, filter, attributes(cfg)),
    )
    .await?;
    let mut out = Vec::new();
    while let Some(entry) = timed("ldap_search_failed", "Lecture de l'annuaire interrompue", stream.next()).await? {
        if let Some(u) = to_ad_user(SearchEntry::construct(entry), cfg) {
            out.push(u);
        }
    }
    timed("ldap_search_failed", "Recherche dans l'annuaire en erreur", async { stream.finish().await.success() }).await?;
    Ok(out)
}

/// Lit tous les comptes du groupe Locksy (liaison du compte de service).
async fn read_directory(cfg: &LdapConfig, server_key: &crypto::SecretKey) -> Result<Vec<AdUser>, IdpFail> {
    let mut ldap = service_bind(cfg, server_key).await?;
    let users = search_users(&mut ldap, cfg, &users_filter(cfg)).await?;
    let _ = timed("ldap_unreachable", "Déliaison", ldap.unbind()).await;
    Ok(users)
}

// ------------------------------------------------------------ Synchronisation

fn sync_meta() -> ClientMeta {
    ClientMeta { ip: "annuaire".into(), user_agent: "Synchronisation Active Directory".into() }
}

/// Personne de l'annuaire laissée de côté par une synchronisation, et pourquoi
/// (`no_email`, `invalid_email`, `domain_not_allowed`, `not_in_group`,
/// `disabled_in_directory`, `duplicate_email`, `last_owner`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Ignored {
    pub login: String,
    pub email: Option<String>,
    pub reason: String,
}

impl Ignored {
    fn new(login: &str, email: Option<&str>, reason: &str) -> Self {
        Self { login: login.to_string(), email: email.map(str::to_string), reason: reason.to_string() }
    }
}

/// Résultat d'une synchronisation : compteurs historiques et ignorés détaillés.
#[derive(Debug, Default)]
pub struct SyncOutcome {
    pub report: LdapSyncReport,
    pub ignored: Vec<Ignored>,
}

/// Refus de désactiver le dernier propriétaire : la personne est ignorée,
/// la synchronisation continue.
fn is_last_owner(e: &ApiError) -> bool {
    e.code == "last_owner"
}

fn role_of(c: &Connection, user_id: &str) -> ApiResult<Option<String>> {
    Ok(c.query_row("SELECT role FROM users WHERE id = ?1", [user_id], |r| r.get(0)).optional()?)
}

/// Applique l'état de l'annuaire à la base, dans la transaction de l'appelant
/// (qui l'annule en cas d'erreur, ou toujours pour une synchronisation à
/// blanc). Refus :
/// - l'annuaire ne renvoie aucun compte alors que des comptes en viennent
///   (erreur de configuration ou panne) : 409 `ldap_empty_result` ;
/// - plus de `directory.max_deprovision_percent` % des comptes actifs issus
///   de l'annuaire seraient désactivés : 409 `too_many_deprovisions`.
pub fn apply_sync(c: &Connection, users: &[AdUser], eff: &Effective, now: i64) -> ApiResult<SyncOutcome> {
    let meta = sync_meta();
    let policy = Deprovision::from_eff(eff);
    let mut out = SyncOutcome { report: LdapSyncReport { found: users.len(), ..Default::default() }, ignored: Vec::new() };
    let active_before: i64 =
        c.query_row("SELECT COUNT(*) FROM directory_users WHERE source = 'ldap' AND active = 1", [], |r| r.get(0))?;
    if users.is_empty() && active_before > 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "ldap_empty_result",
            "L'annuaire n'a renvoyé aucun compte : synchronisation interrompue par sécurité (aucune désactivation).",
        ));
    }
    let mut seen: Vec<String> = Vec::new();
    for u in users {
        let ignore = |reason: &str, email: Option<&str>| Ignored::new(&u.login, email, reason);
        let Some(raw) = u.email.as_deref() else {
            out.ignored.push(ignore("no_email", None));
            continue;
        };
        let Ok(email) = normalize_email(raw) else {
            out.ignored.push(ignore("invalid_email", Some(raw)));
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
        let Some((id, old_email, old_name, old_active, user_id)) = existing else {
            // Nouvelle personne : pas de compte pour un compte AD désactivé
            // ni hors des domaines autorisés.
            if !active {
                out.ignored.push(ignore("disabled_in_directory", Some(&email)));
                continue;
            }
            if !security::email_domain_allowed(eff, &email) {
                out.ignored.push(ignore("domain_not_allowed", Some(&email)));
                continue;
            }
            let clash: bool =
                c.query_row("SELECT COUNT(*) FROM directory_users WHERE email = ?1", [&email], |r| r.get::<_, i64>(0))? > 0;
            if clash {
                out.ignored.push(ignore("duplicate_email", Some(&email)));
                continue;
            }
            let user_id: Option<String> = c.query_row("SELECT id FROM users WHERE email = ?1", [&email], |r| r.get(0)).optional()?;
            c.execute(
                "INSERT INTO directory_users (id, external_id, email, display_name, active, user_id, created_at, updated_at, source)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?6, 'ldap')",
                params![new_uuid(), ext, email, u.name, user_id, now],
            )?;
            if let Some(uid) = &user_id {
                identity_admin::reactivate(c, uid)?;
            }
            let details = if user_id.is_some() { "rattaché à un compte existant" } else { "en attente de première connexion" };
            audit(c, user_id.as_deref(), &email, "ldap.user_created", &email, &meta, details)?;
            out.report.created += 1;
            continue;
        };
        let mut changed = false;
        if !old_email.eq_ignore_ascii_case(&email) || old_name != u.name {
            let taken: bool = c.query_row(
                "SELECT COUNT(*) FROM directory_users WHERE email = ?1 AND id <> ?2",
                params![email, id],
                |r| r.get::<_, i64>(0),
            )? > 0;
            if taken {
                out.ignored.push(ignore("duplicate_email", Some(&email)));
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
        if old_active == active {
            if changed {
                out.report.updated += 1;
            }
            continue;
        }
        if active {
            c.execute("UPDATE directory_users SET active = 1, updated_at = ?1 WHERE id = ?2", params![now, id])?;
            if let Some(uid) = &user_id {
                identity_admin::reactivate(c, uid)?;
            }
            audit(c, user_id.as_deref(), &email, "ldap.user_enabled", &email, &meta, "compte réactivé dans l'annuaire")?;
            out.report.enabled += 1;
            continue;
        }
        // Compte désactivé dans l'AD : accès coupé (pas de suppression, la
        // désactivation peut n'être que temporaire).
        if let Some(uid) = &user_id {
            if let Some(role) = role_of(c, uid)? {
                match identity_admin::directory_disable(c, uid, &role, "directory") {
                    Err(e) if is_last_owner(&e) => {
                        out.ignored.push(ignore("last_owner", Some(&email)));
                        continue;
                    }
                    r => r?,
                }
            }
        }
        c.execute("UPDATE directory_users SET active = 0, updated_at = ?1 WHERE id = ?2", params![now, id])?;
        audit(c, user_id.as_deref(), &email, "ldap.user_disabled", &email, &meta, "compte désactivé dans l'annuaire")?;
        out.report.disabled += 1;
    }
    // Comptes qui ne sont plus dans le groupe (ou supprimés de l'AD) : départ.
    let gone: Vec<(String, String, Option<String>)> = c
        .prepare("SELECT id, email, user_id, external_id FROM directory_users WHERE source = 'ldap' AND active = 1")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get::<_, Option<String>>(3)?)))?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|(_, _, _, ext)| ext.as_ref().is_none_or(|e| !seen.contains(e)))
        .map(|(id, email, uid, _)| (id, email, uid))
        .collect();
    for (id, email, user_id) in gone {
        let mut details = "retiré du groupe Locksy ou supprimé de l'annuaire".to_string();
        if let Some(uid) = &user_id {
            if let Some(role) = role_of(c, uid)? {
                match identity_admin::depart(c, uid, &role, "directory", policy, &meta, now) {
                    Err(e) if is_last_owner(&e) => {
                        out.ignored.push(Ignored::new(&email, Some(&email), "last_owner"));
                        continue;
                    }
                    Err(e) => return Err(e),
                    Ok(identity_admin::Departure::Scheduled(_)) => details.push_str(", suppression programmée"),
                    Ok(identity_admin::Departure::Purged) => details.push_str(", compte supprimé"),
                    Ok(identity_admin::Departure::Disabled) => {}
                }
            }
        }
        c.execute("UPDATE directory_users SET active = 0, updated_at = ?1 WHERE id = ?2", params![now, id])?;
        audit(c, user_id.as_deref(), &email, "ldap.user_disabled", &email, &meta, &details)?;
        out.report.disabled += 1;
    }
    let max_percent = eff.int("directory.max_deprovision_percent");
    let disabled = i64::try_from(out.report.disabled).unwrap_or(i64::MAX);
    if active_before > 0 && disabled.saturating_mul(100) > max_percent.saturating_mul(active_before) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "too_many_deprovisions",
            format!(
                "La synchronisation désactiverait {disabled} compte(s) sur {active_before}, au-delà du seuil de {max_percent} % : rien n'a été modifié. Vérifiez le groupe et la racine de recherche, ou relevez le seuil."
            ),
        ));
    }
    out.report.skipped = out.ignored.iter().map(|i| format!("{} : {}", i.login, i.reason)).collect();
    Ok(out)
}

/// Une ligne de l'historique des synchronisations.
#[derive(Serialize, Debug)]
pub struct SyncHistory {
    pub id: i64,
    pub at: i64,
    pub dry_run: bool,
    pub ok: bool,
    pub found: i64,
    pub created: i64,
    pub updated: i64,
    pub disabled: i64,
    pub ignored: Vec<Ignored>,
    pub ignored_count: usize,
    pub error_code: Option<String>,
    pub triggered_by: Option<String>,
}

/// Synchronisations récentes, la plus récente d'abord.
pub(crate) fn history(c: &Connection, limit: i64) -> ApiResult<Vec<SyncHistory>> {
    let mut st = c.prepare(
        "SELECT id, at, dry_run, found, created, updated, disabled, ignored_json, error_code, triggered_by
         FROM ldap_sync_history ORDER BY at DESC, id DESC LIMIT ?1",
    )?;
    let rows = st
        .query_map([limit], |r| {
            let ignored: Vec<Ignored> = serde_json::from_str(&r.get::<_, String>(7)?).unwrap_or_default();
            let error_code: Option<String> = r.get(8)?;
            Ok(SyncHistory {
                id: r.get(0)?,
                at: r.get(1)?,
                dry_run: r.get(2)?,
                ok: error_code.is_none(),
                found: r.get(3)?,
                created: r.get(4)?,
                updated: r.get(5)?,
                disabled: r.get(6)?,
                ignored_count: ignored.len(),
                ignored,
                error_code,
                triggered_by: r.get(9)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn record_history(c: &Connection, dry_run: bool, r: Result<&SyncOutcome, &str>, by: Option<&str>) -> ApiResult<()> {
    let (report, ignored, code) = match r {
        Ok(o) => (o.report.clone(), serde_json::to_string(&o.ignored).unwrap_or_else(|_| "[]".into()), None),
        Err(code) => (LdapSyncReport::default(), "[]".to_string(), Some(code)),
    };
    let n = |v: usize| i64::try_from(v).unwrap_or(i64::MAX);
    c.execute(
        "INSERT INTO ldap_sync_history (at, dry_run, found, created, updated, disabled, ignored_json, error_code, triggered_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![now_unix(), dry_run, n(report.found), n(report.created), n(report.updated), n(report.disabled), ignored, code, by],
    )?;
    c.execute(
        "DELETE FROM ldap_sync_history WHERE id <= (SELECT MAX(id) FROM ldap_sync_history) - ?1",
        [HISTORY_KEEP],
    )?;
    Ok(())
}

fn summary(r: &Result<SyncOutcome, TestError>) -> String {
    match r {
        Ok(o) => format!(
            "{} compte(s) lu(s) : {} créé(s), {} mis à jour, {} désactivé(s), {} réactivé(s){}",
            o.report.found,
            o.report.created,
            o.report.updated,
            o.report.disabled,
            o.report.enabled,
            if o.ignored.is_empty() { String::new() } else { format!(", {} ignoré(s)", o.ignored.len()) }
        ),
        Err(e) => format!("Échec ({}) : {}", e.err.code, e.err.message),
    }
}

/// Synchronise l'annuaire. À blanc (`dry_run`), le résultat est calculé dans
/// une transaction annulée : seuls l'historique et l'événement
/// `ldap.sync_dry_run` sont écrits. `by` : administrateur à l'origine
/// (`None` pour la synchronisation périodique).
pub async fn run_sync(state: &AppState, dry_run: bool, by: Option<AuthUser>) -> Result<SyncOutcome, TestError> {
    let cfg = state.db.call(|c| load_config(c)).await?;
    let read = async {
        if cfg.base_dn.trim().is_empty() {
            return Err(IdpFail::new("invalid_config", "racine de recherche (base DN) manquante"));
        }
        // Chaque opération a son délai ; le budget global borne en plus une
        // lecture très longue (annuaire lent page après page).
        match tokio::time::timeout(SYNC_BUDGET, read_directory(&cfg, &state.server_key)).await {
            Ok(r) => r,
            Err(_) => Err(IdpFail::new(
                "ldap_timeout",
                format!("lecture de l'annuaire interrompue après {} minutes", SYNC_BUDGET.as_secs() / 60),
            )),
        }
    }
    .await;
    if let Err(f) = &read {
        tracing::warn!(code = f.code, detail = %f.technical, "lecture de l'annuaire en échec");
    }
    finish_sync(state, read, dry_run, by).await
}

/// Applique (ou simule, à blanc) le résultat d'une lecture de l'annuaire,
/// puis l'enregistre : historique, journal et, pour une vraie
/// synchronisation, date et résumé dans la configuration.
pub(crate) async fn finish_sync(
    state: &AppState,
    read: Result<Vec<AdUser>, IdpFail>,
    dry_run: bool,
    by: Option<AuthUser>,
) -> Result<SyncOutcome, TestError> {
    let eff = state.effective().await?;
    state
        .db
        .call(move |c| {
            let result: Result<SyncOutcome, TestError> = match read {
                Err(f) => Err(f.into()),
                Ok(users) => {
                    let tx = c.unchecked_transaction()?;
                    match apply_sync(&tx, &users, &eff, now_unix()) {
                        Ok(o) if !dry_run => {
                            tx.commit()?;
                            Ok(o)
                        }
                        // À blanc ou refusée : la transaction est annulée (drop).
                        r => r.map_err(TestError::from),
                    }
                }
            };
            let (uid, email, meta) = match &by {
                Some(a) => (Some(a.id.as_str()), a.email.as_str(), a.meta.clone()),
                None => (None, "", sync_meta()),
            };
            let code = result.as_ref().err().map(|e| e.err.code);
            record_history(c, dry_run, result.as_ref().map_err(|e| e.err.code), uid)?;
            let text = summary(&result);
            if dry_run {
                audit(c, uid, email, "ldap.sync_dry_run", "", &meta, &text)?;
                return Ok(result);
            }
            let action = match code {
                None => "ldap.sync",
                Some("too_many_deprovisions") => "ldap.sync_refused",
                Some(_) => "ldap.sync_failed",
            };
            let mut cfg = load_config(c)?;
            cfg.last_sync = now_unix();
            cfg.last_result = text.clone();
            db::save_json(c, SETTINGS_KEY, &cfg)?;
            audit(c, uid, email, action, "", &meta, &text)?;
            Ok(result)
        })
        .await?
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
        if let Err(e) = run_sync(&state, false, None).await {
            tracing::warn!(code = e.err.code, message = %e.err.message, "synchronisation Active Directory en échec");
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

/// Attend que la réponse en échec ait duré au moins `LDAP_LOGIN_FLOOR`.
async fn failure_floor(started: tokio::time::Instant) {
    tokio::time::sleep_until(started + LDAP_LOGIN_FLOOR).await;
}

/// Vérifie le mot de passe d'une personne par une liaison à son nom. Un refus
/// de l'annuaire (rc 49…) est un échec d'identifiants (`false`) ; une erreur
/// de transport ou un délai dépassé, une indisponibilité.
async fn user_bind(cfg: &LdapConfig, dn: &str, password: &str) -> Result<bool, IdpFail> {
    let mut conn = connect(cfg).await?;
    let bound = timed("ldap_unreachable", "Liaison de l'utilisateur", conn.simple_bind(dn, password)).await?;
    let ok = bound.success().is_ok();
    let _ = timed("ldap_unreachable", "Déliaison", conn.unbind()).await;
    Ok(ok)
}

/// Connexion avec le compte Windows (route publique). Les erreurs sont
/// volontairement génériques : `invalid_credentials` pour tout échec
/// d'identifiants (inconnu, ambigu, désactivé, mauvais mot de passe) et
/// `ldap_unavailable` pour tout problème d'annuaire, le détail n'allant que
/// dans les journaux du serveur. Tous les échecs durent au moins
/// `LDAP_LOGIN_FLOOR`. Plafond par adresse IP de l'hébergeur et
/// verrouillage après échecs selon `lockout.*`.
pub async fn login(State(state): State<AppState>, meta: ClientMeta, Json(mut req): Json<LdapLoginRequest>) -> ApiResult<Json<LdapLoginResponse>> {
    let started = tokio::time::Instant::now();
    let prepared = async {
        let cfg = state.db.call(|c| load_config(c)).await?;
        if !cfg.allow_login {
            return Err(ApiError::not_found("La connexion avec le compte Windows n'est pas activée."));
        }
        let eff = state.effective().await?;
        // Plafond par adresse, non remis à zéro par une réussite.
        state.limiter.hit(&format!("ldap-ip:{}", meta.rate_key()), state.host.rate.login_ip, 600)?;
        Ok((cfg, eff))
    }
    .await;
    let (cfg, eff) = match prepared {
        Ok(v) => v,
        Err(e) => {
            req.password.zeroize();
            return Err(e);
        }
    };
    let rate = meta.rate_key();
    let login = normalize_login(&req.username).to_lowercase();
    // Mot de passe vide : une liaison « non authentifiée » réussirait. Refus,
    // sans liaison, mais aussi lent qu'un échec ordinaire.
    if login.is_empty() || login.len() > 256 || req.password.is_empty() {
        req.password.zeroize();
        failure_floor(started).await;
        return Err(invalid_credentials());
    }
    // Tentative comptée AVANT toute liaison : des requêtes parallèles ne
    // peuvent pas dépasser le seuil.
    let lock = security::lockout(&eff);
    let pair_key = format!("ldap-pair:{login}|{rate}");
    let user_key = format!("ldap-login:{login}");
    if let Err(e) = state.limiter.attempt_with(&pair_key, lock.pair, &lock) {
        req.password.zeroize();
        return Err(e);
    }
    if let Err(e) = state.limiter.attempt_with(&user_key, lock.account, &lock) {
        state.limiter.release(&pair_key);
        req.password.zeroize();
        return Err(e);
    }
    let outcome = async {
        let mut ldap = service_bind(&cfg, &state.server_key).await?;
        let found = search_users(&mut ldap, &cfg, &login_filter(&cfg, &login, true)).await?;
        let _ = timed("ldap_unreachable", "Déliaison", ldap.unbind()).await;
        let [user] = found.as_slice() else {
            return Ok(None); // inconnu, hors du groupe, ou ambigu
        };
        if user.disabled {
            return Ok(None);
        }
        Ok::<_, IdpFail>(user_bind(&cfg, &user.dn, &req.password).await?.then(|| user.clone()))
    }
    .await;
    req.password.zeroize();
    let user = match outcome {
        Ok(Some(u)) => u,
        Ok(None) => {
            let (l, m) = (login.clone(), meta.clone());
            let audited = state.db.call(move |c| audit(c, None, &l, "ldap.login_failed", &l, &m, "")).await;
            failure_floor(started).await;
            audited?;
            return Err(invalid_credentials());
        }
        Err(f) => {
            // Panne d'annuaire : ce n'est pas un échec d'identifiants.
            tracing::warn!(code = f.code, detail = %f.technical, "connexion LDAP impossible");
            state.limiter.release(&pair_key);
            state.limiter.release(&user_key);
            failure_floor(started).await;
            return Err(public_ldap_error());
        }
    };
    state.limiter.success(&pair_key);
    state.limiter.success(&user_key);
    let email = user
        .email
        .as_deref()
        .and_then(|e| normalize_email(e).ok())
        .ok_or_else(|| ApiError::forbidden("Votre compte n'a pas d'adresse e-mail dans l'annuaire : contactez votre administrateur."))?;
    security::require_email_domain(&eff, &email)?;
    let subject = format!("ldap|{}", user.guid);
    let ticket = state.db.call(move |c| crate::sso::issue_ticket(c, &email, &user.name, &subject, &meta, DIRECTORY_TRUST)).await?;
    let t = ticket.clone();
    let info = state.db.call(move |c| crate::sso::redeem_info(c, &t)).await?;
    Ok(Json(LdapLoginResponse { ticket, info }))
}

// ------------------------------------------------------------ Administration

pub async fn get_config(State(state): State<AppState>, _a: AdminUser) -> ApiResult<Json<LdapConfig>> {
    let mut cfg = state.db.call(|c| load_config(c)).await?;
    cfg.bind_password = String::new();
    cfg.enforce = state.effective().await?.bool("ldap.enforce");
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
    req.has_password = !req.bind_password.is_empty();
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

/// Enregistre la configuration. Imposer la connexion Windows exige un test
/// réussi de cet administrateur depuis moins de 24 h (G-14, 409 `test_required`).
pub async fn put_config(State(state): State<AppState>, AdminUser(admin): AdminUser, Json(req): Json<LdapConfig>) -> ApiResult<Json<LdapConfig>> {
    let key = state.server_key.clone();
    let was_enforced = state.effective().await?.bool("ldap.enforce");
    let cfg = state
        .db
        .call(move |c| {
            let old = load_config(c)?;
            let cfg = sanitize(req, &old, &key)?;
            if cfg.enforce && !was_enforced && !identity_admin::recent_test_ok(c, "ldap", &admin.id, now_unix())? {
                return Err(crate::sso::test_required_error());
            }
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

/// Teste la connexion avec les valeurs saisies (avant enregistrement) :
/// liaison du compte de service et lecture du groupe. En échec : code
/// stable, détail de l'annuaire dans `technical`.
pub async fn test(State(state): State<AppState>, AdminUser(admin): AdminUser, Json(req): Json<LdapConfig>) -> Result<Json<LdapTestResult>, TestError> {
    state.limiter.hit(&format!("idtest-ldap:{}", admin.id), IDENTITY_TEST_MAX, IDENTITY_TEST_WINDOW)?;
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
    let users = read_directory(&cfg, &state.server_key).await.map_err(|f| {
        tracing::warn!(code = f.code, detail = %f.technical, "test de l'annuaire en échec");
        TestError::from(f)
    })?;
    Ok(Json(LdapTestResult {
        users: users.len(),
        sample: users
            .iter()
            .take(5)
            .map(|u| format!("{} ({}){}", u.name, u.email.clone().unwrap_or_else(|| "sans e-mail".into()), if u.disabled { " — désactivé" } else { "" }))
            .collect(),
    }))
}

#[derive(Deserialize)]
pub struct TestLoginRequest {
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
}

/// Contrôle d'une connexion Windows de test : `Ok(email)` si la personne
/// existe, est active, appartient au groupe et a donné le bon mot de passe ;
/// sinon le code d'échec.
async fn check_windows_login(cfg: &LdapConfig, key: &crypto::SecretKey, login: &str, password: &str) -> Result<String, IdpFail> {
    let mut ldap = service_bind(cfg, key).await?;
    let found = search_users(&mut ldap, cfg, &login_filter(cfg, login, false)).await?;
    let in_group = if found.len() == 1 && !cfg.group_dn.trim().is_empty() {
        !search_users(&mut ldap, cfg, &login_filter(cfg, login, true)).await?.is_empty()
    } else {
        true
    };
    let _ = timed("ldap_unreachable", "Déliaison", ldap.unbind()).await;
    let [user] = found.as_slice() else {
        return Err(IdpFail::new("invalid_credentials", "compte introuvable ou ambigu"));
    };
    // L'annuaire refuse de toute façon la liaison d'un compte désactivé :
    // le dire évite une fausse piste (« mot de passe incorrect »).
    if user.disabled {
        return Err(IdpFail::new("account_disabled", "compte désactivé dans l'annuaire"));
    }
    if !user_bind(cfg, &user.dn, password).await? {
        return Err(IdpFail::new("invalid_credentials", "mot de passe refusé par l'annuaire"));
    }
    if !in_group {
        return Err(IdpFail::new("not_in_group", "hors du groupe Locksy"));
    }
    user.email
        .as_deref()
        .and_then(|e| normalize_email(e).ok())
        .ok_or_else(|| IdpFail::new("email_missing", "aucune adresse e-mail dans l'annuaire"))
}

/// `POST /admin/ldap/test-login` : test réel de la connexion avec le compte
/// Windows de l'administrateur (liaison, groupe, adresse e-mail identique à
/// celle de son compte Locksy). Le résultat est enregistré
/// (`identity_tests`, `ldap.tested`) ; le mot de passe n'est ni conservé ni
/// journalisé.
pub async fn test_login(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Json(mut req): Json<TestLoginRequest>,
) -> Result<Json<Value>, TestError> {
    if let Err(e) = state.limiter.hit(&format!("idtest-ldap:{}", admin.id), IDENTITY_TEST_MAX, IDENTITY_TEST_WINDOW) {
        req.password.zeroize();
        return Err(e.into());
    }
    let login = normalize_login(&req.username).to_lowercase();
    let cfg = state.db.call(|c| load_config(c)).await;
    let outcome = match cfg {
        Err(e) => {
            req.password.zeroize();
            return Err(e.into());
        }
        Ok(_) if login.is_empty() || login.len() > 256 || req.password.is_empty() => {
            Err(IdpFail::new("invalid_credentials", "identifiant ou mot de passe vide"))
        }
        Ok(cfg) if !is_configured(&cfg) => Err(IdpFail::new("invalid_config", "annuaire non configuré")),
        Ok(cfg) => check_windows_login(&cfg, &state.server_key, &login, &req.password).await,
    };
    req.password.zeroize();
    let (email, outcome) = match outcome {
        Ok(email) if !email.eq_ignore_ascii_case(&admin.email) => {
            let f = IdpFail::new("email_mismatch", "l'adresse de l'annuaire n'est pas celle de l'administrateur");
            (Some(email), Err(f))
        }
        Ok(email) => (Some(email), Ok(())),
        Err(f) => (None, Err(f)),
    };
    if let Err(f) = &outcome {
        tracing::warn!(code = f.code, detail = %f.technical, "test de connexion Windows en échec");
    }
    let code = outcome.as_ref().err().map(|f| f.code);
    let actor = admin.clone();
    state.db.call(move |c| identity_admin::record_test(c, "ldap", &actor, code)).await?;
    Ok(Json(json!({
        "ok": code.is_none(),
        "error_code": code,
        "email": email,
        "technical": outcome.err().map(|f| f.technical),
    })))
}

#[derive(Deserialize)]
pub struct SyncQuery {
    #[serde(default)]
    dry_run: bool,
}

/// Réponse d'une synchronisation : rapport historique à plat, plus le mode
/// et les personnes ignorées avec leur raison.
#[derive(Serialize)]
pub struct SyncOut {
    #[serde(flatten)]
    report: LdapSyncReport,
    dry_run: bool,
    ignored: Vec<Ignored>,
}

/// `POST /admin/ldap/sync?dry_run=true|false`.
pub async fn sync_now(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Query(q): Query<SyncQuery>,
) -> Result<Json<SyncOut>, TestError> {
    state.limiter.hit(&format!("idsync:{}", admin.id), SYNC_MAX, SYNC_WINDOW)?;
    // La synchronisation tourne dans sa propre tâche : si la requête dépasse
    // LOCKSY_REQUEST_TIMEOUT_SECS (408) ou si le navigateur se ferme, elle va
    // quand même au bout (budget propre de 5 min) au lieu d'être interrompue
    // entre deux opérations ; son résultat reste visible dans l'historique.
    let st = state.clone();
    let dry_run = q.dry_run;
    let o = tokio::spawn(async move { run_sync(&st, dry_run, Some(admin)).await })
        .await
        .map_err(|_| ApiError::internal("synchronisation interrompue"))??;
    Ok(Json(SyncOut { report: o.report, dry_run, ignored: o.ignored }))
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
    fn public_errors_do_not_leak_details() {
        let e = public_ldap_error();
        assert_eq!(e.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(e.code, "ldap_unavailable");
        assert!(!e.message.contains("dc1") && !e.message.contains("certificat"));
        let e = invalid_credentials();
        assert_eq!((e.status, e.code), (StatusCode::UNAUTHORIZED, "invalid_credentials"));
    }

    #[test]
    fn directory_failures_have_stable_codes() {
        for (code, status) in [
            ("ldap_unreachable", StatusCode::BAD_GATEWAY),
            ("ldap_timeout", StatusCode::GATEWAY_TIMEOUT),
            ("ldap_bind_refused", StatusCode::UNPROCESSABLE_ENTITY),
            ("ldap_search_failed", StatusCode::BAD_GATEWAY),
            ("invalid_config", StatusCode::CONFLICT),
        ] {
            let e = IdpFail::new(code, "dc1.corp.local:636 rc=49 détail").to_api();
            assert_eq!((e.code, e.status), (code, status));
            assert!(!e.message.contains("dc1"), "le détail de l'annuaire reste technique");
        }
    }

    #[tokio::test]
    async fn operations_time_out() {
        let r = timed_for(Duration::from_millis(20), "ldap_search_failed", "Recherche", std::future::pending::<Result<(), std::io::Error>>()).await;
        let e = r.unwrap_err();
        assert_eq!(e.code, "ldap_timeout");
        assert!(e.technical.starts_with("Recherche"));
        // Une erreur de l'opération garde son code et son détail (pour l'administrateur).
        let r = timed("ldap_bind_refused", "Liaison", async { Err::<(), _>(std::io::Error::other("rc=49")) }).await;
        let e = r.unwrap_err();
        assert_eq!(e.code, "ldap_bind_refused");
        assert!(e.technical.contains("rc=49"));
        assert_eq!(timed("ldap_unreachable", "Liaison", async { Ok::<_, std::io::Error>(7) }).await.unwrap(), 7);
    }

    async fn state_with_login() -> AppState {
        let st = crate::state::test_state().await;
        st.db
            .call(|c| {
                let cfg = LdapConfig { allow_login: true, url: "ldaps://dc.invalid:636".into(), ..Default::default() };
                db::save_json(c, SETTINGS_KEY, &cfg)
            })
            .await
            .unwrap();
        st
    }

    fn meta() -> ClientMeta {
        ClientMeta { ip: "203.0.113.7".into(), user_agent: "test".into() }
    }

    #[tokio::test]
    async fn failures_respect_the_time_floor() {
        let st = state_with_login().await;
        let req = LdapLoginRequest { username: "CORP\\jdupont".into(), password: String::new() };
        let t = std::time::Instant::now();
        let e = login(State(st), meta(), Json(req)).await.expect_err("refus");
        assert!(t.elapsed() >= LDAP_LOGIN_FLOOR, "réponse trop rapide : {:?}", t.elapsed());
        assert_eq!(e.code, "invalid_credentials");
    }

    #[tokio::test]
    async fn directory_failure_is_generic_and_not_counted() {
        // Sans compte de service, la liaison échoue avant tout réseau.
        let st = state_with_login().await;
        let t = std::time::Instant::now();
        for _ in 0..6 {
            let req = LdapLoginRequest { username: "jdupont".into(), password: "x".into() };
            let e = login(State(st.clone()), meta(), Json(req)).await.expect_err("refus");
            assert_eq!(e.code, "ldap_unavailable", "pas de blocage : la panne n'est pas un échec d'identifiants");
            assert!(!e.message.contains("service"));
        }
        assert!(t.elapsed() >= LDAP_LOGIN_FLOOR);
    }

    #[tokio::test]
    async fn login_uses_the_host_ip_cap() {
        let mut st = state_with_login().await;
        st.host = Arc::new(crate::config::HostConfig {
            rate: crate::config::RateCaps { login_ip: 2, ..st.host.rate.clone() },
            ..(*st.host).clone()
        });
        for _ in 0..2 {
            let req = LdapLoginRequest { username: String::new(), password: String::new() };
            assert_eq!(login(State(st.clone()), meta(), Json(req)).await.unwrap_err().code, "invalid_credentials");
        }
        let req = LdapLoginRequest { username: String::new(), password: String::new() };
        let e = login(State(st), meta(), Json(req)).await.unwrap_err();
        assert_eq!(e.code, "rate_limited");
        assert!(e.retry_after.is_some());
    }

    #[test]
    fn group_filter_uses_nested_membership() {
        let cfg = LdapConfig { group_dn: "CN=GG_Locksy,OU=Groupes,DC=corp,DC=local".into(), ..Default::default() };
        assert_eq!(
            users_filter(&cfg),
            "(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=CN=GG_Locksy,OU=Groupes,DC=corp,DC=local))"
        );
        assert!(login_filter(&cfg, "j*", true).ends_with("(memberOf:1.2.840.113556.1.4.1941:=CN=GG_Locksy,OU=Groupes,DC=corp,DC=local))"));
        assert!(!login_filter(&cfg, "j*", false).contains("memberOf"));
        assert!(login_filter(&cfg, "j*", false).contains("sAMAccountName=j\\2a"));
    }
}
