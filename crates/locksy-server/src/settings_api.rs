//! Réglages de l'organisation : stockage, cache, API d'administration,
//! politique des clients et page publique.
//!
//! - Le registre (`locksy_core::settings`) décrit chaque clé ; la table
//!   `org_settings` ne contient que les valeurs différentes du défaut, avec
//!   une révision globale (`settings_meta`) et un historique par clé
//!   (`settings_history`).
//! - Le cache `SettingsCache` garde les réglages effectifs, la politique et
//!   la page publique précalculées ; il ne relit la base que si la
//!   génération des réglages (`Db::settings_generation`) a changé.
//! - Pont de compatibilité (à retirer quand les lots L5, L6 et L7 auront
//!   basculé sur le registre) : les anciens blocs JSON `settings.org`,
//!   `settings.attachments` et des champs de `sso` et `ldap` sont des
//!   MIROIRS du registre, réécrits à chaque modification ; une écriture par
//!   l'ancien chemin (`db::save_settings`, `db::save_json`) est importée
//!   dans le registre (`import_legacy_blob`).

use crate::db;
use crate::error::{ApiError, ApiResult};
use crate::mail::Notification;
use crate::security::sha256_hex;
use crate::state::{audit, AdminUser, AppState, AuthUser, ClientMeta};
use arc_swap::ArcSwapOption;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use crate::error::Json;
use locksy_core::api::{
    roles, PublicBranding, PublicI18n, PublicKdf, PublicLegal, PublicLogin, PublicMasterPassword, PublicSettings,
    SsoPublic, SyncRevisions,
};
use locksy_core::crypto::{encrypt_str, SecretKey};
use locksy_core::now_unix;
use locksy_core::settings::{
    self as reg, Change, Changes, Ctx, Diff, DiffEntry, Effective, HostCaps, Kind, Profile, ReadError, Rejection,
    SettingDef, Source, StoredValue, REGISTRY,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// Chargements du registre depuis la base (tous les caches du processus).
pub static LOADS: AtomicU64 = AtomicU64::new(0);

/// Format des fichiers d'export de réglages.
const EXPORT_FORMAT: &str = "locksy-settings-v1";

/// Lien de l'impact d'une règle de double authentification.
const LINK_2FA: &str = "#/admin/personnes?2fa=non&etat=actif";
const LINK_ACTIVE: &str = "#/admin/personnes?etat=actif";

/// Correspondance des anciens blocs JSON avec le registre : (bloc, champ, clé).
const LEGACY_MAP: &[(&str, &str, &str)] = &[
    ("org", "require_2fa", "twofa.required"),
    ("org", "session_idle_minutes", "session.idle_minutes"),
    ("org", "session_max_hours", "session.max_hours"),
    ("org", "audit_retention_days", "retention.audit_days"),
    ("org", "trash_retention_days", "retention.trash_days"),
    ("attachments", "per_user_mb", "attachment.quota_user_mib"),
    ("attachments", "total_mb", "attachment.quota_total_mib"),
    ("attachments", "max_per_item", "attachment.max_per_item"),
    ("sso", "enforce", "sso.enforce"),
    ("sso", "public_url", "instance.public_url"),
    ("sso", "allowed_extension_ids", "extension.allowed_ids"),
    ("ldap", "enforce", "ldap.enforce"),
];

// ------------------------------------------------------------ Erreur enrichie

/// Erreur avec des champs en plus du code et du message (`fields`, `keys`,
/// `current_revision`…) et des en-têtes. Corps : `{error, message, …extra}`.
#[derive(Debug)]
pub(crate) struct ExtError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub extra: Map<String, Value>,
    pub headers: Vec<(HeaderName, HeaderValue)>,
}

impl ExtError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, code, message: message.into(), extra: Map::new(), headers: Vec::new() }
    }

    pub fn with(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.extra.insert(key.to_string(), value.into());
        self
    }

    pub fn header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.push((name, value));
        self
    }
}

impl IntoResponse for ExtError {
    fn into_response(self) -> Response {
        let mut body = self.extra;
        body.insert("error".into(), Value::String(self.code.into()));
        body.insert("message".into(), Value::String(self.message));
        let mut res = (self.status, Json(Value::Object(body))).into_response();
        for (name, value) in self.headers {
            res.headers_mut().insert(name, value);
        }
        res
    }
}

impl From<ApiError> for ExtError {
    /// Le code reste celui, littéral, de l'`ApiError` d'origine.
    fn from(e: ApiError) -> Self {
        let mut extra = Map::new();
        let mut headers = Vec::new();
        // Délai d'attente (429, 503) : en-tête Retry-After et champ du corps,
        // comme la réponse d'une ApiError.
        if let Some(s) = e.retry_after {
            extra.insert("retry_after".into(), json!(s));
            if let Ok(v) = HeaderValue::from_str(&s.to_string()) {
                headers.push((header::RETRY_AFTER, v));
            }
        }
        ExtError { status: e.status, code: e.code, message: e.message, extra, headers }
    }
}

type ExtResult<T> = Result<T, ExtError>;

// ------------------------------------------------------------ Stockage

/// Révision courante et auteur de la dernière modification.
#[derive(Clone, Debug, Default)]
pub(crate) struct Meta {
    pub revision: i64,
    pub updated_at: i64,
    /// Nom (ou e-mail) de l'auteur, vide pour une migration ou l'ancien chemin.
    pub by: String,
}

pub(crate) fn read_meta(c: &Connection) -> ApiResult<Meta> {
    Ok(c
        .query_row(
            "SELECT m.revision, m.updated_at, COALESCE(u.name, u.email, '')
             FROM settings_meta m LEFT JOIN users u ON u.id = m.updated_by WHERE m.id = 1",
            [],
            |r| Ok(Meta { revision: r.get(0)?, updated_at: r.get(1)?, by: r.get(2)? }),
        )
        .optional()?
        .unwrap_or_default())
}

/// Valeurs enregistrées (clé -> valeur, date). Une ligne illisible donne
/// une valeur nulle, que le registre refuse : la clé retombe sur son défaut.
pub(crate) fn load_stored(c: &Connection) -> ApiResult<BTreeMap<String, (StoredValue, i64)>> {
    let mut st = c.prepare("SELECT key, value, mode, policy_min, policy_max, updated_at FROM org_settings")?;
    let rows = st
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let json = |s: Option<String>| s.and_then(|s| serde_json::from_str::<Value>(&s).ok()).filter(|v| !v.is_null());
    let mut out = BTreeMap::new();
    for (key, value, mode, min, max, at) in rows {
        let mut value = serde_json::from_str::<Value>(&value).unwrap_or(Value::Null);
        let mode = match mode.as_deref() {
            None => None,
            Some(m) => match reg::Mode::parse(m) {
                Some(m) => Some(m),
                None => {
                    value = Value::Null;
                    None
                }
            },
        };
        out.insert(key, (StoredValue { value, mode, min: json(min), max: json(max) }, at));
    }
    Ok(out)
}

/// Réglages effectifs lus en base, avec les contraintes de l'hébergeur.
pub(crate) fn load_effective(c: &Connection, host: &HostCaps) -> ApiResult<(Effective, Vec<ReadError>)> {
    let stored = load_stored(c)?;
    let meta = read_meta(c)?;
    Ok(reg::build_effective(&stored, host, meta.revision))
}

/// Auteur d'une modification.
#[derive(Clone, Debug)]
pub(crate) struct Actor {
    pub user_id: Option<String>,
    pub email: String,
    pub ip: String,
}

/// Forme d'une valeur dans l'historique : « *** » pour un secret.
fn history_json(d: &SettingDef, sv: &StoredValue) -> String {
    if d.is_secret() {
        return json!("***").to_string();
    }
    reg::stored_to_json(d, sv).to_string()
}

/// Contexte AAD d'un secret de réglage, chiffré par la clé serveur.
fn secret_aad(key: &str) -> String {
    format!("verrou:v1:setting:{key}")
}

/// Écrit (ou retire, pour une valeur par défaut) la ligne d'une clé.
fn write_row(
    c: &Connection,
    d: &SettingDef,
    sv: &StoredValue,
    now: i64,
    by: Option<&str>,
    server_key: Option<&SecretKey>,
) -> ApiResult<()> {
    let empty_secret = d.is_secret() && sv.value.as_str().unwrap_or("").is_empty();
    if *sv == d.default_stored() || empty_secret {
        c.execute("DELETE FROM org_settings WHERE key = ?1", [d.key])?;
        return Ok(());
    }
    let value = if d.is_secret() {
        let key = server_key.ok_or_else(|| ApiError::internal("clé serveur absente pour un secret de réglage"))?;
        json!(encrypt_str(key, sv.value.as_str().unwrap_or(""), &secret_aad(d.key))).to_string()
    } else {
        sv.value.to_string()
    };
    let text = |v: &Option<Value>| v.as_ref().map(Value::to_string);
    c.execute(
        "INSERT INTO org_settings (key, value, mode, policy_min, policy_max, updated_at, updated_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, mode = excluded.mode, policy_min = excluded.policy_min,
             policy_max = excluded.policy_max, updated_at = excluded.updated_at, updated_by = excluded.updated_by",
        params![d.key, value, sv.mode.map(|m| m.as_str()), text(&sv.min), text(&sv.max), now, by],
    )?;
    Ok(())
}

/// Une ligne d'historique.
#[allow(clippy::too_many_arguments)]
fn write_history(
    c: &Connection,
    revision: i64,
    now: i64,
    actor: &Actor,
    d: &SettingDef,
    old: &StoredValue,
    new: &StoredValue,
    source: &str,
    reason: Option<&str>,
) -> ApiResult<()> {
    c.execute(
        "INSERT INTO settings_history (revision, at, user_id, email, ip, key, old_value, new_value, source, reason)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            revision,
            now,
            actor.user_id,
            actor.email,
            actor.ip,
            d.key,
            history_json(d, old),
            history_json(d, new),
            source,
            reason
        ],
    )?;
    Ok(())
}

/// Nouvelle révision.
fn bump_revision(c: &Connection, now: i64, by: Option<&str>) -> ApiResult<i64> {
    c.execute(
        "UPDATE settings_meta SET revision = revision + 1, updated_at = ?1, updated_by = ?2 WHERE id = 1",
        params![now, by],
    )?;
    Ok(c.query_row("SELECT revision FROM settings_meta WHERE id = 1", [], |r| r.get(0))?)
}

/// Écrit une modification validée : une révision, une ligne d'historique par
/// clé, les miroirs, et le rechargement du cache. Renvoie la révision.
pub(crate) fn apply(
    c: &Connection,
    entries: &[DiffEntry],
    actor: &Actor,
    source: &str,
    reason: Option<&str>,
    server_key: &SecretKey,
    host: &HostCaps,
) -> ApiResult<i64> {
    let now = now_unix();
    let revision = bump_revision(c, now, actor.user_id.as_deref())?;
    for e in entries {
        let d = reg::def(&e.key).ok_or_else(|| ApiError::internal("clé de réglage inconnue à l'écriture"))?;
        write_row(c, d, &e.new, now, actor.user_id.as_deref(), Some(server_key))?;
        write_history(c, revision, now, actor, d, &e.old, &e.new, source, reason)?;
    }
    write_mirrors(c, &load_effective(c, host)?.0)?;
    db::mark_settings_changed();
    Ok(revision)
}

/// Réécrit les anciens blocs JSON à partir des valeurs effectives (pont de
/// compatibilité). Un bloc absent n'est créé que si l'une de ses valeurs
/// n'est plus celle par défaut.
pub(crate) fn write_mirrors(c: &Connection, eff: &Effective) -> ApiResult<()> {
    for blob in ["org", "attachments", "sso", "ldap"] {
        let fields: Vec<(&str, &str)> =
            LEGACY_MAP.iter().filter(|(b, _, _)| *b == blob).map(|(_, f, k)| (*f, *k)).collect();
        let raw: Option<String> =
            c.query_row("SELECT value FROM settings WHERE key = ?1", [blob], |r| r.get(0)).optional()?;
        if raw.is_none() && fields.iter().all(|(_, k)| eff.source(k) == Source::Default) {
            continue;
        }
        let mut obj = raw
            .as_deref()
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default();
        let before = obj.clone();
        for (field, key) in &fields {
            obj.insert((*field).to_string(), eff.get(key).clone());
        }
        if raw.is_none() || obj != before {
            c.execute(
                "INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![blob, Value::Object(obj).to_string()],
            )?;
        }
    }
    Ok(())
}

/// Champs d'un ancien bloc repris dans le registre. Une adresse publique
/// vide vaut le défaut : à la migration elle n'est donc pas reprise, et par
/// l'ancien écran SSO elle rétablit le défaut (au lieu d'être réécrite par
/// le miroir).
fn legacy_fields(blob: &str, v: &Value) -> Vec<(&'static SettingDef, Value)> {
    LEGACY_MAP
        .iter()
        .filter(|(b, _, _)| *b == blob)
        .filter_map(|(_, field, key)| Some((reg::def(key)?, v.get(field)?.clone())))
        .collect()
}

/// Valeurs d'un ancien bloc à reprendre : contrôlées par le registre (un
/// champ refusé est journalisé et ignoré), différentes de `current`. Une 2FA
/// imposée par l'ancien chemin l'est sans délai de grâce (blocage immédiat,
/// comme avant la refonte).
fn legacy_changes(blob: &str, v: &Value, current: &Effective) -> Vec<(&'static SettingDef, StoredValue)> {
    let host = HostCaps::default();
    let mut out = Vec::new();
    for (d, raw) in legacy_fields(blob, v) {
        match reg::check_stored(d, &StoredValue::plain(raw), &host) {
            Ok(sv) if Some(&sv) != current.stored(d.key) => out.push((d, sv)),
            Ok(_) => {}
            Err(e) => tracing::error!(bloc = blob, cle = d.key, code = e.code, "ancien réglage refusé par le registre : ignoré"),
        }
    }
    let turns_on = out.iter().any(|(d, sv)| d.key == "twofa.required" && sv.value == json!(true));
    if turns_on && current.int("twofa.grace_days") != 0 {
        if let Some(d) = reg::def("twofa.grace_days") {
            out.push((d, StoredValue::plain(json!(0))));
        }
    }
    out
}

/// Hôte utilisé par le pont pour réécrire les miroirs (valeurs verrouillées
/// comprises). Posé au démarrage ; vide dans les tests.
static BRIDGE_HOST: OnceLock<HostCaps> = OnceLock::new();

pub(crate) fn set_bridge_host(host: HostCaps) {
    let _ = BRIDGE_HOST.set(host);
}

fn bridge_host() -> HostCaps {
    BRIDGE_HOST.get().cloned().unwrap_or_default()
}

/// Pont de compatibilité : un ancien bloc vient d'être écrit par l'ancien
/// chemin ; ses champs repris sont importés dans le registre (une révision
/// par appel de `Db::call`, historique « api »), puis les miroirs sont
/// réécrits.
pub(crate) fn import_legacy_blob(c: &Connection, blob: &str, v: &Value) -> ApiResult<()> {
    let (current, _) = reg::build_effective(&load_stored(c)?, &HostCaps::default(), 0);
    let changes = legacy_changes(blob, v, &current);
    if !changes.is_empty() {
        let now = now_unix();
        let revision = match db::bridge_revision() {
            Some(r) => r,
            None => {
                let r = bump_revision(c, now, None)?;
                db::set_bridge_revision(r);
                r
            }
        };
        let actor = Actor { user_id: None, email: String::new(), ip: String::new() };
        for (d, sv) in &changes {
            let old = current.stored(d.key).cloned().unwrap_or_else(|| d.default_stored());
            write_row(c, d, sv, now, None, None)?;
            write_history(c, revision, now, &actor, d, &old, sv, "api", None)?;
        }
    }
    write_mirrors(c, &load_effective(c, &bridge_host())?.0)
}

/// Reprise des anciens réglages pendant la migration v3 : valeurs
/// différentes du défaut, historique « migration », révision 1. La 2FA
/// imposée garde `updated_at = 0` (pas de délai de grâce rétroactif).
pub(crate) fn migrate_legacy(c: &Connection, now: i64) -> rusqlite::Result<()> {
    let defaults = reg::defaults(&HostCaps::default());
    let mut changes: Vec<(&'static SettingDef, StoredValue)> = Vec::new();
    for blob in ["org", "attachments", "sso", "ldap"] {
        let raw: Option<String> =
            c.query_row("SELECT value FROM settings WHERE key = ?1", [blob], |r| r.get(0)).optional()?;
        let Some(raw) = raw else { continue };
        match serde_json::from_str::<Value>(&raw) {
            Ok(v) => changes.extend(legacy_changes(blob, &v, &defaults)),
            Err(e) => tracing::error!(bloc = blob, error = %e, "ancien réglage illisible : non repris dans le registre"),
        }
    }
    if changes.is_empty() {
        return Ok(());
    }
    c.execute("UPDATE settings_meta SET revision = revision + 1, updated_at = ?1, updated_by = NULL WHERE id = 1", [now])?;
    let revision: i64 = c.query_row("SELECT revision FROM settings_meta WHERE id = 1", [], |r| r.get(0))?;
    for (d, sv) in &changes {
        let at = if d.key == "twofa.required" { 0 } else { now };
        c.execute(
            "INSERT OR REPLACE INTO org_settings (key, value, mode, policy_min, policy_max, updated_at, updated_by)
             VALUES (?1, ?2, NULL, NULL, NULL, ?3, NULL)",
            params![d.key, sv.value.to_string(), at],
        )?;
        c.execute(
            "INSERT INTO settings_history (revision, at, user_id, email, ip, key, old_value, new_value, source)
             VALUES (?1, ?2, NULL, '', '', ?3, ?4, ?5, 'migration')",
            params![revision, now, d.key, history_json(d, &d.default_stored()), history_json(d, sv)],
        )?;
    }
    tracing::info!(cles = changes.len(), "anciens réglages repris dans le registre");
    Ok(())
}

// ------------------------------------------------------------ Cache

/// Dernière modification, affichée en tête des réglages.
#[derive(Clone, Debug, Default)]
pub(crate) struct LastChange {
    pub revision: i64,
    pub at: i64,
    pub by: String,
}

/// Instantané des réglages d'une génération.
pub(crate) struct Loaded {
    pub eff: Arc<Effective>,
    generation: u64,
    /// `/settings/public` (A.5), révision comprise.
    pub public: Value,
    /// `/settings/policy` (A.4), révision comprise.
    pub policy: Value,
    /// Logo décodé et son type.
    pub logo: Option<(Arc<Vec<u8>>, &'static str)>,
    pub last_change: LastChange,
    pub sso: Option<SsoPublic>,
    pub ldap: Option<SsoPublic>,
}

/// Cache des réglages effectifs, partagé par toutes les requêtes.
#[derive(Default)]
pub struct SettingsCache {
    current: ArcSwapOption<Loaded>,
    reload: tokio::sync::Mutex<()>,
    loads: AtomicU64,
}

/// Clés dont l'erreur de lecture a déjà été journalisée par ce processus.
static REPORTED: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

impl SettingsCache {
    /// Chargements faits par ce cache.
    pub fn loads(&self) -> u64 {
        self.loads.load(Ordering::SeqCst)
    }

    /// Instantané courant ; relu en base seulement si la génération des
    /// réglages a changé depuis le dernier chargement.
    pub(crate) async fn loaded(&self, state: &AppState) -> ApiResult<Arc<Loaded>> {
        let generation = state.db.settings_generation();
        if let Some(cur) = self.current.load_full() {
            if cur.generation == generation {
                return Ok(cur);
            }
        }
        let _guard = self.reload.lock().await;
        // La génération est relue AVANT la lecture : une écriture pendant le
        // chargement provoquera un nouveau chargement.
        let generation = state.db.settings_generation();
        if let Some(cur) = self.current.load_full() {
            if cur.generation == generation {
                return Ok(cur);
            }
        }
        let host = state.host.caps.clone();
        let (eff, errors, sso, ldap, meta) = state
            .db
            .read(move |c| {
                let (eff, errors) = load_effective(c, &host)?;
                Ok((eff, errors, crate::sso::public_info(c)?, crate::ldap::public_info(c)?, read_meta(c)?))
            })
            .await?;
        LOADS.fetch_add(1, Ordering::Relaxed);
        self.loads.fetch_add(1, Ordering::SeqCst);
        report_read_errors(state, &errors).await;
        // Envoi au SIEM : cible et format suivent les réglages à chaque révision
        // (sans effet tant que le serveur n'a pas démarré l'envoi : tests).
        crate::syslog::apply(&eff);
        let logo = match eff.str("branding.logo") {
            "" => None,
            data => reg::decode_image(data, usize::MAX).ok().map(|(b, t)| (Arc::new(b), t)),
        };
        let public = serde_json::to_value(public_settings(&eff, sso.as_ref(), ldap.as_ref(), logo.is_some()))
            .map_err(|_| ApiError::internal("sérialisation des réglages publics"))?;
        let policy = json!({ "revision": eff.revision, "policy": eff.policy_json() });
        let loaded = Arc::new(Loaded {
            eff: Arc::new(eff),
            generation,
            public,
            policy,
            logo,
            last_change: LastChange { revision: meta.revision, at: meta.updated_at, by: meta.by },
            sso,
            ldap,
        });
        self.current.store(Some(loaded.clone()));
        Ok(loaded)
    }
}

/// Une valeur illisible en base est journalisée une fois par clé et par
/// processus (`settings.read_error`).
async fn report_read_errors(state: &AppState, errors: &[ReadError]) {
    let fresh: Vec<ReadError> = {
        let mut seen = REPORTED.lock().unwrap_or_else(|p| p.into_inner());
        errors.iter().filter(|e| seen.insert(e.key.clone())).cloned().collect()
    };
    if fresh.is_empty() {
        return;
    }
    for e in &fresh {
        tracing::error!(cle = %e.key, code = e.code, "réglage illisible en base : valeur par défaut appliquée");
    }
    let res = state
        .db
        .call(move |c| {
            let meta = ClientMeta { ip: String::new(), user_agent: "locksy-server".into() };
            for e in &fresh {
                audit(c, None, "", "settings.read_error", &e.key, &meta, e.code)?;
            }
            Ok(())
        })
        .await;
    if let Err(e) = res {
        tracing::warn!(message = %e.message, "journalisation d'un réglage illisible impossible");
    }
}

/// Méthode de connexion activée ?
fn method_enabled(m: &str, sso: Option<&SsoPublic>, ldap: Option<&SsoPublic>) -> bool {
    match m {
        "sso" => sso.is_some(),
        "ldap" => ldap.is_some(),
        _ => true,
    }
}

/// Page publique (A.5).
fn public_settings(eff: &Effective, sso: Option<&SsoPublic>, ldap: Option<&SsoPublic>, has_logo: bool) -> PublicSettings {
    let wanted = eff.str("auth.primary_method");
    let primary = if method_enabled(wanted, sso, ldap) { wanted } else { "password" };
    let mut methods = vec![primary.to_string()];
    for (m, on) in [("password", true), ("ldap", ldap.is_some()), ("sso", sso.is_some())] {
        if on && !methods.iter().any(|x| x == m) {
            methods.push(m.into());
        }
    }
    let banned = eff.list("master_password.banned_words");
    PublicSettings {
        revision: eff.revision,
        branding: PublicBranding {
            org_name: eff.str("branding.org_name").into(),
            accent_color: eff.str("branding.accent_color").into(),
            logo_url: has_logo.then(|| format!("/api/branding/logo?v={}", eff.revision)),
            login_message: eff.str("branding.login_message").into(),
            support_contact: eff.str("branding.support_contact").into(),
        },
        legal: PublicLegal {
            notice_url: eff.str("legal.notice_url").into(),
            privacy_url: eff.str("legal.privacy_url").into(),
            accessibility_url: eff.str("legal.accessibility_url").into(),
            login_banner: eff.str("legal.login_banner").into(),
            charter_version: eff.int("legal.charter_version"),
            dpo_contact: eff.str("legal.dpo_contact").into(),
        },
        i18n: PublicI18n { default_locale: eff.str("i18n.default_locale").into(), timezone: eff.str("i18n.timezone").into() },
        login: PublicLogin {
            primary_method: primary.into(),
            methods,
            sso_label: sso.map(|s| s.label.clone()),
            ldap_label: ldap.map(|s| s.label.clone()),
            enforced: eff.bool("sso.enforce") || eff.bool("ldap.enforce"),
        },
        master_password: PublicMasterPassword {
            min_length: eff.int("master_password.min_length"),
            min_score: eff.int("master_password.min_score"),
            forbid_identity: eff.bool("master_password.forbid_identity"),
            banned_words_count: banned.len() as i64,
            banned_words: banned,
        },
        kdf: PublicKdf {
            memory_mib: eff.int("kdf.memory_mib"),
            iterations: eff.int("kdf.iterations"),
            parallelism: eff.int("kdf.parallelism"),
            upgrade_on_login: eff.bool("kdf.upgrade_on_login"),
        },
    }
}

// ------------------------------------------------------------ En-têtes HTTP

fn etag(revision: i64) -> HeaderValue {
    HeaderValue::from_str(&format!("\"r{revision}\"")).unwrap_or_else(|_| HeaderValue::from_static("\"r0\""))
}

/// Jeton d'un en-tête `If-Match` / `If-None-Match` : `"r42"`, `r42`, `W/"r42"`.
fn tag_value(raw: &str) -> &str {
    raw.trim().trim_start_matches("W/").trim_matches('"')
}

/// `If-None-Match` correspond à la révision courante.
fn not_modified(headers: &HeaderMap, revision: i64) -> bool {
    let want = format!("r{revision}");
    headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|t| tag_value(t) == want || tag_value(t) == "*")
}

/// `If-Match` d'une révision de réglages : absent, illisible (`Some(None)`) ou lu.
fn if_match_revision(headers: &HeaderMap) -> Option<Option<i64>> {
    let raw = headers.get(header::IF_MATCH)?;
    let v = raw.to_str().ok().map(tag_value).map(|t| t.strip_prefix('r').unwrap_or(t).to_string());
    Some(v.and_then(|t| t.parse::<i64>().ok()))
}

/// Réponse JSON avec ETag, ou 304 si le client a déjà cette révision.
fn cached_json(headers: &HeaderMap, revision: i64, body: &Value) -> Response {
    if not_modified(headers, revision) {
        return (StatusCode::NOT_MODIFIED, [(header::ETAG, etag(revision))]).into_response();
    }
    ([(header::ETAG, etag(revision))], Json(body.clone())).into_response()
}

fn parse_body<T: serde::de::DeserializeOwned>(body: &Bytes) -> ApiResult<T> {
    serde_json::from_slice(body).map_err(|_| ApiError::bad_request("Requête illisible : JSON attendu."))
}

fn clean_reason(reason: Option<String>) -> ApiResult<Option<String>> {
    let Some(r) = reason.map(|r| r.trim().to_string()).filter(|r| !r.is_empty()) else { return Ok(None) };
    if r.chars().count() > 500 || r.chars().any(char::is_control) {
        return Err(ApiError::bad_request("Motif trop long (500 caractères au plus) ou illisible."));
    }
    Ok(Some(r))
}

// ------------------------------------------------------------ Réauthentification

/// Preuve de réauthentification d'une action sensible des réglages :
/// en-tête `X-Locksy-Reauth` portant un jeton `rt1.` de l'action « settings »
/// (POST /auth/reauth), ou la forme historique (base64 de l'`auth_key`),
/// acceptée pour cette seule action. Voir `security::require_step_up`.
pub(crate) async fn verify_reauth(state: &AppState, user: &AuthUser, headers: &HeaderMap) -> ApiResult<()> {
    crate::security::require_step_up(state, user, headers, "settings").await
}

// ------------------------------------------------------------ Validation

/// Contexte de validation : l'acteur, ses tests de connexion d'entreprise,
/// les méthodes activées.
async fn context(state: &AppState, user: &AuthUser, loaded: &Loaded) -> ApiResult<Ctx> {
    let uid = user.id.clone();
    let (has_2fa, tests) = state
        .db
        .read(move |c| {
            let has: bool = c.query_row("SELECT totp_secret IS NOT NULL FROM users WHERE id = ?1", [&uid], |r| r.get(0))?;
            let mut st =
                c.prepare("SELECT kind, MAX(at) FROM identity_tests WHERE user_id = ?1 AND ok = 1 GROUP BY kind")?;
            let tests = st
                .query_map([&uid], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok((has, tests))
        })
        .await?;
    let mut last_test_ok_at = BTreeMap::new();
    for (kind, at) in tests {
        match kind.as_str() {
            "sso" => last_test_ok_at.insert("sso", at),
            "ldap" => last_test_ok_at.insert("ldap", at),
            _ => None,
        };
    }
    Ok(Ctx {
        actor_role: user.role.clone(),
        actor_id: user.id.clone(),
        actor_ip: user.meta.ip.parse::<IpAddr>().ok(),
        actor_has_2fa: has_2fa,
        now: now_unix(),
        sso_enabled: loaded.sso.is_some(),
        ldap_login_enabled: loaded.ldap.is_some(),
        last_test_ok_at,
        host: state.host.caps.clone(),
    })
}

/// Erreurs d'une validation refusée, par clé (`{code, …}`).
fn rejection_errors(r: &Rejection) -> Map<String, Value> {
    let (keys, code): (&[String], &str) = match r {
        Rejection::Invalid(fields) => {
            return fields.iter().map(|(k, e)| (k.clone(), serde_json::to_value(e).unwrap_or(Value::Null))).collect();
        }
        Rejection::OwnerOnly(keys) => (keys, "owner_only"),
        Rejection::HostLocked(keys) => (keys, "host_locked"),
        Rejection::TestRequired(key) => (std::slice::from_ref(key), "test_required"),
    };
    keys.iter().map(|k| (k.clone(), json!({ "code": code }))).collect()
}

/// Refus de validation en réponse HTTP (PATCH et autres écritures).
fn rejection_error(r: Rejection) -> ExtError {
    match r {
        Rejection::Invalid(fields) => {
            let n = fields.len();
            let fields = rejection_errors(&Rejection::Invalid(fields));
            let msg = if n == 1 { "1 réglage invalide.".to_string() } else { format!("{n} réglages invalides.") };
            ExtError::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid_settings", msg).with("fields", fields)
        }
        Rejection::OwnerOnly(keys) => {
            ExtError::new(StatusCode::FORBIDDEN, "owner_only", "Ces réglages sont réservés aux propriétaires.").with("keys", keys)
        }
        Rejection::HostLocked(keys) => ExtError::new(
            StatusCode::CONFLICT,
            "host_locked",
            "Ces réglages sont fixés par l'hébergeur du serveur et ne se modifient pas ici.",
        )
        .with("keys", keys),
        Rejection::TestRequired(key) => ExtError::new(
            StatusCode::CONFLICT,
            "test_required",
            "Testez d'abord cette connexion avec votre compte (test réussi de moins de 24 h) avant de l'imposer.",
        )
        .with("key", key),
    }
}

/// Forme d'une valeur pour le client : image résumée, secret masqué.
fn view_value(d: &SettingDef, sv: &StoredValue, revision: i64) -> Value {
    match d.kind {
        Kind::Secret => json!("***"),
        Kind::Image { .. } => {
            let has = !sv.value.as_str().unwrap_or("").is_empty();
            json!({ "has_image": has, "url": has.then(|| format!("/api/branding/logo?v={revision}")) })
        }
        _ => reg::stored_to_json(d, sv),
    }
}

fn diff_json(diff: &Diff, revision: i64) -> Vec<Value> {
    diff.entries
        .iter()
        .filter_map(|e| {
            let d = reg::def(&e.key)?;
            Some(json!({
                "key": e.key,
                "old": view_value(d, &e.old, revision),
                "new": view_value(d, &e.new, revision),
                "lowered": e.lowered,
            }))
        })
        .collect()
}

/// Valeur après modification (diff), sinon valeur actuelle.
fn after_value<'a>(diff: &'a Diff, eff: &'a Effective, key: &str) -> &'a Value {
    diff.entries.iter().find(|e| e.key == key).map(|e| &e.new.value).unwrap_or_else(|| eff.get(key))
}

/// Comptes concernés par une modification (affiché avant d'enregistrer).
fn impact(c: &Connection, diff: &Diff, eff: &Effective) -> ApiResult<Vec<Value>> {
    let changed = |k: &str| diff.entries.iter().any(|e| e.key == k);
    let mut out = Vec::new();
    let count = |sql: &str, p: &[&dyn rusqlite::ToSql]| -> ApiResult<i64> { Ok(c.query_row(sql, p, |r| r.get(0))?) };
    if changed("twofa.required") || changed("twofa.required_roles") {
        let required = after_value(diff, eff, "twofa.required").as_bool().unwrap_or(false);
        let roles: Vec<String> = after_value(diff, eff, "twofa.required_roles")
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        let roles_json = json!(roles).to_string();
        let base = "FROM users WHERE disabled = 0 AND totp_secret IS NULL
                    AND (?1 OR role IN (SELECT value FROM json_each(?2)))";
        let users = count(&format!("SELECT COUNT(*) {base}"), &[&required, &roles_json])?;
        let admins = count(&format!("SELECT COUNT(*) {base} AND role IN ('owner', 'admin')"), &[&required, &roles_json])?;
        let key = if changed("twofa.required") { "twofa.required" } else { "twofa.required_roles" };
        out.push(json!({ "key": key, "affected_users": users, "affected_admins": admins, "link": LINK_2FA }));
    }
    if changed("users.disable_after_inactive_days") {
        let days = after_value(diff, eff, "users.disable_after_inactive_days").as_i64().unwrap_or(0);
        if days > 0 {
            let cutoff = now_unix() - days * 86_400;
            let base = "FROM users WHERE disabled = 0 AND role <> 'owner' AND COALESCE(last_login_at, created_at) < ?1";
            let users = count(&format!("SELECT COUNT(*) {base}"), &[&cutoff])?;
            let admins = count(&format!("SELECT COUNT(*) {base} AND role = 'admin'"), &[&cutoff])?;
            out.push(json!({ "key": "users.disable_after_inactive_days", "affected_users": users, "affected_admins": admins, "link": LINK_ACTIVE }));
        }
    }
    if changed("vault.personal_enabled") && after_value(diff, eff, "vault.personal_enabled") == &json!(false) {
        let base = "FROM users u WHERE u.disabled = 0 AND EXISTS (SELECT 1 FROM memberships m JOIN collections c
                    ON c.id = m.collection_id WHERE m.user_id = u.id AND c.personal = 1)";
        let users = count(&format!("SELECT COUNT(*) {base}"), &[])?;
        let admins = count(&format!("SELECT COUNT(*) {base} AND u.role IN ('owner', 'admin')"), &[])?;
        out.push(json!({ "key": "vault.personal_enabled", "affected_users": users, "affected_admins": admins, "link": LINK_ACTIVE }));
    }
    Ok(out)
}

/// Réponse d'une validation (A.3) : toujours 200, `ok` dit si l'écriture
/// passerait.
async fn validate_response(
    state: &AppState,
    loaded: &Loaded,
    result: Result<Diff, Rejection>,
    extra: Map<String, Value>,
) -> ApiResult<Response> {
    let rev = loaded.eff.revision;
    let mut body = match result {
        Ok(diff) => {
            let eff = loaded.eff.clone();
            let d = diff.clone();
            let impact = state.db.read(move |c| impact(c, &d, &eff)).await?;
            json!({
                "ok": true,
                "diff": diff_json(&diff, rev),
                "requires_reauth": diff.requires_reauth,
                "requires_owner": diff.requires_owner,
                "impact": impact,
                "warnings": diff.warnings,
                "errors": {},
            })
        }
        Err(r) => json!({
            "ok": false,
            "diff": [],
            "requires_reauth": false,
            "requires_owner": matches!(r, Rejection::OwnerOnly(_)),
            "impact": [],
            "warnings": [],
            "errors": rejection_errors(&r),
        }),
    };
    if let Some(obj) = body.as_object_mut() {
        obj.extend(extra);
    }
    Ok(([(header::ETAG, etag(rev))], Json(body)).into_response())
}

// ------------------------------------------------------------ Écriture

/// Nature d'une écriture : source de l'historique et événement d'audit
/// propre (en plus de `settings.updated`).
struct Op {
    source: &'static str,
    action: Option<&'static str>,
}

fn conflict(meta: &Meta) -> ExtError {
    ExtError::new(
        StatusCode::CONFLICT,
        "settings_conflict",
        "Les réglages ont été modifiés entre-temps. Rechargez-les avant d'enregistrer.",
    )
    .with("current_revision", meta.revision)
    .with("by", meta.by.clone())
    .with("at", meta.updated_at)
    .header(header::ETAG, etag(meta.revision))
}

/// Résumé lisible d'une valeur pour le journal d'audit (secrets masqués).
fn audit_value(d: &SettingDef, sv: &StoredValue) -> String {
    let base = match (&d.kind, &sv.value) {
        (Kind::Secret, _) => "***".to_string(),
        (Kind::Image { .. }, v) => if v.as_str().unwrap_or("").is_empty() { "logo de Locksy" } else { "image" }.to_string(),
        (_, Value::Bool(b)) => if *b { "oui" } else { "non" }.to_string(),
        (_, Value::String(s)) => {
            let s: String = s.chars().take(80).collect();
            if s.is_empty() {
                "(vide)".into()
            } else {
                s
            }
        }
        (_, v) => v.to_string(),
    };
    match sv.mode {
        Some(m) if d.modes => {
            let bounds = match (sv.min_i64(), sv.max_i64()) {
                (None, None) => String::new(),
                (lo, hi) => format!(", {}..{}", lo.map(|v| v.to_string()).unwrap_or_default(), hi.map(|v| v.to_string()).unwrap_or_default()),
            };
            format!("{base} ({}{bounds})", m.as_str())
        }
        _ => base,
    }
}

/// Validation complète puis écriture en une révision : If-Match (428),
/// validation (422, 409, 403, 409), révision (409), réauthentification si
/// abaissement (428, 401), écriture (200 + ETag).
async fn write_flow(
    state: &AppState,
    user: &AuthUser,
    headers: &HeaderMap,
    changes: Changes,
    reason: Option<String>,
    op: Op,
    extra: Map<String, Value>,
) -> ExtResult<Response> {
    let Some(if_match) = if_match_revision(headers) else {
        return Err(ExtError::new(
            StatusCode::PRECONDITION_REQUIRED,
            "precondition_required",
            "En-tête If-Match obligatoire : indiquez la révision des réglages que vous modifiez.",
        ));
    };
    let reason = clean_reason(reason)?;
    let loaded = state.settings.loaded(state).await?;
    let ctx = context(state, user, &loaded).await?;
    let diff = reg::validate(&loaded.eff, &changes, &ctx).map_err(rejection_error)?;
    if if_match != Some(loaded.eff.revision) {
        let meta = Meta { revision: loaded.eff.revision, updated_at: loaded.last_change.at, by: loaded.last_change.by.clone() };
        return Err(conflict(&meta));
    }
    if diff.requires_reauth {
        verify_reauth(state, user, headers).await?;
    }
    let expected = loaded.eff.revision;
    let (revision, changed) = if diff.entries.is_empty() {
        (expected, Vec::new())
    } else {
        let st = state.clone();
        let actor_user = user.clone();
        state
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                let meta = read_meta(&tx)?;
                if meta.revision != expected {
                    return Ok(Err(conflict(&meta)));
                }
                // Revalidation sur l'état lu dans la transaction.
                let (current, _) = load_effective(&tx, &st.host.caps)?;
                let diff = match reg::validate(&current, &changes, &ctx) {
                    Ok(d) => d,
                    Err(r) => return Ok(Err(rejection_error(r))),
                };
                let actor = Actor {
                    user_id: Some(actor_user.id.clone()),
                    email: actor_user.email.clone(),
                    ip: actor_user.meta.ip.clone(),
                };
                let revision =
                    apply(&tx, &diff.entries, &actor, op.source, reason.as_deref(), &st.server_key, &st.host.caps)?;
                let target = format!("r{revision}");
                let detail = diff
                    .entries
                    .iter()
                    .filter_map(|e| {
                        let d = reg::def(&e.key)?;
                        Some(format!("{} {}→{}", e.key, audit_value(d, &e.old), audit_value(d, &e.new)))
                    })
                    .collect::<Vec<_>>()
                    .join(" ; ");
                let meta = &actor_user.meta;
                let uid = Some(actor_user.id.as_str());
                audit(&tx, uid, &actor_user.email, "settings.updated", &target, meta, &detail)?;
                if let Some(action) = op.action {
                    audit(&tx, uid, &actor_user.email, action, &target, meta, reason.as_deref().unwrap_or(""))?;
                }
                let lowered: Vec<String> = diff.entries.iter().filter(|e| e.lowered).map(|e| e.key.clone()).collect();
                if !lowered.is_empty() {
                    audit(&tx, uid, &actor_user.email, "settings.lowered", &target, meta, &lowered.join(", "))?;
                    let (after, _) = load_effective(&tx, &st.host.caps)?;
                    let n = Notification::SettingsLowered {
                        revision,
                        keys: lowered,
                        actor_email: actor_user.email.clone(),
                    };
                    st.notifier.enqueue(&tx, &after, &n)?;
                }
                tx.commit()?;
                Ok(Ok((revision, diff.entries.iter().map(|e| e.key.clone()).collect::<Vec<_>>())))
            })
            .await??
    };
    let mut body = json!({ "revision": revision, "changed": changed });
    if let Some(obj) = body.as_object_mut() {
        obj.extend(extra);
    }
    Ok(([(header::ETAG, etag(revision))], Json(body)).into_response())
}

fn require_owner(user: &AuthUser) -> ApiResult<()> {
    if user.role != roles::OWNER {
        return Err(ApiError::forbidden("Réservé aux propriétaires."));
    }
    Ok(())
}

// ------------------------------------------------------------ Routes publiques et utilisateur

/// `GET /settings/public` : apparence, mentions, méthode de connexion,
/// politique du mot de passe maître (sans authentification).
pub async fn get_public(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    let loaded = state.settings.loaded(&state).await?;
    Ok(cached_json(&headers, loaded.eff.revision, &loaded.public))
}

/// `GET /settings/policy` : politique appliquée par les clients.
pub async fn get_policy(State(state): State<AppState>, _user: AuthUser, headers: HeaderMap) -> ApiResult<Response> {
    let loaded = state.settings.loaded(&state).await?;
    Ok(cached_json(&headers, loaded.eff.revision, &loaded.policy))
}

/// `GET /branding/logo` : logo de l'organisation (PNG ou WebP).
pub async fn get_logo(State(state): State<AppState>) -> ApiResult<Response> {
    let loaded = state.settings.loaded(&state).await?;
    let Some((bytes, mime)) = loaded.logo.clone() else {
        return Err(ApiError::not_found("Aucun logo n'est défini."));
    };
    Ok(([(header::CONTENT_TYPE, HeaderValue::from_static(mime))], bytes.as_ref().clone()).into_response())
}

/// Révisions de la politique et des préférences d'un utilisateur, pour
/// `/sync` (branchement par le lot L7 en vague 2).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) async fn revisions_for(state: &AppState, user_id: &str) -> ApiResult<SyncRevisions> {
    let policy_revision = state.effective().await?.revision;
    let uid = user_id.to_string();
    let prefs_revision = state
        .db
        .read(move |c| {
            Ok(c.query_row("SELECT revision FROM user_prefs WHERE user_id = ?1", [uid], |r| r.get(0)).optional()?)
        })
        .await?
        .unwrap_or(0);
    Ok(SyncRevisions { policy_revision, prefs_revision })
}

/// `GET /test/counters` (seulement avec `LOCKSY_ENV=test`).
pub async fn test_counters(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    if !state.host.env_test {
        return Err(ApiError::not_found("Ressource introuvable."));
    }
    Ok(Json(json!({
        "settings_loads": LOADS.load(Ordering::Relaxed),
        "legacy_settings_reads": db::LEGACY_READS.load(Ordering::Relaxed),
        "cache_loads": state.settings.loads(),
    })))
}

// ------------------------------------------------------------ Administration

/// `GET /admin/settings` : valeurs, sources, avertissements, profil le plus
/// proche (A.2), plus les champs historiques à plat (ancien écran).
pub async fn get_settings(State(state): State<AppState>, admin: AdminUser) -> ApiResult<Response> {
    let legacy = crate::admin::get_settings(State(state.clone()), admin).await?;
    let loaded = state.settings.loaded(&state).await?;
    let eff = &loaded.eff;
    let rev = eff.revision;
    let mut values = Map::new();
    for d in REGISTRY {
        let Some(e) = eff.entry(d.key) else { continue };
        let mut v = Map::new();
        if d.is_secret() {
            v.insert("has_secret".into(), json!(!e.stored.value.as_str().unwrap_or("").is_empty()));
            v.insert("default".into(), Value::Null);
        } else if d.modes {
            // Clé à modes : la valeur nue (A.2) ; mode et bornes sont à côté.
            // `stored_to_json` rendrait l'objet {value, mode, min, max}.
            v.insert("value".into(), e.stored.value.clone());
            v.insert("default".into(), d.default_value());
        } else {
            v.insert("value".into(), view_value(d, &StoredValue::plain(e.stored.value.clone()), rev));
            v.insert("default".into(), view_value(d, &StoredValue::plain(d.default_value()), rev));
        }
        if d.modes {
            v.insert("mode".into(), json!(e.stored.mode.map(|m| m.as_str())));
            v.insert("min".into(), e.stored.min.clone().unwrap_or(Value::Null));
            v.insert("max".into(), e.stored.max.clone().unwrap_or(Value::Null));
        }
        v.insert("source".into(), json!(e.source));
        if let Some(var) = &e.locked_by {
            v.insert("locked_by".into(), json!(var));
        }
        v.insert("updated_at".into(), json!(e.updated_at));
        values.insert(d.key.into(), Value::Object(v));
    }
    let (closest, deviations) = reg::closest_profile(eff);
    let mut body = serde_json::to_value(legacy.0).map_err(|_| ApiError::internal("sérialisation des réglages"))?;
    if let Some(obj) = body.as_object_mut() {
        obj.insert("revision".into(), json!(rev));
        obj.insert("schema_version".into(), json!(eff.schema_version));
        obj.insert("values".into(), Value::Object(values));
        obj.insert("warnings".into(), json!(eff.warnings()));
        obj.insert("profile".into(), json!({ "closest": closest, "deviations": deviations }));
        let lc = &loaded.last_change;
        obj.insert("last_change".into(), json!({ "revision": lc.revision, "at": lc.at, "by": lc.by }));
    }
    Ok(([(header::ETAG, etag(rev))], Json(body)).into_response())
}

fn kind_json(d: &SettingDef, host: &HostCaps) -> Value {
    let t = d.kind.type_name();
    match d.kind {
        Kind::Int { unit, .. } => {
            let (min, max) = d.int_bounds(host).unwrap_or((0, 0));
            json!({ "type": t, "min": min, "max": max, "unit": unit })
        }
        Kind::Enum(values) => json!({ "type": t, "values": values }),
        Kind::Text { max_len, multiline } => json!({ "type": t, "max_len": max_len, "multiline": multiline }),
        Kind::Url { https_only } => json!({ "type": t, "https_only": https_only }),
        Kind::Words { max } => json!({ "type": t, "max": max }),
        Kind::Image { max_bytes } => json!({ "type": t, "max_bytes": max_bytes }),
        _ => json!({ "type": t }),
    }
}

/// `GET /admin/settings/schema` : le registre, bornes effectives comprises
/// (A.1). Les libellés viennent du catalogue i18n du client.
pub async fn get_schema(State(state): State<AppState>, _admin: AdminUser) -> ApiResult<Json<Value>> {
    let loaded = state.settings.loaded(&state).await?;
    let host = &state.host.caps;
    let mut defs: Vec<&SettingDef> = REGISTRY.iter().collect();
    defs.sort_by_key(|d| (d.section, d.order));
    let settings: Vec<Value> = defs
        .into_iter()
        .map(|d| {
            let default = if d.modes { reg::stored_to_json(d, &d.default_stored()) } else { d.default_value() };
            json!({
                "key": d.key,
                "kind": kind_json(d, host),
                "default": if d.is_secret() { Value::Null } else { default },
                "section": d.section,
                "order": d.order,
                "advanced": d.advanced,
                "owner_only": d.owner_only,
                "public": d.scope == reg::Scope::Public,
                "client": d.client,
                "modes": d.modes,
                "safer": d.safer,
                "host_locked": loaded.eff.source(d.key) == Source::HostLocked,
                "host_cap": d.host_cap,
                "presets": d.presets,
                "synonyms": d.synonyms,
                "since": d.since,
            })
        })
        .collect();
    let mut profiles = Map::new();
    for p in Profile::ALL {
        let mut values = Map::new();
        for (key, change) in reg::profile(p).0 {
            if let (Some(d), Change::Set(sv)) = (reg::def(&key), change) {
                values.insert(key, reg::stored_to_json(d, &sv));
            }
        }
        profiles.insert(p.as_str().into(), Value::Object(values));
    }
    let sections: Vec<&str> = reg::Section::ALL.iter().map(|s| s.as_str()).collect();
    Ok(Json(json!({
        "schema_version": reg::SCHEMA_VERSION,
        "sections": sections,
        "settings": settings,
        "profiles": profiles,
    })))
}

#[derive(Deserialize)]
struct ChangeRequest {
    changes: Changes,
    #[serde(default)]
    reason: Option<String>,
}

/// `POST /admin/settings/validate` : diff, erreurs, impact, sans écriture.
pub async fn validate_settings(State(state): State<AppState>, AdminUser(user): AdminUser, body: Bytes) -> ApiResult<Response> {
    let req: ChangeRequest = parse_body(&body)?;
    clean_reason(req.reason)?;
    let loaded = state.settings.loaded(&state).await?;
    let ctx = context(&state, &user, &loaded).await?;
    let result = reg::validate(&loaded.eff, &req.changes, &ctx);
    validate_response(&state, &loaded, result, Map::new()).await
}

/// `PATCH /admin/settings`.
pub async fn patch_settings(
    State(state): State<AppState>,
    AdminUser(user): AdminUser,
    headers: HeaderMap,
    body: Bytes,
) -> ExtResult<Response> {
    let req: ChangeRequest = parse_body(&body)?;
    write_flow(&state, &user, &headers, req.changes, req.reason, Op { source: "ui", action: None }, Map::new()).await
}

#[derive(Deserialize)]
struct ResetRequest {
    keys: Vec<String>,
    #[serde(default)]
    reason: Option<String>,
}

/// `POST /admin/settings/reset` : retour au défaut des clés données.
pub async fn reset_settings(
    State(state): State<AppState>,
    AdminUser(user): AdminUser,
    headers: HeaderMap,
    body: Bytes,
) -> ExtResult<Response> {
    let req: ResetRequest = parse_body(&body)?;
    let changes = Changes(req.keys.into_iter().map(|k| (k, Change::Reset)).collect());
    let op = Op { source: "reset", action: Some("settings.reset") };
    write_flow(&state, &user, &headers, changes, req.reason, op, Map::new()).await
}

#[derive(Deserialize)]
struct ProfileRequest {
    profile: String,
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    reason: Option<String>,
}

/// `POST /admin/settings/profile` : applique un profil en une révision (ou
/// l'essaie à blanc).
pub async fn apply_profile(
    State(state): State<AppState>,
    AdminUser(user): AdminUser,
    headers: HeaderMap,
    body: Bytes,
) -> ExtResult<Response> {
    let req: ProfileRequest = parse_body(&body)?;
    let p = Profile::parse(&req.profile).ok_or_else(|| ApiError::bad_request("Profil inconnu : standard, reinforced ou strict."))?;
    let changes = reg::profile(p);
    if req.dry_run {
        let loaded = state.settings.loaded(&state).await?;
        let ctx = context(&state, &user, &loaded).await?;
        let result = reg::validate(&loaded.eff, &changes, &ctx);
        return Ok(validate_response(&state, &loaded, result, Map::new()).await?);
    }
    let op = Op { source: "profile", action: Some("settings.profile_applied") };
    write_flow(&state, &user, &headers, changes, req.reason, op, Map::new()).await
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    page: Option<i64>,
    #[serde(default)]
    per_page: Option<i64>,
}

/// Une ligne de `settings_history`.
struct HistoryRow {
    at: i64,
    email: String,
    source: String,
    reason: Option<String>,
    key: String,
    old: Option<String>,
    new: Option<String>,
    /// Nom actuel de l'auteur, sinon son e-mail.
    by: String,
}

/// Valeur d'historique pour le client (image résumée).
fn history_value(key: &str, raw: Option<String>) -> Value {
    let v = raw.and_then(|s| serde_json::from_str::<Value>(&s).ok()).unwrap_or(Value::Null);
    match reg::def(key).map(|d| d.kind) {
        Some(Kind::Image { .. }) => json!({ "has_image": !v.as_str().unwrap_or("").is_empty() }),
        _ => v,
    }
}

/// `GET /admin/settings/history?key=&page=&per_page=` : révisions, les plus récentes d'abord.
pub async fn history(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(q): Query<HistoryQuery>,
) -> ApiResult<Json<Value>> {
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(20).clamp(1, 100);
    let key = q.key.filter(|k| !k.is_empty());
    let body = state
        .db
        .read(move |c| {
            let filter = "(?1 IS NULL OR key = ?1)";
            let total: i64 = c.query_row(
                &format!("SELECT COUNT(DISTINCT revision) FROM settings_history WHERE {filter}"),
                params![key],
                |r| r.get(0),
            )?;
            let mut st = c.prepare(&format!(
                "SELECT DISTINCT revision FROM settings_history WHERE {filter} ORDER BY revision DESC LIMIT ?2 OFFSET ?3"
            ))?;
            let revisions = st
                .query_map(params![key, per_page, (page - 1) * per_page], |r| r.get::<_, i64>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            let mut rows = c.prepare(
                "SELECT h.at, h.email, h.source, h.reason, h.key, h.old_value, h.new_value, COALESCE(u.name, h.email)
                 FROM settings_history h LEFT JOIN users u ON u.id = h.user_id
                 WHERE h.revision = ?2 AND (?1 IS NULL OR h.key = ?1) ORDER BY h.id",
            )?;
            let mut out = Vec::new();
            for rev in revisions {
                let entries = rows
                    .query_map(params![key, rev], |r| {
                        Ok(HistoryRow {
                            at: r.get(0)?,
                            email: r.get(1)?,
                            source: r.get(2)?,
                            reason: r.get(3)?,
                            key: r.get(4)?,
                            old: r.get(5)?,
                            new: r.get(6)?,
                            by: r.get(7)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                let Some(first) = entries.first() else { continue };
                let changes: Vec<Value> = entries
                    .iter()
                    .map(|h| {
                        json!({ "key": h.key, "old": history_value(&h.key, h.old.clone()), "new": history_value(&h.key, h.new.clone()) })
                    })
                    .collect();
                out.push(json!({
                    "revision": rev,
                    "at": first.at,
                    "by": first.by,
                    "email": first.email,
                    "source": first.source,
                    "reason": first.reason,
                    "changes": changes,
                }));
            }
            Ok(json!({ "total": total, "page": page, "per_page": per_page, "revisions": out }))
        })
        .await?;
    Ok(Json(body))
}

/// Clés modifiables par une restauration ou un import : ni secret, ni clé
/// fixée par l'hébergeur.
fn restorable(d: &SettingDef, eff: &Effective) -> bool {
    !d.is_secret() && eff.source(d.key) != Source::HostLocked
}

/// `POST /admin/settings/revert/:revision` (propriétaire) : nouvelle
/// révision qui reprend les valeurs d'une révision antérieure. Les secrets
/// ne sont pas restaurés (liste `skipped`).
pub async fn revert(
    State(state): State<AppState>,
    AdminUser(user): AdminUser,
    Path(target): Path<i64>,
    headers: HeaderMap,
) -> ExtResult<Response> {
    require_owner(&user)?;
    let loaded = state.settings.loaded(&state).await?;
    if target < 0 || target > loaded.eff.revision {
        return Err(ApiError::not_found("Révision introuvable.").into());
    }
    let rows = state
        .db
        .read(move |c| {
            let mut st = c.prepare(
                "SELECT key, new_value FROM settings_history h
                 WHERE revision <= ?1 AND id = (SELECT MAX(id) FROM settings_history WHERE key = h.key AND revision <= ?1)",
            )?;
            let rows = st
                .query_map([target], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            let mut later = c.prepare("SELECT DISTINCT key FROM settings_history WHERE revision > ?1")?;
            let changed_since = later.query_map([target], |r| r.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?;
            Ok((rows, changed_since))
        })
        .await?;
    let (rows, changed_since) = rows;
    let at_target: BTreeMap<String, Option<String>> = rows.into_iter().collect();
    let mut changes = Changes::default();
    for d in REGISTRY.iter().filter(|d| restorable(d, &loaded.eff)) {
        let change = match at_target.get(d.key).cloned().flatten().and_then(|s| serde_json::from_str::<Value>(&s).ok()) {
            Some(v) => match reg::stored_from_json(d, &v) {
                Ok(sv) => Change::Set(sv),
                Err(_) => continue,
            },
            None => Change::Reset,
        };
        changes.0.insert(d.key.into(), change);
    }
    let skipped: Vec<&str> =
        REGISTRY.iter().filter(|d| d.is_secret() && changed_since.iter().any(|k| k == d.key)).map(|d| d.key).collect();
    let mut extra = Map::new();
    extra.insert("skipped".into(), json!(skipped));
    let op = Op { source: "revert", action: Some("settings.reverted") };
    write_flow(&state, &user, &headers, changes, Some(format!("Retour à la révision {target}")), op, extra).await
}

/// Valeurs d'export (clés enregistrées par l'organisation ; secret = null).
fn export_values(eff: &Effective) -> BTreeMap<String, Value> {
    REGISTRY
        .iter()
        .filter(|d| eff.source(d.key) == Source::Org)
        .filter_map(|d| {
            let sv = eff.stored(d.key)?;
            let v = if d.is_secret() { Value::Null } else { serde_json::to_value(sv).ok()? };
            Some((d.key.to_string(), v))
        })
        .collect()
}

fn values_digest(values: &BTreeMap<String, Value>) -> String {
    sha256_hex(&serde_json::to_string(values).unwrap_or_default())
}

/// `GET /admin/settings/export` (propriétaire) : valeurs non défaut, sans
/// secret, avec une empreinte. Journalisé.
pub async fn export(State(state): State<AppState>, AdminUser(user): AdminUser) -> ApiResult<Json<Value>> {
    require_owner(&user)?;
    let loaded = state.settings.loaded(&state).await?;
    let values = export_values(&loaded.eff);
    let digest = values_digest(&values);
    let rev = loaded.eff.revision;
    let u = user.clone();
    let count = values.len();
    state
        .db
        .call(move |c| audit(c, Some(&u.id), &u.email, "settings.exported", &format!("r{rev}"), &u.meta, &format!("{count} réglages")))
        .await?;
    Ok(Json(json!({
        "format": EXPORT_FORMAT,
        "schema_version": reg::SCHEMA_VERSION,
        "revision": rev,
        "exported_at": now_unix(),
        "values": values,
        "sha256": digest,
    })))
}

#[derive(Deserialize)]
struct ImportDocument {
    format: String,
    #[serde(default)]
    schema_version: u32,
    #[serde(default)]
    values: BTreeMap<String, Value>,
    #[serde(default)]
    sha256: Option<String>,
    /// Clés retenues (cases cochées) ; absent : toutes.
    #[serde(default)]
    keys: Option<Vec<String>>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Deserialize)]
pub struct ImportQuery {
    #[serde(default)]
    dry_run: Option<bool>,
}

/// `POST /admin/settings/import?dry_run=true|false` (propriétaire) : essai à
/// blanc (réponse de validation, rien n'est écrit), puis application en une
/// révision (`If-Match`). Une clé absente du fichier revient au défaut ; un
/// secret (null) est à ressaisir (liste `skipped`).
pub async fn import(
    State(state): State<AppState>,
    AdminUser(user): AdminUser,
    Query(q): Query<ImportQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> ExtResult<Response> {
    require_owner(&user)?;
    let doc: ImportDocument = parse_body(&body)?;
    if doc.format != EXPORT_FORMAT {
        return Err(ApiError::bad_request("Fichier de réglages non reconnu.").into());
    }
    if doc.schema_version > reg::SCHEMA_VERSION {
        return Err(ApiError::bad_request("Fichier exporté par une version plus récente de Locksy.").into());
    }
    if let Some(sum) = &doc.sha256 {
        if !sum.eq_ignore_ascii_case(&values_digest(&doc.values)) {
            return Err(ApiError::bad_request("Fichier de réglages modifié ou incomplet : empreinte invalide.").into());
        }
    }
    let loaded = state.settings.loaded(&state).await?;
    let wanted = |k: &str| doc.keys.as_ref().is_none_or(|keys| keys.iter().any(|x| x == k));
    let mut changes = Changes::default();
    let mut skipped = Vec::new();
    for (k, v) in &doc.values {
        if !wanted(k) {
            continue;
        }
        match reg::def(k) {
            Some(d) if d.is_secret() || v.is_null() => skipped.push(k.clone()),
            Some(d) if !restorable(d, &loaded.eff) => {}
            Some(_) => match serde_json::from_value::<StoredValue>(v.clone()) {
                Ok(sv) => {
                    changes.0.insert(k.clone(), Change::Set(sv));
                }
                Err(_) => return Err(ApiError::bad_request(format!("Valeur illisible pour « {k} ».")).into()),
            },
            // Clé inconnue : refusée par la validation (`unknown_key`).
            None => {
                changes.0.insert(k.clone(), Change::Set(StoredValue::plain(v.clone())));
            }
        }
    }
    for d in REGISTRY.iter().filter(|d| restorable(d, &loaded.eff) && wanted(d.key) && !doc.values.contains_key(d.key)) {
        changes.0.insert(d.key.into(), Change::Reset);
    }
    let mut extra = Map::new();
    extra.insert("skipped".into(), json!(skipped));
    if q.dry_run.unwrap_or(true) {
        let ctx = context(&state, &user, &loaded).await?;
        let result = reg::validate(&loaded.eff, &changes, &ctx);
        return Ok(validate_response(&state, &loaded, result, extra).await?);
    }
    let op = Op { source: "import", action: Some("settings.imported") };
    write_flow(&state, &user, &headers, changes, doc.reason, op, extra).await
}

/// `GET /admin/config/effective` (propriétaire) : configuration de
/// l'hébergeur et sa source, secrets masqués, et les plafonds de requêtes
/// par adresse IP effectivement appliqués.
pub async fn config_effective(State(state): State<AppState>, AdminUser(user): AdminUser) -> ApiResult<Json<Value>> {
    require_owner(&user)?;
    let vars: Vec<Value> = state
        .host
        .vars
        .iter()
        .map(|v| json!({ "name": v.name, "value": v.value, "source": v.source, "secret": v.secret }))
        .collect();
    let r = &state.host.rate;
    let rate_limits = json!({
        "factor": r.factor,
        "login_ip": r.login_ip,
        "prelogin_ip": r.prelogin_ip,
        "register_ip": r.register_ip,
        "recover_ip": r.recover_ip,
        "share_open_ip": r.share_open_ip,
        "invite_ip": r.invite_ip,
    });
    Ok(Json(json!({ "vars": vars, "rate_limits": rate_limits })))
}

/// Journalise au démarrage chaque réglage fixé par l'hébergeur
/// (`settings.host_override`) et aligne les miroirs sur ces valeurs.
pub(crate) async fn record_host_overrides(state: &AppState) -> ApiResult<()> {
    let host = state.host.caps.clone();
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let meta = ClientMeta { ip: String::new(), user_agent: "locksy-server".into() };
            for (key, (_, var)) in &host.locked {
                audit(&tx, None, "", "settings.host_override", key, &meta, &format!("fixé par {var}"))?;
            }
            write_mirrors(&tx, &load_effective(&tx, &host)?.0)?;
            db::mark_settings_changed();
            tx.commit()?;
            Ok(())
        })
        .await
}
