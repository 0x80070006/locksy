//! Provisionnement SCIM 2.0 (RFC 7643/7644) pour Entra ID, Okta, OneLogin…
//!
//! L'annuaire pousse les comptes : création (compte en attente, que la
//! personne active à sa première connexion SSO en choisissant son mot de
//! passe maître), mise à jour, désactivation (accès coupé immédiatement sur
//! tous les appareils) et suppression, qui suit la politique de
//! désinscription (`directory.deprovision` : désactivation seule, ou
//! désactivation puis suppression après `directory.delete_after_days`).
//! Seuls les domaines autorisés (`access.allowed_email_domains`) sont
//! acceptés, et le dernier propriétaire n'est jamais désactivé.
//!
//! Le jeton expire après `scim.token_ttl_days` (0 : jamais) ; le régénérer
//! exige une confirmation d'identité de l'administrateur.
//!
//! Les groupes ne sont pas pris en charge : donner accès à un coffre exige de
//! sceller sa clé pour chaque membre, ce que seul un client peut faire.

use crate::db;
use crate::error::{ApiError, ApiResult};
use crate::identity_admin::{self, Departure, Deprovision};
use crate::security::{self, normalize_email, sha256_hex};
use crate::state::{audit, audit_user, AdminUser, AppState, ClientMeta};
use axum::async_trait;
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use locksy_core::api::{roles, DirectoryEntry, ScimStatus, ScimTokenCreated};
use locksy_core::crypto::{new_uuid, random_token};
use locksy_core::now_unix;
use locksy_core::settings::Effective;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use subtle::ConstantTimeEq;

const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const SETTINGS_KEY: &str = "scim";
const DAY: i64 = 86_400;
/// Créations de jeton par administrateur et par heure (#56).
const TOKEN_MAX_PER_HOUR: u32 = 5;
/// Précision de la date de dernière utilisation du jeton : au plus une
/// écriture par minute, quel que soit le débit de l'annuaire.
const LAST_USED_STEP: i64 = 60;

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct ScimSettings {
    token_hash: String,
    created_at: i64,
    /// Dernière requête authentifiée par ce jeton (0 : jamais).
    last_used_at: i64,
}

/// État du jeton SCIM, sans le jeton.
pub(crate) struct TokenInfo {
    pub created_at: i64,
    /// Expiration selon `scim.token_ttl_days` (`None` : sans expiration).
    pub expires_at: Option<i64>,
    pub last_used_at: Option<i64>,
}

/// Expiration d'un jeton créé à `created_at` (`ttl_days` = 0 : jamais).
/// Calculée avec la durée en vigueur : raccourcir la durée s'applique aussi
/// au jeton déjà émis.
fn expiry(created_at: i64, ttl_days: i64) -> Option<i64> {
    (ttl_days > 0).then(|| created_at + ttl_days * DAY)
}

/// Jeton en place (`None` s'il n'y en a pas).
pub(crate) fn token_info(c: &Connection, ttl_days: i64) -> ApiResult<Option<TokenInfo>> {
    let s: ScimSettings = db::load_json(c, SETTINGS_KEY)?;
    Ok((!s.token_hash.is_empty()).then(|| TokenInfo {
        created_at: s.created_at,
        expires_at: expiry(s.created_at, ttl_days),
        last_used_at: (s.last_used_at > 0).then_some(s.last_used_at),
    }))
}

/// Adresse de base SCIM à déclarer dans l'annuaire, dérivée de l'adresse
/// publique de Locksy (`instance.public_url`, ou origine de la requête).
pub(crate) fn base_url(public: &str) -> String {
    format!("{}/scim/v2", public.trim_end_matches('/'))
}

// ------------------------------------------------------------ Réponses SCIM

pub struct Scim(StatusCode, Value);

impl IntoResponse for Scim {
    fn into_response(self) -> Response {
        (self.0, [(header::CONTENT_TYPE, "application/scim+json")], self.1.to_string()).into_response()
    }
}

#[derive(Debug)]
pub struct ScimError(StatusCode, Option<&'static str>, String);

impl IntoResponse for ScimError {
    fn into_response(self) -> Response {
        let mut body = json!({ "schemas": [ERROR_SCHEMA], "status": self.0.as_u16().to_string(), "detail": self.2 });
        if let Some(t) = self.1 {
            body["scimType"] = json!(t);
        }
        Scim(self.0, body).into_response()
    }
}

impl From<ApiError> for ScimError {
    fn from(e: ApiError) -> Self {
        ScimError(e.status, None, e.message)
    }
}

impl From<rusqlite::Error> for ScimError {
    fn from(e: rusqlite::Error) -> Self {
        ApiError::from(e).into()
    }
}

type ScimResult<T> = Result<T, ScimError>;

fn bad(detail: impl Into<String>) -> ScimError {
    ScimError(StatusCode::BAD_REQUEST, Some("invalidValue"), detail.into())
}

fn not_found() -> ScimError {
    ScimError(StatusCode::NOT_FOUND, None, "Ressource introuvable.".into())
}

// ------------------------------------------------------------ Authentification du client SCIM

/// Client SCIM authentifié, avec ce dont les points d'accès ont besoin :
/// réglages effectifs et adresse de base des ressources.
pub struct ScimClient {
    meta: ClientMeta,
    eff: Arc<Effective>,
    base: String,
}

#[async_trait]
impl FromRequestParts<AppState> for ScimClient {
    type Rejection = ScimError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ScimResult<Self> {
        let meta = ClientMeta::from_request_parts(parts, state).await?;
        let unauthorized = |detail: &str| ScimError(StatusCode::UNAUTHORIZED, None, detail.into());
        state.limiter.check(&format!("scim:{}", meta.rate_key())).map_err(ScimError::from)?;
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(crate::state::bearer_token)
            .unwrap_or_default()
            .to_string();
        let settings: ScimSettings = state.db.read(|c| db::load_json(c, SETTINGS_KEY)).await?;
        let ok = !settings.token_hash.is_empty()
            && !token.is_empty()
            && bool::from(sha256_hex(&token).as_bytes().ct_eq(settings.token_hash.as_bytes()));
        if !ok {
            state.limiter.fail(&format!("scim:{}", meta.rate_key()), 10);
            return Err(unauthorized("Jeton SCIM invalide."));
        }
        let eff = state.effective().await?;
        let now = now_unix();
        if expiry(settings.created_at, eff.int("scim.token_ttl_days")).is_some_and(|at| at <= now) {
            return Err(unauthorized("Jeton SCIM expiré : générez-en un nouveau dans Locksy."));
        }
        if now - settings.last_used_at >= LAST_USED_STEP {
            // Écriture ciblée : un jeton régénéré entre-temps n'est pas touché.
            let hash = settings.token_hash.clone();
            state
                .db
                .call(move |c| {
                    c.execute(
                        "UPDATE settings SET value = json_set(value, '$.last_used_at', ?1)
                         WHERE key = ?2 AND json_extract(value, '$.token_hash') = ?3",
                        params![now, SETTINGS_KEY, hash],
                    )?;
                    Ok(())
                })
                .await?;
        }
        let base = base_url(&crate::sso::public_base(state, &eff, &parts.headers));
        Ok(ScimClient { meta, eff, base })
    }
}

// ------------------------------------------------------------ Représentation

struct DirUser {
    id: String,
    external_id: Option<String>,
    email: String,
    display_name: String,
    active: bool,
    user_id: Option<String>,
    created_at: i64,
    updated_at: i64,
}

const DIR_COLUMNS: &str = "id, external_id, email, display_name, active, user_id, created_at, updated_at";

fn dir_row(r: &rusqlite::Row) -> rusqlite::Result<DirUser> {
    Ok(DirUser {
        id: r.get(0)?,
        external_id: r.get(1)?,
        email: r.get(2)?,
        display_name: r.get(3)?,
        active: r.get(4)?,
        user_id: r.get(5)?,
        created_at: r.get(6)?,
        updated_at: r.get(7)?,
    })
}

fn iso(ts: i64) -> String {
    crate::admin::format_utc(ts).replacen(' ', "T", 1) + "Z"
}

fn to_scim(u: &DirUser, base: &str) -> Value {
    json!({
        "schemas": [USER_SCHEMA],
        "id": u.id,
        "externalId": u.external_id,
        "userName": u.email,
        "displayName": u.display_name,
        "name": { "formatted": u.display_name },
        "emails": [{ "value": u.email, "type": "work", "primary": true }],
        "active": u.active,
        "meta": {
            "resourceType": "User",
            "created": iso(u.created_at),
            "lastModified": iso(u.updated_at),
            "location": format!("{base}/Users/{}", u.id),
        }
    })
}

fn get_dir(c: &Connection, id: &str) -> ScimResult<DirUser> {
    c.query_row(&format!("SELECT {DIR_COLUMNS} FROM directory_users WHERE id = ?1"), [id], dir_row)
        .optional()?
        .ok_or_else(not_found)
}

/// Valeur booléenne telle qu'envoyée par Entra ID (« False ») ou par la norme (false).
fn as_bool(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::String(s) => match s.to_ascii_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// Champs utiles d'une ressource User reçue.
#[derive(Default)]
struct Incoming {
    email: Option<String>,
    external_id: Option<Option<String>>,
    display_name: Option<String>,
    active: Option<bool>,
}

fn display_from(v: &Value) -> Option<String> {
    v.get("displayName").and_then(Value::as_str).map(String::from).or_else(|| {
        let name = v.get("name")?;
        name.get("formatted").and_then(Value::as_str).map(String::from).or_else(|| {
            let g = name.get("givenName").and_then(Value::as_str).unwrap_or_default();
            let f = name.get("familyName").and_then(Value::as_str).unwrap_or_default();
            let full = format!("{g} {f}").trim().to_string();
            (!full.is_empty()).then_some(full)
        })
    })
}

fn email_from(v: &Value) -> Option<String> {
    let user_name = v.get("userName").and_then(Value::as_str).filter(|s| s.contains('@'));
    let primary = v.get("emails").and_then(Value::as_array).and_then(|list| {
        list.iter()
            .find(|e| e.get("primary").and_then(as_bool).unwrap_or(false))
            .or_else(|| list.first())
            .and_then(|e| e.get("value").and_then(Value::as_str))
    });
    user_name.or(primary).map(String::from)
}

fn parse_resource(v: &Value) -> Incoming {
    Incoming {
        email: email_from(v),
        external_id: v.get("externalId").map(|e| e.as_str().map(String::from)),
        display_name: display_from(v),
        active: v.get("active").and_then(as_bool),
    }
}

// ------------------------------------------------------------ Application des changements

/// Adresse hors des domaines autorisés par l'organisation.
fn domain_refused() -> ScimError {
    ScimError(
        StatusCode::FORBIDDEN,
        None,
        "Cette adresse e-mail n'appartient pas à un domaine autorisé par l'organisation (Locksy).".into(),
    )
}

/// Refus du dernier propriétaire actif, en erreur SCIM (409).
fn scim_refusal(e: ApiError) -> ScimError {
    if e.code == "last_owner" {
        ScimError(StatusCode::CONFLICT, None, format!("Refusé : {} Le compte reste actif et provisionné.", e.message))
    } else {
        e.into()
    }
}

fn apply(c: &Connection, client: &ScimClient, u: &mut DirUser, inc: Incoming) -> ScimResult<()> {
    let now = now_unix();
    if let Some(email) = inc.email {
        let email = normalize_email(&email).map_err(|e| bad(e.message))?;
        if !email.eq_ignore_ascii_case(&u.email) {
            if !security::email_domain_allowed(&client.eff, &email) {
                return Err(domain_refused());
            }
            let taken: bool = c.query_row(
                "SELECT COUNT(*) FROM directory_users WHERE email = ?1 AND id <> ?2",
                params![email, u.id],
                |r| r.get::<_, i64>(0),
            )? > 0;
            if taken {
                return Err(ScimError(StatusCode::CONFLICT, Some("uniqueness"), "Adresse déjà utilisée.".into()));
            }
            if let Some(uid) = &u.user_id {
                c.execute("UPDATE users SET email = ?1, updated_at = ?2 WHERE id = ?3", params![email, now, uid])
                    .map_err(|_| ScimError(StatusCode::CONFLICT, Some("uniqueness"), "Adresse déjà utilisée par un autre compte.".into()))?;
            }
            u.email = email;
        }
    }
    if let Some(ext) = inc.external_id {
        u.external_id = ext;
    }
    if let Some(name) = inc.display_name {
        let name: String = name.trim().chars().filter(|c| !c.is_control()).take(100).collect();
        if !name.is_empty() {
            if let Some(uid) = &u.user_id {
                c.execute("UPDATE users SET name = ?1, updated_at = ?2 WHERE id = ?3", params![name, now, uid])?;
            }
            u.display_name = name;
        }
    }
    if let Some(active) = inc.active {
        if active != u.active {
            if let Some(uid) = &u.user_id {
                if active {
                    identity_admin::reactivate(c, uid)?;
                } else {
                    let role: String = c.query_row("SELECT role FROM users WHERE id = ?1", [uid], |r| r.get(0))?;
                    identity_admin::directory_disable(c, uid, &role, "scim").map_err(scim_refusal)?;
                }
            }
            audit(c, u.user_id.as_deref(), &u.email, if active { "scim.user_enabled" } else { "scim.user_disabled" }, &u.email, &client.meta, "")?;
            u.active = active;
        }
    }
    u.updated_at = now;
    c.execute(
        "UPDATE directory_users SET external_id = ?1, email = ?2, display_name = ?3, active = ?4, updated_at = ?5 WHERE id = ?6",
        params![u.external_id, u.email, u.display_name, u.active, u.updated_at, u.id],
    )?;
    Ok(())
}

// ------------------------------------------------------------ Points d'accès Users

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    filter: Option<String>,
    #[serde(default, rename = "startIndex")]
    start_index: Option<i64>,
    #[serde(default)]
    count: Option<i64>,
}

/// Filtres pris en charge : `userName eq "x"`, `externalId eq "x"`, `emails.value eq "x"`.
fn parse_filter(f: &str) -> ScimResult<(String, String)> {
    let mut parts = f.trim().splitn(3, ' ');
    let attr = parts.next().unwrap_or_default().to_ascii_lowercase();
    let op = parts.next().unwrap_or_default().to_ascii_lowercase();
    let value = parts.next().unwrap_or_default().trim().trim_matches('"').replace("\\\"", "\"");
    let column = match attr.as_str() {
        "username" | "emails.value" | "emails[type eq \"work\"].value" => "email",
        "externalid" => "external_id",
        "id" => "id",
        _ => return Err(ScimError(StatusCode::BAD_REQUEST, Some("invalidFilter"), format!("Filtre non pris en charge : {f}"))),
    };
    if op != "eq" {
        return Err(ScimError(StatusCode::BAD_REQUEST, Some("invalidFilter"), "Seul l'opérateur eq est pris en charge.".into()));
    }
    Ok((column.to_string(), value))
}

pub async fn list_users(State(state): State<AppState>, client: ScimClient, Query(q): Query<ListQuery>) -> ScimResult<Scim> {
    let filter = q.filter.as_deref().filter(|f| !f.trim().is_empty()).map(parse_filter).transpose()?;
    let start = q.start_index.unwrap_or(1).max(1);
    let count = q.count.unwrap_or(100).clamp(0, 500);
    let body = state
        .db
        .read(move |c| {
            let base = client.base;
            let (where_sql, arg) = match &filter {
                Some((col, v)) => (format!("WHERE {col} = ?1 COLLATE NOCASE"), v.clone()),
                None => ("WHERE ?1 = ?1".to_string(), String::new()),
            };
            let total: i64 = c.query_row(&format!("SELECT COUNT(*) FROM directory_users {where_sql}"), [&arg], |r| r.get(0))?;
            let mut st = c.prepare(&format!(
                "SELECT {DIR_COLUMNS} FROM directory_users {where_sql} ORDER BY created_at LIMIT ?2 OFFSET ?3"
            ))?;
            let rows = st.query_map(params![arg, count, start - 1], dir_row)?.collect::<Result<Vec<_>, _>>()?;
            let resources: Vec<Value> = rows.iter().map(|u| to_scim(u, &base)).collect();
            Ok(json!({
                "schemas": [LIST_SCHEMA],
                "totalResults": total,
                "startIndex": start,
                "itemsPerPage": resources.len(),
                "Resources": resources,
            }))
        })
        .await?;
    Ok(Scim(StatusCode::OK, body))
}

pub async fn get_user(State(state): State<AppState>, client: ScimClient, Path(id): Path<String>) -> ScimResult<Scim> {
    let u = state.db.read(move |c| Ok(get_dir(c, &id))).await??;
    Ok(Scim(StatusCode::OK, to_scim(&u, &client.base)))
}

pub async fn create_user(State(state): State<AppState>, client: ScimClient, Json(v): Json<Value>) -> ScimResult<Scim> {
    let inc = parse_resource(&v);
    let email = normalize_email(&inc.email.clone().ok_or_else(|| bad("userName ou emails doit contenir une adresse e-mail."))?)
        .map_err(|e| bad(e.message))?;
    let display = inc.display_name.clone().unwrap_or_else(|| email.split('@').next().unwrap_or_default().to_string());
    let result = state.db.call(move |c| in_transaction(c, |tx| create_dir_user(tx, &client, &email, &display, &inc))).await?;
    Ok(Scim(StatusCode::CREATED, result?))
}

/// Exécute `f` dans une transaction validée seulement si le résultat SCIM
/// est un succès ; sinon tout est annulé (lignes et audit). Le résultat SCIM
/// est imbriqué dans l'`ApiResult` de `Db::call`, qui ne porte que les
/// erreurs de la base elle-même.
fn in_transaction<T>(
    c: &mut Connection,
    f: impl FnOnce(&Connection) -> ScimResult<T>,
) -> ApiResult<ScimResult<T>> {
    let tx = c.transaction()?;
    let r = f(&tx);
    if r.is_ok() {
        tx.commit()?;
    }
    Ok(r)
}

/// Crée la personne poussée par l'annuaire. À appeler dans une transaction :
/// une désactivation initiale qui échoue annule aussi la création.
fn create_dir_user(c: &Connection, client: &ScimClient, email: &str, display: &str, inc: &Incoming) -> ScimResult<Value> {
    if !security::email_domain_allowed(&client.eff, email) {
        return Err(domain_refused());
    }
    let exists: bool = c.query_row("SELECT COUNT(*) FROM directory_users WHERE email = ?1", [email], |r| r.get::<_, i64>(0))? > 0;
    if exists {
        return Err(ScimError(StatusCode::CONFLICT, Some("uniqueness"), "Cette personne est déjà provisionnée.".into()));
    }
    // Un compte Locksy existant (créé sur invitation) est rattaché.
    let user_id: Option<String> = c.query_row("SELECT id FROM users WHERE email = ?1", [email], |r| r.get(0)).optional()?;
    let now = now_unix();
    let mut u = DirUser {
        id: new_uuid(),
        external_id: inc.external_id.clone().flatten(),
        email: email.to_string(),
        display_name: display.chars().take(100).collect(),
        active: true,
        user_id,
        created_at: now,
        updated_at: now,
    };
    c.execute(
        &format!("INSERT INTO directory_users ({DIR_COLUMNS}) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?6)"),
        params![u.id, u.external_id, u.email, u.display_name, u.user_id, now],
    )?;
    audit(c, u.user_id.as_deref(), email, "scim.user_created", email, &client.meta, if u.user_id.is_some() { "rattaché à un compte existant" } else { "en attente de première connexion" })?;
    if inc.active == Some(false) {
        apply(c, client, &mut u, Incoming { active: Some(false), ..Default::default() })?;
    } else if let Some(uid) = &u.user_id {
        // Retour d'une personne partie : son compte désactivé par l'annuaire
        // est réactivé et sa suppression programmée annulée.
        identity_admin::reactivate(c, uid)?;
    }
    Ok(to_scim(&u, &client.base))
}

/// Remplacement ou modification d'une personne : `apply` fait plusieurs
/// écritures et un audit, validés ensemble.
fn update_dir_user(c: &Connection, client: &ScimClient, id: &str, inc: Incoming) -> ScimResult<Value> {
    let mut u = get_dir(c, id)?;
    apply(c, client, &mut u, inc)?;
    Ok(to_scim(&u, &client.base))
}

pub async fn replace_user(State(state): State<AppState>, client: ScimClient, Path(id): Path<String>, Json(v): Json<Value>) -> ScimResult<Scim> {
    let inc = parse_resource(&v);
    let result = state.db.call(move |c| in_transaction(c, |tx| update_dir_user(tx, &client, &id, inc))).await?;
    Ok(Scim(StatusCode::OK, result?))
}

/// PATCH : opérations `replace`/`add` sur active, displayName, userName,
/// externalId, name.*, emails ; avec ou sans `path`.
pub async fn patch_user(State(state): State<AppState>, client: ScimClient, Path(id): Path<String>, Json(v): Json<Value>) -> ScimResult<Scim> {
    let ops = v.get("Operations").or_else(|| v.get("operations")).and_then(Value::as_array).cloned().ok_or_else(|| bad("Operations manquant."))?;
    let mut inc = Incoming::default();
    for op in &ops {
        let kind = op.get("op").and_then(Value::as_str).unwrap_or_default().to_ascii_lowercase();
        if kind == "remove" {
            if op.get("path").and_then(Value::as_str).is_some_and(|p| p.eq_ignore_ascii_case("externalId")) {
                inc.external_id = Some(None);
            }
            continue;
        }
        if kind != "replace" && kind != "add" {
            return Err(bad(format!("Opération inconnue : {kind}")));
        }
        let value = op.get("value").cloned().unwrap_or(Value::Null);
        match op.get("path").and_then(Value::as_str).map(str::to_ascii_lowercase) {
            None => {
                let p = parse_resource(&value);
                inc.email = p.email.or(inc.email);
                inc.external_id = p.external_id.or(inc.external_id);
                inc.display_name = p.display_name.or(inc.display_name);
                inc.active = p.active.or(inc.active);
            }
            Some(path) => match path.as_str() {
                "active" => inc.active = as_bool(&value),
                "displayname" | "name.formatted" => inc.display_name = value.as_str().map(String::from),
                "username" => inc.email = value.as_str().map(String::from),
                "externalid" => inc.external_id = Some(value.as_str().map(String::from)),
                p if p.starts_with("emails") => {
                    inc.email = value.as_str().map(String::from).or_else(|| email_from(&json!({ "emails": value })));
                }
                _ => {} // attributs non gérés (téléphone, poste…) : ignorés sans erreur
            },
        }
    }
    let result = state.db.call(move |c| in_transaction(c, |tx| update_dir_user(tx, &client, &id, inc))).await?;
    Ok(Scim(StatusCode::OK, result?))
}

pub async fn delete_user(State(state): State<AppState>, client: ScimClient, Path(id): Path<String>) -> ScimResult<StatusCode> {
    let policy = Deprovision::from_eff(&client.eff);
    let result: ScimResult<()> = state.db.call(move |c| Ok(delete_directory_user(c, &id, &client.meta, policy))).await?;
    result?;
    Ok(StatusCode::NO_CONTENT)
}

/// Suppression d'une personne par l'annuaire : elle disparaît de l'annuaire
/// SCIM (404 ensuite) et son compte Locksy suit la politique de
/// désinscription (désactivation seule, ou désactivation puis suppression
/// programmée ; immédiate avec un délai de 0 jour). Un compte propriétaire ou
/// administrateur n'est jamais supprimé par SCIM (un jeton compromis ou une
/// erreur de l'annuaire détruirait sinon des coffres) : il est seulement
/// désactivé, et le dernier propriétaire ne l'est jamais (409).
fn delete_directory_user(c: &Connection, id: &str, meta: &ClientMeta, policy: Deprovision) -> ScimResult<()> {
    let u = get_dir(c, id)?;
    // Annulée automatiquement (rollback) si elle n'est pas validée.
    let tx = c.unchecked_transaction()?;
    let mut details = "compte en attente supprimé".to_string();
    if let Some(uid) = &u.user_id {
        let role: Option<String> = tx.query_row("SELECT role FROM users WHERE id = ?1", [uid], |r| r.get(0)).optional()?;
        if let Some(role) = role {
            let departure = identity_admin::depart(&tx, uid, &role, "scim", policy, meta, now_unix()).map_err(scim_refusal)?;
            details = match departure {
                Departure::Disabled if role == roles::OWNER || role == roles::ADMIN => {
                    "compte d'administration désactivé (suppression réservée à un administrateur Locksy)".to_string()
                }
                Departure::Disabled => "compte Locksy désactivé".to_string(),
                Departure::Scheduled(at) => {
                    format!("compte Locksy désactivé, suppression programmée le {}", crate::admin::format_utc(at))
                }
                Departure::Purged => "compte Locksy supprimé".to_string(),
            };
        }
    }
    tx.execute("DELETE FROM directory_users WHERE id = ?1", [&u.id])?;
    audit(&tx, u.user_id.as_deref(), &u.email, "scim.user_deleted", &u.email, meta, &details)?;
    tx.commit()?;
    Ok(())
}

// ------------------------------------------------------------ Groupes et métadonnées

pub async fn list_groups(_c: ScimClient) -> Scim {
    Scim(StatusCode::OK, json!({ "schemas": [LIST_SCHEMA], "totalResults": 0, "startIndex": 1, "itemsPerPage": 0, "Resources": [] }))
}

pub async fn groups_unsupported(_c: ScimClient) -> ScimError {
    ScimError(
        StatusCode::NOT_IMPLEMENTED,
        None,
        "Les groupes ne sont pas pris en charge : l'accès aux coffres se donne depuis Locksy (chiffrement de bout en bout).".into(),
    )
}

pub async fn service_provider_config(_c: ScimClient) -> Scim {
    Scim(
        StatusCode::OK,
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": { "supported": true },
            "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
            "filter": { "supported": true, "maxResults": 500 },
            "changePassword": { "supported": false },
            "sort": { "supported": false },
            "etag": { "supported": false },
            "authenticationSchemes": [{ "type": "oauthbearertoken", "name": "Jeton porteur", "description": "Jeton généré dans Locksy, Administration > Provisionnement" }]
        }),
    )
}

pub async fn resource_types(_c: ScimClient) -> Scim {
    Scim(
        StatusCode::OK,
        json!({ "schemas": [LIST_SCHEMA], "totalResults": 1, "Resources": [{
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "User", "name": "User", "endpoint": "/Users", "schema": USER_SCHEMA
        }]}),
    )
}

pub async fn schemas(_c: ScimClient) -> Scim {
    Scim(
        StatusCode::OK,
        json!({ "schemas": [LIST_SCHEMA], "totalResults": 1, "Resources": [{
            "id": USER_SCHEMA, "name": "User",
            "attributes": [
                { "name": "userName", "type": "string", "required": true, "uniqueness": "server" },
                { "name": "displayName", "type": "string" },
                { "name": "active", "type": "boolean" },
                { "name": "externalId", "type": "string" },
                { "name": "emails", "type": "complex", "multiValued": true }
            ]
        }]}),
    )
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/Users", get(list_users).post(create_user))
        .route("/Users/:id", get(get_user).put(replace_user).patch(patch_user).delete(delete_user))
        .route("/Groups", get(list_groups).post(groups_unsupported))
        .route("/Groups/:id", get(groups_unsupported).put(groups_unsupported).patch(groups_unsupported).delete(groups_unsupported))
        .route("/ServiceProviderConfig", get(service_provider_config))
        .route("/ResourceTypes", get(resource_types))
        .route("/Schemas", get(schemas))
}

// ------------------------------------------------------------ Administration

/// État du jeton SCIM : réponse historique à plat, plus l'expiration et la
/// dernière utilisation.
#[derive(Serialize)]
pub struct ScimStatusOut {
    #[serde(flatten)]
    base: ScimStatus,
    expires_at: Option<i64>,
    last_used_at: Option<i64>,
}

pub async fn status(State(state): State<AppState>, _a: AdminUser, headers: HeaderMap) -> ApiResult<Json<ScimStatusOut>> {
    let eff = state.effective().await?;
    let base = base_url(&crate::sso::public_base(&state, &eff, &headers));
    let ttl = eff.int("scim.token_ttl_days");
    let info = state.db.read(move |c| token_info(c, ttl)).await?;
    Ok(Json(ScimStatusOut {
        base: ScimStatus { enabled: info.is_some(), created_at: info.as_ref().map(|i| i.created_at), base_url: base },
        expires_at: info.as_ref().and_then(|i| i.expires_at),
        last_used_at: info.as_ref().and_then(|i| i.last_used_at),
    }))
}

/// Jeton créé (affiché une seule fois) : réponse historique à plat, plus son
/// expiration.
#[derive(Serialize)]
pub struct ScimTokenOut {
    #[serde(flatten)]
    base: ScimTokenCreated,
    expires_at: Option<i64>,
}

/// Crée le jeton SCIM, ou le régénère (l'ancien cesse aussitôt de
/// fonctionner) : la régénération exige une confirmation d'identité
/// (`scim.token`). Au plus 5 créations par administrateur et par heure.
pub async fn create_token(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    headers: HeaderMap,
) -> ApiResult<Json<ScimTokenOut>> {
    state.limiter.hit(&format!("scim-token:{}", admin.id), TOKEN_MAX_PER_HOUR, 3600)?;
    let eff = state.effective().await?;
    let replaces = state.db.read(|c| Ok(token_info(c, 0)?.is_some())).await?;
    if replaces {
        security::require_step_up(&state, &admin, &headers, "scim.token").await?;
    }
    let token = random_token();
    let hash = sha256_hex(&token);
    let now = now_unix();
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            db::save_json(&tx, SETTINGS_KEY, &ScimSettings { token_hash: hash, created_at: now, last_used_at: 0 })?;
            let details = if replaces { "jeton régénéré, l'ancien est révoqué" } else { "premier jeton" };
            audit_user(&tx, &admin, "admin.scim_token_created", "", details)?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    let base_url = base_url(&crate::sso::public_base(&state, &eff, &headers));
    let expires_at = expiry(now, eff.int("scim.token_ttl_days"));
    Ok(Json(ScimTokenOut { base: ScimTokenCreated { token, base_url }, expires_at }))
}

pub async fn revoke_token(State(state): State<AppState>, AdminUser(admin): AdminUser) -> ApiResult<StatusCode> {
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            db::save_json(&tx, SETTINGS_KEY, &ScimSettings::default())?;
            audit_user(&tx, &admin, "admin.scim_token_revoked", "", "")?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn directory(State(state): State<AppState>, _a: AdminUser) -> ApiResult<Json<Vec<DirectoryEntry>>> {
    Ok(Json(
        state
            .db
            .read(|c| {
                let mut st = c.prepare(&format!("SELECT {DIR_COLUMNS} FROM directory_users ORDER BY display_name COLLATE NOCASE"))?;
                let rows = st
                    .query_map([], dir_row)?
                    .map(|r| {
                        r.map(|u| DirectoryEntry {
                            id: u.id,
                            external_id: u.external_id,
                            email: u.email,
                            display_name: u.display_name,
                            active: u.active,
                            registered: u.user_id.is_some(),
                            updated_at: u.updated_at,
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> ClientMeta {
        ClientMeta { ip: "203.0.113.7".into(), user_agent: "test".into() }
    }

    /// Compte Locksy provisionné par l'annuaire, avec une session ouverte.
    fn provisioned(c: &Connection, n: &str, role: &str) {
        c.execute(
            "INSERT INTO users (id, email, name, role, kdf, auth_hash, wrapped_user_key, recovery_wrapped_user_key,
                                recovery_auth_hash, public_key, wrapped_private_key, created_at, updated_at)
             VALUES (?1, ?2, 'Test', ?3, '{}', '', '', '', '', '', '', 0, 0)",
            params![format!("u-{n}"), format!("{n}@corp.fr"), role],
        )
        .unwrap();
        c.execute(
            "INSERT INTO sessions (id, token_hash, user_id, created_at, last_seen_at, expires_at, ip, device)
             VALUES (?1, ?2, ?3, 0, 0, 9999999999, '', '')",
            params![format!("s-{n}"), format!("h-{n}"), format!("u-{n}")],
        )
        .unwrap();
        c.execute(
            "INSERT INTO directory_users (id, external_id, email, display_name, active, user_id, created_at, updated_at)
             VALUES (?1, NULL, ?2, 'Test', 1, ?3, 0, 0)",
            params![format!("d-{n}"), format!("{n}@corp.fr"), format!("u-{n}")],
        )
        .unwrap();
    }

    fn count(c: &Connection, sql: &str, id: &str) -> i64 {
        c.query_row(sql, [id], |r| r.get(0)).unwrap()
    }

    const DISABLE_ONLY: Deprovision = Deprovision { then_delete: false, delete_after_days: 30 };
    const LATER: Deprovision = Deprovision { then_delete: true, delete_after_days: 30 };
    const NOW: Deprovision = Deprovision { then_delete: true, delete_after_days: 0 };

    #[tokio::test]
    async fn scim_deletion_only_disables_admins() {
        let st = crate::state::test_state().await;
        st.db
            .call(|c| {
                provisioned(c, "patron", roles::OWNER);
                provisioned(c, "adjoint", roles::OWNER);
                provisioned(c, "admin", roles::ADMIN);
                delete_directory_user(c, "d-admin", &meta(), NOW).unwrap();
                assert_eq!(count(c, "SELECT COUNT(*) FROM users WHERE id = ?1", "u-admin"), 1, "compte conservé");
                assert_eq!(count(c, "SELECT disabled FROM users WHERE id = ?1", "u-admin"), 1, "compte désactivé");
                assert_eq!(count(c, "SELECT deprovision_at IS NULL FROM users WHERE id = ?1", "u-admin"), 1, "pas de suppression programmée");
                assert_eq!(count(c, "SELECT COUNT(*) FROM sessions WHERE user_id = ?1", "u-admin"), 0, "sessions coupées");
                assert!(get_dir(c, "d-admin").is_err(), "plus visible par l'annuaire (404)");
                // Un propriétaire qui n'est pas le dernier : désactivé lui aussi, pas supprimé.
                delete_directory_user(c, "d-adjoint", &meta(), NOW).unwrap();
                assert_eq!(count(c, "SELECT disabled FROM users WHERE id = ?1", "u-adjoint"), 1);
                Ok(())
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn scim_deletion_follows_the_deprovision_policy() {
        let st = crate::state::test_state().await;
        st.db
            .call(|c| {
                provisioned(c, "patron", roles::OWNER);
                for n in ["jean", "paul", "anne"] {
                    provisioned(c, n, roles::USER);
                }
                // Désactivation seule.
                delete_directory_user(c, "d-jean", &meta(), DISABLE_ONLY).unwrap();
                assert_eq!(count(c, "SELECT disabled FROM users WHERE id = ?1", "u-jean"), 1);
                assert_eq!(count(c, "SELECT deprovision_at IS NULL FROM users WHERE id = ?1", "u-jean"), 1);
                assert_eq!(count(c, "SELECT COUNT(*) FROM users WHERE disabled_reason = ?1", "scim"), 1);
                // Désactivation puis suppression dans 30 jours.
                let before = now_unix();
                delete_directory_user(c, "d-paul", &meta(), LATER).unwrap();
                let at = count(c, "SELECT deprovision_at FROM users WHERE id = ?1", "u-paul");
                assert!((before + 30 * DAY..=now_unix() + 30 * DAY).contains(&at), "échéance {at}");
                assert_eq!(count(c, "SELECT COUNT(*) FROM audit WHERE action = ?1", "directory.deprovision_scheduled"), 1);
                // Délai de 0 jour : suppression immédiate.
                delete_directory_user(c, "d-anne", &meta(), NOW).unwrap();
                assert_eq!(count(c, "SELECT COUNT(*) FROM users WHERE id = ?1", "u-anne"), 0);
                assert_eq!(count(c, "SELECT COUNT(*) FROM audit WHERE action = ?1", "directory.user_purged"), 1);
                for d in ["d-jean", "d-paul", "d-anne"] {
                    assert_eq!(count(c, "SELECT COUNT(*) FROM directory_users WHERE id = ?1", d), 0);
                }
                Ok(())
            })
            .await
            .unwrap();
    }

    #[test]
    fn token_expiry_follows_the_ttl() {
        assert_eq!(expiry(1_000, 0), None, "0 : sans expiration");
        assert_eq!(expiry(1_000, 30), Some(1_000 + 30 * DAY));
    }

    #[tokio::test]
    async fn scim_cannot_disable_the_last_owner() {
        let st = crate::state::test_state().await;
        st.db
            .call(|c| {
                provisioned(c, "patron", roles::OWNER);
                let e = delete_directory_user(c, "d-patron", &meta(), LATER).unwrap_err();
                assert_eq!(e.0, StatusCode::CONFLICT);
                assert!(e.2.contains("propriétaire actif"), "{}", e.2);
                assert_eq!(count(c, "SELECT disabled FROM users WHERE id = ?1", "u-patron"), 0, "rien n'est modifié");
                assert_eq!(count(c, "SELECT COUNT(*) FROM sessions WHERE user_id = ?1", "u-patron"), 1);
                assert_eq!(count(c, "SELECT COUNT(*) FROM directory_users WHERE id = ?1", "d-patron"), 1, "ligne d'annuaire conservée");
                Ok(())
            })
            .await
            .unwrap();
    }

    async fn client(st: &AppState) -> ScimClient {
        ScimClient { meta: meta(), eff: st.effective().await.unwrap(), base: "https://coffre.corp.fr/scim/v2".into() }
    }

    fn scim_err(r: ScimResult<Scim>) -> ScimError {
        match r {
            Err(e) => e,
            Ok(s) => panic!("succès inattendu : {}", s.1),
        }
    }

    #[tokio::test]
    async fn creation_inactive_cree_puis_desactive() {
        let st = crate::state::test_state().await;
        st.db
            .call(|c| {
                provisioned(c, "patron", roles::OWNER);
                // Compte Locksy existant, pas encore dans l'annuaire.
                provisioned(c, "jean", roles::USER);
                c.execute("DELETE FROM directory_users WHERE id = 'd-jean'", [])?;
                Ok(())
            })
            .await
            .unwrap();
        let r = create_user(State(st.clone()), client(&st).await, Json(json!({ "userName": "jean@corp.fr", "active": false })))
            .await
            .expect("création");
        assert_eq!(r.0, StatusCode::CREATED);
        assert_eq!(r.1["active"], json!(false));
        // Personne sans compte : simplement en attente, inactive.
        let r = create_user(State(st.clone()), client(&st).await, Json(json!({ "userName": "paul@corp.fr", "active": "False" })))
            .await
            .expect("création");
        assert_eq!(r.1["active"], json!(false));
        st.db
            .call(|c| {
                assert_eq!(count(c, "SELECT active FROM directory_users WHERE email = ?1", "jean@corp.fr"), 0);
                assert_eq!(count(c, "SELECT active FROM directory_users WHERE email = ?1", "paul@corp.fr"), 0);
                assert_eq!(count(c, "SELECT disabled FROM users WHERE id = ?1", "u-jean"), 1, "compte désactivé");
                assert_eq!(count(c, "SELECT COUNT(*) FROM sessions WHERE user_id = ?1", "u-jean"), 0, "sessions coupées");
                assert_eq!(count(c, "SELECT COUNT(*) FROM audit WHERE action = ?1", "scim.user_created"), 2);
                assert_eq!(count(c, "SELECT COUNT(*) FROM audit WHERE action = ?1", "scim.user_disabled"), 2);
                Ok(())
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn creation_annulee_si_la_desactivation_echoue() {
        let st = crate::state::test_state().await;
        st.db
            .call(|c| {
                // Seul propriétaire, pas encore dans l'annuaire.
                provisioned(c, "patron", roles::OWNER);
                c.execute("DELETE FROM directory_users", [])?;
                Ok(())
            })
            .await
            .unwrap();
        let e = scim_err(create_user(State(st.clone()), client(&st).await, Json(json!({ "userName": "patron@corp.fr", "active": false }))).await);
        assert_eq!(e.0, StatusCode::CONFLICT);
        assert!(e.2.contains("propriétaire actif"), "{}", e.2);
        st.db
            .call(|c| {
                assert_eq!(count(c, "SELECT COUNT(*) FROM directory_users WHERE email = ?1", "patron@corp.fr"), 0, "aucune ligne créée");
                assert_eq!(count(c, "SELECT COUNT(*) FROM audit WHERE action <> ?1", ""), 0, "aucun audit");
                assert_eq!(count(c, "SELECT disabled FROM users WHERE id = ?1", "u-patron"), 0);
                Ok(())
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn modification_annulee_en_bloc() {
        let st = crate::state::test_state().await;
        st.db
            .call(|c| {
                provisioned(c, "patron", roles::OWNER);
                provisioned(c, "jean", roles::USER);
                Ok(())
            })
            .await
            .unwrap();
        // L'adresse est déjà prise par une autre personne de l'annuaire.
        let patch = json!({ "Operations": [{ "op": "replace", "path": "userName", "value": "jean@corp.fr" }, { "op": "replace", "path": "displayName", "value": "Autre" }] });
        let e = scim_err(patch_user(State(st.clone()), client(&st).await, Path("d-patron".into()), Json(patch)).await);
        assert_eq!(e.0, StatusCode::CONFLICT);
        // Nouvelle adresse libre, mais désactivation du dernier propriétaire
        // refusée : la modification d'adresse déjà faite est annulée.
        let patch = json!({ "Operations": [{ "op": "replace", "value": { "userName": "chef@corp.fr", "displayName": "Chef", "active": false } }] });
        let e = scim_err(patch_user(State(st.clone()), client(&st).await, Path("d-patron".into()), Json(patch)).await);
        assert_eq!(e.0, StatusCode::CONFLICT);
        let e = scim_err(
            replace_user(State(st.clone()), client(&st).await, Path("d-patron".into()), Json(json!({ "userName": "chef@corp.fr", "active": false }))).await,
        );
        assert_eq!(e.0, StatusCode::CONFLICT);
        st.db
            .call(|c| {
                assert_eq!(count(c, "SELECT COUNT(*) FROM users WHERE email = ?1", "patron@corp.fr"), 1, "adresse du compte intacte");
                assert_eq!(count(c, "SELECT COUNT(*) FROM users WHERE name = ?1", "Chef"), 0);
                assert_eq!(count(c, "SELECT COUNT(*) FROM directory_users WHERE email = ?1", "patron@corp.fr"), 1);
                assert_eq!(count(c, "SELECT updated_at FROM directory_users WHERE id = ?1", "d-patron"), 0, "ligne d'annuaire intacte");
                assert_eq!(count(c, "SELECT COUNT(*) FROM audit WHERE action <> ?1", ""), 0);
                Ok(())
            })
            .await
            .unwrap();
        // Une modification valide passe, d'un bloc.
        let patch = json!({ "Operations": [{ "op": "replace", "path": "active", "value": false }] });
        let r = patch_user(State(st.clone()), client(&st).await, Path("d-jean".into()), Json(patch)).await.expect("modification");
        assert_eq!(r.1["active"], json!(false));
        st.db
            .call(|c| {
                assert_eq!(count(c, "SELECT disabled FROM users WHERE id = ?1", "u-jean"), 1);
                assert_eq!(count(c, "SELECT COUNT(*) FROM audit WHERE action = ?1", "scim.user_disabled"), 1);
                Ok(())
            })
            .await
            .unwrap();
    }

    #[test]
    fn entra_style_booleans() {
        assert_eq!(as_bool(&json!("False")), Some(false));
        assert_eq!(as_bool(&json!("True")), Some(true));
        assert_eq!(as_bool(&json!(false)), Some(false));
        assert_eq!(as_bool(&json!(1)), None);
    }

    #[test]
    fn filters() {
        assert_eq!(parse_filter("userName eq \"Jean@Exemple.fr\"").unwrap(), ("email".into(), "Jean@Exemple.fr".into()));
        assert_eq!(parse_filter("externalId eq \"abc\"").unwrap().0, "external_id");
        assert!(parse_filter("userName sw \"j\"").is_err());
        assert!(parse_filter("title eq \"x\"").is_err());
    }

    #[test]
    fn resource_parsing() {
        let v = json!({
            "userName": "jean.dupont@exemple.fr",
            "name": { "givenName": "Jean", "familyName": "Dupont" },
            "externalId": "00aa", "active": "True"
        });
        let inc = parse_resource(&v);
        assert_eq!(inc.email.as_deref(), Some("jean.dupont@exemple.fr"));
        assert_eq!(inc.display_name.as_deref(), Some("Jean Dupont"));
        assert_eq!(inc.external_id, Some(Some("00aa".into())));
        assert_eq!(inc.active, Some(true));
        let v = json!({ "userName": "jdupont", "emails": [{ "value": "autre@x.fr" }, { "value": "jean@x.fr", "primary": true }] });
        assert_eq!(parse_resource(&v).email.as_deref(), Some("jean@x.fr"));
    }
}
