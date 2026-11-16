//! Provisionnement SCIM 2.0 (RFC 7643/7644) pour Entra ID, Okta, OneLogin…
//!
//! L'annuaire pousse les comptes : création (compte en attente, que la
//! personne active à sa première connexion SSO en choisissant son mot de
//! passe maître), mise à jour, désactivation (accès coupé immédiatement sur
//! tous les appareils) et suppression.
//!
//! Les groupes ne sont pas pris en charge : donner accès à un coffre exige de
//! sceller sa clé pour chaque membre, ce que seul un client peut faire.

use crate::admin::{remove_user, set_disabled};
use crate::db;
use crate::error::{ApiError, ApiResult};
use crate::security::{normalize_email, sha256_hex};
use crate::state::{audit, audit_user, AdminUser, AppState, ClientMeta};
use axum::async_trait;
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use locksy_core::api::{DirectoryEntry, ScimStatus, ScimTokenCreated};
use locksy_core::crypto::{new_uuid, random_token};
use locksy_core::now_unix;

const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const SETTINGS_KEY: &str = "scim";

#[derive(Serialize, Deserialize, Default)]
struct ScimSettings {
    token_hash: String,
    created_at: i64,
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

pub struct ScimClient {
    meta: ClientMeta,
}

#[async_trait]
impl FromRequestParts<AppState> for ScimClient {
    type Rejection = ScimError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ScimResult<Self> {
        let meta = ClientMeta::from_request_parts(parts, state).await?;
        let unauthorized = || ScimError(StatusCode::UNAUTHORIZED, None, "Jeton SCIM invalide.".into());
        state.limiter.check(&format!("scim:{}", meta.ip)).map_err(ScimError::from)?;
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim)
            .unwrap_or_default()
            .to_string();
        let settings: ScimSettings = state.db.call(|c| db::load_json(c, SETTINGS_KEY)).await?;
        let ok = !settings.token_hash.is_empty()
            && !token.is_empty()
            && bool::from(sha256_hex(&token).as_bytes().ct_eq(settings.token_hash.as_bytes()));
        if !ok {
            state.limiter.fail(&format!("scim:{}", meta.ip), 10);
            return Err(unauthorized());
        }
        Ok(ScimClient { meta })
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

fn base_url(c: &Connection) -> ApiResult<String> {
    Ok(format!("{}/scim/v2", crate::sso::load_config(c)?.public_url.trim_end_matches('/')))
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

fn apply(c: &Connection, client: &ScimClient, u: &mut DirUser, inc: Incoming) -> ScimResult<()> {
    let now = now_unix();
    if let Some(email) = inc.email {
        let email = normalize_email(&email).map_err(|e| bad(e.message))?;
        if !email.eq_ignore_ascii_case(&u.email) {
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
                let role: String = c.query_row("SELECT role FROM users WHERE id = ?1", [uid], |r| r.get(0))?;
                set_disabled(c, uid, &role, !active)?;
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

pub async fn list_users(State(state): State<AppState>, _c: ScimClient, Query(q): Query<ListQuery>) -> ScimResult<Scim> {
    let filter = q.filter.as_deref().filter(|f| !f.trim().is_empty()).map(parse_filter).transpose()?;
    let start = q.start_index.unwrap_or(1).max(1);
    let count = q.count.unwrap_or(100).clamp(0, 500);
    let body = state
        .db
        .call(move |c| {
            let base = base_url(c)?;
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

pub async fn get_user(State(state): State<AppState>, _c: ScimClient, Path(id): Path<String>) -> ScimResult<Scim> {
    let body = state
        .db
        .call(move |c| {
            let base = base_url(c)?;
            let u = get_dir(c, &id).map_err(|e| ApiError::new(e.0, "not_found", e.2))?;
            Ok(to_scim(&u, &base))
        })
        .await?;
    Ok(Scim(StatusCode::OK, body))
}

pub async fn create_user(State(state): State<AppState>, client: ScimClient, Json(v): Json<Value>) -> ScimResult<Scim> {
    let inc = parse_resource(&v);
    let email = normalize_email(&inc.email.clone().ok_or_else(|| bad("userName ou emails doit contenir une adresse e-mail."))?)
        .map_err(|e| bad(e.message))?;
    let display = inc.display_name.clone().unwrap_or_else(|| email.split('@').next().unwrap_or_default().to_string());
    let result: ScimResult<Value> = state
        .db
        .call(move |c| {
            let run = || -> ScimResult<Value> {
                let exists: bool = c.query_row("SELECT COUNT(*) FROM directory_users WHERE email = ?1", [&email], |r| r.get::<_, i64>(0))? > 0;
                if exists {
                    return Err(ScimError(StatusCode::CONFLICT, Some("uniqueness"), "Cette personne est déjà provisionnée.".into()));
                }
                // Un compte Locksy existant (créé sur invitation) est rattaché.
                let user_id: Option<String> = c.query_row("SELECT id FROM users WHERE email = ?1", [&email], |r| r.get(0)).optional()?;
                let now = now_unix();
                let mut u = DirUser {
                    id: new_uuid(),
                    external_id: inc.external_id.clone().flatten(),
                    email: email.clone(),
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
                audit(c, u.user_id.as_deref(), &email, "scim.user_created", &email, &client.meta, if u.user_id.is_some() { "rattaché à un compte existant" } else { "en attente de première connexion" })?;
                if inc.active == Some(false) {
                    apply(c, &client, &mut u, Incoming { active: Some(false), ..Default::default() })?;
                }
                Ok(to_scim(&u, &base_url(c)?))
            };
            Ok(run())
        })
        .await?;
    Ok(Scim(StatusCode::CREATED, result?))
}

pub async fn replace_user(State(state): State<AppState>, client: ScimClient, Path(id): Path<String>, Json(v): Json<Value>) -> ScimResult<Scim> {
    let inc = parse_resource(&v);
    let result: ScimResult<Value> = state
        .db
        .call(move |c| {
            Ok((|| {
                let mut u = get_dir(c, &id)?;
                apply(c, &client, &mut u, inc)?;
                Ok(to_scim(&u, &base_url(c)?))
            })())
        })
        .await?;
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
    let result: ScimResult<Value> = state
        .db
        .call(move |c| {
            Ok((|| {
                let mut u = get_dir(c, &id)?;
                apply(c, &client, &mut u, inc)?;
                Ok(to_scim(&u, &base_url(c)?))
            })())
        })
        .await?;
    Ok(Scim(StatusCode::OK, result?))
}

pub async fn delete_user(State(state): State<AppState>, client: ScimClient, Path(id): Path<String>) -> ScimResult<StatusCode> {
    let result: ScimResult<()> = state
        .db
        .call(move |c| {
            Ok((|| {
                let u = get_dir(c, &id)?;
                let tx = c.unchecked_transaction()?;
                let mut details = "compte en attente supprimé".to_string();
                if let Some(uid) = &u.user_id {
                    let role: Option<String> = tx.query_row("SELECT role FROM users WHERE id = ?1", [uid], |r| r.get(0)).optional()?;
                    if let Some(role) = role {
                        let removed = remove_user(&tx, uid, &role)?;
                        details = format!("compte Locksy supprimé, {removed} coffre(s) sans membre supprimé(s)");
                    }
                }
                tx.execute("DELETE FROM directory_users WHERE id = ?1", [&u.id])?;
                audit(&tx, u.user_id.as_deref(), &u.email, "scim.user_deleted", &u.email, &client.meta, &details)?;
                tx.commit()?;
                Ok(())
            })())
        })
        .await?;
    result?;
    Ok(StatusCode::NO_CONTENT)
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

pub async fn status(State(state): State<AppState>, _a: AdminUser) -> ApiResult<Json<ScimStatus>> {
    Ok(Json(
        state
            .db
            .call(|c| {
                let s: ScimSettings = db::load_json(c, SETTINGS_KEY)?;
                Ok(ScimStatus {
                    enabled: !s.token_hash.is_empty(),
                    created_at: (s.created_at > 0).then_some(s.created_at),
                    base_url: base_url(c)?,
                })
            })
            .await?,
    ))
}

pub async fn create_token(State(state): State<AppState>, AdminUser(admin): AdminUser) -> ApiResult<Json<ScimTokenCreated>> {
    let token = random_token();
    let hash = sha256_hex(&token);
    let base = state
        .db
        .call(move |c| {
            db::save_json(c, SETTINGS_KEY, &ScimSettings { token_hash: hash, created_at: now_unix() })?;
            audit_user(c, &admin, "admin.scim_token_created", "", "l'ancien jeton éventuel est révoqué")?;
            base_url(c)
        })
        .await?;
    Ok(Json(ScimTokenCreated { token, base_url: base }))
}

pub async fn revoke_token(State(state): State<AppState>, AdminUser(admin): AdminUser) -> ApiResult<StatusCode> {
    state
        .db
        .call(move |c| {
            db::save_json(c, SETTINGS_KEY, &ScimSettings::default())?;
            audit_user(c, &admin, "admin.scim_token_revoked", "", "")
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn directory(State(state): State<AppState>, _a: AdminUser) -> ApiResult<Json<Vec<DirectoryEntry>>> {
    Ok(Json(
        state
            .db
            .call(|c| {
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
