//! Stockage SQLite. Le serveur n'y range que des chiffrés opaques, des
//! empreintes Argon2id et des métadonnées (dates, rôles, appartenances).

use crate::error::{ApiError, ApiResult};
use rusqlite::{Connection, OptionalExtension};
use std::path::Path;
use std::sync::{Arc, Mutex};
use locksy_core::api::OrgSettings;

#[derive(Clone)]
pub struct Db(Arc<Mutex<Connection>>);

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id                        TEXT PRIMARY KEY,
    email                     TEXT NOT NULL UNIQUE COLLATE NOCASE,
    name                      TEXT NOT NULL,
    role                      TEXT NOT NULL,
    disabled                  INTEGER NOT NULL DEFAULT 0,
    kdf                       TEXT NOT NULL,
    auth_hash                 TEXT NOT NULL,
    wrapped_user_key          TEXT NOT NULL,
    recovery_wrapped_user_key TEXT NOT NULL,
    recovery_auth_hash        TEXT NOT NULL,
    public_key                TEXT NOT NULL,
    wrapped_private_key       TEXT NOT NULL,
    totp_secret               TEXT,
    totp_pending              TEXT,
    totp_last_step            INTEGER,
    created_at                INTEGER NOT NULL,
    updated_at                INTEGER NOT NULL,
    last_login_at             INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT PRIMARY KEY,
    token_hash   TEXT NOT NULL UNIQUE,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    ip           TEXT NOT NULL,
    device       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS recovery_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS collections (
    id          TEXT PRIMARY KEY,
    enc_name    TEXT NOT NULL,
    personal    INTEGER NOT NULL DEFAULT 0,
    created_by  TEXT,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    key_version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS memberships (
    collection_id TEXT NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role          TEXT NOT NULL,
    sealed_key    TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    PRIMARY KEY (collection_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_memberships_user ON memberships(user_id);

CREATE TABLE IF NOT EXISTS items (
    id            TEXT PRIMARY KEY,
    collection_id TEXT NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
    data          TEXT NOT NULL,
    revision      INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    deleted_at    INTEGER,
    updated_by    TEXT
);
CREATE INDEX IF NOT EXISTS idx_items_collection ON items(collection_id);

CREATE TABLE IF NOT EXISTS invites (
    id         TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    email      TEXT NOT NULL COLLATE NOCASE,
    role       TEXT NOT NULL,
    created_by TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER
);

CREATE TABLE IF NOT EXISTS shares (
    id         TEXT PRIMARY KEY,
    owner_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    data       TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    max_views  INTEGER NOT NULL,
    views      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    at         INTEGER NOT NULL,
    user_id    TEXT,
    email      TEXT NOT NULL DEFAULT '',
    action     TEXT NOT NULL,
    target     TEXT NOT NULL DEFAULT '',
    ip         TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    details    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit(at);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit(user_id);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#;

impl Db {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;
             PRAGMA secure_delete = ON;
             PRAGMA busy_timeout = 5000;",
        )?;
        conn.execute_batch(SCHEMA)?;
        migrate(&conn)?;
        Ok(Self(Arc::new(Mutex::new(conn))))
    }

    /// Exécute `f` sur la connexion dans un fil dédié (SQLite est bloquant).
    pub async fn call<F, T>(&self, f: F) -> ApiResult<T>
    where
        F: FnOnce(&mut Connection) -> ApiResult<T> + Send + 'static,
        T: Send + 'static,
    {
        let db = self.0.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = db.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            f(&mut conn)
        })
        .await
        .map_err(|_| ApiError::internal("tâche base de données interrompue"))?
    }
}

fn has_column(c: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    let mut st = c.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = st.query_map([], |r| r.get::<_, String>(1))?.collect::<Result<Vec<_>, _>>()?;
    Ok(names.iter().any(|n| n == column))
}

/// Évolutions du schéma, appliquées une fois sur les bases existantes.
fn migrate(c: &Connection) -> rusqlite::Result<()> {
    if has_column(c, "directory_users", "id")? && !has_column(c, "directory_users", "source")? {
        c.execute_batch("ALTER TABLE directory_users ADD COLUMN source TEXT NOT NULL DEFAULT 'scim'")?;
    }
    if !has_column(c, "users", "sso_subject")? {
        c.execute_batch("ALTER TABLE users ADD COLUMN sso_subject TEXT")?;
    }
    c.execute_batch(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_sso ON users(sso_subject) WHERE sso_subject IS NOT NULL;

         -- Comptes poussés par l'annuaire (SCIM), en attente ou liés à un compte Locksy.
         CREATE TABLE IF NOT EXISTS directory_users (
             id           TEXT PRIMARY KEY,
             external_id  TEXT,
             email        TEXT NOT NULL UNIQUE COLLATE NOCASE,
             display_name TEXT NOT NULL DEFAULT '',
             active       INTEGER NOT NULL DEFAULT 1,
             user_id      TEXT REFERENCES users(id) ON DELETE SET NULL,
             created_at   INTEGER NOT NULL,
             updated_at   INTEGER NOT NULL,
             source       TEXT NOT NULL DEFAULT 'scim'
         );

         -- Pièces jointes chiffrées (contenu illisible pour le serveur).
         CREATE TABLE IF NOT EXISTS attachments (
             id         TEXT PRIMARY KEY,
             item_id    TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
             data       TEXT NOT NULL,
             size       INTEGER NOT NULL,
             created_at INTEGER NOT NULL,
             created_by TEXT
         );
         CREATE INDEX IF NOT EXISTS idx_attachments_item ON attachments(item_id);

         -- Tickets à usage unique remis après une authentification SSO (5 minutes).
         CREATE TABLE IF NOT EXISTS sso_tickets (
             ticket_hash TEXT PRIMARY KEY,
             email       TEXT NOT NULL,
             name        TEXT NOT NULL DEFAULT '',
             subject     TEXT NOT NULL,
             user_id     TEXT,
             expires_at  INTEGER NOT NULL,
             used        INTEGER NOT NULL DEFAULT 0
         );",
    )
}

pub fn load_json<T: serde::de::DeserializeOwned + Default>(c: &Connection, key: &str) -> ApiResult<T> {
    let raw: Option<String> = c.query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| r.get(0)).optional()?;
    Ok(raw.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default())
}

pub fn save_json<T: serde::Serialize>(c: &Connection, key: &str, value: &T) -> ApiResult<()> {
    let json = serde_json::to_string(value).map_err(|_| ApiError::internal("sérialisation des réglages"))?;
    c.execute(
        "INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [key, &json],
    )?;
    Ok(())
}

pub fn load_settings(c: &Connection) -> ApiResult<OrgSettings> {
    let raw: Option<String> =
        c.query_row("SELECT value FROM settings WHERE key = 'org'", [], |r| r.get(0)).optional()?;
    Ok(raw.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default())
}

pub fn save_settings(c: &Connection, s: &OrgSettings) -> ApiResult<()> {
    let json = serde_json::to_string(s).map_err(|_| ApiError::internal("sérialisation des réglages"))?;
    c.execute(
        "INSERT INTO settings (key, value) VALUES ('org', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [json],
    )?;
    Ok(())
}

pub fn collection_role(c: &Connection, collection_id: &str, user_id: &str) -> ApiResult<Option<String>> {
    Ok(c
        .query_row(
            "SELECT role FROM memberships WHERE collection_id = ?1 AND user_id = ?2",
            [collection_id, user_id],
            |r| r.get(0),
        )
        .optional()?)
}
