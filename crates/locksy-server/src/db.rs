//! Stockage SQLite. Le serveur n'y range que des chiffrés opaques, des
//! empreintes Argon2id et des métadonnées (dates, rôles, appartenances).
//!
//! Connexions :
//! - un écrivain unique, sous verrou, pour toute écriture et tout audit
//!   (`Db::call`) ;
//! - un petit pool de lecteurs en `query_only` (`Db::read`) : grâce au WAL,
//!   ils lisent en parallèle sans attendre l'écrivain, et voient tout ce
//!   qu'un `call` terminé a commité.
//!
//! Versions du schéma : `PRAGMA user_version`, un palier par entrée de
//! `MIGRATIONS`. Un binaire refuse une base plus récente que lui.
//!
//! Journal d'audit : un événement n'est transmis au syslog qu'une fois sa
//! ligne commitée (tampon par appel de `Db::call`, voir `defer_or_emit`).

use crate::error::{ApiError, ApiResult};
use locksy_core::api::OrgSettings;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use std::cell::{Cell, RefCell};
use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::Duration;
use tokio::sync::Semaphore;

/// Version du schéma attendue par ce binaire (`PRAGMA user_version`).
pub const SCHEMA_VERSION: i64 = 4;

/// Délai d'attente d'un verrou SQLite détenu par une autre connexion.
const BUSY_TIMEOUT: Duration = Duration::from_millis(5000);

/// Réglages d'ouverture de la base.
#[derive(Clone, Debug)]
pub struct DbOptions {
    /// Connexions de lecture (0 : les lectures passent par l'écrivain).
    pub readers: usize,
}

impl Default for DbOptions {
    fn default() -> Self {
        Self { readers: 4 }
    }
}

/// Échec à l'ouverture de la base.
#[derive(Debug)]
pub enum OpenError {
    /// Fichier illisible, verrouillé ou corrompu.
    Sqlite(rusqlite::Error),
    /// La base a été créée ou migrée par un binaire plus récent.
    TooNew { found: i64, supported: i64 },
    /// Un palier de migration a échoué (annulé : la base reste au palier précédent).
    Migration { to: i64, source: rusqlite::Error },
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenError::Sqlite(e) => write!(f, "base de données SQLite inaccessible : {e}"),
            OpenError::TooNew { found, supported } => write!(
                f,
                "la base de données est au schéma v{found}, plus récent que celui que gère ce programme \
                 (v{supported}) : installez une version de Locksy à jour ou restaurez une sauvegarde compatible"
            ),
            OpenError::Migration { to, source } => write!(
                f,
                "échec de la migration du schéma vers la v{to} (la base reste à la version précédente) : {source}"
            ),
        }
    }
}

impl std::error::Error for OpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            OpenError::Sqlite(e) | OpenError::Migration { source: e, .. } => Some(e),
            OpenError::TooNew { .. } => None,
        }
    }
}

impl From<rusqlite::Error> for OpenError {
    fn from(e: rusqlite::Error) -> Self {
        OpenError::Sqlite(e)
    }
}

#[derive(Clone)]
pub struct Db {
    inner: Arc<Inner>,
}

struct Inner {
    /// Seule connexion autorisée à écrire.
    writer: Mutex<Connection>,
    /// Connexions en `query_only` ; vide pour une base en mémoire.
    readers: Vec<Mutex<Connection>>,
    /// Un permis par lecteur : un permis obtenu garantit un lecteur libre.
    reader_slots: Arc<Semaphore>,
    /// Génération des réglages : incrémentée après tout appel qui en a écrit
    /// (voir `mark_settings_changed`). Le cache des réglages ne relit la
    /// base que si elle a changé.
    settings_gen: AtomicU64,
}

/// Verrouille un mutex en récupérant un état empoisonné (une panique dans
/// une tâche précédente ne doit pas rendre la base inutilisable).
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Inner {
    /// Premier lecteur libre. Appelé avec un permis du sémaphore : il en
    /// existe forcément un.
    fn free_reader(&self) -> MutexGuard<'_, Connection> {
        for m in &self.readers {
            match m.try_lock() {
                Ok(g) => return g,
                Err(TryLockError::Poisoned(p)) => return p.into_inner(),
                Err(TryLockError::WouldBlock) => {}
            }
        }
        // Inatteignable tant que permis et lecteurs restent appariés : on
        // attend le premier plutôt que d'échouer.
        lock(&self.readers[0])
    }
}

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
    /// Ouvre (ou crée) la base avec les réglages par défaut (tests seulement :
    /// le serveur passe toujours par `open_with` et sa configuration).
    #[cfg(test)]
    pub fn open(path: &Path) -> Result<Db, OpenError> {
        Self::open_with(path, DbOptions::default())
    }

    /// Ouvre (ou crée) la base : contrôle de version, pragmas, migrations,
    /// puis ouverture des lecteurs.
    pub fn open_with(path: &Path, opts: DbOptions) -> Result<Db, OpenError> {
        let in_memory = path == Path::new(":memory:");
        let mut writer = Connection::open(path)?;
        writer.busy_timeout(BUSY_TIMEOUT)?;

        // Version lue AVANT toute écriture, y compris le passage en WAL (qui
        // modifie l'en-tête du fichier) : une base trop récente reste intacte.
        let found = schema_version(&writer)?;
        check_version(found)?;

        configure_writer(&writer, in_memory)?;
        migrate(&mut writer, found)?;
        refresh_triggers(&writer)?;

        // Chaque connexion « :memory: » serait une base vide distincte : pas
        // de lecteurs, les lectures passent alors par l'écrivain.
        let count = if in_memory { 0 } else { opts.readers };
        let readers = (0..count).map(|_| open_reader(path).map(Mutex::new)).collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Db {
            inner: Arc::new(Inner {
                writer: Mutex::new(writer),
                reader_slots: Arc::new(Semaphore::new(readers.len())),
                readers,
                settings_gen: AtomicU64::new(0),
            }),
        })
    }

    /// Exécute `f` sur l'écrivain dans un fil dédié (SQLite est bloquant).
    /// À utiliser pour toute écriture et tout appel de `state::audit`.
    ///
    /// Quand la tâche rend la main, ses écritures sont commitées : un `read`
    /// lancé ensuite les voit. Les événements d'audit écrits dans une
    /// transaction ne partent au syslog qu'ici, une fois le commit constaté.
    pub async fn call<F, T>(&self, f: F) -> ApiResult<T>
    where
        F: FnOnce(&mut Connection) -> ApiResult<T> + Send + 'static,
        T: Send + 'static,
    {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = lock(&inner.writer);
            let tampon = AuditBuffer::open();
            let reglages = SettingsCall::open();
            // La panique est rattrapée pour toujours passer par le contrôle
            // ci-dessous (la transaction en cours a été annulée au déroulement).
            let result = catch_unwind(AssertUnwindSafe(|| f(&mut conn)));
            close_dangling_transaction(&conn, "écrivain");
            flush_audit(&conn, tampon.take());
            // Après le commit (ou l'annulation) : un chargement lancé ensuite
            // voit l'écriture. Une annulation coûte seulement un rechargement.
            if reglages.changed() {
                inner.settings_gen.fetch_add(1, Ordering::SeqCst);
            }
            result.unwrap_or_else(|_| Err(ApiError::internal("panique dans une tâche base de données")))
        })
        .await
        .map_err(|_| ApiError::internal("tâche base de données interrompue"))?
    }

    /// Exécute `f` sur une connexion de lecture (`query_only`), en parallèle
    /// des autres lectures et de l'écrivain. Toute écriture y échoue (erreur
    /// interne), y compris un audit. Voit tout `call` déjà terminé.
    pub async fn read<F, T>(&self, f: F) -> ApiResult<T>
    where
        F: FnOnce(&Connection) -> ApiResult<T> + Send + 'static,
        T: Send + 'static,
    {
        if self.inner.readers.is_empty() {
            // Base en mémoire ou pool désactivé : l'écrivain, bridé en lecture.
            return self
                .call(move |c| {
                    let bride = QueryOnly::on(c)?;
                    f(bride.0)
                })
                .await;
        }
        let permit = self
            .inner
            .reader_slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ApiError::internal("pool de lecture fermé"))?;
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            // Le permis est rendu à la fin du fil, après le lecteur (ordre
            // de destruction inverse des déclarations).
            let _permis = permit;
            let conn = inner.free_reader();
            let result = catch_unwind(AssertUnwindSafe(|| f(&conn)));
            // Jamais de transaction de lecture conservée d'un appel à l'autre :
            // elle figerait l'instantané et bloquerait les points de contrôle.
            close_dangling_transaction(&conn, "lecteur");
            result.unwrap_or_else(|_| Err(ApiError::internal("panique dans une lecture base de données")))
        })
        .await
        .map_err(|_| ApiError::internal("tâche base de données interrompue"))?
    }

    /// Génération des réglages : change après chaque `call` qui a écrit un
    /// réglage. Lecture atomique, sans requête.
    pub fn settings_generation(&self) -> u64 {
        self.inner.settings_gen.load(Ordering::SeqCst)
    }

    /// Reporte le WAL dans le fichier principal et le vide (arrêt du serveur).
    pub async fn checkpoint(&self) -> ApiResult<()> {
        self.call(|c| {
            let (busy, log, done): (i64, i64, i64) =
                c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            if busy != 0 {
                tracing::warn!(log, done, "point de contrôle WAL incomplet : des lectures étaient en cours");
            }
            Ok(())
        })
        .await
    }
}

/// Version du schéma enregistrée dans la base (0 : base neuve ou antérieure
/// aux migrations versionnées).
pub fn schema_version(c: &Connection) -> rusqlite::Result<i64> {
    c.query_row("PRAGMA user_version", [], |r| r.get(0))
}

fn check_version(found: i64) -> Result<(), OpenError> {
    if found > SCHEMA_VERSION {
        return Err(OpenError::TooNew { found, supported: SCHEMA_VERSION });
    }
    if found < 0 {
        // Valeur posée à la main : on ne sait pas ce que contient la base.
        return Err(OpenError::Sqlite(rusqlite::Error::IntegralValueOutOfRange(0, found)));
    }
    Ok(())
}

/// Pragmas de l'écrivain, posés hors transaction (`journal_mode` ne peut
/// pas changer dans une transaction).
fn configure_writer(c: &Connection, in_memory: bool) -> rusqlite::Result<()> {
    let mode: String = c.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
    if !in_memory && !mode.eq_ignore_ascii_case("wal") {
        tracing::warn!(mode, "mode WAL refusé par SQLite (système de fichiers ?) : lectures et écritures se sérialisent");
    }
    // synchronous = FULL : un coffre de mots de passe ne perd pas un commit
    // sur coupure de courant, même en WAL.
    c.execute_batch(
        "PRAGMA synchronous = FULL;
         PRAGMA foreign_keys = ON;
         PRAGMA secure_delete = ON;
         PRAGMA trusted_schema = OFF;",
    )
}

/// Connexion de lecture. Ouverte en lecture-écriture classique (en WAL, il
/// faut pouvoir écrire le fichier -shm), puis bridée par `query_only`.
fn open_reader(path: &Path) -> rusqlite::Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_URI | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let c = Connection::open_with_flags(path, flags)?;
    c.busy_timeout(BUSY_TIMEOUT)?;
    c.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA trusted_schema = OFF;
         PRAGMA query_only = ON;",
    )?;
    Ok(c)
}

/// Annule une transaction laissée ouverte par une tâche (bogue d'appelant) :
/// sinon les tâches suivantes s'y ajouteraient sans jamais être commitées.
fn close_dangling_transaction(c: &Connection, role: &'static str) {
    if !c.is_autocommit() {
        tracing::error!(role, "transaction laissée ouverte par une tâche : annulée");
        if let Err(e) = c.execute_batch("ROLLBACK") {
            tracing::error!(role, error = %e, "annulation impossible");
        }
    }
}

/// Bride temporairement l'écrivain en lecture seule (lecture déléguée) ; la
/// bride est levée à la destruction, panique comprise.
struct QueryOnly<'a>(&'a Connection);

impl<'a> QueryOnly<'a> {
    fn on(c: &'a Connection) -> rusqlite::Result<Self> {
        c.execute_batch("PRAGMA query_only = ON")?;
        Ok(QueryOnly(c))
    }
}

impl Drop for QueryOnly<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.0.execute_batch("PRAGMA query_only = OFF") {
            tracing::error!(error = %e, "impossible de lever la lecture seule de l'écrivain");
        }
    }
}

// ------------------------------------------------------------ Migrations

/// Paliers de migration, indexés par version source : `MIGRATIONS[v]` amène
/// une base de la v`v` à la v`v+1`. Chaque palier tourne dans sa propre
/// transaction avec la mise à jour de `user_version`. On n'ajoute qu'à la
/// fin, sans jamais modifier un palier publié.
const MIGRATIONS: &[fn(&Connection) -> rusqlite::Result<()>] = &[
    // v0 → v1 : schéma de base et évolutions antérieures au versionnage.
    // Une base neuve et une base existante sans version (installations
    // antérieures) prennent le même chemin : tout est idempotent.
    migrate_to_v1,
    // v1 → v2 : index pour les quotas de pièces jointes (par créateur) et
    // la recherche du journal d'audit par action.
    migrate_to_v2,
    // v2 → v3 : migration unique de la refonte (registre des réglages,
    // préférences, comptes, corbeille, liens, synchronisation incrémentale,
    // journal chaîné, file d'e-mails, invitations) et reprise des anciens
    // réglages dans le registre.
    migrate_to_v3,
    // v3 → v4 : nom de la personne invitée (prénom et nom saisis par l'administrateur).
    migrate_to_v4,
];

fn migrate(c: &mut Connection, mut current: i64) -> Result<(), OpenError> {
    while current < SCHEMA_VERSION {
        let to = current + 1;
        let err = |source| OpenError::Migration { to, source };
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate).map_err(err)?;
        // Relue sous le verrou d'écriture : un autre processus a pu migrer
        // entre-temps (la transaction abandonnée est annulée).
        let now = schema_version(&tx).map_err(err)?;
        if now != current {
            check_version(now)?;
            current = now;
            continue;
        }
        MIGRATIONS[current as usize](&tx).map_err(err)?;
        // user_version est transactionnel : valeur et palier vont ensemble.
        tx.execute_batch(&format!("PRAGMA user_version = {to}")).map_err(err)?;
        tx.commit().map_err(err)?;
        tracing::info!(version = to, "schéma de la base migré");
        current = to;
    }
    Ok(())
}

fn has_column(c: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    let mut st = c.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = st.query_map([], |r| r.get::<_, String>(1))?.collect::<Result<Vec<_>, _>>()?;
    Ok(names.iter().any(|n| n == column))
}

/// Index des quotas de pièces jointes et du journal (index seulement : une
/// base v2 reste lisible par un binaire antérieur).
fn migrate_to_v2(c: &Connection) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_attachments_creator ON attachments(created_by);
         CREATE INDEX IF NOT EXISTS idx_audit_action_at ON audit(action, at);",
    )
}

/// Ajoute une colonne si elle manque (pas de CHECK : les valeurs sont
/// contrôlées par le code).
fn add_column(c: &Connection, table: &str, column: &str, decl: &str) -> rusqlite::Result<()> {
    if !has_column(c, table, column)? {
        c.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"))?;
    }
    Ok(())
}

/// Tables et colonnes de la refonte. Tout est idempotent.
const SCHEMA_V3: &str = r#"
-- Réglages de l'organisation : seules les valeurs différentes du défaut.
CREATE TABLE IF NOT EXISTS org_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    mode       TEXT,
    policy_min TEXT,
    policy_max TEXT,
    updated_at INTEGER NOT NULL,
    updated_by TEXT
);
CREATE TABLE IF NOT EXISTS settings_meta (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    revision       INTEGER NOT NULL,
    schema_version INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL DEFAULT 0,
    updated_by     TEXT
);
INSERT OR IGNORE INTO settings_meta (id, revision, schema_version, updated_at) VALUES (1, 0, 2, 0);
CREATE TABLE IF NOT EXISTS settings_history (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    revision  INTEGER NOT NULL,
    at        INTEGER NOT NULL,
    user_id   TEXT,
    email     TEXT NOT NULL,
    ip        TEXT NOT NULL,
    key       TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    source    TEXT NOT NULL,
    reason    TEXT
);
CREATE INDEX IF NOT EXISTS idx_settings_history_rev ON settings_history(revision);
CREATE INDEX IF NOT EXISTS idx_settings_history_key ON settings_history(key, revision);

-- Préférences de l'utilisateur, chiffrées par le client (opaques).
CREATE TABLE IF NOT EXISTS user_prefs (
    user_id    TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    cipher     TEXT NOT NULL,
    revision   INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Synchronisations de l'annuaire et tests de connexion d'entreprise.
CREATE TABLE IF NOT EXISTS ldap_sync_history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    at           INTEGER NOT NULL,
    dry_run      INTEGER NOT NULL,
    found        INTEGER NOT NULL DEFAULT 0,
    created      INTEGER NOT NULL DEFAULT 0,
    updated      INTEGER NOT NULL DEFAULT 0,
    disabled     INTEGER NOT NULL DEFAULT 0,
    ignored_json TEXT NOT NULL DEFAULT '[]',
    error_code   TEXT,
    triggered_by TEXT
);
CREATE TABLE IF NOT EXISTS identity_tests (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT NOT NULL,
    at         INTEGER NOT NULL,
    user_id    TEXT NOT NULL,
    ok         INTEGER NOT NULL,
    error_code TEXT
);
CREATE INDEX IF NOT EXISTS idx_identity_tests ON identity_tests(kind, user_id, at);

-- Codes de secours de la double authentification (empreintes HMAC).
CREATE TABLE IF NOT EXISTS totp_recovery_codes (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    used_at    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_totp_recovery_user ON totp_recovery_codes(user_id);

-- Révélations des liens sécurisés.
CREATE TABLE IF NOT EXISTS share_reveals (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    share_id   TEXT NOT NULL,
    at         INTEGER NOT NULL,
    ip         TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    nonce_hash TEXT,
    counted    INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_share_reveals ON share_reveals(share_id, at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_share_reveals_nonce ON share_reveals(share_id, nonce_hash) WHERE nonce_hash IS NOT NULL;

-- Synchronisation incrémentale : compteur global et pierres tombales.
CREATE TABLE IF NOT EXISTS sync_state (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    seq           INTEGER NOT NULL,
    purged_before INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO sync_state (id, seq, purged_before) VALUES (1, 0, 0);
CREATE TABLE IF NOT EXISTS sync_tombstones (
    seq           INTEGER PRIMARY KEY,
    kind          TEXT NOT NULL,
    object_id     TEXT NOT NULL,
    collection_id TEXT,
    user_id       TEXT,
    at            INTEGER
);
CREATE INDEX IF NOT EXISTS idx_sync_tombstones_collection ON sync_tombstones(collection_id, seq);
CREATE INDEX IF NOT EXISTS idx_sync_tombstones_user ON sync_tombstones(user_id, seq);

-- Ancrages du journal chaîné.
CREATE TABLE IF NOT EXISTS audit_anchors (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    at            INTEGER NOT NULL,
    last_audit_id INTEGER NOT NULL,
    mac           TEXT NOT NULL,
    reason        TEXT NOT NULL
);

-- File d'envoi des e-mails (échecs gardés 30 jours).
CREATE TABLE IF NOT EXISTS mail_queue (
    id                TEXT PRIMARY KEY,
    kind              TEXT NOT NULL,
    to_email          TEXT NOT NULL,
    subject           TEXT NOT NULL,
    body_text         TEXT NOT NULL,
    body_html         TEXT,
    status            TEXT NOT NULL DEFAULT 'pending',
    attempts          INTEGER NOT NULL DEFAULT 0,
    next_attempt_at   INTEGER NOT NULL,
    last_error_code   TEXT,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL,
    sent_at           INTEGER,
    related_user_id   TEXT,
    related_invite_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_mail_queue_status ON mail_queue(status, next_attempt_at);
"#;

/// Colonnes ajoutées aux tables existantes : (table, colonne, déclaration).
const COLUMNS_V3: &[(&str, &str, &str)] = &[
    ("collections", "rotation_suggested_at", "INTEGER"),
    ("collections", "change_seq", "INTEGER NOT NULL DEFAULT 0"),
    ("users", "charter_accepted_version", "INTEGER"),
    ("users", "charter_accepted_at", "INTEGER"),
    ("users", "deprovision_at", "INTEGER"),
    ("users", "access_until", "INTEGER"),
    ("users", "disabled_at", "INTEGER"),
    ("users", "disabled_reason", "TEXT"),
    ("users", "totp_recovery_generated_at", "INTEGER"),
    ("items", "deleted_by", "TEXT"),
    ("items", "purge_at", "INTEGER"),
    ("items", "change_seq", "INTEGER NOT NULL DEFAULT 0"),
    ("memberships", "change_seq", "INTEGER NOT NULL DEFAULT 0"),
    ("shares", "state", "TEXT NOT NULL DEFAULT 'active'"),
    ("shares", "ended_at", "INTEGER"),
    ("shares", "ended_reason", "TEXT"),
    ("shares", "ended_by", "TEXT"),
    ("shares", "verifier", "TEXT"),
    ("shares", "item_id", "TEXT"),
    ("shares", "collection_id", "TEXT"),
    ("audit", "chain_mac", "TEXT"),
    ("invites", "sent_count", "INTEGER NOT NULL DEFAULT 0"),
    ("invites", "last_sent_at", "INTEGER"),
    ("invites", "access_until", "INTEGER"),
];

/// Index sur les colonnes ajoutées (après les ALTER).
const INDEXES_V3: &str = r#"
CREATE INDEX IF NOT EXISTS idx_users_deprovision ON users(deprovision_at) WHERE deprovision_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_shares_owner_state ON shares(owner_id, state);
CREATE INDEX IF NOT EXISTS idx_shares_item ON shares(item_id);
CREATE INDEX IF NOT EXISTS idx_items_change_seq ON items(change_seq);
-- Quotas de pièces jointes : index couvrant (créateur, taille). `size` est
-- rangée après `data` dans la table ; sans cet index, chaque SUM(size)
-- relirait les pages de débordement de toutes les pièces jointes.
CREATE INDEX IF NOT EXISTS idx_attachments_quota ON attachments(created_by, size);
"#;

/// Déclencheurs de la synchronisation incrémentale. Chaque modification
/// incrémente `sync_state.seq` et pose `change_seq` sur la ligne ; une
/// suppression (cascades comprises) ou le déplacement d'un élément vers un
/// autre coffre laisse une pierre tombale. Ils ne contiennent que des
/// fonctions sûres pour `trusted_schema = OFF` (`unixepoch()`).
const TRIGGERS_V3: &str = r#"
CREATE TRIGGER IF NOT EXISTS trg_sync_items_insert AFTER INSERT ON items BEGIN
    UPDATE sync_state SET seq = seq + 1 WHERE id = 1;
    UPDATE items SET change_seq = (SELECT seq FROM sync_state WHERE id = 1) WHERE id = NEW.id;
END;
CREATE TRIGGER IF NOT EXISTS trg_sync_items_update AFTER UPDATE OF data, collection_id, deleted_at, revision ON items BEGIN
    UPDATE sync_state SET seq = seq + 1 WHERE id = 1;
    INSERT INTO sync_tombstones (seq, kind, object_id, collection_id, user_id, at)
        SELECT seq, 'item', OLD.id, OLD.collection_id, NULL, unixepoch() FROM sync_state
        WHERE id = 1 AND OLD.collection_id IS NOT NEW.collection_id;
    UPDATE sync_state SET seq = seq + 1 WHERE id = 1 AND OLD.collection_id IS NOT NEW.collection_id;
    UPDATE items SET change_seq = (SELECT seq FROM sync_state WHERE id = 1) WHERE id = NEW.id;
END;
CREATE TRIGGER IF NOT EXISTS trg_sync_items_delete AFTER DELETE ON items BEGIN
    UPDATE sync_state SET seq = seq + 1 WHERE id = 1;
    INSERT INTO sync_tombstones (seq, kind, object_id, collection_id, user_id, at)
        SELECT seq, 'item', OLD.id, OLD.collection_id, NULL, unixepoch() FROM sync_state WHERE id = 1;
END;
CREATE TRIGGER IF NOT EXISTS trg_sync_collections_insert AFTER INSERT ON collections BEGIN
    UPDATE sync_state SET seq = seq + 1 WHERE id = 1;
    UPDATE collections SET change_seq = (SELECT seq FROM sync_state WHERE id = 1) WHERE id = NEW.id;
END;
CREATE TRIGGER IF NOT EXISTS trg_sync_collections_delete AFTER DELETE ON collections BEGIN
    UPDATE sync_state SET seq = seq + 1 WHERE id = 1;
    INSERT INTO sync_tombstones (seq, kind, object_id, collection_id, user_id, at)
        SELECT seq, 'collection', OLD.id, OLD.id, NULL, unixepoch() FROM sync_state WHERE id = 1;
END;
CREATE TRIGGER IF NOT EXISTS trg_sync_memberships_insert AFTER INSERT ON memberships BEGIN
    UPDATE sync_state SET seq = seq + 1 WHERE id = 1;
    UPDATE memberships SET change_seq = (SELECT seq FROM sync_state WHERE id = 1)
        WHERE collection_id = NEW.collection_id AND user_id = NEW.user_id;
END;
CREATE TRIGGER IF NOT EXISTS trg_sync_memberships_update AFTER UPDATE OF role, sealed_key ON memberships BEGIN
    UPDATE sync_state SET seq = seq + 1 WHERE id = 1;
    UPDATE memberships SET change_seq = (SELECT seq FROM sync_state WHERE id = 1)
        WHERE collection_id = NEW.collection_id AND user_id = NEW.user_id;
END;
CREATE TRIGGER IF NOT EXISTS trg_sync_memberships_delete AFTER DELETE ON memberships BEGIN
    UPDATE sync_state SET seq = seq + 1 WHERE id = 1;
    INSERT INTO sync_tombstones (seq, kind, object_id, collection_id, user_id, at)
        SELECT seq, 'membership', OLD.collection_id, OLD.collection_id, OLD.user_id, unixepoch() FROM sync_state WHERE id = 1;
END;
"#;

/// Déclencheur de mise à jour d'un coffre : le nom, la version de clé et la
/// rotation conseillée (posée par l'assistant de départ) remontent dans
/// /sync?since. Recréé à chaque ouverture s'il ne suit pas la rotation
/// (bases v3 créées avant ce suivi) : DROP puis CREATE, idempotent.
const TRIGGER_COLLECTIONS_UPDATE: &str = r#"
DROP TRIGGER IF EXISTS trg_sync_collections_update;
CREATE TRIGGER trg_sync_collections_update
AFTER UPDATE OF enc_name, key_version, rotation_suggested_at ON collections BEGIN
    UPDATE sync_state SET seq = seq + 1 WHERE id = 1;
    UPDATE collections SET change_seq = (SELECT seq FROM sync_state WHERE id = 1) WHERE id = NEW.id;
END;
"#;

/// Met à jour les déclencheurs d'une base déjà au schéma courant (aucun
/// changement de version : une base reste lisible par le binaire précédent).
fn refresh_triggers(c: &Connection) -> rusqlite::Result<()> {
    if schema_version(c)? < 3 {
        return Ok(());
    }
    let sql: Option<String> = c
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'trg_sync_collections_update'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if !sql.is_some_and(|s| s.contains("rotation_suggested_at")) {
        c.execute_batch(TRIGGER_COLLECTIONS_UPDATE)?;
    }
    Ok(())
}

/// Migration unique de la refonte, puis reprise des anciens réglages
/// (`settings.org`, `settings.attachments`, champs des blocs `sso` et
/// `ldap`) dans le registre. Les anciens blocs sont conservés (miroirs).
fn migrate_to_v3(c: &Connection) -> rusqlite::Result<()> {
    c.execute_batch(SCHEMA_V3)?;
    for (table, column, decl) in COLUMNS_V3 {
        add_column(c, table, column, decl)?;
    }
    c.execute_batch(INDEXES_V3)?;
    c.execute_batch(TRIGGERS_V3)?;
    c.execute_batch(TRIGGER_COLLECTIONS_UPDATE)?;
    crate::settings_api::migrate_legacy(c, locksy_core::now_unix())
}

/// Nom de la personne invitée, repris à l'inscription et dans l'e-mail.
fn migrate_to_v4(c: &Connection) -> rusqlite::Result<()> {
    add_column(c, "invites", "name", "TEXT NOT NULL DEFAULT ''")?;
    // Empreintes des mots de passe d'éléments (politique passwords.unique_across_users).
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS password_fingerprints (
            item_id    TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL,
            fp         TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_password_fingerprints_fp ON password_fingerprints(fp);",
    )
}

/// Schéma de base, puis évolutions appliquées avant le versionnage
/// (`has_column` : idempotent sur une base déjà à jour).
fn migrate_to_v1(c: &Connection) -> rusqlite::Result<()> {
    c.execute_batch(SCHEMA)?;
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

// ------------------------------------------------------------ Audit après commit

/// Événement d'audit en attente de transmission au syslog.
#[derive(Clone, Debug)]
pub(crate) struct AuditEvent {
    pub at: i64,
    pub user_id: Option<String>,
    pub email: String,
    pub action: String,
    pub target: String,
    pub ip: String,
    pub user_agent: String,
    pub details: String,
}

/// Une entrée par ligne d'audit insérée pendant l'appel de `Db::call` en
/// cours sur ce fil : (rowid, événement à émettre si la ligne est commitée).
/// `None` : déjà émis (insertion en autocommit), gardé pour détecter la
/// réutilisation d'un rowid.
type Pending = Vec<(i64, Option<AuditEvent>)>;

thread_local! {
    /// Tampon ouvert par `Db::call` (Some) le temps de la tâche.
    static PENDING_AUDIT: RefCell<Option<Pending>> = const { RefCell::new(None) };
}

/// Ouvre le tampon du fil et le referme à la destruction, panique comprise :
/// un fil du pool bloquant réutilisé ne garde jamais un tampon périmé.
struct AuditBuffer;

impl AuditBuffer {
    fn open() -> Self {
        PENDING_AUDIT.with(|p| *p.borrow_mut() = Some(Vec::new()));
        AuditBuffer
    }

    fn take(&self) -> Pending {
        PENDING_AUDIT.with(|p| p.borrow_mut().take()).unwrap_or_default()
    }
}

impl Drop for AuditBuffer {
    fn drop(&mut self) {
        PENDING_AUDIT.with(|p| *p.borrow_mut() = None);
    }
}

/// Appelée par `state::audit` juste après l'insertion de la ligne `rowid`.
/// - en autocommit, la ligne est déjà commitée : émission immédiate ;
/// - dans une transaction ouverte sous `Db::call` : mise en tampon, l'envoi
///   se décide à la fin de l'appel ;
/// - dans une transaction hors `Db::call` (connexion manipulée directement,
///   seulement en test) : émission immédiate, faute de point de contrôle.
pub(crate) fn defer_or_emit(c: &Connection, rowid: i64, ev: AuditEvent) {
    let autocommit = c.is_autocommit();
    let now = PENDING_AUDIT.with(|p| match p.borrow_mut().as_mut() {
        Some(buf) if autocommit => {
            buf.push((rowid, None));
            Some(ev)
        }
        Some(buf) => {
            buf.push((rowid, Some(ev)));
            None
        }
        None => Some(ev),
    });
    if let Some(ev) = now {
        deliver(&ev);
    }
}

/// Fin de `Db::call`, sous le verrou de l'écrivain : n'émet que les
/// événements dont la ligne existe (transaction commitée).
///
/// Une transaction annulée rend aussi son rowid AUTOINCREMENT (la séquence
/// est annulée avec elle) : une insertion suivante dans le même appel peut
/// le reprendre. Seule la DERNIÈRE insertion d'un rowid peut alors être la
/// ligne présente ; les précédentes sont jetées sans consulter la base.
fn flush_audit(c: &Connection, pending: Pending) {
    for (i, (rowid, ev)) in pending.iter().enumerate() {
        let Some(ev) = ev else { continue };
        if pending[i + 1..].iter().any(|(r, _)| r == rowid) {
            continue;
        }
        match c.query_row("SELECT 1 FROM audit WHERE id = ?1", [rowid], |_| Ok(())).optional() {
            Ok(Some(())) => deliver(ev),
            Ok(None) => {} // transaction annulée : ni base ni SIEM
            Err(e) => {
                // Doute : mieux vaut un événement de trop au SIEM qu'un manquant.
                tracing::warn!(error = %e, "contrôle de l'audit impossible : événement transmis");
                deliver(ev);
            }
        }
    }
}

/// Point de sortie unique des événements d'audit vers le syslog.
fn deliver(ev: &AuditEvent) {
    crate::syslog::emit(
        ev.at,
        ev.user_id.as_deref(),
        &ev.email,
        &ev.action,
        &ev.target,
        &ev.ip,
        &ev.user_agent,
        &ev.details,
    );
    #[cfg(test)]
    lock(&TEST_SINK).push(ev.clone());
}

/// Puits des tests : tout événement émis. Les tests tournent en parallèle,
/// chacun filtre sur une action qui lui est propre.
#[cfg(test)]
pub(crate) static TEST_SINK: Mutex<Vec<AuditEvent>> = Mutex::new(Vec::new());

// ------------------------------------------------------------ Réglages : génération

thread_local! {
    /// Un réglage a été écrit pendant l'appel de `Db::call` en cours sur ce fil.
    static SETTINGS_CHANGED: Cell<bool> = const { Cell::new(false) };
    /// Révision ouverte par le pont de compatibilité pendant cet appel : une
    /// ancienne route qui écrit deux blocs (réglages et quotas) ne crée
    /// qu'une révision.
    static BRIDGE_REVISION: Cell<Option<i64>> = const { Cell::new(None) };
}

/// Remet à zéro l'état « réglages » du fil au début de `Db::call` et à la
/// fin (panique comprise), comme `AuditBuffer`.
struct SettingsCall;

impl SettingsCall {
    fn open() -> Self {
        SETTINGS_CHANGED.with(|c| c.set(false));
        BRIDGE_REVISION.with(|c| c.set(None));
        SettingsCall
    }

    fn changed(&self) -> bool {
        SETTINGS_CHANGED.with(Cell::get)
    }
}

impl Drop for SettingsCall {
    fn drop(&mut self) {
        SETTINGS_CHANGED.with(|c| c.set(false));
        BRIDGE_REVISION.with(|c| c.set(None));
    }
}

/// À appeler par toute écriture de réglage (registre ou ancien bloc JSON) :
/// la génération augmente à la fin de l'appel de `Db::call`, et le cache des
/// réglages se recharge à la requête suivante.
pub fn mark_settings_changed() {
    SETTINGS_CHANGED.with(|c| c.set(true));
}

pub(crate) fn bridge_revision() -> Option<i64> {
    BRIDGE_REVISION.with(Cell::get)
}

pub(crate) fn set_bridge_revision(revision: i64) {
    BRIDGE_REVISION.with(|c| c.set(Some(revision)));
}

/// Lectures de l'ancien bloc `settings.org` (compteur des tests de charge,
/// `GET /api/test/counters`).
pub static LEGACY_READS: AtomicU64 = AtomicU64::new(0);

/// Anciens blocs JSON dont des champs sont repris dans le registre.
const BRIDGED_BLOBS: [&str; 4] = ["org", "attachments", "sso", "ldap"];

/// Lecture tolérante d'un réglage JSON : absent, il vaut sa valeur par défaut.
/// Lecture champ par champ : un champ illisible prend sa valeur par défaut
/// sans emporter les autres, et le journal le signale (un retour silencieux
/// aux valeurs par défaut masquerait la perte d'un réglage : 2FA imposée,
/// SSO…). Un texte qui n'est pas du JSON donne le défaut complet.
pub fn load_json<T>(c: &Connection, key: &str) -> ApiResult<T>
where
    T: serde::de::DeserializeOwned + serde::Serialize + Default,
{
    let raw: Option<String> = c.query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| r.get(0)).optional()?;
    Ok(parse_setting(key, raw))
}

fn parse_setting<T>(key: &str, raw: Option<String>) -> T
where
    T: serde::de::DeserializeOwned + serde::Serialize + Default,
{
    let Some(raw) = raw else { return T::default() };
    let stored: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(key, error = %e, "réglage illisible en base : valeurs par défaut appliquées");
            return T::default();
        }
    };
    if let Ok(v) = serde_json::from_value::<T>(stored.clone()) {
        return v;
    }
    // Échec global : reprise champ par champ à partir des valeurs par défaut.
    let mut merged = serde_json::to_value(T::default()).unwrap_or(serde_json::Value::Null);
    match (stored, merged.as_object_mut()) {
        (serde_json::Value::Object(fields), Some(target)) => {
            for (field, value) in fields {
                let previous = target.insert(field.clone(), value);
                let candidate = serde_json::Value::Object(target.clone());
                if serde_json::from_value::<T>(candidate).is_err() {
                    tracing::error!(key, field = %field, "champ de réglage illisible en base : valeur par défaut appliquée");
                    match previous {
                        Some(p) => target.insert(field, p),
                        None => target.remove(&field),
                    };
                }
            }
        }
        _ => tracing::error!(key, "réglage illisible en base : valeurs par défaut appliquées"),
    }
    serde_json::from_value(merged).unwrap_or_default()
}

/// Exécute `f` dans un point de sauvegarde : tout ou rien, dans une
/// transaction existante comme en autocommit.
fn in_savepoint<T>(c: &Connection, f: impl FnOnce(&Connection) -> ApiResult<T>) -> ApiResult<T> {
    c.execute_batch("SAVEPOINT reglages")?;
    match f(c) {
        Ok(v) => {
            c.execute_batch("RELEASE reglages")?;
            Ok(v)
        }
        Err(e) => {
            if let Err(err) = c.execute_batch("ROLLBACK TO reglages; RELEASE reglages") {
                tracing::error!(error = %err, "annulation du point de sauvegarde des réglages impossible");
            }
            Err(e)
        }
    }
}

fn write_blob(c: &Connection, key: &str, json: &str) -> ApiResult<()> {
    c.execute(
        "INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [key, json],
    )?;
    Ok(())
}

/// Écrit un bloc JSON de la table `settings`. Pont de compatibilité : pour
/// les blocs `attachments`, `sso` et `ldap`, les champs repris dans le
/// registre y sont importés (nouvelle révision), dans le même point de
/// sauvegarde. Les blocs `org`, `attachments`, `sso` et `ldap` rechargent le
/// cache des réglages (la page publique dépend de `sso` et `ldap`).
pub fn save_json<T: serde::Serialize>(c: &Connection, key: &str, value: &T) -> ApiResult<()> {
    let json = serde_json::to_value(value).map_err(|_| ApiError::internal("sérialisation des réglages"))?;
    if !BRIDGED_BLOBS.contains(&key) {
        return write_blob(c, key, &json.to_string());
    }
    in_savepoint(c, |c| {
        write_blob(c, key, &json.to_string())?;
        crate::settings_api::import_legacy_blob(c, key, &json)?;
        mark_settings_changed();
        Ok(())
    })
}

/// Ancien bloc `settings.org` (5 champs). Miroir du registre, conservé
/// tant que des consommateurs le lisent (pont de compatibilité).
pub fn load_settings(c: &Connection) -> ApiResult<OrgSettings> {
    LEGACY_READS.fetch_add(1, Ordering::Relaxed);
    let raw: Option<String> =
        c.query_row("SELECT value FROM settings WHERE key = 'org'", [], |r| r.get(0)).optional()?;
    Ok(parse_setting("org", raw))
}

/// Écrit l'ancien bloc `settings.org` ET importe ses 5 champs dans le
/// registre (nouvelle révision, historique « api »).
pub fn save_settings(c: &Connection, s: &OrgSettings) -> ApiResult<()> {
    save_json(c, "org", s)
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

// ------------------------------------------------------------ Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{audit, ClientMeta};
    use locksy_core::crypto::new_uuid;
    use std::path::PathBuf;

    /// Fichier de base neuf dans un dossier temporaire propre au test.
    fn temp_db() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("locksy-db-{}", new_uuid()));
        std::fs::create_dir_all(&dir).expect("dossier temporaire");
        dir.join("locksy.db")
    }

    fn table_exists(c: &Connection, name: &str) -> bool {
        c.query_row("SELECT COUNT(*) FROM sqlite_master WHERE name = ?1", [name], |r| r.get::<_, i64>(0)).unwrap() > 0
    }

    fn meta() -> ClientMeta {
        ClientMeta { ip: "192.0.2.1".into(), user_agent: "test".into() }
    }

    /// Événements émis pour une action donnée (les tests tournent en parallèle).
    fn emitted(action: &str) -> usize {
        lock(&TEST_SINK).iter().filter(|e| e.action == action).count()
    }

    fn audit_rows(path: &Path, action: &str) -> i64 {
        let c = Connection::open(path).unwrap();
        c.query_row("SELECT COUNT(*) FROM audit WHERE action = ?1", [action], |r| r.get(0)).unwrap()
    }

    #[test]
    fn un_palier_par_version() {
        assert_eq!(MIGRATIONS.len() as i64, SCHEMA_VERSION);
    }

    /// Réglages d'une version antérieure : un champ absent prend sa valeur par
    /// défaut sans perdre les autres (la 2FA imposée reste imposée) ; un JSON
    /// illisible retombe sur les valeurs par défaut au lieu de bloquer.
    #[test]
    fn reglages_lus_de_facon_tolerante() {
        let partiel: OrgSettings = parse_setting("org", Some(r#"{"require_2fa":true}"#.into()));
        assert!(partiel.require_2fa);
        assert_eq!(partiel.session_idle_minutes, OrgSettings::default().session_idle_minutes);
        let illisible: OrgSettings = parse_setting("org", Some("{pas du json".into()));
        assert!(!illisible.require_2fa);
        let absent: i64 = parse_setting("x", None);
        assert_eq!(absent, 0);
    }

    #[test]
    fn migration_d_une_base_v0() {
        let path = temp_db();
        {
            // Installation antérieure : schéma de base seul, sans user_version,
            // sans sso_subject ni directory_users ni attachments.
            let c = Connection::open(&path).unwrap();
            c.execute_batch(SCHEMA).unwrap();
            c.execute(
                "INSERT INTO users (id, email, name, role, kdf, auth_hash, wrapped_user_key,
                     recovery_wrapped_user_key, recovery_auth_hash, public_key, wrapped_private_key,
                     created_at, updated_at)
                 VALUES ('u1', 'alice@example.com', 'Alice', 'owner', 'k', 'h', 'w', 'rw', 'rh', 'p', 'wp', 1, 2)",
                [],
            )
            .unwrap();
            assert_eq!(schema_version(&c).unwrap(), 0);
            assert!(!has_column(&c, "users", "sso_subject").unwrap());
            assert!(!table_exists(&c, "attachments") && !table_exists(&c, "directory_users"));
        }
        drop(Db::open(&path).expect("migration"));
        let c = Connection::open(&path).unwrap();
        assert_eq!(schema_version(&c).unwrap(), SCHEMA_VERSION);
        assert!(has_column(&c, "users", "sso_subject").unwrap());
        assert!(has_column(&c, "directory_users", "source").unwrap());
        for name in
            ["attachments", "directory_users", "sso_tickets", "idx_users_sso", "idx_attachments_creator", "idx_audit_action_at"]
        {
            assert!(table_exists(&c, name), "{name}");
        }
        let (email, name): (String, String) =
            c.query_row("SELECT email, name FROM users WHERE id = 'u1'", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((email.as_str(), name.as_str()), ("alice@example.com", "Alice"));
        let mode: String = c.query_row("PRAGMA journal_mode", [], |r| r.get(0)).unwrap();
        assert_eq!(mode, "wal");
    }

    #[test]
    fn base_v1_passe_en_v2() {
        let path = temp_db();
        {
            let c = Connection::open(&path).unwrap();
            migrate_to_v1(&c).unwrap();
            c.execute_batch("PRAGMA user_version = 1").unwrap();
            assert!(!table_exists(&c, "idx_attachments_creator"));
        }
        drop(Db::open(&path).expect("migration v1 vers v2"));
        let c = Connection::open(&path).unwrap();
        assert_eq!(schema_version(&c).unwrap(), SCHEMA_VERSION);
        assert!(table_exists(&c, "idx_attachments_creator"));
        assert!(table_exists(&c, "idx_audit_action_at"));
    }

    fn dump_schema(p: &Path) -> (Vec<String>, i64) {
        let c = Connection::open(p).unwrap();
        let mut st = c.prepare("SELECT type || '|' || name || '|' || COALESCE(sql, '') FROM sqlite_master ORDER BY name").unwrap();
        let rows = st.query_map([], |r| r.get::<_, String>(0)).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
        (rows, schema_version(&c).unwrap())
    }

    #[test]
    fn reouverture_idempotente() {
        let path = temp_db();
        drop(Db::open(&path).unwrap());
        let first = dump_schema(&path);
        drop(Db::open(&path).unwrap());
        assert_eq!(dump_schema(&path), first);
        assert_eq!(first.1, SCHEMA_VERSION);
    }

    #[test]
    fn refus_d_une_version_future() {
        let path = temp_db();
        let future = SCHEMA_VERSION + 1;
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch(&format!("PRAGMA user_version = {future}")).unwrap();
        }
        let before = std::fs::read(&path).unwrap();
        let err = Db::open(&path).err().expect("ouverture refusée");
        match &err {
            OpenError::TooNew { found, supported } => assert_eq!((*found, *supported), (future, SCHEMA_VERSION)),
            other => panic!("erreur inattendue : {other}"),
        }
        let msg = err.to_string();
        assert!(msg.contains(&format!("v{future}")) && msg.contains(&format!("v{SCHEMA_VERSION}")), "{msg}");
        // Fichier intact : mêmes octets, aucune table, même version.
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let c = Connection::open(&path).unwrap();
        assert_eq!(schema_version(&c).unwrap(), future);
        assert_eq!(c.query_row("SELECT COUNT(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
    }

    #[tokio::test]
    async fn lectures_concurrentes() {
        let db = Db::open_with(&temp_db(), DbOptions { readers: 4 }).unwrap();
        // Chaque lecture attend les trois autres : sérialisées, elles se
        // bloqueraient et le délai expirerait.
        let barrier = Arc::new(std::sync::Barrier::new(4));
        let lecture = |b: Arc<std::sync::Barrier>| {
            db.read(move |c| {
                b.wait();
                Ok(c.query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, i64>(0))?)
            })
        };
        let all = async {
            tokio::join!(
                lecture(barrier.clone()),
                lecture(barrier.clone()),
                lecture(barrier.clone()),
                lecture(barrier.clone())
            )
        };
        let (a, b, c, d) = tokio::time::timeout(Duration::from_secs(5), all).await.expect("lectures parallèles");
        for n in [a, b, c, d] {
            assert_eq!(n.unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn wal_lecture_pendant_une_ecriture() {
        let db = Db::open_with(&temp_db(), DbOptions { readers: 2 }).unwrap();
        db.call(|c| save_json(c, "wal-test", &"ancienne".to_string())).await.unwrap();

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let writer = db.clone();
        let ecriture = tokio::spawn(async move {
            writer
                .call(move |c| {
                    let tx = c.transaction()?;
                    save_json(&tx, "wal-test", &"nouvelle".to_string())?;
                    let _ = started_tx.send(());
                    // Transaction d'écriture tenue jusqu'au signal.
                    let _ = release_rx.recv();
                    tx.commit()?;
                    Ok(())
                })
                .await
        });
        started_rx.await.unwrap();
        let pendant =
            tokio::time::timeout(Duration::from_secs(2), db.read(|c| load_json::<String>(c, "wal-test")))
                .await
                .expect("la lecture n'attend pas l'écrivain")
                .unwrap();
        assert_eq!(pendant, "ancienne");

        release_tx.send(()).unwrap();
        ecriture.await.unwrap().unwrap();
        // Un call terminé est visible de toute lecture lancée ensuite.
        assert_eq!(db.read(|c| load_json::<String>(c, "wal-test")).await.unwrap(), "nouvelle");
    }

    #[tokio::test]
    async fn read_apres_call_voit_l_ecriture() {
        let db = Db::open_with(&temp_db(), DbOptions { readers: 3 }).unwrap();
        for i in 0..20i64 {
            db.call(move |c| save_json(c, "compteur", &i)).await.unwrap();
            assert_eq!(db.read(|c| load_json::<i64>(c, "compteur")).await.unwrap(), i);
        }
    }

    #[tokio::test]
    async fn un_lecteur_refuse_d_ecrire() {
        for opts in [DbOptions { readers: 2 }, DbOptions { readers: 0 }] {
            let db = Db::open_with(&temp_db(), opts.clone()).unwrap();
            let r = db.read(|c| Ok(c.execute("INSERT INTO settings (key, value) VALUES ('x', 'y')", [])?)).await;
            assert!(r.is_err(), "{opts:?}");
            let action = format!("test.lecteur.{}", new_uuid());
            let a = action.clone();
            let r = db.read(move |c| audit(c, None, "", &a, "", &meta(), "")).await;
            assert!(r.is_err(), "audit sur un lecteur : {opts:?}");
            assert_eq!(emitted(&action), 0);
            // L'écrivain, lui, écrit toujours (la bride de lecture est levée).
            db.call(|c| save_json(c, "x", &1)).await.unwrap();
            assert_eq!(db.read(|c| load_json::<i64>(c, "x")).await.unwrap(), 1);
        }
    }

    #[tokio::test]
    async fn base_en_memoire_lit_par_l_ecrivain() {
        let db = Db::open(Path::new(":memory:")).unwrap();
        db.call(|c| save_json(c, "m", &7)).await.unwrap();
        assert_eq!(db.read(|c| load_json::<i64>(c, "m")).await.unwrap(), 7);
        db.checkpoint().await.unwrap();
    }

    #[tokio::test]
    async fn transaction_oubliee_annulee() {
        let db = Db::open_with(&temp_db(), DbOptions { readers: 1 }).unwrap();
        db.call(|c| {
            c.execute_batch("BEGIN")?;
            save_json(c, "oubli", &1)?;
            Ok(())
        })
        .await
        .unwrap();
        // Annulée à la fin de l'appel, et l'écrivain repart en autocommit.
        assert_eq!(db.read(|c| load_json::<i64>(c, "oubli")).await.unwrap(), 0);
        assert!(db.call(|c| Ok(c.is_autocommit())).await.unwrap());
    }

    #[tokio::test]
    async fn panique_dans_un_appel_sans_consequence() {
        let db = Db::open_with(&temp_db(), DbOptions { readers: 1 }).unwrap();
        let r: ApiResult<()> = db
            .call(|c| {
                let tx = c.transaction()?;
                save_json(&tx, "panique", &1)?;
                panic!("panique de test");
            })
            .await;
        assert!(r.is_err());
        assert_eq!(db.read(|c| load_json::<i64>(c, "panique")).await.unwrap(), 0);
        db.call(|c| save_json(c, "panique", &2)).await.unwrap();
        assert_eq!(db.read(|c| load_json::<i64>(c, "panique")).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn checkpoint_vide_le_wal() {
        let path = temp_db();
        let db = Db::open(&path).unwrap();
        db.call(|c| save_json(c, "k", &1)).await.unwrap();
        db.checkpoint().await.unwrap();
        let wal = path.with_file_name("locksy.db-wal");
        assert_eq!(std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0), 0);
    }

    #[tokio::test]
    async fn audit_autocommit_emis_meme_si_l_appel_echoue() {
        let path = temp_db();
        let db = Db::open(&path).unwrap();
        let action = format!("test.autocommit.{}", new_uuid());
        let a = action.clone();
        let r: ApiResult<()> = db
            .call(move |c| {
                audit(c, None, "a@example.com", &a, "", &meta(), "")?;
                Err(ApiError::bad_request("échec après l'audit"))
            })
            .await;
        assert!(r.is_err());
        assert_eq!(emitted(&action), 1);
        assert_eq!(audit_rows(&path, &action), 1);
    }

    #[tokio::test]
    async fn audit_d_une_transaction_annulee_non_emis() {
        let path = temp_db();
        let db = Db::open(&path).unwrap();
        let action = format!("test.rollback.{}", new_uuid());
        let a = action.clone();
        let r: ApiResult<()> = db
            .call(move |c| {
                let tx = c.transaction()?;
                audit(&tx, None, "a@example.com", &a, "", &meta(), "")?;
                Err(ApiError::bad_request("abandon avant commit"))
            })
            .await;
        assert!(r.is_err());
        assert_eq!(emitted(&action), 0);
        assert_eq!(audit_rows(&path, &action), 0);
    }

    #[tokio::test]
    async fn audit_d_une_transaction_commitee_emis_une_fois() {
        let path = temp_db();
        let db = Db::open(&path).unwrap();
        let action = format!("test.commit.{}", new_uuid());
        let a = action.clone();
        db.call(move |c| {
            let tx = c.transaction()?;
            audit(&tx, None, "a@example.com", &a, "cible", &meta(), "détails")?;
            tx.commit()?;
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(emitted(&action), 1);
        assert_eq!(audit_rows(&path, &action), 1);
        let ev = lock(&TEST_SINK).iter().find(|e| e.action == action).cloned().unwrap();
        assert_eq!((ev.target.as_str(), ev.details.as_str(), ev.ip.as_str()), ("cible", "détails", "192.0.2.1"));
    }

    #[tokio::test]
    async fn rowid_repris_apres_annulation_non_confondu() {
        let db = Db::open(&temp_db()).unwrap();
        let annule = format!("test.annule.{}", new_uuid());
        let garde = format!("test.garde.{}", new_uuid());
        let (a, g) = (annule.clone(), garde.clone());
        let ids = db
            .call(move |c| {
                let tx = c.transaction()?;
                audit(&tx, None, "", &a, "", &meta(), "")?;
                let first = tx.last_insert_rowid();
                drop(tx); // annulée : la séquence AUTOINCREMENT recule aussi
                let tx = c.transaction()?;
                audit(&tx, None, "", &g, "", &meta(), "")?;
                let second = tx.last_insert_rowid();
                tx.commit()?;
                Ok((first, second))
            })
            .await
            .unwrap();
        assert_eq!(ids.0, ids.1, "SQLite reprend le rowid de la ligne annulée");
        assert_eq!(emitted(&annule), 0);
        assert_eq!(emitted(&garde), 1);
    }

    /// Valeur d'une ligne du registre : (valeur JSON, updated_at).
    fn registry_row(c: &Connection, key: &str) -> Option<(String, i64)> {
        c.query_row("SELECT value, updated_at FROM org_settings WHERE key = ?1", [key], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()
            .unwrap()
    }

    fn count_of(c: &Connection, sql: &str) -> i64 {
        c.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn base_v2_passe_en_v3_avec_reprise_des_reglages() {
        let path = temp_db();
        {
            let c = Connection::open(&path).unwrap();
            migrate_to_v1(&c).unwrap();
            migrate_to_v2(&c).unwrap();
            c.execute_batch(
                r#"PRAGMA user_version = 2;
                   INSERT INTO settings (key, value) VALUES ('attachments', '{"per_user_mb":5,"total_mb":20480}');
                   INSERT INTO settings (key, value) VALUES ('sso', '{"enabled":true,"enforce":true,"public_url":"https://locksy.acme.fr","allowed_extension_ids":[]}');
                   INSERT INTO settings (key, value) VALUES ('ldap', '{"enforce":false,"sync_minutes":"abc"}');"#,
            )
            .unwrap();
        }
        drop(Db::open(&path).expect("migration v2 vers v3"));
        let c = Connection::open(&path).unwrap();
        assert_eq!(schema_version(&c).unwrap(), SCHEMA_VERSION, "la base migre jusqu'à la version courante (v4 : nom d'invité, empreintes)");
        for name in [
            "org_settings",
            "settings_meta",
            "settings_history",
            "user_prefs",
            "ldap_sync_history",
            "identity_tests",
            "totp_recovery_codes",
            "share_reveals",
            "sync_state",
            "sync_tombstones",
            "audit_anchors",
            "mail_queue",
            "idx_users_deprovision",
            "idx_shares_owner_state",
            "idx_items_change_seq",
            "trg_sync_items_update",
        ] {
            assert!(table_exists(&c, name), "{name}");
        }
        for (table, column, _) in COLUMNS_V3 {
            assert!(has_column(&c, table, column).unwrap(), "{table}.{column}");
        }
        // Seules les valeurs différentes du défaut sont reprises.
        assert_eq!(registry_row(&c, "attachment.quota_user_mib").map(|r| r.0), Some("5".into()));
        assert!(registry_row(&c, "attachment.quota_total_mib").is_none());
        assert_eq!(registry_row(&c, "sso.enforce").map(|r| r.0), Some("true".into()));
        assert_eq!(registry_row(&c, "instance.public_url").map(|r| r.0), Some(r#""https://locksy.acme.fr""#.into()));
        assert!(registry_row(&c, "ldap.enforce").is_none());
        assert_eq!(count_of(&c, "SELECT revision FROM settings_meta"), 1);
        assert_eq!(count_of(&c, "SELECT COUNT(*) FROM settings_history WHERE source = 'migration' AND revision = 1"), 3);
        assert_eq!(count_of(&c, "SELECT seq FROM sync_state"), 0);
        // Anciens blocs conservés (miroirs).
        assert_eq!(count_of(&c, "SELECT COUNT(*) FROM settings WHERE key IN ('attachments', 'sso', 'ldap')"), 3);
    }

    #[test]
    fn base_v0_avec_reglages_de_la_version_1() {
        let path = temp_db();
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch(SCHEMA).unwrap();
            c.execute(
                "INSERT INTO settings (key, value) VALUES ('org', ?1)",
                [r#"{"require_2fa":true,"session_idle_minutes":30}"#],
            )
            .unwrap();
        }
        drop(Db::open(&path).expect("migration v0 vers v3"));
        let c = Connection::open(&path).unwrap();
        assert_eq!(registry_row(&c, "twofa.required"), Some(("true".into(), 0)), "pas de délai de grâce rétroactif");
        assert_eq!(registry_row(&c, "twofa.grace_days").map(|r| r.0), Some("0".into()));
        let (idle, at) = registry_row(&c, "session.idle_minutes").unwrap();
        assert_eq!(idle, "30");
        assert!(at > 0);
        assert_eq!(count_of(&c, "SELECT COUNT(*) FROM settings_history WHERE source = 'migration'"), 3);
        assert_eq!(count_of(&c, "SELECT COUNT(*) FROM settings WHERE key = 'org'"), 1, "ancienne clé conservée");
        // Une base neuve n'a rien à reprendre.
        let fresh = temp_db();
        drop(Db::open(&fresh).unwrap());
        let c = Connection::open(&fresh).unwrap();
        assert_eq!(count_of(&c, "SELECT COUNT(*) FROM org_settings"), 0);
        assert_eq!(count_of(&c, "SELECT revision FROM settings_meta"), 0);
    }

    #[test]
    fn lecture_tolerante_champ_par_champ() {
        let cfg: locksy_core::api::LdapConfig =
            parse_setting("ldap", Some(r#"{"enforce":true,"sync_minutes":"abc","label":"AD"}"#.into()));
        assert!(cfg.enforce);
        assert_eq!(cfg.label, "AD");
        assert_eq!(cfg.sync_minutes, locksy_core::api::LdapConfig::default().sync_minutes);
        let corrompu: locksy_core::api::LdapConfig = parse_setting("ldap", Some(r#"{"enforce": tru"#.into()));
        assert!(!corrompu.enforce);
        let pas_un_objet: OrgSettings = parse_setting("org", Some("[1, 2]".into()));
        assert_eq!(pas_un_objet.session_idle_minutes, OrgSettings::default().session_idle_minutes);
    }

    #[tokio::test]
    async fn generation_des_reglages() {
        let db = Db::open(&temp_db()).unwrap();
        let g0 = db.settings_generation();
        db.call(|c| save_json(c, "scim", &serde_json::json!({ "token_hash": "x" }))).await.unwrap();
        assert_eq!(db.settings_generation(), g0, "bloc sans rapport avec les réglages");
        db.call(|c| save_settings(c, &OrgSettings { session_idle_minutes: 30, ..OrgSettings::default() })).await.unwrap();
        assert_eq!(db.settings_generation(), g0 + 1);
        // Pont : le bloc écrit est repris dans le registre, en une révision.
        let (v, rev, src): (String, i64, String) = db
            .read(|c| {
                Ok(c.query_row(
                    "SELECT o.value, m.revision, h.source FROM org_settings o, settings_meta m, settings_history h
                     WHERE o.key = 'session.idle_minutes' AND h.key = o.key",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )?)
            })
            .await
            .unwrap();
        assert_eq!((v.as_str(), rev, src.as_str()), ("30", 1, "api"));
        // Même valeur : pas de nouvelle révision.
        db.call(|c| save_settings(c, &OrgSettings { session_idle_minutes: 30, ..OrgSettings::default() })).await.unwrap();
        assert_eq!(db.read(|c| Ok(c.query_row("SELECT revision FROM settings_meta", [], |r| r.get::<_, i64>(0))?)).await.unwrap(), 1);
        // Champ refusé par le registre : ignoré, les autres repris.
        db.call(|c| save_json(c, "attachments", &serde_json::json!({ "per_user_mb": 0, "max_per_item": 7 }))).await.unwrap();
        let rows = db
            .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM org_settings WHERE key LIKE 'attachment.%'", [], |r| r.get::<_, i64>(0))?))
            .await
            .unwrap();
        assert_eq!(rows, 1);
        let before = LEGACY_READS.load(Ordering::Relaxed);
        db.read(load_settings).await.unwrap();
        assert!(LEGACY_READS.load(Ordering::Relaxed) > before);
    }

    /// Les deux requêtes de quota de pièces jointes lisent l'index couvrant
    /// (créateur, taille), jamais les données de la table.
    #[test]
    fn quotas_de_pieces_jointes_par_index_couvrant() {
        let path = temp_db();
        drop(Db::open(&path).unwrap());
        let c = Connection::open(&path).unwrap();
        assert!(table_exists(&c, "idx_attachments_quota"));
        for sql in [
            "SELECT COALESCE(SUM(size), 0) FROM attachments",
            "SELECT COALESCE(SUM(size), 0) FROM attachments WHERE created_by = 'u1'",
        ] {
            let mut st = c.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
            let plan: Vec<String> =
                st.query_map([], |r| r.get::<_, String>(3)).unwrap().collect::<Result<_, _>>().unwrap();
            assert!(
                plan.iter().any(|l| l.contains("COVERING INDEX idx_attachments_quota")),
                "{sql} : {plan:?}"
            );
        }
    }

    /// Pont : vider l'adresse publique par l'ancien écran SSO rétablit le
    /// défaut du registre ; le miroir ne remet pas l'ancienne adresse.
    #[tokio::test]
    async fn pont_adresse_publique_videe() {
        let db = Db::open(&temp_db()).unwrap();
        let sso = |url: &'static str| serde_json::json!({ "enabled": false, "enforce": false, "public_url": url });
        db.call(move |c| save_json(c, "sso", &sso("https://coffre.exemple.fr"))).await.unwrap();
        let row = |c: &Connection| -> ApiResult<Option<String>> {
            Ok(c.query_row("SELECT value FROM org_settings WHERE key = 'instance.public_url'", [], |r| r.get(0))
                .optional()?)
        };
        assert_eq!(db.read(row).await.unwrap().as_deref(), Some(r#""https://coffre.exemple.fr""#));
        db.call(move |c| save_json(c, "sso", &sso(""))).await.unwrap();
        assert_eq!(db.read(row).await.unwrap(), None);
        let blob: locksy_core::api::SsoConfig = db.read(|c| load_json(c, "sso")).await.unwrap();
        assert_eq!(blob.public_url, "");
    }

    /// Entier lu par une requête (tests).
    async fn int_of(db: &Db, sql: &'static str) -> i64 {
        db.read(move |c| Ok(c.query_row(sql, [], |r| r.get(0))?)).await.unwrap()
    }

    const ITEM_SEQ: &str = "SELECT change_seq FROM items WHERE id = 'i1'";

    /// Synchronisation incrémentale : déclencheurs actifs avec
    /// `trusted_schema = OFF` (posé par `configure_writer`).
    #[tokio::test]
    async fn declencheurs_de_synchronisation() {
        let db = Db::open(&temp_db()).unwrap();
        let trusted: i64 = db.call(|c| Ok(c.query_row("PRAGMA trusted_schema", [], |r| r.get(0))?)).await.unwrap();
        assert_eq!(trusted, 0);
        db.call(|c| {
            c.execute_batch(
                "INSERT INTO users (id, email, name, role, kdf, auth_hash, wrapped_user_key, recovery_wrapped_user_key,
                     recovery_auth_hash, public_key, wrapped_private_key, created_at, updated_at)
                 VALUES ('u1', 'u1@exemple.fr', 'U', 'user', 'k', 'h', 'w', 'rw', 'rh', 'p', 'wp', 0, 0);
                 INSERT INTO collections (id, enc_name, created_at, updated_at) VALUES ('c1', 'x', 0, 0), ('c2', 'y', 0, 0);
                 INSERT INTO memberships (collection_id, user_id, role, sealed_key, created_at) VALUES ('c1', 'u1', 'manager', 's', 0);
                 INSERT INTO items (id, collection_id, data, created_at, updated_at) VALUES ('i1', 'c1', 'a', 0, 0);",
            )?;
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(int_of(&db, "SELECT seq FROM sync_state").await, 4);
        assert_eq!(int_of(&db, ITEM_SEQ).await, 4);
        // Modification : nouvelle séquence, pas de pierre tombale.
        db.call(|c| Ok(c.execute("UPDATE items SET data = 'b', revision = 2 WHERE id = 'i1'", [])?)).await.unwrap();
        assert_eq!(int_of(&db, ITEM_SEQ).await, 5);
        // Déplacement : pierre tombale pour l'ancien coffre.
        db.call(|c| Ok(c.execute("UPDATE items SET collection_id = 'c2' WHERE id = 'i1'", [])?)).await.unwrap();
        let tomb: (String, String, Option<i64>) = db
            .read(|c| {
                Ok(c.query_row("SELECT kind, collection_id, at FROM sync_tombstones ORDER BY seq DESC LIMIT 1", [], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })?)
            })
            .await
            .unwrap();
        assert_eq!((tomb.0.as_str(), tomb.1.as_str()), ("item", "c1"));
        assert!(tomb.2.is_some_and(|at| at > 0), "date posée malgré trusted_schema = OFF");
        assert!(int_of(&db, ITEM_SEQ).await > 6, "séquence postérieure à la pierre tombale");
        // Suppression d'un coffre : cascades (élément, appartenance) comprises.
        db.call(|c| Ok(c.execute("DELETE FROM collections WHERE id = 'c2'", [])?)).await.unwrap();
        db.call(|c| Ok(c.execute("DELETE FROM collections WHERE id = 'c1'", [])?)).await.unwrap();
        let kinds: Vec<String> = db
            .read(|c| {
                let mut st = c.prepare("SELECT kind || ':' || object_id FROM sync_tombstones ORDER BY seq")?;
                let v = st.query_map([], |r| r.get(0))?.collect::<Result<Vec<_>, _>>()?;
                Ok(v)
            })
            .await
            .unwrap();
        for expected in ["item:i1", "collection:c2", "membership:c1", "collection:c1"] {
            assert!(kinds.iter().any(|k| k == expected), "{expected} absent de {kinds:?}");
        }
        let membership_user: Option<String> = db
            .read(|c| Ok(c.query_row("SELECT user_id FROM sync_tombstones WHERE kind = 'membership'", [], |r| r.get(0))?))
            .await
            .unwrap();
        assert_eq!(membership_user.as_deref(), Some("u1"));
    }

    #[test]
    fn message_d_erreur_de_migration() {
        let e = OpenError::Migration { to: 2, source: rusqlite::Error::InvalidQuery };
        assert!(e.to_string().contains("v2"));
        assert!(std::error::Error::source(&e).is_some());
    }
}
