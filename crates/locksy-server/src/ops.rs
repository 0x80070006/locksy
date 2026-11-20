//! Exploitation : clé serveur, sauvegarde et vérification hors ligne,
//! disponibilité (`/api/ready`), identifiant de requête et journal des requêtes.

use crate::config::ServerConfig;
use crate::db;
use crate::error::ApiError;
use crate::state::AppState;
use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use crate::error::Json;
use locksy_core::crypto::{new_uuid, random_bytes, SecretKey};
use rusqlite::{Connection, OpenFlags};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tower_http::classify::ServerErrorsFailureClass;
use tracing::Span;

/// Vrai dès que l'arrêt est demandé : `/api/ready` répond alors 503, pour que
/// le répartiteur de charge cesse d'envoyer du trafic pendant le délai de grâce.
pub static SHUTTING_DOWN: AtomicBool = AtomicBool::new(false);

/// Délai maximal de la sonde de disponibilité sur la base.
const READY_TIMEOUT: Duration = Duration::from_secs(2);

// ------------------------------------------------------------ Fichiers

/// Suffixe aléatoire des fichiers temporaires.
fn random_suffix() -> String {
    random_bytes(6).iter().map(|b| format!("{b:02x}")).collect()
}

/// `<dossier>/<nom>.tmp-<aléa>`, dans le même dossier que `path` (le
/// renommage final reste ainsi atomique, sur le même système de fichiers).
fn temp_path(path: &Path) -> PathBuf {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "fichier".into());
    path.with_file_name(format!("{name}.tmp-{}", random_suffix()))
}

/// Crée un dossier et ses parents ; ceux créés ici sont en 0700 (unix).
pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// Supprime le fichier temporaire s'il n'a pas été renommé (échec en route).
struct TempGuard(Option<PathBuf>);

impl TempGuard {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        if let Some(p) = &self.0 {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Synchronise le dossier (unix) : le renommage survit à une coupure.
fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Écrit `bytes` dans `path` de façon atomique : fichier temporaire dans le
/// même dossier (créé avec les droits `mode` sous unix), écriture, fsync,
/// renommage, puis fsync du dossier. Un lecteur voit l'ancien contenu ou le
/// nouveau, jamais un fichier partiel.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    create_private_dir(&parent)?;
    let tmp = temp_path(path);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = opts.open(&tmp)?;
    let mut guard = TempGuard(Some(tmp.clone()));
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path)?;
    guard.disarm();
    sync_dir(&parent);
    Ok(())
}

#[cfg(unix)]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o777
}

// ------------------------------------------------------------ Clé serveur

fn missing_key_message(path: &Path) -> String {
    format!(
        "clé serveur introuvable ({}) alors que la base contient déjà des comptes.\n\
         Sans cette clé, les secrets de double authentification, le mot de passe du compte LDAP \
         et le secret client SSO enregistrés sont illisibles.\n\
         - Restaurez server.key depuis votre sauvegarde (elle se range séparément de la base).\n\
         - Si LOCKSY_SERVER_KEY_FILE a changé, déplacez l'ancienne clé vers ce nouveau chemin.\n\
         - En dernier recours seulement, LOCKSY_SERVER_KEY_RESET=true génère une nouvelle clé : \
         la 2FA de chaque compte, la liaison LDAP et le SSO devront alors être reconfigurés.",
        path.display()
    )
}

/// Charge la clé serveur, ou la crée si aucun compte n'existe encore.
///
/// Une clé absente alors que la base contient des comptes est presque
/// toujours une erreur d'exploitation (volume mal monté, chemin modifié) :
/// en générer une nouvelle rendrait silencieusement illisibles les secrets
/// protégés par l'ancienne. Le démarrage est donc refusé, sauf `reset`.
pub fn load_or_create_server_key(path: &Path, db_has_users: bool, reset: bool) -> Result<SecretKey, String> {
    match std::fs::metadata(path) {
        Ok(meta) => {
            if !meta.is_file() {
                return Err(format!("clé serveur {} : ce n'est pas un fichier", path.display()));
            }
            let raw = std::fs::read(path).map_err(|e| format!("clé serveur {} illisible : {e}", path.display()))?;
            let key = SecretKey::from_slice(&raw).map_err(|_| {
                format!(
                    "server.key corrompue ({}) : 32 octets attendus, {} trouvés. Restaurez-la depuis la sauvegarde.",
                    path.display(),
                    raw.len()
                )
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = mode_of(&meta);
                if mode & 0o077 != 0 {
                    tracing::warn!(
                        chemin = %path.display(),
                        "droits de la clé serveur trop ouverts ({mode:o}) : ramenés à 600"
                    );
                    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
                        tracing::warn!("correction des droits de la clé serveur impossible : {e}");
                    }
                }
            }
            Ok(key)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if db_has_users && !reset {
                return Err(missing_key_message(path));
            }
            if db_has_users {
                tracing::warn!(
                    "LOCKSY_SERVER_KEY_RESET=true : nouvelle clé serveur alors que des comptes existent ; \
                     la 2FA des comptes, la liaison LDAP et le SSO doivent être reconfigurés"
                );
            }
            let key = SecretKey::generate();
            write_atomic(path, key.as_bytes(), 0o600)
                .map_err(|e| format!("écriture de la clé serveur {} impossible : {e}", path.display()))?;
            tracing::info!(chemin = %path.display(), "nouvelle clé serveur générée");
            Ok(key)
        }
        Err(e) => Err(format!("clé serveur {} inaccessible : {e}", path.display())),
    }
}

// ------------------------------------------------------------ Sauvegarde

/// Ouvre une base existante en lecture seule, sans jamais la créer ni la migrer.
fn open_read_only(path: &Path) -> rusqlite::Result<Connection> {
    let c = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI)?;
    c.busy_timeout(Duration::from_millis(5000))?;
    Ok(c)
}

/// Résultat de `PRAGMA integrity_check` : `Ok` si la base est saine, sinon
/// les premiers problèmes signalés.
fn integrity(c: &Connection) -> Result<(), String> {
    let mut st = c.prepare("PRAGMA integrity_check").map_err(|e| e.to_string())?;
    let rows = st
        .query_map([], |r| r.get::<_, String>(0))
        .and_then(|it| it.collect::<rusqlite::Result<Vec<_>>>())
        .map_err(|e| e.to_string())?;
    if rows.len() == 1 && rows[0] == "ok" {
        Ok(())
    } else {
        Err(rows.into_iter().take(5).collect::<Vec<_>>().join(" ; "))
    }
}

fn human_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} Mo", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} Ko", bytes as f64 / 1024.0)
    }
}

/// Sauvegarde à chaud de la base (`VACUUM INTO`), vérifiée puis renommée
/// atomiquement vers `dest`. Avec `with_key`, copie aussi la clé serveur dans
/// `<dest>.server.key`. Fonctionne serveur démarré (lecture en WAL) ; la base
/// de production n'est jamais modifiée.
pub fn backup(cfg: &ServerConfig, dest: &Path, with_key: bool, force: bool) -> Result<(), String> {
    let source = &cfg.db_path;
    if !source.is_file() {
        return Err(format!("base introuvable : {} (vérifiez LOCKSY_DATA)", source.display()));
    }
    let key_dest = PathBuf::from(format!("{}.server.key", dest.display()));
    if !force {
        if dest.exists() {
            return Err(format!("{} existe déjà : choisissez un autre nom ou ajoutez --force", dest.display()));
        }
        if with_key && key_dest.exists() {
            return Err(format!("{} existe déjà : choisissez un autre nom ou ajoutez --force", key_dest.display()));
        }
    }
    if dest.is_dir() {
        return Err(format!("{} est un dossier : indiquez un nom de fichier", dest.display()));
    }
    let key_bytes = if with_key {
        let raw = std::fs::read(&cfg.server_key_file)
            .map_err(|e| format!("clé serveur {} illisible : {e}", cfg.server_key_file.display()))?;
        if raw.len() != 32 {
            return Err(format!("clé serveur {} corrompue : 32 octets attendus", cfg.server_key_file.display()));
        }
        Some(raw)
    } else {
        None
    };
    if let Some(parent) = dest.parent().filter(|p| !p.as_os_str().is_empty()) {
        if !parent.is_dir() {
            return Err(format!("dossier de destination introuvable : {}", parent.display()));
        }
    }

    let src = open_read_only(source).map_err(|e| format!("base {} illisible : {e}", source.display()))?;
    let version = db::schema_version(&src).map_err(|e| format!("lecture de la version du schéma : {e}"))?;
    if version > db::SCHEMA_VERSION {
        return Err(format!(
            "la base est au schéma v{version}, plus récent que ce programme (v{}) : utilisez le binaire à jour",
            db::SCHEMA_VERSION
        ));
    }

    let tmp = temp_path(dest);
    let mut guard = TempGuard(Some(tmp.clone()));
    let tmp_str = tmp.to_str().ok_or("chemin de destination non UTF-8")?;
    // Chemin en paramètre lié : jamais interpolé dans le SQL.
    src.execute("VACUUM INTO ?1", [tmp_str]).map_err(|e| format!("copie de la base impossible : {e}"))?;
    drop(src);

    {
        // Ouverture en écriture (sans création) : la fermeture nettoie un
        // éventuel journal WAL de la copie.
        let copy = Connection::open_with_flags(&tmp, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_URI)
            .map_err(|e| format!("copie illisible : {e}"))?;
        integrity(&copy).map_err(|e| format!("copie corrompue (integrity_check) : {e}"))?;
        let copied = db::schema_version(&copy).map_err(|e| format!("copie illisible : {e}"))?;
        if copied != version {
            return Err(format!("version du schéma de la copie (v{copied}) différente de la source (v{version})"));
        }
    }
    for suffix in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{tmp_str}{suffix}"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("droits de la copie : {e}"))?;
    }
    std::fs::rename(&tmp, dest).map_err(|e| format!("renommage vers {} impossible : {e}", dest.display()))?;
    guard.disarm();
    if let Some(parent) = dest.parent().filter(|p| !p.as_os_str().is_empty()) {
        sync_dir(parent);
    }

    let size = std::fs::metadata(dest).map(|m| m.len()).unwrap_or(0);
    println!("Sauvegarde écrite : {} ({}, schéma v{version})", dest.display(), human_size(size));
    if let Some(raw) = key_bytes {
        write_atomic(&key_dest, &raw, 0o600)
            .map_err(|e| format!("copie de la clé serveur vers {} impossible : {e}", key_dest.display()))?;
        println!("Clé serveur copiée : {}", key_dest.display());
        println!(
            "ATTENTION : rangez la clé serveur SÉPARÉMENT de la sauvegarde de la base (autre support, accès restreint)."
        );
    }
    println!(
        "Restauration : arrêtez le serveur, remplacez locksy.db par cette copie, supprimez locksy.db-wal et \
         locksy.db-shm s'ils existent, remettez la clé server.key d'origine, puis redémarrez."
    );
    Ok(())
}

// ------------------------------------------------------------ Vérification

/// Lignes du rapport de `check` et nombre d'erreurs.
#[derive(Default)]
struct Report {
    lines: Vec<String>,
    errors: usize,
}

impl Report {
    fn ok(&mut self, m: impl AsRef<str>) {
        self.lines.push(format!("OK        {}", m.as_ref()));
    }
    fn warn(&mut self, m: impl AsRef<str>) {
        self.lines.push(format!("ATTENTION {}", m.as_ref()));
    }
    fn err(&mut self, m: impl AsRef<str>) {
        self.errors += 1;
        self.lines.push(format!("ERREUR    {}", m.as_ref()));
    }
}

/// Vérifie l'installation sans rien écrire, créer ni migrer. Affiche le
/// rapport et renvoie le code de sortie : 0 sans erreur, 1 en cas d'erreur,
/// 2 si la configuration est illisible.
pub fn check(cfg: &Result<ServerConfig, Vec<String>>) -> i32 {
    let (lines, code) = check_report(cfg);
    for l in lines {
        println!("{l}");
    }
    code
}

fn check_report(cfg: &Result<ServerConfig, Vec<String>>) -> (Vec<String>, i32) {
    let mut r = Report::default();
    let cfg = match cfg {
        Ok(c) => c,
        Err(errors) => {
            for e in errors {
                r.err(format!("configuration : {e}"));
            }
            r.lines.push("Configuration invalide : corrigez les variables ci-dessus.".into());
            return (r.lines, 2);
        }
    };
    let app = &cfg.app;
    r.ok(format!("configuration valide (écoute {}, données {})", app.bind, app.data_dir.display()));

    match std::fs::metadata(&app.data_dir) {
        Ok(m) if m.is_dir() => match std::fs::read_dir(&app.data_dir) {
            Ok(_) if m.permissions().readonly() => {
                r.err(format!("dossier de données {} en lecture seule", app.data_dir.display()))
            }
            Ok(_) => r.ok(format!("dossier de données accessible ({})", app.data_dir.display())),
            Err(e) => r.err(format!("dossier de données {} illisible : {e}", app.data_dir.display())),
        },
        Ok(_) => r.err(format!("{} n'est pas un dossier (LOCKSY_DATA)", app.data_dir.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            r.warn(format!("dossier de données {} absent : il sera créé au démarrage", app.data_dir.display()))
        }
        Err(e) => r.err(format!("dossier de données {} inaccessible : {e}", app.data_dir.display())),
    }

    // Base (ou base d'une installation antérieure, reprise au démarrage).
    let legacy = app.data_dir.join("verrou.db");
    let db_file = if cfg.db_path.is_file() {
        Some(cfg.db_path.clone())
    } else if legacy.is_file() {
        r.warn(format!("base d'une installation antérieure ({}) : elle sera reprise au démarrage", legacy.display()));
        Some(legacy)
    } else {
        r.warn(format!("base absente ({}) : une base neuve sera créée au démarrage", cfg.db_path.display()));
        None
    };
    let mut users = 0i64;
    if let Some(path) = db_file {
        match open_read_only(&path) {
            Err(e) => r.err(format!("base {} illisible : {e}", path.display())),
            Ok(c) => {
                match db::schema_version(&c) {
                    Err(e) => r.err(format!("version du schéma illisible : {e}")),
                    Ok(0) => r.warn("schéma v0 (installation antérieure) : la base sera migrée au démarrage"),
                    Ok(v) if v < db::SCHEMA_VERSION => {
                        r.warn(format!("schéma v{v} : la base sera migrée vers la v{} au démarrage", db::SCHEMA_VERSION))
                    }
                    Ok(v) if v == db::SCHEMA_VERSION => r.ok(format!("schéma v{v} (à jour)")),
                    Ok(v) => r.err(format!(
                        "schéma v{v}, plus récent que ce programme (v{}) : mettez à jour le binaire \
                         ou restaurez une sauvegarde compatible",
                        db::SCHEMA_VERSION
                    )),
                }
                match integrity(&c) {
                    Ok(()) => r.ok("intégrité de la base vérifiée (integrity_check)"),
                    Err(e) => r.err(format!("intégrité de la base : {e}")),
                }
                let violations = foreign_key_violations(&c);
                match violations {
                    Ok(0) => r.ok("aucune violation de clé étrangère"),
                    Ok(n) => r.warn(format!("{n} violation(s) de clé étrangère (PRAGMA foreign_key_check)")),
                    Err(e) => r.err(format!("contrôle des clés étrangères impossible : {e}")),
                }
                users = c.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0)).unwrap_or(0);
                r.ok(format!("{users} compte(s) dans la base"));
            }
        }
    }

    let key = &cfg.server_key_file;
    match std::fs::metadata(key) {
        Ok(m) if !m.is_file() => r.err(format!("clé serveur {} : ce n'est pas un fichier", key.display())),
        Ok(m) if m.len() != 32 => {
            r.err(format!("server.key corrompue ({}) : 32 octets attendus, {} trouvés", key.display(), m.len()))
        }
        Ok(_m) => match std::fs::File::open(key) {
            Err(e) => r.err(format!("clé serveur {} illisible : {e}", key.display())),
            Ok(_) => {
                r.ok(format!("clé serveur présente ({})", key.display()));
                #[cfg(unix)]
                {
                    let mode = mode_of(&_m);
                    if mode & 0o077 != 0 {
                        r.warn(format!(
                            "droits de la clé serveur trop ouverts ({mode:o}) : ramenés à 600 au démarrage \
                             (ou chmod 600 {})",
                            key.display()
                        ));
                    }
                }
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if users > 0 {
                r.err(missing_key_message(key));
            } else {
                r.ok(format!("clé serveur absente ({}) : elle sera générée au démarrage", key.display()));
            }
        }
        Err(e) => r.err(format!("clé serveur {} inaccessible : {e}", key.display())),
    }

    let index = app.web_dir.join("index.html");
    if index.is_file() {
        r.ok(format!("interface web présente ({})", app.web_dir.display()));
    } else {
        r.warn(format!(
            "interface web absente ({}) : seules l'API, l'extension et le client de bureau fonctionneront (LOCKSY_WEB)",
            index.display()
        ));
    }

    match &cfg.tls {
        None => r.ok("HTTPS intégré non configuré (HTTP, ou TLS terminé par un proxy inverse)"),
        Some((cert, key)) => {
            use rustls::pki_types::pem::PemObject;
            use rustls::pki_types::{CertificateDer, PrivateKeyDer};
            match CertificateDer::pem_file_iter(cert).map(|it| it.collect::<Result<Vec<_>, _>>()) {
                Ok(Ok(certs)) if !certs.is_empty() => {
                    r.ok(format!("certificat TLS lisible ({}, {} certificat(s))", cert.display(), certs.len()))
                }
                Ok(Ok(_)) => r.err(format!("certificat TLS {} : aucun certificat PEM", cert.display())),
                Ok(Err(e)) | Err(e) => r.err(format!("certificat TLS {} illisible : {e}", cert.display())),
            }
            match PrivateKeyDer::from_pem_file(key) {
                Ok(_) => r.ok(format!("clé TLS lisible ({})", key.display())),
                Err(e) => r.err(format!("clé TLS {} illisible : {e}", key.display())),
            }
        }
    }

    match &cfg.syslog {
        None => r.ok("envoi syslog désactivé"),
        Some(s) => {
            r.ok(format!("cible syslog valide : {s}"));
            if let Some(ca) = &cfg.syslog_ca_file {
                match crate::syslog::load_ca_file(ca) {
                    Ok(certs) => r.ok(format!("autorité syslog lisible ({}, {} certificat(s))", ca.display(), certs.len())),
                    Err(e) => r.err(format!("autorité syslog {} : {e}", ca.display())),
                }
            }
        }
    }

    let code = if r.errors > 0 { 1 } else { 0 };
    r.lines.push(if code == 0 {
        "Vérification terminée : aucune erreur.".into()
    } else {
        format!("Vérification terminée : {} erreur(s).", r.errors)
    });
    (r.lines, code)
}

/// Nombre de lignes signalées par `PRAGMA foreign_key_check`.
fn foreign_key_violations(c: &Connection) -> rusqlite::Result<usize> {
    let mut st = c.prepare("PRAGMA foreign_key_check")?;
    let n = st.query_map([], |_| Ok(()))?.count();
    Ok(n)
}

// ------------------------------------------------------------ Disponibilité

#[derive(serde::Serialize)]
struct ReadyBody {
    status: &'static str,
    version: &'static str,
    schema_version: i64,
}

/// GET /api/ready : le serveur accepte du trafic (base joignable, arrêt non
/// commencé). Distinct de /api/health, qui décrit l'instance.
pub async fn ready(State(state): State<AppState>) -> Response {
    ready_with(&state, SHUTTING_DOWN.load(Ordering::SeqCst)).await
}

async fn ready_with(state: &AppState, shutting_down: bool) -> Response {
    if shutting_down {
        return ApiError::unavailable("not_ready", "Arrêt du serveur en cours.").into_response();
    }
    // Par le pool de lecteurs : la sonde est publique, elle ne doit ni
    // concurrencer l'écrivain ni empiler des fils bloquants derrière son
    // verrou (l'attente d'un lecteur est asynchrone et s'annule au délai).
    let probe = state.db.read(|c| Ok(c.query_row("SELECT COUNT(*) FROM settings", [], |r| r.get::<_, i64>(0))?));
    match tokio::time::timeout(READY_TIMEOUT, probe).await {
        Ok(Ok(_)) => Json(ReadyBody {
            status: "ready",
            version: env!("CARGO_PKG_VERSION"),
            schema_version: db::SCHEMA_VERSION,
        })
        .into_response(),
        Ok(Err(_)) => ApiError::unavailable("not_ready", "Base de données indisponible.").into_response(),
        Err(_) => ApiError::unavailable("not_ready", "Base de données trop lente à répondre.").into_response(),
    }
}

// ------------------------------------------------------------ Identifiant de requête

/// En-tête portant l'identifiant de requête.
pub const X_REQUEST_ID: &str = "x-request-id";

/// Identifiant de la requête en cours (extension de requête).
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

/// Identifiant fourni par le client ou le proxy : accepté s'il est court et
/// sans caractère spécial (il est recopié dans les journaux et la réponse).
fn valid_request_id(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// Attribue un identifiant à chaque requête : repris de `x-request-id` s'il
/// est valide, sinon tiré au hasard. Il est placé dans la requête (en-tête et
/// extension `RequestId`) et renvoyé dans la réponse.
pub async fn request_id(mut req: Request, next: Next) -> Response {
    let id = req
        .headers()
        .get(X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|v| valid_request_id(v))
        .map(str::to_string)
        .unwrap_or_else(new_uuid);
    let value = HeaderValue::from_str(&id).ok();
    if let Some(v) = &value {
        req.headers_mut().insert(HeaderName::from_static(X_REQUEST_ID), v.clone());
    }
    req.extensions_mut().insert(RequestId(id));
    let mut res = next.run(req).await;
    if let Some(v) = value {
        res.headers_mut().insert(HeaderName::from_static(X_REQUEST_ID), v);
    }
    res
}

// ------------------------------------------------------------ Journal des requêtes

/// Span `requete` : identifiant, méthode et route GÉNÉRIQUE (`MatchedPath`).
/// Jamais l'URI réelle, la requête, les en-têtes ni le corps : certains
/// chemins portent des secrets (jeton d'invitation, identifiant de partage,
/// code OAuth dans la requête du retour SSO).
#[derive(Clone, Copy, Debug, Default)]
pub struct MakeRequestSpan;

impl<B> tower_http::trace::MakeSpan<B> for MakeRequestSpan {
    fn make_span(&mut self, req: &axum::http::Request<B>) -> Span {
        let route = req.extensions().get::<MatchedPath>().map(|p| p.as_str()).unwrap_or("statique");
        let id = req.extensions().get::<RequestId>().map(|r| r.0.as_str()).unwrap_or("");
        tracing::info_span!("requete", request_id = %id, method = %req.method(), route = %route)
    }
}

/// Fin de requête au niveau INFO : statut et latence.
#[derive(Clone, Copy, Debug, Default)]
pub struct LogResponse;

impl<B> tower_http::trace::OnResponse<B> for LogResponse {
    fn on_response(self, res: &axum::http::Response<B>, latency: Duration, _span: &Span) {
        tracing::info!(status = res.status().as_u16(), latence_ms = latency.as_millis() as u64, "réponse");
    }
}

/// Erreur serveur (5xx ou échec du service) au niveau WARN.
#[derive(Clone, Copy, Debug, Default)]
pub struct LogFailure;

impl tower_http::trace::OnFailure<ServerErrorsFailureClass> for LogFailure {
    fn on_failure(&mut self, failure: ServerErrorsFailureClass, latency: Duration, _span: &Span) {
        tracing::warn!(classe = %failure, latence_ms = latency.as_millis() as u64, "échec de la requête");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;

    fn temp_dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("locksy-ops-{}", new_uuid()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn config_for(dir: &Path) -> ServerConfig {
        let data = dir.join("data");
        let web = dir.join("web");
        let get = move |k: &str| match k {
            "LOCKSY_DATA" => Some(data.to_string_lossy().into_owned()),
            "LOCKSY_WEB" => Some(web.to_string_lossy().into_owned()),
            _ => None,
        };
        crate::config::from_lookup(get).unwrap()
    }

    fn insert_user(c: &Connection, email: &str) -> crate::error::ApiResult<()> {
        c.execute(
            "INSERT INTO users (id, email, name, role, kdf, auth_hash, wrapped_user_key, recovery_wrapped_user_key,
                                recovery_auth_hash, public_key, wrapped_private_key, created_at, updated_at)
             VALUES (?1, ?2, 'Test', 'owner', '{}', 'h', 'w', 'rw', 'rh', 'pk', 'wpk', 0, 0)",
            params![new_uuid(), email],
        )?;
        Ok(())
    }

    /// Installation complète dans un dossier temporaire : base peuplée, clé, interface web.
    async fn installation(dir: &Path) -> ServerConfig {
        let cfg = config_for(dir);
        std::fs::create_dir_all(&cfg.app.data_dir).unwrap();
        std::fs::create_dir_all(&cfg.app.web_dir).unwrap();
        std::fs::write(cfg.app.web_dir.join("index.html"), "<!doctype html>").unwrap();
        let db = db::Db::open(&cfg.db_path).unwrap();
        db.call(|c| {
            insert_user(c, "a@example.com")?;
            c.execute("INSERT INTO settings (key, value) VALUES ('org', '{}')", [])?;
            Ok(())
        })
        .await
        .unwrap();
        drop(db);
        load_or_create_server_key(&cfg.server_key_file, false, false).unwrap();
        cfg
    }

    /// Message d'un refus attendu (`SecretKey` n'implémente pas Debug).
    fn refus(r: Result<SecretKey, String>) -> String {
        match r {
            Ok(_) => panic!("refus attendu"),
            Err(e) => e,
        }
    }

    fn leftovers(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp-"))
            .collect()
    }

    #[test]
    fn ecriture_atomique() {
        let dir = temp_dir();
        let path = dir.join("sous").join("dossier").join("secret.bin");
        write_atomic(&path, b"premier", 0o600).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"premier");
        // Remplacement d'un fichier existant.
        write_atomic(&path, b"second", 0o600).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        assert!(leftovers(path.parent().unwrap()).is_empty());
        #[cfg(unix)]
        {
            assert_eq!(mode_of(&std::fs::metadata(&path).unwrap()), 0o600);
            // Les dossiers créés pour l'occasion sont privés.
            assert_eq!(mode_of(&std::fs::metadata(path.parent().unwrap()).unwrap()), 0o700);
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cle_absente_avec_comptes_refusee() {
        let dir = temp_dir();
        let path = dir.join("server.key");
        let err = refus(load_or_create_server_key(&path, true, false));
        assert!(err.contains("LOCKSY_SERVER_KEY_RESET=true") && err.contains("LOCKSY_SERVER_KEY_FILE"), "{err}");
        assert!(!path.exists(), "aucune clé ne doit être créée");
        // Dernier recours explicite.
        let key = load_or_create_server_key(&path, true, true).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), key.as_bytes());
        // Rechargée à l'identique ensuite, comptes ou pas.
        let again = load_or_create_server_key(&path, true, false).unwrap();
        assert_eq!(again.as_bytes(), key.as_bytes());
        assert!(leftovers(&dir).is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cle_neuve_sans_compte() {
        let dir = temp_dir();
        let path = dir.join("cles").join("server.key");
        let key = load_or_create_server_key(&path, false, false).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), key.as_bytes());
        #[cfg(unix)]
        assert_eq!(mode_of(&std::fs::metadata(&path).unwrap()), 0o600);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn droits_trop_ouverts_corriges() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir();
        let path = dir.join("server.key");
        std::fs::write(&path, [7u8; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        load_or_create_server_key(&path, true, false).unwrap();
        assert_eq!(mode_of(&std::fs::metadata(&path).unwrap()), 0o600);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cle_corrompue_refusee() {
        let dir = temp_dir();
        let path = dir.join("server.key");
        std::fs::write(&path, b"trop court").unwrap();
        let err = refus(load_or_create_server_key(&path, false, false));
        assert!(err.contains("server.key corrompue"), "{err}");
        // Le fichier corrompu n'est jamais écrasé, même avec reset.
        assert!(load_or_create_server_key(&path, false, true).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"trop court");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn sauvegarde_verifiee() {
        let dir = temp_dir();
        let cfg = installation(&dir).await;
        let dest = dir.join("sauvegarde.db");
        backup(&cfg, &dest, false, false).unwrap();

        let copy = Connection::open_with_flags(&dest, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        assert!(integrity(&copy).is_ok());
        assert_eq!(db::schema_version(&copy).unwrap(), db::SCHEMA_VERSION);
        let n: i64 = copy.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
        drop(copy);
        #[cfg(unix)]
        assert_eq!(mode_of(&std::fs::metadata(&dest).unwrap()), 0o600);
        assert!(leftovers(&dir).is_empty());

        // Destination existante : refus sans --force, remplacée avec.
        let err = backup(&cfg, &dest, false, false).unwrap_err();
        assert!(err.contains("--force"), "{err}");
        backup(&cfg, &dest, false, true).unwrap();

        // --with-key : copie de la clé à côté.
        let dest2 = dir.join("avec-cle.db");
        backup(&cfg, &dest2, true, false).unwrap();
        let key_copy = dir.join("avec-cle.db.server.key");
        assert_eq!(std::fs::read(&key_copy).unwrap(), std::fs::read(&cfg.server_key_file).unwrap());
        #[cfg(unix)]
        assert_eq!(mode_of(&std::fs::metadata(&key_copy).unwrap()), 0o600);
        assert!(leftovers(&dir).is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn sauvegarde_serveur_demarre() {
        // Base ouverte (WAL) avec des écritures récentes : la copie les contient.
        let dir = temp_dir();
        let cfg = installation(&dir).await;
        let db = db::Db::open(&cfg.db_path).unwrap();
        db.call(|c| insert_user(c, "b@example.com")).await.unwrap();
        let dest = dir.join("chaud.db");
        backup(&cfg, &dest, false, false).unwrap();
        let copy = Connection::open(&dest).unwrap();
        let n: i64 = copy.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 2);
        drop(db);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn sauvegarde_refusee() {
        let dir = temp_dir();
        let cfg = config_for(&dir);
        // Base absente.
        assert!(backup(&cfg, &dir.join("x.db"), false, false).unwrap_err().contains("introuvable"));
        // Base d'un binaire plus récent.
        let cfg = installation(&dir).await;
        Connection::open(&cfg.db_path)
            .unwrap()
            .execute_batch(&format!("PRAGMA user_version = {}", db::SCHEMA_VERSION + 1))
            .unwrap();
        let err = backup(&cfg, &dir.join("y.db"), false, false).unwrap_err();
        assert!(err.contains("plus récent"), "{err}");
        assert!(!dir.join("y.db").exists());
        // --with-key sans clé : refus avant toute copie.
        std::fs::remove_file(&cfg.server_key_file).unwrap();
        Connection::open(&cfg.db_path)
            .unwrap()
            .execute_batch(&format!("PRAGMA user_version = {}", db::SCHEMA_VERSION))
            .unwrap();
        assert!(backup(&cfg, &dir.join("z.db"), true, false).is_err());
        assert!(!dir.join("z.db").exists());
        assert!(leftovers(&dir).is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn verification_installation() {
        let dir = temp_dir();
        let cfg = installation(&dir).await;
        let cfg = Ok(cfg);
        let (lines, code) = check_report(&cfg);
        assert_eq!(code, 0, "{lines:#?}");
        let attendu = format!("schéma v{} (à jour)", db::SCHEMA_VERSION);
        assert!(lines.iter().any(|l| l.contains(&attendu)), "{lines:#?}");

        // Base d'un binaire plus récent : erreur.
        let path = cfg.as_ref().map(|c| c.db_path.clone()).unwrap();
        Connection::open(&path)
            .unwrap()
            .execute_batch(&format!("PRAGMA user_version = {}", db::SCHEMA_VERSION + 1))
            .unwrap();
        let (lines, code) = check_report(&cfg);
        assert_eq!(code, 1, "{lines:#?}");
        assert!(lines.iter().any(|l| l.starts_with("ERREUR") && l.contains("plus récent")), "{lines:#?}");

        // Clé absente alors que des comptes existent : erreur.
        Connection::open(&path)
            .unwrap()
            .execute_batch(&format!("PRAGMA user_version = {}", db::SCHEMA_VERSION))
            .unwrap();
        let key = cfg.as_ref().map(|c| c.server_key_file.clone()).unwrap();
        std::fs::remove_file(&key).unwrap();
        let (lines, code) = check_report(&cfg);
        assert_eq!(code, 1, "{lines:#?}");
        assert!(!key.exists(), "check ne crée rien");

        // Configuration illisible : code 2.
        let (_, code) = check_report(&Err(vec!["LOCKSY_BIND invalide".into()]));
        assert_eq!(code, 2);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn verification_installation_neuve() {
        // Rien encore : aucune erreur, et rien n'est créé.
        let dir = temp_dir();
        let cfg = config_for(&dir);
        let data = cfg.app.data_dir.clone();
        let (lines, code) = check_report(&Ok(cfg));
        assert_eq!(code, 0, "{lines:#?}");
        assert!(!data.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn disponibilite() {
        let st = crate::state::test_state().await;
        let res = ready_with(&st, false).await;
        assert_eq!(res.status(), 200);
        let body = axum::body::to_bytes(res.into_body(), 1 << 16).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ready");
        assert_eq!(json["schema_version"], db::SCHEMA_VERSION);
        assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));

        let res = ready_with(&st, true).await;
        assert_eq!(res.status(), 503);
        let body = axum::body::to_bytes(res.into_body(), 1 << 16).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "not_ready");
        assert!(json["message"].as_str().is_some_and(|m| !m.is_empty()));
    }

    #[test]
    fn identifiants_de_requete() {
        for ok in ["abc", "0f1e-2d3c", "req_1.2:3", &"a".repeat(64)] {
            assert!(valid_request_id(ok), "{ok}");
        }
        for bad in ["", &"a".repeat(65), "a b", "a\r\nb", "é", "<script>", "a/b"] {
            assert!(!valid_request_id(bad), "{bad:?}");
        }
    }
}
