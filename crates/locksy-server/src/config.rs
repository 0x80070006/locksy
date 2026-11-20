//! Configuration du serveur, lue et validée au démarrage.
//!
//! Toutes les variables d'environnement réservées au démarrage sont lues ici,
//! et seulement ici. Une valeur illisible n'arrête plus le serveur par une
//! panique : toutes les erreurs sont collectées puis affichées ensemble, avec
//! pour chacune la variable, la valeur reçue et ce qui est attendu.

use crate::state::{Cidr, Config};
use locksy_core::settings::{self as registry, HostCaps, StoredValue};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

/// Longueur minimale de `LOCKSY_SETUP_TOKEN` (même seuil que l'API d'installation).
const SETUP_TOKEN_MIN_LEN: usize = 20;

/// Configuration complète du serveur. `app` est la partie partagée avec les
/// handlers ; le reste ne sert qu'au démarrage et à l'arrêt.
pub struct ServerConfig {
    pub app: Config,
    /// Base SQLite : `<LOCKSY_DATA>/locksy.db`.
    pub db_path: PathBuf,
    /// Clé serveur : `LOCKSY_SERVER_KEY_FILE`, sinon `<LOCKSY_DATA>/server.key`.
    pub server_key_file: PathBuf,
    /// Autorise une nouvelle clé alors que la base contient déjà des comptes.
    pub server_key_reset: bool,
    /// Connexions de lecture SQLite.
    pub db_readers: usize,
    /// Certificat (chaîne PEM) et clé pour le HTTPS intégré.
    pub tls: Option<(PathBuf, PathBuf)>,
    /// Adresse d'écoute du serveur de redirection HTTP vers HTTPS.
    pub http_redirect: Option<String>,
    /// Cible syslog (`udp://`, `tcp://` ou `tcp+tls://hote:port`).
    pub syslog: Option<String>,
    /// Autorité de certification supplémentaire pour le syslog TLS.
    pub syslog_ca_file: Option<PathBuf>,
    /// Journaux au format JSON (une ligne par événement).
    pub log_json: bool,
    /// Délai laissé aux requêtes en cours à l'arrêt.
    pub shutdown_grace: Duration,
    /// Contraintes de l'hébergeur sur les réglages, limites de débit et
    /// configuration effective affichée aux propriétaires.
    pub host: HostConfig,
}

/// Une variable de l'hébergeur telle qu'affichée dans Réglages › Système
/// (`GET /admin/config/effective`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostVar {
    pub name: &'static str,
    /// Valeur effective ; « *** » pour un secret défini.
    pub value: String,
    /// `env` (variable définie) ou `default`.
    pub source: &'static str,
    pub secret: bool,
}

/// Plafonds par adresse IP des points d'entrée sensibles (requêtes par
/// fenêtre), appliqués par le serveur. Une variable explicite l'emporte sur
/// le facteur `LOCKSY_RATELIMIT_FACTOR`.
#[derive(Clone, Debug, PartialEq)]
pub struct RateCaps {
    pub factor: f64,
    /// Connexions, par fenêtre de 600 s.
    pub login_ip: u32,
    /// Pré-connexions, par fenêtre de 60 s.
    pub prelogin_ip: u32,
    /// Inscriptions, par fenêtre de 3600 s.
    pub register_ip: u32,
    /// Récupérations de compte, par fenêtre de 3600 s.
    pub recover_ip: u32,
    /// Ouvertures de liens de partage, par fenêtre de 60 s.
    pub share_open_ip: u32,
    /// Lectures d'invitations, par fenêtre de 60 s.
    pub invite_ip: u32,
}

impl RateCaps {
    /// Plafond de base multiplié par le facteur de l'hébergeur (au moins 1).
    pub fn scaled(&self, base: u32) -> u32 {
        (f64::from(base) * self.factor).round().clamp(1.0, f64::from(u32::MAX)) as u32
    }
}

impl Default for RateCaps {
    fn default() -> Self {
        let mut r = RateCaps {
            factor: 1.0,
            login_ip: 0,
            prelogin_ip: 0,
            register_ip: 0,
            recover_ip: 0,
            share_open_ip: 0,
            invite_ip: 0,
        };
        for (_, base, slot) in rate_slots(&mut r) {
            *slot = base;
        }
        r
    }
}

/// Variables de limites par IP : nom, plafond de base, champ.
fn rate_slots(r: &mut RateCaps) -> [(&'static str, u32, &mut u32); 6] {
    [
        ("LOCKSY_RATELIMIT_LOGIN_IP", 100, &mut r.login_ip),
        ("LOCKSY_RATELIMIT_PRELOGIN_IP", 60, &mut r.prelogin_ip),
        ("LOCKSY_RATELIMIT_REGISTER_IP", 10, &mut r.register_ip),
        ("LOCKSY_RATELIMIT_RECOVER_IP", 10, &mut r.recover_ip),
        ("LOCKSY_RATELIMIT_SHARE_OPEN_IP", 30, &mut r.share_open_ip),
        ("LOCKSY_RATELIMIT_INVITE_IP", 20, &mut r.invite_ip),
    ]
}

/// Ce que l'hébergeur impose aux réglages de l'organisation.
#[derive(Clone, Debug)]
pub struct HostConfig {
    /// Valeurs verrouillées et plafonds, transmis au registre.
    pub caps: HostCaps,
    pub rate: RateCaps,
    /// `LOCKSY_ENV=test` : compteurs de test exposés, adresse publique en HTTP permise.
    pub env_test: bool,
    /// Configuration effective, secrets masqués.
    pub vars: Vec<HostVar>,
}

/// Valeurs par défaut : celles d'un serveur sans aucune variable.
impl Default for HostConfig {
    fn default() -> Self {
        host_config(&|_: &str| None, None, &mut Vec::new())
    }
}

/// Lit `LOCKSY_SETTINGS_FILE` : un objet JSON `{ "<clé>": valeur | {value,
/// mode, min, max} }`, validé contre le registre. Chaque clé y est
/// verrouillée. Les secrets en sont exclus (ils se saisissent dans
/// l'interface, chiffrés par la clé serveur).
fn parse_settings_file(path: &Path, caps: &HostCaps) -> Result<BTreeMap<String, StoredValue>, Vec<String>> {
    let var = "LOCKSY_SETTINGS_FILE";
    let text = std::fs::read_to_string(path).map_err(|e| vec![format!("{var} invalide : « {} » illisible ({e}).", path.display())])?;
    let doc: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| vec![format!("{var} invalide : « {} » n'est pas un JSON lisible ({e}).", path.display())])?;
    let Some(map) = doc.as_object() else {
        return Err(vec![format!("{var} invalide : un objet JSON {{ \"clé\": valeur }} est attendu.")]);
    };
    let mut out = BTreeMap::new();
    let mut errors = Vec::new();
    for (key, raw) in map {
        let Some(def) = registry::def(key) else {
            errors.push(format!("{var} invalide : réglage inconnu « {key} »."));
            continue;
        };
        if def.is_secret() {
            errors.push(format!("{var} invalide : « {key} » est un secret, à saisir dans l'interface d'administration."));
            continue;
        }
        match registry::stored_from_json(def, raw).and_then(|sv| registry::check_stored(def, &sv, caps)) {
            Ok(sv) => {
                out.insert(key.clone(), sv);
            }
            Err(e) => {
                let params = serde_json::Value::Object(e.params.clone());
                errors.push(format!("{var} invalide : « {key} » refusé ({}{}).", e.code, if e.params.is_empty() { String::new() } else { format!(" {params}") }));
            }
        }
    }
    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

/// Variables affichées dans Réglages › Système : nom, valeur par défaut affichée, secret.
const DISPLAYED_VARS: &[(&str, &str, bool)] = &[
    ("LOCKSY_BIND", "0.0.0.0:8743", false),
    ("LOCKSY_DATA", "/data", false),
    ("LOCKSY_WEB", "/app/web", false),
    ("LOCKSY_TRUST_PROXY", "false", false),
    ("LOCKSY_TRUSTED_PROXIES", "", false),
    ("LOCKSY_TLS_CERT", "", false),
    ("LOCKSY_TLS_KEY", "", false),
    ("LOCKSY_HTTP_REDIRECT", "", false),
    ("LOCKSY_SYSLOG", "", false),
    ("LOCKSY_SYSLOG_CA_FILE", "", false),
    ("LOCKSY_SMTP_CA_FILE", "", false),
    ("LOCKSY_ARGON2_CONCURRENCY", "", false),
    ("LOCKSY_ARGON2_QUEUE", "", false),
    ("LOCKSY_REQUEST_TIMEOUT_SECS", "120", false),
    ("LOCKSY_HEADER_TIMEOUT_SECS", "15", false),
    ("LOCKSY_SETUP_TOKEN", "", true),
    ("LOCKSY_SERVER_KEY_FILE", "", false),
    ("LOCKSY_SERVER_KEY_RESET", "false", false),
    ("LOCKSY_DB_READERS", "4", false),
    ("LOCKSY_LOG_FORMAT", "text", false),
    ("LOCKSY_SHUTDOWN_GRACE_SECS", "10", false),
    ("LOCKSY_SSO_ALLOW_HTTP", "false", false),
    ("LOCKSY_SSO_ALLOW_PRIVATE", "false", false),
    ("LOCKSY_SETTINGS_FILE", "", false),
    ("LOCKSY_MAX_ATTACHMENT_MIB", "10", false),
    ("LOCKSY_MAX_BODY_MIB", "16", false),
    ("LOCKSY_RATELIMIT_FACTOR", "1", false),
    ("LOCKSY_ENV", "production", false),
];

/// Configuration effective affichée : variables définies (secrets masqués)
/// ou valeur par défaut, puis les limites par IP effectives.
fn displayed_vars(get: &impl Fn(&str) -> Option<String>, rate: &RateCaps) -> Vec<HostVar> {
    let mut vars: Vec<HostVar> = DISPLAYED_VARS
        .iter()
        .map(|&(name, default, secret)| match value(get, name) {
            Some(v) => HostVar { name, value: if secret { "***".into() } else { v }, source: "env", secret },
            None => HostVar { name, value: default.into(), source: "default", secret },
        })
        .collect();
    let mut r = rate.clone();
    for (name, _, slot) in rate_slots(&mut r) {
        let source = if value(get, name).is_some() { "env" } else { "default" };
        vars.push(HostVar { name, value: slot.to_string(), source, secret: false });
    }
    vars
}

/// Lit la configuration dans l'environnement du processus.
pub fn from_env() -> Result<ServerConfig, Vec<String>> {
    from_lookup(|k| std::env::var(k).ok())
}

/// Valeur d'une variable, sans les espaces autour ; vide équivaut à absente.
fn value(get: &impl Fn(&str) -> Option<String>, key: &str) -> Option<String> {
    get(key).map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// Lit un booléen : true/false, 1/0, yes/no (casse indifférente).
pub(crate) fn parse_bool(raw: &str) -> Option<bool> {
    match raw.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => None,
    }
}

fn boolean(get: &impl Fn(&str) -> Option<String>, key: &str, default: bool, errors: &mut Vec<String>) -> bool {
    let Some(raw) = value(get, key) else { return default };
    parse_bool(&raw).unwrap_or_else(|| {
        errors.push(format!("{key} invalide : reçu « {raw} », attendu true ou false (ou 1/0, yes/no)."));
        default
    })
}

/// Lit un entier compris dans `[min, max]` ; une valeur illisible ou hors
/// bornes est une erreur, et le défaut est gardé pour poursuivre la lecture.
fn number<T>(
    get: &impl Fn(&str) -> Option<String>,
    key: &str,
    default: T,
    min: T,
    max: T,
    errors: &mut Vec<String>,
) -> T
where
    T: FromStr + PartialOrd + Copy + std::fmt::Display,
{
    let Some(raw) = value(get, key) else { return default };
    match raw.parse::<T>() {
        Ok(n) if n >= min && n <= max => n,
        _ => {
            errors.push(format!("{key} invalide : reçu « {raw} », attendu un nombre entier de {min} à {max}."));
            default
        }
    }
}

/// Vérifie la forme `hote:port` d'une adresse d'écoute (port numérique).
fn check_bind(raw: &str) -> bool {
    match raw.rsplit_once(':') {
        Some((host, port)) => !host.is_empty() && port.parse::<u16>().is_ok(),
        None => false,
    }
}

/// Vérifie qu'un fichier existe et s'ouvre en lecture.
fn readable(path: &Path) -> Result<(), String> {
    match std::fs::metadata(path) {
        Ok(m) if m.is_file() => std::fs::File::open(path).map(|_| ()).map_err(|e| format!("illisible ({e})")),
        Ok(_) => Err("ce n'est pas un fichier".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err("fichier introuvable".into()),
        Err(e) => Err(format!("inaccessible ({e})")),
    }
}

/// Lit `LOCKSY_TRUSTED_PROXIES` : IP ou réseaux CIDR séparés par des virgules.
/// Une entrée illisible est une erreur (mieux vaut refuser de démarrer que de
/// faire confiance au mauvais pair).
pub fn parse_trusted_proxies(raw: &str) -> Result<Vec<Cidr>, String> {
    let mut list = Vec::new();
    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        match Cidr::parse(entry) {
            Some(c) => list.push(c),
            None => {
                return Err(format!(
                    "LOCKSY_TRUSTED_PROXIES invalide : « {entry} » n'est ni une adresse IP ni un réseau CIDR \
                     (exemple : 10.0.0.0/8,192.168.1.10)."
                ))
            }
        }
    }
    Ok(list)
}

/// Adresse d'écoute et présence du TLS, pour la sous-commande `healthcheck`.
/// Tolérante : aucune autre variable n'est lue, rien n'échoue.
pub fn healthcheck_target(get: impl Fn(&str) -> Option<String>) -> (String, bool) {
    let bind = value(&get, "LOCKSY_BIND").unwrap_or_else(|| "0.0.0.0:8743".into());
    let tls = value(&get, "LOCKSY_TLS_CERT").is_some() && value(&get, "LOCKSY_TLS_KEY").is_some();
    (bind, tls)
}

/// Lit et valide la configuration au moyen de `get` (l'environnement en
/// production, une table dans les tests). Toutes les erreurs sont renvoyées.
pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<ServerConfig, Vec<String>> {
    let mut errors = Vec::new();

    let bind = value(&get, "LOCKSY_BIND").unwrap_or_else(|| "0.0.0.0:8743".into());
    if !check_bind(&bind) {
        errors.push(format!(
            "LOCKSY_BIND invalide : reçu « {bind} », attendu hote:port avec un port numérique (exemple : 0.0.0.0:8743)."
        ));
    }
    let data_dir = PathBuf::from(value(&get, "LOCKSY_DATA").unwrap_or_else(|| "/data".into()));
    let web_dir = PathBuf::from(value(&get, "LOCKSY_WEB").unwrap_or_else(|| "/app/web".into()));

    let trust_proxy = boolean(&get, "LOCKSY_TRUST_PROXY", false, &mut errors);
    let trusted_proxies = match parse_trusted_proxies(&value(&get, "LOCKSY_TRUSTED_PROXIES").unwrap_or_default()) {
        Ok(list) => list,
        Err(e) => {
            errors.push(e);
            Vec::new()
        }
    };

    // TLS : les deux fichiers ensemble, ou aucun.
    let tls = match (value(&get, "LOCKSY_TLS_CERT"), value(&get, "LOCKSY_TLS_KEY")) {
        (Some(cert), Some(key)) => {
            let (cert, key) = (PathBuf::from(cert), PathBuf::from(key));
            for (name, path) in [("LOCKSY_TLS_CERT", &cert), ("LOCKSY_TLS_KEY", &key)] {
                if let Err(e) = readable(path) {
                    errors.push(format!("{name} invalide : « {} » : {e}.", path.display()));
                }
            }
            Some((cert, key))
        }
        (None, None) => None,
        (Some(_), None) => {
            errors.push("LOCKSY_TLS_CERT est défini mais LOCKSY_TLS_KEY est absent : définissez les deux (HTTPS intégré) ou aucun.".into());
            None
        }
        (None, Some(_)) => {
            errors.push("LOCKSY_TLS_KEY est défini mais LOCKSY_TLS_CERT est absent : définissez les deux (HTTPS intégré) ou aucun.".into());
            None
        }
    };

    let http_redirect = value(&get, "LOCKSY_HTTP_REDIRECT");
    if let Some(r) = &http_redirect {
        if !check_bind(r) {
            errors.push(format!(
                "LOCKSY_HTTP_REDIRECT invalide : reçu « {r} », attendu hote:port avec un port numérique (exemple : 0.0.0.0:8080)."
            ));
        }
    }

    let request_timeout = number(&get, "LOCKSY_REQUEST_TIMEOUT_SECS", 120u64, 1, 3600, &mut errors);
    let header_timeout = number(&get, "LOCKSY_HEADER_TIMEOUT_SECS", 15u64, 1, 300, &mut errors);
    let argon2_concurrency = number(
        &get,
        "LOCKSY_ARGON2_CONCURRENCY",
        crate::security::default_argon2_concurrency().clamp(1, 1024),
        1usize,
        1024,
        &mut errors,
    );
    let argon2_queue = number(&get, "LOCKSY_ARGON2_QUEUE", argon2_concurrency * 8, 0usize, 100_000, &mut errors);
    let db_readers = number(&get, "LOCKSY_DB_READERS", 4usize, 1, 64, &mut errors);
    let shutdown_grace = number(&get, "LOCKSY_SHUTDOWN_GRACE_SECS", 10u64, 0, 300, &mut errors);

    let log_json = match value(&get, "LOCKSY_LOG_FORMAT").map(|v| v.to_ascii_lowercase()) {
        None => false,
        Some(v) if v == "text" => false,
        Some(v) if v == "json" => true,
        Some(v) => {
            errors.push(format!("LOCKSY_LOG_FORMAT invalide : reçu « {v} », attendu text ou json."));
            false
        }
    };

    // Lue par sso.rs à chaque appel ; seule sa forme est vérifiée ici.
    boolean(&get, "LOCKSY_SSO_ALLOW_HTTP", false, &mut errors);
    boolean(&get, "LOCKSY_SSO_ALLOW_PRIVATE", false, &mut errors);

    // Le jeton lui-même est lu par l'API d'installation ; seule sa forme est vérifiée ici.
    if let Some(token) = value(&get, "LOCKSY_SETUP_TOKEN") {
        let n = token.chars().count();
        if n < SETUP_TOKEN_MIN_LEN {
            // La valeur n'est pas recopiée : c'est un secret.
            errors.push(format!(
                "LOCKSY_SETUP_TOKEN invalide : {n} caractères reçus, au moins {SETUP_TOKEN_MIN_LEN} attendus."
            ));
        }
    }

    let syslog = value(&get, "LOCKSY_SYSLOG");
    if let Some(s) = &syslog {
        if let Err(e) = crate::syslog::parse(s) {
            errors.push(format!("LOCKSY_SYSLOG invalide : reçu « {s} » : {e}."));
        }
    }
    let syslog_ca_file = value(&get, "LOCKSY_SYSLOG_CA_FILE").map(PathBuf::from);
    if let Some(ca) = &syslog_ca_file {
        if let Err(e) = crate::syslog::load_ca_file(ca) {
            errors.push(format!("LOCKSY_SYSLOG_CA_FILE invalide : « {} » : {e}.", ca.display()));
        }
    }
    // Autorité interne du relais SMTP : lue par mail.rs au démarrage du
    // worker ; seule sa forme est vérifiée ici (même format que le syslog).
    if let Some(ca) = value(&get, "LOCKSY_SMTP_CA_FILE").map(PathBuf::from) {
        if let Err(e) = crate::syslog::load_ca_file(&ca) {
            errors.push(format!("LOCKSY_SMTP_CA_FILE invalide : « {} » : {e}.", ca.display()));
        }
    }

    let server_key_file =
        value(&get, "LOCKSY_SERVER_KEY_FILE").map(PathBuf::from).unwrap_or_else(|| data_dir.join("server.key"));
    let server_key_reset = boolean(&get, "LOCKSY_SERVER_KEY_RESET", false, &mut errors);

    let host = host_config(&get, syslog.as_deref(), &mut errors);

    if !errors.is_empty() {
        return Err(errors);
    }
    let app = Config {
        bind,
        data_dir: data_dir.clone(),
        web_dir,
        trust_proxy,
        trusted_proxies,
        hsts: tls.is_some() || trust_proxy,
        request_timeout: Duration::from_secs(request_timeout),
        header_timeout: Duration::from_secs(header_timeout),
        argon2_concurrency,
        argon2_queue,
    };
    Ok(ServerConfig {
        app,
        db_path: data_dir.join("locksy.db"),
        server_key_file,
        server_key_reset,
        db_readers,
        tls,
        http_redirect,
        syslog,
        syslog_ca_file,
        log_json,
        shutdown_grace: Duration::from_secs(shutdown_grace),
        host,
    })
}

/// Contraintes de l'hébergeur : plafonds, environnement, limites par IP,
/// réglages verrouillés (`LOCKSY_SETTINGS_FILE`, `LOCKSY_SYSLOG`).
fn host_config(get: &impl Fn(&str) -> Option<String>, syslog: Option<&str>, errors: &mut Vec<String>) -> HostConfig {
    let max_attachment_mib = number(get, "LOCKSY_MAX_ATTACHMENT_MIB", 10i64, 1, 15, errors);
    let max_body_mib = number(get, "LOCKSY_MAX_BODY_MIB", 16i64, 1, 64, errors);
    let env_test = match value(get, "LOCKSY_ENV").map(|v| v.to_ascii_lowercase()) {
        None => false,
        Some(v) if v == "production" => false,
        Some(v) if v == "test" => true,
        Some(v) => {
            errors.push(format!("LOCKSY_ENV invalide : reçu « {v} », attendu production ou test."));
            false
        }
    };

    let factor = match value(get, "LOCKSY_RATELIMIT_FACTOR") {
        None => 1.0,
        Some(raw) => match raw.replace(',', ".").parse::<f64>() {
            Ok(f) if (0.1..=100.0).contains(&f) => f,
            _ => {
                errors.push(format!(
                    "LOCKSY_RATELIMIT_FACTOR invalide : reçu « {raw} », attendu un nombre de 0.1 à 100 (exemple : 2 ou 0.5)."
                ));
                1.0
            }
        },
    };
    let mut rate = RateCaps { factor, ..RateCaps::default() };
    let base_caps = rate.clone();
    for (name, base, slot) in rate_slots(&mut rate) {
        *slot = number(get, name, base_caps.scaled(base).min(1_000_000), 1u32, 1_000_000, errors);
    }

    let mut caps = HostCaps { max_body_mib, env_test, ..HostCaps::default() };
    caps.caps.insert("attachment.max_file_mib".into(), (max_attachment_mib, "LOCKSY_MAX_ATTACHMENT_MIB".into()));
    if let Some(path) = value(get, "LOCKSY_SETTINGS_FILE") {
        match parse_settings_file(Path::new(&path), &caps) {
            Ok(map) => {
                for (key, sv) in map {
                    caps.locked.insert(key, (sv, "LOCKSY_SETTINGS_FILE".into()));
                }
            }
            Err(e) => errors.extend(e),
        }
    }
    if let Some(url) = syslog {
        let sv = StoredValue::plain(serde_json::Value::String(url.to_string()));
        caps.locked.insert("audit.syslog.url".into(), (sv, "LOCKSY_SYSLOG".into()));
    }
    let vars = displayed_vars(get, &rate);
    HostConfig { caps, rate, env_test, vars }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k| map.get(k).cloned()
    }

    fn errors_of(pairs: &[(&str, &str)]) -> Vec<String> {
        match from_lookup(lookup(pairs)) {
            Ok(_) => panic!("configuration acceptée à tort : {pairs:?}"),
            Err(e) => e,
        }
    }

    /// Fichier temporaire unique, pour les chemins qui doivent être lisibles.
    fn temp_file(content: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("locksy-config-{}", locksy_core::crypto::new_uuid()));
        std::fs::write(&p, content).unwrap();
        p
    }

    #[test]
    fn defauts_sans_aucune_variable() {
        let c = from_lookup(|_| None).unwrap();
        assert_eq!(c.app.bind, "0.0.0.0:8743");
        assert_eq!(c.app.data_dir, PathBuf::from("/data"));
        assert_eq!(c.app.web_dir, PathBuf::from("/app/web"));
        assert!(!c.app.trust_proxy && !c.app.hsts);
        assert!(c.app.trusted_proxies.is_empty());
        assert_eq!(c.app.request_timeout, Duration::from_secs(120));
        assert_eq!(c.app.header_timeout, Duration::from_secs(15));
        assert!(c.app.argon2_concurrency >= 1);
        assert_eq!(c.app.argon2_queue, c.app.argon2_concurrency * 8);
        assert_eq!(c.db_path, PathBuf::from("/data").join("locksy.db"));
        assert_eq!(c.server_key_file, PathBuf::from("/data").join("server.key"));
        assert!(!c.server_key_reset);
        assert_eq!(c.db_readers, 4);
        assert!(c.tls.is_none() && c.http_redirect.is_none() && c.syslog.is_none() && c.syslog_ca_file.is_none());
        assert!(!c.log_json);
        assert_eq!(c.shutdown_grace, Duration::from_secs(10));
    }

    #[test]
    fn valeurs_vides_equivalent_a_absentes() {
        let c = from_lookup(lookup(&[("LOCKSY_BIND", "  "), ("LOCKSY_TLS_CERT", ""), ("LOCKSY_DB_READERS", "")]))
            .unwrap();
        assert_eq!(c.app.bind, "0.0.0.0:8743");
        assert!(c.tls.is_none());
        assert_eq!(c.db_readers, 4);
    }

    #[test]
    fn plusieurs_erreurs_remontees_ensemble() {
        let errs = errors_of(&[
            ("LOCKSY_BIND", "sans-port"),
            ("LOCKSY_TRUST_PROXY", "peut-etre"),
            ("LOCKSY_REQUEST_TIMEOUT_SECS", "deux minutes"),
            ("LOCKSY_LOG_FORMAT", "xml"),
            ("LOCKSY_SYSLOG", "http://siem:514"),
        ]);
        assert_eq!(errs.len(), 5, "{errs:#?}");
        for (var, value) in [
            ("LOCKSY_BIND", "sans-port"),
            ("LOCKSY_TRUST_PROXY", "peut-etre"),
            ("LOCKSY_REQUEST_TIMEOUT_SECS", "deux minutes"),
            ("LOCKSY_LOG_FORMAT", "xml"),
            ("LOCKSY_SYSLOG", "http://siem:514"),
        ] {
            assert!(errs.iter().any(|e| e.contains(var) && e.contains(value)), "{var} absent de {errs:#?}");
        }
    }

    #[test]
    fn tls_a_moitie_configure_refuse() {
        let errs = errors_of(&[("LOCKSY_TLS_CERT", "/etc/cert.pem")]);
        assert!(errs[0].contains("LOCKSY_TLS_KEY est absent"), "{errs:?}");
        let errs = errors_of(&[("LOCKSY_TLS_KEY", "/etc/key.pem")]);
        assert!(errs[0].contains("LOCKSY_TLS_CERT est absent"), "{errs:?}");
        // Fichiers introuvables : une erreur par fichier.
        let errs = errors_of(&[("LOCKSY_TLS_CERT", "/nulle/part/cert.pem"), ("LOCKSY_TLS_KEY", "/nulle/part/key.pem")]);
        assert_eq!(errs.len(), 2, "{errs:?}");
        assert!(errs.iter().all(|e| e.contains("introuvable")));
    }

    #[test]
    fn tls_complet_active_hsts() {
        let (cert, key) = (temp_file("cert"), temp_file("key"));
        let c = from_lookup(lookup(&[
            ("LOCKSY_TLS_CERT", cert.to_str().unwrap()),
            ("LOCKSY_TLS_KEY", key.to_str().unwrap()),
        ]))
        .unwrap();
        assert_eq!(c.tls, Some((cert.clone(), key.clone())));
        assert!(c.app.hsts);
        let _ = std::fs::remove_file(cert);
        let _ = std::fs::remove_file(key);
    }

    #[test]
    fn trust_proxy_valeurs_acceptees_et_refusees() {
        for (raw, expected) in [("true", true), ("TRUE", true), ("1", true), ("Yes", true), ("false", false), ("0", false), ("no", false)] {
            let c = from_lookup(lookup(&[("LOCKSY_TRUST_PROXY", raw)])).unwrap();
            assert_eq!(c.app.trust_proxy, expected, "{raw}");
            assert_eq!(c.app.hsts, expected, "{raw}");
        }
        for raw in ["oui", "on", "2", "vrai"] {
            let errs = errors_of(&[("LOCKSY_TRUST_PROXY", raw)]);
            assert!(errs[0].contains("LOCKSY_TRUST_PROXY") && errs[0].contains(raw), "{errs:?}");
        }
        let errs = errors_of(&[("LOCKSY_SERVER_KEY_RESET", "peut-être")]);
        assert!(errs[0].contains("LOCKSY_SERVER_KEY_RESET"));
        let errs = errors_of(&[("LOCKSY_SSO_ALLOW_HTTP", "oui")]);
        assert!(errs[0].contains("LOCKSY_SSO_ALLOW_HTTP"), "{errs:?}");
        assert!(from_lookup(lookup(&[("LOCKSY_SSO_ALLOW_HTTP", "1")])).is_ok());
        let errs = errors_of(&[("LOCKSY_SSO_ALLOW_PRIVATE", "peut-être")]);
        assert!(errs[0].contains("LOCKSY_SSO_ALLOW_PRIVATE"), "{errs:?}");
        assert!(from_lookup(lookup(&[("LOCKSY_SSO_ALLOW_PRIVATE", "true")])).is_ok());
    }

    #[test]
    fn bornes_numeriques() {
        let cases: &[(&str, &str, &str)] = &[
            ("LOCKSY_REQUEST_TIMEOUT_SECS", "0", "3601"),
            ("LOCKSY_HEADER_TIMEOUT_SECS", "0", "301"),
            ("LOCKSY_ARGON2_CONCURRENCY", "0", "1025"),
            ("LOCKSY_ARGON2_QUEUE", "-1", "100001"),
            ("LOCKSY_DB_READERS", "0", "65"),
            ("LOCKSY_SHUTDOWN_GRACE_SECS", "-1", "301"),
        ];
        for &(var, below, above) in cases {
            for bad in [below, above, "12abc"] {
                let errs = errors_of(&[(var, bad)]);
                assert!(errs[0].contains(var) && errs[0].contains(bad), "{errs:?}");
            }
        }
        let c = from_lookup(lookup(&[
            ("LOCKSY_REQUEST_TIMEOUT_SECS", "3600"),
            ("LOCKSY_HEADER_TIMEOUT_SECS", "1"),
            ("LOCKSY_ARGON2_CONCURRENCY", "3"),
            ("LOCKSY_ARGON2_QUEUE", "0"),
            ("LOCKSY_DB_READERS", "64"),
            ("LOCKSY_SHUTDOWN_GRACE_SECS", "0"),
        ]))
        .unwrap();
        assert_eq!(c.app.request_timeout, Duration::from_secs(3600));
        assert_eq!(c.app.header_timeout, Duration::from_secs(1));
        assert_eq!((c.app.argon2_concurrency, c.app.argon2_queue), (3, 0));
        assert_eq!(c.db_readers, 64);
        assert_eq!(c.shutdown_grace, Duration::ZERO);
        // File d'attente par défaut : 8 × la concurrence choisie.
        let c = from_lookup(lookup(&[("LOCKSY_ARGON2_CONCURRENCY", "2")])).unwrap();
        assert_eq!(c.app.argon2_queue, 16);
    }

    #[test]
    fn format_des_journaux() {
        assert!(!from_lookup(lookup(&[("LOCKSY_LOG_FORMAT", "text")])).unwrap().log_json);
        assert!(from_lookup(lookup(&[("LOCKSY_LOG_FORMAT", "JSON")])).unwrap().log_json);
        let errs = errors_of(&[("LOCKSY_LOG_FORMAT", "logfmt")]);
        assert!(errs[0].contains("LOCKSY_LOG_FORMAT"));
    }

    #[test]
    fn cle_serveur_par_defaut_dans_le_dossier_de_donnees() {
        let c = from_lookup(lookup(&[("LOCKSY_DATA", "/srv/locksy")])).unwrap();
        assert_eq!(c.server_key_file, PathBuf::from("/srv/locksy").join("server.key"));
        assert_eq!(c.db_path, PathBuf::from("/srv/locksy").join("locksy.db"));
        let c = from_lookup(lookup(&[("LOCKSY_DATA", "/srv/locksy"), ("LOCKSY_SERVER_KEY_FILE", "/run/secrets/key")]))
            .unwrap();
        assert_eq!(c.server_key_file, PathBuf::from("/run/secrets/key"));
        let c = from_lookup(lookup(&[("LOCKSY_SERVER_KEY_RESET", "true")])).unwrap();
        assert!(c.server_key_reset);
    }

    #[test]
    fn proxys_de_confiance_lus() {
        let list = parse_trusted_proxies(" 10.0.0.0/8, 192.168.1.10 ,,2001:db8::/32").unwrap();
        assert_eq!(list.len(), 3);
        assert!(parse_trusted_proxies("").unwrap().is_empty());
        let c = from_lookup(lookup(&[("LOCKSY_TRUSTED_PROXIES", "10.0.0.0/8")])).unwrap();
        assert_eq!(c.app.trusted_proxies.len(), 1);
    }

    #[test]
    fn proxy_de_confiance_illisible_refuse() {
        let err = parse_trusted_proxies("10.0.0.0/8, proxy.local").unwrap_err();
        assert!(err.contains("LOCKSY_TRUSTED_PROXIES invalide") && err.contains("proxy.local"), "{err}");
        let errs = errors_of(&[("LOCKSY_TRUSTED_PROXIES", "10.0.0.0/8, proxy.local")]);
        assert_eq!(errs.len(), 1);
    }

    #[test]
    fn adresses_d_ecoute() {
        for ok in ["0.0.0.0:8743", "localhost:8743", "[::]:8443"] {
            assert_eq!(from_lookup(lookup(&[("LOCKSY_BIND", ok)])).unwrap().app.bind, ok);
        }
        for bad in ["8743", ":8743", "0.0.0.0:http", "0.0.0.0:70000"] {
            assert!(errors_of(&[("LOCKSY_BIND", bad)])[0].contains("LOCKSY_BIND"), "{bad}");
        }
        assert!(errors_of(&[("LOCKSY_HTTP_REDIRECT", "8080")])[0].contains("LOCKSY_HTTP_REDIRECT"));
        let c = from_lookup(lookup(&[("LOCKSY_HTTP_REDIRECT", "0.0.0.0:8080")])).unwrap();
        assert_eq!(c.http_redirect.as_deref(), Some("0.0.0.0:8080"));
    }

    #[test]
    fn jeton_d_installation_trop_court_sans_le_recopier() {
        let errs = errors_of(&[("LOCKSY_SETUP_TOKEN", "secret-court")]);
        assert!(errs[0].contains("LOCKSY_SETUP_TOKEN") && !errs[0].contains("secret-court"), "{errs:?}");
        assert!(from_lookup(lookup(&[("LOCKSY_SETUP_TOKEN", "abcdefghij0123456789")])).is_ok());
    }

    #[test]
    fn syslog_et_autorite() {
        let c = from_lookup(lookup(&[("LOCKSY_SYSLOG", "tcp+tls://siem.local:6514")])).unwrap();
        assert_eq!(c.syslog.as_deref(), Some("tcp+tls://siem.local:6514"));
        let errs = errors_of(&[("LOCKSY_SYSLOG_CA_FILE", "/nulle/part/ca.pem")]);
        assert!(errs[0].contains("LOCKSY_SYSLOG_CA_FILE"));
        let not_pem = temp_file("pas un certificat");
        let errs = errors_of(&[("LOCKSY_SYSLOG_CA_FILE", not_pem.to_str().unwrap())]);
        assert!(errs[0].contains("LOCKSY_SYSLOG_CA_FILE"));
        let errs = errors_of(&[("LOCKSY_SMTP_CA_FILE", not_pem.to_str().unwrap())]);
        assert!(errs[0].contains("LOCKSY_SMTP_CA_FILE"), "{errs:?}");
        let _ = std::fs::remove_file(not_pem);
    }

    #[test]
    fn contraintes_de_l_hebergeur_par_defaut() {
        let h = from_lookup(|_| None).unwrap().host;
        assert_eq!(HostConfig::default().caps.caps, h.caps.caps);
        assert!(!h.env_test && !h.caps.env_test);
        assert_eq!(h.caps.max_body_mib, 16);
        assert_eq!(h.caps.caps["attachment.max_file_mib"], (10, "LOCKSY_MAX_ATTACHMENT_MIB".into()));
        assert!(h.caps.locked.is_empty());
        assert_eq!(h.rate, RateCaps::default());
        assert_eq!((h.rate.login_ip, h.rate.prelogin_ip, h.rate.register_ip), (100, 60, 10));
        assert_eq!((h.rate.recover_ip, h.rate.share_open_ip, h.rate.invite_ip), (10, 30, 20));
        assert_eq!(h.rate.scaled(7), 7);
        let token = h.vars.iter().find(|v| v.name == "LOCKSY_SETUP_TOKEN").unwrap();
        assert_eq!((token.value.as_str(), token.source, token.secret), ("", "default", true));
    }

    #[test]
    fn contraintes_de_l_hebergeur_lues() {
        let c = from_lookup(lookup(&[
            ("LOCKSY_MAX_ATTACHMENT_MIB", "5"),
            ("LOCKSY_MAX_BODY_MIB", "32"),
            ("LOCKSY_ENV", "test"),
            ("LOCKSY_RATELIMIT_FACTOR", "2"),
            ("LOCKSY_RATELIMIT_LOGIN_IP", "7"),
            ("LOCKSY_SETUP_TOKEN", "abcdefghij0123456789"),
            ("LOCKSY_SYSLOG", "tcp://siem.local:514"),
        ]))
        .unwrap();
        let h = c.host;
        assert!(h.env_test && h.caps.env_test);
        assert_eq!(h.caps.max_body_mib, 32);
        assert_eq!(h.caps.caps["attachment.max_file_mib"].0, 5);
        // Valeur explicite prioritaire sur le facteur ; les autres doublées.
        assert_eq!((h.rate.login_ip, h.rate.prelogin_ip, h.rate.invite_ip), (7, 120, 40));
        assert_eq!(h.rate.scaled(3), 6);
        let (sv, var) = &h.caps.locked["audit.syslog.url"];
        assert_eq!((sv.value.as_str(), var.as_str()), (Some("tcp://siem.local:514"), "LOCKSY_SYSLOG"));
        let token = h.vars.iter().find(|v| v.name == "LOCKSY_SETUP_TOKEN").unwrap();
        assert_eq!((token.value.as_str(), token.source), ("***", "env"));
        assert!(!h.vars.iter().any(|v| v.value.contains("abcdefghij")));
        let login = h.vars.iter().find(|v| v.name == "LOCKSY_RATELIMIT_LOGIN_IP").unwrap();
        assert_eq!((login.value.as_str(), login.source), ("7", "env"));
    }

    #[test]
    fn contraintes_de_l_hebergeur_refusees() {
        for (var, bad) in [
            ("LOCKSY_MAX_ATTACHMENT_MIB", "16"),
            ("LOCKSY_MAX_BODY_MIB", "0"),
            ("LOCKSY_RATELIMIT_FACTOR", "0.01"),
            ("LOCKSY_RATELIMIT_FACTOR", "beaucoup"),
            ("LOCKSY_RATELIMIT_SHARE_OPEN_IP", "0"),
            ("LOCKSY_ENV", "recette"),
        ] {
            let errs = errors_of(&[(var, bad)]);
            assert!(errs[0].contains(var) && errs[0].contains(bad), "{errs:?}");
        }
        assert!((from_lookup(lookup(&[("LOCKSY_RATELIMIT_FACTOR", "0,5")])).unwrap().host.rate.factor - 0.5).abs() < 1e-9);
    }

    #[test]
    fn fichier_de_reglages_verrouille_ses_cles() {
        let file = temp_file(
            r#"{ "session.idle_minutes": 30,
                 "client.autolock_minutes": { "value": 5, "mode": "enforced" } }"#,
        );
        let c = from_lookup(lookup(&[("LOCKSY_SETTINGS_FILE", file.to_str().unwrap())])).unwrap();
        let locked = &c.host.caps.locked;
        assert_eq!(locked["session.idle_minutes"].0.value, serde_json::json!(30));
        assert_eq!(locked["session.idle_minutes"].1, "LOCKSY_SETTINGS_FILE");
        assert_eq!(locked["client.autolock_minutes"].0.mode, Some(registry::Mode::Enforced));
        let _ = std::fs::remove_file(file);
    }

    #[test]
    fn fichier_de_reglages_invalide() {
        let file = temp_file(
            r#"{ "session.idle_minutes": 2, "inconnue.cle": 1, "mail.smtp.password": "x",
                 "attachment.max_file_mib": 12 }"#,
        );
        let errs = errors_of(&[("LOCKSY_SETTINGS_FILE", file.to_str().unwrap()), ("LOCKSY_MAX_ATTACHMENT_MIB", "8")]);
        assert_eq!(errs.len(), 4, "{errs:#?}");
        for needle in ["session.idle_minutes", "inconnue.cle", "mail.smtp.password", "attachment.max_file_mib"] {
            assert!(errs.iter().any(|e| e.contains("LOCKSY_SETTINGS_FILE") && e.contains(needle)), "{needle} : {errs:#?}");
        }
        assert!(errs.iter().any(|e| e.contains("out_of_range")), "{errs:#?}");
        let _ = std::fs::remove_file(file);
        let pas_json = temp_file("{ pas du json");
        assert!(errors_of(&[("LOCKSY_SETTINGS_FILE", pas_json.to_str().unwrap())])[0].contains("JSON"));
        let _ = std::fs::remove_file(pas_json);
        assert!(errors_of(&[("LOCKSY_SETTINGS_FILE", "/nulle/part/reglages.json")])[0].contains("illisible"));
    }

    #[test]
    fn healthcheck_tolerant() {
        let get = lookup(&[("LOCKSY_BIND", "127.0.0.1:9000"), ("LOCKSY_TRUST_PROXY", "n'importe quoi")]);
        assert_eq!(healthcheck_target(get), ("127.0.0.1:9000".into(), false));
        let get = lookup(&[("LOCKSY_TLS_CERT", "/c.pem"), ("LOCKSY_TLS_KEY", "/k.pem")]);
        assert_eq!(healthcheck_target(get), ("0.0.0.0:8743".into(), true));
    }
}
