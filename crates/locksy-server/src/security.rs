//! Outils de sécurité du serveur : hachage Argon2id des preuves de
//! connaissance, limitation des tentatives, réauthentification (step-up),
//! validation des entrées.

use crate::error::{ApiError, ApiResult};
use crate::state::{AppState, AuthUser};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use axum::http::{HeaderMap, StatusCode};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;
use hmac::{Hmac, Mac};
use locksy_core::crypto::{derive_subkey, is_well_formed_cipher, is_well_formed_sealed, random_array, KdfParams, SecretKey};
use locksy_core::encoding::{b64d, b64e};
use locksy_core::now_unix;
use locksy_core::settings::Effective;

/// Paramètres de l'empreinte serveur des preuves : 19 Mio, 2 passes, 1 voie
/// (référence du banc G16). Une empreinte aux paramètres différents est
/// recalculée à la connexion suivante ([`needs_rehash`]).
const ARGON_M_KIB: u32 = 19 * 1024;
const ARGON_T: u32 = 2;
const ARGON_P: u32 = 1;

fn argon() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(ARGON_M_KIB, ARGON_T, ARGON_P, None).expect("paramètres Argon2 valides"),
    )
}

/// L'empreinte PHC a-t-elle été calculée avec d'autres paramètres que ceux
/// du serveur (algorithme, version, mémoire, passes, voies) ? Une empreinte
/// illisible n'est jamais recalculée : elle ne peut pas être vérifiée.
pub fn needs_rehash(phc: &str) -> bool {
    let Ok(h) = PasswordHash::new(phc) else { return false };
    let Ok(p) = Params::try_from(&h) else { return false };
    h.algorithm.as_str() != "argon2id"
        || h.version != Some(Version::V0x13 as u32)
        || (p.m_cost(), p.t_cost(), p.p_cost()) != (ARGON_M_KIB, ARGON_T, ARGON_P)
}

// ------------------------------------------------------------ Porte Argon2

/// Chaque calcul Argon2 coûte 19 Mo de mémoire et des dizaines de
/// millisecondes de processeur. Sans limite, une rafale de connexions épuise
/// la mémoire du serveur : on borne les calculs simultanés et la file
/// d'attente, au-delà de laquelle le serveur répond 503 `server_busy`.
struct ArgonGate {
    sem: Arc<Semaphore>,
    /// Requêtes en attente d'un permis (hors calculs en cours).
    waiting: AtomicUsize,
    max_waiting: usize,
}

impl ArgonGate {
    fn new(concurrency: usize, max_waiting: usize) -> Self {
        Self { sem: Arc::new(Semaphore::new(concurrency.max(1))), waiting: AtomicUsize::new(0), max_waiting }
    }
}

static ARGON: OnceLock<ArgonGate> = OnceLock::new();

/// Délai maximal d'attente d'un permis de calcul.
const ARGON_WAIT: Duration = Duration::from_secs(10);

/// Nombre de calculs simultanés par défaut : le nombre de processeurs.
pub fn default_argon2_concurrency() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2)
}

/// Fixe les limites des calculs Argon2. Appelée une seule fois au démarrage,
/// avant tout hachage ; les appels suivants sont ignorés.
pub fn init_argon2_limits(concurrency: usize, max_waiting: usize) {
    let _ = ARGON.set(ArgonGate::new(concurrency, max_waiting));
}

/// Porte globale ; sans appel à [`init_argon2_limits`] (tests), valeurs par
/// défaut : un calcul par processeur, file de huit fois cette valeur.
fn gate() -> &'static ArgonGate {
    ARGON.get_or_init(|| {
        let c = default_argon2_concurrency();
        ArgonGate::new(c, c * 8)
    })
}

fn server_busy() -> ApiError {
    ApiError::unavailable("server_busy", "Serveur momentanément surchargé. Réessayez dans quelques secondes.")
}

/// Décrémente le compteur d'attente quelle que soit l'issue (annulation comprise).
struct WaitGuard<'a>(&'a AtomicUsize);

impl Drop for WaitGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Exécute `f` dans un fil bloquant sous la porte `g`.
async fn run_argon_with<T: Send + 'static>(
    g: &ArgonGate,
    f: impl FnOnce() -> T + Send + 'static,
) -> ApiResult<T> {
    let permit = match g.sem.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            // File pleine : réponse immédiate plutôt qu'une attente qui
            // ferait gonfler la mémoire et les connexions ouvertes.
            if g.waiting.fetch_add(1, Ordering::AcqRel) >= g.max_waiting {
                g.waiting.fetch_sub(1, Ordering::AcqRel);
                return Err(server_busy());
            }
            let _guard = WaitGuard(&g.waiting);
            match tokio::time::timeout(ARGON_WAIT, g.sem.clone().acquire_owned()).await {
                Ok(Ok(p)) => p,
                _ => return Err(server_busy()),
            }
        }
    };
    // Le permis est déplacé dans le fil : il n'est rendu qu'à la fin du
    // calcul, même si la requête est abandonnée entre-temps.
    tokio::task::spawn_blocking(move || {
        let out = f();
        drop(permit);
        out
    })
    .await
    .map_err(|_| ApiError::internal("calcul Argon2 interrompu"))
}

/// Hache une preuve envoyée par le client (déjà issue d'Argon2id côté poste).
pub async fn hash_secret(secret: Vec<u8>) -> ApiResult<String> {
    hash_secret_with(gate(), secret).await
}

async fn hash_secret_with(g: &ArgonGate, secret: Vec<u8>) -> ApiResult<String> {
    run_argon_with(g, move || {
        let salt = SaltString::generate(&mut OsRng);
        argon().hash_password(&secret, &salt).map(|h| h.to_string())
    })
    .await?
    .map_err(|_| ApiError::internal("hachage"))
}

/// Vérifie une preuve. `Ok(false)` : preuve incorrecte ou empreinte illisible.
/// `Err` : serveur saturé (503 `server_busy`), la tentative n'a pas été jugée.
pub async fn verify_secret(secret: Vec<u8>, phc: String) -> ApiResult<bool> {
    verify_secret_with(gate(), secret, phc).await
}

async fn verify_secret_with(g: &ArgonGate, secret: Vec<u8>, phc: String) -> ApiResult<bool> {
    let res = run_argon_with(g, move || {
        PasswordHash::new(&phc).map(|h| argon().verify_password(&secret, &h).is_ok()).unwrap_or(false)
    })
    .await;
    match res {
        Ok(ok) => Ok(ok),
        Err(e) if e.code == "server_busy" => Err(e),
        // Calcul interrompu (panique) : traité comme un échec de vérification.
        Err(_) => Ok(false),
    }
}

pub fn sha256_hex(s: &str) -> String {
    Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

// ------------------------------------------------------------ Limitation

#[derive(Default)]
struct Failures {
    count: u32,
    locked_until: i64,
    last: i64,
    /// Valeur de `count` quand le blocage en cours a été posé.
    locked_at: u32,
}

#[derive(Default)]
struct Window {
    start: i64,
    hits: u32,
}

/// Nombre maximal d'entrées par table du limiteur : borne la mémoire face à
/// une rafale de clés distinctes (adresses ou e-mails inventés).
const LIMITER_MAX_ENTRIES: usize = 200_000;

/// Durée du blocage après `count` échecs pour un seuil donné : le délai de
/// base, doublé à chaque échec supplémentaire, plafonné au délai maximal.
fn lock_delay(count: u32, threshold: u32, l: &Lockout) -> i64 {
    let over = count.saturating_sub(threshold).min(30);
    l.base_delay.max(1).saturating_mul(1i64 << over).min(l.max_delay.max(l.base_delay).max(1))
}

/// Seuils et délais du verrouillage après échecs (réglages `lockout.*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lockout {
    /// Échecs tolérés pour une paire (adresse e-mail, adresse IP).
    pub pair: u32,
    /// Échecs tolérés pour une adresse e-mail, toutes adresses IP confondues.
    pub account: u32,
    /// Premier délai de blocage, en secondes.
    pub base_delay: i64,
    /// Délai de blocage maximal, en secondes.
    pub max_delay: i64,
}

impl Default for Lockout {
    /// Valeurs par défaut du registre (5, 50, 30 s, 1 h).
    fn default() -> Self {
        Self { pair: 5, account: 50, base_delay: 30, max_delay: 3600 }
    }
}

/// Seuils de verrouillage effectifs (registre, bornes déjà appliquées).
pub fn lockout(eff: &Effective) -> Lockout {
    let threshold = |k: &str, d: u32| u32::try_from(eff.int(k)).ok().filter(|v| *v > 0).unwrap_or(d);
    let def = Lockout::default();
    let base_delay = Some(eff.int("lockout.base_delay_seconds")).filter(|v| *v > 0).unwrap_or(def.base_delay);
    let max_delay = Some(eff.int("lockout.max_delay_seconds")).filter(|v| *v > 0).unwrap_or(def.max_delay);
    Lockout {
        pair: threshold("lockout.pair_threshold", def.pair),
        account: threshold("lockout.account_threshold", def.account),
        base_delay,
        max_delay: max_delay.max(base_delay),
    }
}

/// Taille visée après éviction : on libère 10 % de la table d'un coup pour
/// ne pas trier à chaque insertion.
fn evict_target(cap: usize) -> usize {
    cap.saturating_sub(cap / 10 + 1)
}

/// Fait de la place avant l'insertion d'une nouvelle clé : on évince d'abord
/// les entrées non bloquées les plus anciennes, puis, si tout est bloqué,
/// les blocages qui expirent le plus tôt.
fn evict_failures(map: &mut HashMap<String, Failures>, now: i64, cap: usize) {
    if map.len() < cap {
        return;
    }
    let target = evict_target(cap);
    let mut free: Vec<(i64, String)> =
        map.iter().filter(|(_, f)| f.locked_until <= now).map(|(k, f)| (f.last, k.clone())).collect();
    free.sort_unstable();
    for (_, k) in free {
        if map.len() <= target {
            return;
        }
        map.remove(&k);
    }
    let mut locked: Vec<(i64, String)> = map.iter().map(|(k, f)| (f.locked_until, k.clone())).collect();
    locked.sort_unstable();
    for (_, k) in locked {
        if map.len() <= target {
            return;
        }
        map.remove(&k);
    }
}

fn evict_windows(map: &mut HashMap<String, Window>, cap: usize) {
    if map.len() < cap {
        return;
    }
    let target = evict_target(cap);
    let mut all: Vec<(i64, String)> = map.iter().map(|(k, w)| (w.start, k.clone())).collect();
    all.sort_unstable();
    for (_, k) in all {
        if map.len() <= target {
            return;
        }
        map.remove(&k);
    }
}

/// Blocage progressif après échecs (30 s, 60 s, 120 s… jusqu'à 1 h) et
/// plafonds de requêtes par fenêtre de temps.
#[derive(Default)]
pub struct Limiter {
    failures: Mutex<HashMap<String, Failures>>,
    windows: Mutex<HashMap<String, Window>>,
}

impl Limiter {
    pub fn check(&self, key: &str) -> ApiResult<()> {
        let now = now_unix();
        let map = self.failures.lock().unwrap_or_else(|p| p.into_inner());
        match map.get(key) {
            Some(f) if f.locked_until > now => Err(ApiError::rate_limited(f.locked_until - now)),
            _ => Ok(()),
        }
    }

    /// Entrée d'une clé, créée au besoin après éviction si la table est pleine.
    fn entry<'a>(map: &'a mut HashMap<String, Failures>, key: &str, now: i64) -> &'a mut Failures {
        if !map.contains_key(key) {
            evict_failures(map, now, LIMITER_MAX_ENTRIES);
        }
        map.entry(key.to_string()).or_default()
    }

    /// Compte un échec et pose le blocage à partir du seuil.
    fn count_failure(f: &mut Failures, threshold: u32, now: i64, l: &Lockout) {
        f.count += 1;
        f.last = now;
        if f.count >= threshold {
            f.locked_until = now + lock_delay(f.count, threshold, l);
            f.locked_at = f.count;
        }
    }

    pub fn fail(&self, key: &str, threshold: u32) {
        let now = now_unix();
        let mut map = self.failures.lock().unwrap_or_else(|p| p.into_inner());
        Self::count_failure(Self::entry(&mut map, key, now), threshold, now, &Lockout::default());
    }

    /// Compte une tentative AVANT de la juger (calcul Argon2, liaison LDAP),
    /// sous un seul verrou : des requêtes parallèles ne peuvent pas dépasser
    /// le seuil. Refuse si la clé est déjà bloquée. Une tentative qui s'avère
    /// ne pas être un échec se rend avec [`Limiter::release`], une réussite
    /// complète avec [`Limiter::success`]. Délais par défaut (30 s à 1 h).
    pub fn attempt(&self, key: &str, threshold: u32) -> ApiResult<()> {
        self.attempt_with(key, threshold, &Lockout::default())
    }

    /// Comme [`Limiter::attempt`], avec les délais de blocage `l` (réglages
    /// `lockout.*`). Le seuil est passé à part : `l.pair` ou `l.account`.
    pub fn attempt_with(&self, key: &str, threshold: u32, l: &Lockout) -> ApiResult<()> {
        let now = now_unix();
        let mut map = self.failures.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(f) = map.get(key) {
            if f.locked_until > now {
                return Err(ApiError::rate_limited(f.locked_until - now));
            }
        }
        Self::count_failure(Self::entry(&mut map, key, now), threshold.max(1), now, l);
        Ok(())
    }

    /// La clé est-elle bloquée en ce moment ? (tests seulement)
    #[cfg(test)]
    pub fn is_locked(&self, key: &str) -> bool {
        self.check(key).is_err()
    }

    /// Rend une tentative comptée par [`Limiter::attempt`] qui n'était pas un
    /// échec (code TOTP manquant, serveur saturé). Le blocage posé par cette
    /// tentative même est levé : quatre fautes de frappe suivies du bon mot
    /// de passe (code TOTP encore à saisir) ne bloquent pas le compte. Un
    /// blocage posé par des échecs réels reste : tant qu'il court, aucune
    /// autre tentative n'est comptée, donc aucune ne peut être rendue.
    pub fn release(&self, key: &str) {
        let now = now_unix();
        let mut map = self.failures.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(f) = map.get_mut(key) {
            if f.locked_until > now && f.locked_at == f.count {
                f.locked_until = 0;
            }
            f.count = f.count.saturating_sub(1);
        }
    }

    pub fn success(&self, key: &str) {
        self.failures.lock().unwrap_or_else(|p| p.into_inner()).remove(key);
    }

    pub fn hit(&self, key: &str, max: u32, window_secs: i64) -> ApiResult<()> {
        let now = now_unix();
        let mut map = self.windows.lock().unwrap_or_else(|p| p.into_inner());
        if !map.contains_key(key) {
            evict_windows(&mut map, LIMITER_MAX_ENTRIES);
        }
        let w = map.entry(key.to_string()).or_default();
        if now - w.start >= window_secs {
            w.start = now;
            w.hits = 0;
        }
        w.hits += 1;
        if w.hits > max {
            return Err(ApiError::rate_limited(window_secs - (now - w.start)));
        }
        Ok(())
    }

    pub fn cleanup(&self) {
        let now = now_unix();
        self.failures.lock().unwrap_or_else(|p| p.into_inner()).retain(|_, f| now - f.last < 86_400);
        self.windows.lock().unwrap_or_else(|p| p.into_inner()).retain(|_, w| now - w.start < 3_600);
    }
}

// ------------------------------------------------------------ Validation

pub fn normalize_email(email: &str) -> ApiResult<String> {
    let e = email.trim().to_lowercase();
    let valid = e.len() <= 254
        && !e.chars().any(|c| c.is_whitespace() || c.is_control())
        && e.split_once('@').is_some_and(|(l, d)| !l.is_empty() && d.contains('.') && !d.starts_with('.'));
    if !valid {
        return Err(ApiError::bad_request("Adresse e-mail invalide."));
    }
    Ok(e)
}

pub fn clean_name(name: &str) -> ApiResult<String> {
    let n = name.trim();
    // Un nom fait seulement de caractères invisibles (espace sans chasse,
    // marques de direction, BOM) s'afficherait vide : refusé comme un nom vide.
    let invisible = |c: char| {
        c.is_whitespace()
            || matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{FEFF}')
    };
    if n.chars().all(invisible) || n.chars().count() > 100 || n.chars().any(|c| c.is_control()) {
        return Err(ApiError::bad_request("Le nom doit faire entre 1 et 100 caractères."));
    }
    Ok(n.to_string())
}

/// Nom facultatif (invitation) : vide accepté, sinon mêmes règles que `clean_name`.
pub fn clean_optional_name(name: &str) -> ApiResult<String> {
    if name.trim().is_empty() {
        return Ok(String::new());
    }
    clean_name(name)
}

pub fn key32(b64: &str, what: &str) -> ApiResult<Vec<u8>> {
    match b64d(b64) {
        Ok(v) if v.len() == 32 => Ok(v),
        _ => Err(ApiError::bad_request(format!("{what} invalide."))),
    }
}

/// Identifiant reçu dans un CORPS de requête : 400 s'il est mal formé.
pub fn uuid(s: &str, what: &str) -> ApiResult<()> {
    if locksy_core::crypto::is_uuid(s) {
        Ok(())
    } else {
        Err(ApiError::bad_request(format!("Identifiant {what} invalide.")))
    }
}

/// Identifiant reçu dans le CHEMIN : un identifiant mal formé désigne une
/// ressource qui n'existe pas (404 « <what> introuvable. »).
pub fn uuid_path(s: &str, what: &str) -> ApiResult<()> {
    if locksy_core::crypto::is_uuid(s) {
        Ok(())
    } else {
        Err(ApiError::not_found(format!("{what} introuvable.")))
    }
}

/// Domaine d'une adresse e-mail permis par une liste (vide : tout passe).
/// Comparaison insensible à la casse ; une entrée « exemple.fr » ne couvre
/// que ce domaine, une entrée « .exemple.fr » couvre aussi ses sous-domaines.
fn domain_in(list: &[String], email: &str) -> bool {
    if list.is_empty() {
        return true;
    }
    let Some((_, domain)) = email.trim().rsplit_once('@') else { return false };
    let domain = domain.to_ascii_lowercase();
    list.iter().map(|e| e.trim().to_ascii_lowercase()).any(|entry| match entry.strip_prefix('.') {
        Some(parent) => domain == parent || domain.ends_with(&entry),
        None => domain == entry,
    })
}

/// L'adresse appartient-elle à un domaine autorisé (`access.allowed_email_domains`) ?
pub fn email_domain_allowed(eff: &Effective, email: &str) -> bool {
    domain_in(&eff.list("access.allowed_email_domains"), email)
}

/// Refus d'une adresse hors des domaines autorisés (403 `domain_not_allowed`).
pub fn require_email_domain(eff: &Effective, email: &str) -> ApiResult<()> {
    if email_domain_allowed(eff, email) {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "domain_not_allowed",
            "Cette adresse e-mail n'appartient pas à un domaine autorisé par votre organisation.",
        ))
    }
}

/// Paramètres de dérivation du client au moins égaux aux planchers de
/// l'organisation (`kdf.min_memory_mib`, `kdf.min_iterations`), sinon 422
/// `kdf_too_weak`. Les bornes absolues restent celles de [`kdf`].
pub fn kdf_policy(eff: &Effective, k: &KdfParams) -> ApiResult<()> {
    let min_m = u32::try_from(eff.int("kdf.min_memory_mib").max(19).saturating_mul(1024)).unwrap_or(u32::MAX);
    let min_t = u32::try_from(eff.int("kdf.min_iterations").max(2)).unwrap_or(u32::MAX);
    if k.m_kib < min_m || k.t < min_t {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "kdf_too_weak",
            format!(
                "Paramètres de protection du mot de passe trop faibles : au moins {} Mio et {} passes exigés.",
                min_m / 1024,
                min_t
            ),
        ));
    }
    Ok(())
}

// ------------------------------------------------------------ Codes de secours 2FA

/// Nombre de codes de secours délivrés à la fois.
pub const RECOVERY_CODES: usize = 10;

/// Libellé de la sous-clé serveur des empreintes de codes de secours (C0.11).
const RECOVERY_CODE_LABEL: &str = "verrou/v1/totp-recovery-code";

/// Alphabet de Crockford sans I, L, O ni U : aucun caractère ambigu à la
/// recopie. 32 symboles : un octet aléatoire réduit modulo 32 reste uniforme.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Nouveaux codes de secours, au format « XXXXX-XXXXX ». Un code n'est jamais
/// fait que de chiffres : il se distingue toujours d'un code TOTP.
pub fn new_recovery_codes() -> Vec<String> {
    let mut codes = Vec::with_capacity(RECOVERY_CODES);
    while codes.len() < RECOVERY_CODES {
        let raw: String = random_array::<10>().iter().map(|b| CROCKFORD[usize::from(b & 31)] as char).collect();
        if raw.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let code = format!("{}-{}", &raw[..5], &raw[5..]);
        if !codes.contains(&code) {
            codes.push(code);
        }
    }
    codes
}

/// Forme comparée d'un code de secours : majuscules, sans tiret ni espace.
pub fn normalize_recovery_code(code: &str) -> String {
    code.chars().filter(|c| *c != '-' && !c.is_whitespace()).collect::<String>().to_uppercase()
}

/// Le code saisi a-t-il la forme d'un code de secours (au moins 10
/// caractères, pas tous des chiffres) plutôt que celle d'un code TOTP ?
pub fn looks_like_recovery_code(code: &str) -> bool {
    let n = normalize_recovery_code(code);
    n.chars().count() >= 10 && !n.chars().all(|c| c.is_ascii_digit())
}

/// Empreinte stockée d'un code de secours : hex HMAC-SHA256 avec une
/// sous-clé du serveur, sur « <id du compte>:<code normalisé> ».
pub fn recovery_code_hash(server_key: &SecretKey, user_id: &str, code: &str) -> String {
    let key = derive_subkey(server_key, RECOVERY_CODE_LABEL);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_bytes()).expect("clé HMAC valide");
    mac.update(user_id.as_bytes());
    mac.update(b":");
    mac.update(normalize_recovery_code(code).as_bytes());
    mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

// ------------------------------------------------------------ Réauthentification (step-up)

/// Actions qui acceptent un jeton de réauthentification.
pub const STEP_UP_ACTIONS: &[&str] = &[
    "settings",
    "admin.role",
    "admin.offboard",
    "admin.delete_user",
    "admin.reset_2fa",
    "admin.bulk",
    "scim.token",
    "vault.export",
    "totp.disable",
    "totp.recovery_codes",
    "recovery.rotate",
];

/// Actions pour lesquelles un compte doté de la 2FA doit aussi fournir un
/// code (ou un code de secours) pour obtenir le jeton.
pub const STEP_UP_SECOND_FACTOR: &[&str] = &["totp.disable", "totp.recovery_codes", "recovery.rotate", "vault.export"];

/// Durée de vie d'un jeton de réauthentification, en secondes.
pub const STEP_UP_TTL_SECS: i64 = 120;

/// Préfixe des jetons (version du format).
const STEP_UP_PREFIX: &str = "rt1.";

/// Nombre maximal de jetons en mémoire : au-delà, les plus proches de
/// l'expiration sont évincés.
const STEP_UP_MAX: usize = 100_000;

/// Essais de preuve tolérés avant blocage, par compte.
const REAUTH_THRESHOLD: u32 = 5;

/// En-tête qui porte le jeton (ou, pour « settings », la preuve historique).
pub const REAUTH_HEADER: &str = "x-locksy-reauth";

/// Jeton délivré : lié au compte, à la session et à l'action.
struct StepUp {
    user_id: String,
    session_id: String,
    action: &'static str,
    expires_at: i64,
}

/// Jetons en mémoire, indexés par leur empreinte SHA-256 (jamais en clair).
/// Un redémarrage les invalide tous : la personne recommence la confirmation.
static STEP_UPS: OnceLock<Mutex<HashMap<String, StepUp>>> = OnceLock::new();

fn step_ups() -> MutexGuard<'static, HashMap<String, StepUp>> {
    STEP_UPS.get_or_init(Mutex::default).lock().unwrap_or_else(|p| p.into_inner())
}

/// Action connue, sous sa forme statique.
pub fn step_up_action(action: &str) -> Option<&'static str> {
    STEP_UP_ACTIONS.iter().copied().find(|a| *a == action)
}

/// Délivre un jeton de réauthentification (« rt1. » + 43 caractères base64 URL).
pub(crate) fn issue_step_up(user_id: &str, session_id: &str, action: &'static str) -> String {
    let token = format!("{STEP_UP_PREFIX}{}", b64e(&random_array::<32>()));
    let now = now_unix();
    let mut map = step_ups();
    map.retain(|_, s| s.expires_at > now);
    if map.len() >= STEP_UP_MAX {
        let mut by_expiry: Vec<(i64, String)> = map.iter().map(|(k, s)| (s.expires_at, k.clone())).collect();
        by_expiry.sort_unstable();
        for (_, k) in by_expiry.into_iter().take(STEP_UP_MAX / 10 + 1) {
            map.remove(&k);
        }
    }
    map.insert(
        sha256_hex(&token),
        StepUp {
            user_id: user_id.to_string(),
            session_id: session_id.to_string(),
            action,
            expires_at: now + STEP_UP_TTL_SECS,
        },
    );
    token
}

fn reauth_invalid() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "reauth_invalid",
        "Confirmation expirée ou déjà utilisée. Confirmez de nouveau votre identité.",
    )
}

/// Consomme un jeton : il ne sert qu'une fois, même présenté à tort (autre
/// action, autre session), et seulement avant son expiration.
fn take_step_up(token: &str, user_id: &str, session_id: &str, action: &str) -> ApiResult<()> {
    let found = step_ups().remove(&sha256_hex(token));
    match found {
        Some(s)
            if s.expires_at > now_unix()
                && s.action == action
                && bool::from(s.user_id.as_bytes().ct_eq(user_id.as_bytes()))
                && bool::from(s.session_id.as_bytes().ct_eq(session_id.as_bytes())) =>
        {
            Ok(())
        }
        _ => Err(reauth_invalid()),
    }
}

/// Vérifie la preuve du mot de passe maître actuel d'un compte (limiteur
/// `reauth:<id>`, 5 essais). Renvoie l'empreinte vérifiée, pour une mise à
/// jour conditionnelle. `wrong` construit l'erreur d'une preuve refusée.
pub(crate) async fn check_password_proof(
    state: &AppState,
    user_id: &str,
    proof_b64: &str,
    wrong: fn() -> ApiError,
) -> ApiResult<String> {
    let proof = b64d(proof_b64).ok().filter(|p| p.len() == 32).ok_or_else(wrong)?;
    let key = format!("reauth:{user_id}");
    // Tentative comptée avant le calcul Argon2 : les requêtes parallèles ne
    // dépassent pas le seuil.
    state.limiter.attempt(&key, REAUTH_THRESHOLD)?;
    let uid = user_id.to_string();
    let hash: String =
        state.db.read(move |c| Ok(c.query_row("SELECT auth_hash FROM users WHERE id = ?1", [uid], |r| r.get(0))?)).await?;
    match verify_secret(proof, hash.clone()).await {
        Ok(true) => {
            state.limiter.success(&key);
            Ok(hash)
        }
        Ok(false) => Err(wrong()),
        Err(e) => {
            // Serveur saturé : rien n'a été vérifié.
            state.limiter.release(&key);
            Err(e)
        }
    }
}

/// Preuve refusée lors d'une confirmation d'identité (403).
pub(crate) fn wrong_password() -> ApiError {
    ApiError::new(StatusCode::FORBIDDEN, "invalid_credentials", "Mot de passe maître incorrect.")
}

/// Preuve historique refusée (en-tête de « settings ») : 401, comme avant
/// les jetons, pour les clients existants.
fn wrong_password_legacy() -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, "invalid_credentials", "Mot de passe maître incorrect.")
}

/// Exige une réauthentification récente pour `action` : en-tête
/// `X-Locksy-Reauth: rt1.<jeton>` délivré par `POST /auth/reauth` pour cette
/// action, ce compte et cette session ; le jeton est consommé.
///
/// - absent : 428 `reauth_required` ;
/// - faux, périmé, déjà utilisé ou d'une autre action : 403 `reauth_invalid` ;
/// - forme historique (base64 de la preuve du mot de passe maître) : acceptée
///   pour « settings » seulement (401 `invalid_credentials` si refusée).
pub(crate) async fn require_step_up(
    state: &AppState,
    user: &AuthUser,
    headers: &HeaderMap,
    action: &'static str,
) -> ApiResult<()> {
    let Some(raw) = headers.get(REAUTH_HEADER).and_then(|v| v.to_str().ok()).map(str::trim).filter(|v| !v.is_empty())
    else {
        return Err(ApiError::new(
            StatusCode::PRECONDITION_REQUIRED,
            "reauth_required",
            "Confirmez votre identité avec votre mot de passe maître pour continuer.",
        ));
    };
    if raw.starts_with(STEP_UP_PREFIX) {
        return take_step_up(raw, &user.id, &user.session_id, action);
    }
    if action != "settings" {
        return Err(reauth_invalid());
    }
    check_password_proof(state, &user.id, raw, wrong_password_legacy).await.map(|_| ())
}

#[cfg(test)]
pub(crate) mod testing {
    /// Fait expirer tous les jetons de réauthentification d'un compte.
    pub(crate) fn expire_step_ups(user_id: &str) {
        for s in super::step_ups().values_mut().filter(|s| s.user_id == user_id) {
            s.expires_at = 0;
        }
    }
}

pub fn cipher(s: &str, max_len: usize, what: &str) -> ApiResult<()> {
    if is_well_formed_cipher(s, max_len) {
        Ok(())
    } else {
        Err(ApiError::bad_request(format!("Donnée chiffrée invalide ou trop volumineuse ({what}).")))
    }
}

pub fn sealed(s: &str) -> ApiResult<()> {
    if is_well_formed_sealed(s) {
        Ok(())
    } else {
        Err(ApiError::bad_request("Clé scellée invalide."))
    }
}

pub fn kdf(k: &KdfParams) -> ApiResult<()> {
    k.validate().map_err(|e| ApiError::bad_request(e.to_string()))
}

pub const KEY_CIPHER_MAX: usize = 512;
pub const NAME_CIPHER_MAX: usize = 2_048;
pub const ITEM_CIPHER_MAX: usize = 262_144;
pub const SHARE_CIPHER_MAX: usize = 65_536;

// ------------------------------------------------------------ Refus par défaut

/// Routes servies sans session (méthode, chemin complet), vérifiées handler
/// par handler : aucune ne prend `AuthUser` ni `AdminUser`. Chacune a sa
/// propre protection : limiteur par adresse, jeton à usage unique, preuve de
/// possession ou réponse anodine. Toute autre route de l'API exige un en-tête
/// `Authorization: Bearer` (couche [`refus_par_defaut`]) ; la matrice
/// d'autorisation (tests/authz_matrix.rs) vérifie la liste contre les routes.
pub const PUBLIQUES: &[(&str, &str)] = &[
    // Sondes de supervision (aucune donnée).
    ("GET", "/api/health"),
    ("GET", "/api/ready"),
    // Connexion, installation, récupération : limiteurs par adresse et par compte.
    ("POST", "/api/auth/prelogin"),
    ("POST", "/api/auth/register"),
    ("POST", "/api/auth/login"),
    ("POST", "/api/auth/recover/start"),
    ("POST", "/api/auth/recover/finish"),
    // Invitation : le jeton est la preuve.
    ("GET", "/api/invites/:token"),
    // Connexion d'entreprise (OIDC, Active Directory).
    ("GET", "/api/sso/start"),
    ("GET", "/api/sso/callback"),
    ("POST", "/api/sso/redeem"),
    ("POST", "/api/ldap/login"),
    // Liens de partage : identifiant secret et preuve de la clé du fragment.
    ("GET", "/api/public/shares/:id"),
    ("POST", "/api/public/shares/:id/peek"),
    ("POST", "/api/public/shares/:id/open"),
    ("GET", "/s/:id"),
    // Écran de connexion : nom, logo et options publiques de l'organisation.
    ("GET", "/api/settings/public"),
    ("GET", "/api/branding/logo"),
    // L'extension vérifie qu'elle est autorisée avant toute connexion.
    ("GET", "/api/extension/allowed"),
    // Compteurs de test : 404 hors LOCKSY_ENV=test.
    ("GET", "/api/test/counters"),
];

/// Route publique ? `chemin` : gabarit de la route (`MatchedPath`), avec ou
/// sans le préfixe `/api` selon le routeur qui l'a résolu. HEAD suit GET.
pub fn route_publique(methode: &axum::http::Method, chemin: &str) -> bool {
    let methode = if methode == axum::http::Method::HEAD { "GET" } else { methode.as_str() };
    let complet = if chemin.starts_with("/api/") { chemin.to_string() } else { format!("/api{chemin}") };
    PUBLIQUES.iter().any(|(m, c)| *m == methode && *c == complet)
}

/// Couche de refus par défaut de l'API (constat #54) : une route hors de
/// [`PUBLIQUES`] sans `Authorization: Bearer <1 à 128 caractères>` reçoit 401
/// avant son handler. Une route ajoutée sans `AuthUser` reste ainsi fermée ;
/// la session elle-même est vérifiée ensuite par `AuthUser`.
pub async fn refus_par_defaut(req: axum::extract::Request, next: axum::middleware::Next) -> axum::response::Response {
    use axum::response::IntoResponse;
    let publique = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .is_some_and(|p| route_publique(req.method(), p.as_str()));
    let jeton = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(crate::state::bearer_token)
        .is_some_and(|t| !t.is_empty() && t.len() <= 128);
    if publique || jeton {
        next.run(req).await
    } else {
        ApiError::unauthorized("Connexion requise.").into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count(l: &Limiter, key: &str) -> u32 {
        l.failures.lock().unwrap().get(key).map_or(0, |f| f.count)
    }

    #[test]
    fn nom_invisible_refuse() {
        assert_eq!(clean_name("  Alice Martin ").unwrap(), "Alice Martin");
        assert_eq!(clean_name("Zoë\u{200B}").unwrap(), "Zoë\u{200B}", "un caractère invisible au milieu d'un vrai nom reste admis");
        for n in ["", "   ", "\u{200B}", "\u{200B}\u{200E}", "\u{FEFF}", " \u{2060} ", &"a".repeat(101), "a\u{7}b"] {
            assert!(clean_name(n).is_err(), "{n:?} devrait être refusé");
        }
    }

    #[test]
    fn liste_des_routes_publiques() {
        use axum::http::Method;
        assert!(route_publique(&Method::GET, "/api/health"));
        assert!(route_publique(&Method::GET, "/health"), "gabarit sans le préfixe du routeur imbriqué");
        assert!(route_publique(&Method::HEAD, "/api/health"), "HEAD suit GET");
        assert!(route_publique(&Method::POST, "/api/public/shares/:id/open"));
        assert!(!route_publique(&Method::POST, "/api/health"), "la méthode compte");
        assert!(!route_publique(&Method::GET, "/api/me"));
        assert!(!route_publique(&Method::GET, "/api/public/shares/abc"), "gabarit, jamais chemin concret");
    }

    /// Une route sans `AuthUser` (oubli) est fermée par la couche ; une route
    /// publique reste ouverte ; un jeton passe la couche.
    #[tokio::test]
    async fn refus_par_defaut_ferme_une_route_oubliee() {
        use axum::routing::get;
        let api = axum::Router::new()
            .route("/health", get(|| async { "ok" }))
            .route("/oubliee", get(|| async { "ouverte" }))
            .route_layer(axum::middleware::from_fn(refus_par_defaut));
        let app = axum::Router::new().nest("/api", api);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let http = reqwest::Client::new();
        let get = |path: &str, jeton: Option<String>| {
            let mut r = http.get(format!("http://{addr}{path}"));
            if let Some(j) = jeton {
                r = r.header("authorization", format!("Bearer {j}"));
            }
            r.send()
        };
        assert_eq!(get("/api/health", None).await.unwrap().status(), 200);
        let refus = get("/api/oubliee", None).await.unwrap();
        assert_eq!(refus.status(), 401);
        let corps: serde_json::Value = refus.json().await.unwrap();
        assert_eq!(corps["error"], "unauthorized");
        assert_eq!(get("/api/oubliee", Some("a".repeat(200))).await.unwrap().status(), 401);
        assert_eq!(get("/api/oubliee", Some("abc".into())).await.unwrap().status(), 200);
    }

    #[test]
    fn attempt_bloque_au_seuil() {
        let l = Limiter::default();
        for _ in 0..5 {
            assert!(l.attempt("k", 5).is_ok());
        }
        let e = l.attempt("k", 5).unwrap_err();
        assert_eq!(e.code, "rate_limited");
        assert_eq!(e.status, StatusCode::TOO_MANY_REQUESTS);
        assert!(l.check("k").is_err());
    }

    #[test]
    fn release_rend_la_tentative() {
        let l = Limiter::default();
        l.attempt("k", 5).unwrap();
        l.attempt("k", 5).unwrap();
        let avant = count(&l, "k");
        l.attempt("k", 5).unwrap();
        l.release("k");
        assert_eq!(count(&l, "k"), avant);
        // Jamais négatif, et sans effet sur une clé inconnue.
        for _ in 0..4 {
            l.release("k");
        }
        assert_eq!(count(&l, "k"), 0);
        l.release("absente");
        assert_eq!(count(&l, "absente"), 0);
    }

    #[test]
    fn release_leve_seulement_le_blocage_de_sa_tentative() {
        let l = Limiter::default();
        // Quatre échecs, puis une tentative qui pose le blocage et s'avère
        // ne pas être un échec : le blocage est levé.
        for _ in 0..5 {
            l.attempt("k", 5).unwrap();
        }
        assert!(l.is_locked("k"));
        l.release("k");
        assert!(!l.is_locked("k"));
        assert_eq!(count(&l, "k"), 4);
        // La tentative suivante échoue réellement (rien n'est rendu) : le
        // blocage reste et les tentatives suivantes ne sont pas comptées.
        l.attempt("k", 5).unwrap();
        assert!(l.is_locked("k"));
        assert!(l.attempt("k", 5).is_err());
        assert_eq!(count(&l, "k"), 5);
    }

    #[test]
    fn success_debloque() {
        let l = Limiter::default();
        for _ in 0..5 {
            l.attempt("k", 5).unwrap();
        }
        assert!(l.attempt("k", 5).is_err());
        l.success("k");
        assert!(l.check("k").is_ok());
        assert!(l.attempt("k", 5).is_ok());
    }

    #[test]
    fn attempt_concurrent_ne_depasse_pas_le_seuil() {
        let l = Limiter::default();
        let ok = AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..16 {
                s.spawn(|| {
                    if l.attempt("k", 5).is_ok() {
                        ok.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(ok.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn progression_du_blocage() {
        let d = Lockout::default();
        assert_eq!(lock_delay(5, 5, &d), 30);
        assert_eq!(lock_delay(6, 5, &d), 60);
        assert_eq!(lock_delay(7, 5, &d), 120);
        assert_eq!(lock_delay(100, 5, &d), 3600);
        assert_eq!(lock_delay(1, 5, &d), 30);
        // Délais réglés : base de 10 s, plafond de 45 s.
        let r = Lockout { pair: 3, account: 10, base_delay: 10, max_delay: 45 };
        assert_eq!(lock_delay(3, 3, &r), 10);
        assert_eq!(lock_delay(4, 3, &r), 20);
        assert_eq!(lock_delay(5, 3, &r), 40);
        assert_eq!(lock_delay(6, 3, &r), 45);
        assert_eq!(lock_delay(u32::MAX, 3, &r), 45);
    }

    #[test]
    fn attempt_with_suit_les_delais_regles() {
        let l = Limiter::default();
        let r = Lockout { pair: 3, account: 10, base_delay: 7, max_delay: 60 };
        for _ in 0..3 {
            l.attempt_with("k", r.pair, &r).unwrap();
        }
        let e = l.attempt_with("k", r.pair, &r).unwrap_err();
        assert_eq!(e.code, "rate_limited");
        assert!(e.retry_after.is_some_and(|s| (1..=7).contains(&s)), "{:?}", e.retry_after);
        assert!(l.is_locked("k"));
        assert!(!l.is_locked("autre"));
    }

    #[test]
    fn empreinte_a_recalculer() {
        let ours = phc_with(ARGON_M_KIB, ARGON_T, ARGON_P);
        assert!(!needs_rehash(&ours));
        assert!(needs_rehash(&phc_with(8 * 1024, 1, 1)));
        assert!(needs_rehash(&phc_with(ARGON_M_KIB, 3, 1)));
        assert!(!needs_rehash("pas un PHC"));
    }

    /// Empreinte Argon2id calculée avec des paramètres donnés.
    fn phc_with(m: u32, t: u32, p: u32) -> String {
        let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(m, t, p, None).unwrap());
        a.hash_password(b"preuve", &SaltString::generate(&mut OsRng)).unwrap().to_string()
    }

    #[test]
    fn domaines_autorises() {
        let list = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(domain_in(&[], "a@b.fr"));
        let l = list(&["exemple.fr", ".groupe.fr"]);
        assert!(domain_in(&l, "alice@exemple.fr"));
        assert!(domain_in(&l, "Alice@EXEMPLE.FR"));
        assert!(!domain_in(&l, "alice@sous.exemple.fr"), "sous-domaine non inclus");
        assert!(!domain_in(&l, "alice@exemple.fr.pirate.com"));
        assert!(!domain_in(&l, "alice@autreexemple.fr"));
        assert!(domain_in(&l, "bob@groupe.fr"));
        assert!(domain_in(&l, "bob@paris.groupe.fr"), "entrée « .groupe.fr » : sous-domaines inclus");
        assert!(!domain_in(&l, "bob@pasgroupe.fr"));
        assert!(!domain_in(&l, "sans-arobase"));
    }

    #[test]
    fn identifiant_de_chemin() {
        assert!(uuid_path(&locksy_core::crypto::new_uuid(), "Élément").is_ok());
        let e = uuid_path("../etc", "Élément").unwrap_err();
        assert_eq!((e.status, e.code), (StatusCode::NOT_FOUND, "not_found"));
        assert_eq!(e.message, "Élément introuvable.");
        // Les corps gardent le 400.
        assert_eq!(uuid("x", "coffre").unwrap_err().status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn codes_de_secours_bien_formes() {
        let codes = new_recovery_codes();
        assert_eq!(codes.len(), RECOVERY_CODES);
        for c in &codes {
            assert_eq!(c.len(), 11, "{c}");
            assert_eq!(&c[5..6], "-");
            assert!(c.chars().filter(|ch| *ch != '-').all(|ch| CROCKFORD.contains(&(ch as u8))), "{c}");
            assert!(!c.contains(['I', 'L', 'O', 'U']));
            assert!(looks_like_recovery_code(c));
        }
        let mut uniques = codes.clone();
        uniques.sort();
        uniques.dedup();
        assert_eq!(uniques.len(), RECOVERY_CODES);
        // Un code TOTP n'a pas la forme d'un code de secours.
        assert!(!looks_like_recovery_code("123456"));
        assert!(!looks_like_recovery_code("12345-67890"));
        assert!(looks_like_recovery_code(" ab3de fgh2k "));
    }

    #[test]
    fn empreinte_de_code_de_secours() {
        let k = SecretKey::generate();
        let h = recovery_code_hash(&k, "u1", "ABCDE-FGH2K");
        assert_eq!(h.len(), 64);
        // Saisie tolérante : casse, tiret et espaces ignorés.
        assert_eq!(h, recovery_code_hash(&k, "u1", "abcde fgh2k"));
        assert_eq!(h, recovery_code_hash(&k, "u1", "ABCDEFGH2K"));
        // Liée au compte et à la clé du serveur.
        assert_ne!(h, recovery_code_hash(&k, "u2", "ABCDE-FGH2K"));
        assert_ne!(h, recovery_code_hash(&SecretKey::generate(), "u1", "ABCDE-FGH2K"));
    }

    #[test]
    fn jeton_de_reauthentification_a_usage_unique() {
        let t = issue_step_up("u1", "s1", "vault.export");
        assert!(t.starts_with("rt1.") && t.len() == 4 + 43, "{t}");
        // Autre session, autre compte, autre action : refusé et consommé.
        assert_eq!(take_step_up(&t, "u1", "s2", "vault.export").unwrap_err().code, "reauth_invalid");
        assert_eq!(take_step_up(&t, "u1", "s1", "vault.export").unwrap_err().code, "reauth_invalid");
        let t = issue_step_up("u1", "s1", "vault.export");
        assert_eq!(take_step_up(&t, "u1", "s1", "settings").unwrap_err().code, "reauth_invalid");
        let t = issue_step_up("u1", "s1", "vault.export");
        assert!(take_step_up(&t, "u1", "s1", "vault.export").is_ok());
        assert_eq!(take_step_up(&t, "u1", "s1", "vault.export").unwrap_err().code, "reauth_invalid", "rejoué");
        // Périmé.
        let t = issue_step_up("u2", "s1", "totp.disable");
        testing::expire_step_ups("u2");
        assert_eq!(take_step_up(&t, "u2", "s1", "totp.disable").unwrap_err().code, "reauth_invalid");
        assert_eq!(step_up_action("admin.role"), Some("admin.role"));
        assert_eq!(step_up_action("admin.tout"), None);
    }

    #[test]
    fn table_bornee_evince_d_abord_les_entrees_libres() {
        let now = 1_000;
        let mut map: HashMap<String, Failures> = HashMap::new();
        for i in 0..10 {
            let locked_until = if i < 3 { now + 60 } else { 0 };
            map.insert(format!("k{i}"), Failures { count: 1, locked_until, last: i, locked_at: 1 });
        }
        evict_failures(&mut map, now, 10);
        assert!(map.len() < 10);
        // Les entrées bloquées sont conservées.
        for i in 0..3 {
            assert!(map.contains_key(&format!("k{i}")));
        }
        // Les plus récentes des entrées libres restent.
        assert!(map.contains_key("k9"));
        assert!(!map.contains_key("k3"));

        // Tout est bloqué : la table reste bornée malgré tout.
        let mut all_locked: HashMap<String, Failures> = HashMap::new();
        for i in 0..10 {
            all_locked.insert(format!("k{i}"), Failures { count: 9, locked_until: now + 100 + i, last: i, locked_at: 9 });
        }
        evict_failures(&mut all_locked, now, 10);
        assert!(all_locked.len() < 10);
        assert!(all_locked.contains_key("k9"));

        let mut w: HashMap<String, Window> = HashMap::new();
        for i in 0..10 {
            w.insert(format!("w{i}"), Window { start: i, hits: 1 });
        }
        evict_windows(&mut w, 10);
        assert!(w.len() < 10);
        assert!(w.contains_key("w9"));
        assert!(!w.contains_key("w0"));
    }

    #[tokio::test]
    async fn hachage_aller_retour() {
        let phc = hash_secret(b"preuve".to_vec()).await.unwrap();
        assert!(verify_secret(b"preuve".to_vec(), phc.clone()).await.unwrap());
        assert!(!verify_secret(b"autre".to_vec(), phc).await.unwrap());
        assert!(!verify_secret(b"preuve".to_vec(), "pas un PHC".into()).await.unwrap());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn porte_saturee_renvoie_server_busy() {
        let g: &'static ArgonGate = Box::leak(Box::new(ArgonGate::new(1, 0)));
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        // Premier calcul : tient le permis jusqu'au signal.
        let first = tokio::spawn(run_argon_with(g, move || {
            let _ = rx.recv();
            7
        }));
        while g.sem.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
        let e = verify_secret_with(g, b"x".to_vec(), "pas un PHC".into()).await.unwrap_err();
        assert_eq!(e.code, "server_busy");
        assert_eq!(e.status, StatusCode::SERVICE_UNAVAILABLE);
        let e = hash_secret_with(g, b"x".to_vec()).await.unwrap_err();
        assert_eq!(e.code, "server_busy");
        assert_eq!(g.waiting.load(Ordering::SeqCst), 0);
        tx.send(()).unwrap();
        assert_eq!(first.await.unwrap().unwrap(), 7);
        // Permis rendu : la vérification aboutit de nouveau.
        assert!(!verify_secret_with(g, b"x".to_vec(), "pas un PHC".into()).await.unwrap());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn file_d_attente_bornee() {
        let g: &'static ArgonGate = Box::leak(Box::new(ArgonGate::new(1, 1)));
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let first = tokio::spawn(run_argon_with(g, move || {
            let _ = rx.recv();
        }));
        while g.sem.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
        // Une requête peut attendre…
        let second = tokio::spawn(run_argon_with(g, || 1));
        while g.waiting.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
        // …la suivante est refusée.
        assert_eq!(run_argon_with(g, || 2).await.unwrap_err().code, "server_busy");
        tx.send(()).unwrap();
        first.await.unwrap().unwrap();
        assert_eq!(second.await.unwrap().unwrap(), 1);
        assert_eq!(g.waiting.load(Ordering::SeqCst), 0);
    }
}
