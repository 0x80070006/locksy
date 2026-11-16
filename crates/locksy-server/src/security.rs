//! Outils de sécurité du serveur : hachage Argon2id des preuves de
//! connaissance, limitation des tentatives, validation des entrées.

use crate::error::{ApiError, ApiResult};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use locksy_core::crypto::{is_well_formed_cipher, is_well_formed_sealed, KdfParams};
use locksy_core::encoding::b64d;
use locksy_core::now_unix;

fn argon() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(19 * 1024, 2, 1, None).expect("paramètres Argon2 valides"),
    )
}

/// Hache une preuve envoyée par le client (déjà issue d'Argon2id côté poste).
pub async fn hash_secret(secret: Vec<u8>) -> ApiResult<String> {
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        argon().hash_password(&secret, &salt).map(|h| h.to_string())
    })
    .await
    .map_err(|_| ApiError::internal("hachage interrompu"))?
    .map_err(|_| ApiError::internal("hachage"))
}

pub async fn verify_secret(secret: Vec<u8>, phc: String) -> bool {
    tokio::task::spawn_blocking(move || {
        PasswordHash::new(&phc).map(|h| argon().verify_password(&secret, &h).is_ok()).unwrap_or(false)
    })
    .await
    .unwrap_or(false)
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
}

#[derive(Default)]
struct Window {
    start: i64,
    hits: u32,
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

    pub fn fail(&self, key: &str, threshold: u32) {
        let now = now_unix();
        let mut map = self.failures.lock().unwrap_or_else(|p| p.into_inner());
        let f = map.entry(key.to_string()).or_default();
        f.count += 1;
        f.last = now;
        if f.count >= threshold {
            let over = (f.count - threshold).min(7);
            f.locked_until = now + (30i64 << over).min(3600);
        }
    }

    pub fn success(&self, key: &str) {
        self.failures.lock().unwrap_or_else(|p| p.into_inner()).remove(key);
    }

    pub fn hit(&self, key: &str, max: u32, window_secs: i64) -> ApiResult<()> {
        let now = now_unix();
        let mut map = self.windows.lock().unwrap_or_else(|p| p.into_inner());
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
        && e.split_once('@').map_or(false, |(l, d)| !l.is_empty() && d.contains('.') && !d.starts_with('.'));
    if !valid {
        return Err(ApiError::bad_request("Adresse e-mail invalide."));
    }
    Ok(e)
}

pub fn clean_name(name: &str) -> ApiResult<String> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > 100 || n.chars().any(|c| c.is_control()) {
        return Err(ApiError::bad_request("Le nom doit faire entre 1 et 100 caractères."));
    }
    Ok(n.to_string())
}

pub fn key32(b64: &str, what: &str) -> ApiResult<Vec<u8>> {
    match b64d(b64) {
        Ok(v) if v.len() == 32 => Ok(v),
        _ => Err(ApiError::bad_request(format!("{what} invalide."))),
    }
}

pub fn uuid(s: &str, what: &str) -> ApiResult<()> {
    if locksy_core::crypto::is_uuid(s) {
        Ok(())
    } else {
        Err(ApiError::bad_request(format!("Identifiant {what} invalide.")))
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
