//! Primitives cryptographiques de Locksy.
//!
//! - Dérivation du mot de passe maître : Argon2id (64 Mio, 3 passes) puis
//!   HKDF-SHA256 pour séparer la clé d'authentification (envoyée au serveur)
//!   de la clé de chiffrement (qui ne quitte jamais le poste).
//! - Chiffrement symétrique : XChaCha20-Poly1305 (AEAD), nonce aléatoire de
//!   192 bits, données associées obligatoires.
//! - Partage : X25519 + HKDF-SHA256 + XChaCha20-Poly1305 (schéma ECIES), clé
//!   éphémère par scellement, contexte lié au coffre et au destinataire.
//! - Toutes les clés sont effacées de la mémoire à leur destruction.

use crate::encoding::{b64d, b64e, crockford_decode, crockford_encode, hex_upper};
use crate::{aad, Error, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use unicode_normalization::UnicodeNormalization;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const CIPHER_PREFIX: &str = "v1.";
pub const SEALED_PREFIX: &str = "s1.";
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const HKDF_SALT: &[u8] = b"verrou-v1";

// ---------------------------------------------------------------------------
// Clés
// ---------------------------------------------------------------------------

/// Clé secrète de 256 bits, effacée de la mémoire à sa destruction.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub fn generate() -> Self {
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        Self(k)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidKey)?;
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_b64(&self) -> String {
        b64e(&self.0)
    }

    pub fn from_b64(s: &str) -> Result<Self> {
        let v = Zeroizing::new(b64d(s)?);
        Self::from_slice(&v)
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<masquée>)")
    }
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    OsRng.fill_bytes(&mut v);
    v
}

pub fn random_array<const N: usize>() -> [u8; N] {
    let mut a = [0u8; N];
    OsRng.fill_bytes(&mut a);
    a
}

/// Jeton aléatoire de 256 bits encodé en base64 URL.
pub fn random_token() -> String {
    b64e(&random_array::<32>())
}

/// Identifiant UUID v4 aléatoire.
pub fn new_uuid() -> String {
    let mut b = random_array::<16>();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

pub fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit() && !c.is_ascii_uppercase(),
        })
}

fn hkdf_expand(salt: Option<&[u8]>, ikm: &[u8], info: &str) -> SecretKey {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info.as_bytes(), &mut okm)
        .expect("32 octets est une longueur valide pour HKDF-SHA256");
    let key = SecretKey(okm);
    okm.zeroize();
    key
}

/// Dérive une sous-clé indépendante à partir d'une clé et d'un libellé.
pub fn derive_subkey(key: &SecretKey, label: &str) -> SecretKey {
    hkdf_expand(Some(HKDF_SALT), key.as_bytes(), label)
}

// ---------------------------------------------------------------------------
// Chiffrement authentifié
// ---------------------------------------------------------------------------

fn cipher_for(key: &SecretKey) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(Key::from_slice(key.as_bytes()))
}

/// Chiffre `plaintext` et renvoie `v1.<base64(nonce ‖ chiffré ‖ tag)>`.
pub fn encrypt(key: &SecretKey, plaintext: &[u8], aad: &[u8]) -> String {
    let nonce: [u8; NONCE_LEN] = random_array();
    let ct = cipher_for(key)
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .expect("le chiffrement XChaCha20-Poly1305 en mémoire ne peut pas échouer");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    format!("{CIPHER_PREFIX}{}", b64e(&out))
}

pub fn decrypt(key: &SecretKey, data: &str, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let body = data.strip_prefix(CIPHER_PREFIX).ok_or(Error::Format)?;
    let raw = b64d(body)?;
    if raw.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::Format);
    }
    let (nonce, ct) = raw.split_at(NONCE_LEN);
    cipher_for(key)
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::Decrypt)
}

pub fn encrypt_str(key: &SecretKey, plaintext: &str, aad: &str) -> String {
    encrypt(key, plaintext.as_bytes(), aad.as_bytes())
}

pub fn decrypt_string(key: &SecretKey, data: &str, aad: &str) -> Result<String> {
    let pt = decrypt(key, data, aad.as_bytes())?;
    String::from_utf8(pt.to_vec()).map_err(|_| Error::Format)
}

/// Vérifie la forme d'un chiffré sans le déchiffrer (contrôle côté serveur).
pub fn is_well_formed_cipher(data: &str, max_len: usize) -> bool {
    well_formed(data, CIPHER_PREFIX, NONCE_LEN + TAG_LEN, max_len)
}

pub fn is_well_formed_sealed(data: &str) -> bool {
    well_formed(data, SEALED_PREFIX, 32 + NONCE_LEN + TAG_LEN, 512)
}

fn well_formed(data: &str, prefix: &str, min_raw: usize, max_len: usize) -> bool {
    if data.len() > max_len {
        return false;
    }
    match data.strip_prefix(prefix) {
        Some(body) => {
            body.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
                && body.len() * 3 / 4 >= min_raw
        }
        None => false,
    }
}

pub fn wrap_key(wrapping: &SecretKey, key: &SecretKey, aad: &str) -> String {
    encrypt(wrapping, key.as_bytes(), aad.as_bytes())
}

pub fn unwrap_key(wrapping: &SecretKey, data: &str, aad: &str) -> Result<SecretKey> {
    let pt = decrypt(wrapping, data, aad.as_bytes())?;
    SecretKey::from_slice(&pt)
}

// ---------------------------------------------------------------------------
// Dérivation du mot de passe maître
// ---------------------------------------------------------------------------

/// Paramètres Argon2id stockés avec le compte (ils peuvent évoluer).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub alg: String,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    pub salt: String,
}

impl KdfParams {
    pub const MIN_M_KIB: u32 = 19 * 1024;
    pub const MAX_M_KIB: u32 = 1024 * 1024;

    /// 64 Mio, 3 passes, 1 voie : au-dessus des recommandations OWASP 2024.
    pub fn recommended() -> Self {
        Self::with_salt(b64e(&random_array::<16>()))
    }

    pub fn with_salt(salt: String) -> Self {
        Self { alg: "argon2id".into(), m_kib: 64 * 1024, t: 3, p: 1, salt }
    }

    pub fn validate(&self) -> Result<()> {
        if self.alg != "argon2id" {
            return Err(Error::Kdf("seul argon2id est accepté".into()));
        }
        if !(Self::MIN_M_KIB..=Self::MAX_M_KIB).contains(&self.m_kib) {
            return Err(Error::Kdf("mémoire hors bornes".into()));
        }
        if !(2..=10).contains(&self.t) {
            return Err(Error::Kdf("nombre de passes hors bornes".into()));
        }
        if !(1..=8).contains(&self.p) {
            return Err(Error::Kdf("parallélisme hors bornes".into()));
        }
        let salt = b64d(&self.salt).map_err(|_| Error::Kdf("sel invalide".into()))?;
        if !(16..=64).contains(&salt.len()) {
            return Err(Error::Kdf("longueur de sel invalide".into()));
        }
        Ok(())
    }
}

/// Clés dérivées du mot de passe maître.
#[derive(Debug)]
pub struct MasterKeys {
    /// Preuve de connaissance du mot de passe, envoyée au serveur (qui la
    /// re-hache avec Argon2id). Ne permet pas de déchiffrer quoi que ce soit.
    pub auth_key: SecretKey,
    /// Clé qui protège la clé utilisateur. Ne quitte jamais le poste.
    pub enc_key: SecretKey,
}

pub fn derive_master_keys(password: &str, params: &KdfParams) -> Result<MasterKeys> {
    params.validate()?;
    if password.is_empty() {
        return Err(Error::InvalidInput("mot de passe vide".into()));
    }
    let salt = b64d(&params.salt)?;
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(params.m_kib, params.t, params.p, Some(32)).map_err(|e| Error::Kdf(e.to_string()))?,
    );
    // Normalisation Unicode NFC : le même mot de passe saisi sur deux systèmes
    // différents donne toujours la même clé.
    let normalized: Zeroizing<String> = Zeroizing::new(password.nfc().collect());
    let mut master = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(normalized.as_bytes(), &salt, master.as_mut())
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(MasterKeys {
        auth_key: hkdf_expand(Some(HKDF_SALT), master.as_ref(), "verrou/v1/auth"),
        enc_key: hkdf_expand(Some(HKDF_SALT), master.as_ref(), "verrou/v1/enc"),
    })
}

// ---------------------------------------------------------------------------
// Clé de récupération
// ---------------------------------------------------------------------------

/// Génère une clé de récupération de 256 bits et sa forme lisible
/// (base32 Crockford + octet de contrôle, groupes de 4 caractères).
pub fn generate_recovery_key() -> (String, SecretKey) {
    let key = SecretKey::generate();
    (format_recovery_key(&key), key)
}

pub fn format_recovery_key(key: &SecretKey) -> String {
    let mut data = Zeroizing::new(Vec::with_capacity(33));
    data.extend_from_slice(key.as_bytes());
    data.push(Sha256::digest(key.as_bytes())[0]);
    let enc = Zeroizing::new(crockford_encode(&data));
    enc.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("-")
}

pub fn parse_recovery_key(input: &str) -> Result<SecretKey> {
    let raw = Zeroizing::new(crockford_decode(input).map_err(|_| {
        Error::InvalidInput("la clé de récupération contient un caractère inconnu".into())
    })?);
    if raw.len() != 33 {
        return Err(Error::InvalidInput("la clé de récupération n'a pas la bonne longueur".into()));
    }
    let key = SecretKey::from_slice(&raw[..32])?;
    if Sha256::digest(key.as_bytes())[0] != raw[32] {
        return Err(Error::InvalidInput("clé de récupération mal recopiée (contrôle invalide)".into()));
    }
    Ok(key)
}

/// Clés dérivées de la clé de récupération.
#[derive(Debug)]
pub struct RecoveryKeys {
    pub wrap_key: SecretKey,
    pub auth_key: SecretKey,
}

pub fn recovery_keys(recovery: &SecretKey) -> RecoveryKeys {
    RecoveryKeys {
        wrap_key: derive_subkey(recovery, "verrou/v1/recovery-enc"),
        auth_key: derive_subkey(recovery, "verrou/v1/recovery-auth"),
    }
}

// ---------------------------------------------------------------------------
// Clés asymétriques et scellement
// ---------------------------------------------------------------------------

/// Génère une paire X25519 : (clé privée, clé publique).
pub fn generate_keypair() -> (SecretKey, [u8; 32]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (SecretKey(secret.to_bytes()), public.to_bytes())
}

pub fn public_key_of(private: &SecretKey) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*private.as_bytes())).to_bytes()
}

fn seal_key_material(shared: &[u8; 32], eph_pub: &[u8; 32], recipient: &[u8; 32], context: &str) -> SecretKey {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(eph_pub);
    salt[32..].copy_from_slice(recipient);
    hkdf_expand(Some(&salt), shared, &format!("verrou/v1/seal|{context}"))
}

/// Scelle `plaintext` pour le détenteur de `recipient_public`.
pub fn seal(recipient_public: &[u8; 32], plaintext: &[u8], context: &str) -> Result<String> {
    let eph = StaticSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&PublicKey::from(*recipient_public));
    if !shared.was_contributory() {
        return Err(Error::InvalidKey);
    }
    let key = seal_key_material(shared.as_bytes(), &eph_pub, recipient_public, context);
    let inner = encrypt(&key, plaintext, context.as_bytes());
    let inner_raw = b64d(inner.strip_prefix(CIPHER_PREFIX).ok_or(Error::Format)?)?;
    let mut out = Vec::with_capacity(32 + inner_raw.len());
    out.extend_from_slice(&eph_pub);
    out.extend_from_slice(&inner_raw);
    Ok(format!("{SEALED_PREFIX}{}", b64e(&out)))
}

pub fn open(private: &SecretKey, sealed: &str, context: &str) -> Result<Zeroizing<Vec<u8>>> {
    let body = sealed.strip_prefix(SEALED_PREFIX).ok_or(Error::Format)?;
    let raw = b64d(body)?;
    if raw.len() < 32 + NONCE_LEN + TAG_LEN {
        return Err(Error::Format);
    }
    let eph_pub: [u8; 32] = raw[..32].try_into().map_err(|_| Error::Format)?;
    let secret = StaticSecret::from(*private.as_bytes());
    let recipient = PublicKey::from(&secret).to_bytes();
    let shared = secret.diffie_hellman(&PublicKey::from(eph_pub));
    if !shared.was_contributory() {
        return Err(Error::Decrypt);
    }
    let key = seal_key_material(shared.as_bytes(), &eph_pub, &recipient, context);
    let inner = format!("{CIPHER_PREFIX}{}", b64e(&raw[32..]));
    decrypt(&key, &inner, context.as_bytes())
}

pub fn seal_key(recipient_public: &[u8; 32], key: &SecretKey, context: &str) -> Result<String> {
    seal(recipient_public, key.as_bytes(), context)
}

pub fn open_key(private: &SecretKey, sealed: &str, context: &str) -> Result<SecretKey> {
    let pt = open(private, sealed, context)?;
    SecretKey::from_slice(&pt)
}

/// Empreinte lisible d'une clé publique, à comparer de vive voix avant un partage.
pub fn fingerprint(public: &[u8; 32]) -> String {
    let h = Sha256::digest(public);
    let hex = hex_upper(&h[..12]);
    hex.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("-")
}

// ---------------------------------------------------------------------------
// Export protégé par mot de passe
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug)]
pub struct ProtectedExport {
    pub format: String,
    pub kdf: KdfParams,
    pub data: String,
}

pub fn protect_with_password(password: &str, plaintext: &[u8]) -> Result<String> {
    let kdf = KdfParams::recommended();
    let keys = derive_master_keys(password, &kdf)?;
    let data = encrypt(&keys.enc_key, plaintext, aad::export().as_bytes());
    serde_json::to_string(&ProtectedExport { format: "verrou-export-v1".into(), kdf, data })
        .map_err(|e| Error::InvalidInput(e.to_string()))
}

pub fn unprotect_with_password(password: &str, json: &str) -> Result<Zeroizing<Vec<u8>>> {
    let exp: ProtectedExport =
        serde_json::from_str(json).map_err(|_| Error::InvalidInput("fichier d'export illisible".into()))?;
    if exp.format != "verrou-export-v1" {
        return Err(Error::InvalidInput("format d'export inconnu".into()));
    }
    let keys = derive_master_keys(password, &exp.kdf)?;
    decrypt(&keys.enc_key, &exp.data, aad::export().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_kdf() -> KdfParams {
        KdfParams { alg: "argon2id".into(), m_kib: KdfParams::MIN_M_KIB, t: 2, p: 1, salt: b64e(&[7u8; 16]) }
    }

    #[test]
    fn encrypt_roundtrip_and_aad_binding() {
        let k = SecretKey::generate();
        let ct = encrypt(&k, b"secret", b"ctx-a");
        assert_eq!(&*decrypt(&k, &ct, b"ctx-a").unwrap(), b"secret");
        assert_eq!(decrypt(&k, &ct, b"ctx-b").unwrap_err(), Error::Decrypt);
        assert_eq!(decrypt(&SecretKey::generate(), &ct, b"ctx-a").unwrap_err(), Error::Decrypt);
        assert!(is_well_formed_cipher(&ct, 1000));
    }

    #[test]
    fn tampering_is_detected() {
        let k = SecretKey::generate();
        let ct = encrypt(&k, b"secret", b"");
        let mut raw = b64d(&ct[3..]).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        let bad = format!("v1.{}", b64e(&raw));
        assert_eq!(decrypt(&k, &bad, b"").unwrap_err(), Error::Decrypt);
    }

    #[test]
    fn nonces_are_unique() {
        let k = SecretKey::generate();
        assert_ne!(encrypt(&k, b"x", b""), encrypt(&k, b"x", b""));
    }

    #[test]
    fn master_keys_are_deterministic_and_separated() {
        let a = derive_master_keys("Cheval-Batterie-Agrafe", &fast_kdf()).unwrap();
        let b = derive_master_keys("Cheval-Batterie-Agrafe", &fast_kdf()).unwrap();
        assert_eq!(a.auth_key.as_bytes(), b.auth_key.as_bytes());
        assert_ne!(a.auth_key.as_bytes(), a.enc_key.as_bytes());
        // NFC : « é » précomposé ou décomposé donne la même clé.
        let c = derive_master_keys("caf\u{e9}", &fast_kdf()).unwrap();
        let d = derive_master_keys("cafe\u{301}", &fast_kdf()).unwrap();
        assert_eq!(c.enc_key.as_bytes(), d.enc_key.as_bytes());
    }

    #[test]
    fn weak_kdf_params_are_rejected() {
        let mut p = fast_kdf();
        p.m_kib = 1024;
        assert!(derive_master_keys("x", &p).is_err());
        let mut p = fast_kdf();
        p.alg = "pbkdf2".into();
        assert!(p.validate().is_err());
    }

    #[test]
    fn seal_roundtrip_and_context_binding() {
        let (sk, pk) = generate_keypair();
        assert_eq!(public_key_of(&sk), pk);
        let s = seal(&pk, b"cle-de-coffre", "ctx").unwrap();
        assert!(is_well_formed_sealed(&s));
        assert_eq!(&*open(&sk, &s, "ctx").unwrap(), b"cle-de-coffre");
        assert!(open(&sk, &s, "autre").is_err());
        let (other, _) = generate_keypair();
        assert!(open(&other, &s, "ctx").is_err());
    }

    #[test]
    fn recovery_key_roundtrip_and_checksum() {
        let (display, key) = generate_recovery_key();
        let parsed = parse_recovery_key(&display.to_lowercase()).unwrap();
        assert_eq!(parsed.as_bytes(), key.as_bytes());
        let mut chars: Vec<char> = display.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.into_iter().collect();
        assert!(parse_recovery_key(&typo).is_err());
    }

    #[test]
    fn uuid_format() {
        let u = new_uuid();
        assert!(is_uuid(&u), "{u}");
        assert!(!is_uuid("not-a-uuid"));
        assert!(!is_uuid(&u.to_uppercase()));
    }

    #[test]
    fn export_roundtrip() {
        let json = protect_with_password("motdepasse-export", b"{\"items\":[]}").unwrap();
        assert_eq!(&*unprotect_with_password("motdepasse-export", &json).unwrap(), b"{\"items\":[]}");
        assert!(unprotect_with_password("mauvais", &json).is_err());
    }
}
