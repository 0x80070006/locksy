//! Lecture des bases KDBX 3.1 et 4 (format de fichier de KeePass).
//!
//! Chaîne de lecture, d'après la spécification publique du format :
//! 1. en-tête en clair : signature, version, chiffrement, dérivation de clé ;
//! 2. clé composite = SHA-256(SHA-256(mot de passe) ‖ clé du fichier clé) ;
//! 3. dérivation : AES-KDF ou Argon2d/Argon2id, bornée (C1.7) ;
//! 4. KDBX 4 : empreinte SHA-256 et HMAC-SHA-256 de l'en-tête (le HMAC prouve
//!    la clé), puis HMAC de CHAQUE bloc vérifié avant tout déchiffrement ;
//!    KDBX 3.1 : déchiffrement, octets de début, blocs hachés SHA-256 ;
//! 5. déchiffrement AES-256-CBC ou ChaCha20 (Twofish : `unsupported_cipher`),
//!    décompression gzip bornée ;
//! 6. XML interne : valeurs protégées déchiffrées par le flux interne
//!    (Salsa20 ou ChaCha20), dans l'ordre du document ;
//! 7. correspondance vers le modèle Locksy (corbeille ignorée).

use super::{limits, warning, ImportError, ImportResult, MAX_INFLATED};
use crate::model::{CustomField, ItemData, ItemKind, PasswordHistoryEntry};
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecryptMut, BlockEncrypt, KeyInit, KeyIvInit, StreamCipher};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use quick_xml::events::Event;
use sha2::{Digest, Sha256};
use std::io::Read;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

type E = ImportError;
type HmacSha256 = Hmac<Sha256>;

const SIG1: u32 = 0x9AA2_D903;
const SIG2_KDBX: u32 = 0xB54B_FB67;
/// KeePass 1 (.kdb) et préversions de KDBX 2 : versions non prises en charge.
const SIG2_OLD: [u32; 2] = [0xB54B_FB65, 0xB54B_FB66];

/// Identifiant à 16 octets écrit sous sa forme textuelle habituelle.
const fn uuid(s: &str) -> [u8; 16] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("identifiant invalide"),
        }
    }
    let b = s.as_bytes();
    let mut out = [0u8; 16];
    let (mut i, mut n) = (0, 0);
    while i < b.len() {
        if b[i] != b'-' {
            out[n / 2] |= nibble(b[i]) << if n % 2 == 0 { 4 } else { 0 };
            n += 1;
        }
        i += 1;
    }
    out
}

pub(crate) const CIPHER_AES256: [u8; 16] = uuid("31c1f2e6-bf71-4350-be58-05216afc5aff");
pub(crate) const CIPHER_CHACHA20: [u8; 16] = uuid("d6038a2b-8b6f-4cb5-a524-339a31dbb59a");
/// Twofish : non pris en charge (`unsupported_cipher`), identifiant des tests.
#[cfg(test)]
pub(crate) const CIPHER_TWOFISH: [u8; 16] = uuid("ad68f29f-576f-4bb9-a36a-d47af965346c");
pub(crate) const KDF_AES_KDBX3: [u8; 16] = uuid("c9d9f39a-628a-4460-bf74-0d08c18a4fea");
pub(crate) const KDF_AES_KDBX4: [u8; 16] = uuid("7c02bb82-79a7-4ac0-927d-114a00648238");
pub(crate) const KDF_ARGON2D: [u8; 16] = uuid("ef636ddf-8c29-444b-91f7-a9a403e30a0c");
pub(crate) const KDF_ARGON2ID: [u8; 16] = uuid("9e298b19-56db-4773-b23d-fc3ec6f0a1e6");

/// Nonce fixe du flux interne Salsa20 (KDBX 3.1).
pub(crate) const SALSA20_NONCE: [u8; 8] = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];
/// Secondes entre le 1er janvier de l'an 1 et l'époque Unix (dates KDBX 4).
const EPOCH_OFFSET: i64 = 62_135_596_800;

/// Lit une base KDBX 3.1 ou 4. `password` vide : la base est ouverte par le
/// fichier clé seul, ou avec un mot de passe vide si elle en a un.
pub fn read_kdbx(data: &[u8], password: &str, keyfile: Option<&[u8]>) -> Result<ImportResult, ImportError> {
    let header = Header::parse(data)?;
    let keyfile_key = keyfile.map(keyfile_key).transpose()?;
    // Clés candidates : un mot de passe vide peut signifier « pas de mot de
    // passe » (fichier clé seul) ou « mot de passe vide ». Chaque essai coûte
    // une dérivation complète ; un échec passe au candidat suivant.
    let password_hash = sha256(&[password.as_bytes()]);
    let with_password: &[bool] = if password.is_empty() && keyfile_key.is_some() { &[false, true] } else { &[true] };
    for &with_password in with_password {
        let key = match (&keyfile_key, with_password) {
            (Some(k), true) => sha256(&[password_hash.as_slice(), k.as_slice()]),
            (Some(k), false) => sha256(&[k.as_slice()]),
            (None, _) => sha256(&[password_hash.as_slice()]),
        };
        let transformed = header.kdf.transform(&key)?;
        match header.open(&transformed) {
            Err(E::WrongPassword) => continue,
            Ok((xml, stream)) => return parse_xml(&xml, stream, &header),
            Err(e) => return Err(e),
        }
    }
    if password.is_empty() && keyfile.is_none() {
        Err(E::KeyfileRequired)
    } else {
        Err(E::WrongPassword)
    }
}

// ------------------------------------------------------------------ Lecture binaire

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], E> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.data.len()).ok_or(E::Corrupt)?;
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], E> {
        Ok(self.take(N)?.try_into().expect("longueur vérifiée"))
    }

    fn u8(&mut self) -> Result<u8, E> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, E> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, E> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    /// Longueur signée sur 4 octets ; négative = fichier corrompu.
    fn len32(&mut self) -> Result<usize, E> {
        usize::try_from(i32::from_le_bytes(self.array()?)).map_err(|_| E::Corrupt)
    }

    fn rest(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }
}

pub(crate) fn sha256(parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut h = Sha256::new();
    parts.iter().for_each(|p| h.update(p));
    Zeroizing::new(h.finalize().into())
}

pub(crate) fn sha512(parts: &[&[u8]]) -> Zeroizing<[u8; 64]> {
    let mut h = sha2::Sha512::new();
    parts.iter().for_each(|p| h.update(p));
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&h.finalize());
    out
}

fn le_u32(b: &[u8]) -> Result<u32, E> {
    Ok(u32::from_le_bytes(b.try_into().map_err(|_| E::Corrupt)?))
}

fn le_u64(b: &[u8]) -> Result<u64, E> {
    Ok(u64::from_le_bytes(b.try_into().map_err(|_| E::Corrupt)?))
}

// ------------------------------------------------------------------ En-tête

#[derive(Clone, Copy, PartialEq, Eq)]
enum Cipher {
    Aes256,
    ChaCha20,
}

enum Kdf {
    Aes { seed: [u8; 32], rounds: u64 },
    Argon2 { algorithm: argon2::Algorithm, version: argon2::Version, salt: Vec<u8>, memory: u64, iterations: u64, parallelism: u64 },
}

impl Kdf {
    /// Bornes vérifiées dès la lecture de l'en-tête, avant tout calcul.
    fn check(&self) -> Result<(), E> {
        let ok = match self {
            Kdf::Aes { rounds, .. } => *rounds <= limits::AES_KDF_MAX_ROUNDS,
            Kdf::Argon2 { memory, iterations, parallelism, .. } => {
                *memory <= limits::ARGON2_MAX_MEMORY_MIB * 1024 * 1024
                    && *memory >= 1024
                    && (1..=limits::ARGON2_MAX_ITERATIONS).contains(iterations)
                    && (1..=limits::ARGON2_MAX_PARALLELISM).contains(parallelism)
            }
        };
        if ok {
            Ok(())
        } else {
            Err(E::KdfOutOfBounds)
        }
    }

    fn transform(&self, composite: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, E> {
        match self {
            Kdf::Aes { seed, rounds } => Ok(aes_kdf(seed, *rounds, composite)),
            Kdf::Argon2 { algorithm, version, salt, memory, iterations, parallelism } => super::argon2_derive(
                *algorithm,
                *version,
                memory / 1024,
                *iterations,
                *parallelism,
                composite,
                salt,
            ),
        }
    }
}

/// AES-KDF : chaque moitié de la clé est chiffrée `rounds` fois en AES-256
/// (mode ECB, clé = graine), puis le tout est haché en SHA-256.
pub(crate) fn aes_kdf(seed: &[u8; 32], rounds: u64, composite: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let cipher = aes::Aes256::new(GenericArray::from_slice(seed));
    let mut blocks = [*GenericArray::from_slice(&composite[..16]), *GenericArray::from_slice(&composite[16..])];
    for _ in 0..rounds {
        cipher.encrypt_blocks(&mut blocks);
    }
    let out = sha256(&[&blocks[0], &blocks[1]]);
    blocks.iter_mut().for_each(|b| b.as_mut_slice().zeroize());
    out
}

struct Header<'a> {
    v4: bool,
    cipher: Cipher,
    compressed: bool,
    master_seed: &'a [u8],
    iv: &'a [u8],
    kdf: Kdf,
    /// KDBX 3.1 : clé du flux interne, octets de début, algorithme du flux.
    protected_stream_key: &'a [u8],
    stream_start: &'a [u8],
    inner_stream_id: u32,
    /// En-tête brut (signature comprise), couvert par l'empreinte et le HMAC.
    raw: &'a [u8],
    /// Suite du fichier après l'en-tête.
    body: &'a [u8],
}

impl<'a> Header<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, E> {
        let mut c = Cursor::new(data);
        let sig1 = c.u32().map_err(|_| E::UnsupportedFormat)?;
        let sig2 = c.u32().map_err(|_| E::UnsupportedFormat)?;
        if sig1 != SIG1 {
            return Err(E::UnsupportedFormat);
        }
        if SIG2_OLD.contains(&sig2) {
            return Err(E::UnsupportedVersion);
        }
        if sig2 != SIG2_KDBX {
            return Err(E::UnsupportedFormat);
        }
        let v4 = match c.u32()? >> 16 {
            3 => false,
            4 => true,
            _ => return Err(E::UnsupportedVersion),
        };
        let mut cipher = None;
        let mut compressed = false;
        let (mut master_seed, mut iv) = (None, None);
        let (mut transform_seed, mut transform_rounds) = (None, None);
        let (mut protected_stream_key, mut stream_start) = (&[][..], &[][..]);
        let mut inner_stream_id = 0;
        let mut kdf = None;
        loop {
            let id = c.u8()?;
            let size = if v4 { c.u32()? as usize } else { c.u16()? as usize };
            let value = c.take(size)?;
            match id {
                0 => break,
                2 => {
                    cipher = Some(match value {
                        v if v == CIPHER_AES256 => Cipher::Aes256,
                        v if v == CIPHER_CHACHA20 => Cipher::ChaCha20,
                        _ => return Err(E::UnsupportedCipher),
                    })
                }
                3 => {
                    compressed = match le_u32(value)? {
                        0 => false,
                        1 => true,
                        _ => return Err(E::UnsupportedFormat),
                    }
                }
                4 => master_seed = Some(value),
                5 => transform_seed = Some(value),
                6 => transform_rounds = Some(le_u64(value)?),
                7 => iv = Some(value),
                8 => protected_stream_key = value,
                9 => stream_start = value,
                10 => inner_stream_id = le_u32(value)?,
                11 if v4 => kdf = Some(parse_kdf_parameters(value)?),
                _ => {}
            }
        }
        let raw = &data[..c.pos];
        let cipher = cipher.ok_or(E::Corrupt)?;
        let master_seed = master_seed.filter(|s| s.len() == 32).ok_or(E::Corrupt)?;
        let iv_len = if cipher == Cipher::Aes256 { 16 } else { 12 };
        let iv = iv.filter(|v| v.len() == iv_len).ok_or(E::Corrupt)?;
        let kdf = if v4 {
            kdf.ok_or(E::Corrupt)?
        } else {
            let seed = transform_seed.and_then(|s| <[u8; 32]>::try_from(s).ok()).ok_or(E::Corrupt)?;
            if stream_start.len() != 32 || protected_stream_key.is_empty() {
                return Err(E::Corrupt);
            }
            Kdf::Aes { seed, rounds: transform_rounds.ok_or(E::Corrupt)? }
        };
        kdf.check()?;
        Ok(Header {
            v4,
            cipher,
            compressed,
            master_seed,
            iv,
            kdf,
            protected_stream_key,
            stream_start,
            inner_stream_id,
            raw,
            body: c.rest(),
        })
    }

    /// Ouvre la charge utile avec la clé transformée : XML interne et flux de
    /// protection des champs. `wrong_password` si la clé ne convient pas.
    fn open(&self, transformed: &[u8; 32]) -> Result<(Zeroizing<Vec<u8>>, InnerStream), E> {
        let key = sha256(&[self.master_seed, transformed]);
        if self.v4 {
            self.open_v4(transformed, &key)
        } else {
            self.open_v3(&key)
        }
    }

    fn open_v4(&self, transformed: &[u8; 32], key: &[u8; 32]) -> Result<(Zeroizing<Vec<u8>>, InnerStream), E> {
        let mut c = Cursor::new(self.body);
        let header_hash = c.take(32)?;
        let header_mac = c.take(32)?;
        if !bool::from(Sha256::digest(self.raw).as_slice().ct_eq(header_hash)) {
            return Err(E::Integrity);
        }
        let hmac_base = sha512(&[self.master_seed, transformed, &[1u8]]);
        // Le HMAC de l'en-tête dépend de la clé : c'est la preuve du mot de passe.
        let mut mac = <HmacSha256 as Mac>::new_from_slice(block_key(u64::MAX, &hmac_base).as_slice()).expect("clé HMAC");
        mac.update(self.raw);
        if mac.verify_slice(header_mac).is_err() {
            return Err(E::WrongPassword);
        }
        // Tous les blocs sont authentifiés AVANT le moindre déchiffrement.
        let mut ciphertext = Zeroizing::new(Vec::with_capacity(c.rest().len()));
        for index in 0u64.. {
            let block_mac = c.take(32)?;
            let size = c.len32()?;
            let data = c.take(size)?;
            let mut mac = <HmacSha256 as Mac>::new_from_slice(block_key(index, &hmac_base).as_slice()).expect("clé HMAC");
            mac.update(&index.to_le_bytes());
            mac.update(&(size as i32).to_le_bytes());
            mac.update(data);
            if mac.verify_slice(block_mac).is_err() {
                return Err(E::Integrity);
            }
            if size == 0 {
                break;
            }
            ciphertext.extend_from_slice(data);
        }
        let plain = decrypt_payload(self.cipher, key, self.iv, ciphertext).map_err(|()| E::Corrupt)?;
        let payload = if self.compressed { inflate(&plain, MAX_INFLATED)? } else { plain };
        // En-tête interne : flux de protection des champs et pièces jointes.
        let mut c = Cursor::new(&payload);
        let (mut stream_id, mut stream_key) = (0, &[][..]);
        loop {
            let id = c.u8()?;
            let size = c.len32()?;
            let value = c.take(size)?;
            match id {
                0 => break,
                1 => stream_id = le_u32(value)?,
                2 => stream_key = value,
                _ => {}
            }
        }
        let stream = InnerStream::new(stream_id, stream_key)?;
        let xml = Zeroizing::new(c.rest().to_vec());
        Ok((xml, stream))
    }

    fn open_v3(&self, key: &[u8; 32]) -> Result<(Zeroizing<Vec<u8>>, InnerStream), E> {
        // KDBX 3.1 n'authentifie pas avant déchiffrement : un remplissage
        // invalide ou des octets de début différents signalent une mauvaise clé.
        let plain = decrypt_payload(self.cipher, key, self.iv, Zeroizing::new(self.body.to_vec()))
            .map_err(|()| E::WrongPassword)?;
        if plain.len() < 32 || !bool::from(plain[..32].ct_eq(self.stream_start)) {
            return Err(E::WrongPassword);
        }
        let mut c = Cursor::new(&plain[32..]);
        let mut content = Zeroizing::new(Vec::with_capacity(plain.len()));
        for expected in 0u32.. {
            if c.u32()? != expected {
                return Err(E::Corrupt);
            }
            let hash = c.take(32)?;
            let size = c.len32()?;
            let data = c.take(size)?;
            if size == 0 {
                break;
            }
            if !bool::from(Sha256::digest(data).as_slice().ct_eq(hash)) {
                return Err(E::Integrity);
            }
            content.extend_from_slice(data);
        }
        let xml = if self.compressed { inflate(&content, MAX_INFLATED)? } else { content };
        let stream = InnerStream::new(self.inner_stream_id, self.protected_stream_key)?;
        Ok((xml, stream))
    }
}

/// Clé HMAC d'un bloc KDBX 4 (`u64::MAX` pour l'en-tête).
pub(crate) fn block_key(index: u64, hmac_base: &[u8; 64]) -> Zeroizing<[u8; 64]> {
    sha512(&[&index.to_le_bytes(), hmac_base])
}

fn decrypt_payload(cipher: Cipher, key: &[u8; 32], iv: &[u8], mut data: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, ()> {
    match cipher {
        Cipher::Aes256 => {
            let dec = cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv).map_err(|_| ())?;
            let len = dec
                .decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut data)
                .map_err(|_| ())?
                .len();
            data.truncate(len);
        }
        Cipher::ChaCha20 => {
            let mut c = chacha20::ChaCha20::new_from_slices(key, iv).map_err(|_| ())?;
            c.apply_keystream(&mut data);
        }
    }
    Ok(data)
}

/// Décompression gzip bornée à `limit` octets ([`MAX_INFLATED`] en usage).
fn inflate(data: &[u8], limit: u64) -> Result<Zeroizing<Vec<u8>>, E> {
    let mut out = Zeroizing::new(Vec::new());
    flate2::read::GzDecoder::new(data)
        .take(limit + 1)
        .read_to_end(&mut out)
        .map_err(|_| E::Corrupt)?;
    if out.len() as u64 > limit {
        return Err(E::TooLarge);
    }
    Ok(out)
}

/// Paramètres de dérivation KDBX 4 (dictionnaire de variantes).
fn parse_kdf_parameters(data: &[u8]) -> Result<Kdf, E> {
    let mut c = Cursor::new(data);
    if c.u16()? >> 8 != 1 {
        return Err(E::UnsupportedVersion);
    }
    let mut fields: Vec<(&[u8], &[u8])> = Vec::new();
    loop {
        let kind = c.u8()?;
        if kind == 0 {
            break;
        }
        let name_len = c.len32()?;
        let name = c.take(name_len)?;
        let value_len = c.len32()?;
        fields.push((name, c.take(value_len)?));
    }
    let get = |name: &str| fields.iter().find(|(n, _)| *n == name.as_bytes()).map(|(_, v)| *v);
    let uuid = get("$UUID").ok_or(E::Corrupt)?;
    let int = |name: &str| -> Result<u64, E> {
        let v = get(name).ok_or(E::Corrupt)?;
        match v.len() {
            4 => Ok(le_u32(v)? as u64),
            8 => le_u64(v),
            _ => Err(E::Corrupt),
        }
    };
    if uuid == KDF_AES_KDBX3 || uuid == KDF_AES_KDBX4 {
        let seed = get("S").and_then(|s| <[u8; 32]>::try_from(s).ok()).ok_or(E::Corrupt)?;
        return Ok(Kdf::Aes { seed, rounds: int("R")? });
    }
    let algorithm = match uuid {
        u if u == KDF_ARGON2D => argon2::Algorithm::Argon2d,
        u if u == KDF_ARGON2ID => argon2::Algorithm::Argon2id,
        _ => return Err(E::UnsupportedKdf),
    };
    // Clé secrète et données associées d'Argon2 : jamais écrites par les
    // logiciels courants, refusées plutôt qu'ignorées.
    if get("K").is_some_and(|v| !v.is_empty()) || get("A").is_some_and(|v| !v.is_empty()) {
        return Err(E::UnsupportedKdf);
    }
    let version = match int("V")? {
        0x10 => argon2::Version::V0x10,
        0x13 => argon2::Version::V0x13,
        _ => return Err(E::UnsupportedKdf),
    };
    Ok(Kdf::Argon2 {
        algorithm,
        version,
        salt: get("S").ok_or(E::Corrupt)?.to_vec(),
        memory: int("M")?,
        iterations: int("I")?,
        parallelism: int("P")?,
    })
}

// ------------------------------------------------------------------ Fichier clé

/// Clé à 32 octets tirée d'un fichier clé : XML (versions 1.0 et 2.0),
/// 32 octets bruts, 64 caractères hexadécimaux, sinon SHA-256 du fichier.
pub(crate) fn keyfile_key(data: &[u8]) -> Result<Zeroizing<[u8; 32]>, E> {
    if let Some(k) = xml_keyfile(data)? {
        return Ok(k);
    }
    if let Ok(raw) = <[u8; 32]>::try_from(data) {
        return Ok(Zeroizing::new(raw));
    }
    if data.len() == 64 {
        if let Some(k) = hex32(data) {
            return Ok(k);
        }
    }
    Ok(sha256(&[data]))
}

fn hex32(data: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    let digits: Vec<u8> = data.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
    if digits.len() != 64 {
        return None;
    }
    let mut out = Zeroizing::new([0u8; 32]);
    for (i, pair) in digits.chunks(2).enumerate() {
        let s = std::str::from_utf8(pair).ok()?;
        out[i] = u8::from_str_radix(s, 16).ok()?;
    }
    Some(out)
}

/// Fichier clé XML. `None` si le fichier n'en est pas un (il sera haché).
fn xml_keyfile(data: &[u8]) -> Result<Option<Zeroizing<[u8; 32]>>, E> {
    let text = match std::str::from_utf8(data.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(data)) {
        Ok(t) if t.contains("<KeyFile") => t,
        _ => return Ok(None),
    };
    let mut reader = quick_xml::Reader::from_str(text);
    let mut path: Vec<Vec<u8>> = Vec::new();
    let (mut version, mut key_data, mut hash) = (String::new(), Zeroizing::new(String::new()), None);
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                if e.local_name().as_ref() == b"Data" {
                    hash = e
                        .try_get_attribute("Hash")
                        .ok()
                        .flatten()
                        .and_then(|a| String::from_utf8(a.value.into_owned()).ok());
                }
                path.push(e.local_name().as_ref().to_vec());
            }
            Ok(Event::End(_)) => {
                path.pop();
            }
            Ok(Event::Text(t)) => {
                let Ok(t) = t.decode() else { return Ok(None) };
                match path.iter().map(Vec::as_slice).collect::<Vec<_>>().as_slice() {
                    [.., b"Meta", b"Version"] => version.push_str(t.trim()),
                    [.., b"Key", b"Data"] => key_data.push_str(&t),
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return Ok(None),
            _ => {}
        }
    }
    let key = if version.starts_with("1.") {
        let raw = Zeroizing::new(STANDARD.decode(key_data.trim()).map_err(|_| E::Corrupt)?);
        Zeroizing::new(<[u8; 32]>::try_from(raw.as_slice()).map_err(|_| E::Corrupt)?)
    } else if version.starts_with("2.") {
        let key = hex32(key_data.as_bytes()).ok_or(E::Corrupt)?;
        if let Some(expected) = hash {
            let digest = Sha256::digest(key.as_slice());
            let actual: String = digest[..4].iter().map(|b| format!("{b:02x}")).collect();
            if !actual.eq_ignore_ascii_case(expected.trim()) {
                return Err(E::Corrupt);
            }
        }
        key
    } else {
        return Err(E::UnsupportedVersion);
    };
    Ok(Some(key))
}

// ------------------------------------------------------------------ Flux interne

/// Flux de protection des valeurs « Protected » du XML.
pub(crate) enum InnerStream {
    Plain,
    Salsa20(Box<salsa20::Salsa20>),
    ChaCha20(Box<chacha20::ChaCha20>),
}

impl InnerStream {
    pub(crate) fn new(id: u32, key: &[u8]) -> Result<Self, E> {
        Ok(match id {
            0 => InnerStream::Plain,
            2 => {
                let k = sha256(&[key]);
                InnerStream::Salsa20(Box::new(salsa20::Salsa20::new(GenericArray::from_slice(k.as_slice()), &SALSA20_NONCE.into())))
            }
            3 => {
                let h = sha512(&[key]);
                InnerStream::ChaCha20(Box::new(chacha20::ChaCha20::new_from_slices(&h[..32], &h[32..44]).expect("tailles fixes")))
            }
            // 1 = ArcFour, abandonné par le format.
            _ => return Err(E::UnsupportedCipher),
        })
    }

    pub(crate) fn apply(&mut self, buf: &mut [u8]) {
        match self {
            InnerStream::Plain => {}
            InnerStream::Salsa20(s) => s.apply_keystream(buf),
            InnerStream::ChaCha20(s) => s.apply_keystream(buf),
        }
    }
}

// ------------------------------------------------------------------ XML interne

struct Group {
    uuid: String,
    name: String,
    parent: Option<usize>,
}

#[derive(Default)]
struct Entry {
    uuid: String,
    group: usize,
    /// (clé, valeur, protégée), dans l'ordre du fichier.
    strings: Vec<(String, String, bool)>,
    tags: String,
    expires: bool,
    expiry_time: String,
    modified: String,
    binaries: usize,
    /// Versions précédentes, de la plus ancienne à la plus récente.
    history: Vec<Entry>,
}

impl Entry {
    fn get(&self, key: &str) -> Option<&str> {
        self.strings.iter().find(|(k, _, _)| k == key).map(|(_, v, _)| v.as_str())
    }
}

impl Drop for Entry {
    fn drop(&mut self) {
        for (_, v, _) in self.strings.iter_mut() {
            v.zeroize();
        }
    }
}

fn parse_xml(xml: &[u8], mut stream: InnerStream, header: &Header) -> Result<ImportResult, E> {
    let text = std::str::from_utf8(xml.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(xml)).map_err(|_| E::Corrupt)?;
    let mut reader = quick_xml::Reader::from_str(text);
    reader.config_mut().expand_empty_elements = true;

    // Pile des éléments ouverts : (nom local, valeur protégée).
    let mut path: Vec<(Vec<u8>, bool)> = Vec::new();
    let mut text = Zeroizing::new(String::new());
    let mut groups: Vec<Group> = Vec::new();
    let mut group_stack: Vec<usize> = Vec::new();
    let mut entry_stack: Vec<Entry> = Vec::new();
    let mut entries: Vec<Entry> = Vec::new();
    let (mut string_key, mut string_value, mut string_protected) = (String::new(), Zeroizing::new(String::new()), false);
    let (mut recycle_bin, mut recycle_enabled, mut header_hash) = (String::new(), true, None::<String>);

    loop {
        match reader.read_event().map_err(|_| E::Corrupt)? {
            Event::Start(e) => {
                let name = e.local_name().as_ref().to_vec();
                let protected = e
                    .try_get_attribute("Protected")
                    .map_err(|_| E::Corrupt)?
                    .is_some_and(|a| a.value.eq_ignore_ascii_case(b"true"));
                let parent = path.last().map(|(n, _)| n.as_slice());
                match (parent, name.as_slice()) {
                    (Some(b"Root" | b"Group"), b"Group") => {
                        groups.push(Group { uuid: String::new(), name: String::new(), parent: group_stack.last().copied() });
                        group_stack.push(groups.len() - 1);
                    }
                    (Some(b"Group"), b"Entry") => {
                        let mut entry = Entry::default();
                        entry.group = *group_stack.last().ok_or(E::Corrupt)?;
                        entry_stack.push(entry);
                    }
                    (Some(b"History"), b"Entry") => entry_stack.push(Entry::default()),
                    _ => {}
                }
                path.push((name, protected));
                text.clear();
            }
            Event::Text(t) => text.push_str(&t.xml10_content().map_err(|_| E::Corrupt)?),
            Event::CData(t) => text.push_str(&t.decode().map_err(|_| E::Corrupt)?),
            Event::GeneralRef(r) => match r.resolve_char_ref().map_err(|_| E::Corrupt)? {
                Some(ch) => text.push(ch),
                None => {
                    let name = r.decode().map_err(|_| E::Corrupt)?;
                    text.push_str(quick_xml::escape::resolve_predefined_entity(&name).ok_or(E::Corrupt)?);
                }
            },
            Event::End(_) => {
                let (name, protected) = path.pop().ok_or(E::Corrupt)?;
                // Les valeurs protégées consomment le flux dans l'ordre du
                // document, y compris celles qui ne sont pas importées.
                let value: Zeroizing<String> = if protected {
                    let mut raw = Zeroizing::new(STANDARD.decode(text.trim()).map_err(|_| E::Corrupt)?);
                    stream.apply(&mut raw);
                    Zeroizing::new(String::from_utf8_lossy(&raw).into_owned())
                } else {
                    Zeroizing::new(std::mem::take(&mut *text))
                };
                text.clear();
                let names: Vec<&[u8]> = path.iter().map(|(n, _)| n.as_slice()).collect();
                match (names.as_slice(), name.as_slice()) {
                    ([b"KeePassFile", b"Meta"], b"RecycleBinUUID") => recycle_bin = value.trim().to_string(),
                    ([b"KeePassFile", b"Meta"], b"RecycleBinEnabled") => recycle_enabled = is_true(&value),
                    ([b"KeePassFile", b"Meta"], b"HeaderHash") => header_hash = Some(value.trim().to_string()),
                    ([.., b"Group"], b"UUID") => {
                        if let Some(&g) = group_stack.last() {
                            groups[g].uuid = value.trim().to_string();
                        }
                    }
                    ([.., b"Group"], b"Name") => {
                        if let Some(&g) = group_stack.last() {
                            groups[g].name = value.trim().to_string();
                        }
                    }
                    ([.., b"Root" | b"Group"], b"Group") => {
                        group_stack.pop();
                    }
                    ([.., b"Entry", b"String"], b"Key") => string_key = value.to_string(),
                    ([.., b"Entry", b"String"], b"Value") => {
                        string_value = value;
                        string_protected = protected;
                    }
                    ([.., b"Entry"], b"String") => {
                        if let Some(e) = entry_stack.last_mut() {
                            let v = std::mem::take(&mut *string_value);
                            e.strings.push((std::mem::take(&mut string_key), v, string_protected));
                        }
                        string_protected = false;
                    }
                    ([.., b"Entry"], b"UUID") => set(&mut entry_stack, |e| e.uuid = value.trim().to_string()),
                    ([.., b"Entry"], b"Tags") => set(&mut entry_stack, |e| e.tags = value.to_string()),
                    ([.., b"Entry"], b"Binary") => set(&mut entry_stack, |e| e.binaries += 1),
                    ([.., b"Entry", b"Times"], b"Expires") => set(&mut entry_stack, |e| e.expires = is_true(&value)),
                    ([.., b"Entry", b"Times"], b"ExpiryTime") => set(&mut entry_stack, |e| e.expiry_time = value.trim().to_string()),
                    ([.., b"Entry", b"Times"], b"LastModificationTime") => {
                        set(&mut entry_stack, |e| e.modified = value.trim().to_string())
                    }
                    ([.., b"History"], b"Entry") => {
                        let old = entry_stack.pop().ok_or(E::Corrupt)?;
                        entry_stack.last_mut().ok_or(E::Corrupt)?.history.push(old);
                    }
                    ([.., b"Group"], b"Entry") => entries.push(entry_stack.pop().ok_or(E::Corrupt)?),
                    _ => {}
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if !path.is_empty() || groups.is_empty() {
        return Err(E::Corrupt);
    }
    // KDBX 3.1 : l'empreinte de l'en-tête recopiée dans le XML (chiffré)
    // garantit que l'en-tête en clair n'a pas été modifié.
    if let Some(hash) = header_hash.filter(|h| !h.is_empty() && !header.v4) {
        let expected = STANDARD.decode(hash).map_err(|_| E::Corrupt)?;
        if !bool::from(Sha256::digest(header.raw).as_slice().ct_eq(&expected)) {
            return Err(E::Integrity);
        }
    }
    Ok(build_result(&groups, entries, recycle_enabled.then_some(recycle_bin)))
}

fn set(stack: &mut [Entry], f: impl FnOnce(&mut Entry)) {
    if let Some(e) = stack.last_mut() {
        f(e);
    }
}

fn is_true(v: &str) -> bool {
    v.trim().eq_ignore_ascii_case("true")
}

/// Identifiant nul : aucune corbeille.
const NULL_UUID: &str = "AAAAAAAAAAAAAAAAAAAAAA==";

fn build_result(groups: &[Group], entries: Vec<Entry>, recycle_bin: Option<String>) -> ImportResult {
    let recycle_bin = recycle_bin.filter(|u| !u.is_empty() && u != NULL_UUID);
    let in_trash = |mut g: usize| loop {
        if recycle_bin.as_deref() == Some(groups[g].uuid.as_str()) {
            return true;
        }
        match groups[g].parent {
            Some(p) => g = p,
            None => return false,
        }
    };
    // Chemin « A/B » sans le groupe racine (nom de la base).
    let path_of = |mut g: usize| {
        let mut names = Vec::new();
        while let Some(p) = groups[g].parent {
            names.push(groups[g].name.as_str());
            g = p;
        }
        names.reverse();
        names.join("/")
    };
    let mut result = ImportResult::default();
    for g in 0..groups.len() {
        if !in_trash(g) {
            result.add_folder(&path_of(g));
        }
    }
    let mut trashed = 0usize;
    for entry in entries {
        if in_trash(entry.group) {
            trashed += 1;
            continue;
        }
        let index = result.items.len();
        let attachments = entry.binaries > 0;
        let source_id = uuid_text(&entry.uuid);
        result.push_item(entry_to_item(&entry), path_of(entry.group), source_id);
        if attachments {
            result.warn(warning::ATTACHMENTS_SKIPPED, Some(index));
        }
    }
    if trashed > 0 {
        result.warn(warning::TRASH_SKIPPED, None);
    }
    result
}

/// Identifiant base64 de 16 octets mis sous forme textuelle habituelle.
fn uuid_text(b64: &str) -> String {
    match STANDARD.decode(b64.trim()) {
        Ok(b) if b.len() == 16 => {
            let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
            format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
        }
        _ => b64.trim().to_string(),
    }
}

/// Date KDBX : ISO 8601 (KDBX 3.1) ou secondes depuis l'an 1 en base64 (KDBX 4).
fn parse_time(s: &str) -> Option<i64> {
    if s.contains('-') {
        return super::parse_iso8601(s);
    }
    let raw: [u8; 8] = STANDARD.decode(s.trim()).ok()?.try_into().ok()?;
    i64::from_le_bytes(raw).checked_sub(EPOCH_OFFSET)
}

/// Champs standards repris dans les champs du modèle.
const STANDARD_KEYS: [&str; 5] = ["Title", "UserName", "Password", "URL", "Notes"];

fn entry_to_item(e: &Entry) -> ItemData {
    let get = |k: &str| e.get(k).unwrap_or_default().to_string();
    let mut item = ItemData {
        name: get("Title"),
        username: get("UserName"),
        password: get("Password"),
        notes: get("Notes"),
        ..Default::default()
    };
    let url = get("URL");
    if !url.trim().is_empty() {
        item.urls.push(url.trim().to_string());
    }
    item.tags = e.tags.split([';', ',']).map(str::trim).filter(|t| !t.is_empty()).map(String::from).collect();
    let (totp, consumed) = totp_of(e);
    item.totp = totp;
    for (key, value, protected) in &e.strings {
        if STANDARD_KEYS.contains(&key.as_str()) || consumed.contains(&key.as_str()) {
            continue;
        }
        if key.starts_with("KP2A_URL") {
            if !value.trim().is_empty() {
                item.urls.push(value.trim().to_string());
            }
            continue;
        }
        item.fields.push(CustomField { label: key.clone(), value: value.clone(), hidden: *protected });
    }
    if e.expires {
        item.expires_at = parse_time(&e.expiry_time).unwrap_or(0).max(0);
    }
    // Historique : chaque changement de mot de passe entre deux versions
    // successives (la dernière étant l'élément courant) donne une entrée.
    let versions: Vec<(&str, i64)> = e
        .history
        .iter()
        .map(|h| (h.get("Password").unwrap_or_default(), parse_time(&h.modified).unwrap_or(0)))
        .chain(std::iter::once((item.password.as_str(), parse_time(&e.modified).unwrap_or(0))))
        .collect();
    let mut history = Vec::new();
    for pair in versions.windows(2) {
        let ((old, _), (new, changed_at)) = (pair[0], pair[1]);
        if old != new {
            if !old.is_empty() {
                history.push(PasswordHistoryEntry { password: old.to_string(), changed_at });
            }
            item.password_changed_at = changed_at;
        }
    }
    history.reverse();
    item.password_history = history;
    if item.username.is_empty() && item.password.is_empty() && item.urls.is_empty() && item.totp.is_empty() && !item.notes.is_empty() {
        item.kind = ItemKind::Note;
    }
    item
}

/// Secret TOTP de l'entrée et champs qu'il remplace. Trois conventions :
/// champ « otp » (URI otpauth), champs « TimeOtp-* », champs « TOTP Seed » et
/// « TOTP Settings ».
fn totp_of(e: &Entry) -> (String, Vec<&'static str>) {
    if let Some(otp) = e.get("otp").filter(|v| !v.trim().is_empty()) {
        return (otp.trim().to_string(), vec!["otp"]);
    }
    if let Some(secret) = e.get("TimeOtp-Secret-Base32").filter(|v| !v.trim().is_empty()) {
        let algorithm = match e.get("TimeOtp-Algorithm").map(str::trim) {
            Some("HMAC-SHA-256") => Some("SHA256"),
            Some("HMAC-SHA-512") => Some("SHA512"),
            _ => None,
        };
        let params = [("digits", e.get("TimeOtp-Length")), ("period", e.get("TimeOtp-Period"))];
        let consumed = vec!["TimeOtp-Secret-Base32", "TimeOtp-Length", "TimeOtp-Period", "TimeOtp-Algorithm"];
        return (otpauth(secret, params, algorithm), consumed);
    }
    if let Some(seed) = e.get("TOTP Seed").filter(|v| !v.trim().is_empty()) {
        let settings = e.get("TOTP Settings").unwrap_or_default();
        let (period, digits) = settings.split_once(';').unwrap_or((settings, ""));
        // « S » = codes de type Steam : non pris en charge, réglages conservés.
        if digits.trim().eq_ignore_ascii_case("s") {
            return (seed.trim().to_string(), vec!["TOTP Seed"]);
        }
        return (otpauth(seed, [("digits", Some(digits)), ("period", Some(period))], None), vec!["TOTP Seed", "TOTP Settings"]);
    }
    (String::new(), Vec::new())
}

fn otpauth(secret: &str, params: [(&str, Option<&str>); 2], algorithm: Option<&str>) -> String {
    let secret: String = secret.chars().filter(|c| !c.is_whitespace()).collect();
    let mut query: Vec<String> = params
        .iter()
        .filter_map(|(k, v)| v.map(str::trim).filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit())).map(|v| format!("{k}={v}")))
        .collect();
    if let Some(a) = algorithm {
        query.push(format!("algorithm={a}"));
    }
    if query.is_empty() {
        secret
    } else {
        format!("otpauth://totp/?secret={secret}&{}", query.join("&"))
    }
}

#[cfg(test)]
mod tests {
    use super::super::testgen::{self, KdbxSpec, Kdf as GenKdf, Stream};
    use super::*;

    fn read(spec: &KdbxSpec) -> Result<ImportResult, E> {
        let file = testgen::write_kdbx(spec);
        read_kdbx(&file, &spec.password, spec.keyfile.as_deref())
    }

    /// Contenu attendu de la base de test (voir testgen::sample_entries).
    fn check_sample(r: &ImportResult) {
        assert_eq!(r.items.len(), 4, "{r:?}");
        let mail = &r.items[0];
        assert_eq!(mail.data.name, "Messagerie");
        assert_eq!(mail.data.username, "alice@exemple.fr");
        assert_eq!(mail.data.password, testgen::TRICKY_PASSWORD);
        assert_eq!(mail.data.urls, vec!["https://mail.exemple.fr".to_string(), "https://webmail.exemple.fr".to_string()]);
        assert_eq!(mail.data.notes, "Ligne 1\nLigne 2 & <3>");
        assert_eq!(mail.data.totp, "otpauth://totp/Exemple:alice?secret=JBSWY3DPEHPK3PXP");
        assert_eq!(mail.data.tags, vec!["pro".to_string(), "mail".to_string()]);
        assert_eq!(
            mail.data.fields,
            vec![
                CustomField { label: "Code PIN".into(), value: "1234".into(), hidden: true },
                CustomField { label: "Service".into(), value: "Courrier".into(), hidden: false },
            ]
        );
        assert_eq!(mail.data.password_history.len(), 1);
        assert_eq!(mail.data.password_history[0].password, "ancien-mot-de-passe");
        assert_eq!(mail.data.password_history[0].changed_at, 1_700_000_000);
        assert_eq!(mail.data.password_changed_at, 1_700_000_000);
        assert_eq!(mail.data.expires_at, 1_900_000_000);
        assert_eq!(mail.folder, "");
        assert_eq!(mail.source_id, "00112233-4455-6677-8899-aabbccddeeff");

        let note = &r.items[1];
        assert_eq!(note.data.kind, ItemKind::Note);
        assert_eq!(note.data.notes, "Code de la porte : 4321");
        assert_eq!(note.data.password, "");
        let attached = &r.items[2];
        assert_eq!(attached.data.name, "Avec pièce jointe");
        assert_eq!(attached.data.password, "pj");
        // Après la corbeille : le flux interne est resté synchronisé.
        let bank = &r.items[3];
        assert_eq!(bank.data.name, "Banque en ligne");
        assert_eq!(bank.data.password, "b@nque");
        assert_eq!(bank.folder, "Banque/Comptes");
        assert_eq!(bank.data.totp, "otpauth://totp/?secret=GEZDGNBVGY3TQOJQ&digits=8&algorithm=SHA256");
        assert!(bank.data.fields.is_empty());
        let totp = crate::totp::parse(&bank.data.totp).unwrap();
        assert_eq!(totp.digits, 8);
        crate::totp::parse(&mail.data.totp).unwrap();
        assert_eq!(r.folders, vec!["Banque".to_string(), "Banque/Comptes".to_string()]);
        assert_eq!(
            r.warnings,
            vec![
                super::super::ImportWarning { code: warning::ATTACHMENTS_SKIPPED, index: Some(2) },
                super::super::ImportWarning { code: warning::TRASH_SKIPPED, index: None },
            ]
        );
    }

    #[test]
    fn kdbx4_aes_argon2id() {
        let spec = KdbxSpec::v4(CIPHER_AES256, GenKdf::Argon2id);
        check_sample(&read(&spec).unwrap());
    }

    #[test]
    fn kdbx4_chacha20_argon2d_sans_compression() {
        let spec = KdbxSpec { compress: false, ..KdbxSpec::v4(CIPHER_CHACHA20, GenKdf::Argon2d) };
        check_sample(&read(&spec).unwrap());
    }

    #[test]
    fn kdbx4_aes_kdf() {
        check_sample(&read(&KdbxSpec::v4(CIPHER_AES256, GenKdf::Aes(1000))).unwrap());
    }

    #[test]
    fn kdbx31_aes_kdf_salsa20() {
        let spec = KdbxSpec::v3(Stream::Salsa20);
        check_sample(&read(&spec).unwrap());
    }

    #[test]
    fn kdbx31_flux_chacha20_et_chiffrement_chacha20() {
        let spec = KdbxSpec { cipher: CIPHER_CHACHA20, ..KdbxSpec::v3(Stream::ChaCha20) };
        check_sample(&read(&spec).unwrap());
    }

    #[test]
    fn mauvais_mot_de_passe() {
        for spec in [KdbxSpec::v4(CIPHER_AES256, GenKdf::Argon2id), KdbxSpec::v3(Stream::Salsa20)] {
            let file = testgen::write_kdbx(&spec);
            assert_eq!(read_kdbx(&file, "faux", None).unwrap_err(), E::WrongPassword);
        }
    }

    #[test]
    fn bloc_altere_refuse_avant_dechiffrement() {
        let spec = KdbxSpec::v4(CIPHER_AES256, GenKdf::Aes(10));
        let mut file = testgen::write_kdbx(&spec);
        // Dernier octet de données du premier bloc (avant le bloc final vide
        // de 36 octets) : déchiffré, il casserait le remplissage (corrupt) ;
        // le HMAC le refuse avant (integrity).
        let n = file.len();
        file[n - 37] ^= 0x01;
        assert_eq!(read_kdbx(&file, &spec.password, None).unwrap_err(), E::Integrity);
    }

    #[test]
    fn en_tete_altere() {
        let spec = KdbxSpec::v4(CIPHER_AES256, GenKdf::Aes(10));
        let mut file = testgen::write_kdbx(&spec);
        // Un octet de la graine maîtresse (champ 4, après les 12 premiers octets).
        let pos = testgen::field_offset(&file, 4).unwrap();
        file[pos] ^= 0x01;
        assert_eq!(read_kdbx(&file, &spec.password, None).unwrap_err(), E::Integrity);
        // KDBX 3.1 : l'empreinte d'en-tête recopiée dans le XML.
        let spec = KdbxSpec::v3(Stream::Salsa20);
        let mut file = testgen::write_kdbx(&spec);
        let pos = testgen::field_offset(&file, 1).unwrap();
        file[pos] ^= 0x01;
        assert_eq!(read_kdbx(&file, &spec.password, None).unwrap_err(), E::Integrity);
    }

    #[test]
    fn bornes_de_derivation() {
        for kdf in [
            GenKdf::Argon2Raw { memory: 2048 * 1024 * 1024, iterations: 2, parallelism: 1 },
            GenKdf::Argon2Raw { memory: 1024 * 1024, iterations: 101, parallelism: 1 },
            GenKdf::Argon2Raw { memory: 1024 * 1024, iterations: 2, parallelism: 17 },
            GenKdf::Aes(limits::AES_KDF_MAX_ROUNDS + 1),
        ] {
            let spec = KdbxSpec::v4(CIPHER_AES256, kdf);
            let file = testgen::write_kdbx(&spec);
            assert_eq!(read_kdbx(&file, &spec.password, None).unwrap_err(), E::KdfOutOfBounds);
        }
    }

    #[test]
    fn formats_et_algorithmes_inconnus() {
        assert_eq!(read_kdbx(b"PK\x03\x04 pas une base", "x", None).unwrap_err(), E::UnsupportedFormat);
        assert_eq!(read_kdbx(b"", "x", None).unwrap_err(), E::UnsupportedFormat);
        let mut kdb1 = 0x9AA2_D903u32.to_le_bytes().to_vec();
        kdb1.extend_from_slice(&0xB54B_FB65u32.to_le_bytes());
        kdb1.extend_from_slice(&[0; 32]);
        assert_eq!(read_kdbx(&kdb1, "x", None).unwrap_err(), E::UnsupportedVersion);
        let twofish = testgen::write_kdbx(&KdbxSpec::v4(CIPHER_TWOFISH, GenKdf::Aes(10)));
        assert_eq!(read_kdbx(&twofish, "x", None).unwrap_err(), E::UnsupportedCipher);
        let mut kdf = testgen::write_kdbx(&KdbxSpec::v4(CIPHER_AES256, GenKdf::Aes(10)));
        // Remplace l'identifiant de l'AES-KDF par un identifiant inconnu.
        let pos = kdf.windows(16).position(|w| w == KDF_AES_KDBX4).unwrap();
        kdf[pos] ^= 0xFF;
        assert_eq!(read_kdbx(&kdf, "x", None).unwrap_err(), E::UnsupportedKdf);
        let mut truncated = testgen::write_kdbx(&KdbxSpec::v4(CIPHER_AES256, GenKdf::Aes(10)));
        truncated.truncate(truncated.len() - 50);
        assert_eq!(read_kdbx(&truncated, testgen::PASSWORD, None).unwrap_err(), E::Corrupt);
    }

    #[test]
    fn fichiers_cles() {
        let xml2 = testgen::keyfile_xml_v2(&[7u8; 32]);
        let raw = [9u8; 32];
        let hex = b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_vec();
        let other = b"n'importe quel fichier".to_vec();
        for keyfile in [xml2, raw.to_vec(), hex, other] {
            // Mot de passe + fichier clé.
            let spec = KdbxSpec { keyfile: Some(keyfile.clone()), ..KdbxSpec::v4(CIPHER_AES256, GenKdf::Aes(10)) };
            check_sample(&read(&spec).unwrap());
            let file = testgen::write_kdbx(&spec);
            assert_eq!(read_kdbx(&file, &spec.password, None).unwrap_err(), E::WrongPassword);
            assert_eq!(read_kdbx(&file, &spec.password, Some(b"autre")).unwrap_err(), E::WrongPassword);
            // Fichier clé seul.
            let spec = KdbxSpec { password: String::new(), ..spec };
            let file = testgen::write_kdbx(&spec);
            check_sample(&read_kdbx(&file, "", Some(&keyfile)).unwrap());
            assert_eq!(read_kdbx(&file, "", None).unwrap_err(), E::KeyfileRequired);
        }
        // Fichier clé XML dont l'empreinte ne correspond pas.
        let bad = String::from_utf8(testgen::keyfile_xml_v2(&[7u8; 32])).unwrap().replace("Hash=\"", "Hash=\"0");
        assert_eq!(read_kdbx(&testgen::write_kdbx(&KdbxSpec::v4(CIPHER_AES256, GenKdf::Aes(10))), "x", Some(bad.as_bytes())).unwrap_err(), E::Corrupt);
    }

    #[test]
    fn mot_de_passe_vide_sans_fichier_cle() {
        let spec = KdbxSpec { password: String::new(), ..KdbxSpec::v4(CIPHER_AES256, GenKdf::Aes(10)) };
        check_sample(&read(&spec).unwrap());
    }

    #[test]
    fn decompression_bornee() {
        let zeros = testgen::gzip(&[0u8; 4096]);
        assert_eq!(inflate(&zeros, 4096).unwrap().len(), 4096);
        assert_eq!(inflate(&zeros, 4095).unwrap_err(), E::TooLarge);
        assert_eq!(inflate(b"pas du gzip", 4096).unwrap_err(), E::Corrupt);
    }

    #[test]
    fn dates_kdbx() {
        assert_eq!(parse_time("2023-11-14T22:13:20Z"), Some(1_700_000_000));
        let kdbx4 = STANDARD.encode((1_700_000_000i64 + EPOCH_OFFSET).to_le_bytes());
        assert_eq!(parse_time(&kdbx4), Some(1_700_000_000));
        assert_eq!(parse_time("???"), None);
    }

    #[test]
    fn identifiants_connus() {
        assert_eq!(CIPHER_AES256[..4], [0x31, 0xC1, 0xF2, 0xE6]);
        assert_eq!(KDF_ARGON2ID[15], 0xE6);
        assert_eq!(uuid_text("ABEiM0RVZneImaq7zN3u/w=="), "00112233-4455-6677-8899-aabbccddeeff");
    }
}
