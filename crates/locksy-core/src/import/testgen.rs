//! Écrivains de fichiers de test (tests seulement) : bases KDBX 3.1 et 4 et
//! exports JSON chiffrés, générés de façon reproductible (graines et vecteurs
//! d'initialisation fixes) d'après les spécifications publiques des formats.
//! Aucun fichier tiers n'est copié.

use super::kdbx::{self, InnerStream};
use aes::cipher::{BlockEncryptMut, KeyIvInit, StreamCipher};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::Write;

type HmacSha256 = Hmac<Sha256>;

pub const PASSWORD: &str = "Mot de passe de test";
/// Mot de passe piège : séparateurs CSV, retours à la ligne, caractères XML.
pub const TRICKY_PASSWORD: &str = "a;b,c\nd\r\n\"e\" 'f' <g> & é ";

#[derive(Clone, Copy)]
pub enum Kdf {
    Aes(u64),
    Argon2id,
    Argon2d,
    /// Paramètres arbitraires (mémoire en octets), pour les tests de bornes.
    Argon2Raw { memory: u64, iterations: u64, parallelism: u64 },
}

#[derive(Clone, Copy)]
pub enum Stream {
    Salsa20,
    ChaCha20,
}

#[derive(Clone)]
pub struct KdbxSpec {
    pub v4: bool,
    pub cipher: [u8; 16],
    pub kdf: Kdf,
    pub stream: Stream,
    pub compress: bool,
    pub password: String,
    pub keyfile: Option<Vec<u8>>,
}

impl KdbxSpec {
    pub fn v4(cipher: [u8; 16], kdf: Kdf) -> Self {
        KdbxSpec { v4: true, cipher, kdf, stream: Stream::ChaCha20, compress: true, password: PASSWORD.into(), keyfile: None }
    }

    pub fn v3(stream: Stream) -> Self {
        KdbxSpec {
            v4: false,
            cipher: kdbx::CIPHER_AES256,
            kdf: Kdf::Aes(1000),
            stream,
            compress: true,
            password: PASSWORD.into(),
            keyfile: None,
        }
    }
}

const MASTER_SEED: [u8; 32] = [0x11; 32];
const KDF_SEED: [u8; 32] = [0x33; 32];
const STREAM_START: [u8; 32] = [0x77; 32];
/// Taille des blocs de la charge utile : petite pour en avoir plusieurs.
const BLOCK: usize = 256;

pub fn gzip(data: &[u8]) -> Vec<u8> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(data).unwrap();
    gz.finish().unwrap()
}

fn uuid64(n: u8) -> String {
    STANDARD.encode([n; 16])
}

/// Date au format ISO 8601 (KDBX 3.1).
fn iso(unix: i64) -> String {
    let (days, secs) = (unix.div_euclid(86_400), unix.rem_euclid(86_400));
    // Algorithme « civil_from_days » (calendrier grégorien proleptique).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", secs / 3600, secs % 3600 / 60, secs % 60)
}

/// Rédacteur XML : les valeurs protégées passent par le flux interne dans
/// l'ordre du document, comme le format l'exige.
struct Xml<'a> {
    out: String,
    stream: &'a mut InnerStream,
    v4: bool,
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

impl Xml<'_> {
    fn open(&mut self, tag: &str) {
        self.out.push_str(&format!("<{tag}>"));
    }

    fn close(&mut self, tag: &str) {
        self.out.push_str(&format!("</{tag}>\n"));
    }

    fn leaf(&mut self, tag: &str, text: &str) {
        self.out.push_str(&format!("<{tag}>{}</{tag}>\n", escape(text)));
    }

    fn protected_bytes(&mut self, tag: &str, attrs: &str, value: &[u8]) {
        if value.is_empty() {
            self.out.push_str(&format!("<{tag}{attrs} Protected=\"True\" />\n"));
            return;
        }
        let mut buf = value.to_vec();
        self.stream.apply(&mut buf);
        self.out.push_str(&format!("<{tag}{attrs} Protected=\"True\">{}</{tag}>\n", STANDARD.encode(buf)));
    }

    fn time(&mut self, tag: &str, unix: i64) {
        let text = if self.v4 { STANDARD.encode((unix + 62_135_596_800).to_le_bytes()) } else { iso(unix) };
        self.leaf(tag, &text);
    }

    fn string(&mut self, key: &str, value: &str, protected: bool) {
        self.open("String");
        self.leaf("Key", key);
        if protected {
            self.protected_bytes("Value", "", value.as_bytes());
        } else {
            self.leaf("Value", value);
        }
        self.close("String");
    }

    fn entry(&mut self, uuid: &str, modified: i64, expiry: Option<i64>, strings: &[(&str, &str, bool)], extra: impl FnOnce(&mut Self)) {
        self.open("Entry");
        self.leaf("UUID", uuid);
        self.open("Times");
        self.time("LastModificationTime", modified);
        if let Some(at) = expiry {
            self.time("ExpiryTime", at);
            self.leaf("Expires", "True");
        }
        self.close("Times");
        for (k, v, p) in strings {
            self.string(k, v, *p);
        }
        extra(self);
        self.close("Entry");
    }
}

/// XML de la base d'exemple (contenu vérifié par kdbx::tests::check_sample).
fn sample_xml(stream: &mut InnerStream, v4: bool, header_hash: Option<String>) -> String {
    let mut x = Xml { out: String::from("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n"), stream, v4 };
    x.open("KeePassFile");
    x.open("Meta");
    x.leaf("Generator", "Locksy (tests)");
    if let Some(h) = header_hash {
        x.leaf("HeaderHash", &h);
    }
    x.leaf("RecycleBinEnabled", "True");
    x.leaf("RecycleBinUUID", &uuid64(2));
    if !v4 {
        // KDBX 3.1 : pièce jointe protégée dans les métadonnées, avant tout
        // élément : elle consomme le flux interne.
        x.open("Binaries");
        x.protected_bytes("Binary", " ID=\"0\" Compressed=\"False\"", b"\x89PNG contenu");
        x.close("Binaries");
    }
    x.close("Meta");
    x.open("Root");
    x.open("Group");
    x.leaf("UUID", &uuid64(1));
    x.leaf("Name", "Base de test");
    x.entry(
        "ABEiM0RVZneImaq7zN3u/w==",
        1_700_000_000,
        Some(1_900_000_000),
        &[
            ("Title", "Messagerie", false),
            ("UserName", "alice@exemple.fr", false),
            ("Password", TRICKY_PASSWORD, true),
            ("URL", "https://mail.exemple.fr", false),
            ("KP2A_URL", "https://webmail.exemple.fr", false),
            ("Notes", "Ligne 1\nLigne 2 & <3>", false),
            ("otp", "otpauth://totp/Exemple:alice?secret=JBSWY3DPEHPK3PXP", true),
            ("Code PIN", "1234", true),
            ("Service", "Courrier", false),
        ],
        |x| {
            x.leaf("Tags", "pro;mail");
            x.open("History");
            for modified in [1_600_000_000, 1_650_000_000] {
                x.entry("ABEiM0RVZneImaq7zN3u/w==", modified, None, &[("Title", "Messagerie", false), ("Password", "ancien-mot-de-passe", true)], |_| {});
            }
            x.close("History");
        },
    );
    x.entry(&uuid64(10), 1_700_000_000, None, &[("Title", "Porte", false), ("Password", "", true), ("Notes", "Code de la porte : 4321", false)], |_| {});
    x.entry(&uuid64(11), 1_700_000_000, None, &[("Title", "Avec pièce jointe", false), ("Password", "pj", true)], |x| {
        x.out.push_str("<Binary><Key>photo.png</Key><Value Ref=\"0\" /></Binary>\n");
    });
    // Corbeille AVANT le groupe Banque : ses valeurs protégées, ignorées à
    // l'import, doivent tout de même consommer le flux.
    x.open("Group");
    x.leaf("UUID", &uuid64(2));
    x.leaf("Name", "Corbeille");
    x.entry(&uuid64(12), 1_700_000_000, None, &[("Title", "Supprimé", false), ("Password", "jeté", true)], |_| {});
    x.close("Group");
    x.open("Group");
    x.leaf("UUID", &uuid64(3));
    x.leaf("Name", "Banque");
    x.open("Group");
    x.leaf("UUID", &uuid64(4));
    x.leaf("Name", "Comptes");
    x.entry(
        &uuid64(13),
        1_700_000_000,
        None,
        &[
            ("Title", "Banque en ligne", false),
            ("Password", "b@nque", true),
            ("TimeOtp-Secret-Base32", "GEZDGNBVGY3TQOJQ", true),
            ("TimeOtp-Length", "8", false),
            ("TimeOtp-Algorithm", "HMAC-SHA-256", false),
        ],
        |_| {},
    );
    x.close("Group");
    x.close("Group");
    x.close("Group");
    x.close("Root");
    x.close("KeePassFile");
    x.out
}

fn variant(out: &mut Vec<u8>, kind: u8, name: &str, value: &[u8]) {
    out.push(kind);
    out.extend_from_slice(&(name.len() as i32).to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&(value.len() as i32).to_le_bytes());
    out.extend_from_slice(value);
}

fn kdf_parameters(kdf: Kdf) -> Vec<u8> {
    let mut d = 0x0100u16.to_le_bytes().to_vec();
    match kdf {
        Kdf::Aes(rounds) => {
            variant(&mut d, 0x42, "$UUID", &kdbx::KDF_AES_KDBX4);
            variant(&mut d, 0x05, "R", &rounds.to_le_bytes());
            variant(&mut d, 0x42, "S", &KDF_SEED);
        }
        _ => {
            let (uuid, memory, iterations, parallelism) = argon2_params(kdf);
            variant(&mut d, 0x42, "$UUID", &uuid);
            variant(&mut d, 0x42, "S", &KDF_SEED);
            variant(&mut d, 0x04, "P", &(parallelism as u32).to_le_bytes());
            variant(&mut d, 0x05, "M", &memory.to_le_bytes());
            variant(&mut d, 0x05, "I", &iterations.to_le_bytes());
            variant(&mut d, 0x04, "V", &0x13u32.to_le_bytes());
        }
    }
    d.push(0);
    d
}

fn argon2_params(kdf: Kdf) -> ([u8; 16], u64, u64, u64) {
    match kdf {
        Kdf::Argon2id => (kdbx::KDF_ARGON2ID, 1024 * 1024, 2, 2),
        Kdf::Argon2d => (kdbx::KDF_ARGON2D, 1024 * 1024, 2, 2),
        Kdf::Argon2Raw { memory, iterations, parallelism } => (kdbx::KDF_ARGON2ID, memory, iterations, parallelism),
        Kdf::Aes(_) => unreachable!(),
    }
}

/// Clé transformée ; des zéros quand les paramètres sont hors bornes (le
/// lecteur doit refuser avant toute dérivation).
fn transformed_key(spec: &KdbxSpec) -> [u8; 32] {
    let mut h = sha2::Sha256::default();
    use sha2::Digest;
    if !spec.password.is_empty() || spec.keyfile.is_none() {
        h.update(sha2::Sha256::digest(spec.password.as_bytes()));
    }
    if let Some(k) = &spec.keyfile {
        h.update(kdbx::keyfile_key(k).unwrap().as_slice());
    }
    let composite: [u8; 32] = h.finalize().into();
    match spec.kdf {
        Kdf::Aes(rounds) if rounds <= super::limits::AES_KDF_MAX_ROUNDS => *kdbx::aes_kdf(&KDF_SEED, rounds, &composite),
        Kdf::Aes(_) => [0; 32],
        kdf => {
            let (uuid, memory, iterations, parallelism) = argon2_params(kdf);
            let algorithm = if uuid == kdbx::KDF_ARGON2D { argon2::Algorithm::Argon2d } else { argon2::Algorithm::Argon2id };
            super::argon2_derive(algorithm, argon2::Version::V0x13, memory / 1024, iterations, parallelism, &composite, &KDF_SEED)
                .map(|k| *k)
                .unwrap_or([0; 32])
        }
    }
}

fn field(out: &mut Vec<u8>, v4: bool, id: u8, value: &[u8]) {
    out.push(id);
    if v4 {
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    } else {
        out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    }
    out.extend_from_slice(value);
}

fn encrypt(cipher: [u8; 16], key: &[u8; 32], iv: &[u8], data: &[u8]) -> Vec<u8> {
    if cipher == kdbx::CIPHER_CHACHA20 {
        let mut buf = data.to_vec();
        chacha20::ChaCha20::new_from_slices(key, iv).unwrap().apply_keystream(&mut buf);
        return buf;
    }
    // AES-256-CBC (et octets quelconques pour un chiffrement inconnu).
    let mut buf = data.to_vec();
    buf.resize(data.len() + 16, 0);
    let len = cbc::Encryptor::<aes::Aes256>::new_from_slices(key, iv)
        .unwrap()
        .encrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buf, data.len())
        .unwrap()
        .len();
    buf.truncate(len);
    buf
}

/// Écrit une base KDBX selon `spec`, avec le contenu d'exemple.
pub fn write_kdbx(spec: &KdbxSpec) -> Vec<u8> {
    let v4 = spec.v4;
    let iv: Vec<u8> = if spec.cipher == kdbx::CIPHER_CHACHA20 { vec![0x22; 12] } else { vec![0x22; 16] };
    let stream_key: Vec<u8> = if v4 { vec![0x55; 64] } else { vec![0x66; 32] };
    let stream_id: u32 = if v4 { 3 } else { match spec.stream { Stream::Salsa20 => 2, Stream::ChaCha20 => 3 } };
    let mut out = Vec::new();
    out.extend_from_slice(&0x9AA2_D903u32.to_le_bytes());
    out.extend_from_slice(&0xB54B_FB67u32.to_le_bytes());
    out.extend_from_slice(&(if v4 { 0x0004_0000u32 } else { 0x0003_0001 }).to_le_bytes());
    if !v4 {
        // Commentaire : champ propre à KDBX 3.1 (modifié par le test d'en-tête).
        field(&mut out, v4, 1, b"Locksy");
    }
    field(&mut out, v4, 2, &spec.cipher);
    field(&mut out, v4, 3, &u32::from(spec.compress).to_le_bytes());
    field(&mut out, v4, 4, &MASTER_SEED);
    if v4 {
        field(&mut out, v4, 7, &iv);
        field(&mut out, v4, 11, &kdf_parameters(spec.kdf));
    } else {
        let Kdf::Aes(rounds) = spec.kdf else { panic!("KDBX 3.1 : AES-KDF seulement") };
        field(&mut out, v4, 5, &KDF_SEED);
        field(&mut out, v4, 6, &rounds.to_le_bytes());
        field(&mut out, v4, 7, &iv);
        field(&mut out, v4, 8, &stream_key);
        field(&mut out, v4, 9, &STREAM_START);
        field(&mut out, v4, 10, &stream_id.to_le_bytes());
    }
    field(&mut out, v4, 0, b"\r\n\r\n");
    let header = out.clone();

    let transformed = transformed_key(spec);
    let key = kdbx::sha256(&[&MASTER_SEED, &transformed]);
    let mut stream = InnerStream::new(stream_id, &stream_key).unwrap();
    if v4 {
        let base = kdbx::sha512(&[&MASTER_SEED, &transformed, &[1u8]]);
        out.extend_from_slice(kdbx::sha256(&[&header]).as_slice());
        let mut mac = <HmacSha256 as Mac>::new_from_slice(kdbx::block_key(u64::MAX, &base).as_slice()).unwrap();
        mac.update(&header);
        out.extend_from_slice(&mac.finalize().into_bytes());
        let mut payload = Vec::new();
        for (id, value) in [(1u8, stream_id.to_le_bytes().to_vec()), (2, stream_key.clone()), (3, b"\x01\x89PNG contenu".to_vec()), (0, vec![])] {
            payload.push(id);
            payload.extend_from_slice(&(value.len() as u32).to_le_bytes());
            payload.extend_from_slice(&value);
        }
        payload.extend_from_slice(sample_xml(&mut stream, true, None).as_bytes());
        let payload = if spec.compress { gzip(&payload) } else { payload };
        let ciphertext = encrypt(spec.cipher, &key, &iv, &payload);
        let chunks: Vec<&[u8]> = ciphertext.chunks(BLOCK).chain(std::iter::once(&[][..])).collect();
        for (index, chunk) in chunks.into_iter().enumerate() {
            let index = index as u64;
            let mut mac = <HmacSha256 as Mac>::new_from_slice(kdbx::block_key(index, &base).as_slice()).unwrap();
            mac.update(&index.to_le_bytes());
            mac.update(&(chunk.len() as i32).to_le_bytes());
            mac.update(chunk);
            out.extend_from_slice(&mac.finalize().into_bytes());
            out.extend_from_slice(&(chunk.len() as i32).to_le_bytes());
            out.extend_from_slice(chunk);
        }
    } else {
        let header_hash = STANDARD.encode(kdbx::sha256(&[&header]).as_slice());
        let xml = sample_xml(&mut stream, false, Some(header_hash));
        let content = if spec.compress { gzip(xml.as_bytes()) } else { xml.into_bytes() };
        let mut plain = STREAM_START.to_vec();
        let mut index = 0u32;
        for chunk in content.chunks(BLOCK) {
            plain.extend_from_slice(&index.to_le_bytes());
            plain.extend_from_slice(kdbx::sha256(&[chunk]).as_slice());
            plain.extend_from_slice(&(chunk.len() as i32).to_le_bytes());
            plain.extend_from_slice(chunk);
            index += 1;
        }
        plain.extend_from_slice(&index.to_le_bytes());
        plain.extend_from_slice(&[0; 32]);
        plain.extend_from_slice(&0i32.to_le_bytes());
        out.extend_from_slice(&encrypt(spec.cipher, &key, &iv, &plain));
    }
    out
}

/// Position des données du champ d'en-tête `id`.
pub fn field_offset(file: &[u8], id: u8) -> Option<usize> {
    let v4 = u32::from_le_bytes(file[8..12].try_into().ok()?) >> 16 == 4;
    let mut pos = 12;
    loop {
        let fid = *file.get(pos)?;
        let (size, data) = if v4 {
            (u32::from_le_bytes(file.get(pos + 1..pos + 5)?.try_into().ok()?) as usize, pos + 5)
        } else {
            (u16::from_le_bytes(file.get(pos + 1..pos + 3)?.try_into().ok()?) as usize, pos + 3)
        };
        if fid == id {
            return Some(data);
        }
        if fid == 0 {
            return None;
        }
        pos = data + size;
    }
}

/// Fichier clé XML version 2.0 (hexadécimal groupé, empreinte de contrôle).
pub fn keyfile_xml_v2(key: &[u8; 32]) -> Vec<u8> {
    use sha2::Digest;
    let hex: Vec<String> = key.chunks(4).map(|c| c.iter().map(|b| format!("{b:02X}")).collect()).collect();
    let hash: String = sha2::Sha256::digest(key)[..4].iter().map(|b| format!("{b:02X}")).collect();
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<KeyFile>\n\t<Meta>\n\t\t<Version>2.0</Version>\n\t</Meta>\n\t<Key>\n\t\t<Data Hash=\"{hash}\">\n\t\t\t{}\n\t\t\t{}\n\t\t</Data>\n\t</Key>\n</KeyFile>\n",
        hex[..4].join(" "),
        hex[4..].join(" ")
    )
    .into_bytes()
}

// ------------------------------------------------------------------ Export JSON chiffré

#[derive(Clone, Copy)]
pub enum BwKdf {
    Pbkdf2(u64),
    Argon2id { memory_mib: u64, iterations: u64, parallelism: u64 },
}

/// Chiffre `plain` en chaîne de type 2 : « 2.iv|chiffré|mac » (base64).
pub fn enc_string(enc_key: &[u8; 32], mac_key: &[u8; 32], iv: [u8; 16], plain: &[u8]) -> String {
    let mut buf = plain.to_vec();
    buf.resize(plain.len() + 16, 0);
    let len = cbc::Encryptor::<aes::Aes256>::new_from_slices(enc_key, &iv)
        .unwrap()
        .encrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buf, plain.len())
        .unwrap()
        .len();
    buf.truncate(len);
    let mut mac = <HmacSha256 as Mac>::new_from_slice(mac_key).unwrap();
    mac.update(&iv);
    mac.update(&buf);
    format!("2.{}|{}|{}", STANDARD.encode(iv), STANDARD.encode(&buf), STANDARD.encode(mac.finalize().into_bytes()))
}

/// Export JSON protégé par mot de passe contenant `inner` (export en clair).
pub fn write_bitwarden(password: &str, kdf: BwKdf, inner: &str) -> String {
    use sha2::Digest;
    let salt = "c2VsLWRlLXRlc3QtcmVwcm9kdWN0aWJsZQ==";
    let mut master = [0u8; 32];
    let (kdf_type, iterations, memory, parallelism) = match kdf {
        BwKdf::Pbkdf2(iterations) => {
            pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt.as_bytes(), iterations as u32, &mut master);
            (0, iterations, serde_json::Value::Null, serde_json::Value::Null)
        }
        BwKdf::Argon2id { memory_mib, iterations, parallelism } => {
            let params = argon2::Params::new((memory_mib * 1024) as u32, iterations as u32, parallelism as u32, Some(32)).unwrap();
            let salt_hash = sha2::Sha256::digest(salt.as_bytes());
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                .hash_password_into(password.as_bytes(), &salt_hash, &mut master)
                .unwrap();
            (1, iterations, memory_mib.into(), parallelism.into())
        }
    };
    let hk = hkdf::Hkdf::<Sha256>::from_prk(&master).unwrap();
    let (mut enc_key, mut mac_key) = ([0u8; 32], [0u8; 32]);
    hk.expand(b"enc", &mut enc_key).unwrap();
    hk.expand(b"mac", &mut mac_key).unwrap();
    serde_json::json!({
        "encrypted": true,
        "passwordProtected": true,
        "salt": salt,
        "kdfType": kdf_type,
        "kdfIterations": iterations,
        "kdfMemory": memory,
        "kdfParallelism": parallelism,
        "encKeyValidation_DO_NOT_EDIT": enc_string(&enc_key, &mac_key, [0x01; 16], b"7f3c5c2e-validation"),
        "data": enc_string(&enc_key, &mac_key, [0x02; 16], inner.as_bytes()),
    })
    .to_string()
}
