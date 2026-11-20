//! Lecture des exports JSON au format d'échange de Bitwarden.
//!
//! - Export protégé par mot de passe (`encrypted` et `passwordProtected`) :
//!   clé maîtresse PBKDF2-SHA256 (`kdfType` 0) ou Argon2id (`kdfType` 1, sel
//!   haché en SHA-256), paramètres bornés (C1.7) ; extension HKDF-SHA256
//!   (`enc`, `mac`) ; chaînes chiffrées de type 2 « iv|chiffré|mac » :
//!   HMAC-SHA256 vérifié en temps constant AVANT le déchiffrement AES-256-CBC.
//!   `encKeyValidation_DO_NOT_EDIT` prouve le mot de passe (`wrong_password`),
//!   un MAC faux sur les données signale une altération (`integrity`).
//! - Export en clair (`encrypted` faux ou absent) : lu tel quel.
//! - Export chiffré par la clé du compte (sans mot de passe) : illisible hors
//!   du compte d'origine, `unsupported_format`.
//!
//! Types repris : identifiant, note, carte, identité, clé SSH ; dossiers (ou,
//! à défaut, collection) → dossier ; champs personnalisés et historique.

use super::{limits, warning, ImportError, ImportResult};
use crate::model::{CustomField, ItemData, ItemKind, PasswordHistoryEntry};
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use zeroize::{Zeroize, Zeroizing};

type E = ImportError;

/// Lit un export JSON (chiffré par mot de passe ou en clair).
pub fn read_bitwarden_json(text: &str, password: &str) -> Result<ImportResult, ImportError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let envelope: Envelope = serde_json::from_str(text).map_err(|_| E::UnsupportedFormat)?;
    if !envelope.encrypted {
        if envelope.items.is_none() {
            return Err(E::UnsupportedFormat);
        }
        let export: Export = serde_json::from_str(text).map_err(|_| E::UnsupportedFormat)?;
        return Ok(map_export(export));
    }
    if !envelope.password_protected {
        return Err(E::UnsupportedFormat);
    }
    let keys = Keys::derive(&envelope, password)?;
    let validation = envelope.enc_key_validation.as_deref().ok_or(E::Corrupt)?;
    keys.decrypt(validation).map_err(|e| if e == Failure::Mac { E::WrongPassword } else { e.into() })?;
    let data = envelope.data.as_deref().ok_or(E::Corrupt)?;
    let plain = keys.decrypt(data).map_err(|e| if e == Failure::Mac { E::Integrity } else { e.into() })?;
    let inner = std::str::from_utf8(&plain).map_err(|_| E::Corrupt)?;
    let export: Export = serde_json::from_str(inner).map_err(|_| E::Corrupt)?;
    Ok(map_export(export))
}

// ------------------------------------------------------------------ Enveloppe

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Envelope {
    #[serde(default, deserialize_with = "lenient_bool")]
    encrypted: bool,
    #[serde(default, deserialize_with = "lenient_bool")]
    password_protected: bool,
    #[serde(default)]
    salt: Option<String>,
    #[serde(default)]
    kdf_type: Option<u64>,
    #[serde(default)]
    kdf_iterations: Option<u64>,
    #[serde(default)]
    kdf_memory: Option<u64>,
    #[serde(default)]
    kdf_parallelism: Option<u64>,
    #[serde(default, rename = "encKeyValidation_DO_NOT_EDIT")]
    enc_key_validation: Option<String>,
    #[serde(default)]
    data: Option<String>,
    /// Présent (tableau) dans un export en clair.
    #[serde(default)]
    items: Option<serde::de::IgnoredAny>,
}

fn lenient_bool<'de, D: Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    Ok(Option::<bool>::deserialize(d)?.unwrap_or(false))
}

/// Échecs de déchiffrement d'une chaîne chiffrée.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Failure {
    /// MAC faux : mauvaise clé ou donnée altérée (selon la chaîne).
    Mac,
    Other(ImportError),
}

impl From<Failure> for ImportError {
    fn from(f: Failure) -> Self {
        match f {
            Failure::Mac => E::Integrity,
            Failure::Other(e) => e,
        }
    }
}

struct Keys {
    enc: Zeroizing<[u8; 32]>,
    mac: Zeroizing<[u8; 32]>,
}

impl Keys {
    fn derive(env: &Envelope, password: &str) -> Result<Self, E> {
        let salt = env.salt.as_deref().filter(|s| !s.is_empty()).ok_or(E::Corrupt)?;
        let iterations = env.kdf_iterations.ok_or(E::Corrupt)?;
        let master = match env.kdf_type {
            Some(0) => {
                if !(limits::PBKDF2_MIN_ITERATIONS..=limits::PBKDF2_MAX_ITERATIONS).contains(&iterations) {
                    return Err(E::KdfOutOfBounds);
                }
                let mut out = Zeroizing::new([0u8; 32]);
                pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt.as_bytes(), iterations as u32, out.as_mut());
                out
            }
            Some(1) => {
                let memory_mib = env.kdf_memory.ok_or(E::Corrupt)?;
                let parallelism = env.kdf_parallelism.ok_or(E::Corrupt)?;
                if memory_mib > limits::ARGON2_MAX_MEMORY_MIB {
                    return Err(E::KdfOutOfBounds);
                }
                let salt_hash = Sha256::digest(salt.as_bytes());
                super::argon2_derive(
                    argon2::Algorithm::Argon2id,
                    argon2::Version::V0x13,
                    memory_mib * 1024,
                    iterations,
                    parallelism,
                    password.as_bytes(),
                    &salt_hash,
                )?
            }
            Some(_) => return Err(E::UnsupportedKdf),
            None => return Err(E::Corrupt),
        };
        Ok(Self::stretch(&master))
    }

    /// Extension HKDF-SHA256 (étape « expand » seule) de la clé maîtresse.
    fn stretch(master: &[u8; 32]) -> Self {
        let hk = hkdf::Hkdf::<Sha256>::from_prk(master).expect("clé de 32 octets");
        let mut keys = Keys { enc: Zeroizing::new([0; 32]), mac: Zeroizing::new([0; 32]) };
        hk.expand(b"enc", keys.enc.as_mut()).expect("longueur valide");
        hk.expand(b"mac", keys.mac.as_mut()).expect("longueur valide");
        keys
    }

    /// Déchiffre une chaîne de type 2. Le MAC est vérifié avant tout.
    fn decrypt(&self, enc: &str) -> Result<Zeroizing<Vec<u8>>, Failure> {
        let corrupt = Failure::Other(E::Corrupt);
        let (kind, rest) = enc.trim().split_once('.').ok_or(corrupt)?;
        if kind != "2" {
            return Err(Failure::Other(E::UnsupportedCipher));
        }
        let mut parts = rest.split('|');
        let (Some(iv), Some(ct), Some(mac), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
            return Err(corrupt);
        };
        let iv = STANDARD.decode(iv).map_err(|_| corrupt)?;
        let mut ct = Zeroizing::new(STANDARD.decode(ct).map_err(|_| corrupt)?);
        let mac = STANDARD.decode(mac).map_err(|_| corrupt)?;
        if iv.len() != 16 || mac.len() != 32 {
            return Err(corrupt);
        }
        let mut check = Hmac::<Sha256>::new_from_slice(self.mac.as_slice()).expect("clé HMAC");
        check.update(&iv);
        check.update(&ct);
        check.verify_slice(&mac).map_err(|_| Failure::Mac)?;
        let len = cbc::Decryptor::<aes::Aes256>::new_from_slices(self.enc.as_slice(), &iv)
            .map_err(|_| corrupt)?
            .decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut ct)
            .map_err(|_| corrupt)?
            .len();
        ct.truncate(len);
        Ok(ct)
    }
}

// ------------------------------------------------------------------ Export en clair

/// Chaîne tolérante : `null`, nombre ou booléen acceptés (export variable).
#[derive(Default)]
struct Text(String);

impl<'de> Deserialize<'de> for Text {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Text(match serde_json::Value::deserialize(d)? {
            serde_json::Value::String(s) => s,
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            _ => String::new(),
        }))
    }
}

impl Drop for Text {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Text {
    fn take(&mut self) -> String {
        std::mem::take(&mut self.0)
    }

    fn trimmed(&self) -> &str {
        self.0.trim()
    }
}

/// Tableau tolérant : `null` ou absent = vide.
fn list<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Vec<T>, D::Error> {
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Export {
    #[serde(deserialize_with = "list")]
    folders: Vec<Named>,
    #[serde(deserialize_with = "list")]
    collections: Vec<Named>,
    #[serde(deserialize_with = "list")]
    items: Vec<Item>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Named {
    id: Text,
    name: Text,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Item {
    id: Text,
    folder_id: Text,
    #[serde(deserialize_with = "list")]
    collection_ids: Vec<String>,
    #[serde(rename = "type")]
    kind: Option<u64>,
    name: Text,
    notes: Text,
    favorite: Option<bool>,
    #[serde(deserialize_with = "list")]
    fields: Vec<Field>,
    login: Option<Login>,
    card: Option<Card>,
    identity: Option<Identity>,
    ssh_key: Option<Ssh>,
    #[serde(deserialize_with = "list")]
    password_history: Vec<History>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Field {
    name: Text,
    value: Text,
    #[serde(rename = "type")]
    kind: Option<u64>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Login {
    #[serde(deserialize_with = "list")]
    uris: Vec<Uri>,
    username: Text,
    password: Text,
    totp: Text,
    password_revision_date: Text,
    #[serde(deserialize_with = "list")]
    fido2_credentials: Vec<serde_json::Value>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Uri {
    uri: Text,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Card {
    cardholder_name: Text,
    brand: Text,
    number: Text,
    exp_month: Text,
    exp_year: Text,
    code: Text,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Identity {
    title: Text,
    first_name: Text,
    middle_name: Text,
    last_name: Text,
    address1: Text,
    address2: Text,
    address3: Text,
    city: Text,
    state: Text,
    postal_code: Text,
    country: Text,
    company: Text,
    email: Text,
    phone: Text,
    ssn: Text,
    username: Text,
    passport_number: Text,
    license_number: Text,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Ssh {
    private_key: Text,
    public_key: Text,
    key_fingerprint: Text,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct History {
    last_used_date: Text,
    password: Text,
}

// ------------------------------------------------------------------ Correspondance

fn map_export(mut export: Export) -> ImportResult {
    let names = |list: &mut Vec<Named>| -> HashMap<String, String> {
        list.iter_mut().map(|n| (n.id.take(), n.name.trimmed().to_string())).collect()
    };
    let mut result = ImportResult::default();
    for n in export.folders.iter().chain(export.collections.iter()) {
        result.add_folder(n.name.trimmed());
    }
    let folders = names(&mut export.folders);
    let collections = names(&mut export.collections);
    for mut item in export.items.drain(..) {
        let Some(data) = map_item(&mut item) else {
            result.warn(warning::ITEM_TYPE_UNSUPPORTED, None);
            continue;
        };
        let index = result.items.len();
        let folder = match folders.get(item.folder_id.trimmed()) {
            Some(f) => f.clone(),
            None => {
                let first = item.collection_ids.first().and_then(|c| collections.get(c)).cloned().unwrap_or_default();
                if item.collection_ids.len() > 1 {
                    result.warn(warning::MULTIPLE_COLLECTIONS, Some(index));
                }
                first
            }
        };
        if item.fields.iter().any(|f| f.kind == Some(3)) {
            result.warn(warning::LINKED_FIELD_SKIPPED, Some(index));
        }
        if item.login.as_ref().is_some_and(|l| !l.fido2_credentials.is_empty()) {
            result.warn(warning::PASSKEYS_SKIPPED, Some(index));
        }
        result.push_item(data, folder, item.id.take());
    }
    result
}

fn field(label: &str, value: &mut Text, hidden: bool) -> Option<CustomField> {
    let value = value.take();
    (!value.trim().is_empty()).then(|| CustomField { label: label.to_string(), value, hidden })
}

fn map_item(item: &mut Item) -> Option<ItemData> {
    let mut data = ItemData {
        name: item.name.take(),
        notes: item.notes.take(),
        favorite: item.favorite.unwrap_or(false),
        ..Default::default()
    };
    match item.kind? {
        1 => {
            data.kind = ItemKind::Login;
            if let Some(login) = item.login.as_mut() {
                data.username = login.username.take();
                data.password = login.password.take();
                data.totp = login.totp.take();
                data.urls = login.uris.iter().map(|u| u.uri.trimmed().to_string()).filter(|u| !u.is_empty()).collect();
                data.password_changed_at = super::parse_iso8601(login.password_revision_date.trimmed()).unwrap_or(0);
            }
        }
        2 => data.kind = ItemKind::Note,
        3 => {
            data.kind = ItemKind::Card;
            if let Some(card) = item.card.as_mut() {
                data.card.holder = card.cardholder_name.take();
                data.card.number = card.number.take();
                data.card.cvv = card.code.take();
                data.card.expiry = expiry(card.exp_month.trimmed(), card.exp_year.trimmed());
                data.fields.extend(field("Réseau", &mut card.brand, false));
            }
        }
        4 => {
            data.kind = ItemKind::Identity;
            if let Some(id) = item.identity.as_mut() {
                let i = &mut data.identity;
                i.first_name = id.first_name.take();
                i.last_name = id.last_name.take();
                i.email = id.email.take();
                i.phone = id.phone.take();
                i.company = id.company.take();
                let city = format!("{} {}", id.postal_code.trimmed(), id.city.trimmed());
                i.address = [id.address1.trimmed(), id.address2.trimmed(), id.address3.trimmed(), city.trim(), id.state.trimmed(), id.country.trimmed()]
                    .into_iter()
                    .filter(|l| !l.is_empty())
                    .collect::<Vec<_>>()
                    .join("\n");
                // Un seul numéro de document dans le modèle : les autres
                // deviennent des champs personnalisés.
                let mut documents = [("Numéro de passeport", &mut id.passport_number), ("Numéro de permis de conduire", &mut id.license_number), ("Numéro de sécurité sociale", &mut id.ssn)];
                for (label, value) in documents.iter_mut() {
                    if i.document_number.is_empty() && !value.trimmed().is_empty() {
                        i.document_number = value.take();
                    } else {
                        data.fields.extend(field(label, value, true));
                    }
                }
                data.fields.extend(field("Civilité", &mut id.title, false));
                data.fields.extend(field("Deuxième prénom", &mut id.middle_name, false));
                data.fields.extend(field("Nom d'utilisateur", &mut id.username, false));
            }
        }
        5 => {
            data.kind = ItemKind::Ssh;
            if let Some(ssh) = item.ssh_key.as_mut() {
                data.ssh.private_key = ssh.private_key.take();
                data.ssh.public_key = ssh.public_key.take();
                data.fields.extend(field("Empreinte", &mut ssh.key_fingerprint, false));
            }
        }
        _ => return None,
    }
    for f in item.fields.iter_mut() {
        match f.kind {
            // Champ lié : n'a pas de valeur propre.
            Some(3) => {}
            kind => data.fields.push(CustomField { label: f.name.take(), value: f.value.take(), hidden: kind == Some(1) }),
        }
    }
    let mut history: Vec<PasswordHistoryEntry> = item
        .password_history
        .iter_mut()
        .filter(|h| !h.password.0.is_empty())
        .map(|h| PasswordHistoryEntry { changed_at: super::parse_iso8601(h.last_used_date.trimmed()).unwrap_or(0), password: h.password.take() })
        .collect();
    history.sort_by_key(|h| std::cmp::Reverse(h.changed_at));
    data.password_history = history;
    Some(data)
}

/// Échéance de carte au format du modèle : « MM/AA ».
fn expiry(month: &str, year: &str) -> String {
    let month = month.parse::<u32>().ok().filter(|m| (1..=12).contains(m)).map(|m| format!("{m:02}"));
    let digits: String = year.chars().filter(char::is_ascii_digit).collect();
    let year = match digits.len() {
        0 => None,
        1 | 2 => Some(format!("{:0>2}", digits)),
        n => Some(digits[n - 2..].to_string()),
    };
    match (month, year) {
        (Some(m), Some(y)) => format!("{m}/{y}"),
        (Some(m), None) => m,
        (None, Some(y)) => y,
        (None, None) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::testgen::{self, BwKdf};
    use super::*;

    /// Export en clair d'exemple : tous les types, dossiers, collections.
    fn sample() -> String {
        serde_json::json!({
            "encrypted": false,
            "folders": [ { "id": "f1", "name": "Perso/Banque" }, { "id": "f2", "name": "Vide" } ],
            "collections": [ { "id": "c1", "organizationId": "o", "name": "Équipe" }, { "id": "c2", "name": "Autre" } ],
            "items": [
                {
                    "id": "i1", "folderId": "f1", "type": 1, "name": "Banque", "notes": "Agence\ncentre", "favorite": true,
                    "fields": [
                        { "name": "Question", "value": "Chat", "type": 0 },
                        { "name": "Code", "value": "9876", "type": 1 },
                        { "name": "Actif", "value": "true", "type": 2 },
                        { "name": "Lien", "value": null, "type": 3, "linkedId": 100 }
                    ],
                    "login": {
                        "uris": [ { "match": null, "uri": "https://banque.exemple.fr" }, { "uri": "https://m.banque.exemple.fr" } ],
                        "username": "alice", "password": testgen::TRICKY_PASSWORD, "totp": "JBSWY3DPEHPK3PXP",
                        "passwordRevisionDate": "2023-11-14T22:13:20.000Z",
                        "fido2Credentials": [ { "credentialId": "x" } ]
                    },
                    "passwordHistory": [
                        { "lastUsedDate": "2020-09-13T12:26:40.000Z", "password": "plus-ancien" },
                        { "lastUsedDate": "2022-01-01T00:00:00.000Z", "password": "ancien" }
                    ]
                },
                { "id": "i2", "folderId": null, "collectionIds": ["c1", "c2"], "type": 2, "name": "Note", "notes": "Secret", "secureNote": { "type": 0 } },
                {
                    "id": "i3", "type": 3, "name": "Carte",
                    "card": { "cardholderName": "Alice Martin", "brand": "Visa", "number": "4111111111111111", "expMonth": "3", "expYear": "2031", "code": "123" }
                },
                {
                    "id": "i4", "type": 4, "name": "Identité",
                    "identity": {
                        "title": "Mme", "firstName": "Alice", "middleName": null, "lastName": "Martin",
                        "address1": "1 rue de la Paix", "address2": null, "address3": "", "city": "Paris", "state": null,
                        "postalCode": "75002", "country": "FR", "company": "Exemple", "email": "alice@exemple.fr",
                        "phone": "0102030405", "ssn": "2850175000000", "username": "amartin", "passportNumber": "12AB34567", "licenseNumber": null
                    }
                },
                { "id": "i5", "type": 5, "name": "Serveur", "sshKey": { "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----", "publicKey": "ssh-ed25519 AAAA alice@poste", "keyFingerprint": "SHA256:xyz" } },
                { "id": "i6", "type": 99, "name": "Inconnu" },
                { "id": "i7", "type": 1, "name": "", "login": null }
            ]
        })
        .to_string()
    }

    fn check_sample(r: &ImportResult) {
        assert_eq!(r.items.len(), 6, "{r:?}");
        let login = &r.items[0];
        assert_eq!(login.source_id, "i1");
        assert_eq!(login.folder, "Perso/Banque");
        let d = &login.data;
        assert_eq!((d.kind, d.name.as_str(), d.username.as_str()), (ItemKind::Login, "Banque", "alice"));
        assert_eq!(d.password, testgen::TRICKY_PASSWORD);
        assert_eq!(d.notes, "Agence\ncentre");
        assert!(d.favorite);
        assert_eq!(d.totp, "JBSWY3DPEHPK3PXP");
        assert_eq!(d.urls, vec!["https://banque.exemple.fr".to_string(), "https://m.banque.exemple.fr".to_string()]);
        assert_eq!(d.password_changed_at, 1_700_000_000);
        assert_eq!(
            d.fields,
            vec![
                CustomField { label: "Question".into(), value: "Chat".into(), hidden: false },
                CustomField { label: "Code".into(), value: "9876".into(), hidden: true },
                CustomField { label: "Actif".into(), value: "true".into(), hidden: false },
            ]
        );
        assert_eq!(d.password_history.iter().map(|h| (h.password.as_str(), h.changed_at)).collect::<Vec<_>>(), vec![("ancien", 1_640_995_200), ("plus-ancien", 1_600_000_000)]);

        let note = &r.items[1];
        assert_eq!((note.data.kind, note.data.notes.as_str(), note.folder.as_str()), (ItemKind::Note, "Secret", "Équipe"));
        let card = &r.items[2].data;
        assert_eq!(card.kind, ItemKind::Card);
        assert_eq!((card.card.holder.as_str(), card.card.number.as_str(), card.card.cvv.as_str(), card.card.expiry.as_str()), ("Alice Martin", "4111111111111111", "123", "03/31"));
        assert_eq!(card.fields, vec![CustomField { label: "Réseau".into(), value: "Visa".into(), hidden: false }]);
        let id = &r.items[3].data;
        assert_eq!(id.kind, ItemKind::Identity);
        assert_eq!(id.identity.address, "1 rue de la Paix\n75002 Paris\nFR");
        assert_eq!(id.identity.document_number, "12AB34567");
        assert_eq!((id.identity.first_name.as_str(), id.identity.last_name.as_str(), id.identity.email.as_str()), ("Alice", "Martin", "alice@exemple.fr"));
        let labels: Vec<_> = id.fields.iter().map(|f| (f.label.as_str(), f.value.as_str(), f.hidden)).collect();
        assert_eq!(labels, vec![("Numéro de sécurité sociale", "2850175000000", true), ("Civilité", "Mme", false), ("Nom d'utilisateur", "amartin", false)]);
        let ssh = &r.items[4].data;
        assert_eq!(ssh.kind, ItemKind::Ssh);
        assert!(ssh.ssh.private_key.starts_with("-----BEGIN") && ssh.ssh.private_key.contains('\n'));
        assert_eq!(ssh.ssh.public_key, "ssh-ed25519 AAAA alice@poste");
        assert_eq!(r.items[5].data.name, "");
        assert_eq!(r.folders, vec!["Perso/Banque".to_string(), "Vide".to_string(), "Équipe".to_string(), "Autre".to_string()]);
        use super::super::ImportWarning as W;
        assert_eq!(
            r.warnings,
            vec![
                W { code: warning::LINKED_FIELD_SKIPPED, index: Some(0) },
                W { code: warning::PASSKEYS_SKIPPED, index: Some(0) },
                W { code: warning::MULTIPLE_COLLECTIONS, index: Some(1) },
                W { code: warning::ITEM_TYPE_UNSUPPORTED, index: None },
                W { code: warning::MISSING_TITLE, index: Some(5) },
            ]
        );
    }

    #[test]
    fn export_en_clair() {
        check_sample(&read_bitwarden_json(&sample(), "ignoré").unwrap());
    }

    #[test]
    fn export_chiffre_pbkdf2() {
        let file = testgen::write_bitwarden(testgen::PASSWORD, BwKdf::Pbkdf2(5000), &sample());
        check_sample(&read_bitwarden_json(&file, testgen::PASSWORD).unwrap());
    }

    #[test]
    fn export_chiffre_argon2id() {
        let kdf = BwKdf::Argon2id { memory_mib: 1, iterations: 2, parallelism: 1 };
        let file = testgen::write_bitwarden(testgen::TRICKY_PASSWORD, kdf, &sample());
        check_sample(&read_bitwarden_json(&file, testgen::TRICKY_PASSWORD).unwrap());
    }

    #[test]
    fn mauvais_mot_de_passe() {
        let file = testgen::write_bitwarden(testgen::PASSWORD, BwKdf::Pbkdf2(5000), &sample());
        assert_eq!(read_bitwarden_json(&file, "faux").unwrap_err(), E::WrongPassword);
    }

    #[test]
    fn donnees_alterees_refusees_avant_dechiffrement() {
        let file = testgen::write_bitwarden(testgen::PASSWORD, BwKdf::Pbkdf2(5000), &sample());
        let mut v: serde_json::Value = serde_json::from_str(&file).unwrap();
        let data = v["data"].as_str().unwrap().to_string();
        let (head, rest) = data.split_once('|').unwrap();
        let (ct, mac) = rest.split_once('|').unwrap();
        // Dernier bloc chiffré modifié : déchiffré, il casserait le
        // remplissage (corrupt) ; le MAC le refuse avant (integrity).
        let mut raw = STANDARD.decode(ct).unwrap();
        let n = raw.len();
        raw[n - 1] ^= 1;
        v["data"] = format!("{head}|{}|{mac}", STANDARD.encode(raw)).into();
        assert_eq!(read_bitwarden_json(&v.to_string(), testgen::PASSWORD).unwrap_err(), E::Integrity);
    }

    #[test]
    fn bornes_de_derivation() {
        let file = testgen::write_bitwarden("x", BwKdf::Pbkdf2(5000), "{}");
        let mut v: serde_json::Value = serde_json::from_str(&file).unwrap();
        for (iterations, code) in [(4999, E::KdfOutOfBounds), (2_000_001, E::KdfOutOfBounds)] {
            v["kdfIterations"] = iterations.into();
            assert_eq!(read_bitwarden_json(&v.to_string(), "x").unwrap_err(), code);
        }
        v["kdfType"] = 1.into();
        for (memory, iterations, parallelism) in [(1025, 3, 4), (64, 101, 4), (64, 3, 17), (64, 0, 4), (0, 3, 4)] {
            v["kdfMemory"] = memory.into();
            v["kdfIterations"] = iterations.into();
            v["kdfParallelism"] = parallelism.into();
            assert_eq!(read_bitwarden_json(&v.to_string(), "x").unwrap_err(), E::KdfOutOfBounds, "{memory} {iterations} {parallelism}");
        }
        v["kdfType"] = 7.into();
        assert_eq!(read_bitwarden_json(&v.to_string(), "x").unwrap_err(), E::UnsupportedKdf);
    }

    #[test]
    fn formats_refuses() {
        assert_eq!(read_bitwarden_json("bonjour", "x").unwrap_err(), E::UnsupportedFormat);
        assert_eq!(read_bitwarden_json("{\"autre\":1}", "x").unwrap_err(), E::UnsupportedFormat);
        assert_eq!(read_bitwarden_json("[1,2]", "x").unwrap_err(), E::UnsupportedFormat);
        // Chiffré par la clé du compte : illisible hors du compte.
        assert_eq!(read_bitwarden_json("{\"encrypted\":true,\"encKeyValidation_DO_NOT_EDIT\":\"2.a|b|c\",\"data\":\"2.a|b|c\"}", "x").unwrap_err(), E::UnsupportedFormat);
        // Chaîne chiffrée d'un autre type (sans MAC).
        let file = testgen::write_bitwarden("x", BwKdf::Pbkdf2(5000), "{}");
        let mut v: serde_json::Value = serde_json::from_str(&file).unwrap();
        v["encKeyValidation_DO_NOT_EDIT"] = "0.AAAA|BBBB".into();
        assert_eq!(read_bitwarden_json(&v.to_string(), "x").unwrap_err(), E::UnsupportedCipher);
        v["encKeyValidation_DO_NOT_EDIT"] = "2.pas|du|base64!".into();
        assert_eq!(read_bitwarden_json(&v.to_string(), "x").unwrap_err(), E::Corrupt);
    }

    #[test]
    fn contenu_dechiffre_illisible() {
        let file = testgen::write_bitwarden("x", BwKdf::Pbkdf2(5000), "pas du json");
        assert_eq!(read_bitwarden_json(&file, "x").unwrap_err(), E::Corrupt);
    }

    #[test]
    fn echeances_de_carte() {
        assert_eq!(expiry("12", "2030"), "12/30");
        assert_eq!(expiry("1", "7"), "01/07");
        assert_eq!(expiry("", "2030"), "30");
        assert_eq!(expiry("13", ""), "");
    }
}
