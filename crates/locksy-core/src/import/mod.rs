//! Import de coffres depuis d'autres gestionnaires de mots de passe.
//!
//! Lecture, entièrement côté client, des formats d'échange chiffrés :
//! - [`kdbx`] : bases KDBX 3.1 et 4 (format de fichier de KeePass) ;
//! - [`bitwarden`] : export JSON (chiffré par mot de passe ou en clair) au
//!   format d'échange de Bitwarden.
//!
//! Les deux lecteurs rendent un [`ImportResult`] : des éléments au format du
//! modèle Locksy ([`ItemData`]), le dossier d'origine de chacun et des
//! avertissements à codes stables. Les erreurs sont des codes stables
//! ([`ImportError`]) traduits par l'interface (`import.error.<code>`) : aucun
//! message ne contient de secret, et les `Debug` des résultats n'affichent
//! que des nombres.
//!
//! Formats implémentés d'après leurs spécifications publiques ; aucun fichier
//! tiers n'est copié : les tests génèrent leurs propres fichiers.

pub mod bitwarden;
pub mod kdbx;

#[cfg(test)]
mod testgen;

use crate::model::ItemData;
use serde::Serialize;
use std::fmt;

/// Erreur d'import : un code stable, sans donnée secrète.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportError {
    /// Mot de passe (ou fichier clé) incorrect.
    WrongPassword,
    /// Fichier qui n'est pas du format annoncé.
    UnsupportedFormat,
    /// Version de format non prise en charge (KDBX 1 et 2, par exemple).
    UnsupportedVersion,
    /// Algorithme de chiffrement non pris en charge (Twofish, par exemple).
    UnsupportedCipher,
    /// Fonction de dérivation de clé non prise en charge.
    UnsupportedKdf,
    /// Paramètres de dérivation de clé hors des bornes admises.
    KdfOutOfBounds,
    /// Fichier tronqué ou mal formé.
    Corrupt,
    /// Contrôle d'intégrité en échec : fichier altéré.
    Integrity,
    /// Contenu trop volumineux.
    TooLarge,
    /// La base exige un fichier clé et aucun n'a été fourni.
    KeyfileRequired,
}

impl ImportError {
    /// Code stable, identique à la forme sérialisée.
    pub fn code(self) -> &'static str {
        match self {
            ImportError::WrongPassword => "wrong_password",
            ImportError::UnsupportedFormat => "unsupported_format",
            ImportError::UnsupportedVersion => "unsupported_version",
            ImportError::UnsupportedCipher => "unsupported_cipher",
            ImportError::UnsupportedKdf => "unsupported_kdf",
            ImportError::KdfOutOfBounds => "kdf_out_of_bounds",
            ImportError::Corrupt => "corrupt",
            ImportError::Integrity => "integrity",
            ImportError::TooLarge => "too_large",
            ImportError::KeyfileRequired => "keyfile_required",
        }
    }
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for ImportError {}

/// Avertissement d'import. `index` désigne l'élément concerné dans
/// [`ImportResult::items`] ; il est absent quand l'avertissement porte sur
/// des données écartées (corbeille, type d'élément inconnu).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImportWarning {
    pub code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<usize>,
}

/// Codes d'avertissement (libellés `import.warning.<code>`).
pub mod warning {
    /// Éléments de la corbeille de la base ignorés.
    pub const TRASH_SKIPPED: &str = "trash_skipped";
    /// Pièces jointes non importées (à rattacher à la main).
    pub const ATTACHMENTS_SKIPPED: &str = "attachments_skipped";
    /// Élément sans nom ni adresse ni identifiant.
    pub const MISSING_TITLE: &str = "missing_title";
    /// Type d'élément inconnu, écarté.
    pub const ITEM_TYPE_UNSUPPORTED: &str = "item_type_unsupported";
    /// Champ lié à un autre champ (sans valeur propre), écarté.
    pub const LINKED_FIELD_SKIPPED: &str = "linked_field_skipped";
    /// Clés d'accès (passkeys) non importées.
    pub const PASSKEYS_SKIPPED: &str = "passkeys_skipped";
    /// Élément rangé dans plusieurs collections : seule la première est gardée.
    pub const MULTIPLE_COLLECTIONS: &str = "multiple_collections";
    /// Historique des mots de passe tronqué à la limite du modèle.
    pub const HISTORY_TRUNCATED: &str = "history_truncated";
}

/// Élément importé, au format du modèle Locksy.
#[derive(Clone, Serialize)]
pub struct ImportedItem {
    pub data: ItemData,
    /// Chemin du dossier d'origine (« A/B »), vide à la racine.
    pub folder: String,
    /// Identifiant de l'élément dans le fichier source.
    pub source_id: String,
}

impl fmt::Debug for ImportedItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Ni nom ni secret : seulement le type.
        f.debug_struct("ImportedItem").field("kind", &self.data.kind).finish_non_exhaustive()
    }
}

/// Résultat d'un import.
#[derive(Clone, Default, Serialize)]
pub struct ImportResult {
    pub items: Vec<ImportedItem>,
    /// Chemins de dossiers rencontrés (vides compris), dans l'ordre du fichier.
    pub folders: Vec<String>,
    pub warnings: Vec<ImportWarning>,
}

impl fmt::Debug for ImportResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImportResult")
            .field("items", &self.items.len())
            .field("folders", &self.folders.len())
            .field("warnings", &self.warnings)
            .finish()
    }
}

impl ImportResult {
    fn warn(&mut self, code: &'static str, index: Option<usize>) {
        self.warnings.push(ImportWarning { code, index });
    }

    /// Ajoute un dossier s'il est nouveau (ordre d'apparition conservé).
    fn add_folder(&mut self, path: &str) {
        if !path.is_empty() && !self.folders.iter().any(|f| f == path) {
            self.folders.push(path.to_string());
        }
    }

    /// Ajoute un élément après les compléments communs aux deux formats :
    /// nom de repli, historique borné.
    fn push_item(&mut self, mut data: ItemData, folder: String, source_id: String) {
        let index = self.items.len();
        if data.name.trim().is_empty() {
            let fallback = data.urls.first().cloned().unwrap_or_else(|| data.username.clone());
            data.name = fallback;
            if data.name.trim().is_empty() {
                self.warn(warning::MISSING_TITLE, Some(index));
            }
        }
        if data.password_history.len() > crate::model::PASSWORD_HISTORY_MAX {
            data.password_history.truncate(crate::model::PASSWORD_HISTORY_MAX);
            self.warn(warning::HISTORY_TRUNCATED, Some(index));
        }
        self.add_folder(&folder);
        self.items.push(ImportedItem { data, folder, source_id });
    }
}

/// Bornes des paramètres de dérivation lus dans un fichier (contrat C1.7) :
/// au-delà, `kdf_out_of_bounds`, avant tout calcul. Elles protègent le poste
/// d'un fichier piégé qui exigerait des minutes de calcul ou des gigaoctets.
pub mod limits {
    /// Mémoire Argon2 maximale (Mio).
    pub const ARGON2_MAX_MEMORY_MIB: u64 = 1024;
    /// Nombre maximal de passes Argon2.
    pub const ARGON2_MAX_ITERATIONS: u64 = 100;
    /// Parallélisme Argon2 maximal.
    pub const ARGON2_MAX_PARALLELISM: u64 = 16;
    /// Nombre maximal de tours de l'AES-KDF (KDBX).
    pub const AES_KDF_MAX_ROUNDS: u64 = 50_000_000;
    /// Itérations PBKDF2-SHA256 admises (export JSON chiffré).
    pub const PBKDF2_MIN_ITERATIONS: u64 = 5_000;
    pub const PBKDF2_MAX_ITERATIONS: u64 = 2_000_000;
}

/// Taille maximale d'un contenu décompressé (protection contre les bombes
/// de décompression) : au-delà, `too_large`.
pub(crate) const MAX_INFLATED: u64 = 256 * 1024 * 1024;

/// Argon2 borné : 32 octets dérivés de `password` et `salt`. La mémoire est
/// réservée sans paniquer : un poste qui ne peut pas l'allouer (WebAssembly)
/// obtient `kdf_out_of_bounds` au lieu d'un arrêt brutal.
pub(crate) fn argon2_derive(
    algorithm: argon2::Algorithm,
    version: argon2::Version,
    memory_kib: u64,
    iterations: u64,
    parallelism: u64,
    password: &[u8],
    salt: &[u8],
) -> Result<zeroize::Zeroizing<[u8; 32]>, ImportError> {
    use limits::*;
    let in_bounds = (1..=ARGON2_MAX_MEMORY_MIB * 1024).contains(&memory_kib)
        && (1..=ARGON2_MAX_ITERATIONS).contains(&iterations)
        && (1..=ARGON2_MAX_PARALLELISM).contains(&parallelism);
    if !in_bounds {
        return Err(ImportError::KdfOutOfBounds);
    }
    let params = argon2::Params::new(memory_kib as u32, iterations as u32, parallelism as u32, Some(32))
        .map_err(|_| ImportError::KdfOutOfBounds)?;
    let mut blocks: Vec<argon2::Block> = Vec::new();
    blocks.try_reserve_exact(params.block_count()).map_err(|_| ImportError::KdfOutOfBounds)?;
    blocks.resize(params.block_count(), argon2::Block::default());
    let mut out = zeroize::Zeroizing::new([0u8; 32]);
    let result = argon2::Argon2::new(algorithm, version, params).hash_password_into_with_memory(
        password,
        salt,
        out.as_mut(),
        &mut blocks,
    );
    // Les blocs contiennent des états intermédiaires dérivés du secret.
    zeroize::Zeroize::zeroize(&mut blocks);
    result.map_err(|_| ImportError::KdfOutOfBounds)?;
    Ok(out)
}

/// Date ISO 8601 (`2024-05-01T10:20:30Z`, fraction et décalage admis) en
/// secondes Unix. `None` si la forme n'est pas reconnue.
pub(crate) fn parse_iso8601(s: &str) -> Option<i64> {
    let s = s.trim();
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || !(b[10] == b'T' || b[10] == b' ') || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> { s.get(r)?.parse::<i64>().ok() };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, se) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let mut rest = &s[19..];
    if let Some(frac) = rest.strip_prefix('.') {
        let digits = frac.bytes().take_while(u8::is_ascii_digit).count();
        rest = &frac[digits..];
    }
    let offset = match rest {
        "" | "Z" | "z" => 0,
        _ => {
            let sign = match rest.as_bytes()[0] {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let hm = rest[1..].replace(':', "");
            if hm.len() != 4 {
                return None;
            }
            let oh: i64 = hm[0..2].parse().ok()?;
            let om: i64 = hm[2..4].parse().ok()?;
            sign * (oh * 3600 + om * 60)
        }
    };
    Some(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se - offset)
}

/// Nombre de jours depuis le 1er janvier 1970 (calendrier grégorien proleptique).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso8601_variantes() {
        assert_eq!(parse_iso8601("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_iso8601("2024-02-29T12:00:00Z"), Some(1_709_208_000));
        assert_eq!(parse_iso8601("2024-02-29T12:00:00.123Z"), Some(1_709_208_000));
        assert_eq!(parse_iso8601("2024-02-29T14:00:00+02:00"), Some(1_709_208_000));
        assert_eq!(parse_iso8601("0001-01-01T00:00:00Z"), Some(-62_135_596_800));
        assert_eq!(parse_iso8601("pas une date"), None);
        assert_eq!(parse_iso8601("2024-13-01T00:00:00Z"), None);
    }

    #[test]
    fn codes_stables_et_debug_sans_secret() {
        assert_eq!(serde_json::to_value(ImportError::KdfOutOfBounds).unwrap(), "kdf_out_of_bounds");
        assert_eq!(ImportError::KeyfileRequired.to_string(), "keyfile_required");
        let mut r = ImportResult::default();
        let data = ItemData { name: "Banque".into(), password: "s3cret".into(), ..Default::default() };
        r.push_item(data, "Perso/Banque".into(), "id".into());
        let dbg = format!("{r:?} {:?}", r.items[0]);
        assert!(!dbg.contains("s3cret") && !dbg.contains("Banque"), "{dbg}");
        assert_eq!(r.folders, vec!["Perso/Banque".to_string()]);
    }

    #[test]
    fn nom_de_repli_et_avertissement() {
        let mut r = ImportResult::default();
        r.push_item(ItemData { urls: vec!["https://exemple.fr".into()], ..Default::default() }, String::new(), "a".into());
        r.push_item(ItemData::default(), String::new(), "b".into());
        assert_eq!(r.items[0].data.name, "https://exemple.fr");
        assert_eq!(r.warnings, vec![ImportWarning { code: warning::MISSING_TITLE, index: Some(1) }]);
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["warnings"][0], serde_json::json!({ "code": "missing_title", "index": 1 }));
        assert_eq!(json["items"][0]["folder"], "");
    }
}
