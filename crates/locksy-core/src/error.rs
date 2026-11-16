use std::fmt;

/// Erreurs du noyau. Les messages ne contiennent jamais de donnée secrète.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Texte encodé invalide (base64, base32…).
    Encoding,
    /// Format de chiffré inconnu ou tronqué.
    Format,
    /// Authentification du chiffré échouée : mauvaise clé ou donnée altérée.
    Decrypt,
    /// Paramètres de dérivation de clé refusés.
    Kdf(String),
    /// Clé de longueur ou de valeur invalide.
    InvalidKey,
    /// Entrée invalide fournie par l'appelant.
    InvalidInput(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Encoding => write!(f, "encodage invalide"),
            Error::Format => write!(f, "format de donnée chiffrée invalide"),
            Error::Decrypt => write!(f, "déchiffrement impossible : clé incorrecte ou donnée altérée"),
            Error::Kdf(m) => write!(f, "dérivation de clé refusée : {m}"),
            Error::InvalidKey => write!(f, "clé invalide"),
            Error::InvalidInput(m) => write!(f, "entrée invalide : {m}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
