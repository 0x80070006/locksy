//! Noyau de Locksy : chiffrement, dérivation de clés, TOTP, générateur,
//! estimation de robustesse et modèle de données partagé entre le serveur,
//! l'interface web (via WebAssembly) et le client de bureau.
//!
//! Principe : le serveur ne voit jamais un secret en clair. Tout est chiffré
//! et déchiffré sur le poste de l'utilisateur (« zero-knowledge »).

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

pub mod aad;
pub mod admin_api;
pub mod api;
pub mod crypto;
pub mod encoding;
pub mod error;
pub mod generator;
pub mod import;
pub mod model;
pub mod settings;
pub mod strength;
pub mod totp;

pub use error::{Error, Result};

/// Heure Unix courante en secondes.
pub fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
