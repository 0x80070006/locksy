//! Déchiffrement `v1.` d'une entrée quelconque : ne doit jamais paniquer
//! (préfixe absent, base64 invalide, chiffré tronqué, tag faux…).
#![no_main]

use libfuzzer_sys::fuzz_target;
use locksy_core::crypto::{self, SecretKey};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let key = SecretKey::from_bytes([0x42; 32]);
    let _ = crypto::is_well_formed_cipher(s, 1 << 20);
    let _ = crypto::decrypt(&key, s, b"verrou:v1:fuzz");
    let _ = crypto::decrypt_string(&key, s, "verrou:v1:fuzz");
    let _ = crypto::unwrap_key(&key, s, "verrou:v1:user-key");
});
