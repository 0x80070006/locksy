//! Ouverture d'un scellement `s1.` quelconque : ne doit jamais paniquer
//! (clé éphémère faible, chiffré tronqué, base64 invalide…).
#![no_main]

use libfuzzer_sys::fuzz_target;
use locksy_core::crypto::{self, SecretKey};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let private = SecretKey::from_bytes([0x66; 32]);
    let context = "verrou:v1:collection-key:fuzz:fuzz";
    let _ = crypto::is_well_formed_sealed(s);
    let _ = crypto::open(&private, s, context);
    let _ = crypto::open_key(&private, s, context);
});
