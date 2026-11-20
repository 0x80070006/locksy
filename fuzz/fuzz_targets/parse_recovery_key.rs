//! Lecture d'une clé de récupération saisie : pas de panique, et une clé
//! acceptée se reformate en une saisie qui redonne la même clé.
#![no_main]

use libfuzzer_sys::fuzz_target;
use locksy_core::crypto;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Ok(key) = crypto::parse_recovery_key(s) {
        let formatted = crypto::format_recovery_key(&key);
        assert_eq!(crypto::parse_recovery_key(&formatted).expect("reformatage").as_bytes(), key.as_bytes());
    }
});
