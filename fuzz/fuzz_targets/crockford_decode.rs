//! Décodage base32 Crockford (clé de récupération) : pas de panique.
#![no_main]

use libfuzzer_sys::fuzz_target;
use locksy_core::encoding::{crockford_decode, crockford_encode};

fuzz_target!(|data: &[u8]| {
    // Aller-retour exact sur des octets quelconques.
    assert_eq!(crockford_decode(&crockford_encode(data)).expect("aller-retour"), data);
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Ok(bytes) = crockford_decode(s) {
        assert_eq!(crockford_decode(&crockford_encode(&bytes)).expect("réencodage"), bytes);
    }
});
