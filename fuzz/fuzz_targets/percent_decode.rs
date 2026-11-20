//! Décodage d'URL (%XX et +) : pas de panique, et aller-retour exact.
#![no_main]

use libfuzzer_sys::fuzz_target;
use locksy_core::encoding::{percent_decode, percent_encode};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    assert_eq!(percent_decode(&percent_encode(s)).expect("aller-retour"), s);
    let _ = percent_decode(s);
});
