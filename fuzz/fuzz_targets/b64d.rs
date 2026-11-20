//! Décodage base64 URL : pas de panique, et aller-retour exact.
#![no_main]

use libfuzzer_sys::fuzz_target;
use locksy_core::encoding::{b64d, b64e};

fuzz_target!(|data: &[u8]| {
    // Encodage puis décodage : on retrouve les octets d'origine.
    assert_eq!(b64d(&b64e(data)).expect("aller-retour"), data);
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Ok(bytes) = b64d(s) {
        // Décodage réussi : le réencodage (forme canonique) se relit à l'identique.
        let again = b64e(&bytes);
        assert_eq!(b64d(&again).expect("réencodage"), bytes);
    }
});
