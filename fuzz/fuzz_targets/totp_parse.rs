//! Lecture d'un secret TOTP ou d'une URI otpauth:// : pas de panique, et un
//! secret accepté produit un code à la bonne longueur. Le code saisi est
//! aussi passé à la vérification du serveur.
#![no_main]

use libfuzzer_sys::fuzz_target;
use locksy_core::totp;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Ok(cfg) = totp::parse(s) {
        let code = totp::code_at(&cfg, 1_700_000_000);
        assert_eq!(code.len(), cfg.digits as usize);
        assert!(code.bytes().all(|c| c.is_ascii_digit()));
        assert!((1..=cfg.period).contains(&totp::seconds_remaining(&cfg, 1_700_000_000)));
    }
    let _ = totp::verify(b"12345678901234567890", s, 1_700_000_000, Some(56_666_665));
});
