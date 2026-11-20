//! Codes à usage unique TOTP (RFC 6238) : génération pour les éléments du
//! coffre et vérification pour la double authentification du serveur.

use crate::encoding::{base32_decode, base32_encode, percent_decode, percent_encode};
use crate::{crypto::random_array, Error, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone, Debug)]
pub struct TotpConfig {
    pub secret: Zeroizing<Vec<u8>>,
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub period: u64,
    pub issuer: Option<String>,
    pub account: Option<String>,
}

/// Accepte un secret base32 brut ou une URI `otpauth://totp/...`.
pub fn parse(input: &str) -> Result<TotpConfig> {
    let input = input.trim();
    if input.is_empty() {
        return Err(Error::InvalidInput("secret TOTP vide".into()));
    }
    if let Some(rest) = input.strip_prefix("otpauth://") {
        let rest_lower = rest.to_ascii_lowercase();
        if !rest_lower.starts_with("totp/") {
            return Err(Error::InvalidInput("seuls les codes TOTP sont pris en charge".into()));
        }
        let rest = &rest[5..];
        let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
        let label = percent_decode(label)?;
        let (mut issuer, account) = match label.split_once(':') {
            Some((i, a)) => (Some(i.trim().to_string()), Some(a.trim().to_string())),
            None => (None, Some(label.trim().to_string())),
        };
        let mut secret = None;
        let mut algorithm = TotpAlgorithm::Sha1;
        let mut digits = 6;
        let mut period = 30;
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let v = percent_decode(v)?;
            match k.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(Zeroizing::new(base32_decode(&v)?)),
                "issuer" => issuer = Some(v),
                "algorithm" => {
                    algorithm = match v.to_ascii_uppercase().as_str() {
                        "SHA1" => TotpAlgorithm::Sha1,
                        "SHA256" => TotpAlgorithm::Sha256,
                        "SHA512" => TotpAlgorithm::Sha512,
                        _ => return Err(Error::InvalidInput("algorithme TOTP inconnu".into())),
                    }
                }
                "digits" => digits = v.parse().map_err(|_| Error::InvalidInput("nombre de chiffres invalide".into()))?,
                "period" => period = v.parse().map_err(|_| Error::InvalidInput("période invalide".into()))?,
                _ => {}
            }
        }
        let secret = secret.ok_or_else(|| Error::InvalidInput("l'URI ne contient pas de secret".into()))?;
        let cfg = TotpConfig { secret, algorithm, digits, period, issuer, account };
        validate(&cfg)?;
        return Ok(cfg);
    }
    let cfg = TotpConfig {
        secret: Zeroizing::new(base32_decode(input).map_err(|_| Error::InvalidInput("secret TOTP non base32".into()))?),
        algorithm: TotpAlgorithm::Sha1,
        digits: 6,
        period: 30,
        issuer: None,
        account: None,
    };
    validate(&cfg)?;
    Ok(cfg)
}

fn validate(cfg: &TotpConfig) -> Result<()> {
    if cfg.secret.len() < 5 {
        return Err(Error::InvalidInput("secret TOTP trop court".into()));
    }
    if !(6..=8).contains(&cfg.digits) {
        return Err(Error::InvalidInput("6 à 8 chiffres attendus".into()));
    }
    if !(1..=300).contains(&cfg.period) {
        return Err(Error::InvalidInput("période hors bornes".into()));
    }
    Ok(())
}

fn hmac_digest(alg: TotpAlgorithm, key: &[u8], msg: &[u8]) -> Vec<u8> {
    macro_rules! run {
        ($h:ty) => {{
            let mut m = <Hmac<$h> as Mac>::new_from_slice(key).expect("HMAC accepte toute longueur de clé");
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }};
    }
    match alg {
        TotpAlgorithm::Sha1 => run!(sha1::Sha1),
        TotpAlgorithm::Sha256 => run!(sha2::Sha256),
        TotpAlgorithm::Sha512 => run!(sha2::Sha512),
    }
}

fn hotp(secret: &[u8], counter: u64, alg: TotpAlgorithm, digits: u32) -> u32 {
    let d = hmac_digest(alg, secret, &counter.to_be_bytes());
    let offset = (d[d.len() - 1] & 0x0f) as usize;
    let bin = ((d[offset] as u32 & 0x7f) << 24)
        | ((d[offset + 1] as u32) << 16)
        | ((d[offset + 2] as u32) << 8)
        | d[offset + 3] as u32;
    bin % 10u32.pow(digits)
}

pub fn code_at(cfg: &TotpConfig, unix: u64) -> String {
    let v = hotp(&cfg.secret, unix / cfg.period, cfg.algorithm, cfg.digits);
    format!("{v:0width$}", width = cfg.digits as usize)
}

pub fn seconds_remaining(cfg: &TotpConfig, unix: u64) -> u64 {
    cfg.period - unix % cfg.period
}

/// Vérifie un code serveur (SHA-1, 6 chiffres, 30 s) avec une tolérance d'un
/// pas. Renvoie le pas accepté, qui doit être strictement supérieur au
/// dernier pas utilisé : un même code ne sert jamais deux fois.
pub fn verify(secret: &[u8], code: &str, unix: u64, last_step: Option<u64>) -> Option<u64> {
    let code = code.trim().replace(' ', "");
    if code.len() != 6 || !code.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let now_step = unix / 30;
    let mut matched = None;
    for step in [now_step.saturating_sub(1), now_step, now_step + 1] {
        let expected = format!("{:06}", hotp(secret, step, TotpAlgorithm::Sha1, 6));
        let ok: bool = expected.as_bytes().ct_eq(code.as_bytes()).into();
        if ok && last_step.is_none_or(|l| step > l) {
            matched = Some(step);
        }
    }
    matched
}

/// Secret de 160 bits pour l'application d'authentification de l'utilisateur.
pub fn generate_secret() -> String {
    base32_encode(&random_array::<20>())
}

pub fn provisioning_uri(secret_b32: &str, account: &str, issuer: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        percent_encode(issuer),
        percent_encode(account),
        secret_b32,
        percent_encode(issuer)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vecteurs de la RFC 6238, annexe B.
    #[test]
    fn rfc6238_vectors() {
        let sha1 = TotpConfig {
            secret: Zeroizing::new(b"12345678901234567890".to_vec()),
            algorithm: TotpAlgorithm::Sha1,
            digits: 8,
            period: 30,
            issuer: None,
            account: None,
        };
        assert_eq!(code_at(&sha1, 59), "94287082");
        assert_eq!(code_at(&sha1, 1111111109), "07081804");
        let sha256 = TotpConfig {
            secret: Zeroizing::new(b"12345678901234567890123456789012".to_vec()),
            algorithm: TotpAlgorithm::Sha256,
            ..sha1.clone()
        };
        assert_eq!(code_at(&sha256, 59), "46119246");
        let sha512 = TotpConfig {
            secret: Zeroizing::new(b"1234567890123456789012345678901234567890123456789012345678901234".to_vec()),
            algorithm: TotpAlgorithm::Sha512,
            ..sha1
        };
        assert_eq!(code_at(&sha512, 59), "90693936");
    }

    #[test]
    fn parses_otpauth_uri() {
        let cfg = parse("otpauth://totp/Exemple%20SA:jean%40exemple.fr?secret=JBSWY3DPEHPK3PXP&digits=8&period=60&algorithm=SHA256").unwrap();
        assert_eq!(cfg.digits, 8);
        assert_eq!(cfg.period, 60);
        assert_eq!(cfg.algorithm, TotpAlgorithm::Sha256);
        assert_eq!(cfg.issuer.as_deref(), Some("Exemple SA"));
        assert_eq!(cfg.account.as_deref(), Some("jean@exemple.fr"));
        assert!(parse("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP").is_err());
    }

    #[test]
    fn verify_rejects_replay() {
        let secret = b"12345678901234567890";
        let t = 1_700_000_000u64;
        let code = format!("{:06}", hotp(secret, t / 30, TotpAlgorithm::Sha1, 6));
        let step = verify(secret, &code, t, None).unwrap();
        assert_eq!(verify(secret, &code, t, Some(step)), None);
        assert_eq!(verify(secret, "000000x", t, None), None);
    }
}
