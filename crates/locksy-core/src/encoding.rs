//! Encodages : base64 URL sans remplissage, base32 RFC 4648 (TOTP) et
//! base32 Crockford (clé de récupération, tolérante aux fautes de lecture).

use crate::{Error, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

const RFC4648: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub fn b64e(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn b64d(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.trim()).map_err(|_| Error::Encoding)
}

pub fn b64d_array<const N: usize>(s: &str) -> Result<[u8; N]> {
    let v = b64d(s)?;
    v.as_slice().try_into().map_err(|_| Error::Encoding)
}

fn b32_encode(data: &[u8], alphabet: &[u8; 32]) -> String {
    let mut out = String::with_capacity(data.len() * 8 / 5 + 1);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &b in data {
        buffer = (buffer << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(alphabet[((buffer >> bits) & 31) as usize] as char);
        }
        buffer &= (1u32 << bits) - 1;
    }
    if bits > 0 {
        out.push(alphabet[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn b32_decode_values(values: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(values.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &v in values {
        buffer = (buffer << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
        buffer &= (1u32 << bits) - 1;
    }
    out
}

/// Base32 RFC 4648 sans remplissage (secrets TOTP).
pub fn base32_encode(data: &[u8]) -> String {
    b32_encode(data, RFC4648)
}

/// Décode un secret base32 : ignore espaces, tirets et `=`, insensible à la casse.
pub fn base32_decode(s: &str) -> Result<Vec<u8>> {
    let mut values = Vec::with_capacity(s.len());
    for c in s.chars() {
        if c.is_whitespace() || c == '-' || c == '=' {
            continue;
        }
        let up = c.to_ascii_uppercase() as u8;
        let pos = RFC4648.iter().position(|&a| a == up).ok_or(Error::Encoding)?;
        values.push(pos as u8);
    }
    if values.is_empty() {
        return Err(Error::Encoding);
    }
    Ok(b32_decode_values(&values))
}

pub fn crockford_encode(data: &[u8]) -> String {
    b32_encode(data, CROCKFORD)
}

/// Décode du base32 Crockford : `O`→0, `I`/`L`→1, ignore espaces et tirets.
pub fn crockford_decode(s: &str) -> Result<Vec<u8>> {
    let mut values = Vec::with_capacity(s.len());
    for c in s.chars() {
        if c.is_whitespace() || c == '-' {
            continue;
        }
        let up = match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        } as u8;
        let pos = CROCKFORD.iter().position(|&a| a == up).ok_or(Error::Encoding)?;
        values.push(pos as u8);
    }
    Ok(b32_decode_values(&values))
}

/// Encodage pour URL (RFC 3986, caractères non réservés conservés).
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub fn percent_decode(s: &str) -> Result<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = bytes.get(i + 1..i + 3).ok_or(Error::Encoding)?;
                let hex = std::str::from_utf8(hex).map_err(|_| Error::Encoding)?;
                out.push(u8::from_str_radix(hex, 16).map_err(|_| Error::Encoding)?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| Error::Encoding)
}

pub fn hex_upper(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02X}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_roundtrip_rfc_vector() {
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32_decode("MZXW6YTBOI======").unwrap(), b"foobar");
        assert_eq!(base32_decode("mzxw 6ytb oi").unwrap(), b"foobar");
    }

    #[test]
    fn crockford_tolerates_confusable_letters() {
        let data = [0u8, 1, 2, 250, 255, 17, 42];
        let enc = crockford_encode(&data);
        let messy = enc.replace('0', "o").replace('1', "l").to_lowercase();
        assert_eq!(crockford_decode(&messy).unwrap(), data);
    }

    #[test]
    fn percent_roundtrip() {
        let s = "Société Générale:jean@exemple.fr";
        assert_eq!(percent_decode(&percent_encode(s)).unwrap(), s);
    }
}
