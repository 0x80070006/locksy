//! Générateur de mots de passe et de phrases de passe, tirage uniforme sans
//! biais (échantillonnage par rejet) sur le générateur aléatoire du système.

use crate::{Error, Result};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?/~";
const AMBIGUOUS: &str = "lIO01|`'\"";

const CONSONANTS: &[u8] = b"bdfgjklmnprstvz";
const VOWELS: &[u8] = b"aeiou";

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct PasswordOptions {
    pub length: usize,
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self { length: 20, lower: true, upper: true, digits: true, symbols: true, avoid_ambiguous: true }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct PassphraseOptions {
    pub words: usize,
    pub separator: String,
    pub capitalize: bool,
    pub include_number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self { words: 5, separator: "-".into(), capitalize: true, include_number: true }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Generated {
    pub value: String,
    pub entropy_bits: f64,
}

/// Entier uniforme dans `[0, n)`.
pub fn uniform(n: u32) -> u32 {
    assert!(n > 0, "intervalle vide");
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let v = OsRng.next_u32();
        if v < zone {
            return v % n;
        }
    }
}

fn pick(chars: &[char]) -> char {
    chars[uniform(chars.len() as u32) as usize]
}

fn filtered(set: &str, avoid_ambiguous: bool) -> Vec<char> {
    set.chars().filter(|c| !avoid_ambiguous || !AMBIGUOUS.contains(*c)).collect()
}

pub fn generate_password(opts: &PasswordOptions) -> Result<Generated> {
    if !(8..=128).contains(&opts.length) {
        return Err(Error::InvalidInput("longueur entre 8 et 128 caractères".into()));
    }
    let mut sets: Vec<Vec<char>> = Vec::new();
    if opts.lower {
        sets.push(filtered(LOWER, opts.avoid_ambiguous));
    }
    if opts.upper {
        sets.push(filtered(UPPER, opts.avoid_ambiguous));
    }
    if opts.digits {
        sets.push(filtered(DIGITS, opts.avoid_ambiguous));
    }
    if opts.symbols {
        sets.push(filtered(SYMBOLS, opts.avoid_ambiguous));
    }
    if sets.is_empty() {
        return Err(Error::InvalidInput("choisissez au moins un type de caractères".into()));
    }
    let all: Vec<char> = sets.iter().flatten().copied().collect();
    // Un caractère de chaque famille choisie, puis le reste dans l'ensemble.
    let mut out: Vec<char> = sets.iter().map(|s| pick(s)).collect();
    while out.len() < opts.length {
        out.push(pick(&all));
    }
    for i in (1..out.len()).rev() {
        let j = uniform(i as u32 + 1) as usize;
        out.swap(i, j);
    }
    Ok(Generated {
        value: out.into_iter().collect(),
        entropy_bits: opts.length as f64 * (all.len() as f64).log2(),
    })
}

fn pronounceable_word() -> String {
    let mut w = String::with_capacity(6);
    for _ in 0..3 {
        w.push(CONSONANTS[uniform(CONSONANTS.len() as u32) as usize] as char);
        w.push(VOWELS[uniform(VOWELS.len() as u32) as usize] as char);
    }
    w
}

/// Phrase de mots prononçables (3 syllabes par mot, ≈ 18,7 bits par mot).
pub fn generate_passphrase(opts: &PassphraseOptions) -> Result<Generated> {
    if !(3..=12).contains(&opts.words) {
        return Err(Error::InvalidInput("entre 3 et 12 mots".into()));
    }
    if opts.separator.chars().count() > 3 {
        return Err(Error::InvalidInput("séparateur de 3 caractères au plus".into()));
    }
    let mut words: Vec<String> = (0..opts.words).map(|_| pronounceable_word()).collect();
    if opts.capitalize {
        for w in &mut words {
            let mut c = w.chars();
            if let Some(f) = c.next() {
                *w = f.to_ascii_uppercase().to_string() + c.as_str();
            }
        }
    }
    let per_word = ((CONSONANTS.len() * VOWELS.len()) as f64).log2() * 3.0;
    let mut entropy = per_word * opts.words as f64;
    if opts.include_number {
        let idx = uniform(words.len() as u32) as usize;
        words[idx].push_str(&uniform(100).to_string());
        entropy += 100f64.log2();
    }
    Ok(Generated { value: words.join(&opts.separator), entropy_bits: entropy })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_respects_options() {
        let opts = PasswordOptions { length: 40, symbols: false, ..Default::default() };
        let g = generate_password(&opts).unwrap();
        assert_eq!(g.value.chars().count(), 40);
        assert!(g.value.chars().all(|c| c.is_ascii_alphanumeric()));
        assert!(g.value.chars().any(|c| c.is_ascii_digit()));
        assert!(!g.value.contains('0') && !g.value.contains('l'));
        assert!(g.entropy_bits > 200.0);
    }

    #[test]
    fn invalid_options_are_rejected() {
        let none = PasswordOptions { lower: false, upper: false, digits: false, symbols: false, ..Default::default() };
        assert!(generate_password(&none).is_err());
        assert!(generate_password(&PasswordOptions { length: 4, ..Default::default() }).is_err());
    }

    #[test]
    fn passphrase_shape() {
        let g = generate_passphrase(&PassphraseOptions::default()).unwrap();
        assert_eq!(g.value.split('-').count(), 5);
        assert!(g.entropy_bits > 90.0);
    }

    #[test]
    fn uniform_covers_range() {
        let mut seen = [false; 7];
        for _ in 0..1000 {
            seen[uniform(7) as usize] = true;
        }
        assert!(seen.iter().all(|s| *s));
    }
}
