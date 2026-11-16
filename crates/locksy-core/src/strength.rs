//! Estimation de la robustesse d'un mot de passe. Heuristique prudente :
//! on part de l'entropie brute et on retire ce qu'un attaquant devine vite
//! (mots courants, suites, répétitions, années, claviers).

use serde::{Deserialize, Serialize};

const COMMON: &[&str] = &[
    "123456", "123456789", "12345678", "password", "motdepasse", "azerty", "qwerty", "azertyuiop",
    "111111", "123123", "000000", "1234567890", "abc123", "password1", "admin", "administrateur",
    "iloveyou", "soleil", "bonjour", "doudou", "chouchou", "loulou", "marseille", "football",
    "jetaime", "nicolas", "camille", "princesse", "dragon", "monkey", "letmein", "welcome",
    "sunshine", "master", "superman", "batman", "trustno1", "qwertyuiop", "654321", "121212",
    "666666", "secret", "changeme", "passw0rd", "p@ssw0rd", "motdepasse1", "bienvenue", "toto",
    "test", "root", "user", "guest", "france", "paris", "chocolat", "1q2w3e4r", "zaq12wsx",
];

const WORDS: &[&str] = &[
    "password", "passe", "motdepasse", "admin", "azerty", "qwerty", "soleil", "bonjour", "amour",
    "secret", "login", "welcome", "bienvenue", "france", "paris", "summer", "winter", "hiver",
    "printemps", "automne", "janvier", "fevrier", "mars", "avril", "juillet", "decembre", "lundi",
    "dragon", "football", "master", "monkey", "shadow", "princesse", "chocolat", "chat", "chien",
];

const SEQUENCES: &[&str] = &[
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "azertyuiopqsdfghjklmwxcvbn",
    "qwertyuiopasdfghjklzxcvbnm",
];

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Strength {
    /// 0 (très faible) à 4 (excellent).
    pub score: u8,
    pub entropy_bits: f64,
    pub label: String,
    pub warnings: Vec<String>,
}

fn charset_size(pw: &str) -> f64 {
    let mut size = 0.0;
    if pw.chars().any(|c| c.is_ascii_lowercase()) {
        size += 26.0;
    }
    if pw.chars().any(|c| c.is_ascii_uppercase()) {
        size += 26.0;
    }
    if pw.chars().any(|c| c.is_ascii_digit()) {
        size += 10.0;
    }
    if pw.chars().any(|c| c.is_ascii_punctuation() || c == ' ') {
        size += 33.0;
    }
    if pw.chars().any(|c| !c.is_ascii()) {
        size += 60.0;
    }
    size
}

/// Longueur des portions faciles à deviner (suites et répétitions de 3+).
fn predictable_runs(lower: &[char]) -> usize {
    let mut predictable = 0;
    let mut i = 0;
    while i + 2 < lower.len() {
        let mut j = i + 1;
        while j < lower.len() && lower[j] == lower[i] {
            j += 1;
        }
        if j - i >= 3 {
            predictable += j - i - 1;
            i = j;
            continue;
        }
        let mut k = i;
        'outer: for seq in SEQUENCES {
            let seq: Vec<char> = seq.chars().collect();
            for dir in [1i32, -1] {
                let mut len = 1;
                while i + len < lower.len() {
                    let a = seq.iter().position(|c| *c == lower[i + len - 1]);
                    let b = seq.iter().position(|c| *c == lower[i + len]);
                    match (a, b) {
                        (Some(a), Some(b)) if b as i32 - a as i32 == dir => len += 1,
                        _ => break,
                    }
                }
                if len >= 3 {
                    k = i + len;
                    break 'outer;
                }
            }
        }
        if k > i {
            predictable += k - i - 1;
            i = k;
        } else {
            i += 1;
        }
    }
    predictable
}

pub fn estimate(password: &str) -> Strength {
    let mut warnings = Vec::new();
    let chars: Vec<char> = password.chars().collect();
    if chars.is_empty() {
        return Strength { score: 0, entropy_bits: 0.0, label: "Vide".into(), warnings };
    }
    let lower: String = password.to_lowercase();
    let deleet: String = lower
        .chars()
        .map(|c| match c {
            '@' | '4' => 'a',
            '3' => 'e',
            '1' | '!' => 'i',
            '0' => 'o',
            '$' | '5' => 's',
            '7' => 't',
            c => c,
        })
        .collect();
    if COMMON.contains(&lower.as_str()) || COMMON.contains(&deleet.as_str()) {
        warnings.push("Ce mot de passe figure parmi les plus utilisés au monde.".into());
        return Strength { score: 0, entropy_bits: 5.0, label: "Très faible".into(), warnings };
    }

    let cs = charset_size(password).max(1.0);
    let mut effective_len = chars.len() as f64;

    for w in WORDS {
        if deleet.contains(w) {
            effective_len -= w.chars().count() as f64 - 1.5;
            warnings.push(format!("Contient un mot courant ({w})."));
        }
    }
    let lower_chars: Vec<char> = lower.chars().collect();
    let runs = predictable_runs(&lower_chars);
    if runs > 0 {
        effective_len -= runs as f64;
        warnings.push("Contient des suites ou des répétitions (abc, 123, aaa, azerty…).".into());
    }
    let has_year = lower_chars.windows(4).any(|w| {
        let s: String = w.iter().collect();
        s.parse::<u32>().map(|y| (1900..=2099).contains(&y)).unwrap_or(false)
    });
    if has_year {
        effective_len -= 2.0;
        warnings.push("Contient une année, facile à deviner.".into());
    }
    if password.chars().all(|c| c.is_ascii_digit()) {
        warnings.push("Uniquement des chiffres.".into());
    }
    if chars.len() < 12 {
        warnings.push("Moins de 12 caractères.".into());
    }

    let entropy = (effective_len.max(1.0) * cs.log2()).max(0.0);
    let score = match entropy {
        e if e < 28.0 => 0,
        e if e < 40.0 => 1,
        e if e < 60.0 => 2,
        e if e < 80.0 => 3,
        _ => 4,
    };
    let label = ["Très faible", "Faible", "Moyen", "Fort", "Excellent"][score as usize].to_string();
    Strength { score, entropy_bits: (entropy * 10.0).round() / 10.0, label, warnings }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_passwords_score_zero() {
        assert_eq!(estimate("azerty").score, 0);
        assert_eq!(estimate("P@ssw0rd").score, 0);
    }

    #[test]
    fn patterns_lower_the_score() {
        assert!(estimate("Soleil2024!").score <= 2);
        assert!(estimate("abcdefgh123").score <= 1);
    }

    #[test]
    fn random_long_passwords_score_high() {
        assert_eq!(estimate("q7#Vt9$kLm2!Xz8@Rw4p").score, 4);
        assert!(estimate("Bakotu-Rimesa-Lodivu-Zepaga-Nufore42").score >= 4);
    }
}
