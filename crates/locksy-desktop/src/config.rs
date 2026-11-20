//! Préférences de l'utilisateur et politique d'entreprise du poste.
//!
//! - Préférences non sensibles : `%APPDATA%\Locksy\bureau.json` (adresse du
//!   serveur, dernier e-mail, délais, paramètres KDF déjà vus).
//! - Politique machine, qui l'emporte : registre `HKLM\SOFTWARE\Policies\Locksy`
//!   (GPO ou Intune), puis `C:\ProgramData\Locksy\bureau.json`.
//!
//! Les deux restent séparées : une valeur imposée n'est jamais recopiée dans
//! le fichier de l'utilisateur, et l'interface lit toujours les valeurs
//! effectives (`effective_*`), qui appliquent la politique.

use crate::client::validate_server_url;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Serveur proposé par défaut (installation de démonstration sur ce poste).
pub const DEFAULT_SERVER: &str = "http://localhost:8743";

/// Paramètres KDF les plus forts déjà vus pour un compte (anti-rétrogradation).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(default)]
pub struct KdfPin {
    pub m_kib: u32,
    pub t: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct Config {
    pub server_url: String,
    pub last_email: String,
    /// Verrouillage après inactivité, en minutes (0 = jamais).
    pub auto_lock_minutes: u64,
    /// Effacement du presse-papiers, en secondes (0 = jamais).
    pub clipboard_seconds: u64,
    /// Verrouillage quand la fenêtre reste en arrière-plan, en minutes (0 = jamais).
    pub lock_on_focus_loss_minutes: u64,
    /// Paramètres KDF épinglés, par e-mail normalisé.
    pub kdf_pins: BTreeMap<String, KdfPin>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_url: DEFAULT_SERVER.into(),
            last_email: String::new(),
            auto_lock_minutes: 10,
            clipboard_seconds: 30,
            lock_on_focus_loss_minutes: 5,
            kdf_pins: BTreeMap::new(),
        }
    }
}

/// Valeur brute lue dans la politique (registre ou fichier machine).
#[derive(Clone, Debug, PartialEq)]
pub enum PolicyValue {
    Str(String),
    Num(u64),
}

/// Réglages imposés par l'organisation sur ce poste.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Policy {
    /// Adresse du serveur : le champ n'est plus modifiable.
    pub server_url: Option<String>,
    /// Délai de verrouillage maximal (1-1440 min) ; « jamais » est interdit.
    pub max_auto_lock_minutes: Option<u64>,
    /// Délai maximal d'effacement du presse-papiers (5-600 s) ; ne peut être ni désactivé ni allongé.
    pub clipboard_seconds: Option<u64>,
    /// Verrouillage en arrière-plan (0-1440 min) : maximum imposé, ou 0 pour le désactiver.
    pub lock_on_focus_loss_minutes: Option<u64>,
}

/// Noms des valeurs de registre et clés équivalentes du fichier machine.
const POLICY_KEYS: [(&str, &str); 4] = [
    ("ServerUrl", "server_url"),
    ("MaxAutoLockMinutes", "max_auto_lock_minutes"),
    ("ClipboardSeconds", "clipboard_seconds"),
    ("LockOnFocusLossMinutes", "lock_on_focus_loss_minutes"),
];

fn policy_num(name: &str, v: Option<PolicyValue>, range: std::ops::RangeInclusive<u64>) -> Option<u64> {
    let n = match v? {
        PolicyValue::Num(n) => Some(n),
        PolicyValue::Str(s) => s.trim().parse::<u64>().ok(),
    };
    match n {
        Some(n) if range.contains(&n) => Some(n),
        _ => {
            eprintln!("Politique Locksy : valeur {name} ignorée (attendu : {} à {}).", range.start(), range.end());
            None
        }
    }
}

impl Policy {
    /// Construit la politique à partir d'une fonction de lecture par nom de
    /// valeur (`ServerUrl`, `MaxAutoLockMinutes`, `ClipboardSeconds`,
    /// `LockOnFocusLossMinutes`). Les valeurs invalides ou hors bornes sont
    /// ignorées (avec un message sur la sortie d'erreur).
    pub fn from_lookup(get: impl Fn(&str) -> Option<PolicyValue>) -> Self {
        let server_url = match get("ServerUrl") {
            Some(PolicyValue::Str(s)) if s.trim().is_empty() => None,
            Some(PolicyValue::Str(s)) => match validate_server_url(&s) {
                Ok(url) => Some(url),
                Err(e) => {
                    eprintln!("Politique Locksy : ServerUrl ignorée ({e}).");
                    None
                }
            },
            Some(PolicyValue::Num(_)) => {
                eprintln!("Politique Locksy : ServerUrl ignorée (texte attendu).");
                None
            }
            None => None,
        };
        Self {
            server_url,
            max_auto_lock_minutes: policy_num("MaxAutoLockMinutes", get("MaxAutoLockMinutes"), 1..=1440),
            clipboard_seconds: policy_num("ClipboardSeconds", get("ClipboardSeconds"), 5..=600),
            lock_on_focus_loss_minutes: policy_num("LockOnFocusLossMinutes", get("LockOnFocusLossMinutes"), 0..=1440),
        }
    }

    /// Politique tirée d'un fichier machine `bureau.json` (clés en minuscules).
    pub fn from_json(text: &str) -> Self {
        let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(text) else {
            eprintln!("Politique Locksy : fichier machine illisible, ignoré.");
            return Self::default();
        };
        Self::from_lookup(|name| {
            let key = POLICY_KEYS.iter().find(|(reg, _)| *reg == name).map(|(_, k)| *k)?;
            match map.get(key)? {
                serde_json::Value::String(s) => Some(PolicyValue::Str(s.clone())),
                serde_json::Value::Number(n) => n.as_u64().map(PolicyValue::Num).or(Some(PolicyValue::Str(n.to_string()))),
                serde_json::Value::Null => None,
                other => Some(PolicyValue::Str(other.to_string())),
            }
        })
    }

    /// Fusion champ par champ : `self` (registre) l'emporte sur `other` (fichier machine).
    pub fn or(self, other: Policy) -> Policy {
        Policy {
            server_url: self.server_url.or(other.server_url),
            max_auto_lock_minutes: self.max_auto_lock_minutes.or(other.max_auto_lock_minutes),
            clipboard_seconds: self.clipboard_seconds.or(other.clipboard_seconds),
            lock_on_focus_loss_minutes: self.lock_on_focus_loss_minutes.or(other.lock_on_focus_loss_minutes),
        }
    }

    /// Politique du poste : HKLM, puis `C:\ProgramData\Locksy\bureau.json`.
    pub fn load() -> Self {
        let file = machine_path().and_then(|p| std::fs::read_to_string(p).ok()).map(|s| Self::from_json(&s)).unwrap_or_default();
        registry_policy().or(file)
    }
}

#[cfg(windows)]
fn registry_policy() -> Policy {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey("SOFTWARE\\Policies\\Locksy") else {
        return Policy::default();
    };
    Policy::from_lookup(|name| {
        if let Ok(s) = key.get_value::<String, _>(name) {
            return Some(PolicyValue::Str(s));
        }
        if let Ok(n) = key.get_value::<u32, _>(name) {
            return Some(PolicyValue::Num(u64::from(n)));
        }
        key.get_value::<u64, _>(name).ok().map(PolicyValue::Num)
    })
}

#[cfg(not(windows))]
fn registry_policy() -> Policy {
    Policy::default()
}

fn path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("Locksy").join("bureau.json"))
}

/// Configuration commune au poste, déposée par GPO ou par install-client.ps1 :
/// `C:\ProgramData\Locksy\bureau.json`, par exemple
/// `{ "server_url": "https://locksy.corp.local", "max_auto_lock_minutes": 15 }`.
fn machine_path() -> Option<PathBuf> {
    std::env::var_os("ProgramData").map(|d| PathBuf::from(d).join("Locksy").join("bureau.json"))
}

/// Normalise un e-mail pour l'épinglage KDF (minuscules, sans espaces).
pub fn pin_key(email: &str) -> String {
    email.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_lowercase()
}

/// Ajoute la valeur imposée à la liste des choix si elle n'y est pas, retire
/// ce qui la dépasse et « jamais » (0). Sans maximum, la liste est inchangée.
pub fn choices(base: &[u64], max: Option<u64>) -> Vec<u64> {
    let Some(max) = max else { return base.to_vec() };
    let mut out: Vec<u64> = base.iter().copied().filter(|v| *v != 0 && *v <= max).collect();
    if !out.contains(&max) {
        out.push(max);
    }
    out.sort_unstable();
    out
}

/// Applique un maximum imposé à une préférence où 0 signifie « jamais ».
fn bounded(user: u64, max: Option<u64>, hard_max: u64) -> u64 {
    let user = user.min(hard_max);
    match max {
        None => user,
        Some(m) if user == 0 => m,
        Some(m) => user.min(m),
    }
}

impl Config {
    pub fn load() -> Self {
        Self::from_json(path().and_then(|p| std::fs::read_to_string(p).ok()).as_deref())
    }

    /// Lecture tolérante : fichier absent ou illisible = valeurs par défaut ;
    /// clés absentes (anciens fichiers) = valeurs par défaut.
    pub fn from_json(text: Option<&str>) -> Self {
        text.and_then(|s| serde_json::from_str(s).ok()).unwrap_or_default()
    }

    /// Contenu écrit sur le disque : jamais une valeur imposée par la politique.
    pub fn to_json(&self, policy: &Policy) -> String {
        let mut value = serde_json::to_value(self).unwrap_or_default();
        if let (Some(imposed), Some(map)) = (&policy.server_url, value.as_object_mut()) {
            if self.server_url.trim().trim_end_matches('/') == imposed {
                map.remove("server_url");
            }
        }
        serde_json::to_string_pretty(&value).unwrap_or_default()
    }

    /// Écriture atomique (fichier temporaire puis renommage).
    pub fn save(&self, policy: &Policy) {
        if let Some(p) = path() {
            if let Err(e) = write_atomic(&p, &self.to_json(policy)) {
                eprintln!("Préférences Locksy non enregistrées : {e}");
            }
        }
    }

    /// Adresse du serveur à utiliser : celle de la politique si elle existe.
    pub fn effective_server(&self, policy: &Policy) -> String {
        match &policy.server_url {
            Some(url) => url.clone(),
            None if self.server_url.trim().is_empty() => DEFAULT_SERVER.into(),
            None => self.server_url.clone(),
        }
    }

    /// Verrouillage après inactivité (minutes, 0 = jamais, interdit sous politique).
    pub fn effective_auto_lock(&self, policy: &Policy) -> u64 {
        bounded(self.auto_lock_minutes, policy.max_auto_lock_minutes, 1440)
    }

    /// Effacement du presse-papiers (secondes, 0 = jamais, interdit sous politique).
    pub fn effective_clipboard(&self, policy: &Policy) -> u64 {
        bounded(self.clipboard_seconds, policy.clipboard_seconds, 600)
    }

    /// Verrouillage en arrière-plan (minutes, 0 = jamais).
    pub fn effective_focus_lock(&self, policy: &Policy) -> u64 {
        match policy.lock_on_focus_loss_minutes {
            Some(0) => 0,
            max => bounded(self.lock_on_focus_loss_minutes, max, 1440),
        }
    }

    pub fn kdf_pin(&self, email: &str) -> Option<KdfPin> {
        self.kdf_pins.get(&pin_key(email)).copied()
    }

    /// Retient le maximum vu pour ce compte (après une connexion réussie).
    pub fn update_kdf_pin(&mut self, email: &str, seen: KdfPin) {
        let pin = self.kdf_pins.entry(pin_key(email)).or_default();
        pin.m_kib = pin.m_kib.max(seen.m_kib);
        pin.t = pin.t.max(seen.t);
    }
}

fn write_atomic(path: &Path, content: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, content)?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup(pairs: &[(&str, PolicyValue)]) -> impl Fn(&str) -> Option<PolicyValue> {
        let map: HashMap<String, PolicyValue> = pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        move |name| map.get(name).cloned()
    }

    #[test]
    fn policy_bounds_and_invalid_values() {
        let p = Policy::from_lookup(lookup(&[
            ("ServerUrl", PolicyValue::Str("https://coffre.corp.fr/".into())),
            ("MaxAutoLockMinutes", PolicyValue::Num(15)),
            ("ClipboardSeconds", PolicyValue::Num(20)),
            ("LockOnFocusLossMinutes", PolicyValue::Num(0)),
        ]));
        assert_eq!(p.server_url.as_deref(), Some("https://coffre.corp.fr"));
        assert_eq!(p.max_auto_lock_minutes, Some(15));
        assert_eq!(p.clipboard_seconds, Some(20));
        assert_eq!(p.lock_on_focus_loss_minutes, Some(0));

        let bad = Policy::from_lookup(lookup(&[
            ("ServerUrl", PolicyValue::Str("http://coffre.corp.fr".into())),
            ("MaxAutoLockMinutes", PolicyValue::Num(0)),
            ("ClipboardSeconds", PolicyValue::Num(4)),
            ("LockOnFocusLossMinutes", PolicyValue::Num(1441)),
        ]));
        assert_eq!(bad, Policy::default(), "valeurs hors bornes ou HTTP distant ignorés");

        let edge = Policy::from_lookup(lookup(&[
            ("ServerUrl", PolicyValue::Num(3)),
            ("MaxAutoLockMinutes", PolicyValue::Num(1440)),
            ("ClipboardSeconds", PolicyValue::Str("600".into())),
            ("LockOnFocusLossMinutes", PolicyValue::Str("abc".into())),
        ]));
        assert_eq!(edge.server_url, None);
        assert_eq!(edge.max_auto_lock_minutes, Some(1440));
        assert_eq!(edge.clipboard_seconds, Some(600));
        assert_eq!(edge.lock_on_focus_loss_minutes, None);
        assert_eq!(Policy::from_lookup(|_| None), Policy::default());
    }

    #[test]
    fn registry_wins_over_machine_file() {
        let registry = Policy::from_lookup(lookup(&[("MaxAutoLockMinutes", PolicyValue::Num(5))]));
        let file = Policy::from_json(r#"{"server_url":"https://fichier.corp.fr","max_auto_lock_minutes":60,"clipboard_seconds":45}"#);
        let p = registry.or(file);
        assert_eq!(p.max_auto_lock_minutes, Some(5), "HKLM l'emporte");
        assert_eq!(p.server_url.as_deref(), Some("https://fichier.corp.fr"), "complété par le fichier machine");
        assert_eq!(p.clipboard_seconds, Some(45));
        assert_eq!(p.lock_on_focus_loss_minutes, None);
    }

    #[test]
    fn old_machine_file_is_still_understood() {
        // Ancien format : configuration complète déposée par GPO.
        let p = Policy::from_json(r#"{"server_url":"https://locksy.corp.local","last_email":"","auto_lock_minutes":10,"clipboard_seconds":30}"#);
        assert_eq!(p.server_url.as_deref(), Some("https://locksy.corp.local"));
        assert_eq!(p.clipboard_seconds, Some(30));
        assert_eq!(Policy::from_json("pas du json"), Policy::default());
        assert_eq!(Policy::from_json(r#"{"server_url":""}"#), Policy::default());
    }

    #[test]
    fn auto_lock_is_bounded_and_never_forbidden_under_policy() {
        let mut c = Config { auto_lock_minutes: 60, ..Default::default() };
        let free = Policy::default();
        let max = Policy { max_auto_lock_minutes: Some(15), ..Default::default() };
        assert_eq!(c.effective_auto_lock(&free), 60);
        assert_eq!(c.effective_auto_lock(&max), 15);
        c.auto_lock_minutes = 5;
        assert_eq!(c.effective_auto_lock(&max), 5);
        c.auto_lock_minutes = 0;
        assert_eq!(c.effective_auto_lock(&free), 0, "« jamais » permis sans politique");
        assert_eq!(c.effective_auto_lock(&max), 15, "« jamais » interdit sous politique");
    }

    #[test]
    fn clipboard_and_focus_lock() {
        let mut c = Config { clipboard_seconds: 120, ..Default::default() };
        let p = Policy { clipboard_seconds: Some(30), ..Default::default() };
        assert_eq!(c.effective_clipboard(&Policy::default()), 120);
        assert_eq!(c.effective_clipboard(&p), 30);
        c.clipboard_seconds = 0;
        assert_eq!(c.effective_clipboard(&p), 30, "désactivation interdite");
        c.clipboard_seconds = 15;
        assert_eq!(c.effective_clipboard(&p), 15);

        assert_eq!(c.effective_focus_lock(&Policy::default()), 5);
        let off = Policy { lock_on_focus_loss_minutes: Some(0), ..Default::default() };
        assert_eq!(c.effective_focus_lock(&off), 0);
        c.lock_on_focus_loss_minutes = 0;
        let max = Policy { lock_on_focus_loss_minutes: Some(2), ..Default::default() };
        assert_eq!(c.effective_focus_lock(&max), 2);
    }

    #[test]
    fn imposed_server_is_never_written() {
        let policy = Policy { server_url: Some("https://corp.fr".into()), clipboard_seconds: Some(10), ..Default::default() };
        let mine = Config { server_url: "https://perso.fr".into(), clipboard_seconds: 120, ..Default::default() };
        let json = mine.to_json(&policy);
        assert!(json.contains("https://perso.fr") && !json.contains("corp.fr"));
        assert!(json.contains("\"clipboard_seconds\": 120"), "préférence de l'utilisateur conservée telle quelle");
        assert_eq!(mine.effective_server(&policy), "https://corp.fr");

        let copied = Config { server_url: "https://corp.fr/".into(), ..Default::default() };
        let json = copied.to_json(&policy);
        assert!(!json.contains("corp.fr"), "valeur imposée retirée : {json}");
        assert_eq!(Config::from_json(Some(&json)).server_url, DEFAULT_SERVER);
    }

    #[test]
    fn old_user_file_gets_defaults() {
        let c = Config::from_json(Some(r#"{"server_url":"https://a.fr","last_email":"x@a.fr","auto_lock_minutes":30,"clipboard_seconds":60}"#));
        assert_eq!(c.server_url, "https://a.fr");
        assert_eq!(c.auto_lock_minutes, 30);
        assert_eq!(c.lock_on_focus_loss_minutes, 5);
        assert!(c.kdf_pins.is_empty());
        assert_eq!(Config::from_json(Some("{")), Config::default());
        assert_eq!(Config::from_json(None), Config::default());
    }

    #[test]
    fn choices_follow_policy() {
        assert_eq!(choices(&[1, 5, 10, 30, 60, 0], None), vec![1, 5, 10, 30, 60, 0]);
        assert_eq!(choices(&[1, 5, 10, 30, 60, 0], Some(15)), vec![1, 5, 10, 15]);
        assert_eq!(choices(&[15, 30, 60, 120, 0], Some(30)), vec![15, 30]);
        assert_eq!(choices(&[15, 30, 60, 120, 0], Some(5)), vec![5]);
    }

    #[test]
    fn kdf_pins_keep_the_maximum() {
        let mut c = Config::default();
        c.update_kdf_pin(" Jean@Corp.FR ", KdfPin { m_kib: 65536, t: 3 });
        c.update_kdf_pin("jean@corp.fr", KdfPin { m_kib: 19456, t: 4 });
        assert_eq!(c.kdf_pin("JEAN@corp.fr"), Some(KdfPin { m_kib: 65536, t: 4 }));
        assert_eq!(c.kdf_pin("autre@corp.fr"), None);
    }

    #[test]
    fn atomic_write_replaces_file() {
        let dir = std::env::temp_dir().join(format!("locksy-desktop-cfg-{}", std::process::id()));
        let p = dir.join("bureau.json");
        write_atomic(&p, "{\"a\":1}").unwrap();
        write_atomic(&p, "{\"a\":2}").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "{\"a\":2}");
        assert!(!p.with_extension("json.tmp").exists());
        let _ = std::fs::remove_dir_all(dir);
    }
}
