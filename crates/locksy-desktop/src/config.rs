//! Préférences non sensibles, dans %APPDATA%\Locksy\bureau.json.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct Config {
    pub server_url: String,
    pub last_email: String,
    pub auto_lock_minutes: u64,
    pub clipboard_seconds: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_url: "http://localhost:8743".into(),
            last_email: String::new(),
            auto_lock_minutes: 10,
            clipboard_seconds: 30,
        }
    }
}

fn path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("Locksy").join("bureau.json"))
}

/// Configuration commune au poste, déposée par GPO :
/// `C:\ProgramData\Locksy\bureau.json`, par exemple `{ "server_url": "https://locksy.corp.local" }`.
fn machine_path() -> Option<PathBuf> {
    std::env::var_os("ProgramData").map(|d| PathBuf::from(d).join("Locksy").join("bureau.json"))
}

fn read(p: Option<PathBuf>) -> Option<Config> {
    p.and_then(|p| std::fs::read_to_string(p).ok()).and_then(|s| serde_json::from_str(&s).ok())
}

impl Config {
    pub fn load() -> Self {
        let machine = read(machine_path());
        match (read(path()), machine) {
            // Préférences de l'utilisateur ; l'adresse imposée par l'entreprise l'emporte si elle existe.
            (Some(mut user), Some(m)) if !m.server_url.is_empty() => {
                user.server_url = m.server_url;
                user
            }
            (Some(user), _) => user,
            (None, Some(m)) => m,
            (None, None) => Self::default(),
        }
    }

    pub fn save(&self) {
        if let Some(p) = path() {
            if let Some(dir) = p.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            if let Ok(json) = serde_json::to_string_pretty(self) {
                let _ = std::fs::write(p, json);
            }
        }
    }
}
