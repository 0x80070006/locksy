//! Contenu d'un élément du coffre. Cette structure est sérialisée en JSON
//! puis chiffrée : le serveur n'en voit jamais aucun champ.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const PASSWORD_HISTORY_MAX: usize = 20;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    #[default]
    Login,
    Note,
    Card,
    Identity,
    Ssh,
}

impl ItemKind {
    pub const ALL: [ItemKind; 5] = [ItemKind::Login, ItemKind::Note, ItemKind::Card, ItemKind::Identity, ItemKind::Ssh];

    pub fn label(self) -> &'static str {
        match self {
            ItemKind::Login => "Identifiant",
            ItemKind::Note => "Note sécurisée",
            ItemKind::Card => "Carte bancaire",
            ItemKind::Identity => "Identité",
            ItemKind::Ssh => "Clé SSH",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Zeroize)]
#[serde(default)]
pub struct CustomField {
    pub label: String,
    pub value: String,
    pub hidden: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Zeroize)]
#[serde(default)]
pub struct Card {
    pub holder: String,
    pub number: String,
    pub expiry: String,
    pub cvv: String,
    pub pin: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Zeroize)]
#[serde(default)]
pub struct Identity {
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub phone: String,
    pub address: String,
    pub company: String,
    pub document_number: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Zeroize)]
#[serde(default)]
pub struct SshKey {
    pub private_key: String,
    pub public_key: String,
    pub passphrase: String,
}

/// Fichier joint : le contenu est chiffré à part avec `key`, clé aléatoire
/// qui n'existe qu'à l'intérieur de l'élément chiffré.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Zeroize)]
#[serde(default)]
pub struct Attachment {
    pub id: String,
    pub name: String,
    pub size: u64,
    pub mime: String,
    pub key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Zeroize)]
#[serde(default)]
pub struct PasswordHistoryEntry {
    pub password: String,
    pub changed_at: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Zeroize)]
#[serde(default)]
pub struct ItemData {
    #[zeroize(skip)]
    pub kind: ItemKind,
    pub name: String,
    pub favorite: bool,
    pub tags: Vec<String>,
    pub username: String,
    pub password: String,
    pub urls: Vec<String>,
    pub totp: String,
    pub notes: String,
    pub fields: Vec<CustomField>,
    pub card: Card,
    pub identity: Identity,
    pub ssh: SshKey,
    pub password_history: Vec<PasswordHistoryEntry>,
    pub attachments: Vec<Attachment>,
    pub password_changed_at: i64,
    /// Date de renouvellement choisie par l'utilisateur (0 = aucune).
    pub expires_at: i64,
}

impl ItemData {
    /// Applique un nouveau mot de passe en conservant l'ancien dans l'historique.
    pub fn set_password(&mut self, new_password: String, now: i64) {
        if new_password == self.password {
            return;
        }
        if !self.password.is_empty() {
            let old = std::mem::take(&mut self.password);
            self.password_history.insert(0, PasswordHistoryEntry { password: old, changed_at: now });
            self.password_history.truncate(PASSWORD_HISTORY_MAX);
        }
        self.password = new_password;
        self.password_changed_at = now;
    }

    pub fn subtitle(&self) -> String {
        match self.kind {
            ItemKind::Login => self.username.clone(),
            ItemKind::Card => {
                let digits: String = self.card.number.chars().filter(|c| c.is_ascii_digit()).collect();
                if digits.len() >= 4 {
                    format!("•••• {}", &digits[digits.len() - 4..])
                } else {
                    String::new()
                }
            }
            ItemKind::Identity => {
                format!("{} {}", self.identity.first_name, self.identity.last_name).trim().to_string()
            }
            ItemKind::Ssh => self.ssh.public_key.split_whitespace().last().unwrap_or_default().to_string(),
            ItemKind::Note => self.notes.lines().next().unwrap_or_default().chars().take(60).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_history_keeps_previous_values() {
        let mut item = ItemData::default();
        item.set_password("a".into(), 1);
        item.set_password("b".into(), 2);
        item.set_password("b".into(), 3);
        assert_eq!(item.password, "b");
        assert_eq!(item.password_history.len(), 1);
        assert_eq!(item.password_history[0].password, "a");
        assert_eq!(item.password_changed_at, 2);
    }

    #[test]
    fn unknown_fields_are_tolerated() {
        let item: ItemData = serde_json::from_str(r#"{"kind":"note","name":"x","futur":1}"#).unwrap();
        assert_eq!(item.kind, ItemKind::Note);
    }
}
