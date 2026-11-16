//! Données associées (AAD) et contextes de scellement.
//!
//! Chaque chiffré est lié à sa place : un serveur malveillant ne peut pas
//! déplacer un élément d'un coffre à un autre, ni échanger deux éléments,
//! sans que le déchiffrement échoue. Le client JavaScript utilise exactement
//! les mêmes chaînes (voir `web/js/aad.js`).

pub fn user_key() -> String {
    "verrou:v1:user-key".to_string()
}

pub fn recovery_user_key() -> String {
    "verrou:v1:recovery-user-key".to_string()
}

pub fn private_key(user_id: &str) -> String {
    format!("verrou:v1:private-key:{user_id}")
}

pub fn collection_name(collection_id: &str) -> String {
    format!("verrou:v1:collection-name:{collection_id}")
}

pub fn item(collection_id: &str, item_id: &str) -> String {
    format!("verrou:v1:item:{collection_id}:{item_id}")
}

/// Contexte du scellement d'une clé de coffre pour un membre.
pub fn collection_key(collection_id: &str, user_id: &str) -> String {
    format!("verrou:v1:collection-key:{collection_id}:{user_id}")
}

pub fn attachment(attachment_id: &str) -> String {
    format!("verrou:v1:attachment:{attachment_id}")
}

pub fn share() -> String {
    "verrou:v1:share".to_string()
}

pub fn export() -> String {
    "verrou:v1:export".to_string()
}

pub fn server_totp(user_id: &str) -> String {
    format!("verrou:v1:server-totp:{user_id}")
}
