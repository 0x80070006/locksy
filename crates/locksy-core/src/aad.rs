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

/// Document de préférences de l'utilisateur, chiffré avec sa clé (`/me/prefs`).
pub fn prefs(user_id: &str) -> String {
    format!("verrou:v1:prefs:{user_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Chaque contexte, calculé avec « {} » à la place de ses paramètres, et
    /// sa présence attendue dans `web/js/aad.js` (faux : propre au Rust,
    /// utilisé par le serveur ou par le module WebAssembly).
    fn contexts() -> Vec<(&'static str, String, bool)> {
        let p = "{}";
        vec![
            ("user_key", user_key(), true),
            ("recovery_user_key", recovery_user_key(), true),
            ("private_key", private_key(p), true),
            ("collection_name", collection_name(p), true),
            ("item", item(p, p), true),
            ("collection_key", collection_key(p, p), true),
            ("attachment", attachment(p), true),
            ("share", share(), true),
            ("export", export(), false),
            ("server_totp", server_totp(p), false),
            ("prefs", prefs(p), true),
        ]
    }

    /// Littéraux « verrou:v1:… » d'un source JavaScript, paramètres `${x}`
    /// ramenés à « {} ».
    fn js_literals(src: &str) -> Vec<String> {
        let mut out = Vec::new();
        for quote in ['"', '`'] {
            for part in src.split(quote).skip(1).step_by(2) {
                if !part.starts_with("verrou:v1:") {
                    continue;
                }
                let mut s = String::new();
                let mut rest = part;
                while let Some(i) = rest.find("${") {
                    s.push_str(&rest[..i]);
                    s.push_str("{}");
                    rest = rest[i..].split_once('}').map(|(_, r)| r).unwrap_or("");
                }
                s.push_str(rest);
                out.push(s);
            }
        }
        out
    }

    #[test]
    fn chaque_fonction_est_couverte() {
        let src = include_str!("aad.rs");
        let declared: Vec<&str> = src
            .lines()
            .filter_map(|l| l.strip_prefix("pub fn "))
            .filter_map(|l| l.split('(').next())
            .collect();
        let covered: Vec<&str> = contexts().iter().map(|(n, _, _)| *n).collect();
        assert_eq!(declared, covered);
    }

    #[test]
    fn identiques_au_client_javascript() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../web/js/aad.js");
        let Ok(js) = std::fs::read_to_string(&path) else {
            eprintln!("{} absent : test sauté", path.display());
            return;
        };
        let literals = js_literals(&js);
        for (name, rust, in_js) in contexts() {
            assert_eq!(literals.contains(&rust), in_js, "{name} : {rust} (aad.js : {literals:?})");
        }
        assert_eq!(prefs("u1"), "verrou:v1:prefs:u1");
    }
}
