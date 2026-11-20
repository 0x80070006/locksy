//! Politique « mot de passe unique dans l'organisation »
//! (`passwords.unique_across_users`).
//!
//! Le serveur ne voit jamais un mot de passe d'élément. Pour détecter que deux
//! personnes utilisent le même, chaque poste envoie une EMPREINTE :
//! SHA-256(poivre + « \0 » + mot de passe), où le poivre est dérivé de la clé du
//! serveur (même valeur pour toute l'organisation, fournie aux comptes connectés
//! quand la politique est active). Le serveur ne stocke que cette empreinte, liée
//! à l'élément, et compare entre comptes différents.
//!
//! Limite assumée (voir SECURITE.md) : l'exploitant du serveur, qui détient le
//! poivre, pourrait tester des mots de passe courants contre ces empreintes. La
//! politique est donc désactivée par défaut et son activation est un choix de
//! l'organisation.

use crate::error::{ApiError, ApiResult, Json};
use crate::state::{AppState, AuthUser};
use axum::extract::State;
use hmac::{Hmac, Mac};
use locksy_core::crypto::SecretKey;
use locksy_core::encoding::b64e;
use locksy_core::now_unix;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Empreintes acceptées par appel (un import par lots de 500).
const MAX_ENTRIES: usize = 1000;
/// Appels tolérés par personne et par minute.
const PER_MIN: u32 = 120;

/// Poivre de l'organisation, dérivé de la clé du serveur.
fn pepper(server_key: &SecretKey) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(server_key.as_bytes()).expect("clé HMAC valide");
    mac.update(b"locksy:password-fingerprint:v1");
    b64e(&mac.finalize().into_bytes())
}

#[derive(Serialize)]
pub struct PepperOut {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pepper: Option<String>,
}

/// `GET /passwords/pepper` : la politique est-elle active, et avec quel poivre.
pub async fn pepper_info(State(state): State<AppState>, _user: AuthUser) -> ApiResult<Json<PepperOut>> {
    let enabled = state.effective().await?.bool("passwords.unique_across_users");
    Ok(Json(PepperOut { enabled, pepper: enabled.then(|| pepper(&state.server_key)) }))
}

#[derive(Deserialize)]
pub struct Entry {
    pub item_id: String,
    pub fp: String,
}

#[derive(Deserialize)]
pub struct ClaimIn {
    pub entries: Vec<Entry>,
    /// Simple vérification : rien n'est enregistré (proposition d'un mot de
    /// passe avant qu'il soit adopté).
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Serialize)]
pub struct ClaimOut {
    /// Éléments dont le mot de passe est déjà utilisé par un autre compte.
    pub conflicts: Vec<String>,
}

fn hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `POST /passwords/fingerprints` : enregistre l'empreinte de chaque élément et
/// renvoie ceux dont le mot de passe est déjà celui d'un élément d'un autre
/// compte (élément non supprimé). Politique inactive : rien n'est enregistré.
pub async fn claim(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<ClaimIn>,
) -> ApiResult<Json<ClaimOut>> {
    state.limiter.hit(&format!("pwfp:{}", user.id), state.host.rate.scaled(PER_MIN), 60)?;
    if req.entries.is_empty() || req.entries.len() > MAX_ENTRIES {
        return Err(ApiError::bad_request(format!("Entre 1 et {MAX_ENTRIES} empreintes par appel.")));
    }
    for e in &req.entries {
        crate::security::uuid(&e.item_id, "élément")?;
        if !hex64(&e.fp) {
            return Err(ApiError::bad_request("Empreinte invalide."));
        }
    }
    if !state.effective().await?.bool("passwords.unique_across_users") {
        return Ok(Json(ClaimOut { conflicts: Vec::new() }));
    }
    let out = state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let now = now_unix();
            let mut conflicts = Vec::new();
            for e in &req.entries {
                let fp = e.fp.to_ascii_lowercase();
                let clash: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM password_fingerprints f JOIN items i ON i.id = f.item_id
                      WHERE f.fp = ?1 AND f.user_id <> ?2 AND f.item_id <> ?3 AND i.deleted_at IS NULL)",
                    params![fp, user.id, e.item_id],
                    |r| r.get(0),
                )?;
                if clash {
                    conflicts.push(e.item_id.clone());
                    continue;
                }
                if req.dry_run {
                    continue;
                }
                tx.execute(
                    "INSERT INTO password_fingerprints (item_id, user_id, fp, updated_at) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(item_id) DO UPDATE SET user_id = excluded.user_id, fp = excluded.fp, updated_at = excluded.updated_at",
                    params![e.item_id, user.id, fp, now],
                )?;
            }
            tx.commit()?;
            Ok(conflicts)
        })
        .await?;
    Ok(Json(ClaimOut { conflicts: out }))
}
