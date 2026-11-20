//! Pièces jointes chiffrées. Chaque fichier est chiffré dans le navigateur
//! avec une clé aléatoire, elle-même rangée dans l'élément chiffré : le serveur
//! ne voit ni le nom, ni le type, ni le contenu. L'accès suit l'élément :
//! seuls les membres de son coffre peuvent télécharger le fichier.
//!
//! Politique (registre) : `attachment.enabled`, `attachment.max_file_mib`
//! (borné par l'hébergeur), `attachment.max_per_item`, et les quotas
//! `attachment.quota_user_mib` et `attachment.quota_total_mib`. Les quotas
//! portent sur la taille stockée (chiffré encodé en base64) ; la taille
//! maximale d'un fichier porte sur sa taille claire, déduite exactement de la
//! longueur du chiffré.

use crate::db;
use crate::error::{ApiError, ApiResult};
use crate::security as sec;
use crate::state::{audit_user, AppState, AuthUser};
use crate::vault::{personal_disabled, require_role, Missing, ANY, WRITE};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use crate::error::Json;
use locksy_core::crypto::CIPHER_PREFIX;
use locksy_core::now_unix;
use locksy_core::settings::Effective;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

/// Clé des anciens quotas dans la table settings (miroir lu par l'ancien
/// écran d'administration ; l'application passe par le registre).
pub const QUOTAS_KEY: &str = "attachments";

/// Nonce (24 octets) et étiquette (16 octets) ajoutés par le chiffrement.
const CIPHER_OVERHEAD: i64 = 24 + 16;

const MIB: i64 = 1_048_576;

/// Plafond absolu d'une pièce jointe fixé par l'hébergeur
/// (`LOCKSY_MAX_ATTACHMENT_MIB`, borné à 15 Mio par config.rs).
const HOST_MAX_ATTACHMENT_MIB: i64 = 15;

/// Taille maximale du corps de PUT /items/:item_id/attachments/:id : de quoi
/// porter le chiffré d'un fichier au plafond absolu (base64 + enveloppe
/// JSON), et jamais moins que la limite générale `max_body` (octets). Sans
/// elle, un fichier permis par le réglage serait coupé par axum avec un 413
/// en texte brut au lieu du code `attachment_too_large`.
pub(crate) fn upload_body_limit(max_body: usize) -> usize {
    cipher_len_for(HOST_MAX_ATTACHMENT_MIB * MIB).saturating_add(1024).max(max_body)
}

/// Quotas de pièces jointes. Les champs absents d'un réglage enregistré
/// prennent leur valeur par défaut.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(default)]
pub struct AttachmentQuotas {
    /// Espace maximal par utilisateur (Mo, pièces jointes qu'il a ajoutées).
    pub per_user_mb: i64,
    /// Espace maximal pour toute l'organisation (Mo).
    pub total_mb: i64,
    /// Nombre maximal de pièces jointes par élément.
    pub max_per_item: i64,
}

impl Default for AttachmentQuotas {
    fn default() -> Self {
        Self { per_user_mb: 1024, total_mb: 20_480, max_per_item: 20 }
    }
}

pub fn load_quotas(c: &Connection) -> ApiResult<AttachmentQuotas> {
    db::load_json(c, QUOTAS_KEY)
}

/// Octets convertis en Mo, arrondis au supérieur (un octet compte pour 1 Mo).
pub fn to_mb(bytes: i64) -> i64 {
    (bytes.max(0) + MIB - 1) / MIB
}

/// Espace occupé par toutes les pièces jointes de l'organisation (octets).
pub fn used_total(c: &Connection) -> ApiResult<i64> {
    Ok(c.query_row("SELECT COALESCE(SUM(size), 0) FROM attachments", [], |r| r.get(0))?)
}

fn used_by(c: &Connection, user_id: &str) -> ApiResult<i64> {
    Ok(c.query_row("SELECT COALESCE(SUM(size), 0) FROM attachments WHERE created_by = ?1", [user_id], |r| r.get(0))?)
}

/// Quotas appliqués, lus dans le registre.
fn quotas(eff: &Effective) -> AttachmentQuotas {
    AttachmentQuotas {
        per_user_mb: eff.int("attachment.quota_user_mib"),
        total_mb: eff.int("attachment.quota_total_mib"),
        max_per_item: eff.int("attachment.max_per_item"),
    }
}

/// Taille maximale d'un fichier en octets : réglage de l'organisation, borné
/// par le plafond de l'hébergeur (`LOCKSY_MAX_ATTACHMENT_MIB`).
fn max_file_bytes(eff: &Effective) -> i64 {
    let key = "attachment.max_file_mib";
    let mib = eff.int(key).min(eff.bounds(key).1.unwrap_or(i64::MAX)).max(1);
    mib.saturating_mul(MIB)
}

/// Longueur maximale du chiffré d'un fichier de `bytes` octets
/// (`v1.` + base64 URL sans bourrage du nonce, du contenu et de l'étiquette).
fn cipher_len_for(bytes: i64) -> usize {
    let raw = bytes.max(0) + CIPHER_OVERHEAD;
    let encoded = (raw * 4 + 2) / 3;
    usize::try_from(encoded).unwrap_or(usize::MAX).saturating_add(CIPHER_PREFIX.len())
}

/// Taille claire d'un chiffré bien formé (exacte : base64 sans bourrage).
fn plain_len(cipher: &str) -> i64 {
    let body = cipher.len().saturating_sub(CIPHER_PREFIX.len()) as i64;
    (body * 3 / 4 - CIPHER_OVERHEAD).max(0)
}

fn too_large(max_bytes: i64) -> ApiError {
    ApiError::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        "attachment_too_large",
        format!("Ce fichier est trop volumineux : {} Mo au plus par pièce jointe.", max_bytes / MIB),
    )
}

/// Vérifie qu'ajouter `add` octets respecte les quotas (0 : illimité).
/// Atteindre exactement la limite est permis ; la dépasser renvoie 413
/// `quota_exceeded`.
fn check_quota(used_user: i64, used_total: i64, add: i64, q: &AttachmentQuotas) -> ApiResult<()> {
    let exceeded = |used: i64, max_mb: i64| max_mb > 0 && used.saturating_add(add) > max_mb.saturating_mul(MIB);
    if exceeded(used_user, q.per_user_mb) {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "quota_exceeded",
            format!("Quota personnel de pièces jointes atteint : {} Mo utilisés sur {} Mo.", to_mb(used_user), q.per_user_mb),
        ));
    }
    if exceeded(used_total, q.total_mb) {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "quota_exceeded",
            format!(
                "Espace de stockage des pièces jointes de l'organisation plein ({} Mo sur {} Mo). Contactez un administrateur.",
                to_mb(used_total),
                q.total_mb
            ),
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct UploadRequest {
    pub data: String,
    /// Taille claire annoncée par le client (facultative) : refus immédiat
    /// si elle dépasse la limite, et elle doit égaler la taille réelle.
    #[serde(default)]
    pub size: Option<i64>,
}

#[derive(Serialize)]
pub struct DownloadResponse {
    pub data: String,
}

fn item_collection(c: &Connection, item_id: &str) -> ApiResult<String> {
    c.query_row("SELECT collection_id FROM items WHERE id = ?1", [item_id], |r| r.get(0))
        .optional()?
        .ok_or_else(|| Missing::Item.error())
}

fn attachment_collection(c: &Connection, id: &str) -> ApiResult<(String, String)> {
    c.query_row(
        "SELECT a.item_id, i.collection_id FROM attachments a JOIN items i ON i.id = a.item_id WHERE a.id = ?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()?
    .ok_or_else(|| Missing::Attachment.error())
}

pub async fn upload(
    State(state): State<AppState>,
    user: AuthUser,
    Path((item_id, id)): Path<(String, String)>,
    Json(req): Json<UploadRequest>,
) -> ApiResult<StatusCode> {
    sec::uuid_path(&item_id, "Élément")?;
    sec::uuid_path(&id, "Pièce jointe")?;
    let eff = state.effective().await?;
    if !eff.bool("attachment.enabled") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "attachments_disabled",
            "Votre organisation a désactivé l'ajout de pièces jointes.",
        ));
    }
    // Taille annoncée puis taille réelle (déduite du chiffré), avant tout
    // accès à la base.
    let max_bytes = max_file_bytes(&eff);
    if req.size.is_some_and(|s| s > max_bytes) || req.data.len() > cipher_len_for(max_bytes) {
        return Err(too_large(max_bytes));
    }
    sec::cipher(&req.data, cipher_len_for(max_bytes), "pièce jointe")?;
    if req.size.is_some_and(|s| s != plain_len(&req.data)) {
        return Err(ApiError::bad_request("La taille annoncée ne correspond pas au fichier envoyé."));
    }
    let q = quotas(&eff);
    let personal_enabled = eff.bool("vault.personal_enabled");
    state
        .db
        .call(move |c| {
            // Droits, nombre, quotas et insertion dans la même transaction :
            // deux envois simultanés ne peuvent pas dépasser ensemble un quota.
            let tx = c.transaction()?;
            let cid = item_collection(&tx, &item_id)?;
            require_role(&tx, &cid, &user.id, WRITE, Missing::Item)?;
            if !personal_enabled && tx.query_row("SELECT personal FROM collections WHERE id = ?1", [&cid], |r| r.get(0))? {
                return Err(personal_disabled());
            }
            let count: i64 = tx.query_row("SELECT COUNT(*) FROM attachments WHERE item_id = ?1", [&item_id], |r| r.get(0))?;
            if count >= q.max_per_item {
                let unite = if q.max_per_item > 1 { "pièces jointes" } else { "pièce jointe" };
                return Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "attachment_limit",
                    format!("{} {unite} au plus par élément.", q.max_per_item),
                ));
            }
            let size = req.data.len() as i64;
            check_quota(used_by(&tx, &user.id)?, used_total(&tx)?, size, &q)?;
            let n = tx.execute(
                "INSERT OR IGNORE INTO attachments (id, item_id, data, size, created_at, created_by) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![id, item_id, req.data, size, now_unix(), user.id],
            )?;
            if n == 0 {
                return Err(ApiError::conflict("Cette pièce jointe existe déjà."));
            }
            audit_user(&tx, &user, "attachment.added", &item_id, &format!("{} Ko chiffrés", req.data.len() / 1024))?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::CREATED)
}

pub async fn download(State(state): State<AppState>, user: AuthUser, Path(id): Path<String>) -> ApiResult<Json<DownloadResponse>> {
    sec::uuid_path(&id, "Pièce jointe")?;
    // Lecture (et contrôle d'accès) hors de l'écrivain : un gros fichier ne
    // bloque pas les écritures des autres.
    let uid = user.id.clone();
    let (item_id, data) = state
        .db
        .read(move |c| {
            let (item_id, cid) = attachment_collection(c, &id)?;
            require_role(c, &cid, &uid, ANY, Missing::Attachment)?;
            let data: String = c.query_row("SELECT data FROM attachments WHERE id = ?1", [&id], |r| r.get(0))?;
            Ok((item_id, data))
        })
        .await?;
    // Pas de données sans trace : si l'audit échoue, l'erreur est renvoyée.
    state.db.call(move |c| audit_user(c, &user, "attachment.downloaded", &item_id, "")).await?;
    Ok(Json(DownloadResponse { data }))
}

pub async fn remove(State(state): State<AppState>, user: AuthUser, Path(id): Path<String>) -> ApiResult<StatusCode> {
    sec::uuid_path(&id, "Pièce jointe")?;
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let (item_id, cid) = attachment_collection(&tx, &id)?;
            require_role(&tx, &cid, &user.id, WRITE, Missing::Attachment)?;
            tx.execute("DELETE FROM attachments WHERE id = ?1", [&id])?;
            audit_user(&tx, &user, "attachment.removed", &item_id, "")?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_state;
    use crate::vault::testing::*;
    use locksy_core::api::roles::{READER, USER};
    use locksy_core::crypto::new_uuid;

    fn q(per_user_mb: i64, total_mb: i64) -> AttachmentQuotas {
        AttachmentQuotas { per_user_mb, total_mb, max_per_item: 20 }
    }

    #[test]
    fn corps_d_envoi_assez_grand_pour_le_plafond() {
        // 15 Mio chiffrés en base64 : un peu moins de 21 Mo, plus l'enveloppe.
        let n = upload_body_limit(16 * 1024 * 1024);
        assert!(n > cipher_len_for(15 * MIB), "{n}");
        assert!(n < 22 * 1024 * 1024, "{n}");
        // Une limite générale plus large l'emporte.
        assert_eq!(upload_body_limit(64 * 1024 * 1024), 64 * 1024 * 1024);
    }

    #[test]
    fn quota_sous_a_et_au_dela_de_la_limite() {
        let q = q(1, 3);
        assert!(check_quota(0, 0, 1000, &q).is_ok());
        // Exactement à la limite : permis.
        assert!(check_quota(MIB - 10, MIB - 10, 10, &q).is_ok());
        assert!(check_quota(0, 3 * MIB - 1, 1, &q).is_ok());
        // Un octet de trop pour l'utilisateur.
        let e = check_quota(MIB - 10, MIB - 10, 11, &q).unwrap_err();
        assert_eq!((e.status, e.code), (StatusCode::PAYLOAD_TOO_LARGE, "quota_exceeded"));
        assert!(e.message.starts_with("Quota personnel"), "{}", e.message);
        assert!(e.message.contains("sur 1 Mo"), "{}", e.message);
        // Un octet de trop pour l'organisation.
        let e = check_quota(0, 3 * MIB, 1, &q).unwrap_err();
        assert_eq!((e.status, e.code), (StatusCode::PAYLOAD_TOO_LARGE, "quota_exceeded"));
        assert!(e.message.contains("organisation"), "{}", e.message);
        assert!(e.message.contains("3 Mo sur 3 Mo"), "{}", e.message);
    }

    #[test]
    fn quotas_par_defaut_et_reglage_partiel() {
        assert_eq!(AttachmentQuotas::default(), AttachmentQuotas { per_user_mb: 1024, total_mb: 20_480, max_per_item: 20 });
        let partial: AttachmentQuotas = serde_json::from_str(r#"{"per_user_mb": 5}"#).unwrap();
        assert_eq!(partial, AttachmentQuotas { per_user_mb: 5, ..Default::default() });
        assert_eq!(to_mb(0), 0);
        assert_eq!(to_mb(1), 1);
        assert_eq!(to_mb(MIB), 1);
        assert_eq!(to_mb(MIB + 1), 2);
        // Quota à 0 : illimité.
        assert!(check_quota(i64::MAX / 2, i64::MAX / 2, MIB, &q(0, 0)).is_ok());
    }

    #[test]
    fn taille_claire_deduite_du_chiffre() {
        let key = locksy_core::crypto::SecretKey::generate();
        for n in [0usize, 1, 2, 3, 1000, 65_537] {
            let c = locksy_core::crypto::encrypt(&key, &vec![7u8; n], b"aad");
            assert_eq!(plain_len(&c), n as i64, "taille {n}");
            assert_eq!(c.len(), cipher_len_for(n as i64), "longueur du chiffré pour {n}");
        }
    }

    /// Chiffré d'environ `kib` Kio une fois encodé.
    fn blob(kib: usize) -> Json<UploadRequest> {
        Json(UploadRequest { data: cipher(&"a".repeat(kib * 768)), size: None })
    }

    #[tokio::test]
    async fn envoi_bloque_par_le_quota_et_le_nombre() {
        let st = test_state().await;
        let (owner, item_a, item_b) = st
            .db
            .call(|c| {
                let owner = user(c, "alice", USER);
                let col = collection(c, &owner, false);
                let a = item(c, &col);
                let b = item(c, &col);
                Ok((owner, a, b))
            })
            .await
            .unwrap();
        crate::tests::set_setting(&st, "attachment.quota_user_mib", serde_json::json!(1)).await;
        crate::tests::set_setting(&st, "attachment.max_per_item", serde_json::json!(1)).await;
        let up = |item: &str, data| upload(State(st.clone()), owner.clone(), Path((item.to_string(), new_uuid())), data);

        assert_eq!(up(&item_a, blob(600)).await.unwrap(), StatusCode::CREATED);
        // Second fichier sur le même élément : nombre maximal atteint (422).
        let e = up(&item_a, blob(1)).await.unwrap_err();
        assert_eq!((e.status, e.code), (StatusCode::UNPROCESSABLE_ENTITY, "attachment_limit"));
        assert_eq!(e.message, "1 pièce jointe au plus par élément.");
        // Autre élément, mais 600 + 600 Kio dépassent 1 Mo (413).
        let e = up(&item_b, blob(600)).await.unwrap_err();
        assert_eq!((e.status, e.code), (StatusCode::PAYLOAD_TOO_LARGE, "quota_exceeded"));
        // Rien n'a été écrit pour les refus.
        let (n, audits) = st
            .db
            .call(|c| {
                Ok((
                    c.query_row("SELECT COUNT(*) FROM attachments", [], |r| r.get::<_, i64>(0))?,
                    c.query_row("SELECT COUNT(*) FROM audit WHERE action = 'attachment.added'", [], |r| r.get::<_, i64>(0))?,
                ))
            })
            .await
            .unwrap();
        assert_eq!((n, audits), (1, 1));
        // Un petit fichier passe encore.
        assert_eq!(up(&item_b, blob(100)).await.unwrap(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn not_found_uniforme_et_403_lecteur() {
        let st = test_state().await;
        let (owner, stranger, reader, it, att) = st
            .db
            .call(|c| {
                let owner = user(c, "alice", USER);
                let stranger = user(c, "bob", USER);
                let reader = user(c, "carole", USER);
                let col = collection(c, &owner, false);
                member(c, &col, &reader, READER);
                let it = item(c, &col);
                let att = new_uuid();
                c.execute(
                    "INSERT INTO attachments (id, item_id, data, size, created_at, created_by) VALUES (?1, ?2, 'x', 1, 0, ?3)",
                    params![att, it, owner.id],
                )?;
                Ok((owner, stranger, reader, it, att))
            })
            .await
            .unwrap();
        let same = |a: &ApiError, b: &ApiError| {
            assert_eq!((a.status, a.code, a.message.as_str()), (b.status, b.code, b.message.as_str()));
        };

        // Envoi : élément inexistant ou d'un coffre étranger.
        let foreign = upload(State(st.clone()), stranger.clone(), Path((it.clone(), new_uuid())), blob(1)).await.unwrap_err();
        let missing = upload(State(st.clone()), stranger.clone(), Path((new_uuid(), new_uuid())), blob(1)).await.unwrap_err();
        same(&foreign, &missing);
        assert_eq!((foreign.status, foreign.message.as_str()), (StatusCode::NOT_FOUND, "Élément introuvable."));

        // Téléchargement et suppression : pièce jointe inexistante ou étrangère.
        let foreign = download(State(st.clone()), stranger.clone(), Path(att.clone())).await.err().unwrap();
        let missing = download(State(st.clone()), stranger.clone(), Path(new_uuid())).await.err().unwrap();
        same(&foreign, &missing);
        assert_eq!(foreign.message, "Pièce jointe introuvable.");
        let foreign = remove(State(st.clone()), stranger.clone(), Path(att.clone())).await.unwrap_err();
        let missing = remove(State(st.clone()), stranger.clone(), Path(new_uuid())).await.unwrap_err();
        same(&foreign, &missing);

        // Lecteur : lit, mais ne peut ni ajouter ni supprimer.
        assert_eq!(download(State(st.clone()), reader.clone(), Path(att.clone())).await.unwrap().0.data, "x");
        let e = upload(State(st.clone()), reader.clone(), Path((it.clone(), new_uuid())), blob(1)).await.unwrap_err();
        assert_eq!((e.status, e.code), (StatusCode::FORBIDDEN, "forbidden"));
        let e = remove(State(st.clone()), reader.clone(), Path(att.clone())).await.unwrap_err();
        assert_eq!((e.status, e.code), (StatusCode::FORBIDDEN, "forbidden"));

        // Le téléchargement réussi est journalisé (écriture séparée de la lecture).
        let n: i64 = st
            .db
            .call(|c| Ok(c.query_row("SELECT COUNT(*) FROM audit WHERE action = 'attachment.downloaded'", [], |r| r.get(0))?))
            .await
            .unwrap();
        assert_eq!(n, 1);
        remove(State(st.clone()), owner, Path(att)).await.unwrap();
    }
}
