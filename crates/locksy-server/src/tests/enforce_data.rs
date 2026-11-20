//! Tests du domaine « enforce_data » (lot L7b) : seuils appliqués aux
//! coffres, aux liens de partage et aux pièces jointes, preuve de possession
//! des liens, révocations automatiques et synchronisation incrémentale.
//!
//! Chaque réglage du registre appliqué ici a son test « valeur modifiée →
//! comportement changé » (matrice G2).

use super::{account, count, set_setting, Account, AccountOpts, Rep, Srv};
use crate::vault::testing::cipher;
use locksy_core::crypto::{self, new_uuid, SecretKey};
use locksy_core::encoding::b64e;
use reqwest::Method;
use rusqlite::params;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

// ------------------------------------------------------------ Outils

async fn compte(s: &Srv) -> Account {
    compte_role(s, "user").await
}

/// Compte connecté dont le profil se lit (`/sync` renvoie le profil, et le
/// harnais commun pose un KDF factice).
async fn compte_role(s: &Srv, role: &'static str) -> Account {
    const KDF: &str = r#"{"alg":"argon2id","m_kib":65536,"t":3,"p":1,"salt":"c2Vs"}"#;
    let a = account(&s.st, &AccountOpts { role, ..AccountOpts::default() }).await;
    let id = a.id.clone();
    s.st.db.call(move |c| Ok(c.execute("UPDATE users SET kdf = ?1 WHERE id = ?2", [KDF, id.as_str()])?)).await.unwrap();
    a
}

fn jeton(a: &Account) -> Option<&str> {
    Some(a.token.as_str())
}

/// Coffre inséré en base, dont `owner` est gestionnaire.
async fn coffre(s: &Srv, owner: &Account, personal: bool) -> String {
    let (id, uid) = (new_uuid(), owner.id.clone());
    let cid = id.clone();
    s.st.db
        .call(move |c| {
            c.execute(
                "INSERT INTO collections (id, enc_name, personal, created_by, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, 0, 0)",
                params![cid, cipher("nom"), personal, uid],
            )?;
            c.execute(
                "INSERT INTO memberships (collection_id, user_id, role, sealed_key, created_at) VALUES (?1, ?2, 'manager', 'scellée', 0)",
                params![cid, uid],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    id
}

async fn membre(s: &Srv, collection_id: &str, user: &Account, role: &'static str) {
    let (cid, uid) = (collection_id.to_string(), user.id.clone());
    s.st.db
        .call(move |c| {
            c.execute(
                "INSERT INTO memberships (collection_id, user_id, role, sealed_key, created_at) VALUES (?1, ?2, ?3, 'scellée', 0)",
                params![cid, uid, role],
            )?;
            Ok(())
        })
        .await
        .unwrap();
}

/// Élément inséré en base (révision 1).
async fn element(s: &Srv, collection_id: &str) -> String {
    let (id, cid) = (new_uuid(), collection_id.to_string());
    let iid = id.clone();
    s.st.db
        .call(move |c| {
            c.execute(
                "INSERT INTO items (id, collection_id, data, revision, created_at, updated_at) VALUES (?1, ?2, ?3, 1, 0, 0)",
                params![iid, cid, cipher("élément")],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    id
}

/// Valeur d'une requête à un paramètre (`NULL` lu comme `Value::Null`).
async fn sql(s: &Srv, query: &str, arg: &str) -> Value {
    let (q, a) = (query.to_string(), arg.to_string());
    s.st.db
        .read(move |c| {
            Ok(c.query_row(&q, [a], |r| {
                Ok(match r.get_ref(0)? {
                    rusqlite::types::ValueRef::Null => Value::Null,
                    rusqlite::types::ValueRef::Integer(i) => json!(i),
                    rusqlite::types::ValueRef::Text(t) => json!(String::from_utf8_lossy(t)),
                    other => json!(format!("{other:?}")),
                })
            })?)
        })
        .await
        .unwrap()
}

async fn sql_exec(s: &Srv, query: &'static str, arg: &str) {
    let a = arg.to_string();
    s.st.db.call(move |c| Ok(c.execute(query, [a])?)).await.unwrap();
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Preuve (base64 URL) et vérificateur (hex) d'une clé de fragment (C5).
fn preuve(cle: &str) -> (String, String) {
    let proof: [u8; 32] = Sha256::digest(cle.as_bytes()).into();
    (b64e(&proof), hex(&Sha256::digest(proof)))
}

fn nonce() -> String {
    b64e(&crypto::random_array::<16>())
}

/// Clé de coffre scellée bien formée (pour un destinataire quelconque).
fn scellee() -> String {
    let (_, public) = crypto::generate_keypair();
    crypto::seal_key(&public, &SecretKey::generate(), "contexte").unwrap()
}

async fn ouvrir(s: &Srv, id: &str, proof: &str, nonce: &str) -> Rep {
    s.post(&format!("/api/public/shares/{id}/open"), None, json!({ "proof": proof, "nonce": nonce })).await
}

async fn apercu(s: &Srv, id: &str, proof: &str) -> Rep {
    s.post(&format!("/api/public/shares/{id}/peek"), None, json!({ "proof": proof })).await
}

/// Corps de création d'un lien : 60 minutes, `views` consultations, plus
/// les champs de `extra`.
fn corps_lien(views: i64, extra: Value) -> Value {
    let mut b = json!({ "data": cipher("secret partagé"), "expires_in_minutes": 60, "max_views": views });
    if let (Some(o), Value::Object(e)) = (b.as_object_mut(), extra) {
        o.extend(e);
    }
    b
}

async fn creer_lien(s: &Srv, a: &Account, views: i64, extra: Value) -> String {
    let r = s.post("/api/shares", jeton(a), corps_lien(views, extra)).await;
    r.expect(200, "")["id"].as_str().unwrap().to_string()
}

/// État, motif et contenu d'un lien en base.
async fn etat_lien(s: &Srv, id: &str) -> (Value, Value, Value) {
    (
        sql(s, "SELECT state FROM shares WHERE id = ?1", id).await,
        sql(s, "SELECT ended_reason FROM shares WHERE id = ?1", id).await,
        sql(s, "SELECT data FROM shares WHERE id = ?1", id).await,
    )
}

async fn assert_termine(s: &Srv, id: &str, state: &str, reason: &str) {
    let (st, why, data) = etat_lien(s, id).await;
    assert_eq!((st, why, data), (json!(state), json!(reason), json!("")), "lien {id}");
}

/// Pièce jointe chiffrée de `taille` octets clairs.
fn piece(taille: usize) -> Value {
    json!({ "data": crypto::encrypt(&SecretKey::generate(), &vec![0x5a; taille], b"aad") })
}

async fn joindre(s: &Srv, a: &Account, item: &str, corps: Value) -> Rep {
    s.put(&format!("/api/items/{item}/attachments/{}", new_uuid()), jeton(a), corps).await
}

fn ids(v: &Value) -> Vec<String> {
    let mut out: Vec<String> =
        v.as_array().unwrap().iter().map(|x| x["id"].as_str().or(x.as_str()).unwrap().to_string()).collect();
    out.sort();
    out
}

async fn sync(s: &Srv, a: &Account, since: Option<i64>) -> Value {
    let path = since.map_or("/api/sync".to_string(), |n| format!("/api/sync?since={n}"));
    s.get(&path, jeton(a)).await.expect(200, "").clone()
}

// ------------------------------------------------------------ Partage : réglages

#[tokio::test]
async fn partage_desactive_par_l_organisation() {
    let s = super::srv().await;
    let a = compte(&s).await;
    s.post("/api/shares", jeton(&a), corps_lien(1, json!({}))).await.expect(200, "");
    set_setting(&s.st, "share.enabled", json!(false)).await;
    s.post("/api/shares", jeton(&a), corps_lien(1, json!({}))).await.expect(403, "share_disabled");
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM shares").await, 1);
}

#[tokio::test]
async fn partage_duree_et_ouvertures_plafonnees() {
    let s = super::srv().await;
    let a = compte(&s).await;
    let corps = |minutes: i64, views: i64| {
        json!({ "data": cipher("x"), "expires_in_minutes": minutes, "max_views": views })
    };
    // Défauts : 30 jours et 100 ouvertures.
    s.post("/api/shares", jeton(&a), corps(240, 10)).await.expect(200, "");
    set_setting(&s.st, "share.max_expiry_minutes", json!(60)).await;
    set_setting(&s.st, "share.max_views", json!(3)).await;
    let r = s.post("/api/shares", jeton(&a), corps(240, 1)).await;
    let b = r.expect(422, "share_limit");
    assert_eq!((b["max_minutes"].clone(), b["max_views"].clone()), (json!(60), json!(3)));
    s.post("/api/shares", jeton(&a), corps(60, 4)).await.expect(422, "share_limit");
    s.post("/api/shares", jeton(&a), corps(60, 3)).await.expect(200, "");
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM shares").await, 2);
}

#[tokio::test]
async fn partage_cadence_par_heure() {
    let s = super::srv().await;
    let a = compte(&s).await;
    set_setting(&s.st, "share.max_per_hour", json!(2)).await;
    for _ in 0..2 {
        s.post("/api/shares", jeton(&a), corps_lien(1, json!({}))).await.expect(200, "");
    }
    let r = s.post("/api/shares", jeton(&a), corps_lien(1, json!({}))).await;
    r.expect(429, "rate_limited");
    assert!(r.header("retry-after").is_some());
    // La limite est propre à chaque compte.
    let b = compte(&s).await;
    s.post("/api/shares", jeton(&b), corps_lien(1, json!({}))).await.expect(200, "");
}

#[tokio::test]
async fn partage_rattache_a_un_element_visible() {
    let s = super::srv().await;
    let (a, etranger) = (compte(&s).await, compte(&s).await);
    let c = coffre(&s, &a, false).await;
    let it = element(&s, &c).await;
    // Élément d'autrui ou inexistant : même 404.
    let r1 = s.post("/api/shares", jeton(&etranger), corps_lien(1, json!({ "item_id": it }))).await;
    let r2 = s.post("/api/shares", jeton(&etranger), corps_lien(1, json!({ "item_id": new_uuid() }))).await;
    r1.expect(404, "not_found");
    assert_eq!(r1.body, r2.body);
    // Vérificateur mal formé : 400.
    s.post("/api/shares", jeton(&a), corps_lien(1, json!({ "verifier": "abc" }))).await.expect(400, "bad_request");
    let id = creer_lien(&s, &a, 1, json!({ "item_id": it, "verifier": preuve("k").1 })).await;
    assert_eq!(sql(&s, "SELECT collection_id FROM shares WHERE id = ?1", &id).await, json!(c));
    let liste = s.get("/api/shares?all=1", jeton(&a)).await;
    let ligne = &liste.expect(200, "")[0];
    assert_eq!((ligne["item_id"].clone(), ligne["has_verifier"].clone(), ligne["state"].clone()), (json!(it), json!(true), json!("active")));
}

// ------------------------------------------------------------ Coffres : réglages

#[tokio::test]
async fn creation_de_coffre_partage_reservee_aux_administrateurs() {
    let s = super::srv().await;
    let (u, admin) = (compte(&s).await, compte_role(&s, "admin").await);
    let corps = || json!({ "id": new_uuid(), "enc_name": cipher("Équipe"), "sealed_key": scellee() });
    s.post("/api/collections", jeton(&u), corps()).await.expect(201, "");
    set_setting(&s.st, "vault.users_can_create_shared", json!(false)).await;
    s.post("/api/collections", jeton(&u), corps()).await.expect(403, "shared_vault_creation_disabled");
    s.post("/api/collections", jeton(&admin), corps()).await.expect(201, "");
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM collections").await, 2);
}

#[tokio::test]
async fn espace_personnel_bloquable() {
    let s = super::srv().await;
    let a = compte(&s).await;
    let perso = coffre(&s, &a, true).await;
    let equipe = coffre(&s, &a, false).await;
    let ancien = element(&s, &perso).await;
    let nouvel = |cid: &str| json!({ "id": new_uuid(), "collection_id": cid, "data": cipher("x") });
    // Permis par défaut.
    s.post("/api/items", jeton(&a), nouvel(&perso)).await.expect(201, "");
    let avant = sync(&s, &a, None).await;
    let seq = avant["seq"].as_i64().unwrap();
    assert_eq!(avant["collections"].as_array().unwrap().len(), 2);

    set_setting(&s.st, "vault.personal_enabled", json!(false)).await;
    s.post("/api/items", jeton(&a), nouvel(&perso)).await.expect(403, "personal_vault_disabled");
    s.post("/api/items/batch", jeton(&a), json!({ "items": [nouvel(&equipe), nouvel(&perso)] }))
        .await
        .expect(403, "personal_vault_disabled");
    let maj = |cid: &str| json!({ "collection_id": cid, "data": cipher("y"), "revision": 1 });
    s.put(&format!("/api/items/{ancien}"), jeton(&a), maj(&perso)).await.expect(403, "personal_vault_disabled");
    // Pièce jointe et lien vers l'espace personnel : refusés aussi.
    joindre(&s, &a, &ancien, piece(10)).await.expect(403, "personal_vault_disabled");
    s.post("/api/shares", jeton(&a), corps_lien(1, json!({ "item_id": ancien }))).await.expect(403, "item_not_shareable");
    // L'espace personnel disparaît de la synchronisation.
    let apres = sync(&s, &a, None).await;
    assert_eq!(ids(&apres["collections"]), vec![equipe.clone()]);
    assert!(apres["items"].as_array().unwrap().iter().all(|i| i["collection_id"] == json!(equipe)));
    let delta = sync(&s, &a, Some(seq)).await;
    assert_eq!(delta["removed"]["collections"], json!([perso]));
    // Sortir un élément de l'espace personnel reste possible.
    s.put(&format!("/api/items/{ancien}"), jeton(&a), maj(&equipe)).await.expect(200, "");
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM items").await, 2);
}

// ------------------------------------------------------------ Pièces jointes : réglages

#[tokio::test]
async fn pieces_jointes_desactivables() {
    let s = super::srv().await;
    let a = compte(&s).await;
    let it = element(&s, &coffre(&s, &a, false).await).await;
    let id = new_uuid();
    s.put(&format!("/api/items/{it}/attachments/{id}"), jeton(&a), piece(100)).await.expect(201, "");
    set_setting(&s.st, "attachment.enabled", json!(false)).await;
    joindre(&s, &a, &it, piece(100)).await.expect(403, "attachments_disabled");
    // Les fichiers déjà joints restent lisibles.
    s.get(&format!("/api/attachments/{id}"), jeton(&a)).await.expect(200, "");
}

#[tokio::test]
async fn piece_jointe_taille_maximale() {
    const MIB: usize = 1_048_576;
    let s = super::srv().await;
    let a = compte(&s).await;
    let it = element(&s, &coffre(&s, &a, false).await).await;
    joindre(&s, &a, &it, piece(MIB + 1)).await.expect(201, "");
    set_setting(&s.st, "attachment.max_file_mib", json!(1)).await;
    let r = joindre(&s, &a, &it, piece(MIB + 1)).await;
    r.expect(413, "attachment_too_large");
    // Taille annoncée au-delà de la limite : refus sans lire le fichier.
    let mut annonce = piece(10);
    annonce["size"] = json!(2 * MIB);
    joindre(&s, &a, &it, annonce).await.expect(413, "attachment_too_large");
    // Taille annoncée fausse : 400.
    let mut fausse = piece(10);
    fausse["size"] = json!(11);
    joindre(&s, &a, &it, fausse).await.expect(400, "bad_request");
    // Exactement à la limite : accepté (taille annoncée juste).
    let mut juste = piece(MIB);
    juste["size"] = json!(MIB);
    joindre(&s, &a, &it, juste).await.expect(201, "");
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM attachments").await, 2);
}

#[tokio::test]
async fn piece_jointe_nombre_par_element() {
    let s = super::srv().await;
    let a = compte(&s).await;
    let it = element(&s, &coffre(&s, &a, false).await).await;
    for _ in 0..2 {
        joindre(&s, &a, &it, piece(10)).await.expect(201, "");
    }
    set_setting(&s.st, "attachment.max_per_item", json!(2)).await;
    joindre(&s, &a, &it, piece(10)).await.expect(422, "attachment_limit");
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM attachments").await, 2);
}

#[tokio::test]
async fn piece_jointe_quota_utilisateur() {
    let s = super::srv().await;
    let a = compte(&s).await;
    let it = element(&s, &coffre(&s, &a, false).await).await;
    // Environ 800 Ko stockés : sous le quota par défaut comme sous 1 Mo.
    joindre(&s, &a, &it, piece(600_000)).await.expect(201, "");
    joindre(&s, &a, &it, piece(300_000)).await.expect(201, "");
    set_setting(&s.st, "attachment.quota_user_mib", json!(1)).await;
    joindre(&s, &a, &it, piece(300_000)).await.expect(413, "quota_exceeded");
    // Le quota est personnel : un autre membre peut encore joindre.
    let b = compte(&s).await;
    let cid = sql(&s, "SELECT collection_id FROM items WHERE id = ?1", &it).await;
    membre(&s, cid.as_str().unwrap(), &b, "editor").await;
    joindre(&s, &b, &it, piece(300_000)).await.expect(201, "");
}

/// `attachment.quota_total_mib` : l'espace de toute l'organisation, tous
/// comptes confondus (le quota personnel, lui, n'est pas atteint).
#[tokio::test]
async fn piece_jointe_quota_total() {
    let s = super::srv().await;
    let a = compte(&s).await;
    let b = compte(&s).await;
    let it_a = element(&s, &coffre(&s, &a, false).await).await;
    let it_b = element(&s, &coffre(&s, &b, false).await).await;
    set_setting(&s.st, "attachment.quota_total_mib", json!(1)).await;
    joindre(&s, &a, &it_a, piece(600_000)).await.expect(201, "");
    joindre(&s, &b, &it_b, piece(600_000)).await.expect(413, "quota_exceeded");
    // Sous le plafond restant, l'envoi passe encore.
    joindre(&s, &b, &it_b, piece(100_000)).await.expect(201, "");
    // Avec le défaut, plus de blocage.
    set_setting(&s.st, "attachment.quota_total_mib", json!(20_480)).await;
    joindre(&s, &b, &it_b, piece(600_000)).await.expect(201, "");
}

// ------------------------------------------------------------ Corbeille

#[tokio::test]
async fn corbeille_auteur_et_date_de_purge() {
    const DAY: i64 = 86_400;
    let s = super::srv().await;
    let a = compte(&s).await;
    let c = coffre(&s, &a, false).await;
    let it = element(&s, &c).await;
    s.delete(&format!("/api/items/{it}"), jeton(&a)).await.expect(204, "");
    let trouve = |v: &Value| v["items"].as_array().unwrap().iter().find(|i| i["id"] == json!(it)).cloned().unwrap();
    let i = trouve(&sync(&s, &a, None).await);
    let deleted_at = i["deleted_at"].as_i64().unwrap();
    assert_eq!(i["deleted_by"], json!(a.id));
    assert_eq!(i["purge_at"], json!(deleted_at + 30 * DAY));
    set_setting(&s.st, "retention.trash_days", json!(7)).await;
    assert_eq!(trouve(&sync(&s, &a, None).await)["purge_at"], json!(deleted_at + 7 * DAY));
    // Restauration : plus d'auteur ni de date de purge.
    s.post(&format!("/api/items/{it}/restore"), jeton(&a), json!({})).await.expect(204, "");
    let i = trouve(&sync(&s, &a, None).await);
    assert_eq!((i["deleted_by"].clone(), i["purge_at"].clone()), (Value::Null, Value::Null));
}

// ------------------------------------------------------------ Preuve de possession

#[tokio::test]
async fn preuve_de_possession_avant_toute_lecture() {
    let s = super::srv().await;
    let a = compte(&s).await;
    let (proof, verifier) = preuve("cle-du-fragment");
    let (fausse, _) = preuve("autre-cle");
    let id = creer_lien(&s, &a, 2, json!({ "verifier": verifier })).await;

    // Fausse preuve, preuve illisible, lien inconnu : même 404, rien n'est compté.
    let r1 = ouvrir(&s, &id, &fausse, &nonce()).await;
    r1.expect(404, "not_found");
    let r2 = ouvrir(&s, &id, "illisible", &nonce()).await;
    let r3 = ouvrir(&s, &crypto::random_token(), &proof, &nonce()).await;
    assert_eq!(r1.body, r3.body);
    assert_eq!(r2.body, r3.body);
    apercu(&s, &id, &fausse).await.expect(404, "not_found");
    assert_eq!(sql(&s, "SELECT views FROM shares WHERE id = ?1", &id).await, json!(0));
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM share_reveals").await, 0);
    // Le lien sécurisé n'est pas servi par l'ancienne route.
    s.get(&format!("/api/public/shares/{id}"), None).await.expect(404, "not_found");

    // Aperçu : rien n'est décompté.
    let p = apercu(&s, &id, &proof).await;
    let b = p.expect(200, "");
    assert_eq!((b["state"].clone(), b["views_left"].clone()), (json!("active"), json!(2)));

    // Ouverture, puis même ouverture rejouée : une seule vue comptée.
    let n1 = nonce();
    let o = ouvrir(&s, &id, &proof, &n1).await;
    let b = o.expect(200, "");
    assert_eq!((b["views_left"].clone(), b["replayed"].clone()), (json!(1), json!(false)));
    assert!(b["data"].as_str().is_some_and(|d| d.starts_with("v1.")));
    let o = ouvrir(&s, &id, &proof, &n1).await;
    let b = o.expect(200, "");
    assert_eq!((b["views_left"].clone(), b["replayed"].clone()), (json!(1), json!(true)));
    assert_eq!(sql(&s, "SELECT views FROM shares WHERE id = ?1", &id).await, json!(1));
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM share_reveals WHERE counted = 1").await, 1);

    // Dernière vue : lien épuisé, contenu effacé dans la même transaction.
    let o = ouvrir(&s, &id, &proof, &nonce()).await;
    assert_eq!(o.expect(200, "")["views_left"], json!(0));
    assert_termine(&s, &id, "exhausted", "exhausted").await;
    // Ensuite : 410 avec le motif, seulement pour qui a la preuve.
    let fin = ouvrir(&s, &id, &proof, &nonce()).await;
    let b = fin.expect(410, "share_ended");
    assert_eq!(b["reason"], json!("exhausted"));
    assert!(b["ended_at"].as_i64().is_some());
    apercu(&s, &id, &proof).await.expect(410, "share_ended");
    ouvrir(&s, &id, &proof, &n1).await.expect(410, "share_ended");
    apercu(&s, &id, &fausse).await.expect(404, "not_found");
    // Identifiant de consultation mal formé.
    ouvrir(&s, &id, &proof, "court").await.expect(400, "bad_request");
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'share.revealed'").await, 2);
}

#[tokio::test]
async fn lien_historique_sans_verificateur() {
    let s = super::srv().await;
    let a = compte(&s).await;
    let id = creer_lien(&s, &a, 1, json!({})).await;
    // Pas de vérificateur : l'aperçu et l'ouverture par preuve répondent 404.
    let (proof, _) = preuve("k");
    apercu(&s, &id, &proof).await.expect(404, "not_found");
    ouvrir(&s, &id, &proof, &nonce()).await.expect(404, "not_found");
    assert_eq!(sql(&s, "SELECT views FROM shares WHERE id = ?1", &id).await, json!(0));
    let r = s.get(&format!("/api/public/shares/{id}"), None).await;
    assert_eq!(r.expect(200, "")["views_left"], json!(0));
    assert_termine(&s, &id, "exhausted", "exhausted").await;
    s.get(&format!("/api/public/shares/{id}"), None).await.expect(404, "not_found");
}

// ------------------------------------------------------------ États terminaux et révocations

#[tokio::test]
async fn revocation_par_le_createur_idempotente() {
    let s = super::srv().await;
    let (a, b) = (compte(&s).await, compte(&s).await);
    let id = creer_lien(&s, &a, 3, json!({})).await;
    // Le lien d'autrui : 404.
    s.delete(&format!("/api/shares/{id}"), jeton(&b)).await.expect(404, "not_found");
    s.delete(&format!("/api/shares/{id}"), jeton(&a)).await.expect(204, "");
    s.delete(&format!("/api/shares/{id}"), jeton(&a)).await.expect(204, "");
    assert_termine(&s, &id, "revoked", "revoked").await;
    assert_eq!(sql(&s, "SELECT ended_by FROM shares WHERE id = ?1", &id).await, json!(a.id));
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'share.revoked'").await, 1);
    // Liste : absent des liens actifs, présent avec son état dans l'historique.
    assert_eq!(s.get("/api/shares", jeton(&a)).await.expect(200, "").as_array().unwrap().len(), 0);
    let tous = s.get("/api/shares?all=1", jeton(&a)).await;
    let l = &tous.expect(200, "")[0];
    assert_eq!((l["state"].clone(), l["ended_reason"].clone()), (json!("revoked"), json!("revoked")));
}

#[tokio::test]
async fn revocation_automatique_a_la_corbeille() {
    let s = super::srv().await;
    let a = compte(&s).await;
    let c = coffre(&s, &a, false).await;
    let (it, autre) = (element(&s, &c).await, element(&s, &c).await);
    let lie = creer_lien(&s, &a, 3, json!({ "item_id": it })).await;
    let libre = creer_lien(&s, &a, 3, json!({ "item_id": autre })).await;
    s.delete(&format!("/api/items/{it}"), jeton(&a)).await.expect(204, "");
    assert_termine(&s, &lie, "revoked", "item_deleted").await;
    assert_eq!(sql(&s, "SELECT state FROM shares WHERE id = ?1", &libre).await, json!("active"));
    // Un élément à la corbeille ne se partage pas.
    s.post("/api/shares", jeton(&a), corps_lien(1, json!({ "item_id": it }))).await.expect(403, "item_not_shareable");
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'share.revoked_auto'").await, 1);
}

#[tokio::test]
async fn revocation_automatique_rotation_et_retrait() {
    let s = super::srv().await;
    let (a, b) = (compte(&s).await, compte(&s).await);
    let c = coffre(&s, &a, false).await;
    membre(&s, &c, &b, "editor").await;
    let (i1, i2) = (element(&s, &c).await, element(&s, &c).await);
    let de_b = creer_lien(&s, &b, 3, json!({ "item_id": i1 })).await;
    let de_a = creer_lien(&s, &a, 3, json!({ "item_id": i2 })).await;
    let hors_coffre = creer_lien(&s, &a, 3, json!({})).await;
    sql_exec(&s, "UPDATE collections SET rotation_suggested_at = 123 WHERE id = ?1", &c).await;

    let rotation = json!({
        "remove_user_ids": [b.id],
        "enc_name": cipher("nom"),
        "members": [{ "user_id": a.id, "sealed_key": scellee() }],
        "items": [{ "id": i1, "data": cipher("1") }, { "id": i2, "data": cipher("2") }],
    });
    s.post(&format!("/api/collections/{c}/rotate"), jeton(&a), rotation).await.expect(204, "");
    assert_termine(&s, &de_b, "revoked", "access_lost").await;
    assert_termine(&s, &de_a, "revoked", "rotated").await;
    assert_eq!(sql(&s, "SELECT state FROM shares WHERE id = ?1", &hors_coffre).await, json!("active"));
    // La rotation conseillée est faite : l'alerte disparaît.
    assert_eq!(sql(&s, "SELECT rotation_suggested_at FROM collections WHERE id = ?1", &c).await, Value::Null);
    let col = &sync(&s, &a, None).await["collections"][0];
    assert_eq!((col["key_version"].clone(), col["rotation_suggested_at"].clone()), (json!(2), Value::Null));
}

#[tokio::test]
async fn revocation_automatique_au_depart_d_un_membre() {
    let s = super::srv().await;
    let (a, b) = (compte(&s).await, compte(&s).await);
    let c = coffre(&s, &a, false).await;
    membre(&s, &c, &b, "reader").await;
    let it = element(&s, &c).await;
    let de_b = creer_lien(&s, &b, 3, json!({ "item_id": it })).await;
    let de_a = creer_lien(&s, &a, 3, json!({ "item_id": it })).await;
    s.delete(&format!("/api/collections/{c}/members/{}", b.id), jeton(&b)).await.expect(204, "");
    assert_termine(&s, &de_b, "revoked", "access_lost").await;
    assert_eq!(sql(&s, "SELECT state FROM shares WHERE id = ?1", &de_a).await, json!("active"));
}

#[tokio::test]
async fn revocation_des_liens_d_un_compte() {
    let s = super::srv().await;
    let (a, b) = (compte(&s).await, compte(&s).await);
    let (l1, l2) = (creer_lien(&s, &a, 3, json!({})).await, creer_lien(&s, &a, 3, json!({})).await);
    let autre = creer_lien(&s, &b, 3, json!({})).await;
    // Fonction partagée (contrat C2.6), appelée à la désactivation d'un compte.
    let uid = a.id.clone();
    let n = s.st.db.call(move |c| crate::shares::revoke_for_user(c, &uid, crate::shares::reason::OWNER_DISABLED, None)).await.unwrap();
    assert_eq!(n, 2);
    assert_termine(&s, &l1, "revoked", "owner_disabled").await;
    assert_termine(&s, &l2, "revoked", "owner_disabled").await;
    assert_eq!(sql(&s, "SELECT state FROM shares WHERE id = ?1", &autre).await, json!("active"));
    // Fonction rattachée à un élément.
    let c = coffre(&s, &b, false).await;
    let it = element(&s, &c).await;
    let lie = creer_lien(&s, &b, 3, json!({ "item_id": it })).await;
    let iid = it.clone();
    let n = s.st.db.call(move |c| crate::shares::revoke_for_item(c, &iid, "item_deleted", None)).await.unwrap();
    assert_eq!(n, 1);
    assert_termine(&s, &lie, "revoked", "item_deleted").await;
}

#[tokio::test]
async fn revocation_par_un_administrateur() {
    let s = super::srv().await;
    let (u, admin, owner) = (compte(&s).await, compte_role(&s, "admin").await, compte_role(&s, "owner").await);
    let l = creer_lien(&s, &u, 3, json!({})).await;
    let lo = creer_lien(&s, &owner, 3, json!({})).await;
    s.post("/api/admin/shares/revoke", jeton(&u), json!({ "owner_id": u.id })).await.expect(403, "forbidden");
    // Un administrateur ne révoque pas les liens d'un propriétaire.
    s.post("/api/admin/shares/revoke", jeton(&admin), json!({ "owner_id": owner.id })).await.expect(403, "owner_only");
    let r = s.post("/api/admin/shares/revoke", jeton(&admin), json!({ "owner_id": u.id })).await;
    assert_eq!(r.expect(200, "")["revoked"], json!(1));
    assert_termine(&s, &l, "revoked", "revoked_admin").await;
    assert_eq!(sql(&s, "SELECT ended_by FROM shares WHERE id = ?1", &l).await, json!(admin.id));
    assert_eq!(sql(&s, "SELECT state FROM shares WHERE id = ?1", &lo).await, json!("active"));
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'admin.shares_revoked'").await, 1);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'share.ended' AND details = 'revoked_admin'").await, 1);
    s.post("/api/admin/shares/revoke", jeton(&admin), json!({ "owner_id": new_uuid() })).await.expect(404, "not_found");
}

// ------------------------------------------------------------ Synchronisation incrémentale

#[tokio::test]
async fn synchronisation_incrementale() {
    let s = super::srv().await;
    let (a, b) = (compte(&s).await, compte(&s).await);
    let mien = coffre(&s, &a, false).await;
    let (i1, i2) = (element(&s, &mien).await, element(&s, &mien).await);
    let sien = coffre(&s, &b, false).await;
    membre(&s, &sien, &a, "editor").await;
    let i3 = element(&s, &sien).await;

    let complet = sync(&s, &a, None).await;
    assert_eq!(complet["full"], json!(true));
    assert_eq!(ids(&complet["items"]), {
        let mut v = vec![i1.clone(), i2.clone(), i3.clone()];
        v.sort();
        v
    });
    assert_eq!(complet["removed"], json!({ "items": [], "collections": [] }));
    let s0 = complet["seq"].as_i64().unwrap();
    // Rien n'a changé : réponse partielle vide.
    let vide = sync(&s, &a, Some(s0)).await;
    assert_eq!((vide["full"].clone(), vide["items"].clone(), vide["collections"].clone()), (json!(false), json!([]), json!([])));

    // Élément modifié : seul lui revient.
    let maj = json!({ "collection_id": mien, "data": cipher("v2"), "revision": 1 });
    s.put(&format!("/api/items/{i1}"), jeton(&a), maj).await.expect(200, "");
    let d1 = sync(&s, &a, Some(s0)).await;
    assert_eq!(ids(&d1["items"]), vec![i1.clone()]);
    let s1 = d1["seq"].as_i64().unwrap();
    assert!(s1 > s0);

    // Élément supprimé définitivement : dans removed.items.
    s.delete(&format!("/api/items/{i2}"), jeton(&a)).await.expect(204, "");
    s.delete(&format!("/api/items/{i2}/purge"), jeton(&a)).await.expect(204, "");
    let d2 = sync(&s, &a, Some(s1)).await;
    assert_eq!(d2["removed"]["items"], json!([i2]));
    let s2 = d2["seq"].as_i64().unwrap();

    // Coffre quitté : dans removed.collections.
    s.delete(&format!("/api/collections/{sien}/members/{}", a.id), jeton(&a)).await.expect(204, "");
    let d3 = sync(&s, &a, Some(s2)).await;
    assert_eq!(d3["removed"]["collections"], json!([sien]));
    let s3 = d3["seq"].as_i64().unwrap();

    // Coffre devenu visible : lui et TOUS ses éléments, même anciens.
    let autre = coffre(&s, &b, false).await;
    let ancien = element(&s, &autre).await;
    let s4 = sync(&s, &a, Some(s3)).await["seq"].as_i64().unwrap();
    membre(&s, &autre, &a, "reader").await;
    let d4 = sync(&s, &a, Some(s4)).await;
    assert_eq!(ids(&d4["collections"]), vec![autre.clone()]);
    assert_eq!(ids(&d4["items"]), vec![ancien.clone()]);
    // Le nombre de membres d'un coffre change pour les autres membres aussi.
    let d4b = sync(&s, &b, Some(s4)).await;
    assert_eq!(ids(&d4b["collections"]), vec![autre.clone()]);
    assert_eq!(d4b["collections"][0]["member_count"], json!(2));

    // Coffre supprimé par son gestionnaire : retiré chez les membres.
    let s5 = d4["seq"].as_i64().unwrap();
    s.delete(&format!("/api/collections/{autre}"), jeton(&b)).await.expect(204, "");
    let d5 = sync(&s, &a, Some(s5)).await;
    assert_eq!(d5["removed"]["collections"], json!([autre]));

    // Position inconnue ou trop ancienne : réponse complète.
    assert_eq!(sync(&s, &a, Some(i64::MAX / 2)).await["full"], json!(true));
    assert_eq!(s.get("/api/sync?since=abc", jeton(&a)).await.expect(200, "")["full"], json!(true));
    let cur = d5["seq"].as_i64().unwrap();
    sql_exec(&s, "UPDATE sync_state SET purged_before = CAST(?1 AS INTEGER) WHERE id = 1", &cur.to_string()).await;
    assert_eq!(sync(&s, &a, Some(cur - 1)).await["full"], json!(true));
    assert_eq!(sync(&s, &a, Some(cur)).await["full"], json!(false));
}

#[tokio::test]
async fn synchronisation_revisions_de_politique_et_de_preferences() {
    let s = super::srv().await;
    let a = compte(&s).await;
    let r0 = sync(&s, &a, None).await;
    let (p0, q0) = (r0["policy_revision"].as_i64().unwrap(), r0["prefs_revision"].as_i64().unwrap());
    assert_eq!(q0, 0);
    set_setting(&s.st, "share.max_views", json!(50)).await;
    let r1 = sync(&s, &a, None).await;
    assert!(r1["policy_revision"].as_i64().unwrap() > p0, "{r1}");
    let r = s.req(Method::PUT, "/api/me/prefs", jeton(&a), Some(&json!({ "cipher": cipher("{}") })), &[("if-match", "\"0\"")]).await;
    r.expect(200, "");
    let r2 = sync(&s, &a, Some(r1["seq"].as_i64().unwrap())).await;
    assert_eq!(r2["prefs_revision"], json!(1));
}

// ------------------------------------------------------------ Version de clé

#[tokio::test]
async fn ecriture_sous_une_cle_perimee() {
    let s = super::srv().await;
    let a = compte(&s).await;
    let c = coffre(&s, &a, false).await;
    let it = element(&s, &c).await;
    sql_exec(&s, "UPDATE collections SET key_version = 2 WHERE id = ?1", &c).await;
    let maj = |v: i64| json!({ "collection_id": c, "data": cipher("x"), "revision": 1, "key_version": v });
    let r = s.put(&format!("/api/items/{it}"), jeton(&a), maj(1)).await;
    let b = r.expect(409, "rekey_required");
    assert_eq!((b["collection_id"].clone(), b["key_version"].clone()), (json!(c), json!(2)));
    assert_eq!(sql(&s, "SELECT revision FROM items WHERE id = ?1", &it).await, json!(1));
    let nouvel = json!({ "id": new_uuid(), "collection_id": c, "data": cipher("x"), "key_version": 1 });
    s.post("/api/items", jeton(&a), nouvel.clone()).await.expect(409, "rekey_required");
    s.post("/api/items/batch", jeton(&a), json!({ "items": [nouvel] })).await.expect(409, "rekey_required");
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM items").await, 1);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'item.rekey_refused'").await, 3);
    // Bonne version, ou version absente (client ancien) : accepté.
    s.put(&format!("/api/items/{it}"), jeton(&a), maj(2)).await.expect(200, "");
    let sans = json!({ "collection_id": c, "data": cipher("x"), "revision": 2 });
    s.put(&format!("/api/items/{it}"), jeton(&a), sans).await.expect(200, "");
}

// ------------------------------------------------------------ Identifiants de chemin

#[tokio::test]
async fn identifiant_mal_forme_donne_404() {
    let s = super::srv().await;
    let a = compte(&s).await;
    let c = coffre(&s, &a, false).await;
    let it = element(&s, &c).await;
    let x = "pas-un-uuid";
    let cas = [
        s.get(&format!("/api/attachments/{x}"), jeton(&a)).await,
        s.delete(&format!("/api/attachments/{x}"), jeton(&a)).await,
        s.put(&format!("/api/items/{it}/attachments/{x}"), jeton(&a), piece(10)).await,
        s.put(&format!("/api/items/{x}/attachments/{}", new_uuid()), jeton(&a), piece(10)).await,
        s.delete(&format!("/api/items/{x}"), jeton(&a)).await,
        s.delete(&format!("/api/items/{x}/purge"), jeton(&a)).await,
        s.put(&format!("/api/items/{x}"), jeton(&a), json!({ "collection_id": c, "data": cipher("x"), "revision": 1 })).await,
        s.get(&format!("/api/collections/{x}/members"), jeton(&a)).await,
        s.delete(&format!("/api/collections/{x}"), jeton(&a)).await,
    ];
    for r in &cas {
        r.expect(404, "not_found");
    }
    // Même réponse qu'un identifiant bien formé mais inexistant.
    let absent = s.delete(&format!("/api/items/{}", new_uuid()), jeton(&a)).await;
    assert_eq!(cas[4].body, absent.body);
    let absent = s.get(&format!("/api/attachments/{}", new_uuid()), jeton(&a)).await;
    assert_eq!(cas[0].body, absent.body);
}

// ------------------------------------------------------------ Intégration

#[tokio::test]
async fn rotation_conseillee_dans_la_synchronisation_partielle() {
    let s = super::srv().await;
    let a = compte(&s).await;
    let c = coffre(&s, &a, false).await;
    let s0 = sync(&s, &a, None).await["seq"].as_i64().unwrap();
    // Posée par l'assistant de départ (admin_people) : le coffre revient
    // dans la réponse partielle avec la date.
    sql_exec(&s, "UPDATE collections SET rotation_suggested_at = unixepoch() WHERE id = ?1", &c).await;
    let d = sync(&s, &a, Some(s0)).await;
    assert_eq!(d["full"], json!(false));
    assert_eq!(ids(&d["collections"]), vec![c.clone()]);
    assert!(d["collections"][0]["rotation_suggested_at"].as_i64().is_some(), "{d}");
}

#[tokio::test]
async fn piece_jointe_au_dela_de_la_limite_generale_du_corps() {
    // 12 Mio chiffrés en base64 dépassent LOCKSY_MAX_BODY_MIB (16 Mo) : la
    // route d'envoi a sa propre limite, calée sur le plafond de l'hébergeur.
    const MIB: usize = 1_048_576;
    let s = super::srv_with(|st| {
        // Plafond de l'hébergeur au maximum (LOCKSY_MAX_ATTACHMENT_MIB=15).
        let mut host = (*st.host).clone();
        host.caps.caps.insert("attachment.max_file_mib".into(), (15, "LOCKSY_MAX_ATTACHMENT_MIB".into()));
        st.host = std::sync::Arc::new(host);
    })
    .await;
    let a = compte(&s).await;
    let it = element(&s, &coffre(&s, &a, false).await).await;
    set_setting(&s.st, "attachment.max_file_mib", json!(15)).await;
    let mut corps = piece(12 * MIB);
    corps["size"] = json!(12 * MIB);
    joindre(&s, &a, &it, corps).await.expect(201, "");
    // Au-delà du réglage : le code attendu, pas un 413 en texte brut d'axum.
    set_setting(&s.st, "attachment.max_file_mib", json!(10)).await;
    joindre(&s, &a, &it, piece(12 * MIB)).await.expect(413, "attachment_too_large");
}
