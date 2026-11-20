//! Politique « mot de passe unique dans l'organisation » (empreintes comparées
//! entre comptes) et nom de la personne invitée.

use super::{account, count, set_setting, srv, Account, AccountOpts, Rep, Srv};
use crate::state::AppState;
use locksy_core::{crypto, now_unix};
use rusqlite::params;
use serde_json::json;

const FP_X: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const FP_Z: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const FP_Y: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// Élément (et son coffre) inséré directement : seul son identifiant compte ici.
async fn item(st: &AppState, deleted: bool) -> String {
    let (col, id) = (crypto::new_uuid(), crypto::new_uuid());
    let (c, i) = (col.clone(), id.clone());
    st.db
        .call(move |db| {
            let now = now_unix();
            db.execute(
                "INSERT INTO collections (id, enc_name, personal, created_at, updated_at) VALUES (?1, 'x', 0, ?2, ?2)",
                params![c, now],
            )?;
            db.execute(
                "INSERT INTO items (id, collection_id, data, created_at, updated_at, deleted_at) VALUES (?1, ?2, 'x', ?3, ?3, ?4)",
                params![i, c, now, deleted.then_some(now)],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    id
}

async fn claim(s: &Srv, who: &Account, id: &str, fp: &str) -> Rep {
    s.post("/api/passwords/fingerprints", Some(&who.token), json!({ "entries": [{ "item_id": id, "fp": fp }] })).await
}

#[tokio::test]
async fn mot_de_passe_unique_entre_comptes() {
    let s = srv().await;
    let (a, b) = (account(&s.st, &AccountOpts::default()).await, account(&s.st, &AccountOpts::default()).await);
    let (ia, ib, ib2) = (item(&s.st, false).await, item(&s.st, false).await, item(&s.st, false).await);

    // Politique inactive : aucun conflit, rien n'est conservé, pas de poivre.
    assert_eq!(claim(&s, &a, &ia, FP_X).await.expect(200, "")["conflicts"], json!([]));
    assert_eq!(claim(&s, &b, &ib, FP_X).await.expect(200, "")["conflicts"], json!([]));
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM password_fingerprints").await, 0);
    let p = s.get("/api/passwords/pepper", Some(&a.token)).await;
    assert_eq!(p.expect(200, "")["enabled"], false);
    assert!(p.body.get("pepper").is_none());

    // Politique active : le même mot de passe chez un autre compte est refusé.
    set_setting(&s.st, "passwords.unique_across_users", json!(true)).await;
    let p = s.get("/api/passwords/pepper", Some(&a.token)).await;
    assert_eq!(p.expect(200, "")["enabled"], true);
    assert!(p.body["pepper"].as_str().is_some_and(|x| x.len() >= 40));
    assert_eq!(claim(&s, &a, &ia, FP_X).await.expect(200, "")["conflicts"], json!([]));
    assert_eq!(claim(&s, &b, &ib, FP_X).await.expect(200, "")["conflicts"], json!([ib.clone()]));
    // Un autre mot de passe passe ; le premier compte peut revalider le sien.
    assert_eq!(claim(&s, &b, &ib, FP_Y).await.expect(200, "")["conflicts"], json!([]));
    assert_eq!(claim(&s, &a, &ia, FP_X).await.expect(200, "")["conflicts"], json!([]));
    // Le même compte peut réutiliser son propre mot de passe (le Bilan s'en charge).
    assert_eq!(claim(&s, &a, &ib2, FP_X).await.expect(200, "")["conflicts"], json!([]));
    // Élément supprimé : son mot de passe est de nouveau libre.
    let del = item(&s.st, true).await;
    assert_eq!(claim(&s, &b, &del, FP_Z).await.expect(200, "")["conflicts"], json!([]));
    assert_eq!(claim(&s, &a, &ib2, FP_Z).await.expect(200, "")["conflicts"], json!([]));

    // Entrées invalides et accès sans session.
    claim(&s, &a, &ia, "pas-une-empreinte").await.expect(400, "bad_request");
    s.post("/api/passwords/fingerprints", Some(&a.token), json!({ "entries": [] })).await.expect(400, "bad_request");
    assert_eq!(s.post("/api/passwords/fingerprints", None, json!({ "entries": [] })).await.status, 401);
    assert_eq!(s.get("/api/passwords/pepper", None).await.status, 401);
}

#[tokio::test]
async fn nom_de_la_personne_invitee() {
    let s = srv().await;
    let owner = account(&s.st, &AccountOpts { role: "owner", ..Default::default() }).await;
    let t = Some(owner.token.as_str());
    let r = s
        .post(
            "/api/admin/invites/batch",
            t,
            json!({ "emails": ["alex@exemple.fr", "sans.nom@exemple.fr"], "names": ["Alex Martin"], "role": "user" }),
        )
        .await;
    let created = r.expect(200, "")["created"].as_array().unwrap().clone();
    assert_eq!(created.len(), 2);
    let token = |i: usize| created[i]["link"].as_str().unwrap().rsplit('/').next().unwrap().to_string();
    let info = s.get(&format!("/api/invites/{}", token(0)), None).await;
    assert_eq!(info.expect(200, "")["name"], "Alex Martin");
    assert_eq!(s.get(&format!("/api/invites/{}", token(1)), None).await.expect(200, "")["name"], "");
    // Invitation unitaire avec un nom.
    let r = s.post("/api/admin/invites", t, json!({ "email": "solo@exemple.fr", "role": "user", "name": "Sam Durand" })).await;
    let tok = r.expect(200, "")["token"].as_str().unwrap().to_string();
    assert_eq!(s.get(&format!("/api/invites/{tok}"), None).await.expect(200, "")["name"], "Sam Durand");
    // Nom illisible (caractère de contrôle) : refusé pour l'invitation unitaire.
    s.post("/api/admin/invites", t, json!({ "email": "x@exemple.fr", "role": "user", "name": "A\u{7}B" })).await.expect(400, "bad_request");
}
