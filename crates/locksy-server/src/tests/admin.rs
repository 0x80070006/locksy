//! Tests du domaine « admin » (lot L5) : personnes, fiche, actions de masse,
//! invitations, départ de l'entreprise, statistiques, journal et exports.

use super::{account, count, set_setting, srv, srv_with, Account, AccountOpts, Srv};
use crate::error::ApiResult;
use crate::mail::{Notification, Notifier, NotifyOutcome};
use crate::security::{issue_step_up, sha256_hex};
use crate::state::{audit, AppState, AuthUser, ClientMeta};
use locksy_core::crypto::new_uuid;
use locksy_core::now_unix;
use locksy_core::settings::Effective;
use reqwest::Method;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

// ------------------------------------------------------------ Outils du lot

async fn acc(st: &AppState, role: &'static str) -> Account {
    account(st, &AccountOpts { role, ..Default::default() }).await
}

/// Exécute du SQL de préparation sur l'écrivain.
async fn exec(st: &AppState, f: impl FnOnce(&Connection) -> rusqlite::Result<()> + Send + 'static) {
    st.db.call(move |c| Ok(f(c)?)).await.unwrap();
}

/// Valeur entière d'une requête paramétrée par un identifiant.
async fn int(st: &AppState, sql: &'static str, id: &str) -> i64 {
    let id = id.to_string();
    st.db.read(move |c| Ok(c.query_row(sql, [id], |r| r.get(0))?)).await.unwrap()
}

/// Jeton de réauthentification délivré pour la session du compte.
async fn step_up(st: &AppState, a: &Account, action: &'static str) -> String {
    let sid: String = st
        .db
        .read({
            let id = a.id.clone();
            move |c| Ok(c.query_row("SELECT id FROM sessions WHERE user_id = ?1 LIMIT 1", [id], |r| r.get(0))?)
        })
        .await
        .unwrap();
    issue_step_up(&a.id, &sid, action)
}

/// Coffre dont `members` sont membres (identifiant, rôle), avec `items` éléments.
async fn collection(st: &AppState, members: &[(&str, &str)], items: usize, personal: bool) -> String {
    let cid = new_uuid();
    let members: Vec<(String, String)> = members.iter().map(|(u, r)| (u.to_string(), r.to_string())).collect();
    let c2 = cid.clone();
    exec(st, move |c| {
        c.execute(
            "INSERT INTO collections (id, enc_name, personal, created_at, updated_at) VALUES (?1, 'NOM-SECRET-COFFRE', ?2, 0, 0)",
            params![c2, personal],
        )?;
        for (i, (u, r)) in members.iter().enumerate() {
            c.execute(
                "INSERT INTO memberships (collection_id, user_id, role, sealed_key, created_at) VALUES (?1, ?2, ?3, 'k', ?4)",
                params![c2, u, r, i as i64],
            )?;
        }
        for _ in 0..items {
            c.execute(
                "INSERT INTO items (id, collection_id, data, created_at, updated_at) VALUES (?1, ?2, 'DONNEE-SECRETE', 0, 0)",
                params![new_uuid(), c2],
            )?;
        }
        Ok(())
    })
    .await;
    cid
}

/// Lien de partage actif créé par `owner`.
async fn share(st: &AppState, owner: &str) {
    let owner = owner.to_string();
    exec(st, move |c| {
        c.execute(
            "INSERT INTO shares (id, owner_id, data, created_at, expires_at, max_views) VALUES (?1, ?2, 'x', 0, ?3, 5)",
            params![new_uuid(), owner, now_unix() + 3600],
        )?;
        Ok(())
    })
    .await;
}

/// Notificateur de test : garde les notifications reçues, toutes « en file ».
#[derive(Default)]
struct Capture(Mutex<Vec<Notification>>);

impl Notifier for Capture {
    fn enqueue(&self, _c: &Connection, _settings: &Effective, n: &Notification) -> ApiResult<NotifyOutcome> {
        self.0.lock().unwrap().push(n.clone());
        Ok(NotifyOutcome::Queued)
    }
}

async fn srv_capture() -> (Srv, Arc<Capture>) {
    let cap = Arc::new(Capture::default());
    let n = cap.clone();
    (srv_with(move |st| st.notifier = n).await, cap)
}

fn ids(rows: &Value) -> Vec<String> {
    rows["rows"].as_array().unwrap().iter().map(|r| r["id"].as_str().unwrap().to_string()).collect()
}

/// Empreinte des tables qu'un départ modifie (simulation : identique).
async fn fingerprint(st: &AppState) -> String {
    st.db
        .read(|c| {
            let mut out = String::new();
            for sql in [
                "SELECT id || role || disabled || COALESCE(disabled_reason, '') || COALESCE(deprovision_at, '') FROM users ORDER BY id",
                "SELECT collection_id || user_id || role FROM memberships ORDER BY collection_id, user_id",
                "SELECT id FROM sessions ORDER BY id",
                "SELECT id || state || data FROM shares ORDER BY id",
                "SELECT id || COALESCE(rotation_suggested_at, '') FROM collections ORDER BY id",
                "SELECT CAST(COUNT(*) AS TEXT) FROM audit",
            ] {
                let rows: Vec<String> = c.prepare(sql)?.query_map([], |r| r.get::<_, String>(0))?.collect::<Result<_, _>>()?;
                out.push_str(&rows.join(","));
                out.push('|');
            }
            Ok(out)
        })
        .await
        .unwrap()
}

/// Lignes d'un CSV (BOM retiré, CRLF).
fn csv_lines(body: &Value) -> Vec<String> {
    let s = body.as_str().expect("CSV");
    let s = s.strip_prefix('\u{feff}').expect("BOM");
    s.split("\r\n").filter(|l| !l.is_empty()).map(str::to_string).collect()
}

// ------------------------------------------------------------ Droits

#[tokio::test]
async fn routes_reservees_aux_administrateurs() {
    let s = srv().await;
    let user = acc(&s.st, "user").await;
    let other = acc(&s.st, "user").await;
    let (u, inv) = (&other.id, new_uuid());
    let routes: Vec<(Method, String, Option<Value>)> = vec![
        (Method::GET, "/api/admin/people".into(), None),
        (Method::GET, format!("/api/admin/users/{u}"), None),
        (Method::PATCH, format!("/api/admin/users/{u}"), Some(json!({ "name": "X" }))),
        (Method::DELETE, format!("/api/admin/users/{u}/sessions/{}", new_uuid()), None),
        (Method::POST, "/api/admin/users/bulk".into(), Some(json!({ "ids": [u], "action": "disable" }))),
        (Method::POST, "/api/admin/invites/batch".into(), Some(json!({ "emails": ["a@exemple.fr"], "role": "user" }))),
        (Method::POST, format!("/api/admin/invites/{inv}/resend"), Some(json!({}))),
        (Method::GET, format!("/api/admin/users/{u}/offboard-plan"), None),
        (Method::POST, format!("/api/admin/users/{u}/offboard?dry_run=true"), Some(json!({}))),
        (Method::GET, format!("/api/admin/users/{u}/access-report.csv"), None),
    ];
    for (m, path, body) in &routes {
        let anon = s.req(m.clone(), path, None, body.as_ref(), &[]).await;
        assert_eq!(anon.status, 401, "{m} {path} anonyme");
        s.req(m.clone(), path, Some(&user.token), body.as_ref(), &[]).await.expect(403, "forbidden");
    }
    // Rien n'a changé pour le compte visé.
    assert_eq!(int(&s.st, "SELECT disabled FROM users WHERE id = ?1", u).await, 0);
}

#[tokio::test]
async fn admin_non_proprietaire_sur_action_de_proprietaire() {
    let s = srv().await;
    let admin = acc(&s.st, "admin").await;
    let owner = acc(&s.st, "owner").await;
    let peer = acc(&s.st, "admin").await;
    let user = acc(&s.st, "user").await;
    let t = Some(admin.token.as_str());
    // Toucher un propriétaire ou un administrateur.
    s.patch(&format!("/api/admin/users/{}", owner.id), t, json!({ "email": "x@exemple.fr" }), &[]).await.expect(403, "owner_only");
    s.put(&format!("/api/admin/users/{}", peer.id), t, json!({ "disabled": true })).await.expect(403, "owner_only");
    s.post(&format!("/api/admin/users/{}/revoke-sessions", owner.id), t, json!({})).await.expect(403, "owner_only");
    s.post(&format!("/api/admin/users/{}/offboard?dry_run=true", owner.id), t, json!({})).await.expect(403, "owner_only");
    s.req(Method::DELETE, &format!("/api/admin/users/{}", owner.id), t, None, &[]).await.expect(403, "owner_only");
    // Nommer un administrateur : refusé AVANT de demander la confirmation.
    s.put(&format!("/api/admin/users/{}", user.id), t, json!({ "role": "admin" })).await.expect(403, "owner_only");
    s.post("/api/admin/invites", t, json!({ "email": "n@exemple.fr", "role": "admin" })).await.expect(403, "owner_only");
    s.post("/api/admin/invites/batch", t, json!({ "emails": ["n@exemple.fr"], "role": "admin" })).await.expect(403, "owner_only");
    // En masse : ignorés avec la raison.
    let r = s.post("/api/admin/users/bulk", t, json!({ "ids": [owner.id, peer.id, user.id], "action": "revoke_sessions" })).await;
    let b = r.expect(200, "");
    assert_eq!(b["done"], json!([user.id]));
    assert_eq!(b["skipped"], json!([{ "id": owner.id, "reason": "owner_only" }, { "id": peer.id, "reason": "owner_only" }]));
    assert_eq!(int(&s.st, "SELECT COUNT(*) FROM sessions WHERE user_id = ?1", &owner.id).await, 1);
}

#[tokio::test]
async fn garde_fous_soi_meme_et_dernier_proprietaire() {
    let s = srv().await;
    let me = acc(&s.st, "owner").await;
    let t = Some(me.token.as_str());
    let path = format!("/api/admin/users/{}", me.id);
    s.put(&path, t, json!({ "disabled": true })).await.expect(409, "self_action");
    s.put(&path, t, json!({ "role": "user" })).await.expect(409, "self_action");
    s.req(Method::DELETE, &path, t, None, &[]).await.expect(409, "self_action");
    s.patch(&path, t, json!({ "access_until": now_unix() + 3600 }), &[]).await.expect(409, "self_action");
    s.post(&format!("{path}/offboard?dry_run=true"), t, json!({})).await.expect(409, "self_action");
    // Son propre nom reste modifiable.
    s.patch(&path, t, json!({ "name": "Camille" }), &[]).await.expect(200, "");

    // Dernier propriétaire actif : protégé même si l'acteur a perdu son rôle
    // entre-temps (course), en unitaire comme dans les fonctions partagées.
    let other = acc(&s.st, "owner").await;
    let ghost = AuthUser {
        id: new_uuid(),
        email: "x@exemple.fr".into(),
        role: "owner".into(),
        session_id: String::new(),
        meta: ClientMeta { ip: String::new(), user_agent: String::new() },
    };
    let (oid, mid) = (other.id.clone(), me.id.clone());
    let r = s
        .st
        .db
        .call(move |c| {
            c.execute("UPDATE users SET role = 'admin' WHERE id = ?1", [&mid])?;
            let refus = crate::admin::refusal(c, &ghost, &oid, "owner", crate::admin::Act::Disable)?;
            let demote = crate::admin::refusal(c, &ghost, &oid, "owner", crate::admin::Act::SetRole("admin"))?;
            let touch = crate::admin::refusal(c, &ghost, &oid, "owner", crate::admin::Act::Touch)?;
            let set = crate::admin::set_disabled_reason(c, &oid, "owner", true, "scim").unwrap_err();
            let del = crate::admin::remove_user(c, &oid, "owner").unwrap_err();
            Ok((refus, demote, touch, set.code, del.code))
        })
        .await
        .unwrap();
    use crate::admin::Refusal::LastOwner;
    assert_eq!(r, (Some(LastOwner), Some(LastOwner), None, "last_owner", "last_owner"));
}

// ------------------------------------------------------------ Rôles et confirmation d'identité

#[tokio::test]
async fn elevation_de_role_exige_une_confirmation() {
    let s = srv().await;
    let owner = acc(&s.st, "owner").await;
    let user = acc(&s.st, "user").await;
    let t = Some(owner.token.as_str());
    let path = format!("/api/admin/users/{}", user.id);
    let role = |st: AppState, id: String| async move { int(&st, "SELECT role = 'admin' FROM users WHERE id = ?1", &id).await };

    s.put(&path, t, json!({ "role": "admin" })).await.expect(428, "reauth_required");
    let legacy = super::reauth_header(&owner);
    s.req(Method::PUT, &path, t, Some(&json!({ "role": "admin" })), &[(legacy.0, &legacy.1)]).await.expect(403, "reauth_invalid");
    let wrong = step_up(&s.st, &owner, "admin.delete_user").await;
    s.req(Method::PUT, &path, t, Some(&json!({ "role": "admin" })), &[("x-locksy-reauth", &wrong)]).await.expect(403, "reauth_invalid");
    assert_eq!(role(s.st.clone(), user.id.clone()).await, 0);

    let ok = step_up(&s.st, &owner, "admin.role").await;
    s.req(Method::PUT, &path, t, Some(&json!({ "role": "admin" })), &[("x-locksy-reauth", &ok)]).await.expect(204, "");
    assert_eq!(role(s.st.clone(), user.id.clone()).await, 1);
    // Jeton à usage unique.
    s.req(Method::PUT, &path, t, Some(&json!({ "role": "owner" })), &[("x-locksy-reauth", &ok)]).await.expect(403, "reauth_invalid");
    // Rétrogradation : sans confirmation.
    s.put(&path, t, json!({ "role": "user" })).await.expect(204, "");
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'admin.user_role'").await, 2);

    // En masse.
    let bulk = json!({ "ids": [user.id], "action": "set_role", "role": "admin" });
    s.post("/api/admin/users/bulk", t, bulk.clone()).await.expect(428, "reauth_required");
    let ok = step_up(&s.st, &owner, "admin.role").await;
    let r = s.req(Method::POST, "/api/admin/users/bulk", t, Some(&bulk), &[("x-locksy-reauth", &ok)]).await;
    assert_eq!(r.expect(200, "")["done"], json!([user.id]));
    // Même rôle : ignoré (« unchanged »).
    let ok = step_up(&s.st, &owner, "admin.role").await;
    let r = s.req(Method::POST, "/api/admin/users/bulk", t, Some(&bulk), &[("x-locksy-reauth", &ok)]).await;
    assert_eq!(r.expect(200, "")["skipped"], json!([{ "id": user.id, "reason": "unchanged" }]));
    // Rôle inconnu, action inconnue, trop de comptes : 400.
    s.post("/api/admin/users/bulk", t, json!({ "ids": [user.id], "action": "set_role", "role": "chef" })).await.expect(400, "bad_request");
    s.post("/api/admin/users/bulk", t, json!({ "ids": [user.id], "action": "purge" })).await.expect(400, "bad_request");
    let many: Vec<String> = (0..501).map(|_| new_uuid()).collect();
    s.post("/api/admin/users/bulk", t, json!({ "ids": many, "action": "disable" })).await.expect(400, "bad_request");
}

#[tokio::test]
async fn suppression_et_reinitialisation_2fa_confirmees() {
    let (s, cap) = srv_capture().await;
    let owner = acc(&s.st, "owner").await;
    let user = account(&s.st, &AccountOpts { totp: true, ..Default::default() }).await;
    let t = Some(owner.token.as_str());
    let uid = user.id.clone();
    exec(&s.st, move |c| {
        c.execute("INSERT INTO totp_recovery_codes (id, user_id, code_hash, created_at) VALUES ('r', ?1, 'h', 0)", [uid])?;
        Ok(())
    })
    .await;
    let reset = format!("/api/admin/users/{}/reset-2fa", user.id);
    s.post(&reset, t, json!({})).await.expect(428, "reauth_required");
    let tok = step_up(&s.st, &owner, "admin.reset_2fa").await;
    s.req(Method::POST, &reset, t, Some(&json!({})), &[("x-locksy-reauth", &tok)]).await.expect(204, "");
    assert_eq!(int(&s.st, "SELECT COUNT(*) FROM totp_recovery_codes WHERE user_id = ?1", &user.id).await, 0);
    assert_eq!(int(&s.st, "SELECT totp_secret IS NULL FROM users WHERE id = ?1", &user.id).await, 1);
    let events: Vec<_> = cap
        .0
        .lock()
        .unwrap()
        .iter()
        .filter_map(|n| match n {
            Notification::SecurityChange { user_id, event, .. } => Some((user_id.clone(), *event)),
            _ => None,
        })
        .collect();
    assert_eq!(events, vec![(user.id.clone(), "admin.2fa_reset")]);

    let del = format!("/api/admin/users/{}", user.id);
    s.req(Method::DELETE, &del, t, None, &[]).await.expect(428, "reauth_required");
    let tok = step_up(&s.st, &owner, "admin.delete_user").await;
    s.req(Method::DELETE, &del, t, None, &[("x-locksy-reauth", &tok)]).await.expect(204, "");
    assert_eq!(int(&s.st, "SELECT COUNT(*) FROM users WHERE id = ?1", &user.id).await, 0);
    // Identifiant mal formé : 404.
    s.req(Method::DELETE, "/api/admin/users/pas-un-id", t, None, &[]).await.expect(404, "not_found");
}

#[tokio::test]
async fn actions_de_masse() {
    let s = srv().await;
    let owner = acc(&s.st, "owner").await;
    let a = acc(&s.st, "user").await;
    let b = acc(&s.st, "user").await;
    share(&s.st, &a.id).await;
    let t = Some(owner.token.as_str());
    let body = json!({ "ids": [owner.id, a.id, a.id, b.id, new_uuid(), "x"], "action": "disable" });
    let r = s.post("/api/admin/users/bulk", t, body).await;
    let r = r.expect(200, "");
    assert_eq!(r["done"], json!([a.id, b.id]));
    let skipped: Vec<(String, String)> = r["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| (x["id"].as_str().unwrap().to_string(), x["reason"].as_str().unwrap().to_string()))
        .collect();
    assert_eq!(skipped[0], (owner.id.clone(), "self".into()));
    assert_eq!(skipped.iter().filter(|x| x.1 == "not_found").count(), 2);
    // Désactivation : sessions fermées, liens révoqués, motif noté.
    assert_eq!(int(&s.st, "SELECT COUNT(*) FROM sessions WHERE user_id = ?1", &a.id).await, 0);
    assert_eq!(int(&s.st, "SELECT COUNT(*) FROM shares WHERE owner_id = ?1 AND state = 'active'", &a.id).await, 0);
    assert_eq!(int(&s.st, "SELECT disabled_at IS NOT NULL AND disabled_reason = 'admin' FROM users WHERE id = ?1", &a.id).await, 1);
    // Une ligne d'audit par compte, plus le résumé.
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'admin.user_disabled'").await, 2);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'admin.bulk_action'").await, 1);
    // Déjà désactivés : ignorés ; réactivation.
    let r = s.post("/api/admin/users/bulk", t, json!({ "ids": [a.id], "action": "disable" })).await;
    assert_eq!(r.expect(200, "")["skipped"], json!([{ "id": a.id, "reason": "unchanged" }]));
    let r = s.post("/api/admin/users/bulk", t, json!({ "ids": [a.id, b.id], "action": "enable" })).await;
    assert_eq!(r.expect(200, "")["done"], json!([a.id, b.id]));
    // Double authentification en masse : confirmation « admin.bulk ».
    s.post("/api/admin/users/bulk", t, json!({ "ids": [a.id], "action": "reset_2fa" })).await.expect(428, "reauth_required");
}

// ------------------------------------------------------------ Statistiques

#[tokio::test]
async fn taux_de_double_authentification_sur_les_comptes_actifs() {
    let s = srv().await;
    let owner = account(&s.st, &AccountOpts { role: "owner", totp: true, ..Default::default() }).await;
    let _admin = acc(&s.st, "admin").await;
    let _u = acc(&s.st, "user").await;
    // Comptes avec 2FA mais inactifs : désactivé, fin d'accès passée.
    account(&s.st, &AccountOpts { totp: true, disabled: true, ..Default::default() }).await;
    let expired = account(&s.st, &AccountOpts { totp: true, ..Default::default() }).await;
    let id = expired.id.clone();
    exec(&s.st, move |c| {
        c.execute("UPDATE users SET access_until = 1 WHERE id = ?1", [id])?;
        c.execute(
            "INSERT INTO invites (id, token_hash, email, role, created_at, expires_at) VALUES ('i1', 'h1', 'a@x.fr', 'user', 0, 1)",
            [],
        )?;
        c.execute(
            "INSERT INTO invites (id, token_hash, email, role, created_at, expires_at) VALUES ('i2', 'h2', 'b@x.fr', 'user', 0, ?1)",
            [now_unix() + 3600],
        )?;
        Ok(())
    })
    .await;
    let st = s.get("/api/admin/stats", Some(&owner.token)).await;
    let v = st.expect(200, "");
    assert_eq!((v["active_users"].as_i64(), v["active_with_2fa"].as_i64()), (Some(3), Some(1)));
    assert!(v["active_with_2fa"].as_i64() <= v["active_users"].as_i64());
    assert_eq!(v["users_with_2fa"], v["active_with_2fa"]);
    assert_eq!(v["users"], 5);
    assert_eq!((v["admins_without_2fa"].as_i64(), v["owners"].as_i64()), (Some(1), Some(1)));
    assert_eq!((v["pending_invites"].as_i64(), v["expired_invites"].as_i64()), (Some(1), Some(1)));
    assert_eq!(v["inactive_users"], 0);
    assert_eq!(v["setup"]["twofa_self"], true);
    assert_eq!(v["setup"]["second_owner"], false);
    assert_eq!(v["setup"]["invites_sent"], true);
    assert_eq!(v["setup"]["siem_configured"], false);
    assert!(v["last_ldap_sync"].is_null() && v["last_backup_at"].is_null());
}

// ------------------------------------------------------------ Liste des personnes

#[tokio::test]
async fn pagination_stable() {
    let s = srv().await;
    let owner = acc(&s.st, "owner").await;
    for _ in 0..7 {
        acc(&s.st, "user").await;
    }
    exec(&s.st, |c| {
        c.execute("UPDATE users SET name = 'Dupont'", [])?;
        Ok(())
    })
    .await;
    let t = Some(owner.token.as_str());
    let p1 = s.get("/api/admin/people?par_page=5&page=1", t).await;
    let p1 = p1.expect(200, "").clone();
    let p2 = s.get("/api/admin/people?par_page=5&page=2", t).await;
    let p2 = p2.expect(200, "").clone();
    assert_eq!((p1["total"].as_i64(), p1["per_page"].as_i64(), p2["page"].as_i64()), (Some(8), Some(5), Some(2)));
    let (a, b) = (ids(&p1), ids(&p2));
    assert_eq!((a.len(), b.len()), (5, 3));
    let all: HashSet<_> = a.iter().chain(&b).collect();
    assert_eq!(all.len(), 8, "aucun doublon entre les pages");
    // Égalité de nom : départagée par l'identifiant.
    let mut sorted = a.clone();
    sorted.extend(b.clone());
    let mut expected = sorted.clone();
    expected.sort();
    assert_eq!(sorted, expected);
    // Page au-delà de la fin : vide.
    assert_eq!(ids(s.get("/api/admin/people?par_page=5&page=3", t).await.expect(200, "")).len(), 0);
    // Paramètres invalides : 400.
    for q in ["page=0", "par_page=101", "etat=perdu", "tri=taille", "2fa=1", "origine=ad", "role=chef"] {
        s.get(&format!("/api/admin/people?{q}"), t).await.expect(400, "bad_request");
    }
}

#[tokio::test]
async fn filtres_et_statuts_calcules() {
    let s = srv().await;
    let owner = account(&s.st, &AccountOpts { role: "owner", totp: true, ..Default::default() }).await;
    let disabled = account(&s.st, &AccountOpts { disabled: true, ..Default::default() }).await;
    let expired = acc(&s.st, "user").await;
    let old = account(&s.st, &AccountOpts { created_at: Some(1000), ..Default::default() }).await;
    let gone = account(&s.st, &AccountOpts { disabled: true, ..Default::default() }).await;
    let sso = acc(&s.st, "user").await;
    let ldap = acc(&s.st, "admin").await;
    let invited = acc(&s.st, "user").await;
    let (e, o, g, so, l, i) =
        (expired.id.clone(), old.id.clone(), gone.id.clone(), sso.id.clone(), ldap.id.clone(), invited.email.clone());
    exec(&s.st, move |c| {
        c.execute("UPDATE users SET access_until = 10 WHERE id = ?1", [&e])?;
        c.execute("DELETE FROM sessions WHERE user_id = ?1", [&o])?;
        c.execute("UPDATE users SET deprovision_at = ?1 WHERE id = ?2", params![now_unix() + 86_400, g])?;
        c.execute("UPDATE users SET sso_subject = 'sub-1' WHERE id = ?1", [&so])?;
        c.execute(
            "INSERT INTO directory_users (id, email, user_id, created_at, updated_at, source) VALUES ('d1', 'l@x.fr', ?1, 0, 0, 'ldap')",
            [&l],
        )?;
        c.execute(
            "INSERT INTO invites (id, token_hash, email, role, created_at, expires_at, used_at) VALUES (?1, 'hu', ?2, 'user', 0, 1, 5)",
            params![new_uuid(), i],
        )?;
        c.execute(
            "INSERT INTO invites (id, token_hash, email, role, created_at, expires_at) VALUES (?1, 'h1', 'zz-attente@x.fr', 'user', 0, ?2)",
            params![new_uuid(), now_unix() + 3600],
        )?;
        c.execute(
            "INSERT INTO invites (id, token_hash, email, role, created_at, expires_at) VALUES (?1, 'h2', 'zz-expiree@x.fr', 'user', 0, 5)",
            [new_uuid()],
        )?;
        Ok(())
    })
    .await;
    let t = Some(owner.token.as_str());
    let get = |q: &'static str| {
        let s = &s;
        async move { s.get(&format!("/api/admin/people?{q}"), t).await.expect(200, "").clone() }
    };
    let all = get("").await;
    assert_eq!(all["total"], 10);
    let me = all["rows"].as_array().unwrap().iter().find(|r| r["id"] == json!(owner.id)).unwrap().clone();
    assert_eq!((me["is_self"].as_bool(), me["twofa"].as_bool(), me["status"].as_str()), (Some(true), Some(true), Some("active")));
    assert_eq!(ids(&get("etat=desactive").await), vec![disabled.id.clone()]);
    assert_eq!(ids(&get("etat=expire").await), vec![expired.id.clone()]);
    assert_eq!(ids(&get("etat=inactif").await), vec![old.id.clone()]);
    assert_eq!(ids(&get("etat=suppression_programmee").await), vec![gone.id.clone()]);
    let inv = get("etat=invite").await;
    assert_eq!(inv["rows"][0]["email"], "zz-attente@x.fr");
    assert_eq!((inv["rows"][0]["kind"].as_str(), inv["total"].as_i64()), (Some("invite"), Some(1)));
    assert_eq!(get("etat=invitation_expiree").await["rows"][0]["email"], "zz-expiree@x.fr");
    assert_eq!(get("etat=actif").await["total"], 4);
    assert_eq!(ids(&get("2fa=oui").await), vec![owner.id.clone()]);
    assert_eq!(get("2fa=non").await["total"], 7);
    assert_eq!(ids(&get("origine=sso").await), vec![sso.id.clone()]);
    assert_eq!(ids(&get("origine=ldap").await), vec![ldap.id.clone()]);
    // Origine « invitation » : comptes nés d'une invitation acceptée, plus
    // les invitations encore en attente (même origine dans la liste).
    let by_invite = get("origine=invite").await;
    assert_eq!(by_invite["total"], 3);
    let users: Vec<&Value> = by_invite["rows"].as_array().unwrap().iter().filter(|r| r["kind"] == "user").collect();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0]["id"], json!(invited.id));
    assert_eq!(get("origine=invite&etat=actif").await["total"], 1);
    assert_eq!(get("origine=local").await["total"], 5);
    assert_eq!(get("role=admin").await["total"], 1);
    // Recherche dans l'adresse, caractères spéciaux neutralisés.
    assert_eq!(get("q=zz-att").await["total"], 1);
    assert_eq!(get("q=%25").await["total"], 0);
    // Tri par adresse décroissante : les invitations « zz-… » en tête.
    let desc = get("tri=-email").await;
    assert_eq!(desc["rows"][0]["email"], "zz-expiree@x.fr");
    let roles: Vec<String> =
        get("tri=role").await["rows"].as_array().unwrap().iter().map(|r| r["role"].as_str().unwrap().to_string()).collect();
    assert_eq!(roles[0], "owner");
    assert_eq!(roles[1], "admin");
}

// ------------------------------------------------------------ Fiche

#[tokio::test]
async fn fiche_et_modification_d_une_personne() {
    let s = srv().await;
    let owner = acc(&s.st, "owner").await;
    let user = account(&s.st, &AccountOpts { totp: true, ..Default::default() }).await;
    let taken = acc(&s.st, "user").await;
    let col = collection(&s.st, &[(&user.id, "manager"), (&taken.id, "reader")], 3, false).await;
    let t = Some(owner.token.as_str());
    let path = format!("/api/admin/users/{}", user.id);
    let d = s.get(&path, t).await;
    let d = d.expect(200, "").clone();
    assert_eq!((d["id"].as_str(), d["status"].as_str(), d["recovery_codes_remaining"].as_i64()), (Some(user.id.as_str()), Some("active"), Some(0)));
    assert_eq!(d["sessions"].as_array().unwrap().len(), 1);
    assert_eq!(d["sessions"][0]["current"], false);
    let c = &d["collections"][0];
    assert_eq!((c["id"].as_str(), c["members_count"].as_i64(), c["items_count"].as_i64()), (Some(col.as_str()), Some(2), Some(3)));
    assert_eq!((c["sole_manager"].as_bool(), c["shared"].as_bool()), (Some(true), Some(true)));
    // Sa propre fiche : la session courante est signalée.
    let mine = s.get(&format!("/api/admin/users/{}", owner.id), t).await;
    assert_eq!(mine.expect(200, "")["sessions"][0]["current"], true);
    s.get(&format!("/api/admin/users/{}", new_uuid()), t).await.expect(404, "not_found");

    // Modification : adresse prise, domaine refusé, puis succès.
    s.patch(&path, t, json!({ "email": taken.email }), &[]).await.expect(409, "email_taken");
    set_setting(&s.st, "access.allowed_email_domains", json!(["acme.fr"])).await;
    s.patch(&path, t, json!({ "email": "lea@ailleurs.fr" }), &[]).await.expect(403, "domain_not_allowed");
    let r = s.patch(&path, t, json!({ "name": "Léa Petit", "email": "Lea@ACME.fr", "access_until": now_unix() + 86_400 }), &[]).await;
    let r = r.expect(200, "");
    assert_eq!((r["kind"].as_str(), r["name"].as_str(), r["email"].as_str()), (Some("user"), Some("Léa Petit"), Some("lea@acme.fr")));
    assert!(r["access_until"].is_i64());
    let details: String = s
        .st
        .db
        .read(|c| Ok(c.query_row("SELECT details FROM audit WHERE action = 'admin.user_updated'", [], |r| r.get(0))?))
        .await
        .unwrap();
    assert_eq!(details, "champs : nom, e-mail, fin d'accès");
    // Fin d'accès passée : statut « expired », sessions fermées.
    let r = s.patch(&path, t, json!({ "access_until": 100 }), &[]).await;
    assert_eq!(r.expect(200, "")["status"], "expired");
    assert_eq!(int(&s.st, "SELECT COUNT(*) FROM sessions WHERE user_id = ?1", &user.id).await, 0);
    let r = s.patch(&path, t, json!({ "access_until": null }), &[]).await;
    assert!(r.expect(200, "")["access_until"].is_null());

    // Fermeture d'une session précise.
    let sid: String = s
        .st
        .db
        .read({
            let id = taken.id.clone();
            move |c| Ok(c.query_row("SELECT id FROM sessions WHERE user_id = ?1", [id], |r| r.get(0))?)
        })
        .await
        .unwrap();
    let close = format!("/api/admin/users/{}/sessions/{sid}", taken.id);
    s.delete(&close, t).await.expect(204, "");
    s.delete(&close, t).await.expect(404, "not_found");
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'admin.user_session_closed'").await, 1);
}

// ------------------------------------------------------------ Invitations

#[tokio::test]
async fn invitations_par_lot_et_renvoi() {
    let (s, cap) = srv_capture().await;
    let owner = acc(&s.st, "owner").await;
    let existing = acc(&s.st, "user").await;
    let t = Some(owner.token.as_str());
    set_setting(&s.st, "invite.ttl_days", json!(3)).await;
    set_setting(&s.st, "access.allowed_email_domains", json!(["exemple.fr"])).await;
    let before = now_unix();
    let r = s
        .post(
            "/api/admin/invites/batch",
            t,
            json!({
                "emails": ["a@exemple.fr", "A@Exemple.fr", "pas une adresse", "c@ailleurs.com", existing.email],
                "role": "user"
            }),
        )
        .await;
    let r = r.expect(200, "").clone();
    let created = r["created"].as_array().unwrap();
    assert_eq!(created.len(), 1);
    let inv = &created[0];
    assert_eq!((inv["email"].as_str(), inv["mailed"].as_bool()), (Some("a@exemple.fr"), Some(true)));
    let link = inv["link"].as_str().unwrap();
    assert!(link.contains("/#/inscription/"), "{link}");
    let exp = inv["expires_at"].as_i64().unwrap();
    assert!((before + 3 * 86_400..=now_unix() + 3 * 86_400).contains(&exp), "durée invite.ttl_days");
    let reasons: Vec<&str> = r["skipped"].as_array().unwrap().iter().map(|x| x["reason"].as_str().unwrap()).collect();
    assert_eq!(reasons, vec!["invited", "invalid", "domain_not_allowed", "exists"]);
    // Déjà invitée : ignorée au lot suivant.
    let r = s.post("/api/admin/invites/batch", t, json!({ "emails": ["a@exemple.fr"], "role": "user" })).await;
    assert_eq!(r.expect(200, "")["skipped"][0]["reason"], "invited");
    // Invitation unitaire hors domaine : 403.
    s.post("/api/admin/invites", t, json!({ "email": "x@ailleurs.com", "role": "user" })).await.expect(403, "domain_not_allowed");
    let one = s.post("/api/admin/invites", t, json!({ "email": "b@exemple.fr", "role": "user" })).await;
    let one = one.expect(200, "");
    assert!(one["token"].as_str().is_some_and(|x| !x.is_empty()) && one["link"].is_string());
    s.post("/api/admin/invites", t, json!({ "email": existing.email, "role": "user" })).await.expect(409, "email_taken");

    // Renvoi : nouveau jeton, l'ancien ne vaut plus.
    let id = inv["id"].as_str().unwrap().to_string();
    let old_token = link.rsplit('/').next().unwrap().to_string();
    let r = s.post(&format!("/api/admin/invites/{id}/resend"), t, json!({})).await;
    let r = r.expect(200, "").clone();
    let new_token = r["link"].as_str().unwrap().rsplit('/').next().unwrap().to_string();
    assert_ne!(old_token, new_token);
    let hash: String = s
        .st
        .db
        .read({
            let id = id.clone();
            move |c| Ok(c.query_row("SELECT token_hash FROM invites WHERE id = ?1", [id], |r| r.get(0))?)
        })
        .await
        .unwrap();
    assert_eq!(hash, sha256_hex(&new_token));
    assert_eq!(int(&s.st, "SELECT sent_count FROM invites WHERE id = ?1", &id).await, 2);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'admin.invite_resent'").await, 1);
    s.post(&format!("/api/admin/invites/{}/resend", new_uuid()), t, json!({})).await.expect(404, "not_found");
    // Un e-mail par invitation émise ou renvoyée.
    let invites = cap.0.lock().unwrap().iter().filter(|n| matches!(n, Notification::Invite { .. })).count();
    assert_eq!(invites, 3);
    // Le lien n'apparaît jamais dans le journal.
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE details LIKE '%inscription%'").await, 0);
}

// ------------------------------------------------------------ Départ de l'entreprise

#[tokio::test]
async fn depart_simulation_puis_reel() {
    let s = srv().await;
    let owner = acc(&s.st, "owner").await;
    let leaver = acc(&s.st, "user").await;
    let heir = acc(&s.st, "user").await;
    let outsider = acc(&s.st, "user").await;
    let shared = collection(&s.st, &[(&leaver.id, "manager"), (&heir.id, "reader")], 2, false).await;
    let managed = collection(&s.st, &[(&heir.id, "manager"), (&leaver.id, "editor")], 1, false).await;
    let personal = collection(&s.st, &[(&leaver.id, "manager")], 4, true).await;
    let foreign = collection(&s.st, &[(&outsider.id, "manager")], 0, false).await;
    share(&s.st, &leaver.id).await;
    let t = Some(owner.token.as_str());
    let base = format!("/api/admin/users/{}", leaver.id);

    // Plan : métadonnées et repreneurs possibles.
    let plan = s.get(&format!("{base}/offboard-plan"), t).await;
    let plan = plan.expect(200, "").clone();
    assert_eq!((plan["sessions"].as_i64(), plan["delete_after_days"].as_i64()), (Some(1), Some(30)));
    let first = &plan["collections"][0];
    assert_eq!(first["id"], json!(personal));
    assert_eq!(first["members"], json!([]));
    let c_shared = plan["collections"].as_array().unwrap().iter().find(|c| c["id"] == json!(shared)).unwrap();
    assert_eq!(c_shared["members"][0]["user_id"], json!(heir.id));
    assert_eq!(c_shared["sole_manager"], true);

    let body = json!({ "transfers": [{ "collection_id": shared, "new_manager_id": heir.id }] });
    // Transferts refusés.
    let bad = |cid: &str, uid: &str| json!({ "transfers": [{ "collection_id": cid, "new_manager_id": uid }] });
    s.post(&format!("{base}/offboard?dry_run=true"), t, bad(&shared, &outsider.id)).await.expect(422, "not_a_member");
    s.post(&format!("{base}/offboard?dry_run=true"), t, bad(&foreign, &outsider.id)).await.expect(422, "invalid_transfer");
    s.post(&format!("{base}/offboard?dry_run=true"), t, bad(&shared, &leaver.id)).await.expect(422, "invalid_transfer");
    s.post(&format!("{base}/offboard?dry_run=true"), t, json!({ "delete_after_days": 400 })).await.expect(400, "bad_request");

    // Simulation : rapport complet, aucune écriture.
    let before = fingerprint(&s.st).await;
    let sim = s.post(&format!("{base}/offboard?dry_run=true"), t, body.clone()).await;
    let sim = sim.expect(200, "").clone();
    assert_eq!(fingerprint(&s.st).await, before, "simulation sans écriture");
    let rep = &sim["report"];
    assert_eq!((rep["disabled"].as_bool(), rep["sessions_closed"].as_i64(), rep["transferred"].as_i64()), (Some(true), Some(1), Some(1)));
    assert_eq!((rep["rotation_suggested"].as_i64(), rep["shares_revoked"].as_i64()), (Some(2), Some(1)));
    assert_eq!(rep["orphaned"], json!([{ "collection_id": personal, "items_count": 4 }]));
    assert_eq!(sim["report_csv"], json!(format!("/api/admin/users/{}/access-report.csv", leaver.id)));

    // Réel : confirmation exigée, puis même rapport.
    s.post(&format!("{base}/offboard?dry_run=false"), t, body.clone()).await.expect(428, "reauth_required");
    assert_eq!(fingerprint(&s.st).await, before);
    let tok = step_up(&s.st, &owner, "admin.offboard").await;
    let real = s.req(Method::POST, &format!("{base}/offboard"), t, Some(&body), &[("x-locksy-reauth", &tok)]).await;
    let real = real.expect(200, "").clone();
    let mut expected = sim["report"].clone();
    let mut got = real["report"].clone();
    // L'échéance peut différer d'une seconde entre les deux appels.
    let (e, g) = (expected["deprovision_at"].as_i64().unwrap(), got["deprovision_at"].as_i64().unwrap());
    assert!((g - e).abs() <= 2);
    expected["deprovision_at"] = Value::Null;
    got["deprovision_at"] = Value::Null;
    assert_eq!(got, expected);

    // État de la base cohérent avec le rapport.
    let heir_role: String = s
        .st
        .db
        .read({
            let (c, u) = (shared.clone(), heir.id.clone());
            move |db| Ok(db.query_row("SELECT role FROM memberships WHERE collection_id = ?1 AND user_id = ?2", [c, u], |r| r.get(0))?)
        })
        .await
        .unwrap();
    assert_eq!(heir_role, "manager");
    assert_eq!(int(&s.st, "SELECT disabled = 1 AND disabled_reason = 'offboard' FROM users WHERE id = ?1", &leaver.id).await, 1);
    assert_eq!(int(&s.st, "SELECT COUNT(*) FROM sessions WHERE user_id = ?1", &leaver.id).await, 0);
    assert_eq!(int(&s.st, "SELECT COUNT(*) FROM shares WHERE owner_id = ?1 AND state = 'active'", &leaver.id).await, 0);
    assert_eq!(int(&s.st, "SELECT rotation_suggested_at IS NOT NULL FROM collections WHERE id = ?1", &shared).await, 1);
    assert_eq!(int(&s.st, "SELECT rotation_suggested_at IS NOT NULL FROM collections WHERE id = ?1", &managed).await, 1);
    assert_eq!(int(&s.st, "SELECT rotation_suggested_at IS NULL FROM collections WHERE id = ?1", &personal).await, 1);
    let dep = int(&s.st, "SELECT deprovision_at FROM users WHERE id = ?1", &leaver.id).await;
    assert!((dep - now_unix() - 30 * 86_400).abs() <= 5);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'admin.user_offboarded'").await, 1);
    // Aucune clé transmise : la clé scellée du repreneur est inchangée.
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM memberships WHERE sealed_key <> 'k'").await, 0);

    // Rapport d'accès : un coffre par ligne, actions consignées, séparateur réglé.
    set_setting(&s.st, "audit.csv_separator", json!("comma")).await;
    let csv = s.get(&format!("{base}/access-report.csv"), t).await;
    assert_eq!(csv.status, 200);
    assert!(csv.header("content-type").unwrap().starts_with("text/csv"));
    let lines = csv_lines(&csv.body);
    assert_eq!(lines[0], "coffre,role,membres,elements,seul_gestionnaire,derniere_connexion,actions");
    assert_eq!(lines.len(), 4);
    let line_of = |cid: &str| lines.iter().find(|l| l.starts_with(&format!("\"{cid}\""))).unwrap().clone();
    assert!(line_of(&shared).ends_with(&format!("\"repreneur : {}, rotation conseillée\"", heir.id)), "{}", line_of(&shared));
    assert!(line_of(&personal).contains("\"manager\",1,4,\"oui\""), "{}", line_of(&personal));
    assert!(line_of(&personal).ends_with("\"aucun autre membre : supprimé avec le compte\""));
    assert!(line_of(&managed).ends_with("\"rotation conseillée\""));
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'admin.access_report_exported'").await, 1);
}

#[tokio::test]
async fn depart_avec_suppression_immediate() {
    let s = srv().await;
    let owner = acc(&s.st, "owner").await;
    let leaver = acc(&s.st, "user").await;
    collection(&s.st, &[(&leaver.id, "manager")], 1, true).await;
    let t = Some(owner.token.as_str());
    let path = format!("/api/admin/users/{}/offboard", leaver.id);
    let body = json!({ "delete_after_days": 0 });
    // La confirmation « admin.offboard » ne suffit pas pour une suppression immédiate.
    let tok = step_up(&s.st, &owner, "admin.offboard").await;
    s.req(Method::POST, &path, t, Some(&body), &[("x-locksy-reauth", &tok)]).await.expect(403, "reauth_invalid");
    let tok = step_up(&s.st, &owner, "admin.delete_user").await;
    s.req(Method::POST, &path, t, Some(&body), &[("x-locksy-reauth", &tok)]).await.expect(200, "");
    assert_eq!(int(&s.st, "SELECT COUNT(*) FROM users WHERE id = ?1", &leaver.id).await, 0);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM collections").await, 0);
}

#[tokio::test]
async fn aucun_nom_de_coffre_ni_d_element_dans_les_reponses() {
    let s = srv().await;
    let owner = acc(&s.st, "owner").await;
    let user = acc(&s.st, "user").await;
    collection(&s.st, &[(&user.id, "manager"), (&owner.id, "reader")], 2, false).await;
    let t = Some(owner.token.as_str());
    for path in [
        "/api/admin/people".to_string(),
        format!("/api/admin/users/{}", user.id),
        format!("/api/admin/users/{}/offboard-plan", user.id),
        format!("/api/admin/users/{}/access-report.csv", user.id),
        "/api/admin/stats".to_string(),
    ] {
        let r = s.get(&path, t).await;
        assert_eq!(r.status, 200, "{path}");
        let text = r.body.to_string();
        for secret in ["NOM-SECRET-COFFRE", "DONNEE-SECRETE", "enc_name", "sealed_key"] {
            assert!(!text.contains(secret), "{path} contient {secret}");
        }
    }
}

// ------------------------------------------------------------ Journal

#[tokio::test]
async fn journal_filtre_par_gravite_acteur_type_et_curseur() {
    let s = srv().await;
    let owner = acc(&s.st, "owner").await;
    let user = acc(&s.st, "user").await;
    let (uid, uemail) = (user.id.clone(), user.email.clone());
    exec(&s.st, move |c| {
        let meta = ClientMeta { ip: "203.0.113.9".into(), user_agent: "test".into() };
        let rows: [(Option<&str>, &str, &str, &str); 6] = [
            (None, "", "settings.lowered", "twofa.required"),
            (Some(&uid), &uemail, "login.failed", "=1+1"),
            (Some(&uid), &uemail, "login.success", "+33 6"),
            (Some(&uid), &uemail, "item.created", "-2"),
            (None, "", "admin.user_role", "@SUM(A1)"),
            (Some(&uid), &uemail, "2fa.disabled", "imposée"),
        ];
        for (u, e, action, details) in rows {
            audit(c, u, e, action, "cible", &meta, details).map_err(|_| rusqlite::Error::InvalidQuery)?;
        }
        Ok(())
    })
    .await;
    let t = Some(owner.token.as_str());
    let get = |q: String| {
        let s = &s;
        async move { s.get(&format!("/api/admin/audit?{q}"), t).await.expect(200, "").clone() }
    };
    let crit = get("severity=critical".into()).await;
    let actions: Vec<&str> = crit["entries"].as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap()).collect();
    assert_eq!(actions, vec!["2fa.disabled", "admin.user_role", "settings.lowered"]);
    assert!(crit["entries"].as_array().unwrap().iter().all(|e| e["severity"] == "critical"));
    assert_eq!(crit["total"], 3);
    assert_eq!(get("severity=warning".into()).await["entries"][0]["action"], "login.failed");
    // Acteur (identifiant ou adresse) et type (famille d'actions).
    assert_eq!(get(format!("actor={}", user.id)).await["total"], 4);
    assert_eq!(get(format!("actor={}", user.email.to_uppercase())).await["total"], 4);
    assert_eq!(get("type=login".into()).await["total"], 2);
    assert_eq!(get("type=admin".into()).await["total"], 1);
    // L'ancien filtre par préfixe garde les tirets bas.
    assert_eq!(get("action=admin.user_role".into()).await["total"], 1);
    // Curseur : pages disjointes, puis fin.
    let p1 = get(format!("actor={}&limit=3", user.id)).await;
    let cursor = p1["next_cursor"].as_i64().expect("page suivante");
    let p2 = get(format!("actor={}&limit=3&before_id={cursor}", user.id)).await;
    assert_eq!(p2["entries"].as_array().unwrap().len(), 1);
    assert!(p2["next_cursor"].is_null());
    assert!(p2["entries"][0]["id"].as_i64().unwrap() < cursor);
    s.get("/api/admin/audit?severity=grave", t).await.expect(400, "bad_request");

    // Export CSV : séparateur réglé, colonnes, gravité, neutralisation.
    set_setting(&s.st, "audit.csv_separator", json!("tab")).await;
    let csv = s.get(&format!("/api/admin/audit.csv?actor={}", user.id), t).await;
    assert_eq!(csv.status, 200);
    let lines = csv_lines(&csv.body);
    assert_eq!(lines[0], "date_locale\tdate_utc\thorodatage\tutilisateur\taction\tgravite\tcible\tadresse_ip\tnavigateur\tdetails");
    assert_eq!(lines.len(), 5);
    let body = csv.body.as_str().unwrap();
    for neutralized in ["\"'=1+1\"", "\"'+33 6\"", "\"'-2\""] {
        assert!(body.contains(neutralized), "{neutralized} absent : {body}");
    }
    assert!(lines.iter().any(|l| l.contains("\"login.failed\"\t\"warning\"")));
    set_setting(&s.st, "audit.csv_separator", json!("comma")).await;
    let all = s.get("/api/admin/audit.csv", t).await;
    let all_body = all.body.as_str().unwrap().to_string();
    assert!(all_body.contains("\"'@SUM(A1)\""));
    assert!(csv_lines(&all.body)[0].starts_with("date_locale,date_utc,horodatage,"));
}

/// Dernière utilisation du jeton SCIM : lue sur le jeton lui-même.
#[tokio::test]
async fn statistiques_derniere_utilisation_scim() {
    let s = srv().await;
    let o = account(&s.st, &AccountOpts { role: "owner", ..Default::default() }).await;
    let v = s.get("/api/admin/stats", Some(&o.token)).await.expect(200, "").clone();
    assert!(v["scim_last_used_at"].is_null(), "{v}");
    let token = s.post("/api/admin/scim/token", Some(&o.token), json!({})).await.expect(200, "")["token"]
        .as_str()
        .expect("jeton SCIM")
        .to_string();
    let r = s.http.get(format!("{}/scim/v2/Users", s.base)).bearer_auth(&token).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let v = s.get("/api/admin/stats", Some(&o.token)).await.expect(200, "").clone();
    assert!(v["scim_last_used_at"].as_i64().is_some_and(|t| t >= now_unix() - 60), "{v}");
}
