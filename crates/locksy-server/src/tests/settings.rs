//! Réglages de l'organisation : API d'administration, politique, page
//! publique, préférences, pont de compatibilité, cache, maintenance.

use super::*;
use crate::db;
use locksy_core::aad;
use locksy_core::crypto::SecretKey;
use locksy_core::settings::StoredValue;
use serde_json::json;
use std::sync::Arc;

const SETTINGS: &str = "/api/admin/settings";

async fn owner(st: &AppState) -> Account {
    account(st, &AccountOpts { role: "owner", totp: true, with_password: true, ..Default::default() }).await
}

fn etag(r: &Rep) -> String {
    r.header("etag").expect("ETag absent").to_string()
}

/// ETag courant des réglages.
async fn current(s: &Srv, a: &Account) -> String {
    etag(&s.get(SETTINGS, Some(&a.token)).await)
}

async fn patch(s: &Srv, a: &Account, changes: Value, extra: &[(&str, &str)]) -> Rep {
    let tag = current(s, a).await;
    let mut headers = vec![("if-match", tag.as_str())];
    headers.extend_from_slice(extra);
    s.patch(SETTINGS, Some(&a.token), json!({ "changes": changes }), &headers).await
}

async fn values(s: &Srv, a: &Account) -> Value {
    s.get(SETTINGS, Some(&a.token)).await.expect(200, "")["values"].clone()
}

/// Base64 standard (avec remplissage), celui des URL `data:`.
fn std_b64(data: &[u8]) -> String {
    let mut s = b64e(data).replace('-', "+").replace('_', "/");
    while !s.len().is_multiple_of(4) {
        s.push('=');
    }
    s
}

async fn exec(st: &AppState, sql: &'static str, p: Vec<Value>) {
    st.db
        .call(move |c| {
            let p: Vec<String> = p.iter().map(|v| v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())).collect();
            c.execute(sql, rusqlite::params_from_iter(p.iter()))?;
            db::mark_settings_changed();
            Ok(())
        })
        .await
        .unwrap();
}

// ------------------------------------------------------------ Contrôles de PATCH

#[tokio::test]
async fn patch_sans_if_match() {
    let s = srv().await;
    let o = owner(&s.st).await;
    let r = s.patch(SETTINGS, Some(&o.token), json!({ "changes": { "session.idle_minutes": 30 } }), &[]).await;
    r.expect(428, "precondition_required");
}

#[tokio::test]
async fn patch_revision_perimee() {
    let s = srv().await;
    let o = owner(&s.st).await;
    let first = current(&s, &o).await;
    assert_eq!(first, "\"r0\"");
    let r = s.patch(SETTINGS, Some(&o.token), json!({ "changes": { "session.idle_minutes": 30 } }), &[("if-match", &first)]).await;
    assert_eq!(r.expect(200, "")["revision"], json!(1));
    assert_eq!(r.body["changed"], json!(["session.idle_minutes"]));
    assert_eq!(etag(&r), "\"r1\"");
    // Révision périmée : conflit avec la révision actuelle et son auteur.
    let r = s.patch(SETTINGS, Some(&o.token), json!({ "changes": { "session.idle_minutes": 20 } }), &[("if-match", &first)]).await;
    let b = r.expect(409, "settings_conflict");
    assert_eq!(b["current_revision"], json!(1));
    assert_eq!(b["by"], json!("Compte owner"));
    assert!(b["at"].as_i64().unwrap() > 0);
    assert_eq!(etag(&r), "\"r1\"", "ETag de la révision actuelle");
    // If-Match illisible : même conflit ; forme sans guillemets acceptée.
    s.patch(SETTINGS, Some(&o.token), json!({ "changes": { "session.idle_minutes": 20 } }), &[("if-match", "abc")])
        .await
        .expect(409, "settings_conflict");
    s.patch(SETTINGS, Some(&o.token), json!({ "changes": { "session.idle_minutes": 20 } }), &[("if-match", "r1")])
        .await
        .expect(200, "");
}

#[tokio::test]
async fn patch_valeur_invalide() {
    let s = srv().await;
    let o = owner(&s.st).await;
    let r = patch(&s, &o, json!({ "session.idle_minutes": 2, "inconnue.cle": 1 }), &[]).await;
    let b = r.expect(422, "invalid_settings");
    assert_eq!(b["fields"]["session.idle_minutes"], json!({ "code": "out_of_range", "min": 5, "max": 1440 }));
    assert_eq!(b["fields"]["inconnue.cle"]["code"], json!("unknown_key"));
    // Corps illisible.
    let tag = current(&s, &o).await;
    s.req(Method::PATCH, SETTINGS, Some(&o.token), Some(&json!({ "changes": { "x": { "value": 1, "mode": "?" } } })), &[("if-match", &tag)])
        .await
        .expect(400, "bad_request");
}

#[tokio::test]
async fn patch_reserve_aux_proprietaires() {
    let s = srv().await;
    let admin = account(&s.st, &AccountOpts { role: "admin", totp: true, ..Default::default() }).await;
    assert_eq!(admin.role, "admin");
    let r = patch(&s, &admin, json!({ "twofa.required": true, "session.idle_minutes": 30 }), &[]).await;
    assert_eq!(r.expect(403, "owner_only")["keys"], json!(["twofa.required"]));
    // Un réglage ordinaire passe pour un administrateur.
    patch(&s, &admin, json!({ "session.idle_minutes": 30 }), &[]).await.expect(200, "");
    // Les routes du propriétaire lui sont fermées.
    s.get("/api/admin/settings/export", Some(&admin.token)).await.expect(403, "forbidden");
    s.get("/api/admin/config/effective", Some(&admin.token)).await.expect(403, "forbidden");
    // Un utilisateur n'a pas accès à l'administration.
    let user = account(&s.st, &AccountOpts::default()).await;
    s.get(SETTINGS, Some(&user.token)).await.expect(403, "forbidden");
    s.get("/api/admin/settings/schema", Some(&user.token)).await.expect(403, "forbidden");
}

#[tokio::test]
async fn patch_cle_fixee_par_l_hebergeur() {
    let s = srv_with(|st| {
        let mut host = (*st.host).clone();
        host.caps.locked.insert(
            "session.idle_minutes".into(),
            (StoredValue::plain(json!(30)), "LOCKSY_SETTINGS_FILE".into()),
        );
        st.host = Arc::new(host);
    })
    .await;
    let o = owner(&s.st).await;
    let r = patch(&s, &o, json!({ "session.idle_minutes": 45 }), &[]).await;
    assert_eq!(r.expect(409, "host_locked")["keys"], json!(["session.idle_minutes"]));
    let v = values(&s, &o).await;
    assert_eq!(v["session.idle_minutes"]["value"], json!(30));
    assert_eq!(v["session.idle_minutes"]["source"], json!("host_locked"));
    assert_eq!(v["session.idle_minutes"]["locked_by"], json!("LOCKSY_SETTINGS_FILE"));
    let schema = s.get("/api/admin/settings/schema", Some(&o.token)).await;
    let def = schema.expect(200, "")["settings"].as_array().unwrap().iter().find(|d| d["key"] == "session.idle_minutes").cloned().unwrap();
    assert_eq!(def["host_locked"], json!(true));
}

#[tokio::test]
async fn abaissement_avec_reauthentification() {
    let s = srv().await;
    let o = owner(&s.st).await;
    // 12 h -> 24 h : abaissement.
    patch(&s, &o, json!({ "session.max_hours": 24 }), &[]).await.expect(428, "reauth_required");
    let faux = ("x-locksy-reauth", b64e(&[0u8; 32]));
    patch(&s, &o, json!({ "session.max_hours": 24 }), &[(faux.0, &faux.1)]).await.expect(401, "invalid_credentials");
    let (h, v) = reauth_header(&o);
    patch(&s, &o, json!({ "session.max_hours": 24 }), &[(h, &v)]).await.expect(200, "");
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'settings.lowered'").await, 1);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'settings.updated' AND target = 'r1'").await, 1);
    // Renforcer ne demande rien.
    patch(&s, &o, json!({ "session.max_hours": 8 }), &[]).await.expect(200, "");
}

#[tokio::test]
async fn imposer_le_sso_exige_un_test_recent() {
    let s = srv().await;
    let o = owner(&s.st).await;
    s.st.db
        .call(|c| {
            db::save_json(
                c,
                "sso",
                &json!({ "enabled": true, "label": "SSO", "issuer": "https://idp.exemple.fr", "client_id": "locksy" }),
            )
        })
        .await
        .unwrap();
    let r = patch(&s, &o, json!({ "sso.enforce": true }), &[]).await;
    assert_eq!(r.expect(409, "test_required")["key"], json!("sso.enforce"));
    // Test réussi trop ancien, puis récent.
    let old = now_unix() - 25 * 3600;
    exec(&s.st, "INSERT INTO identity_tests (kind, at, user_id, ok) VALUES ('sso', ?1, ?2, 1)", vec![json!(old), json!(o.id)]).await;
    patch(&s, &o, json!({ "sso.enforce": true }), &[]).await.expect(409, "test_required");
    let recent = now_unix() - 3600;
    exec(&s.st, "INSERT INTO identity_tests (kind, at, user_id, ok) VALUES ('sso', ?1, ?2, 1)", vec![json!(recent), json!(o.id)]).await;
    patch(&s, &o, json!({ "sso.enforce": true }), &[]).await.expect(200, "");
    // Reflété dans la page publique et dans le bloc SSO (miroir).
    assert_eq!(s.get("/api/settings/public", None).await.expect(200, "")["login"]["enforced"], json!(true));
    let enforced = s.st.db.read(|c| Ok(crate::sso::load_config(c)?.enforce)).await.unwrap();
    assert!(enforced);
}

#[tokio::test]
async fn liste_blanche_sans_l_adresse_de_l_auteur() {
    let s = srv().await;
    let o = owner(&s.st).await;
    let r = patch(&s, &o, json!({ "access.ip_allowlist": ["10.0.0.0/8"] }), &[]).await;
    let b = r.expect(422, "invalid_settings");
    assert_eq!(b["fields"]["access.ip_allowlist"], json!({ "code": "missing_own_ip", "ip": "127.0.0.1" }));
    patch(&s, &o, json!({ "access.ip_allowlist": ["127.0.0.0/8"] }), &[]).await.expect(200, "");
    s.get("/api/settings/policy", Some(&o.token)).await.expect(200, "");
}

#[tokio::test]
async fn deux_fa_imposee_sans_la_deux_fa_de_l_auteur() {
    let s = srv().await;
    let o = account(&s.st, &AccountOpts { role: "owner", ..Default::default() }).await;
    let r = patch(&s, &o, json!({ "twofa.required": true }), &[]).await;
    assert_eq!(r.expect(422, "invalid_settings")["fields"]["twofa.required"]["code"], json!("actor_without_2fa"));
}

// ------------------------------------------------------------ Validation, schéma, profils

#[tokio::test]
async fn validation_sans_ecriture_avec_impact() {
    let s = srv().await;
    let o = owner(&s.st).await;
    account(&s.st, &AccountOpts::default()).await;
    account(&s.st, &AccountOpts { role: "admin", ..Default::default() }).await;
    account(&s.st, &AccountOpts { disabled: true, ..Default::default() }).await;
    let r = s.post("/api/admin/settings/validate", Some(&o.token), json!({ "changes": { "twofa.required": true }, "reason": "audit" })).await;
    let b = r.expect(200, "");
    assert_eq!(b["ok"], json!(true));
    assert_eq!(b["requires_owner"], json!(true));
    assert_eq!(b["diff"], json!([{ "key": "twofa.required", "old": false, "new": true, "lowered": false }]));
    assert_eq!(b["impact"][0], json!({ "key": "twofa.required", "affected_users": 2, "affected_admins": 1, "link": "#/admin/personnes?2fa=non&etat=actif" }));
    let r = s.post("/api/admin/settings/validate", Some(&o.token), json!({ "changes": { "session.max_hours": 0 } })).await;
    assert_eq!(r.expect(200, "")["ok"], json!(false));
    assert_eq!(r.body["errors"]["session.max_hours"]["code"], json!("out_of_range"));
    s.post("/api/admin/settings/validate", Some(&o.token), json!("pas un objet")).await.expect(400, "bad_request");
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM settings_history").await, 0);
}

#[tokio::test]
async fn schema_du_registre() {
    let s = srv().await;
    let o = owner(&s.st).await;
    let r = s.get("/api/admin/settings/schema", Some(&o.token)).await;
    let b = r.expect(200, "");
    assert_eq!(b["schema_version"], json!(2));
    let sections = b["sections"].as_array().unwrap();
    assert_eq!(sections.len(), 10);
    assert_eq!(sections.first(), Some(&json!("login")));
    assert_eq!(sections.last(), Some(&json!("identity")));
    let settings = b["settings"].as_array().unwrap();
    assert_eq!(settings.len(), locksy_core::settings::REGISTRY.len());
    let autolock = settings.iter().find(|d| d["key"] == "client.autolock_minutes").unwrap();
    assert_eq!(autolock["kind"], json!({ "type": "int", "min": 1, "max": 1440, "unit": "minutes" }));
    assert_eq!(autolock["default"], json!({ "value": 10, "mode": "default", "min": null, "max": null }));
    assert_eq!(autolock["safer"], json!("lower"));
    assert_eq!(autolock["client"], json!(true));
    let file = settings.iter().find(|d| d["key"] == "attachment.max_file_mib").unwrap();
    assert_eq!(file["host_cap"], json!("LOCKSY_MAX_ATTACHMENT_MIB"));
    assert_eq!(file["kind"]["max"], json!(10), "plafond de l'hébergeur appliqué");
    assert!(b["profiles"]["strict"]["twofa.required"] == json!(true));
}

#[tokio::test]
async fn profil_essaye_puis_applique() {
    let s = srv().await;
    let o = owner(&s.st).await;
    let r = s.post("/api/admin/settings/profile", Some(&o.token), json!({ "profile": "reinforced", "dry_run": true })).await;
    let b = r.expect(200, "");
    assert_eq!(b["ok"], json!(true));
    assert!(b["diff"].as_array().unwrap().len() >= 10);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM settings_history").await, 0);
    s.post("/api/admin/settings/profile", Some(&o.token), json!({ "profile": "inconnu", "dry_run": true })).await.expect(400, "bad_request");
    let tag = current(&s, &o).await;
    let r = s
        .req(Method::POST, "/api/admin/settings/profile", Some(&o.token), Some(&json!({ "profile": "reinforced" })), &[("if-match", &tag)])
        .await;
    assert_eq!(r.expect(200, "")["revision"], json!(1));
    let b = s.get(SETTINGS, Some(&o.token)).await;
    assert_eq!(b.body["profile"], json!({ "closest": "reinforced", "deviations": [] }));
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'settings.profile_applied'").await, 1);
}

#[tokio::test]
async fn retour_au_defaut() {
    let s = srv().await;
    let o = owner(&s.st).await;
    set_setting(&s.st, "session.max_hours", json!(8)).await;
    let tag = current(&s, &o).await;
    let (h, v) = reauth_header(&o);
    let r = s
        .req(Method::POST, "/api/admin/settings/reset", Some(&o.token), Some(&json!({ "keys": ["session.max_hours"] })), &[("if-match", &tag), (h, &v)])
        .await;
    assert_eq!(r.expect(200, "")["changed"], json!(["session.max_hours"]));
    assert_eq!(values(&s, &o).await["session.max_hours"]["source"], json!("default"));
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM org_settings WHERE key = 'session.max_hours'").await, 0);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM settings_history WHERE source = 'reset'").await, 1);
}

// ------------------------------------------------------------ Historique, restauration, export et import

#[tokio::test]
async fn historique_pagine_et_restauration() {
    let s = srv().await;
    let o = owner(&s.st).await;
    patch(&s, &o, json!({ "session.idle_minutes": 30 }), &[]).await.expect(200, "");
    patch(&s, &o, json!({ "session.idle_minutes": 15, "share.max_views": 10 }), &[]).await.expect(200, "");
    let r = s.get("/api/admin/settings/history?per_page=1&page=2", Some(&o.token)).await;
    let b = r.expect(200, "");
    assert_eq!((b["total"].clone(), b["page"].clone(), b["per_page"].clone()), (json!(2), json!(2), json!(1)));
    let rev = &b["revisions"][0];
    assert_eq!(rev["revision"], json!(1));
    assert_eq!(rev["email"], json!(o.email));
    assert_eq!(rev["source"], json!("ui"));
    assert_eq!(rev["changes"], json!([{ "key": "session.idle_minutes", "old": 60, "new": 30 }]));
    let r = s.get("/api/admin/settings/history?key=share.max_views", Some(&o.token)).await;
    assert_eq!(r.expect(200, "")["total"], json!(1));
    assert_eq!(r.body["revisions"][0]["changes"].as_array().unwrap().len(), 1);

    // Retour à la révision 1 : nouvelle révision (15 -> 30 min : abaissement).
    let tag = current(&s, &o).await;
    let (h, v) = reauth_header(&o);
    let r = s.req(Method::POST, "/api/admin/settings/revert/1", Some(&o.token), None, &[("if-match", &tag), (h, &v)]).await;
    assert_eq!(r.expect(200, "")["revision"], json!(3));
    let v = values(&s, &o).await;
    assert_eq!(v["session.idle_minutes"]["value"], json!(30));
    assert_eq!(v["share.max_views"]["value"], json!(100));
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM settings_history WHERE revision = 3 AND source = 'revert'").await, 2);
    s.req(Method::POST, "/api/admin/settings/revert/99", Some(&o.token), None, &[("if-match", "\"r3\"")]).await.expect(404, "not_found");
}

/// Empreinte du stockage des réglages (valeurs et historique).
async fn fingerprint(st: &AppState) -> (i64, i64, i64) {
    (
        count(st, "SELECT COUNT(*) FROM org_settings").await,
        count(st, "SELECT COUNT(*) FROM settings_history").await,
        count(st, "SELECT revision FROM settings_meta").await,
    )
}

#[tokio::test]
async fn export_sans_secret_et_import() {
    let s = srv().await;
    let o = owner(&s.st).await;
    patch(&s, &o, json!({ "mail.smtp.password": "s3cret-smtp", "session.idle_minutes": 30 }), &[]).await.expect(200, "");
    // Secret chiffré en base, jamais renvoyé.
    let stored: String = s
        .st
        .db
        .read(|c| Ok(c.query_row("SELECT value FROM org_settings WHERE key = 'mail.smtp.password'", [], |r| r.get(0))?))
        .await
        .unwrap();
    assert!(stored.starts_with("\"v1.") && !stored.contains("s3cret"), "{stored}");
    let full = s.get(SETTINGS, Some(&o.token)).await;
    assert_eq!(full.body["values"]["mail.smtp.password"]["has_secret"], json!(true));
    assert!(!full.body.to_string().contains("s3cret"));
    assert!(!s.get("/api/admin/settings/history", Some(&o.token)).await.body.to_string().contains("s3cret"));

    let r = s.get("/api/admin/settings/export", Some(&o.token)).await;
    let mut doc = r.expect(200, "").clone();
    assert_eq!(doc["format"], json!("locksy-settings-v1"));
    assert_eq!(doc["values"]["mail.smtp.password"], Value::Null);
    assert_eq!(doc["values"]["session.idle_minutes"], json!({ "value": 30 }));
    assert_eq!(doc["sha256"].as_str().unwrap().len(), 64);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'settings.exported'").await, 1);

    // Essai à blanc : rien n'est écrit.
    doc["values"]["session.idle_minutes"] = json!({ "value": 15 });
    doc["sha256"] = Value::Null;
    let before = fingerprint(&s.st).await;
    let r = s.post("/api/admin/settings/import?dry_run=true", Some(&o.token), doc.clone()).await;
    let b = r.expect(200, "");
    assert_eq!(b["ok"], json!(true));
    assert_eq!(b["skipped"], json!(["mail.smtp.password"]));
    assert_eq!(b["diff"], json!([{ "key": "session.idle_minutes", "old": 30, "new": 15, "lowered": false }]));
    assert_eq!(fingerprint(&s.st).await, before);
    // Empreinte fausse : refus.
    let mut altered = doc.clone();
    altered["sha256"] = json!("0".repeat(64));
    s.post("/api/admin/settings/import?dry_run=true", Some(&o.token), altered).await.expect(400, "bad_request");
    // Application : If-Match exigé, une révision « import ».
    s.post("/api/admin/settings/import?dry_run=false", Some(&o.token), doc.clone()).await.expect(428, "precondition_required");
    let tag = current(&s, &o).await;
    let r = s.req(Method::POST, "/api/admin/settings/import?dry_run=false", Some(&o.token), Some(&doc), &[("if-match", &tag)]).await;
    assert_eq!(r.expect(200, "")["revision"], json!(2));
    assert_eq!(values(&s, &o).await["session.idle_minutes"]["value"], json!(15));
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM settings_history WHERE source = 'import'").await, 1);
    // Le secret n'a pas été effacé par l'import.
    assert_eq!(values(&s, &o).await["mail.smtp.password"]["has_secret"], json!(true));
}

#[tokio::test]
async fn configuration_de_l_hebergeur_et_compteurs() {
    let s = srv().await;
    let o = owner(&s.st).await;
    let r = s.get("/api/admin/config/effective", Some(&o.token)).await;
    assert!(r.expect(200, "")["vars"].is_array());
    assert_eq!(r.body["rate_limits"]["login_ip"], json!(100));
    s.get("/api/test/counters", None).await.expect(404, "not_found");
    let t = srv_with(|st| {
        let mut host = (*st.host).clone();
        host.env_test = true;
        st.host = Arc::new(host);
    })
    .await;
    let b = t.get("/api/test/counters", None).await;
    let b = b.expect(200, "");
    assert!(b["settings_loads"].is_u64() && b["legacy_settings_reads"].is_u64() && b["cache_loads"].is_u64());
}

// ------------------------------------------------------------ Politique, page publique, logo

#[tokio::test]
async fn etag_et_304_de_la_politique_et_de_la_page_publique() {
    let s = srv().await;
    let o = owner(&s.st).await;
    for (path, token) in [("/api/settings/policy", Some(o.token.as_str())), ("/api/settings/public", None)] {
        let r = s.get(path, token).await;
        r.expect(200, "");
        let tag = etag(&r);
        assert_eq!(r.header("cache-control"), Some("no-store"));
        let r = s.req(Method::GET, path, token, None, &[("if-none-match", &tag)]).await;
        assert_eq!(r.status, 304, "{path}");
    }
    let policy = s.get("/api/settings/policy", Some(&o.token)).await;
    assert_eq!(policy.body["policy"]["client.autolock_minutes"], json!({ "value": 10, "mode": "default", "min": 1, "max": 1440 }));
    s.get("/api/settings/policy", None).await.expect(401, "unauthorized");
    let public = s.get("/api/settings/public", None).await;
    let p = public.expect(200, "");
    assert_eq!(p["login"]["methods"], json!(["password"]));
    assert_eq!(p["login"]["sso_label"], Value::Null);
    assert_eq!(p["master_password"]["min_length"], json!(12));
    assert_eq!(p["kdf"]["memory_mib"], json!(64));
    assert_eq!(p["branding"]["logo_url"], Value::Null);
    // Après une modification : nouvelle révision, l'ancien ETag ne vaut plus.
    let old = etag(&public);
    patch(&s, &o, json!({ "branding.org_name": "ACME Industrie" }), &[]).await.expect(200, "");
    let r = s.req(Method::GET, "/api/settings/public", None, None, &[("if-none-match", &old)]).await;
    assert_eq!(r.expect(200, "")["branding"]["org_name"], json!("ACME Industrie"));
    assert_eq!(etag(&r), "\"r1\"");
}

#[tokio::test]
async fn logo_de_l_organisation() {
    let s = srv().await;
    let o = owner(&s.st).await;
    s.get("/api/branding/logo", None).await.expect(404, "not_found");
    let png = [b"\x89PNG\r\n\x1a\n".as_slice(), b"logo-de-test"].concat();
    let data = format!("data:image/png;base64,{}", std_b64(&png));
    patch(&s, &o, json!({ "branding.logo": data }), &[]).await.expect(200, "");
    let public = s.get("/api/settings/public", None).await;
    assert_eq!(public.body["branding"]["logo_url"], json!("/api/branding/logo?v=1"));
    let res = s.http.get(format!("{}/api/branding/logo?v=1", s.base)).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()["content-type"], "image/png");
    assert_eq!(res.headers()["x-content-type-options"], "nosniff");
    assert_eq!(res.bytes().await.unwrap().as_ref(), png.as_slice());
    let v = values(&s, &o).await;
    assert_eq!(v["branding.logo"]["value"], json!({ "has_image": true, "url": "/api/branding/logo?v=1" }));
    // Faux PNG refusé ; null rétablit le logo de Locksy.
    let faux = format!("data:image/png;base64,{}", std_b64(b"GIF89a-pas-un-png"));
    let r = patch(&s, &o, json!({ "branding.logo": faux }), &[]).await;
    assert_eq!(r.expect(422, "invalid_settings")["fields"]["branding.logo"]["code"], json!("invalid_image"));
    patch(&s, &o, json!({ "branding.logo": null }), &[]).await.expect(200, "");
    s.get("/api/branding/logo", None).await.expect(404, "not_found");
}

// ------------------------------------------------------------ Préférences et charte

#[tokio::test]
async fn preferences_chiffrees() {
    let s = srv().await;
    let u = account(&s.st, &AccountOpts::default()).await;
    let t = Some(u.token.as_str());
    s.get("/api/me/prefs", t).await.expect(404, "not_found");
    let cipher = crypto::encrypt_str(&SecretKey::generate(), r#"{"v":1}"#, &aad::prefs(&u.id));
    let put = |c: &str| json!({ "cipher": c });
    s.put("/api/me/prefs", t, put(&cipher)).await.expect(428, "precondition_required");
    let r = s.req(Method::PUT, "/api/me/prefs", t, Some(&put(&cipher)), &[("if-match", "\"0\"")]).await;
    assert_eq!(r.expect(200, "")["revision"], json!(1));
    let r = s.req(Method::PUT, "/api/me/prefs", t, Some(&put(&cipher)), &[("if-match", "0")]).await;
    assert_eq!(r.expect(409, "prefs_conflict")["current_revision"], json!(1));
    let big = format!("v1.{}", "A".repeat(70_000));
    s.req(Method::PUT, "/api/me/prefs", t, Some(&put(&big)), &[("if-match", "1")]).await.expect(413, "too_large");
    s.req(Method::PUT, "/api/me/prefs", t, Some(&put(r#"{"v":1,"ui":{}}"#)), &[("if-match", "1")]).await.expect(400, "invalid_prefs");
    let r = s.req(Method::PUT, "/api/me/prefs", t, Some(&put(&cipher)), &[("if-match", "1")]).await;
    assert_eq!(r.expect(200, "")["revision"], json!(2));
    let doc = s.get("/api/me/prefs", t).await;
    assert_eq!(doc.expect(200, "")["cipher"], json!(cipher));
    assert_eq!(doc.body["revision"], json!(2));
    // Corps au-delà de la limite de la route : refusé avant le handler.
    let huge = format!("v1.{}", "A".repeat(200_000));
    assert_eq!(s.req(Method::PUT, "/api/me/prefs", t, Some(&put(&huge)), &[("if-match", "2")]).await.status, 413);
    // Pas de suppression du document par l'API.
    s.delete("/api/me/prefs", t).await.expect(405, "");
    // Révisions pour la synchronisation.
    let rev = crate::settings_api::revisions_for(&s.st, &u.id).await.unwrap();
    assert_eq!((rev.policy_revision, rev.prefs_revision), (0, 2));
}

#[tokio::test]
async fn charte_d_utilisation() {
    let s = srv().await;
    let u = account(&s.st, &AccountOpts::default()).await;
    let t = Some(u.token.as_str());
    assert_eq!(s.get("/api/me/charter", t).await.expect(200, ""), &json!({ "required_version": 0, "accepted_version": 0 }));
    s.post("/api/me/charter", t, json!({ "version": 0 })).await.expect(409, "conflict");
    set_setting(&s.st, "legal.charter_version", json!(3)).await;
    s.post("/api/me/charter", t, json!({ "version": 2 })).await.expect(409, "conflict");
    let r = s.post("/api/me/charter", t, json!({ "version": 3 })).await;
    assert_eq!(r.expect(200, ""), &json!({ "required_version": 3, "accepted_version": 3 }));
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'user.charter_accepted'").await, 1);
}

// ------------------------------------------------------------ Pont de compatibilité

#[tokio::test]
async fn ancien_put_accepte_et_reflete() {
    let s = srv().await;
    let o = owner(&s.st).await;
    let r = s.put(SETTINGS, Some(&o.token), json!({ "session_idle_minutes": 30, "attachment_quota_user_mb": 5 })).await;
    assert_eq!(r.expect(200, "")["session_idle_minutes"], json!(30));
    let full = s.get(SETTINGS, Some(&o.token)).await;
    let b = full.expect(200, "");
    // Une seule révision pour les deux anciens blocs.
    assert_eq!(b["revision"], json!(1));
    assert_eq!(b["values"]["session.idle_minutes"]["value"], json!(30));
    assert_eq!(b["values"]["session.idle_minutes"]["source"], json!("org"));
    assert_eq!(b["values"]["attachment.quota_user_mib"]["value"], json!(5));
    assert_eq!(b["session_idle_minutes"], json!(30));
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM settings_history WHERE revision = 1 AND source = 'api'").await, 2);
    // Une écriture par le registre est reflétée dans l'ancien bloc.
    patch(&s, &o, json!({ "session.idle_minutes": 20 }), &[]).await.expect(200, "");
    let b = s.get(SETTINGS, Some(&o.token)).await;
    assert_eq!(b.body["session_idle_minutes"], json!(20));
    let legacy = s.st.db.read(db::load_settings).await.unwrap();
    assert_eq!(legacy.session_idle_minutes, 20);
    // 2FA imposée par l'ancien chemin : sans délai de grâce.
    s.put(SETTINGS, Some(&o.token), json!({ "require_2fa": true })).await.expect(200, "");
    let v = values(&s, &o).await;
    assert_eq!((v["twofa.required"]["value"].clone(), v["twofa.grace_days"]["value"].clone()), (json!(true), json!(0)));
}

#[tokio::test]
async fn valeur_illisible_en_base() {
    let s = srv().await;
    let o = owner(&s.st).await;
    set_setting(&s.st, "session.idle_minutes", json!(30)).await;
    set_setting(&s.st, "session.max_hours", json!(8)).await;
    exec(&s.st, "UPDATE org_settings SET value = '\"abc\"' WHERE key = ?1", vec![json!("session.idle_minutes")]).await;
    let b = s.get(SETTINGS, Some(&o.token)).await;
    let b = b.expect(200, "");
    assert_eq!(b["values"]["session.idle_minutes"]["value"], json!(60));
    assert_eq!(b["values"]["session.idle_minutes"]["source"], json!("default"));
    assert_eq!(b["values"]["session.max_hours"]["value"], json!(8));
    let warnings = b["warnings"].as_array().unwrap();
    assert!(warnings.iter().any(|w| w["key"] == "session.idle_minutes" && w["code"] == "read_error"), "{warnings:?}");
}

// ------------------------------------------------------------ Cache

#[tokio::test]
async fn aucune_lecture_des_reglages_par_requete() {
    let s = srv().await;
    let o = owner(&s.st).await;
    s.get("/api/settings/policy", Some(&o.token)).await.expect(200, "");
    let loads = s.st.settings.loads();
    for _ in 0..50 {
        s.get("/api/settings/policy", Some(&o.token)).await.expect(200, "");
    }
    assert_eq!(s.st.settings.loads(), loads, "aucun rechargement sans écriture");
    patch(&s, &o, json!({ "session.idle_minutes": 30 }), &[]).await.expect(200, "");
    for _ in 0..10 {
        s.get("/api/me/charter", Some(&o.token)).await.expect(200, "");
    }
    // Lecture de l'ETag par `patch` puis écriture : un seul rechargement ensuite.
    assert_eq!(s.st.settings.loads(), loads + 1);
}

#[tokio::test]
async fn fusion_de_routeurs_sur_un_meme_chemin() {
    use axum::routing::{get, post};
    let a: axum::Router<AppState> = axum::Router::new().route("/admin/essai/:id", get(|| async { "lecture" }));
    let b: axum::Router<AppState> = axum::Router::new().route("/admin/essai/:id", post(|| async { "action" }));
    let st = crate::state::test_state().await;
    // Les deux routes factices fusionnées, puis tous les routeurs des lots
    // (aucune paire chemin + méthode en double : sinon panique d'axum).
    let app = a
        .merge(b)
        .merge(crate::admin_people::router())
        .merge(crate::identity_admin::router())
        .merge(crate::mail::router())
        .merge(crate::auth::router())
        .merge(crate::vault::router())
        .merge(crate::audit_chain::router())
        .with_state(st);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let http = reqwest::Client::new();
    let get = http.get(format!("http://{addr}/admin/essai/1")).send().await.unwrap();
    assert_eq!(get.text().await.unwrap(), "lecture");
    let post = http.post(format!("http://{addr}/admin/essai/1")).send().await.unwrap();
    assert_eq!(post.text().await.unwrap(), "action");
}

/// Clé à modes : `value` et `default` sont des valeurs nues (A.2), le mode et
/// les bornes sont des champs voisins ; jamais l'objet stocké imbriqué.
#[tokio::test]
async fn reglage_a_modes_valeur_nue() {
    let s = srv().await;
    let o = owner(&s.st).await;
    let v = values(&s, &o).await;
    assert_eq!(v["client.autolock_minutes"]["value"], json!(10));
    assert_eq!(v["client.autolock_minutes"]["default"], json!(10));
    assert_eq!(v["client.lock_on_hide"]["value"], json!(false));
    assert_eq!(v["client.lock_on_hide"]["mode"], json!("default"));
    set_setting(&s.st, "client.autolock_minutes", json!({ "value": 15, "mode": "default", "min": 5, "max": 30 })).await;
    set_setting(&s.st, "client.lock_on_hide", json!(true)).await;
    let v = values(&s, &o).await;
    let a = &v["client.autolock_minutes"];
    assert_eq!((&a["value"], &a["default"], &a["mode"]), (&json!(15), &json!(10), &json!("default")), "{a}");
    assert_eq!((&a["min"], &a["max"]), (&json!(5), &json!(30)), "{a}");
    assert_eq!(v["client.lock_on_hide"]["value"], json!(true), "{}", v["client.lock_on_hide"]);
}

// ------------------------------------------------------------ Maintenance

#[tokio::test]
async fn maintenance_liens_corbeille_et_comptes_inactifs() {
    let s = srv().await;
    let o = owner(&s.st).await;
    let now = now_unix();
    let old = now - 400 * 86_400;
    let idle_user = account(&s.st, &AccountOpts { created_at: Some(old), ..Default::default() }).await;
    let idle_owner = account(&s.st, &AccountOpts { role: "owner", created_at: Some(old), ..Default::default() }).await;
    set_setting(&s.st, "users.disable_after_inactive_days", json!(90)).await;
    let owner_id = o.id.clone();
    s.st.db
        .call(move |c| {
            for (id, expires, views, max) in [("expire", now - 10, 0, 5), ("epuise", now + 3600, 5, 5), ("actif", now + 3600, 0, 5)] {
                c.execute(
                    "INSERT INTO shares (id, owner_id, data, created_at, expires_at, max_views, views) VALUES (?1, ?2, 'x', ?3, ?4, ?5, ?6)",
                    params![id, owner_id, now - 100, expires, max, views],
                )?;
            }
            c.execute("INSERT INTO collections (id, enc_name, created_at, updated_at) VALUES ('c1', 'x', ?1, ?1)", [now])?;
            for (id, deleted, purge) in
                [("purge_passee", Some(now - 60), Some(now - 1)), ("purge_future", Some(now - 40 * 86_400), Some(now + 86_400)), ("vivant", None, None)]
            {
                c.execute(
                    "INSERT INTO items (id, collection_id, data, created_at, updated_at, deleted_at, purge_at) VALUES (?1, 'c1', 'x', ?2, ?2, ?3, ?4)",
                    params![id, now, deleted, purge],
                )?;
            }
            Ok(())
        })
        .await
        .unwrap();
    let eff = s.st.effective().await.unwrap();
    s.st.db
        .call(move |c| {
            crate::maintenance(c, &eff, now);
            Ok(())
        })
        .await
        .unwrap();
    let state_of = |id: &'static str| {
        let st = s.st.clone();
        async move {
            st.db
                .read(move |c| {
                    Ok(c.query_row("SELECT state || '/' || COALESCE(ended_reason, '') FROM shares WHERE id = ?1", [id], |r| {
                        r.get::<_, String>(0)
                    })?)
                })
                .await
                .unwrap()
        }
    };
    assert_eq!(state_of("expire").await, "expired/expired");
    assert_eq!(state_of("epuise").await, "exhausted/exhausted");
    assert_eq!(state_of("actif").await, "active/");
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM shares WHERE data = ''").await, 2, "contenu des liens terminés effacé");
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM shares WHERE id = 'actif' AND data = 'x'").await, 1);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM items WHERE id = 'purge_passee'").await, 0);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM items WHERE id IN ('purge_future', 'vivant')").await, 2);
    let disabled = |id: String| {
        let st = s.st.clone();
        async move {
            st.db
                .read(move |c| {
                    Ok(c.query_row("SELECT disabled || '/' || COALESCE(disabled_reason, '') FROM users WHERE id = ?1", [id], |r| {
                        r.get::<_, String>(0)
                    })?)
                })
                .await
                .unwrap()
        }
    };
    assert_eq!(disabled(idle_user.id.clone()).await, "1/inactive");
    assert_eq!(disabled(idle_owner.id.clone()).await, "0/", "un propriétaire n'est jamais désactivé");
    assert_eq!(disabled(o.id.clone()).await, "0/");
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'user.disabled_inactive'").await, 1);
    s.get("/api/settings/policy", Some(&idle_user.token)).await.expect(401, "unauthorized");
}

/// Lance la maintenance avec les réglages effectifs courants.
async fn maintenir(s: &Srv, now: i64) {
    let eff = s.st.effective().await.unwrap();
    s.st.db
        .call(move |c| {
            crate::maintenance(c, &eff, now);
            Ok(())
        })
        .await
        .unwrap();
}

/// `retention.audit_days` : les liens terminés (et leurs révélations) sont
/// purgés après la durée de conservation du journal, et pas avant.
#[tokio::test]
async fn maintenance_purge_selon_retention_du_journal() {
    let s = srv().await;
    let o = owner(&s.st).await;
    let now = now_unix();
    let owner_id = o.id.clone();
    s.st.db
        .call(move |c| {
            for (id, jours) in [("fini_40j", 40), ("fini_400j", 400)] {
                c.execute(
                    "INSERT INTO shares (id, owner_id, data, created_at, expires_at, max_views, views, state, ended_at, ended_reason)
                     VALUES (?1, ?2, '', ?3, ?3, 1, 1, 'exhausted', ?3, 'exhausted')",
                    params![id, owner_id, now - jours * 86_400],
                )?;
            }
            Ok(())
        })
        .await
        .unwrap();
    // Défaut (365 jours) : seul le lien terminé depuis 400 jours part.
    maintenir(&s, now).await;
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM shares WHERE id = 'fini_400j'").await, 0);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM shares WHERE id = 'fini_40j'").await, 1, "conservé à 365 jours");
    // 30 jours : le lien terminé depuis 40 jours part aussi.
    set_setting(&s.st, "retention.audit_days", json!(30)).await;
    maintenir(&s, now).await;
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM shares WHERE id = 'fini_40j'").await, 0, "purgé à 30 jours");
}

/// `retention.expired_invites_days` : une invitation échue depuis 10 jours
/// est gardée à 30 jours de conservation, supprimée à 7.
#[tokio::test]
async fn maintenance_supprime_invitations_echues() {
    let s = srv().await;
    let now = now_unix();
    s.st.db
        .call(move |c| {
            c.execute(
                "INSERT INTO invites (id, token_hash, email, role, created_at, expires_at) VALUES ('echue', 'h-echue', 'e@x.fr', 'user', ?1, ?2)",
                params![now - 20 * 86_400, now - 10 * 86_400],
            )?;
            c.execute(
                "INSERT INTO invites (id, token_hash, email, role, created_at, expires_at) VALUES ('valide', 'h-valide', 'v@x.fr', 'user', ?1, ?2)",
                params![now, now + 86_400],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    set_setting(&s.st, "retention.expired_invites_days", json!(30)).await;
    maintenir(&s, now).await;
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM invites WHERE id = 'echue'").await, 1, "conservée à 30 jours");
    set_setting(&s.st, "retention.expired_invites_days", json!(7)).await;
    maintenir(&s, now).await;
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM invites WHERE id = 'echue'").await, 0, "supprimée à 7 jours");
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM invites WHERE id = 'valide'").await, 1, "invitation valide intacte");
}

#[tokio::test]
async fn maintenance_desactive_les_acces_echus() {
    let s = srv().await;
    let now = now_unix();
    let echu = account(&s.st, &AccountOpts::default()).await;
    let futur = account(&s.st, &AccountOpts::default()).await;
    let seul_proprio = account(&s.st, &AccountOpts { role: "owner", ..Default::default() }).await;
    for (id, until) in [(echu.id.clone(), now - 60), (futur.id.clone(), now + 86_400), (seul_proprio.id.clone(), now - 60)] {
        s.st.db
            .call(move |c| Ok(c.execute("UPDATE users SET access_until = ?1 WHERE id = ?2", params![until, id])?))
            .await
            .unwrap();
    }
    let eff = s.st.effective().await.unwrap();
    s.st.db
        .call(move |c| {
            crate::maintenance(c, &eff, now);
            Ok(())
        })
        .await
        .unwrap();
    let etat = |id: String| {
        let st = s.st.clone();
        async move {
            st.db
                .read(move |c| {
                    Ok(c.query_row("SELECT disabled || '/' || COALESCE(disabled_reason, '') FROM users WHERE id = ?1", [id], |r| {
                        r.get::<_, String>(0)
                    })?)
                })
                .await
                .unwrap()
        }
    };
    assert_eq!(etat(echu.id.clone()).await, "1/expired");
    assert_eq!(etat(futur.id.clone()).await, "0/");
    assert_eq!(etat(seul_proprio.id.clone()).await, "0/", "le dernier propriétaire n'est jamais désactivé");
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'user.disabled_expired'").await, 1);
    let id = echu.id.clone();
    let sessions: i64 =
        s.st.db.read(move |c| Ok(c.query_row("SELECT COUNT(*) FROM sessions WHERE user_id = ?1", [id], |r| r.get(0))?)).await.unwrap();
    assert_eq!(sessions, 0, "sessions fermées");
}

// ------------------------------------------------------------ Règles appliquées par les anciens modules

/// Une 2FA exigée pour le rôle (registre) interdit de la retirer, comme
/// l'ancienne règle pour toute l'organisation.
#[tokio::test]
async fn deux_fa_exigee_par_role_non_retirable() {
    let s = srv().await;
    let user = account(&s.st, &AccountOpts { totp: true, ..Default::default() }).await;
    let admin = account(&s.st, &AccountOpts { role: "admin", totp: true, ..Default::default() }).await;
    set_setting(&s.st, "twofa.required_roles", json!(["user"])).await;
    s.post("/api/me/2fa/disable", Some(&user.token), json!({ "code": "000000" })).await.expect(403, "forbidden");
    // Rôle non visé : la demande va jusqu'à la vérification du code.
    let rep = s.post("/api/me/2fa/disable", Some(&admin.token), json!({ "code": "000000" })).await;
    assert_ne!(rep.body["error"], json!("forbidden"), "{}", rep.body);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM users WHERE totp_secret IS NOT NULL").await, 2);
}

// ------------------------------------------------------------ Réglages publics (intégration)

/// Chaque réglage public modifié dans le registre est servi tel quel par
/// GET /settings/public (écran de connexion, pages légales, politique du
/// mot de passe maître appliquée par les clients).
#[tokio::test]
async fn reglages_publics_suivent_le_registre() {
    let s = srv().await;
    for (key, value) in [
        ("branding.login_message", json!("Bienvenue sur le coffre de l'équipe.")),
        ("branding.support_contact", json!("support@exemple.fr")),
        ("legal.privacy_url", json!("https://exemple.fr/confidentialite")),
        ("legal.accessibility_url", json!("https://exemple.fr/accessibilite")),
        ("legal.login_banner", json!("Accès réservé au personnel.")),
        ("legal.dpo_contact", json!("dpo@exemple.fr")),
        ("i18n.default_locale", json!("en-GB")),
        ("master_password.min_score", json!(4)),
        ("master_password.forbid_identity", json!(false)),
    ] {
        set_setting(&s.st, key, value).await;
    }
    let p = s.get("/api/settings/public", None).await.expect(200, "").clone();
    assert_eq!(p["branding"]["login_message"], json!("Bienvenue sur le coffre de l'équipe."));
    assert_eq!(p["branding"]["support_contact"], json!("support@exemple.fr"));
    assert_eq!(p["legal"]["privacy_url"], json!("https://exemple.fr/confidentialite"));
    assert_eq!(p["legal"]["accessibility_url"], json!("https://exemple.fr/accessibilite"));
    assert_eq!(p["legal"]["login_banner"], json!("Accès réservé au personnel."));
    assert_eq!(p["legal"]["dpo_contact"], json!("dpo@exemple.fr"));
    assert_eq!(p["i18n"]["default_locale"], json!("en-GB"));
    assert_eq!(p["master_password"]["min_score"], json!(4));
    assert_eq!(p["master_password"]["forbid_identity"], json!(false));
}

/// État d'une personne dans GET /admin/people.
async fn statut(s: &Srv, o: &Account, email: String) -> Value {
    let r = s.get("/api/admin/people?etat=tous&par_page=100", Some(&o.token)).await.expect(200, "").clone();
    r["rows"].as_array().unwrap().iter().find(|x| x["email"] == json!(email)).unwrap()["status"].clone()
}

/// Le seuil d'inactivité (users.inactive_alert_days) décide de l'état
/// « inactif » dans la liste des personnes.
#[tokio::test]
async fn seuil_d_inactivite_reglable() {
    let s = srv().await;
    let o = owner(&s.st).await;
    let now = now_unix();
    let u = account(&s.st, &AccountOpts { created_at: Some(now - 60 * 86_400), ..Default::default() }).await;
    let id = u.id.clone();
    s.st.db
        .call(move |c| {
            // Dernière connexion et dernière activité de session : il y a 45 jours.
            c.execute("UPDATE users SET last_login_at = ?1 WHERE id = ?2", params![now - 45 * 86_400, id])?;
            Ok(c.execute("UPDATE sessions SET last_seen_at = ?1 WHERE user_id = ?2", params![now - 45 * 86_400, id])?)
        })
        .await
        .unwrap();
    // Défaut 90 jours : 45 jours sans connexion, encore actif.
    assert_eq!(statut(&s, &o, u.email.clone()).await, json!("active"));
    set_setting(&s.st, "users.inactive_alert_days", json!(30)).await;
    assert_eq!(statut(&s, &o, u.email.clone()).await, json!("inactive"));
}
