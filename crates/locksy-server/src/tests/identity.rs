//! Tests du domaine « identité » (lot L6) : garde-fous de l'imposition du
//! SSO et du compte Windows (G-14), tests enregistrés, filtre anti-SSRF,
//! synchronisation de l'annuaire (à blanc, garde-fou de désactivation,
//! dernier propriétaire, domaines), SCIM (désinscription différée, jeton à
//! durée limitée, régénération confirmée), limites de débit (#56), état et
//! route « extension autorisée ? ».
//!
//! Aucun annuaire réel : la synchronisation est éprouvée par
//! `ldap::finish_sync` avec une lecture simulée. Le fournisseur OpenID
//! Connect est un petit serveur local (dérogation `allow_private` du test).

use super::{account, count, set_setting, srv, srv_with, Account, AccountOpts, Srv};
use crate::ldap::{self, AdUser};
use crate::sso::SsoRuntime;
use crate::state::AppState;
use axum::extract::Form;
use axum::routing::{get, post};
use axum::{Json, Router};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use locksy_core::now_unix;
use reqwest::Method;
use rusqlite::params;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

const HOUR: i64 = 3600;
const DAY: i64 = 86_400;
const EXT: &str = "abcdefghijklmnopabcdefghijklmnop";
const CLIENT_ID: &str = "locksy-test";

/// Autorité de test (auto-signée, P-256), pour une configuration LDAPS valide.
const TEST_CA: &str = "-----BEGIN CERTIFICATE-----
MIIBmjCCAUGgAwIBAgIUBOqZdni1wPKa6ilfPnZ11ka/ThMwCgYIKoZIzj0EAwIw
IjEgMB4GA1UEAwwXQXV0b3JpdGUgZGUgdGVzdCBMb2Nrc3kwIBcNMjYxMTE4MDE0
NTA5WhgPMjEyNjEwMjUwMTQ1MDlaMCIxIDAeBgNVBAMMF0F1dG9yaXRlIGRlIHRl
c3QgTG9ja3N5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFosj0Ms4w5ArHtGI
7SpAg5kXTZ9owweymk1yQsCs69rxEQseN1LROWmsaZRnxZMJ50L2tbVcVg6Vvsdr
rF8ioKNTMFEwHQYDVR0OBBYEFDEMnSh/vt77f/spCbUR/DTEeFgeMB8GA1UdIwQY
MBaAFDEMnSh/vt77f/spCbUR/DTEeFgeMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZI
zj0EAwIDRwAwRAIgH266/BnaYKFVNDg2sWB/odpYsPm2STYZYAzUXfIdWrUCIEy1
aY8Dl19vZnVew21iRzYkFU1pUPR3vQ7iQkcDGFS2
-----END CERTIFICATE-----
";

/// Clé de signature du fournisseur d'identité simulé (P-256, test seulement).
const IDP_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1eKEx58BputrK6Gt
HYBIKJ7gAC/G+j9cH3KqwQFANcyhRANCAATD1tIs0EItR4jHHWRWUZpPujSwvLHX
J58RVArtEkha8egDIOAMZDgJfIgma9qcP7GoLSJtYJppsbTRQJtU9lOy
-----END PRIVATE KEY-----
";
const IDP_X: &str = "w9bSLNBCLUeIxx1kVlGaT7o0sLyx1yefEVQK7RJIWvE";
const IDP_Y: &str = "6AMg4AxkOAl8iCZr2pw_sagtIm1gmmmxtNFAm1T2U7I";

// ------------------------------------------------------------ Outils

fn admin_opts() -> AccountOpts {
    AccountOpts { role: "admin", ..Default::default() }
}

fn owner_opts() -> AccountOpts {
    AccountOpts { role: "owner", ..Default::default() }
}

/// Serveur dont le client du fournisseur d'identité a les dérogations
/// données (HTTP clair, réseau interne), sans lire l'environnement.
async fn srv_sso(allow_http: bool, allow_private: bool) -> Srv {
    srv_with(move |st| st.sso = Arc::new(SsoRuntime::new(allow_http, allow_private))).await
}

/// Enregistre un test de connexion (`ok`) daté de `ago` secondes.
async fn put_test(st: &AppState, kind: &'static str, user_id: &str, ok: bool, ago: i64) {
    let uid = user_id.to_string();
    st.db
        .call(move |c| {
            c.execute(
                "INSERT INTO identity_tests (kind, at, user_id, ok, error_code) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![kind, now_unix() - ago, uid, ok, (!ok).then_some("idp_denied")],
            )?;
            Ok(())
        })
        .await
        .unwrap();
}

async fn session_id(st: &AppState, a: &Account) -> String {
    let uid = a.id.clone();
    st.db
        .read(move |c| Ok(c.query_row("SELECT id FROM sessions WHERE user_id = ?1", [uid], |r| r.get(0))?))
        .await
        .unwrap()
}

/// Jeton de réauthentification délivré pour `action` (comme `POST /auth/reauth`).
async fn step_up(st: &AppState, a: &Account, action: &'static str) -> String {
    crate::security::issue_step_up(&a.id, &session_id(st, a).await, action)
}

/// Client HTTP qui ne suit pas les redirections (retours SSO).
fn no_redirect() -> reqwest::Client {
    reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap()
}

// ------------------------------------------------------------ Fournisseur simulé

/// Fournisseur OpenID Connect local : découverte, clés, et point de jeton
/// qui signe un jeton d'identité dont le `code` porte « nonce~adresse ».
async fn fake_idp() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let (b1, b2) = (base.clone(), base.clone());
    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(move || {
                let b = b1.clone();
                async move {
                    Json(json!({
                        "issuer": b,
                        "authorization_endpoint": format!("{b}/auth"),
                        "token_endpoint": format!("{b}/token"),
                        "jwks_uri": format!("{b}/jwks"),
                    }))
                }
            }),
        )
        .route(
            "/jwks",
            get(|| async {
                Json(json!({ "keys": [{ "kty": "EC", "crv": "P-256", "x": IDP_X, "y": IDP_Y, "kid": "k1", "alg": "ES256", "use": "sig" }] }))
            }),
        )
        .route(
            "/token",
            post(move |Form(f): Form<HashMap<String, String>>| {
                let b = b2.clone();
                async move {
                    let code = f.get("code").cloned().unwrap_or_default();
                    let (nonce, email) = code.split_once('~').unwrap_or_default();
                    let now = now_unix();
                    let claims = json!({
                        "iss": b, "aud": CLIENT_ID, "sub": format!("sub-{email}"), "iat": now, "exp": now + 300,
                        "nonce": nonce, "email": email, "email_verified": true, "name": "Test",
                    });
                    let header = Header { kid: Some("k1".into()), ..Header::new(Algorithm::ES256) };
                    let key = EncodingKey::from_ec_pem(IDP_KEY.as_bytes()).unwrap();
                    let id_token = jsonwebtoken::encode(&header, &claims, &key).unwrap();
                    Json(json!({ "id_token": id_token, "token_type": "Bearer" }))
                }
            }),
        );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    base
}

/// Configuration SSO active vers le fournisseur simulé.
async fn configure_sso(s: &Srv, admin: &Account, idp: &str) {
    let body = json!({ "enabled": true, "issuer": idp, "client_id": CLIENT_ID, "label": "Test" });
    s.put("/api/admin/sso", Some(&admin.token), body).await.expect(200, "");
}

/// Lance un test SSO et revient du fournisseur avec l'adresse `email` :
/// renvoie l'adresse de redirection finale.
async fn sso_test_round(s: &Srv, admin: &Account, email: &str) -> String {
    let r = s.post("/api/admin/sso/test-start", Some(&admin.token), json!({})).await;
    let url = url::Url::parse(r.expect(200, "")["url"].as_str().unwrap()).unwrap();
    let q: HashMap<String, String> = url.query_pairs().into_owned().collect();
    assert!(q["state"].starts_with("t."), "état de test reconnaissable");
    let code = format!("{}~{email}", q["nonce"]);
    let res = no_redirect()
        .get(format!("{}/api/sso/callback", s.base))
        .query(&[("code", code.as_str()), ("state", q["state"].as_str())])
        .send()
        .await
        .unwrap();
    assert!(res.status().is_redirection(), "redirection attendue : {}", res.status());
    res.headers()["location"].to_str().unwrap().to_string()
}

// ------------------------------------------------------------ SSO : tests et garde-fous

#[tokio::test]
async fn test_sso_reel_enregistre_par_acteur_et_garde_d_imposition() {
    let s = srv_sso(true, true).await;
    let idp = fake_idp().await;
    let a = account(&s.st, &admin_opts()).await;
    let b = account(&s.st, &admin_opts()).await;
    configure_sso(&s, &a, &idp).await;

    // Sans test réussi, impossible d'imposer.
    let enforce = json!({ "enabled": true, "issuer": idp, "client_id": CLIENT_ID, "enforce": true });
    s.put("/api/admin/sso", Some(&a.token), enforce.clone()).await.expect(409, "test_required");

    // Test avec une autre adresse : refusé (email_mismatch), enregistré.
    let loc = sso_test_round(&s, &a, "quelqu.un@autre.fr").await;
    assert!(loc.ends_with("/#/admin/connexion/sso?test=erreur&code=email_mismatch"), "{loc}");
    // Test avec sa propre adresse : réussi.
    let loc = sso_test_round(&s, &a, &a.email).await;
    assert!(loc.ends_with("/#/admin/connexion/sso?test=ok"), "{loc}");
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM identity_tests WHERE kind = 'sso' AND ok = 1").await, 1);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM identity_tests WHERE error_code = 'email_mismatch'").await, 1);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'sso.tested'").await, 2);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM sso_tickets").await, 0, "un test n'émet aucun ticket");

    // Le test réussi de A ne vaut pas pour B.
    s.put("/api/admin/sso", Some(&b.token), enforce.clone()).await.expect(409, "test_required");
    // A peut imposer : le registre suit.
    let r = s.put("/api/admin/sso", Some(&a.token), enforce).await;
    assert_eq!(r.expect(200, "")["enforce"], true);
    assert!(s.st.effective().await.unwrap().bool("sso.enforce"));

    // État : dernier test, dernière réussite de l'acteur, dernière erreur.
    let st = s.get("/api/admin/identity/status", Some(&a.token)).await;
    let sso = &st.expect(200, "")["sso"];
    assert_eq!((sso["configured"].as_bool(), sso["enforce"].as_bool()), (Some(true), Some(true)));
    assert_eq!(sso["last_test"]["ok"], true);
    assert_eq!(sso["last_test"]["by_me"], true);
    assert!(sso["last_ok_by_me_at"].is_i64());
    assert_eq!(sso["last_error"]["code"], "email_mismatch");
    let other = s.get("/api/admin/identity/status", Some(&b.token)).await;
    assert_eq!(other.body["sso"]["last_test"]["by_me"], false);
    assert!(other.body["sso"]["last_ok_by_me_at"].is_null());
}

#[tokio::test]
async fn imposition_sso_refusee_avec_un_test_de_plus_de_24_h() {
    let s = srv_sso(true, true).await;
    let idp = fake_idp().await;
    let a = account(&s.st, &admin_opts()).await;
    configure_sso(&s, &a, &idp).await;
    put_test(&s.st, "sso", &a.id, true, 25 * HOUR).await;
    put_test(&s.st, "sso", &a.id, false, HOUR).await;
    let enforce = json!({ "enabled": true, "issuer": idp, "client_id": CLIENT_ID, "enforce": true });
    s.put("/api/admin/sso", Some(&a.token), enforce.clone()).await.expect(409, "test_required");
    put_test(&s.st, "sso", &a.id, true, 23 * HOUR).await;
    s.put("/api/admin/sso", Some(&a.token), enforce).await.expect(200, "");
}

#[tokio::test]
async fn retour_de_test_expire_et_routes_reservees() {
    let s = srv_sso(true, true).await;
    let res = no_redirect()
        .get(format!("{}/api/sso/callback", s.base))
        .query(&[("code", "x"), ("state", "t.inconnu")])
        .send()
        .await
        .unwrap();
    let loc = res.headers()["location"].to_str().unwrap();
    assert!(loc.ends_with("/#/admin/connexion/sso?test=erreur&code=identity_test_expired"), "{loc}");
    let u = account(&s.st, &AccountOpts::default()).await;
    s.post("/api/admin/sso/test-start", Some(&u.token), json!({})).await.expect(403, "forbidden");
    s.get("/api/admin/identity/status", Some(&u.token)).await.expect(403, "forbidden");
    s.post("/api/admin/ldap/test-login", Some(&u.token), json!({ "username": "x", "password": "y" })).await.expect(403, "forbidden");
}

// ------------------------------------------------------------ Filtre anti-SSRF

#[tokio::test]
async fn ssrf_adresse_interne_refusee_et_journalisee() {
    let s = srv_sso(true, false).await;
    let a = account(&s.st, &admin_opts()).await;
    for issuer in ["http://127.0.0.1:9", "https://[::1]:9", "https://169.254.169.254", "https://localhost"] {
        let r = s.post("/api/admin/sso/test", Some(&a.token), json!({ "issuer": issuer, "client_id": CLIENT_ID })).await;
        let body = r.expect(422, "ssrf_blocked");
        assert!(body["technical"].as_str().is_some_and(|t| !t.is_empty()), "détail technique à part : {body}");
        assert!(!body["message"].as_str().unwrap().contains("127.0.0.1"), "le détail n'est pas dans le message");
    }
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'sso.discovery_blocked'").await, 4);
    // Activer le SSO vers une adresse interne est refusé de même.
    let body = json!({ "enabled": true, "issuer": "http://10.0.0.5", "client_id": CLIENT_ID });
    s.put("/api/admin/sso", Some(&a.token), body).await.expect(422, "ssrf_blocked");
}

#[tokio::test]
async fn ssrf_derogation_explicite_pour_un_fournisseur_interne() {
    let s = srv_sso(true, true).await;
    let idp = fake_idp().await;
    let a = account(&s.st, &admin_opts()).await;
    let r = s.post("/api/admin/sso/test", Some(&a.token), json!({ "issuer": idp, "client_id": CLIENT_ID })).await;
    let body = r.expect(200, "");
    assert_eq!(body["keys"], 1);
    assert_eq!(body["token_endpoint"], format!("{idp}/token"));
}

// ------------------------------------------------------------ Limites de débit (#56)

#[tokio::test]
async fn tests_de_connexion_limites_par_administrateur() {
    let s = srv_sso(false, false).await;
    let a = account(&s.st, &admin_opts()).await;
    let b = account(&s.st, &admin_opts()).await;
    let body = json!({ "issuer": "https://127.0.0.1:9", "client_id": CLIENT_ID });
    for _ in 0..crate::sso::IDENTITY_TEST_MAX {
        s.post("/api/admin/sso/test", Some(&a.token), body.clone()).await.expect(422, "ssrf_blocked");
    }
    let r = s.post("/api/admin/sso/test-start", Some(&a.token), json!({})).await;
    r.expect(429, "rate_limited");
    assert!(r.header("retry-after").and_then(|v| v.parse::<i64>().ok()).is_some_and(|v| v > 0));
    assert!(r.body["retry_after"].as_i64().is_some_and(|v| v > 0));
    // Un autre administrateur n'est pas concerné.
    s.post("/api/admin/sso/test", Some(&b.token), body).await.expect(422, "ssrf_blocked");
    // Même plafond pour l'annuaire, compté à part.
    let r = s.post("/api/admin/ldap/test-login", Some(&a.token), json!({ "username": "jdupont", "password": "x" })).await;
    r.expect(200, "");
}

#[tokio::test]
async fn synchronisations_manuelles_limitees() {
    let s = srv().await;
    let a = account(&s.st, &admin_opts()).await;
    for _ in 0..6 {
        let r = s.post("/api/admin/ldap/sync?dry_run=true", Some(&a.token), json!({})).await;
        let body = r.expect(409, "invalid_config");
        assert!(body["technical"].is_string());
    }
    s.post("/api/admin/ldap/sync", Some(&a.token), json!({})).await.expect(429, "rate_limited");
    let h = s.get("/api/admin/ldap/history?limit=3", Some(&a.token)).await;
    let rows = h.expect(200, "").as_array().unwrap().clone();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0]["dry_run"], true);
    assert_eq!(rows[0]["ok"], false);
    assert_eq!(rows[0]["error_code"], "invalid_config");
    assert_eq!(rows[0]["triggered_by"], a.id.as_str());
}

// ------------------------------------------------------------ Active Directory

/// Compte Locksy issu de l'annuaire (ligne `directory_users` source ldap).
async fn from_directory(st: &AppState, opts: &AccountOpts) -> (Account, AdUser) {
    let a = account(st, opts).await;
    let guid = format!("{:0>32}", &a.id.replace('-', "")[..16]);
    let (uid, email, g) = (a.id.clone(), a.email.clone(), guid.clone());
    st.db
        .call(move |c| {
            c.execute(
                "INSERT INTO directory_users (id, external_id, email, display_name, active, user_id, created_at, updated_at, source)
                 VALUES (?1, ?2, ?3, 'Test', 1, ?4, 1, 1, 'ldap')",
                params![locksy_core::crypto::new_uuid(), format!("ad:{g}"), email, uid],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let ad = AdUser { guid, dn: format!("CN={}", a.email), login: a.email.clone(), email: Some(a.email.clone()), name: "Test".into(), disabled: false };
    (a, ad)
}

fn new_ad(login: &str, email: Option<&str>) -> AdUser {
    let guid = format!("{:0>32}", login.bytes().map(|b| format!("{b:02x}")).collect::<String>());
    AdUser { guid: guid[guid.len() - 32..].to_string(), dn: format!("CN={login}"), login: login.into(), email: email.map(str::to_string), name: login.into(), disabled: false }
}

/// Empreinte des comptes et de l'annuaire : nombre de lignes, somme des dates
/// de modification et état (une écriture la change).
async fn fingerprint(st: &AppState) -> String {
    st.db
        .read(|c| {
            let users: String = c.query_row(
                "SELECT COUNT(*) || ':' || COALESCE(SUM(updated_at), 0) || ':' || COALESCE(SUM(disabled), 0) || ':' || COALESCE(SUM(deprovision_at), 0) FROM users",
                [],
                |r| r.get(0),
            )?;
            let dir: String = c.query_row(
                "SELECT COUNT(*) || ':' || COALESCE(SUM(updated_at), 0) || ':' || COALESCE(SUM(active), 0) FROM directory_users",
                [],
                |r| r.get(0),
            )?;
            Ok(format!("{users}|{dir}"))
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn synchronisation_a_blanc_sans_ecriture() {
    let s = srv().await;
    let admin = account(&s.st, &admin_opts()).await;
    let mut read = Vec::new();
    for _ in 0..10 {
        read.push(from_directory(&s.st, &AccountOpts::default()).await.1);
    }
    read.truncate(9); // un départ (10 %)
    read[0].disabled = true; // une désactivation dans l'AD
    read.push(new_ad("nouveau", Some("nouveau@exemple.fr")));
    read.push(new_ad("sansmail", None));
    let before = fingerprint(&s.st).await;
    let audits = count(&s.st, "SELECT COUNT(*) FROM audit").await;
    let o = ldap::finish_sync(&s.st, Ok(read.clone()), true, None).await.map_err(|e| e.err.code).unwrap();
    assert_eq!((o.report.created, o.report.disabled), (1, 2));
    assert_eq!(o.ignored, vec![ldap::Ignored { login: "sansmail".into(), email: None, reason: "no_email".into() }]);
    assert_eq!(fingerprint(&s.st).await, before, "aucune écriture sur les comptes ni l'annuaire");
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit").await, audits + 1, "seul l'événement de la synchronisation à blanc");
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'ldap.sync_dry_run'").await, 1);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM ldap_sync_history WHERE dry_run = 1 AND created = 1 AND disabled = 2").await, 1);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM settings WHERE key = 'ldap'").await, 0, "configuration intacte");
    // La même lecture, pour de vrai : les écritures ont lieu.
    let o = ldap::finish_sync(&s.st, Ok(read), false, Some(admin_user(&admin))).await.map_err(|e| e.err.code).unwrap();
    assert_eq!(o.report.disabled, 2);
    assert_ne!(fingerprint(&s.st).await, before);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM users WHERE disabled_reason = 'directory'").await, 2);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM users WHERE deprovision_at IS NOT NULL").await, 1, "seul le départ est programmé");
}

fn admin_user(a: &Account) -> crate::state::AuthUser {
    crate::state::AuthUser {
        id: a.id.clone(),
        email: a.email.clone(),
        role: a.role.to_string(),
        session_id: String::new(),
        meta: crate::state::ClientMeta { ip: "203.0.113.7".into(), user_agent: "test".into() },
    }
}

#[tokio::test]
async fn synchronisation_refusee_au_dela_du_seuil() {
    let s = srv().await;
    let admin = account(&s.st, &admin_opts()).await;
    let mut read = Vec::new();
    for _ in 0..10 {
        read.push(from_directory(&s.st, &AccountOpts::default()).await.1);
    }
    let before = fingerprint(&s.st).await;
    // 3 départs sur 10 comptes actifs : 30 % > 20 %.
    let e = ldap::finish_sync(&s.st, Ok(read[..7].to_vec()), false, Some(admin_user(&admin))).await.err().unwrap();
    assert_eq!((e.err.status.as_u16(), e.err.code), (409, "too_many_deprovisions"));
    assert_eq!(fingerprint(&s.st).await, before, "rien n'est modifié");
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'ldap.sync_refused'").await, 1);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM ldap_sync_history WHERE error_code = 'too_many_deprovisions'").await, 1);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'ldap.user_disabled'").await, 0);
    // 2 départs sur 10 (20 %) : accepté ; seuil relevé : 3 départs acceptés aussi.
    ldap::finish_sync(&s.st, Ok(read[..8].to_vec()), false, None).await.map_err(|e| e.err.code).unwrap();
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM users WHERE disabled = 1").await, 2);
    set_setting(&s.st, "directory.max_deprovision_percent", json!(50)).await;
    let o = ldap::finish_sync(&s.st, Ok(read[..5].to_vec()), false, None).await.map_err(|e| e.err.code).unwrap();
    assert_eq!(o.report.disabled, 3);
}

#[tokio::test]
async fn annuaire_vide_refuse() {
    let s = srv().await;
    from_directory(&s.st, &AccountOpts::default()).await;
    let e = ldap::finish_sync(&s.st, Ok(Vec::new()), false, None).await.err().unwrap();
    assert_eq!(e.err.code, "ldap_empty_result");
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM users WHERE disabled = 1").await, 0);
}

#[tokio::test]
async fn annuaire_ne_desactive_jamais_le_dernier_proprietaire() {
    let s = srv().await;
    let (owner, owner_ad) = from_directory(&s.st, &owner_opts()).await;
    let mut read = Vec::new();
    for _ in 0..4 {
        read.push(from_directory(&s.st, &AccountOpts::default()).await.1);
    }
    // Sorti du groupe…
    let o = ldap::finish_sync(&s.st, Ok(read.clone()), false, None).await.map_err(|e| e.err.code).unwrap();
    assert_eq!(o.ignored.iter().map(|i| i.reason.as_str()).collect::<Vec<_>>(), vec!["last_owner"]);
    // …ou désactivé dans l'AD : jamais désactivé dans Locksy.
    let mut disabled = owner_ad.clone();
    disabled.disabled = true;
    read.push(disabled);
    let o = ldap::finish_sync(&s.st, Ok(read), false, None).await.map_err(|e| e.err.code).unwrap();
    assert_eq!(o.ignored[0].reason, "last_owner");
    let uid = owner.id.clone();
    let disabled: bool = s.st.db.read(move |c| Ok(c.query_row("SELECT disabled FROM users WHERE id = ?1", [uid], |r| r.get(0))?)).await.unwrap();
    assert!(!disabled);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM sessions").await, 5, "sessions intactes");
}

#[tokio::test]
async fn annuaire_applique_les_domaines_autorises() {
    let s = srv().await;
    set_setting(&s.st, "access.allowed_email_domains", json!(["exemple.fr"])).await;
    let read = vec![
        new_ad("dedans", Some("dedans@exemple.fr")),
        new_ad("dehors", Some("dehors@autre.fr")),
        new_ad("casse", Some("pas une adresse")),
    ];
    let o = ldap::finish_sync(&s.st, Ok(read), false, None).await.map_err(|e| e.err.code).unwrap();
    assert_eq!(o.report.created, 1);
    let reasons: Vec<&str> = o.ignored.iter().map(|i| i.reason.as_str()).collect();
    assert_eq!(reasons, vec!["domain_not_allowed", "invalid_email"]);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM directory_users").await, 1);
}

#[tokio::test]
async fn retour_dans_le_groupe_reactive_sauf_decision_locksy() {
    let s = srv().await;
    let mut read = Vec::new();
    let mut accounts = Vec::new();
    for _ in 0..5 {
        let (a, ad) = from_directory(&s.st, &AccountOpts::default()).await;
        accounts.push(a);
        read.push(ad);
    }
    // Départ du premier (20 %), puis retour : réactivé, suppression annulée.
    ldap::finish_sync(&s.st, Ok(read[1..].to_vec()), false, None).await.map_err(|e| e.err.code).unwrap();
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM users WHERE deprovision_at IS NOT NULL").await, 1);
    let o = ldap::finish_sync(&s.st, Ok(read.clone()), false, None).await.map_err(|e| e.err.code).unwrap();
    assert_eq!(o.report.enabled, 1);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM users WHERE disabled = 1 OR deprovision_at IS NOT NULL").await, 0);
    // Désactivé par un administrateur Locksy : l'annuaire ne le réactive pas.
    let uid = accounts[2].id.clone();
    s.st.db
        .call(move |c| {
            c.execute("UPDATE users SET disabled = 1, disabled_reason = 'admin' WHERE id = ?1", [&uid])?;
            Ok(())
        })
        .await
        .unwrap();
    let mut gone_and_back = read.clone();
    gone_and_back[2].disabled = true;
    ldap::finish_sync(&s.st, Ok(gone_and_back), false, None).await.map_err(|e| e.err.code).unwrap();
    ldap::finish_sync(&s.st, Ok(read), false, None).await.map_err(|e| e.err.code).unwrap();
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM users WHERE disabled = 1").await, 1);
}

#[tokio::test]
async fn imposition_ldap_exige_un_test_de_l_acteur() {
    let s = srv().await;
    let a = account(&s.st, &admin_opts()).await;
    let b = account(&s.st, &admin_opts()).await;
    let cfg = json!({
        "url": "ldaps://dc.corp.local:636", "ca_pem": TEST_CA, "bind_dn": "svc@corp.local", "bind_password": "secret",
        "base_dn": "DC=corp,DC=local", "allow_login": true, "enforce": true,
    });
    s.put("/api/admin/ldap", Some(&a.token), cfg.clone()).await.expect(409, "test_required");
    put_test(&s.st, "ldap", &b.id, true, HOUR).await;
    s.put("/api/admin/ldap", Some(&a.token), cfg.clone()).await.expect(409, "test_required");
    put_test(&s.st, "ldap", &a.id, true, 25 * HOUR).await;
    s.put("/api/admin/ldap", Some(&a.token), cfg.clone()).await.expect(409, "test_required");
    put_test(&s.st, "ldap", &a.id, true, HOUR).await;
    let r = s.put("/api/admin/ldap", Some(&a.token), cfg).await;
    assert_eq!(r.expect(200, "")["enforce"], true);
    assert!(s.st.effective().await.unwrap().bool("ldap.enforce"));
    assert_eq!(s.get("/api/admin/ldap", Some(&a.token)).await.body["bind_password"], "", "secret jamais renvoyé");
}

#[tokio::test]
async fn test_de_connexion_windows_enregistre_sans_le_mot_de_passe() {
    let s = srv().await;
    let a = account(&s.st, &admin_opts()).await;
    let r = s.post("/api/admin/ldap/test-login", Some(&a.token), json!({ "username": "CORP\\jdupont", "password": "Secret-123" })).await;
    let body = r.expect(200, "");
    assert_eq!((body["ok"].as_bool(), body["error_code"].as_str()), (Some(false), Some("invalid_config")));
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM identity_tests WHERE kind = 'ldap' AND ok = 0 AND error_code = 'invalid_config'").await, 1);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'ldap.tested'").await, 1);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE details LIKE '%Secret-123%' OR target LIKE '%Secret-123%'").await, 0);
    let st = s.get("/api/admin/identity/status", Some(&a.token)).await;
    assert_eq!(st.body["ldap"]["last_test"]["error_code"], "invalid_config");
    assert!(st.body["ldap"]["last_ok_by_me_at"].is_null());
}

// ------------------------------------------------------------ SCIM

/// Crée le premier jeton SCIM (sans confirmation).
async fn scim_token(s: &Srv, admin: &Account) -> Value {
    s.post("/api/admin/scim/token", Some(&admin.token), json!({})).await.expect(200, "").clone()
}

async fn scim(s: &Srv, method: Method, path: &str, token: &str, body: Option<Value>) -> super::Rep {
    s.req(method, &format!("/scim/v2{path}"), Some(token), body.as_ref(), &[]).await
}

#[tokio::test]
async fn scim_suppression_differee_puis_purge() {
    let s = srv().await;
    let owner = account(&s.st, &owner_opts()).await;
    let token = scim_token(&s, &owner).await["token"].as_str().unwrap().to_string();
    let jean = account(&s.st, &AccountOpts::default()).await;
    let r = scim(&s, Method::POST, "/Users", &token, Some(json!({ "userName": jean.email }))).await;
    assert_eq!(r.status, 201);
    let id = r.body["id"].as_str().unwrap().to_string();
    assert!(r.body["meta"]["location"].as_str().unwrap().starts_with(&format!("{}/scim/v2/Users/", s.base)));
    let r = scim(&s, Method::DELETE, &format!("/Users/{id}"), &token, None).await;
    assert_eq!(r.status, 204);
    assert_eq!(scim(&s, Method::GET, &format!("/Users/{id}"), &token, None).await.status, 404);
    let uid = jean.id.clone();
    let (disabled, at): (bool, i64) = s
        .st
        .db
        .read(move |c| Ok(c.query_row("SELECT disabled, deprovision_at FROM users WHERE id = ?1", [uid], |r| Ok((r.get(0)?, r.get(1)?)))?))
        .await
        .unwrap();
    assert!(disabled);
    assert!((at - (now_unix() + 30 * DAY)).abs() < 60, "suppression dans 30 jours (défaut)");
    // Pas avant l'échéance…
    assert_eq!(s.st.db.call(|c| crate::identity_admin::purge_deprovisioned(c, now_unix())).await.unwrap(), 0);
    // …puis à l'échéance.
    let n = s.st.db.call(move |c| crate::identity_admin::purge_deprovisioned(c, at)).await.unwrap();
    assert_eq!(n, 1);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM audit WHERE action = 'directory.user_purged'").await, 1);
    let uid = jean.id.clone();
    let left: i64 = s.st.db.read(move |c| Ok(c.query_row("SELECT COUNT(*) FROM users WHERE id = ?1", [uid], |r| r.get(0))?)).await.unwrap();
    assert_eq!(left, 0);
}

#[tokio::test]
async fn scim_desactivation_seule_selon_la_politique() {
    let s = srv().await;
    let owner = account(&s.st, &owner_opts()).await;
    set_setting(&s.st, "directory.deprovision", json!("disable")).await;
    let token = scim_token(&s, &owner).await["token"].as_str().unwrap().to_string();
    let jean = account(&s.st, &AccountOpts::default()).await;
    let r = scim(&s, Method::POST, "/Users", &token, Some(json!({ "userName": jean.email }))).await;
    let id = r.body["id"].as_str().unwrap().to_string();
    assert_eq!(scim(&s, Method::DELETE, &format!("/Users/{id}"), &token, None).await.status, 204);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM users WHERE disabled = 1 AND deprovision_at IS NULL AND disabled_reason = 'scim'").await, 1);
}

#[tokio::test]
async fn scim_ne_desactive_jamais_le_dernier_proprietaire() {
    let s = srv().await;
    let owner = account(&s.st, &owner_opts()).await;
    let token = scim_token(&s, &owner).await["token"].as_str().unwrap().to_string();
    let r = scim(&s, Method::POST, "/Users", &token, Some(json!({ "userName": owner.email }))).await;
    let id = r.body["id"].as_str().unwrap().to_string();
    let patch = json!({ "Operations": [{ "op": "replace", "path": "active", "value": false }] });
    assert_eq!(scim(&s, Method::PATCH, &format!("/Users/{id}"), &token, Some(patch)).await.status, 409);
    assert_eq!(scim(&s, Method::DELETE, &format!("/Users/{id}"), &token, None).await.status, 409);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM users WHERE disabled = 1").await, 0);
}

#[tokio::test]
async fn scim_refuse_un_domaine_non_autorise() {
    let s = srv().await;
    let owner = account(&s.st, &owner_opts()).await;
    set_setting(&s.st, "access.allowed_email_domains", json!(["corp.fr"])).await;
    let token = scim_token(&s, &owner).await["token"].as_str().unwrap().to_string();
    let r = scim(&s, Method::POST, "/Users", &token, Some(json!({ "userName": "jean@autre.fr" }))).await;
    assert_eq!(r.status, 403);
    assert_eq!(r.body["schemas"][0], "urn:ietf:params:scim:api:messages:2.0:Error");
    let r = scim(&s, Method::POST, "/Users", &token, Some(json!({ "userName": "jean@corp.fr" }))).await;
    assert_eq!(r.status, 201);
    let id = r.body["id"].as_str().unwrap().to_string();
    let patch = json!({ "Operations": [{ "op": "replace", "path": "userName", "value": "jean@autre.fr" }] });
    assert_eq!(scim(&s, Method::PATCH, &format!("/Users/{id}"), &token, Some(patch)).await.status, 403);
    assert_eq!(count(&s.st, "SELECT COUNT(*) FROM directory_users WHERE email LIKE '%autre.fr'").await, 0);
}

#[tokio::test]
async fn scim_jeton_expire_refuse() {
    let s = srv().await;
    let owner = account(&s.st, &owner_opts()).await;
    set_setting(&s.st, "scim.token_ttl_days", json!(30)).await;
    let created = scim_token(&s, &owner).await;
    let expires = created["expires_at"].as_i64().expect("expiration annoncée");
    assert!((expires - (now_unix() + 30 * DAY)).abs() < 60);
    let token = created["token"].as_str().unwrap().to_string();
    assert_eq!(scim(&s, Method::GET, "/Users", &token, None).await.status, 200);
    let st = s.get("/api/admin/scim", Some(&owner.token)).await;
    assert!(st.expect(200, "")["last_used_at"].is_i64(), "dernière utilisation notée");
    // Jeton créé il y a 31 jours : refusé.
    s.st.db
        .call(|c| {
            c.execute(
                "UPDATE settings SET value = json_set(value, '$.created_at', ?1) WHERE key = 'scim'",
                [now_unix() - 31 * DAY],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let r = scim(&s, Method::GET, "/Users", &token, None).await;
    assert_eq!(r.status, 401);
    assert!(r.body["detail"].as_str().unwrap().contains("expiré"));
    let st = s.get("/api/admin/identity/status", Some(&owner.token)).await;
    assert!(st.body["scim"]["token_expires_at"].as_i64().unwrap() < now_unix());
    // Durée 0 : sans expiration.
    set_setting(&s.st, "scim.token_ttl_days", json!(0)).await;
    assert_eq!(scim(&s, Method::GET, "/Users", &token, None).await.status, 200);
}

#[tokio::test]
async fn scim_regeneration_confirmee_et_limitee() {
    let s = srv().await;
    let a = account(&s.st, &admin_opts()).await;
    let first = scim_token(&s, &a).await["token"].as_str().unwrap().to_string();
    // Régénérer sans confirmation : 428 ; jeton d'une autre action : 403.
    s.post("/api/admin/scim/token", Some(&a.token), json!({})).await.expect(428, "reauth_required");
    let wrong = step_up(&s.st, &a, "settings").await;
    let r = s.req(Method::POST, "/api/admin/scim/token", Some(&a.token), Some(&json!({})), &[("x-locksy-reauth", &wrong)]).await;
    r.expect(403, "reauth_invalid");
    assert_eq!(scim(&s, Method::GET, "/Users", &first, None).await.status, 200, "l'ancien jeton reste valable");
    let ok = step_up(&s.st, &a, "scim.token").await;
    let r = s.req(Method::POST, "/api/admin/scim/token", Some(&a.token), Some(&json!({})), &[("x-locksy-reauth", &ok)]).await;
    let second = r.expect(200, "")["token"].as_str().unwrap().to_string();
    assert_eq!(scim(&s, Method::GET, "/Users", &first, None).await.status, 401, "ancien jeton révoqué");
    assert_eq!(scim(&s, Method::GET, "/Users", &second, None).await.status, 200);
    // 5 créations par heure : la sixième est refusée.
    s.post("/api/admin/scim/token", Some(&a.token), json!({})).await.expect(428, "reauth_required");
    let r = s.post("/api/admin/scim/token", Some(&a.token), json!({})).await;
    r.expect(429, "rate_limited");
    assert!(r.header("retry-after").is_some());
}

// ------------------------------------------------------------ Extension et état

#[tokio::test]
async fn extension_autorisee() {
    let s = srv().await;
    let path = format!("/api/extension/allowed?id={EXT}");
    // Liste vide : toute extension est acceptée, sauf sans identifiant.
    assert_eq!(s.get(&path, None).await.expect(200, "")["allowed"], true);
    assert_eq!(s.get("/api/extension/allowed", None).await.body["allowed"], false, "sans identifiant");
    // Liste renseignée : seuls les identifiants listés.
    set_setting(&s.st, "extension.allowed_ids", json!([EXT])).await;
    assert_eq!(s.get(&path, None).await.body["allowed"], true);
    assert_eq!(s.get(&format!("/api/extension/allowed?id={}", EXT.to_uppercase()), None).await.body["allowed"], true);
    assert_eq!(s.get("/api/extension/allowed?id=pppppppppppppppppppppppppppppppp", None).await.body["allowed"], false);
}

#[tokio::test]
async fn etat_de_la_connexion_d_entreprise() {
    let s = srv().await;
    let a = account(&s.st, &owner_opts()).await;
    let r = s.get("/api/admin/identity/status", Some(&a.token)).await;
    let b = r.expect(200, "");
    assert_eq!(b["sso"]["configured"], false);
    assert!(b["sso"]["last_test"].is_null() && b["sso"]["last_error"].is_null());
    assert_eq!(b["ldap"]["configured"], false);
    assert!(b["ldap"]["last_sync"].is_null());
    assert_eq!(b["scim"]["token_set"], false);
    assert_eq!(b["scim"]["base_url"], format!("{}/scim/v2", s.base));
    set_setting(&s.st, "instance.public_url", json!("https://coffre.corp.fr")).await;
    scim_token(&s, &a).await;
    let b = s.get("/api/admin/identity/status", Some(&a.token)).await.body;
    assert_eq!(b["scim"]["base_url"], "https://coffre.corp.fr/scim/v2", "adresse publique du registre");
    assert_eq!(b["scim"]["token_set"], true);
    assert!(b["scim"]["token_expires_at"].is_null(), "sans expiration par défaut");
}

#[tokio::test]
async fn delai_de_suppression_reglable() {
    // directory.delete_after_days fixe l'échéance de la suppression d'un
    // compte retiré de l'annuaire (désactivation puis suppression).
    let s = srv().await;
    set_setting(&s.st, "directory.deprovision", json!("disable_then_delete")).await;
    set_setting(&s.st, "directory.delete_after_days", json!(7)).await;
    let mut read = Vec::new();
    for _ in 0..5 {
        read.push(from_directory(&s.st, &AccountOpts::default()).await.1);
    }
    ldap::finish_sync(&s.st, Ok(read[1..].to_vec()), false, None).await.map_err(|e| e.err.code).unwrap();
    let dep: i64 = s
        .st
        .db
        .read(|c| Ok(c.query_row("SELECT deprovision_at FROM users WHERE deprovision_at IS NOT NULL", [], |r| r.get(0))?))
        .await
        .unwrap();
    assert!((dep - now_unix() - 7 * 86_400).abs() <= 5, "{dep}");
}
