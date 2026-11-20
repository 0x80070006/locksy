//! Domaine « enforce_auth » (lot L7a) : seuils et règles appliqués par le
//! serveur à l'authentification et au compte. Pour chaque réglage appliqué
//! ici, un test « valeur modifiée → comportement changé ».

use super::{account, set_setting, Account, AccountOpts, Rep, Srv};
use crate::error::ApiResult;
use crate::mail::{Notification, Notifier, NotifyOutcome};
use crate::security as sec;
use crate::state::{AppState, Config};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHasher, SaltString};
use locksy_core::crypto::{self, KdfParams, SecretKey};
use locksy_core::encoding::{b64e, base32_encode};
use locksy_core::settings::Effective;
use locksy_core::{now_unix, totp};
use reqwest::Method;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

// ------------------------------------------------------------ Harnais

/// L'adresse cliente est lue dans X-Forwarded-For (un proxy devant).
fn trust_proxy(st: &mut AppState) {
    let b = &st.config;
    st.config = Arc::new(Config {
        bind: b.bind.clone(),
        data_dir: b.data_dir.clone(),
        web_dir: b.web_dir.clone(),
        trust_proxy: true,
        trusted_proxies: Vec::new(),
        hsts: b.hsts,
        request_timeout: b.request_timeout,
        header_timeout: b.header_timeout,
        argon2_concurrency: b.argon2_concurrency,
        argon2_queue: b.argon2_queue,
    });
}

/// Notificateur qui garde la trace de chaque demande d'envoi.
#[derive(Default)]
struct Recorder(Mutex<Vec<String>>);

impl Recorder {
    fn events(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }

    fn has(&self, event: &str) -> bool {
        self.events().iter().any(|e| e == event)
    }
}

impl Notifier for Recorder {
    fn enqueue(&self, _c: &Connection, _s: &Effective, n: &Notification) -> ApiResult<NotifyOutcome> {
        let label = match n {
            Notification::SecurityChange { event, .. } => (*event).to_string(),
            Notification::NewDevice { device, ip, .. } => format!("new_device:{device}@{ip}"),
            _ => "autre".to_string(),
        };
        self.0.lock().unwrap().push(label);
        Ok(NotifyOutcome::Queued)
    }
}

/// Serveur du lot dont les notifications sont enregistrées.
async fn srv_recorded() -> (Srv, Arc<Recorder>) {
    let rec = Arc::new(Recorder::default());
    let r = rec.clone();
    (super::srv_with(move |st| st.notifier = r).await, rec)
}

/// Compte avec mot de passe vérifiable (et 2FA si demandé).
async fn user(s: &Srv, role: &'static str, totp: bool) -> Account {
    full(&s.st, &AccountOpts { role, totp, with_password: true, ..Default::default() }).await
}

/// Compte du harnais complété de paramètres de dérivation lisibles (le
/// profil les renvoie).
async fn full(st: &AppState, o: &AccountOpts) -> Account {
    let a = account(st, o).await;
    let (uid, kdf) = (a.id.clone(), serde_json::to_string(&KdfParams::recommended()).unwrap());
    st.db
        .call(move |c| {
            c.execute("UPDATE users SET kdf = ?1 WHERE id = ?2", params![kdf, uid])?;
            Ok(())
        })
        .await
        .unwrap();
    a
}

/// Entier lu en base.
async fn int(st: &AppState, sql: &str, args: Vec<String>) -> i64 {
    let sql = sql.to_string();
    st.db
        .read(move |c| Ok(c.query_row(&sql, rusqlite::params_from_iter(args.iter()), |r| r.get(0))?))
        .await
        .unwrap()
}

/// Nombre de lignes du journal pour une action.
async fn audits(st: &AppState, action: &str) -> i64 {
    int(st, "SELECT COUNT(*) FROM audit WHERE action = ?1", vec![action.into()]).await
}

/// Code TOTP d'un compte, décalé de `offset` pas de 30 s (un même pas ne
/// sert qu'une fois).
async fn totp_code(st: &AppState, user_id: &str, offset: i64) -> String {
    let uid = user_id.to_string();
    let enc: String = st
        .db
        .read(move |c| Ok(c.query_row("SELECT totp_secret FROM users WHERE id = ?1", [uid], |r| r.get(0))?))
        .await
        .unwrap();
    let raw = crate::auth::decrypt_totp_secret(&st.server_key, user_id, &enc).unwrap();
    let cfg = totp::parse(&base32_encode(&raw)).unwrap();
    totp::code_at(&cfg, (now_unix() + offset * 30) as u64)
}

/// Code TOTP faux à coup sûr (aucun des pas acceptés).
async fn wrong_totp(st: &AppState, user_id: &str) -> String {
    let mut ok = Vec::new();
    for o in -1..=1 {
        ok.push(totp_code(st, user_id, o).await);
    }
    (0..10).map(|d| format!("{d}{d}{d}{d}{d}{d}")).find(|c| !ok.contains(c)).unwrap()
}

fn login_body(a: &Account, key: &[u8; 32], totp: Option<&str>) -> Value {
    json!({ "email": a.email, "auth_key": b64e(key), "totp": totp, "device": "Poste de test" })
}

async fn login(s: &Srv, a: &Account, totp: Option<&str>) -> Rep {
    s.post("/api/auth/login", None, login_body(a, &a.auth_key, totp)).await
}

/// Connexion depuis une adresse donnée (serveur derrière un proxy de confiance).
async fn login_from(s: &Srv, body: &Value, ip: &str) -> Rep {
    s.req(Method::POST, "/api/auth/login", None, Some(body), &[("x-forwarded-for", ip)]).await
}

/// Jeton de réauthentification pour `action`.
async fn step_up(s: &Srv, a: &Account, action: &str, totp: Option<&str>) -> String {
    let rep = s
        .post("/api/auth/reauth", Some(&a.token), json!({ "action": action, "auth_key": b64e(&a.auth_key), "totp": totp }))
        .await;
    let body = rep.expect(200, "");
    assert_eq!(body["action"], json!(action));
    assert_eq!(body["expires_in"], json!(120));
    body["token"].as_str().unwrap().to_string()
}

/// Requête POST avec un en-tête de réauthentification.
async fn post_reauth(s: &Srv, a: &Account, path: &str, body: Value, token: &str) -> Rep {
    s.req(Method::POST, path, Some(&a.token), Some(&body), &[("x-locksy-reauth", token)]).await
}

/// Le 429 porte Retry-After (en-tête et corps), entre 1 et `max` secondes.
#[track_caller]
fn assert_retry_after(rep: &Rep, max: i64) -> i64 {
    rep.expect(429, "rate_limited");
    let secs: i64 = rep.header("retry-after").expect("en-tête Retry-After").parse().unwrap();
    assert!((1..=max).contains(&secs), "Retry-After = {secs}, attendu 1..={max}");
    assert_eq!(rep.body["retry_after"], json!(secs));
    secs
}

/// Empreinte Argon2id calculée avec d'autres paramètres que ceux du serveur.
fn weak_phc(key: &[u8]) -> String {
    let a = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(8 * 1024, 1, 1, None).unwrap(),
    );
    a.hash_password(key, &SaltString::generate(&mut OsRng)).unwrap().to_string()
}

fn kdf_json(mib: u32, t: u32) -> Value {
    json!(KdfParams { m_kib: mib * 1024, t, ..KdfParams::recommended() })
}

// ------------------------------------------------------------ Réauthentification (step-up)

#[tokio::test]
async fn reauthentification_jeton_court_lie_a_l_action() {
    let s = super::srv().await;
    let a = user(&s, "user", false).await;
    let export = json!({ "scope": "all", "items": 3, "attachments": false, "format": "csv" });

    // Absent : 428 ; action inconnue : 400 ; preuve fausse : 403.
    s.post("/api/me/export", Some(&a.token), export.clone()).await.expect(428, "reauth_required");
    s.post("/api/auth/reauth", Some(&a.token), json!({ "action": "admin.tout", "auth_key": b64e(&a.auth_key) }))
        .await
        .expect(400, "bad_request");
    s.post("/api/auth/reauth", Some(&a.token), json!({ "action": "vault.export", "auth_key": b64e(&[0u8; 32]) }))
        .await
        .expect(403, "invalid_credentials");

    // Jeton d'une autre action : refusé (et consommé).
    let t = step_up(&s, &a, "settings", None).await;
    assert!(t.starts_with("rt1.") && t.len() == 47, "{t}");
    post_reauth(&s, &a, "/api/me/export", export.clone(), &t).await.expect(403, "reauth_invalid");

    // Bon jeton : une seule fois.
    let t = step_up(&s, &a, "vault.export", None).await;
    post_reauth(&s, &a, "/api/me/export", export.clone(), &t).await.expect(204, "");
    post_reauth(&s, &a, "/api/me/export", export.clone(), &t).await.expect(403, "reauth_invalid");

    // Périmé.
    let t = step_up(&s, &a, "vault.export", None).await;
    sec::testing::expire_step_ups(&a.id);
    post_reauth(&s, &a, "/api/me/export", export.clone(), &t).await.expect(403, "reauth_invalid");

    // Forme historique (preuve en base64) : « settings » seulement.
    post_reauth(&s, &a, "/api/me/export", export.clone(), &b64e(&a.auth_key)).await.expect(403, "reauth_invalid");

    // Lié à la session : une autre session du même compte ne peut pas s'en servir.
    let t = step_up(&s, &a, "vault.export", None).await;
    let other = login(&s, &a, None).await.expect(200, "")["token"].as_str().unwrap().to_string();
    let rep = s.req(Method::POST, "/api/me/export", Some(&other), Some(&export), &[("x-locksy-reauth", &t)]).await;
    rep.expect(403, "reauth_invalid");

    assert_eq!(audits(&s.st, "auth.step_up").await, 4);
    assert_eq!(audits(&s.st, "vault.exported").await, 1);
}

#[tokio::test]
async fn reauthentification_bloquee_apres_cinq_preuves_fausses() {
    let s = super::srv().await;
    let a = user(&s, "user", false).await;
    let faux = json!({ "action": "settings", "auth_key": b64e(&[1u8; 32]) });
    for _ in 0..5 {
        s.post("/api/auth/reauth", Some(&a.token), faux.clone()).await.expect(403, "invalid_credentials");
    }
    let rep = s.post("/api/auth/reauth", Some(&a.token), json!({ "action": "settings", "auth_key": b64e(&a.auth_key) })).await;
    assert_retry_after(&rep, 30);
}

#[tokio::test]
async fn reauthentification_exige_le_second_facteur_pour_retirer_la_2fa() {
    let (s, rec) = srv_recorded().await;
    let a = user(&s, "user", true).await;
    let base = json!({ "action": "totp.disable", "auth_key": b64e(&a.auth_key) });
    s.post("/api/auth/reauth", Some(&a.token), base.clone()).await.expect(401, "totp_required");
    let mut faux = base.clone();
    faux["totp"] = json!(wrong_totp(&s.st, &a.id).await);
    s.post("/api/auth/reauth", Some(&a.token), faux).await.expect(401, "invalid_totp");
    // Pour « settings », le mot de passe suffit, même avec la 2FA.
    step_up(&s, &a, "settings", None).await;

    let code = totp_code(&s.st, &a.id, 0).await;
    let t = step_up(&s, &a, "totp.disable", Some(&code)).await;
    // Sans code dans le corps : le jeton suffit.
    let rep = post_reauth(&s, &a, "/api/me/2fa/disable", json!({}), &t).await;
    assert_eq!(rep.expect(200, "")["totp_enabled"], json!(false));
    assert!(rec.has("2fa.disabled"));
    s.post("/api/me/2fa/disable", Some(&a.token), json!({ "code": "123456" })).await.expect(409, "totp_not_enabled");
}

// ------------------------------------------------------------ Codes de secours

#[tokio::test]
async fn codes_de_secours_generation_consommation_regeneration() {
    let (s, rec) = srv_recorded().await;
    let a = user(&s, "user", true).await;
    let status = s.get("/api/me/2fa/recovery-codes", Some(&a.token)).await;
    assert_eq!(status.expect(200, ""), &json!({ "remaining": 0, "total": 0, "generated_at": null }));

    // Jeton « totp.recovery_codes » exigé.
    s.post("/api/me/2fa/recovery-codes", Some(&a.token), json!({})).await.expect(428, "reauth_required");
    let code = totp_code(&s.st, &a.id, 0).await;
    let t = step_up(&s, &a, "totp.recovery_codes", Some(&code)).await;
    let rep = post_reauth(&s, &a, "/api/me/2fa/recovery-codes", json!({}), &t).await;
    let body = rep.expect(200, "");
    let codes: Vec<String> = serde_json::from_value(body["codes"].clone()).unwrap();
    assert_eq!(codes.len(), 10);
    assert!(codes.iter().all(|c| sec::looks_like_recovery_code(c) && c.len() == 11));
    assert!(rec.has("2fa.recovery_codes_generated"));
    // Seules les empreintes sont gardées.
    let clair = int(&s.st, "SELECT COUNT(*) FROM totp_recovery_codes WHERE code_hash = ?1", vec![codes[0].clone()]).await;
    assert_eq!(clair, 0);
    let status = s.get("/api/me/2fa/recovery-codes", Some(&a.token)).await;
    assert_eq!(status.expect(200, "")["remaining"], json!(10));
    assert_eq!(status.body["total"], json!(10));
    assert_eq!(status.body["generated_at"], body["generated_at"]);

    // Connexion avec un code de secours (casse et tiret indifférents), une seule fois.
    let saisie = codes[0].to_lowercase().replace('-', " ");
    login(&s, &a, Some(&saisie)).await.expect(200, "");
    login(&s, &a, Some(&codes[0])).await.expect(401, "invalid_totp");
    assert_eq!(s.get("/api/me/2fa/recovery-codes", Some(&a.token)).await.body["remaining"], json!(9));
    assert_eq!(audits(&s.st, "2fa.recovery_code_used").await, 1);
    assert!(rec.has("2fa.recovery_code_used"));

    // Régénération : les anciens codes ne valent plus.
    let code = totp_code(&s.st, &a.id, 1).await;
    let t = step_up(&s, &a, "totp.recovery_codes", Some(&code)).await;
    let nouveaux = post_reauth(&s, &a, "/api/me/2fa/recovery-codes", json!({}), &t).await.expect(200, "").clone();
    login(&s, &a, Some(&codes[1])).await.expect(401, "invalid_totp");
    login(&s, &a, Some(nouveaux["codes"][0].as_str().unwrap())).await.expect(200, "");

    // Un code de secours confirme aussi une réauthentification.
    let t = step_up(&s, &a, "vault.export", Some(nouveaux["codes"][1].as_str().unwrap())).await;
    assert!(t.starts_with("rt1."));
}

#[tokio::test]
async fn codes_de_secours_a_l_activation_et_supprimes_au_retrait() {
    let s = super::srv().await;
    let a = user(&s, "user", false).await;
    s.post("/api/me/2fa/recovery-codes", Some(&a.token), json!({})).await.expect(409, "totp_not_enabled");

    let setup = s.post("/api/me/2fa/setup", Some(&a.token), json!({})).await;
    let secret = setup.expect(200, "")["secret"].as_str().unwrap().to_string();
    let cfg = totp::parse(&secret).unwrap();
    let rep = s.post("/api/me/2fa/enable", Some(&a.token), json!({ "code": totp::code_at(&cfg, now_unix() as u64) })).await;
    let body = rep.expect(200, "");
    // Profil aplati, plus les codes.
    assert_eq!(body["totp_enabled"], json!(true));
    assert_eq!(body["id"], json!(a.id));
    assert_eq!(body["recovery_codes"].as_array().unwrap().len(), 10);
    assert_eq!(int(&s.st, "SELECT COUNT(*) FROM totp_recovery_codes WHERE user_id = ?1", vec![a.id.clone()]).await, 10);

    // Retrait par un code de secours (sans jeton) : les codes disparaissent.
    let code = body["recovery_codes"][0].as_str().unwrap();
    s.post("/api/me/2fa/disable", Some(&a.token), json!({ "code": code })).await.expect(200, "");
    assert_eq!(int(&s.st, "SELECT COUNT(*) FROM totp_recovery_codes WHERE user_id = ?1", vec![a.id.clone()]).await, 0);
    let status = s.get("/api/me/2fa/recovery-codes", Some(&a.token)).await;
    assert_eq!(status.expect(200, ""), &json!({ "remaining": 0, "total": 0, "generated_at": null }));
}

/// Secret 2FA chiffré par une autre clé serveur (clé régénérée, restauration
/// sans la clé) : erreur claire 409 `totp_unreadable`, jamais un 500.
#[tokio::test]
async fn secret_2fa_illisible_apres_changement_de_cle() {
    let s = super::srv().await;
    let a = user(&s, "user", true).await;
    let autre = crypto::encrypt_str(&SecretKey::generate(), "JBSWY3DPEHPK3PXP", &locksy_core::aad::server_totp(&a.id));
    let id = a.id.clone();
    s.st.db
        .call(move |c| Ok(c.execute("UPDATE users SET totp_secret = ?1 WHERE id = ?2", params![autre, id])?))
        .await
        .unwrap();
    let rep = login(&s, &a, Some("123456")).await;
    let body = rep.expect(409, "totp_unreadable");
    assert!(body["message"].as_str().unwrap().contains("administrateur"), "{body}");
    // Même réponse pour une réauthentification avec un code.
    let rep = s
        .post("/api/auth/reauth", Some(&a.token), json!({ "action": "vault.export", "auth_key": b64e(&a.auth_key), "totp": "123456" }))
        .await;
    assert!(rep.status < 500, "{} {}", rep.status, rep.body);
}

// ------------------------------------------------------------ Mot de passe maître

fn password_body(current: &[u8; 32], kdf: Value, totp: Option<&str>) -> Value {
    let k = SecretKey::generate();
    json!({
        "current_auth_key": b64e(current),
        "auth_key": b64e(&[42u8; 32]),
        "kdf": kdf,
        "wrapped_user_key": crypto::wrap_key(&k, &k, "test:user"),
        "totp": totp,
    })
}

#[tokio::test]
async fn changement_de_mot_de_passe_403_totp_et_planchers() {
    let (s, rec) = srv_recorded().await;
    let a = user(&s, "user", true).await;
    let kdf = kdf_json(64, 3);
    // Preuve refusée : 403 (plus 401, qui déconnecterait le client).
    let code = totp_code(&s.st, &a.id, 0).await;
    s.post("/api/me/password", Some(&a.token), password_body(&[0u8; 32], kdf.clone(), Some(&code)))
        .await
        .expect(403, "invalid_credentials");
    // Second facteur obligatoire.
    s.post("/api/me/password", Some(&a.token), password_body(&a.auth_key, kdf.clone(), None))
        .await
        .expect(401, "totp_required");
    let faux = wrong_totp(&s.st, &a.id).await;
    s.post("/api/me/password", Some(&a.token), password_body(&a.auth_key, kdf.clone(), Some(&faux)))
        .await
        .expect(401, "invalid_totp");
    // kdf.min_memory_mib relevé : 64 Mio exigés.
    set_setting(&s.st, "kdf.min_memory_mib", json!(128)).await;
    s.post("/api/me/password", Some(&a.token), password_body(&a.auth_key, kdf.clone(), Some(&code)))
        .await
        .expect(422, "kdf_too_weak");
    set_setting(&s.st, "kdf.min_iterations", json!(4)).await;
    s.post("/api/me/password", Some(&a.token), password_body(&a.auth_key, kdf_json(128, 3), Some(&code)))
        .await
        .expect(422, "kdf_too_weak");

    // Réussite : autres sessions fermées, notification.
    // Codes calculés au dernier moment : le test peut durer plus d'un pas de 30 s.
    let autre = login(&s, &a, Some(&totp_code(&s.st, &a.id, 0).await)).await.expect(200, "")["token"]
        .as_str()
        .unwrap()
        .to_string();
    let code = totp_code(&s.st, &a.id, 1).await;
    s.post("/api/me/password", Some(&a.token), password_body(&a.auth_key, kdf_json(128, 4), Some(&code)))
        .await
        .expect(204, "");
    s.get("/api/me", Some(&autre)).await.expect(401, "unauthorized");
    s.get("/api/me", Some(&a.token)).await.expect(200, "");
    assert!(rec.has("password.changed"));
}

/// Mise à jour conditionnelle : si l'empreinte a changé depuis la
/// vérification (autre appareil, récupération), rien n'est écrit (409).
#[tokio::test]
async fn changement_de_mot_de_passe_concurrent_409() {
    let s = super::srv().await;
    let a = user(&s, "user", false).await;
    let uid = a.id.clone();
    let (verifiee, en_base) = s
        .st
        .db
        .call(move |c| {
            let h: String = c.query_row("SELECT auth_hash FROM users WHERE id = ?1", [&uid], |r| r.get(0))?;
            // Un autre appareil change le mot de passe entre-temps.
            crate::me::update_secret(c, &uid, &h, "empreinte-b", "{}", "cle-b")?;
            let perdu = crate::me::update_secret(c, &uid, &h, "empreinte-c", "{}", "cle-c").unwrap_err();
            assert_eq!((perdu.status.as_u16(), perdu.code), (409, "password_changed_concurrently"));
            let apres: String = c.query_row("SELECT auth_hash FROM users WHERE id = ?1", [&uid], |r| r.get(0))?;
            Ok((h, apres))
        })
        .await
        .unwrap();
    assert_ne!(verifiee, en_base);
    assert_eq!(en_base, "empreinte-b");
}

#[tokio::test]
async fn rotation_de_la_cle_de_recuperation() {
    let (s, rec) = srv_recorded().await;
    let a = user(&s, "user", true).await;
    let k = SecretKey::generate();
    let body = |current: &[u8; 32], totp: Option<String>| {
        json!({
            "current_auth_key": b64e(current),
            "recovery_wrapped_user_key": crypto::wrap_key(&k, &k, "test:recovery"),
            "recovery_auth": b64e(&[5u8; 32]),
            "totp": totp,
        })
    };
    s.post("/api/me/recovery", Some(&a.token), body(&[0u8; 32], Some(totp_code(&s.st, &a.id, 0).await)))
        .await
        .expect(403, "invalid_credentials");
    s.post("/api/me/recovery", Some(&a.token), body(&a.auth_key, None)).await.expect(401, "totp_required");
    s.post("/api/me/recovery", Some(&a.token), body(&a.auth_key, Some(totp_code(&s.st, &a.id, 0).await)))
        .await
        .expect(204, "");
    assert!(rec.has("recovery_key.rotated"));
    // Avec un jeton « recovery.rotate », ni preuve ni code dans le corps.
    let t = step_up(&s, &a, "recovery.rotate", Some(&totp_code(&s.st, &a.id, 1).await)).await;
    post_reauth(&s, &a, "/api/me/recovery", body(&[0u8; 32], None), &t).await.expect(204, "");
    post_reauth(&s, &a, "/api/me/recovery", body(&[0u8; 32], None), &t).await.expect(403, "reauth_invalid");
    assert_eq!(audits(&s.st, "recovery_key.rotated").await, 2);
}

// ------------------------------------------------------------ Paramètres de dérivation

#[tokio::test]
async fn montee_du_kdf_client() {
    let s = super::srv().await;
    let a = user(&s, "user", false).await;
    let (uid, kdf) = (a.id.clone(), serde_json::to_string(&KdfParams { m_kib: 32 * 1024, t: 2, ..KdfParams::recommended() }).unwrap());
    s.st.db
        .call(move |c| {
            c.execute("UPDATE users SET kdf = ?1 WHERE id = ?2", params![kdf, uid])?;
            Ok(())
        })
        .await
        .unwrap();
    let k = SecretKey::generate();
    let body = |kdf: Value| {
        json!({
            "current_auth_key": b64e(&a.auth_key),
            "kdf": kdf,
            "auth_key": b64e(&[77u8; 32]),
            "wrapped_user_key": crypto::wrap_key(&k, &k, "test:user"),
        })
    };
    let autre = login(&s, &a, None).await.expect(200, "")["token"].as_str().unwrap().to_string();
    // Baisse refusée (mémoire ou passes).
    s.post("/api/me/kdf", Some(&a.token), body(kdf_json(19, 3))).await.expect(422, "kdf_too_weak");
    // Réglage coupé : refus.
    set_setting(&s.st, "kdf.upgrade_on_login", json!(false)).await;
    s.post("/api/me/kdf", Some(&a.token), body(kdf_json(64, 3))).await.expect(409, "conflict");
    set_setting(&s.st, "kdf.upgrade_on_login", json!(true)).await;
    let rep = s.post("/api/me/kdf", Some(&a.token), body(kdf_json(64, 3))).await;
    assert_eq!(rep.expect(200, "")["kdf"]["m_kib"], json!(64 * 1024));
    assert_eq!(audits(&s.st, "login.kdf_upgraded").await, 1);
    // Les autres sessions restent ouvertes ; la nouvelle preuve sert à la connexion.
    s.get("/api/me", Some(&autre)).await.expect(200, "");
    s.post("/api/auth/login", None, login_body(&a, &[77u8; 32], None)).await.expect(200, "");
}

#[tokio::test]
async fn empreinte_serveur_recalculee_a_la_connexion() {
    let s = super::srv().await;
    let a = user(&s, "user", false).await;
    let (uid, phc) = (a.id.clone(), weak_phc(&a.auth_key));
    s.st.db
        .call(move |c| {
            c.execute("UPDATE users SET auth_hash = ?1 WHERE id = ?2", params![phc, uid])?;
            Ok(())
        })
        .await
        .unwrap();
    login(&s, &a, None).await.expect(200, "");
    assert_eq!(audits(&s.st, "login.rehashed").await, 1);
    let uid = a.id.clone();
    let phc: String = s
        .st
        .db
        .read(move |c| Ok(c.query_row("SELECT auth_hash FROM users WHERE id = ?1", [uid], |r| r.get(0))?))
        .await
        .unwrap();
    assert!(!sec::needs_rehash(&phc), "{phc}");
    // La connexion suivante ne recalcule plus rien.
    login(&s, &a, None).await.expect(200, "");
    assert_eq!(audits(&s.st, "login.rehashed").await, 1);
}

#[tokio::test]
async fn kdf_factice_suit_la_politique() {
    let s = super::srv().await;
    let prelogin = |email: &str| s.post("/api/auth/prelogin", None, json!({ "email": email }));
    let defaut = prelogin("personne@exemple.fr").await.expect(200, "")["kdf"].clone();
    assert_eq!((defaut["m_kib"].clone(), defaut["t"].clone()), (json!(64 * 1024), json!(3)));

    set_setting(&s.st, "kdf.memory_mib", json!(128)).await;
    set_setting(&s.st, "kdf.iterations", json!(4)).await;
    set_setting(&s.st, "kdf.parallelism", json!(2)).await;
    // Compte réel créé sous la nouvelle politique.
    let a = user(&s, "user", false).await;
    let (uid, kdf) = (
        a.id.clone(),
        serde_json::to_string(&KdfParams { m_kib: 128 * 1024, t: 4, p: 2, ..KdfParams::recommended() }).unwrap(),
    );
    s.st.db
        .call(move |c| {
            c.execute("UPDATE users SET kdf = ?1 WHERE id = ?2", params![kdf, uid])?;
            Ok(())
        })
        .await
        .unwrap();
    let reel = prelogin(&a.email).await.expect(200, "")["kdf"].clone();
    let factice = prelogin("personne@exemple.fr").await.expect(200, "")["kdf"].clone();
    for champ in ["alg", "m_kib", "t", "p"] {
        assert_eq!(reel[champ], factice[champ], "champ {champ}");
    }
    assert_eq!(reel["salt"].as_str().unwrap().len(), factice["salt"].as_str().unwrap().len());
    assert_eq!(factice["salt"], defaut["salt"], "sel stable pour une adresse");
}

// ------------------------------------------------------------ Connexion : verrouillage

#[tokio::test]
async fn seuil_par_paire_regle() {
    let (s, rec) = srv_recorded().await;
    let a = user(&s, "user", false).await;
    let faux = login_body(&a, &[0u8; 32], None);
    // Défaut : 5 échecs tolérés. Réglé à 3 : le quatrième essai est refusé.
    // Délai long : le blocage ne doit pas expirer pendant le test.
    set_setting(&s.st, "lockout.pair_threshold", json!(3)).await;
    set_setting(&s.st, "lockout.base_delay_seconds", json!(600)).await;
    for _ in 0..3 {
        s.post("/api/auth/login", None, faux.clone()).await.expect(401, "invalid_credentials");
    }
    let rep = login(&s, &a, None).await;
    assert_retry_after(&rep, 600);
    assert_eq!(audits(&s.st, "login.locked").await, 1);
    assert!(rec.has("login.locked"));
}

#[tokio::test]
async fn delai_de_base_regle() {
    let s = super::srv().await;
    let a = user(&s, "user", false).await;
    set_setting(&s.st, "lockout.base_delay_seconds", json!(7)).await;
    let faux = login_body(&a, &[0u8; 32], None);
    for _ in 0..5 {
        s.post("/api/auth/login", None, faux.clone()).await.expect(401, "invalid_credentials");
    }
    // 7 s au lieu de 30 s.
    assert_retry_after(&login(&s, &a, None).await, 7);
}

#[tokio::test]
async fn delai_maximal_regle() {
    let s = super::srv().await;
    assert_eq!(sec::lockout(&s.st.effective().await.unwrap()), sec::Lockout::default());
    set_setting(&s.st, "lockout.max_delay_seconds", json!(120)).await;
    set_setting(&s.st, "lockout.pair_threshold", json!(4)).await;
    set_setting(&s.st, "lockout.account_threshold", json!(40)).await;
    let l = sec::lockout(&s.st.effective().await.unwrap());
    // Seuils et délais transmis au limiteur (progression plafonnée : test
    // unitaire progression_du_blocage de security.rs).
    assert_eq!(l, sec::Lockout { pair: 4, account: 40, base_delay: 30, max_delay: 120 });
}

#[tokio::test]
async fn seuil_par_compte_regle() {
    let s = super::srv_with(trust_proxy).await;
    let a = user(&s, "user", false).await;
    set_setting(&s.st, "lockout.account_threshold", json!(10)).await;
    set_setting(&s.st, "lockout.base_delay_seconds", json!(600)).await;
    let faux = login_body(&a, &[0u8; 32], None);
    // Dix échecs depuis dix adresses : aucune paire n'est bloquée, le compte l'est.
    for i in 1..=10 {
        login_from(&s, &faux, &format!("192.0.2.{i}")).await.expect(401, "invalid_credentials");
    }
    let rep = login_from(&s, &login_body(&a, &a.auth_key, None), "192.0.2.200").await;
    assert_retry_after(&rep, 600);
    assert_eq!(audits(&s.st, "login.locked").await, 1);
}

#[tokio::test]
async fn fautes_de_frappe_puis_code_totp_a_saisir_ne_bloquent_pas() {
    let s = super::srv().await;
    let a = user(&s, "user", true).await;
    for _ in 0..4 {
        s.post("/api/auth/login", None, login_body(&a, &[0u8; 32], None)).await.expect(401, "invalid_credentials");
    }
    // Cinquième essai : bon mot de passe, code à saisir (pas un échec).
    login(&s, &a, None).await.expect(401, "totp_required");
    let code = totp_code(&s.st, &a.id, 0).await;
    login(&s, &a, Some(&code)).await.expect(200, "");
}

#[tokio::test]
async fn plafonds_par_ip_de_l_hebergeur() {
    let s = super::srv_with(|st| {
        let mut h = (*st.host).clone();
        h.rate.login_ip = 2;
        h.rate.prelogin_ip = 2;
        h.rate.register_ip = 2;
        h.rate.recover_ip = 2;
        h.rate.invite_ip = 2;
        st.host = Arc::new(h);
    })
    .await;
    let cas: [(Method, &str, Value, i64); 5] = [
        (Method::POST, "/api/auth/login", json!({ "email": "x@exemple.fr", "auth_key": b64e(&[1u8; 32]) }), 600),
        (Method::POST, "/api/auth/prelogin", json!({ "email": "x@exemple.fr" }), 60),
        (Method::POST, "/api/auth/register", register_body("x@exemple.fr", kdf_json(64, 3)), 3600),
        (Method::POST, "/api/auth/recover/start", json!({ "email": "x@exemple.fr", "recovery_auth": b64e(&[1u8; 32]) }), 3600),
        (Method::GET, "/api/invites/inconnue", Value::Null, 60),
    ];
    for (method, path, body, window) in cas {
        let body = (!body.is_null()).then_some(body);
        for _ in 0..2 {
            let rep = s.req(method.clone(), path, None, body.as_ref(), &[]).await;
            assert_ne!(rep.status, 429, "{path} : {}", rep.body);
        }
        let rep = s.req(method.clone(), path, None, body.as_ref(), &[]).await;
        assert_retry_after(&rep, window);
    }
}

// ------------------------------------------------------------ Connexion : accès

#[tokio::test]
async fn liste_blanche_ip_a_la_connexion() {
    let s = super::srv().await;
    let a = user(&s, "user", false).await;
    let o = user(&s, "owner", false).await;
    login(&s, &a, None).await.expect(200, "");
    set_setting(&s.st, "access.ip_allowlist", json!(["10.0.0.0/8"])).await;
    // Mot de passe vérifié d'abord : un mauvais mot de passe reste un 401.
    s.post("/api/auth/login", None, login_body(&a, &[0u8; 32], None)).await.expect(401, "invalid_credentials");
    login(&s, &a, None).await.expect(403, "ip_not_allowed");
    login(&s, &o, None).await.expect(403, "ip_not_allowed");
    // Réseau de secours : propriétaires seulement.
    set_setting(&s.st, "access.ip_rescue", json!(["127.0.0.0/8"])).await;
    login(&s, &o, None).await.expect(200, "");
    login(&s, &a, None).await.expect(403, "ip_not_allowed");
    assert!(audits(&s.st, "login.refused").await >= 3);
}

#[tokio::test]
async fn compte_desactive_ou_expire() {
    let s = super::srv().await;
    let d = full(&s.st, &AccountOpts { disabled: true, with_password: true, ..Default::default() }).await;
    login(&s, &d, None).await.expect(403, "account_disabled");
    let a = user(&s, "user", false).await;
    let set_until = |t: i64| {
        let uid = a.id.clone();
        s.st.db.call(move |c| {
            c.execute("UPDATE users SET access_until = ?1 WHERE id = ?2", params![t, uid])?;
            Ok(())
        })
    };
    set_until(now_unix() + 3600).await.unwrap();
    login(&s, &a, None).await.expect(200, "");
    set_until(now_unix() - 1).await.unwrap();
    login(&s, &a, None).await.expect(403, "account_expired");
    // Un mauvais mot de passe ne révèle rien.
    s.post("/api/auth/login", None, login_body(&a, &[0u8; 32], None)).await.expect(401, "invalid_credentials");

    // Récupération : la clé correcte révèle l'état du compte.
    let (uid, h) = (d.id.clone(), sec::hash_secret(vec![9u8; 32]).await.unwrap());
    s.st.db
        .call(move |c| {
            c.execute("UPDATE users SET recovery_auth_hash = ?1 WHERE id = ?2", params![h, uid])?;
            Ok(())
        })
        .await
        .unwrap();
    s.post("/api/auth/recover/start", None, json!({ "email": d.email, "recovery_auth": b64e(&[9u8; 32]) }))
        .await
        .expect(403, "account_disabled");
}

// ------------------------------------------------------------ Sessions

#[tokio::test]
async fn duree_de_session_reglee() {
    let s = super::srv().await;
    let a = user(&s, "user", false).await;
    set_setting(&s.st, "session.max_hours", json!(2)).await;
    login(&s, &a, None).await.expect(200, "");
    let duree =
        int(&s.st, "SELECT expires_at - created_at FROM sessions WHERE user_id = ?1 AND device = 'Poste de test'", vec![a.id.clone()])
            .await;
    assert_eq!(duree, 2 * 3600);
}

#[tokio::test]
async fn sessions_par_compte_plafonnees() {
    let s = super::srv().await;
    let a = user(&s, "user", false).await;
    set_setting(&s.st, "session.max_per_user", json!(2)).await;
    let mut jetons = Vec::new();
    for _ in 0..3 {
        jetons.push(login(&s, &a, None).await.expect(200, "")["token"].as_str().unwrap().to_string());
    }
    assert_eq!(int(&s.st, "SELECT COUNT(*) FROM sessions WHERE user_id = ?1", vec![a.id.clone()]).await, 2);
    // Les plus anciennes sont fermées : la session de départ et la première connexion.
    s.get("/api/me", Some(&a.token)).await.expect(401, "unauthorized");
    s.get("/api/me", Some(&jetons[0])).await.expect(401, "unauthorized");
    s.get("/api/me", Some(&jetons[2])).await.expect(200, "");
    assert_eq!(audits(&s.st, "session.evicted").await, 2);
}

#[tokio::test]
async fn nouvel_appareil_signale() {
    let (s, rec) = srv_recorded().await;
    let a = user(&s, "user", false).await;
    // Première connexion du compte : rien à signaler.
    login(&s, &a, None).await.expect(200, "");
    login(&s, &a, None).await.expect(200, "");
    assert!(!rec.events().iter().any(|e| e.starts_with("new_device:")), "{:?}", rec.events());
    let mut body = login_body(&a, &a.auth_key, None);
    body["device"] = json!("Portable personnel");
    s.post("/api/auth/login", None, body.clone()).await.expect(200, "");
    assert_eq!(rec.events().iter().filter(|e| e.starts_with("new_device:Portable personnel@")).count(), 1);
    // Revu : plus de signalement.
    s.post("/api/auth/login", None, body).await.expect(200, "");
    assert_eq!(rec.events().iter().filter(|e| e.starts_with("new_device:")).count(), 1);
}

#[tokio::test]
async fn identifiant_de_session_mal_forme_404() {
    let s = super::srv().await;
    let a = user(&s, "user", false).await;
    s.delete("/api/me/sessions/pas-un-uuid", Some(&a.token)).await.expect(404, "not_found");
}

// ------------------------------------------------------------ 2FA imposée, émetteur

#[tokio::test]
async fn deux_fa_imposee_par_role_dans_le_profil() {
    let s = super::srv().await;
    let old = now_unix() - 30 * 86_400;
    let u = full(&s.st, &AccountOpts { created_at: Some(old), ..Default::default() }).await;
    let adm = full(&s.st, &AccountOpts { role: "admin", created_at: Some(old), ..Default::default() }).await;
    set_setting(&s.st, "twofa.required_roles", json!(["user"])).await;
    // Délai de grâce de 7 jours depuis la règle : pas encore exigée.
    assert_eq!(s.get("/api/me", Some(&u.token)).await.expect(200, "")["must_setup_2fa"], json!(false));
    set_setting(&s.st, "twofa.grace_days", json!(0)).await;
    assert_eq!(s.get("/api/me", Some(&u.token)).await.expect(200, "")["must_setup_2fa"], json!(true));
    assert_eq!(s.get("/api/me", Some(&adm.token)).await.expect(200, "")["must_setup_2fa"], json!(false));
}

#[tokio::test]
async fn emetteur_totp_regle() {
    let s = super::srv().await;
    let a = user(&s, "user", false).await;
    let uri = |r: &Rep| r.body["uri"].as_str().unwrap().to_string();
    let rep = s.post("/api/me/2fa/setup", Some(&a.token), json!({})).await;
    rep.expect(200, "");
    assert!(uri(&rep).contains("issuer=Locksy"), "{}", uri(&rep));
    set_setting(&s.st, "branding.totp_issuer", json!("Coffre Durand")).await;
    let rep = s.post("/api/me/2fa/setup", Some(&a.token), json!({})).await;
    rep.expect(200, "");
    assert!(uri(&rep).contains("Coffre%20Durand"), "{}", uri(&rep));
}

// ------------------------------------------------------------ Export

#[tokio::test]
async fn export_desactivable() {
    let s = super::srv().await;
    let a = user(&s, "user", true).await;
    let corps = json!({ "scope": "personal", "items": 0, "attachments": true, "format": "locksy" });
    // 2FA active : le second facteur est exigé pour « vault.export ».
    s.post("/api/auth/reauth", Some(&a.token), json!({ "action": "vault.export", "auth_key": b64e(&a.auth_key) }))
        .await
        .expect(401, "totp_required");
    let t = step_up(&s, &a, "vault.export", Some(&totp_code(&s.st, &a.id, 0).await)).await;
    let mut faux = corps.clone();
    faux["format"] = json!("xml");
    post_reauth(&s, &a, "/api/me/export", faux, &t).await.expect(400, "bad_request");
    post_reauth(&s, &a, "/api/me/export", corps.clone(), &t).await.expect(204, "");
    set_setting(&s.st, "export.enabled", json!(false)).await;
    let t = step_up(&s, &a, "vault.export", Some(&totp_code(&s.st, &a.id, 1).await)).await;
    post_reauth(&s, &a, "/api/me/export", corps, &t).await.expect(403, "export_disabled");
    assert_eq!(audits(&s.st, "vault.exported").await, 1);
}

// ------------------------------------------------------------ Inscription

/// Corps d'inscription bien formé (clés générées pour l'occasion).
fn register_body(email: &str, kdf: Value) -> Value {
    let user_key = SecretKey::generate();
    let (private, public) = crypto::generate_keypair();
    let ck = SecretKey::generate();
    json!({
        "user_id": crypto::new_uuid(),
        "email": email,
        "name": "Propriétaire",
        "auth_key": b64e(&[7u8; 32]),
        "kdf": kdf,
        "wrapped_user_key": crypto::wrap_key(&user_key, &user_key, "test:user"),
        "recovery_wrapped_user_key": crypto::wrap_key(&user_key, &user_key, "test:recovery"),
        "recovery_auth": b64e(&[8u8; 32]),
        "public_key": b64e(&public),
        "wrapped_private_key": crypto::wrap_key(&user_key, &private, "test:private"),
        "personal_collection": {
            "id": crypto::new_uuid(),
            "enc_name": crypto::encrypt_str(&ck, "Personnel", "test:name"),
            "sealed_key": crypto::seal_key(&public, &ck, "test:collection").unwrap(),
        },
    })
}

#[tokio::test]
async fn inscription_domaines_et_planchers_kdf() {
    let s = super::srv().await;
    let reg = |email: &str, kdf: Value| s.post("/api/auth/register", None, register_body(email, kdf));
    // Sans politique : les contrôles passent, seul le jeton d'installation manque.
    reg("alice@ailleurs.fr", kdf_json(19, 2)).await.expect(403, "setup_token_required");

    set_setting(&s.st, "access.allowed_email_domains", json!(["exemple.fr"])).await;
    reg("alice@ailleurs.fr", kdf_json(64, 3)).await.expect(403, "domain_not_allowed");
    reg("alice@exemple.fr", kdf_json(64, 3)).await.expect(403, "setup_token_required");

    set_setting(&s.st, "kdf.min_memory_mib", json!(64)).await;
    reg("alice@exemple.fr", kdf_json(19, 3)).await.expect(422, "kdf_too_weak");
    set_setting(&s.st, "kdf.min_iterations", json!(3)).await;
    reg("alice@exemple.fr", kdf_json(64, 2)).await.expect(422, "kdf_too_weak");
    reg("alice@exemple.fr", kdf_json(64, 3)).await.expect(403, "setup_token_required");
}

// ------------------------------------------------------------ Récupération

/// Jeton de récupération posé directement en base.
async fn recovery_token(st: &AppState, user_id: &str) -> String {
    let token = crypto::random_token();
    let (h, uid) = (sec::sha256_hex(&token), user_id.to_string());
    st.db
        .call(move |c| {
            c.execute(
                "INSERT INTO recovery_tokens (token_hash, user_id, expires_at) VALUES (?1, ?2, ?3)",
                params![h, uid, now_unix() + 600],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    token
}

#[tokio::test]
async fn recuperation_idempotente() {
    let (s, rec) = srv_recorded().await;
    let a = user(&s, "user", false).await;
    let token = recovery_token(&s.st, &a.id).await;
    let k = SecretKey::generate();
    let corps = |cle: u8, kdf: Value| {
        json!({
            "recovery_token": token,
            "auth_key": b64e(&[cle; 32]),
            "kdf": kdf,
            "wrapped_user_key": crypto::wrap_key(&k, &k, "test:user"),
        })
    };
    let demande = corps(31, kdf_json(64, 3));
    // Plancher relevé : refus avant toute écriture.
    set_setting(&s.st, "kdf.min_memory_mib", json!(128)).await;
    s.post("/api/auth/recover/finish", None, demande.clone()).await.expect(422, "kdf_too_weak");
    set_setting(&s.st, "kdf.min_memory_mib", json!(19)).await;

    let premiere = s.post("/api/auth/recover/finish", None, demande.clone()).await;
    assert_eq!(premiere.expect(200, ""), &json!({ "user_id": a.id }));
    // Même demande rejouée : même réponse, rien de plus.
    let rejeu = s.post("/api/auth/recover/finish", None, demande.clone()).await;
    assert_eq!(rejeu.expect(200, ""), &premiere.body);
    assert_eq!(audits(&s.st, "recovery.completed").await, 1);
    assert_eq!(rec.events().iter().filter(|e| *e == "recovery.completed").count(), 1);
    // Autre demande avec le même jeton : 409.
    s.post("/api/auth/recover/finish", None, corps(32, kdf_json(64, 3))).await.expect(409, "recovery_already_used");
    // Jeton inconnu : 401 comme avant.
    let mut inconnu = demande.clone();
    inconnu["recovery_token"] = json!(crypto::random_token());
    s.post("/api/auth/recover/finish", None, inconnu).await.expect(401, "unauthorized");
    // Le nouveau mot de passe fonctionne, les sessions ont été fermées.
    s.get("/api/me", Some(&a.token)).await.expect(401, "unauthorized");
    s.post("/api/auth/login", None, login_body(&a, &[31u8; 32], None)).await.expect(200, "");
}

// ------------------------------------------------------------ Intégration

#[tokio::test]
async fn session_d_un_compte_desactive_ou_echu() {
    // Route authentifiée sans dépendance au profil (le harnais pose un KDF factice).
    const PING: &str = "/api/settings/policy";
    let s = super::srv().await;
    // Compte désactivé pendant sa session : 403 account_disabled (le client
    // vide la session et l'explique), puis la session n'existe plus (401).
    let a = account(&s.st, &AccountOpts::default()).await;
    s.get(PING, Some(&a.token)).await.expect(200, "");
    let id = a.id.clone();
    s.st.db.call(move |c| Ok(c.execute("UPDATE users SET disabled = 1 WHERE id = ?1", [id])?)).await.unwrap();
    s.get(PING, Some(&a.token)).await.expect(403, "account_disabled");
    s.get(PING, Some(&a.token)).await.expect(401, "unauthorized");
    // Date de fin d'accès dépassée : 403 account_expired.
    let b = account(&s.st, &AccountOpts::default()).await;
    let id = b.id.clone();
    s.st.db
        .call(move |c| Ok(c.execute("UPDATE users SET access_until = unixepoch() - 1 WHERE id = ?1", [id])?))
        .await
        .unwrap();
    s.get(PING, Some(&b.token)).await.expect(403, "account_expired");
    // Fin d'accès future : rien ne change.
    let c = account(&s.st, &AccountOpts::default()).await;
    let id = c.id.clone();
    s.st.db
        .call(move |cn| Ok(cn.execute("UPDATE users SET access_until = unixepoch() + 3600 WHERE id = ?1", [id])?))
        .await
        .unwrap();
    s.get(PING, Some(&c.token)).await.expect(200, "");
}

#[tokio::test]
async fn jeton_de_reauthentification_accepte_par_les_reglages() {
    // verify_reauth délègue à require_step_up(…, "settings") : un jeton rt1
    // de l'action « settings » permet l'abaissement, une seule fois ; un
    // jeton d'une autre action est refusé.
    const SETTINGS: &str = "/api/admin/settings";
    let s = super::srv().await;
    let o = user(&s, "owner", false).await;
    let patch = |jeton: String, heures: i64| {
        let (s, o) = (&s, &o);
        async move {
            let tag = s.get(SETTINGS, Some(&o.token)).await.header("etag").unwrap().to_string();
            let body = json!({ "changes": { "session.max_hours": heures } });
            s.req(Method::PATCH, SETTINGS, Some(&o.token), Some(&body), &[("if-match", &tag), ("x-locksy-reauth", &jeton)])
                .await
        }
    };
    let autre = step_up(&s, &o, "vault.export", None).await;
    patch(autre, 24).await.expect(403, "reauth_invalid");
    let jeton = step_up(&s, &o, "settings", None).await;
    patch(jeton.clone(), 24).await.expect(200, "");
    // Usage unique : rejoué pour un nouvel abaissement, il est refusé.
    patch(jeton, 48).await.expect(403, "reauth_invalid");
}
