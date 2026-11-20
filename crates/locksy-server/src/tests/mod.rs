//! Tests d'intégration du serveur, par domaine. La crate étant binaire, ils
//! vivent dans `src/tests/` et non dans `tests/`.
//!
//! Harnais commun : serveur complet (`build_app`) sur un port local libre,
//! comptes créés directement en base avec leur session, requêtes JSON.
//! Règles : aucun test ne lit ni ne modifie de variable d'environnement, et
//! chacun a sa propre base (les tests tournent en parallèle).

mod admin;
mod audit_chain;
mod authz_matrix;
mod enforce_auth;
mod enforce_data;
mod identity;
mod mail;
mod passwords;
mod settings;

use crate::security::{hash_secret, sha256_hex};
use crate::settings_api::{self, Actor};
use crate::state::AppState;
use locksy_core::crypto;
use locksy_core::encoding::b64e;
use locksy_core::settings::{self as reg, DiffEntry};
use locksy_core::{now_unix, totp};
use reqwest::Method;
use rusqlite::params;
use serde_json::Value;
use std::net::SocketAddr;

/// Serveur de test : routeur complet sur un port local libre.
pub(crate) struct Srv {
    pub base: String,
    pub http: reqwest::Client,
    pub st: AppState,
}

/// Serveur sur un état de test neuf.
pub(crate) async fn srv() -> Srv {
    srv_with(|_| {}).await
}

/// Serveur sur un état de test modifié avant le démarrage (configuration
/// de l'hébergeur, notificateur…).
pub(crate) async fn srv_with(f: impl FnOnce(&mut AppState)) -> Srv {
    let mut st = crate::state::test_state().await;
    f(&mut st);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = crate::build_app(st.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await;
    });
    Srv { base: format!("http://{addr}"), http: reqwest::Client::new(), st }
}

/// Compte connecté.
pub(crate) struct Account {
    pub id: String,
    pub email: String,
    pub token: String,
    pub role: &'static str,
    /// Preuve d'authentification (avec `with_password`, l'empreinte en base
    /// lui correspond : la réauthentification fonctionne).
    pub auth_key: [u8; 32],
}

/// Options de création d'un compte.
pub(crate) struct AccountOpts {
    pub role: &'static str,
    pub totp: bool,
    pub disabled: bool,
    pub created_at: Option<i64>,
    /// Empreinte Argon2 réelle de `auth_key` (plus lent).
    pub with_password: bool,
}

impl Default for AccountOpts {
    fn default() -> Self {
        Self { role: "user", totp: false, disabled: false, created_at: None, with_password: false }
    }
}

/// Insère un compte et une session d'une heure.
pub(crate) async fn account(st: &AppState, o: &AccountOpts) -> Account {
    let id = crypto::new_uuid();
    let email = format!("{}@exemple.fr", &id[..8]);
    let token = crypto::random_token();
    let auth_key: [u8; 32] = crypto::random_array();
    let auth_hash = if o.with_password { hash_secret(auth_key.to_vec()).await.unwrap() } else { "aucune".into() };
    let secret = o.totp.then(|| crate::auth::encrypt_totp_secret(st, &id, &totp::generate_secret()));
    let (u, e, r, h, disabled) = (id.clone(), email.clone(), o.role, sha256_hex(&token), o.disabled);
    let created = o.created_at.unwrap_or_else(now_unix);
    st.db
        .call(move |c| {
            let now = now_unix();
            c.execute(
                "INSERT INTO users (id, email, name, role, disabled, kdf, auth_hash, wrapped_user_key,
                     recovery_wrapped_user_key, recovery_auth_hash, public_key, wrapped_private_key,
                     totp_secret, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'k', ?6, 'x', 'x', 'x', 'p', 'x', ?7, ?8, ?8)",
                params![u, e, format!("Compte {r}"), r, disabled, auth_hash, secret, created],
            )?;
            c.execute(
                "INSERT INTO sessions (id, token_hash, user_id, created_at, last_seen_at, expires_at, ip, device)
                 VALUES (?1, ?2, ?3, ?4, ?4, ?5, '', 'test')",
                params![crypto::new_uuid(), h, u, now, now + 3600],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    Account { id, email, token, role: o.role, auth_key }
}

/// Réponse lue : statut, en-têtes, corps JSON (`Null` si vide, chaîne si
/// ce n'est pas du JSON).
pub(crate) struct Rep {
    pub status: u16,
    pub headers: reqwest::header::HeaderMap,
    pub body: Value,
}

impl Rep {
    /// Vérifie le statut et le code d'erreur (vide pour une réussite) ;
    /// renvoie le corps. Une erreur porte toujours un message.
    #[track_caller]
    pub fn expect(&self, status: u16, code: &str) -> &Value {
        let got = self.body["error"].as_str().unwrap_or("");
        assert_eq!((self.status, got), (status, code), "réponse inattendue : {}", self.body);
        if !code.is_empty() {
            assert!(self.body["message"].as_str().is_some_and(|m| !m.is_empty()), "message absent : {}", self.body);
        }
        &self.body
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

impl Srv {
    pub async fn req(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
        headers: &[(&str, &str)],
    ) -> Rep {
        let mut req = self.http.request(method, format!("{}{path}", self.base));
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        if let Some(b) = body {
            req = req.json(b);
        }
        let res = req.send().await.expect("requête HTTP");
        let status = res.status().as_u16();
        let headers = res.headers().clone();
        let bytes = res.bytes().await.expect("corps de réponse");
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
        };
        Rep { status, headers, body }
    }

    pub async fn get(&self, path: &str, token: Option<&str>) -> Rep {
        self.req(Method::GET, path, token, None, &[]).await
    }

    pub async fn post(&self, path: &str, token: Option<&str>, body: Value) -> Rep {
        self.req(Method::POST, path, token, Some(&body), &[]).await
    }

    pub async fn put(&self, path: &str, token: Option<&str>, body: Value) -> Rep {
        self.req(Method::PUT, path, token, Some(&body), &[]).await
    }

    pub async fn patch(&self, path: &str, token: Option<&str>, body: Value, headers: &[(&str, &str)]) -> Rep {
        self.req(Method::PATCH, path, token, Some(&body), headers).await
    }

    pub async fn delete(&self, path: &str, token: Option<&str>) -> Rep {
        self.req(Method::DELETE, path, token, None, &[]).await
    }
}

/// En-tête de réauthentification d'un compte (`X-Locksy-Reauth`).
pub(crate) fn reauth_header(a: &Account) -> (&'static str, String) {
    ("x-locksy-reauth", b64e(&a.auth_key))
}

/// Écrit un réglage par le stockage du registre (une révision, historique
/// « api »). `value` : valeur nue, ou `{value, mode, min, max}` pour une clé
/// à modes.
pub(crate) async fn set_setting(st: &AppState, key: &'static str, value: Value) {
    let (server_key, host) = (st.server_key.clone(), st.host.caps.clone());
    st.db
        .call(move |c| {
            let tx = c.transaction()?;
            let d = reg::def(key).expect("clé du registre");
            let (eff, _) = settings_api::load_effective(&tx, &host)?;
            let old = eff.stored(key).cloned().expect("valeur actuelle");
            let mut new = reg::stored_from_json(d, &value).expect("valeur lisible");
            if d.modes && new.mode.is_none() {
                new = reg::StoredValue { mode: old.mode, min: old.min.clone(), max: old.max.clone(), ..new };
            }
            let new = reg::check_stored(d, &new, &host).expect("valeur valide");
            let entry = DiffEntry { key: key.into(), old, new, lowered: false };
            let actor = Actor { user_id: None, email: String::new(), ip: String::new() };
            settings_api::apply(&tx, &[entry], &actor, "api", None, &server_key, &host)?;
            tx.commit()?;
            Ok(())
        })
        .await
        .unwrap();
}

/// Résultat d'un `SELECT COUNT(*)` (ou de toute requête renvoyant un entier).
pub(crate) async fn count(st: &AppState, sql: &'static str) -> i64 {
    st.db.read(move |c| Ok(c.query_row(sql, [], |r| r.get(0))?)).await.unwrap()
}
