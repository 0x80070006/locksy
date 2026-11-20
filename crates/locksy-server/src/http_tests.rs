//! Tests d'intégration HTTP : le routeur complet (`build_app`, avec toutes ses
//! couches) servi sur un vrai port local et interrogé par un client reqwest,
//! comme le feraient le navigateur, l'extension ou le client de bureau.
//!
//! Un vrai port plutôt qu'un appel direct au service : l'adresse du pair
//! (`ConnectInfo`) est alors connue, ce qui rend testables le limiteur et la
//! lecture de X-Forwarded-For.
//!
//! Règles : aucun test ne lit ni ne modifie de variable d'environnement (sauf
//! la lecture, par `init_setup_token`, de `LOCKSY_SETUP_TOKEN`, jamais
//! positionnée ici), ni ne touche `ops::SHUTTING_DOWN`,
//! `security::init_argon2_limits` ou `db::TEST_SINK` : ces globaux sont
//! partagés par les tests qui tournent en parallèle. Chaque test a sa base et
//! son limiteur ; peu de comptes sont créés par HTTP, car chaque inscription
//! coûte deux calculs Argon2 sous un sémaphore global.

use crate::security::{hash_secret, sha256_hex};
use crate::state::{AppState, Cidr, Config};
use locksy_core::crypto::{self, KdfParams, SecretKey};
use locksy_core::encoding::{b64d, b64e};
use locksy_core::{aad, now_unix, totp};
use reqwest::Method;
use rusqlite::params;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;

// ------------------------------------------------------------ Outils

/// Serveur de test : routeur complet sur un port local libre.
struct Serveur {
    base: String,
    http: reqwest::Client,
    st: AppState,
}

/// Réponse lue : statut, en-têtes et corps JSON (`Null` si vide).
struct Rep {
    status: u16,
    headers: reqwest::header::HeaderMap,
    corps: Value,
}

impl Rep {
    /// Code d'erreur stable (`{"error": …}`), ou chaîne vide.
    fn code(&self) -> &str {
        self.corps["error"].as_str().unwrap_or("")
    }

    /// Vérifie le statut et, pour une erreur, le code ; renvoie le corps.
    #[track_caller]
    fn attendu(&self, status: u16, code: &str) -> &Value {
        assert_eq!((self.status, self.code()), (status, code), "réponse inattendue : {}", self.corps);
        if !code.is_empty() {
            assert!(self.corps["message"].as_str().is_some_and(|m| !m.is_empty()), "message absent : {}", self.corps);
        }
        &self.corps
    }
}

async fn demarrer(st: AppState) -> Serveur {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = super::build_app(st.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await;
    });
    Serveur { base: format!("http://{addr}"), http: reqwest::Client::new(), st }
}

impl Serveur {
    async fn envoyer(
        &self,
        methode: Method,
        chemin: &str,
        jeton: Option<&str>,
        corps: Option<&Value>,
        entetes: &[(&str, &str)],
    ) -> Rep {
        let mut req = self.http.request(methode, format!("{}{chemin}", self.base));
        if let Some(j) = jeton {
            req = req.bearer_auth(j);
        }
        for (k, v) in entetes {
            req = req.header(*k, *v);
        }
        if let Some(c) = corps {
            req = req.json(c);
        }
        let res = req.send().await.expect("requête HTTP");
        let status = res.status().as_u16();
        let headers = res.headers().clone();
        let octets = res.bytes().await.expect("corps de réponse");
        let corps = if octets.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&octets).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&octets).into_owned()))
        };
        Rep { status, headers, corps }
    }

    async fn get(&self, chemin: &str, jeton: Option<&str>) -> Rep {
        self.envoyer(Method::GET, chemin, jeton, None, &[]).await
    }

    async fn post(&self, chemin: &str, jeton: Option<&str>, corps: Value) -> Rep {
        self.envoyer(Method::POST, chemin, jeton, Some(&corps), &[]).await
    }

    async fn put(&self, chemin: &str, jeton: Option<&str>, corps: Value) -> Rep {
        self.envoyer(Method::PUT, chemin, jeton, Some(&corps), &[]).await
    }

    async fn delete(&self, chemin: &str, jeton: Option<&str>) -> Rep {
        self.envoyer(Method::DELETE, chemin, jeton, None, &[]).await
    }
}

/// Compte connecté : identifiant, jeton de session et paire X25519.
struct Compte {
    id: String,
    email: String,
    jeton: String,
    privee: SecretKey,
    publique: [u8; 32],
}

/// Corps d'inscription bien formé, construit avec l'API publique du noyau
/// comme le ferait un client. La preuve d'authentification vaut `[graine; 32]`.
fn corps_inscription(email: &str, graine: u8) -> (Value, String, SecretKey, [u8; 32]) {
    let user_id = crypto::new_uuid();
    let cid = crypto::new_uuid();
    let user_key = SecretKey::generate();
    let (privee, publique) = crypto::generate_keypair();
    let ck = SecretKey::generate();
    let corps = json!({
        "user_id": user_id,
        "email": email,
        "name": format!("Compte {graine}"),
        "auth_key": b64e(&[graine; 32]),
        "kdf": KdfParams::recommended(),
        "wrapped_user_key": crypto::wrap_key(&SecretKey::generate(), &user_key, &aad::user_key()),
        "recovery_wrapped_user_key": crypto::wrap_key(&SecretKey::generate(), &user_key, &aad::recovery_user_key()),
        "recovery_auth": b64e(&[graine.wrapping_add(100); 32]),
        "public_key": b64e(&publique),
        "wrapped_private_key": crypto::wrap_key(&user_key, &privee, &aad::private_key(&user_id)),
        "personal_collection": {
            "id": cid,
            "enc_name": crypto::encrypt_str(&ck, "Personnel", &aad::collection_name(&cid)),
            "sealed_key": crypto::seal_key(&publique, &ck, &aad::collection_key(&cid, &user_id)).unwrap(),
        },
    });
    (corps, user_id, privee, publique)
}

/// Inscription par HTTP avec un champ supplémentaire (`setup_token` ou
/// `invite_token`) ; la réponse doit être 200.
async fn inscrire(srv: &Serveur, email: &str, graine: u8, champ: &str, valeur: &str) -> Compte {
    let (mut corps, id, privee, publique) = corps_inscription(email, graine);
    corps[champ] = json!(valeur);
    let rep = srv.post("/api/auth/register", None, corps).await;
    let corps = rep.attendu(200, "");
    assert_eq!(corps["profile"]["id"], json!(id));
    Compte { id, email: email.into(), jeton: corps["token"].as_str().unwrap().into(), privee, publique }
}

/// Jeton d'installation généré dans le dossier de données (jamais par l'environnement).
async fn jeton_installation(st: &AppState) -> String {
    crate::auth::init_setup_token(&st.db, &st.config.data_dir).await.unwrap();
    std::fs::read_to_string(st.config.data_dir.join(crate::auth::SETUP_TOKEN_FILE)).unwrap().trim().to_string()
}

/// Premier compte (propriétaire), créé avec le jeton d'installation.
async fn proprietaire(srv: &Serveur) -> Compte {
    let jeton = jeton_installation(&srv.st).await;
    inscrire(srv, "proprietaire@exemple.fr", 1, "setup_token", &jeton).await
}

/// Invitation créée par `admin`, renvoie le jeton d'invitation.
async fn inviter(srv: &Serveur, admin: &Compte, email: &str) -> String {
    let rep = srv.post("/api/admin/invites", Some(&admin.jeton), json!({ "email": email, "role": "user" })).await;
    rep.attendu(200, "")["token"].as_str().unwrap().to_string()
}

/// Membre inscrit par HTTP sur invitation du propriétaire.
async fn membre(srv: &Serveur, admin: &Compte, email: &str, graine: u8) -> Compte {
    let invitation = inviter(srv, admin, email).await;
    inscrire(srv, email, graine, "invite_token", &invitation).await
}

/// Compte et session insérés directement en base (sans Argon2 pour la
/// session) : pour les tests dont l'inscription n'est pas le sujet. Avec
/// `cle`, la preuve d'authentification est hachée comme à l'inscription ;
/// avec `deux_facteurs`, un secret TOTP chiffré par la clé serveur est posé.
async fn compte_direct(st: &AppState, role: &str, cle: Option<[u8; 32]>, deux_facteurs: bool) -> (Compte, Option<String>) {
    let id = crypto::new_uuid();
    let email = format!("{}@exemple.fr", &id[..8]);
    let jeton = crypto::random_token();
    let (privee, publique) = crypto::generate_keypair();
    let auth_hash = match cle {
        Some(k) => hash_secret(k.to_vec()).await.unwrap(),
        None => "aucune".into(),
    };
    let secret = deux_facteurs.then(totp::generate_secret);
    let chiffre = secret.as_ref().map(|s| crate::auth::encrypt_totp_secret(st, &id, s));
    let kdf = serde_json::to_string(&KdfParams::recommended()).unwrap();
    let (u, e, r, h, pk) = (id.clone(), email.clone(), role.to_string(), sha256_hex(&jeton), b64e(&publique));
    st.db
        .call(move |c| {
            let now = now_unix();
            c.execute(
                "INSERT INTO users (id, email, name, role, kdf, auth_hash, wrapped_user_key,
                    recovery_wrapped_user_key, recovery_auth_hash, public_key, wrapped_private_key,
                    totp_secret, created_at, updated_at)
                 VALUES (?1, ?2, 'Direct', ?3, ?4, ?5, 'x', 'x', 'x', ?6, 'x', ?7, ?8, ?8)",
                params![u, e, r, kdf, auth_hash, pk, chiffre, now],
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
    (Compte { id, email, jeton, privee, publique }, secret)
}

/// Coffre partagé créé par HTTP, avec sa clé (connue du seul client).
struct Coffre {
    id: String,
    cle: SecretKey,
}

async fn creer_coffre(srv: &Serveur, c: &Compte) -> Coffre {
    let id = crypto::new_uuid();
    let cle = SecretKey::generate();
    let corps = json!({
        "id": id,
        "enc_name": crypto::encrypt_str(&cle, "Coffre partagé", &aad::collection_name(&id)),
        "sealed_key": crypto::seal_key(&c.publique, &cle, &aad::collection_key(&id, &c.id)).unwrap(),
    });
    srv.post("/api/collections", Some(&c.jeton), corps).await.attendu(201, "");
    Coffre { id, cle }
}

const ELEMENT_CLAIR: &str = r#"{"type":"login","name":"Messagerie","password":"Été-2026!"}"#;

async fn creer_element(srv: &Serveur, c: &Compte, coffre: &Coffre) -> String {
    let id = crypto::new_uuid();
    let data = crypto::encrypt_str(&coffre.cle, ELEMENT_CLAIR, &aad::item(&coffre.id, &id));
    let corps = json!({ "id": id, "collection_id": coffre.id, "data": data });
    srv.post("/api/items", Some(&c.jeton), corps).await.attendu(201, "");
    id
}

/// Pièce jointe chiffrée de `taille` octets.
fn piece_jointe(id: &str, taille: usize) -> Value {
    json!({ "data": crypto::encrypt(&SecretKey::generate(), &vec![0x5a; taille], aad::attachment(id).as_bytes()) })
}

async fn ajouter_piece_jointe(srv: &Serveur, c: &Compte, element: &str) -> String {
    let id = crypto::new_uuid();
    srv.put(&format!("/api/items/{element}/attachments/{id}"), Some(&c.jeton), piece_jointe(&id, 2048)).await.attendu(201, "");
    id
}

/// Lignes du journal d'audit pour une action, dans l'ordre (adresse IP).
async fn ip_auditees(st: &AppState, action: &'static str) -> Vec<String> {
    st.db
        .call(move |c| {
            let mut s = c.prepare("SELECT ip FROM audit WHERE action = ?1 ORDER BY id")?;
            let v = s.query_map([action], |r| r.get(0))?.collect::<Result<Vec<String>, _>>()?;
            Ok(v)
        })
        .await
        .unwrap()
}

/// Copie de la configuration de test avec un autre réglage de proxy.
fn config_proxy(base: &Config, trust_proxy: bool, trusted_proxies: Vec<Cidr>) -> Config {
    Config {
        bind: base.bind.clone(),
        data_dir: base.data_dir.clone(),
        web_dir: base.web_dir.clone(),
        trust_proxy,
        trusted_proxies,
        hsts: base.hsts,
        request_timeout: base.request_timeout,
        header_timeout: base.header_timeout,
        argon2_concurrency: base.argon2_concurrency,
        argon2_queue: base.argon2_queue,
    }
}

// ------------------------------------------------------------ a. Jeton d'installation

#[tokio::test]
async fn jeton_d_installation_par_http() {
    let srv = demarrer(crate::state::test_state().await).await;
    let health = srv.get("/api/health", None).await;
    assert_eq!(health.attendu(200, "")["needs_setup"], json!(true));

    let jeton = jeton_installation(&srv.st).await;
    let fichier = srv.st.config.data_dir.join(crate::auth::SETUP_TOKEN_FILE);
    assert!(fichier.exists());

    // Sans jeton, puis avec un mauvais jeton : refus, aucun compte créé.
    let (corps, ..) = corps_inscription("proprietaire@exemple.fr", 1);
    srv.post("/api/auth/register", None, corps).await.attendu(403, "setup_token_required");
    let (mut corps, ..) = corps_inscription("proprietaire@exemple.fr", 1);
    corps["setup_token"] = json!("mauvais-jeton-d-installation-0000");
    srv.post("/api/auth/register", None, corps).await.attendu(403, "invalid_setup_token");
    assert_eq!(srv.get("/api/health", None).await.corps["needs_setup"], json!(true));

    // Bon jeton : premier compte, propriétaire.
    let (mut corps, ..) = corps_inscription("proprietaire@exemple.fr", 1);
    corps["setup_token"] = json!(jeton);
    let rep = srv.post("/api/auth/register", None, corps).await;
    assert_eq!(rep.attendu(200, "")["profile"]["role"], json!("owner"));
    assert!(rep.corps["token"].as_str().is_some_and(|t| !t.is_empty()));

    // Jeton consommé : fichier supprimé, installation terminée.
    assert!(!fichier.exists());
    assert_eq!(srv.get("/api/health", None).await.corps["needs_setup"], json!(false));

    // Rejouer le même jeton pour un second compte : l'inscription ne se fait
    // plus que sur invitation.
    let (mut corps, ..) = corps_inscription("intrus@exemple.fr", 2);
    corps["setup_token"] = json!(jeton);
    srv.post("/api/auth/register", None, corps).await.attendu(403, "forbidden");
}

// ------------------------------------------------------------ b. Invitation et connexion

#[tokio::test]
async fn invitation_connexion_et_deconnexion() {
    let srv = demarrer(crate::state::test_state().await).await;
    let a = proprietaire(&srv).await;

    // Invitation : consultable sans compte, puis utilisée pour s'inscrire.
    let invitation = inviter(&srv, &a, "bob@exemple.fr").await;
    let info = srv.get(&format!("/api/invites/{invitation}"), None).await;
    assert_eq!(info.attendu(200, "")["email"], json!("bob@exemple.fr"));
    let (mut corps, id_b, ..) = corps_inscription("bob@exemple.fr", 2);
    let kdf_b = corps["kdf"].clone();
    corps["invite_token"] = json!(invitation);
    let rep = srv.post("/api/auth/register", None, corps).await;
    assert_eq!(rep.attendu(200, "")["profile"]["role"], json!("user"));
    // Invitation à usage unique.
    srv.get(&format!("/api/invites/{invitation}"), None).await.attendu(404, "not_found");

    // Pré-connexion : le KDF du compte ; pour une adresse inconnue, un KDF
    // factice stable (on ne distingue pas un compte inexistant).
    let pre = srv.post("/api/auth/prelogin", None, json!({ "email": "Bob@Exemple.fr" })).await;
    assert_eq!(pre.attendu(200, "")["kdf"], kdf_b);
    let inconnu1 = srv.post("/api/auth/prelogin", None, json!({ "email": "personne@exemple.fr" })).await;
    let inconnu2 = srv.post("/api/auth/prelogin", None, json!({ "email": "personne@exemple.fr" })).await;
    let autre = srv.post("/api/auth/prelogin", None, json!({ "email": "quelquun@exemple.fr" })).await;
    assert_eq!(inconnu1.attendu(200, "")["kdf"], inconnu2.corps["kdf"]);
    assert_eq!(inconnu1.corps["kdf"]["alg"], json!("argon2id"));
    assert_ne!(inconnu1.corps["kdf"]["salt"], autre.corps["kdf"]["salt"]);

    // Mauvais mot de passe, puis connexion.
    let login = |cle: u8| json!({ "email": "bob@exemple.fr", "auth_key": b64e(&[cle; 32]), "device": "Tests" });
    srv.post("/api/auth/login", None, login(99)).await.attendu(401, "invalid_credentials");
    let rep = srv.post("/api/auth/login", None, login(2)).await;
    let jeton = rep.attendu(200, "")["token"].as_str().unwrap().to_string();
    assert_eq!(rep.corps["profile"]["id"], json!(id_b));
    let sync = srv.get("/api/sync", Some(&jeton)).await;
    assert_eq!(sync.attendu(200, "")["profile"]["email"], json!("bob@exemple.fr"));
    assert_eq!(sync.corps["collections"].as_array().unwrap().len(), 1, "coffre personnel seul");

    // Déconnexion : la session est détruite.
    srv.post("/api/auth/logout", Some(&jeton), json!({})).await.attendu(204, "");
    srv.get("/api/sync", Some(&jeton)).await.attendu(401, "unauthorized");

    // En-tête Authorization absent, vide, invalide ou d'un autre schéma.
    srv.get("/api/sync", None).await.attendu(401, "unauthorized");
    for valeur in ["Bearer ", "Bearer    ", "Bearer jeton-inconnu", "Basic Ym9iOm1vdA=="] {
        let rep = srv.envoyer(Method::GET, "/api/sync", None, None, &[("authorization", valeur)]).await;
        rep.attendu(401, "unauthorized");
    }
    // La session du propriétaire n'est pas touchée.
    srv.get("/api/sync", Some(&a.jeton)).await.attendu(200, "");
}

// ------------------------------------------------------------ c. Accès entre utilisateurs (IDOR)

/// La requête de `jeton` sur l'objet d'autrui (`vrai`) et sur un objet
/// inexistant (`faux`) donnent exactement la même réponse 404.
#[track_caller]
fn meme_404(vrai: &Rep, faux: &Rep, quoi: &str) {
    assert_eq!(vrai.status, 404, "{quoi} : {}", vrai.corps);
    assert_eq!(faux.status, 404, "{quoi} (inexistant) : {}", faux.corps);
    assert_eq!(vrai.corps, faux.corps, "{quoi} : le 404 révèle l'existence de l'objet");
    assert_eq!(vrai.code(), "not_found");
}

#[tokio::test]
async fn acces_aux_objets_d_un_autre_utilisateur() {
    let srv = demarrer(crate::state::test_state().await).await;
    let a = proprietaire(&srv).await;
    let c = membre(&srv, &a, "carole@exemple.fr", 3).await;

    let coffre = creer_coffre(&srv, &a).await;
    let element = creer_element(&srv, &a, &coffre).await;
    let pj = ajouter_piece_jointe(&srv, &a, &element).await;
    let partage = srv
        .post(
            "/api/shares",
            Some(&a.jeton),
            json!({
                "data": crypto::encrypt_str(&SecretKey::generate(), "secret partagé", &aad::share()),
                "expires_in_minutes": 60,
                "max_views": 3,
            }),
        )
        .await;
    let partage = partage.attendu(200, "")["id"].as_str().unwrap().to_string();

    let cj = Some(c.jeton.as_str());
    let x = crypto::new_uuid();
    let donnees = |cid: &str, iid: &str| crypto::encrypt_str(&SecretKey::generate(), "{}", &aad::item(cid, iid));
    let maj = json!({ "collection_id": coffre.id, "data": donnees(&coffre.id, &element), "revision": 1 });
    let rotation = json!({
        "remove_user_ids": [a.id],
        "enc_name": crypto::encrypt_str(&SecretKey::generate(), "volé", &aad::collection_name(&coffre.id)),
        "members": [],
        "items": [],
    });
    let scelle = crypto::seal_key(&c.publique, &SecretKey::generate(), &aad::collection_key(&coffre.id, &c.id)).unwrap();

    // Pièce jointe : lecture et suppression.
    let (v, f) = (srv.get(&format!("/api/attachments/{pj}"), cj).await, srv.get(&format!("/api/attachments/{x}"), cj).await);
    meme_404(&v, &f, "GET pièce jointe");
    let (v, f) = (srv.delete(&format!("/api/attachments/{pj}"), cj).await, srv.delete(&format!("/api/attachments/{x}"), cj).await);
    meme_404(&v, &f, "DELETE pièce jointe");

    // Élément : modification, corbeille, restauration, purge, ajout de pièce jointe.
    let (v, f) = (srv.put(&format!("/api/items/{element}"), cj, maj.clone()).await, srv.put(&format!("/api/items/{x}"), cj, maj.clone()).await);
    meme_404(&v, &f, "PUT élément");
    let (v, f) = (srv.delete(&format!("/api/items/{element}"), cj).await, srv.delete(&format!("/api/items/{x}"), cj).await);
    meme_404(&v, &f, "DELETE élément");
    let (v, f) = (
        srv.post(&format!("/api/items/{element}/restore"), cj, json!({})).await,
        srv.post(&format!("/api/items/{x}/restore"), cj, json!({})).await,
    );
    meme_404(&v, &f, "restauration d'élément");
    let (v, f) = (srv.delete(&format!("/api/items/{element}/purge"), cj).await, srv.delete(&format!("/api/items/{x}/purge"), cj).await);
    meme_404(&v, &f, "purge d'élément");
    let nouvelle = crypto::new_uuid();
    let (v, f) = (
        srv.put(&format!("/api/items/{element}/attachments/{nouvelle}"), cj, piece_jointe(&nouvelle, 64)).await,
        srv.put(&format!("/api/items/{x}/attachments/{nouvelle}"), cj, piece_jointe(&nouvelle, 64)).await,
    );
    meme_404(&v, &f, "ajout de pièce jointe");

    // Élément créé dans le coffre d'autrui.
    let nouvel = crypto::new_uuid();
    let creation = |cid: &str| json!({ "id": nouvel, "collection_id": cid, "data": donnees(cid, &nouvel) });
    let (v, f) = (srv.post("/api/items", cj, creation(&coffre.id)).await, srv.post("/api/items", cj, creation(&x)).await);
    meme_404(&v, &f, "création d'élément");

    // Coffre : membres, rotation, renommage, suppression, auto-ajout, changement de rôle, départ.
    let col = |suffixe: &str, id: &str| format!("/api/collections/{id}{suffixe}");
    let (v, f) = (srv.get(&col("/members", &coffre.id), cj).await, srv.get(&col("/members", &x), cj).await);
    meme_404(&v, &f, "liste des membres");
    let (v, f) = (
        srv.post(&col("/rotate", &coffre.id), cj, rotation.clone()).await,
        srv.post(&col("/rotate", &x), cj, rotation.clone()).await,
    );
    meme_404(&v, &f, "rotation de clé");
    let nom = json!({ "enc_name": crypto::encrypt_str(&SecretKey::generate(), "x", "aad") });
    let (v, f) = (srv.put(&col("", &coffre.id), cj, nom.clone()).await, srv.put(&col("", &x), cj, nom.clone()).await);
    meme_404(&v, &f, "renommage du coffre");
    let (v, f) = (srv.delete(&col("", &coffre.id), cj).await, srv.delete(&col("", &x), cj).await);
    meme_404(&v, &f, "suppression du coffre");
    let ajout = json!({ "user_id": c.id, "role": "manager", "sealed_key": scelle });
    let (v, f) = (
        srv.post(&col("/members", &coffre.id), cj, ajout.clone()).await,
        srv.post(&col("/members", &x), cj, ajout.clone()).await,
    );
    meme_404(&v, &f, "auto-ajout comme gestionnaire");
    let role = json!({ "role": "manager" });
    let (v, f) = (
        srv.put(&col(&format!("/members/{}", a.id), &coffre.id), cj, role.clone()).await,
        srv.put(&col(&format!("/members/{}", a.id), &x), cj, role.clone()).await,
    );
    meme_404(&v, &f, "changement de rôle");
    let (v, f) = (
        srv.delete(&col(&format!("/members/{}", c.id), &coffre.id), cj).await,
        srv.delete(&col(&format!("/members/{}", c.id), &x), cj).await,
    );
    meme_404(&v, &f, "départ d'un coffre étranger");

    // Lien de partage d'autrui.
    let (v, f) = (
        srv.delete(&format!("/api/shares/{partage}"), cj).await,
        srv.delete(&format!("/api/shares/{}", crypto::random_token()), cj).await,
    );
    meme_404(&v, &f, "révocation d'un partage");

    // La synchronisation et la liste des partages de C ne montrent rien de A.
    let sync = srv.get("/api/sync", cj).await;
    let texte = sync.attendu(200, "").to_string();
    for secret in [&coffre.id, &element, &pj] {
        assert!(!texte.contains(secret.as_str()), "{secret} visible par C");
    }
    assert_eq!(sync.corps["items"], json!([]));
    assert!(!srv.get("/api/shares", cj).await.attendu(200, "").to_string().contains(&partage));

    // Rien n'a bougé chez A : élément intact, pièce jointe et partage présents.
    let sync = srv.get("/api/sync", Some(&a.jeton)).await;
    let items = sync.attendu(200, "")["items"].as_array().unwrap().clone();
    let item = items.iter().find(|i| i["id"] == json!(element)).expect("élément de A");
    assert_eq!((item["revision"].clone(), item["deleted_at"].clone()), (json!(1), Value::Null));
    let texte = crypto::decrypt_string(&coffre.cle, item["data"].as_str().unwrap(), &aad::item(&coffre.id, &element)).unwrap();
    assert_eq!(texte, ELEMENT_CLAIR);
    let membres = srv.get(&col("/members", &coffre.id), Some(&a.jeton)).await;
    assert_eq!(membres.attendu(200, "").as_array().unwrap().len(), 1);
    srv.get(&format!("/api/attachments/{pj}"), Some(&a.jeton)).await.attendu(200, "");
    assert!(srv.get("/api/shares", Some(&a.jeton)).await.attendu(200, "").to_string().contains(&partage));
}

// ------------------------------------------------------------ d. Rôles de coffre

#[tokio::test]
async fn roles_lecteur_editeur_gestionnaire() {
    let srv = demarrer(crate::state::test_state().await).await;
    let a = proprietaire(&srv).await;
    let b = membre(&srv, &a, "bob@exemple.fr", 2).await;
    let c = membre(&srv, &a, "carole@exemple.fr", 3).await;
    let coffre = creer_coffre(&srv, &a).await;
    let element = creer_element(&srv, &a, &coffre).await;
    let pj = ajouter_piece_jointe(&srv, &a, &element).await;
    let col = |suffixe: &str| format!("/api/collections/{}{suffixe}", coffre.id);

    // Clé publique de B lue dans l'annuaire, comme le fait le client.
    let annuaire = srv.get("/api/directory", Some(&a.jeton)).await;
    let fiche = annuaire.attendu(200, "").as_array().unwrap().iter().find(|u| u["id"] == json!(b.id)).cloned().unwrap();
    let pub_b: [u8; 32] = b64d(fiche["public_key"].as_str().unwrap()).unwrap().try_into().unwrap();
    assert_eq!(pub_b, b.publique);
    let scelle = |pour: &Compte, cle: &[u8; 32]| {
        crypto::seal_key(cle, &coffre.cle, &aad::collection_key(&coffre.id, &pour.id)).unwrap()
    };

    // A ajoute B en lecteur.
    let ajout_b = json!({ "user_id": b.id, "role": "reader", "sealed_key": scelle(&b, &pub_b) });
    srv.post(&col("/members"), Some(&a.jeton), ajout_b).await.attendu(201, "");

    // B lit : le coffre apparaît, sa clé s'ouvre avec la clé privée de B et
    // l'élément se déchiffre ; la pièce jointe se télécharge.
    let bj = Some(b.jeton.as_str());
    let sync = srv.get("/api/sync", bj).await;
    let vue = sync.attendu(200, "")["collections"].as_array().unwrap().iter().find(|v| v["id"] == json!(coffre.id)).cloned();
    let vue = vue.expect("coffre partagé visible par B");
    assert_eq!(vue["role"], json!("reader"));
    let cle = crypto::open_key(&b.privee, vue["sealed_key"].as_str().unwrap(), &aad::collection_key(&coffre.id, &b.id)).unwrap();
    assert_eq!(cle.as_bytes(), coffre.cle.as_bytes());
    let item = sync.corps["items"].as_array().unwrap().iter().find(|i| i["id"] == json!(element)).cloned().unwrap();
    assert_eq!(crypto::decrypt_string(&cle, item["data"].as_str().unwrap(), &aad::item(&coffre.id, &element)).unwrap(), ELEMENT_CLAIR);
    srv.get(&format!("/api/attachments/{pj}"), bj).await.attendu(200, "");
    srv.get(&col("/members"), bj).await.attendu(200, "");

    // Lecteur : aucune écriture (403 : il connaît déjà le coffre).
    let maj = |rev: i64| {
        json!({
            "collection_id": coffre.id,
            "data": crypto::encrypt_str(&coffre.cle, "{\"name\":\"modifié\"}", &aad::item(&coffre.id, &element)),
            "revision": rev,
        })
    };
    let nouvelle = crypto::new_uuid();
    let nom = json!({ "enc_name": crypto::encrypt_str(&coffre.cle, "renommé", &aad::collection_name(&coffre.id)) });
    let ajout_c = json!({ "user_id": c.id, "role": "reader", "sealed_key": scelle(&c, &c.publique) });
    srv.put(&format!("/api/items/{element}"), bj, maj(1)).await.attendu(403, "forbidden");
    srv.delete(&format!("/api/items/{element}"), bj).await.attendu(403, "forbidden");
    srv.put(&format!("/api/items/{element}/attachments/{nouvelle}"), bj, piece_jointe(&nouvelle, 64)).await.attendu(403, "forbidden");
    srv.delete(&format!("/api/attachments/{pj}"), bj).await.attendu(403, "forbidden");
    srv.put(&col(""), bj, nom.clone()).await.attendu(403, "forbidden");
    srv.post(&col("/members"), bj, ajout_c.clone()).await.attendu(403, "forbidden");

    // B passe éditeur : il modifie l'élément (bonne révision), pas les membres.
    srv.put(&col(&format!("/members/{}", b.id)), Some(&a.jeton), json!({ "role": "editor" })).await.attendu(204, "");
    assert_eq!(srv.put(&format!("/api/items/{element}"), bj, maj(1)).await.attendu(200, ""), &json!(2));
    srv.put(&format!("/api/items/{element}"), bj, maj(1)).await.attendu(409, "conflict");
    srv.post(&col("/members"), bj, ajout_c.clone()).await.attendu(403, "forbidden");
    srv.put(&col(&format!("/members/{}", b.id)), bj, json!({ "role": "manager" })).await.attendu(403, "forbidden");
    srv.put(&col(""), bj, nom.clone()).await.attendu(403, "forbidden");
    srv.delete(&col(""), bj).await.attendu(403, "forbidden");
    let rotation = json!({ "remove_user_ids": [], "enc_name": nom["enc_name"], "members": [], "items": [] });
    srv.post(&col("/rotate"), bj, rotation).await.attendu(403, "forbidden");

    // B passe gestionnaire : il peut ajouter C, qui voit alors le coffre.
    srv.put(&col(&format!("/members/{}", b.id)), Some(&a.jeton), json!({ "role": "manager" })).await.attendu(204, "");
    srv.post(&col("/members"), bj, ajout_c).await.attendu(201, "");
    let sync_c = srv.get("/api/sync", Some(&c.jeton)).await;
    let vue_c = sync_c.attendu(200, "")["collections"].as_array().unwrap().iter().find(|v| v["id"] == json!(coffre.id)).cloned();
    assert_eq!(vue_c.expect("coffre visible par C")["role"], json!("reader"));
}

// ------------------------------------------------------------ e. Administration

#[tokio::test]
async fn routes_d_administration_refusees_a_un_membre() {
    let st = crate::state::test_state().await;
    let (membre, _) = compte_direct(&st, "user", None, false).await;
    let (admin, _) = compte_direct(&st, "admin", None, false).await;
    let srv = demarrer(st).await;
    let moi = &membre.id;
    let invitation = crypto::new_uuid();
    // Toutes les routes /api/admin/* de main.rs. Les cibles :id visent le
    // membre lui-même (tentative d'élévation de ses propres droits).
    let routes: &[(Method, String, Option<Value>)] = &[
        (Method::GET, "/api/admin/ldap".into(), None),
        (Method::PUT, "/api/admin/ldap".into(), Some(json!({}))),
        (Method::POST, "/api/admin/ldap/test".into(), Some(json!({}))),
        (Method::POST, "/api/admin/ldap/sync".into(), Some(json!({}))),
        (Method::GET, "/api/admin/sso".into(), None),
        (Method::PUT, "/api/admin/sso".into(), Some(json!({}))),
        (Method::POST, "/api/admin/sso/test".into(), Some(json!({}))),
        (Method::GET, "/api/admin/scim".into(), None),
        (Method::POST, "/api/admin/scim/token".into(), Some(json!({}))),
        (Method::DELETE, "/api/admin/scim/token".into(), None),
        (Method::GET, "/api/admin/directory".into(), None),
        (Method::GET, "/api/admin/stats".into(), None),
        (Method::GET, "/api/admin/users".into(), None),
        (Method::PUT, format!("/api/admin/users/{moi}"), Some(json!({ "role": "owner" }))),
        (Method::DELETE, format!("/api/admin/users/{moi}"), None),
        (Method::POST, format!("/api/admin/users/{moi}/reset-2fa"), Some(json!({}))),
        (Method::POST, format!("/api/admin/users/{moi}/revoke-sessions"), Some(json!({}))),
        (Method::GET, "/api/admin/invites".into(), None),
        (Method::POST, "/api/admin/invites".into(), Some(json!({ "email": "x@exemple.fr", "role": "admin" }))),
        (Method::DELETE, format!("/api/admin/invites/{invitation}"), None),
        (Method::GET, "/api/admin/audit".into(), None),
        (Method::GET, "/api/admin/audit.csv".into(), None),
        (Method::GET, "/api/admin/settings".into(), None),
        (Method::PUT, "/api/admin/settings".into(), Some(json!({ "require_2fa": false, "session_max_hours": 720 }))),
    ];
    for (methode, chemin, corps) in routes {
        let anonyme = srv.envoyer(methode.clone(), chemin, None, corps.as_ref(), &[]).await;
        assert_eq!((anonyme.status, anonyme.code()), (401, "unauthorized"), "{methode} {chemin} anonyme : {}", anonyme.corps);
        let rep = srv.envoyer(methode.clone(), chemin, Some(&membre.jeton), corps.as_ref(), &[]).await;
        assert_eq!((rep.status, rep.code()), (403, "forbidden"), "{methode} {chemin} membre : {}", rep.corps);
    }
    // Le membre est resté simple utilisateur, avec sa session.
    let me = srv.get("/api/me", Some(&membre.jeton)).await;
    assert_eq!(me.attendu(200, "")["role"], json!("user"));
    // Un administrateur, lui, y accède.
    srv.get("/api/admin/stats", Some(&admin.jeton)).await.attendu(200, "");
    srv.get("/api/admin/settings", Some(&admin.jeton)).await.attendu(200, "");

    // SCIM : ni anonyme, ni avec un jeton de session (seul le jeton SCIM vaut).
    assert_eq!(srv.get("/scim/v2/Users", None).await.status, 401);
    assert_eq!(srv.get("/scim/v2/Users", Some(&admin.jeton)).await.status, 401);
}

// ------------------------------------------------------------ f. Double authentification

/// Insère un ticket SSO valable 5 minutes, comme `sso::callback` (ou
/// `ldap::login`, qui passe par la même table) après une authentification réussie.
async fn ticket_sso(st: &AppState, compte: &Compte) -> String {
    let ticket = crypto::random_token();
    let (h, e, u) = (sha256_hex(&ticket), compte.email.clone(), compte.id.clone());
    st.db
        .call(move |c| {
            c.execute(
                "INSERT INTO sso_tickets (ticket_hash, email, name, subject, user_id, expires_at)
                 VALUES (?1, ?2, '', 'sujet', ?3, ?4)",
                params![h, e, u, now_unix() + 300],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    ticket
}

#[tokio::test]
async fn totp_exige_apres_sso_et_ldap() {
    // La connexion par le compte Windows (LDAP) produit un ticket rangé dans
    // la même table `sso_tickets` et échangé par le même POST /api/auth/login :
    // ce test couvre donc aussi ce chemin. Une vraie liaison LDAP demanderait
    // un annuaire, hors de portée ici.
    let st = crate::state::test_state().await;
    let cle = [21u8; 32];
    let (compte, secret) = compte_direct(&st, "user", Some(cle), true).await;
    let srv = demarrer(st).await;
    let ticket = ticket_sso(&srv.st, &compte).await;
    let login = |code: Option<String>, ticket: &str| {
        json!({ "email": compte.email, "auth_key": b64e(&cle), "sso_ticket": ticket, "totp": code })
    };

    // Ticket valable mais pas de code : la 2FA Locksy reste exigée.
    srv.post("/api/auth/login", None, login(None, &ticket)).await.attendu(401, "totp_required");

    // Mauvais code (hors de la fenêtre de tolérance).
    let cfg = totp::parse(&secret.unwrap()).unwrap();
    let now = now_unix() as u64;
    let valides: Vec<String> = [now - 30, now, now + 30, now + 60].iter().map(|t| totp::code_at(&cfg, *t)).collect();
    let faux = (0..10).map(|d| format!("{d}{d}{d}{d}{d}{d}")).find(|c| !valides.contains(c)).unwrap();
    srv.post("/api/auth/login", None, login(Some(faux), &ticket)).await.attendu(401, "invalid_totp");

    // Bon code : connexion ; le ticket est alors consommé.
    let bon = totp::code_at(&cfg, now_unix() as u64);
    let rep = srv.post("/api/auth/login", None, login(Some(bon), &ticket)).await;
    let jeton = rep.attendu(200, "")["token"].as_str().unwrap().to_string();
    srv.get("/api/sync", Some(&jeton)).await.attendu(200, "");
    let rejeu = totp::code_at(&cfg, now_unix() as u64 + 30);
    srv.post("/api/auth/login", None, login(Some(rejeu), &ticket)).await.attendu(401, "unauthorized");
}

/// Organisation qui impose la 2FA : propriétaire, membre sans 2FA, membre avec 2FA.
async fn organisation_2fa_obligatoire() -> (Serveur, Compte, Compte, Compte) {
    let st = crate::state::test_state().await;
    let (proprio, _) = compte_direct(&st, "owner", None, false).await;
    let (sans, _) = compte_direct(&st, "user", None, false).await;
    let (avec, _) = compte_direct(&st, "user", None, true).await;
    let srv = demarrer(st).await;
    let rep = srv.put("/api/admin/settings", Some(&proprio.jeton), json!({ "require_2fa": true })).await;
    let reglages = rep.attendu(200, "");
    assert_eq!(reglages["require_2fa"], json!(true));
    // Envoi partiel : les autres règles gardent leur valeur.
    assert_eq!(reglages["session_idle_minutes"], json!(60));
    (srv, proprio, sans, avec)
}

#[tokio::test]
async fn deux_facteurs_imposes_par_l_organisation() {
    let (srv, proprio, sans, avec) = organisation_2fa_obligatoire().await;
    // Sans 2FA : coffre refusé.
    srv.get("/api/sync", Some(&sans.jeton)).await.attendu(403, "2fa_required");
    srv.get("/api/directory", Some(&sans.jeton)).await.attendu(403, "2fa_required");
    // Le propriétaire est soumis à la même règle.
    srv.get("/api/admin/settings", Some(&proprio.jeton)).await.attendu(403, "2fa_required");
    // Avec 2FA : accès normal.
    srv.get("/api/sync", Some(&avec.jeton)).await.attendu(200, "");
}

/// Régression corrigée le 17/11/2026 : `AuthUser` (state.rs) comparait le
/// chemin vu sous `Router::nest("/api", …)` (« /me », préfixe retiré) à
/// « /api/me ». Quand la 2FA était imposée, un compte sans 2FA recevait 403
/// `2fa_required` sur son profil, sur l'activation de la 2FA et sur la
/// déconnexion : il restait bloqué. Le chemin d'origine (`OriginalUri`) sert
/// désormais à la comparaison.
#[tokio::test]
async fn deux_facteurs_imposes_profil_et_deconnexion_restent_permis() {
    let (srv, _, sans, _) = organisation_2fa_obligatoire().await;
    let me = srv.get("/api/me", Some(&sans.jeton)).await;
    assert_eq!(me.attendu(200, "")["must_setup_2fa"], json!(true));
    srv.post("/api/me/2fa/setup", Some(&sans.jeton), json!({})).await.attendu(200, "");
    srv.post("/api/auth/logout", Some(&sans.jeton), json!({})).await.attendu(204, "");
}

// ------------------------------------------------------------ g. Limiteur et X-Forwarded-For

/// Tentative de connexion sur un compte inexistant (empreinte factice : même
/// coût qu'un vrai compte), avec un X-Forwarded-For donné.
async fn essai(srv: &Serveur, xff: &str) -> Rep {
    let corps = json!({ "email": "cible@exemple.fr", "auth_key": b64e(&[9u8; 32]) });
    srv.envoyer(Method::POST, "/api/auth/login", None, Some(&corps), &[("x-forwarded-for", xff)]).await
}

#[tokio::test]
async fn limiteur_sans_proxy_ignore_x_forwarded_for() {
    let srv = demarrer(crate::state::test_state().await).await;
    assert!(!srv.st.config.trust_proxy);
    for i in 1..=5 {
        essai(&srv, &format!("198.51.100.{i}")).await.attendu(401, "invalid_credentials");
    }
    // Changer d'en-tête ne sert à rien : c'est l'adresse du pair qui compte.
    essai(&srv, "198.51.100.99").await.attendu(429, "rate_limited");
    assert_eq!(ip_auditees(&srv.st, "login.failed").await, ["127.0.0.1"; 5]);
}

#[tokio::test]
async fn limiteur_proxy_unique_entree_de_droite() {
    let mut st = crate::state::test_state().await;
    st.config = Arc::new(config_proxy(&st.config, true, Vec::new()));
    let srv = demarrer(st).await;
    // L'entrée de gauche est fournie par le client : la faire varier n'aide pas.
    for i in 1..=5 {
        essai(&srv, &format!("203.0.113.{i}, 198.51.100.7")).await.attendu(401, "invalid_credentials");
    }
    essai(&srv, "203.0.113.99, 198.51.100.7").await.attendu(429, "rate_limited");
    // Une autre adresse de droite (ajoutée par le proxy) n'est pas bloquée.
    essai(&srv, "198.51.100.8").await.attendu(401, "invalid_credentials");
    let mut attendu = vec!["198.51.100.7"; 5];
    attendu.push("198.51.100.8");
    assert_eq!(ip_auditees(&srv.st, "login.failed").await, attendu);
}

#[tokio::test]
async fn limiteur_proxys_de_confiance_pair_non_reconnu() {
    let mut st = crate::state::test_state().await;
    st.config = Arc::new(config_proxy(&st.config, true, vec![Cidr::parse("10.0.0.0/8").unwrap()]));
    let srv = demarrer(st).await;
    // Le pair (127.0.0.1) n'est pas un proxy de confiance : en-tête ignoré.
    for i in 1..=5 {
        essai(&srv, &format!("203.0.113.{i}, 198.51.100.{i}")).await.attendu(401, "invalid_credentials");
    }
    essai(&srv, "198.51.100.200").await.attendu(429, "rate_limited");
    assert_eq!(ip_auditees(&srv.st, "login.failed").await, ["127.0.0.1"; 5]);
}

// ------------------------------------------------------------ h. Quotas

#[tokio::test]
async fn quotas_de_pieces_jointes() {
    let st = crate::state::test_state().await;
    let (proprio, _) = compte_direct(&st, "owner", None, false).await;
    let srv = demarrer(st).await;
    let pj = Some(proprio.jeton.as_str());

    // Deux réglages, puis le quota seul : l'envoi partiel garde le reste.
    srv.put("/api/admin/settings", pj, json!({ "session_idle_minutes": 30, "trash_retention_days": 10 })).await.attendu(200, "");
    srv.put("/api/admin/settings", pj, json!({ "attachment_quota_user_mb": 1 })).await.attendu(200, "");
    // Bornes : valeur refusée, rien n'est modifié.
    srv.put("/api/admin/settings", pj, json!({ "attachment_quota_user_mb": 0 })).await.attendu(400, "bad_request");
    srv.put("/api/admin/settings", pj, json!({ "session_idle_minutes": 1, "attachment_max_per_item": 5 })).await.attendu(400, "bad_request");
    let rep = srv.get("/api/admin/settings", pj).await;
    let r = rep.attendu(200, "");
    assert_eq!(r["attachment_quota_user_mb"], json!(1));
    assert_eq!(r["session_idle_minutes"], json!(30));
    assert_eq!(r["trash_retention_days"], json!(10));
    assert_eq!(r["require_2fa"], json!(false));
    assert_eq!(r["session_max_hours"], json!(12));
    assert_eq!(r["attachment_quota_total_mb"], json!(20_480));
    assert_eq!(r["attachment_max_per_item"], json!(20));
    assert_eq!(r["attachment_used_mb"], json!(0));

    let coffre = creer_coffre(&srv, &proprio).await;
    let element = creer_element(&srv, &proprio, &coffre).await;
    let envoyer = |taille: usize| {
        let id = crypto::new_uuid();
        let chemin = format!("/api/items/{element}/attachments/{id}");
        (chemin, piece_jointe(&id, taille))
    };
    // Environ 1,6 Mo stockés (base64 de 1,2 Mo) : au-delà du quota de 1 Mo.
    let (chemin, corps) = envoyer(1_200_000);
    srv.put(&chemin, pj, corps).await.attendu(413, "quota_exceeded");
    // Sous la limite : accepté.
    let (chemin, corps) = envoyer(600_000);
    srv.put(&chemin, pj, corps).await.attendu(201, "");
    // Le cumul compte : un second envoi qui ferait dépasser est refusé.
    let (chemin, corps) = envoyer(300_000);
    srv.put(&chemin, pj, corps).await.attendu(413, "quota_exceeded");
    assert_eq!(srv.get("/api/admin/settings", pj).await.corps["attachment_used_mb"], json!(1));
}

// ------------------------------------------------------------ i. Sondes et en-têtes

#[tokio::test]
async fn sondes_et_en_tetes_de_l_api() {
    let srv = demarrer(crate::state::test_state().await).await;
    let ready = srv.get("/api/ready", None).await;
    assert_eq!(ready.attendu(200, "")["status"], json!("ready"));
    assert_eq!(ready.corps["schema_version"], json!(crate::db::SCHEMA_VERSION));
    let health = srv.get("/api/health", None).await;
    assert_eq!(health.attendu(200, "")["status"], json!("ok"));
    // Une erreur porte les mêmes en-têtes qu'une réussite.
    let refus = srv.get("/api/sync", None).await;
    refus.attendu(401, "unauthorized");
    for rep in [&ready, &health, &refus] {
        assert_eq!(rep.headers.get("cache-control").unwrap(), "no-store");
        assert_eq!(rep.headers.get("x-request-id").expect("x-request-id").to_str().unwrap().len(), 36);
        assert_eq!(rep.headers.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(rep.headers.get("x-frame-options").unwrap(), "DENY");
        assert!(rep.headers.get("content-security-policy").is_some());
        // Sans TLS ni proxy : pas de HSTS.
        assert!(rep.headers.get("strict-transport-security").is_none());
    }
}
