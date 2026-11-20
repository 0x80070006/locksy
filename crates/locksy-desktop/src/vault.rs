//! Logique du coffre côté bureau : mêmes règles cryptographiques que
//! l'interface web, appliquées par le même noyau Rust.

use crate::client::{ApiError, ApiResult, Client};
use crate::config::KdfPin;
use locksy_core::aad;
use locksy_core::api::*;
use locksy_core::crypto::{self, SecretKey};
use locksy_core::encoding::b64e;
use locksy_core::model::ItemData;
use zeroize::{Zeroize, Zeroizing};

pub struct Collection {
    pub id: String,
    pub name: String,
    pub personal: bool,
    pub role: String,
    pub key: Option<SecretKey>,
}

impl Collection {
    pub fn writable(&self) -> bool {
        self.key.is_some() && (self.role == roles::MANAGER || self.role == roles::EDITOR)
    }
    pub fn label(&self) -> &str {
        if self.personal { "Personnel" } else { &self.name }
    }
}

pub struct Item {
    pub id: String,
    pub collection_id: String,
    pub revision: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub deleted_at: Option<i64>,
    pub data: Option<ItemData>,
}

pub struct Vault {
    pub profile: Profile,
    /// Conservée déverrouillée pendant la session, effacée au verrouillage.
    _user_key: SecretKey,
    priv_key: SecretKey,
    pub collections: Vec<Collection>,
    pub items: Vec<Item>,
    /// Paramètres KDF de la connexion réussie, à épingler sur ce poste.
    pub kdf: KdfPin,
}

impl Drop for Vault {
    fn drop(&mut self) {
        for i in &mut self.items {
            if let Some(d) = &mut i.data {
                d.zeroize();
            }
        }
    }
}

/// Connexion en attente du code de double authentification.
pub struct PendingLogin {
    pub email: String,
    auth_key: SecretKey,
    enc_key: SecretKey,
    sso_ticket: Option<Zeroizing<String>>,
    kdf: KdfPin,
}

impl PendingLogin {
    /// Vrai si l'identité a été confirmée par le SSO ou le compte Windows
    /// (le ticket n'est valable que 5 minutes).
    pub fn via_sso(&self) -> bool {
        self.sso_ticket.is_some()
    }
}

/// Refuse des paramètres KDF plus faibles que ceux déjà vus sur ce poste pour
/// ce compte (même règle que l'interface web), AVANT toute dérivation : un
/// serveur compromis ne peut pas obtenir une preuve plus facile à casser.
pub fn check_kdf(pin: Option<KdfPin>, kdf: &crypto::KdfParams) -> ApiResult<()> {
    let Some(pin) = pin else { return Ok(()) };
    if kdf.alg != "argon2id" || kdf.m_kib < pin.m_kib || kdf.t < pin.t {
        return Err(ApiError {
            status: 0,
            code: "kdf_downgrade".into(),
            message: format!(
                "Les paramètres de sécurité annoncés par le serveur pour ce compte ({} Mio, {} passes) sont plus faibles que ceux déjà utilisés sur ce poste ({} Mio, {} passes). Connexion bloquée par précaution : contactez votre administrateur.",
                kdf.m_kib / 1024,
                kdf.t,
                pin.m_kib / 1024,
                pin.t
            ),
        });
    }
    Ok(())
}

pub enum LoginOutcome {
    Done(Client, Box<Vault>),
    NeedTotp(Client, PendingLogin, Option<String>),
}

fn device_name() -> String {
    let host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "poste".into());
    format!("Bureau Windows · {host}")
}

pub fn login(client: Client, email: &str, password: &str, pin: Option<KdfPin>) -> ApiResult<LoginOutcome> {
    let pre: PreloginResponse = client.send("POST", "/auth/prelogin", &PreloginRequest { email: email.to_string() })?;
    login_with(client, email, password, &pre.kdf, None, pin)
}

/// Connexion après le SSO ou le compte Windows : le ticket prouve l'identité
/// d'entreprise ; la double authentification Locksy reste exigée si elle est
/// active (le serveur répond `totp_required` sans consommer le ticket), et le
/// mot de passe maître reste indispensable pour déchiffrer le coffre.
pub fn login_with(
    mut client: Client,
    email: &str,
    password: &str,
    kdf: &crypto::KdfParams,
    sso_ticket: Option<String>,
    pin: Option<KdfPin>,
) -> ApiResult<LoginOutcome> {
    check_kdf(pin, kdf)?;
    let keys = crypto::derive_master_keys(password, kdf)?;
    let pending = PendingLogin {
        email: email.to_string(),
        auth_key: keys.auth_key,
        enc_key: keys.enc_key,
        sso_ticket: sso_ticket.map(Zeroizing::new),
        kdf: KdfPin { m_kib: kdf.m_kib, t: kdf.t },
    };
    client.token = None;
    finish_login(client, pending, None)
}

/// Après un ticket d'entreprise, un 401 signifie que le ticket a expiré
/// (5 minutes) ou a déjà servi : on le dit clairement.
fn explain_sso_expiry(e: ApiError, via_sso: bool) -> ApiError {
    if via_sso && e.status == 401 {
        ApiError { message: "Connexion d'entreprise expirée (5 minutes). Recommencez.".into(), ..e }
    } else {
        e
    }
}

pub fn finish_login(mut client: Client, pending: PendingLogin, totp: Option<String>) -> ApiResult<LoginOutcome> {
    let req = LoginRequest {
        email: pending.email.clone(),
        auth_key: pending.auth_key.to_b64(),
        totp,
        device: Some(device_name()),
        sso_ticket: pending.sso_ticket.as_ref().map(|t| t.to_string()),
    };
    match client.send::<_, LoginResponse>("POST", "/auth/login", &req) {
        Ok(res) => {
            client.token = Some(Zeroizing::new(res.token));
            let mut vault = Vault::unlock(res.profile, &pending.enc_key, pending.kdf)?;
            vault.apply_sync(Vault::fetch(&client)?);
            Ok(LoginOutcome::Done(client, Box::new(vault)))
        }
        Err(e) if e.code == "totp_required" => Ok(LoginOutcome::NeedTotp(client, pending, None)),
        Err(e) if e.code == "invalid_totp" => Ok(LoginOutcome::NeedTotp(client, pending, Some(e.message))),
        Err(e) => Err(explain_sso_expiry(e, pending.via_sso())),
    }
}

/// Nom de fichier sûr pour Windows à partir du nom d'une pièce jointe :
/// caractères interdits et de contrôle remplacés, points et espaces de bord
/// retirés, noms réservés (CON, NUL, COM1…) préfixés.
pub fn sanitize_file_name(name: &str) -> String {
    let clean: String = name
        .chars()
        .map(|c| if c.is_control() || "<>:\"/\\|?*".contains(c) { '_' } else { c })
        .take(200)
        .collect::<String>()
        .trim_matches(|c: char| c == '.' || c.is_whitespace())
        .to_string();
    if clean.is_empty() {
        return "piece-jointe".to_string();
    }
    let stem = clean.split('.').next().unwrap_or_default().trim_end().to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4 && (stem.starts_with("COM") || stem.starts_with("LPT")) && stem.as_bytes()[3].is_ascii_digit());
    if reserved {
        format!("_{clean}")
    } else {
        clean
    }
}

/// Vrai si le chemin passe par un dossier synchronisé avec OneDrive.
pub fn is_onedrive(path: &std::path::Path) -> bool {
    path.components().any(|c| c.as_os_str().to_string_lossy().to_lowercase().starts_with("onedrive"))
}

/// Emplacement par défaut hors Windows (pas de dialogue) : dossier
/// Téléchargements, sans écraser un fichier existant.
#[cfg(not(windows))]
pub fn default_download_path(name: &str) -> ApiResult<std::path::PathBuf> {
    let folder = dirs::download_dir()
        .or_else(dirs::desktop_dir)
        .ok_or_else(|| ApiError { status: 0, code: "io".into(), message: "Dossier Téléchargements introuvable.".into() })?;
    let clean = sanitize_file_name(name);
    let (stem, ext) = match clean.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s.to_string(), format!(".{e}")),
        _ => (clean.clone(), String::new()),
    };
    let mut path = folder.join(&clean);
    let mut n = 1;
    while path.exists() {
        path = folder.join(format!("{stem} ({n}){ext}"));
        n += 1;
    }
    Ok(path)
}

/// Télécharge, vérifie et déchiffre une pièce jointe, puis l'écrit à
/// l'emplacement choisi par l'utilisateur.
pub fn save_attachment_to(client: &Client, att: &locksy_core::model::Attachment, path: &std::path::Path) -> ApiResult<()> {
    #[derive(serde::Deserialize)]
    struct Download {
        data: String,
    }
    let dl: Download = client.get(&format!("/attachments/{}", att.id))?;
    let key = SecretKey::from_b64(&att.key)?;
    let mut bytes = crypto::decrypt(&key, &dl.data, aad::attachment(&att.id).as_bytes())?;
    let written = std::fs::write(path, &*bytes);
    zeroize::Zeroize::zeroize(&mut *bytes);
    written.map_err(|e| ApiError { status: 0, code: "io".into(), message: format!("Écriture impossible : {e}") })
}

impl Vault {
    fn unlock(profile: Profile, enc_key: &SecretKey, kdf: KdfPin) -> ApiResult<Self> {
        let user_key = crypto::unwrap_key(enc_key, &profile.wrapped_user_key, &aad::user_key())?;
        let priv_key = crypto::unwrap_key(&user_key, &profile.wrapped_private_key, &aad::private_key(&profile.id))?;
        if b64e(&crypto::public_key_of(&priv_key)) != profile.public_key {
            return Err(ApiError {
                status: 0,
                code: "key_mismatch".into(),
                message: "La clé publique fournie par le serveur ne correspond pas à votre clé privée. Connexion interrompue.".into(),
            });
        }
        Ok(Self { profile, _user_key: user_key, priv_key, collections: Vec::new(), items: Vec::new(), kdf })
    }

    /// Appel réseau, sans toucher au coffre (exécuté hors du fil d'interface).
    pub fn fetch(client: &Client) -> ApiResult<SyncResponse> {
        client.get("/sync")
    }

    /// Déchiffre une réponse de synchronisation (rapide, fil d'interface).
    pub fn apply_sync(&mut self, data: SyncResponse) {
        let uid = data.profile.id.clone();
        let collections: Vec<Collection> = data
            .collections
            .into_iter()
            .map(|c| {
                let key = crypto::open_key(&self.priv_key, &c.sealed_key, &aad::collection_key(&c.id, &uid)).ok();
                let name = key
                    .as_ref()
                    .and_then(|k| crypto::decrypt_string(k, &c.enc_name, &aad::collection_name(&c.id)).ok())
                    .unwrap_or_else(|| "Coffre illisible".into());
                Collection { id: c.id, name, personal: c.personal, role: c.role, key }
            })
            .collect();
        let items = data
            .items
            .into_iter()
            .map(|i| {
                let data = collections
                    .iter()
                    .find(|c| c.id == i.collection_id)
                    .and_then(|c| c.key.as_ref())
                    .and_then(|k| crypto::decrypt(k, &i.data, aad::item(&i.collection_id, &i.id).as_bytes()).ok())
                    .and_then(|pt| serde_json::from_slice::<ItemData>(&pt).ok());
                Item {
                    id: i.id,
                    collection_id: i.collection_id,
                    revision: i.revision,
                    created_at: i.created_at,
                    updated_at: i.updated_at,
                    deleted_at: i.deleted_at,
                    data,
                }
            })
            .collect();
        for i in &mut self.items {
            if let Some(d) = &mut i.data {
                d.zeroize();
            }
        }
        self.profile = data.profile;
        self.collections = collections;
        self.items = items;
    }


    pub fn collection(&self, id: &str) -> Option<&Collection> {
        self.collections.iter().find(|c| c.id == id)
    }

    fn encrypt_item(&self, collection_id: &str, item_id: &str, data: &ItemData) -> ApiResult<String> {
        let col = self.collection(collection_id).ok_or_else(|| ApiError { status: 0, code: "collection".into(), message: "Coffre introuvable.".into() })?;
        let key = col.key.as_ref().ok_or_else(|| ApiError { status: 0, code: "collection".into(), message: "Coffre illisible.".into() })?;
        let mut json = serde_json::to_vec(data).map_err(|e| ApiError { status: 0, code: "json".into(), message: e.to_string() })?;
        let ct = crypto::encrypt(key, &json, aad::item(collection_id, item_id).as_bytes());
        json.zeroize();
        Ok(ct)
    }

    /// Prépare la création (chiffrement local) ; l'envoi se fait ailleurs.
    pub fn prepare_create(&self, collection_id: &str, data: &ItemData) -> ApiResult<CreateItemRequest> {
        let id = crypto::new_uuid();
        Ok(CreateItemRequest { data: self.encrypt_item(collection_id, &id, data)?, id, collection_id: collection_id.to_string() })
    }

    pub fn prepare_update(&self, item_id: &str, collection_id: &str, data: &ItemData) -> ApiResult<(String, UpdateItemRequest)> {
        let item = self
            .items
            .iter()
            .find(|i| i.id == item_id)
            .ok_or_else(|| ApiError { status: 0, code: "item".into(), message: "Élément introuvable.".into() })?;
        Ok((
            format!("/items/{item_id}"),
            UpdateItemRequest { collection_id: collection_id.to_string(), data: self.encrypt_item(collection_id, item_id, data)?, revision: item.revision },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn file_names_are_safe_for_windows() {
        assert_eq!(sanitize_file_name("rapport.pdf"), "rapport.pdf");
        assert_eq!(sanitize_file_name("a/b\\c:d*e?.txt"), "a_b_c_d_e_.txt");
        assert_eq!(sanitize_file_name("..\\..\\Windows\\evil.exe"), "_.._Windows_evil.exe");
        assert_eq!(sanitize_file_name("nom\u{0}avec\ncontrôles.txt"), "nom_avec_contrôles.txt");
        assert_eq!(sanitize_file_name("  .secret.  "), "secret");
        assert_eq!(sanitize_file_name("..."), "piece-jointe");
        assert_eq!(sanitize_file_name(""), "piece-jointe");
        assert_eq!(sanitize_file_name("CON"), "_CON");
        assert_eq!(sanitize_file_name("nul.txt"), "_nul.txt");
        assert_eq!(sanitize_file_name("com1.log"), "_com1.log");
        assert_eq!(sanitize_file_name("LPT9"), "_LPT9");
        assert_eq!(sanitize_file_name("console.txt"), "console.txt");
        assert_eq!(sanitize_file_name("COM10.txt"), "COM10.txt");
        assert_eq!(sanitize_file_name(&"x".repeat(500)).chars().count(), 200);
    }

    #[test]
    fn onedrive_paths_are_detected() {
        assert!(is_onedrive(Path::new("/home/u/OneDrive - Contoso/Documents/a.pdf")));
        assert!(is_onedrive(Path::new("/home/u/onedrive/a.pdf")));
        assert!(!is_onedrive(Path::new("/home/u/Documents/a.pdf")));
    }

    fn kdf(alg: &str, m_kib: u32, t: u32) -> crypto::KdfParams {
        crypto::KdfParams { alg: alg.into(), m_kib, t, p: 1, salt: String::new() }
    }

    #[test]
    fn kdf_downgrade_is_refused_before_derivation() {
        let pin = Some(KdfPin { m_kib: 65536, t: 3 });
        assert!(check_kdf(None, &kdf("argon2id", 19456, 2)).is_ok());
        assert!(check_kdf(pin, &kdf("argon2id", 65536, 3)).is_ok());
        assert!(check_kdf(pin, &kdf("argon2id", 131072, 4)).is_ok());
        for weak in [kdf("argon2id", 19456, 3), kdf("argon2id", 65536, 2), kdf("pbkdf2", 65536, 3)] {
            let e = check_kdf(pin, &weak).unwrap_err();
            assert_eq!(e.code, "kdf_downgrade");
            assert!(e.message.contains("Connexion bloquée"));
        }
        // Refus avant toute dérivation : login_with échoue sans appel réseau ni Argon2.
        let client = Client::new("http://127.0.0.1:9").unwrap();
        let r = login_with(client, "a@b.fr", "mot de passe", &kdf("argon2id", 19456, 2), None, pin);
        assert_eq!(r.err().map(|e| e.code).as_deref(), Some("kdf_downgrade"));
    }

    #[test]
    fn expired_sso_ticket_is_explained() {
        let e = || ApiError { status: 401, code: "unauthorized".into(), message: "Non authentifié.".into() };
        assert_eq!(explain_sso_expiry(e(), true).message, "Connexion d'entreprise expirée (5 minutes). Recommencez.");
        assert_eq!(explain_sso_expiry(e(), false).message, "Non authentifié.");
        let other = ApiError { status: 403, code: "forbidden".into(), message: "Refusé.".into() };
        assert_eq!(explain_sso_expiry(other, true).message, "Refusé.");
    }
}

#[cfg(test)]
mod live_tests {
    //! Test de bout en bout contre un serveur réel (ignoré par défaut) :
    //! LOCKSY_TEST_URL, LOCKSY_TEST_EMAIL et LOCKSY_TEST_PASSWORD.
    use super::*;
    use locksy_core::model::ItemKind;

    #[test]
    #[ignore]
    fn login_sync_create_roundtrip() {
        let url = std::env::var("LOCKSY_TEST_URL").expect("LOCKSY_TEST_URL");
        let email = std::env::var("LOCKSY_TEST_EMAIL").expect("LOCKSY_TEST_EMAIL");
        let password = std::env::var("LOCKSY_TEST_PASSWORD").expect("LOCKSY_TEST_PASSWORD");
        let client = Client::new(&url).expect("client");
        let (client, mut vault) = match login(client, &email, &password, None).expect("connexion") {
            LoginOutcome::Done(c, v) => (c, v),
            LoginOutcome::NeedTotp(..) => panic!("compte de test avec 2FA"),
        };
        let before = vault.items.iter().filter(|i| i.data.is_some()).count();
        let target = vault.collections.iter().find(|c| c.writable()).expect("coffre inscriptible").id.clone();
        let mut data = ItemData { kind: ItemKind::Login, name: "Créé par le client de bureau".into(), username: "bureau".into(), ..Default::default() };
        data.set_password("Bureau-Test-2026!".into(), locksy_core::now_unix());
        let req = vault.prepare_create(&target, &data).expect("chiffrement");
        let id = req.id.clone();
        client.send::<_, serde_json::Value>("POST", "/items", &req).expect("envoi");
        vault.apply_sync(Vault::fetch(&client).expect("sync"));
        let item = vault.items.iter().find(|i| i.id == id).expect("élément présent");
        assert_eq!(item.data.as_ref().expect("déchiffré").password, "Bureau-Test-2026!");
        assert_eq!(vault.items.iter().filter(|i| i.data.is_some()).count(), before + 1);
        // Modification avec contrôle de révision.
        let mut changed = item.data.clone().unwrap();
        changed.set_password("Bureau-Test-2027!".into(), locksy_core::now_unix());
        let (path, upd) = vault.prepare_update(&id, &target, &changed).expect("prép. mise à jour");
        client.send::<_, i64>("PUT", &path, &upd).expect("mise à jour");
        let stale = client.send::<_, i64>("PUT", &path, &upd);
        assert_eq!(stale.expect_err("révision périmée refusée").status, 409);
        vault.apply_sync(Vault::fetch(&client).expect("sync"));
        let item = vault.items.iter().find(|i| i.id == id).unwrap();
        assert_eq!(item.data.as_ref().unwrap().password_history[0].password, "Bureau-Test-2026!");
        client.send_empty("POST", "/auth/logout").expect("déconnexion");
        println!("OK : {} élément(s) lisibles après le test", vault.items.iter().filter(|i| i.data.is_some()).count());
    }
}
