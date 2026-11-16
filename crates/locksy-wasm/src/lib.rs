//! Pont WebAssembly entre l'interface web et `locksy-core`.
//!
//! Interface volontairement minimale, sans dépendance JavaScript générée :
//! - `locksy_alloc` / `locksy_free` gèrent les tampons (effacés à la libération) ;
//! - `locksy_call` reçoit une requête JSON `{ "op": ..., ... }` et renvoie
//!   `{ "ok": true, "result": ... }` ou `{ "ok": false, "error": "..." }`.
//!
//! Les clés restent dans la mémoire WebAssembly : JavaScript ne manipule que
//! des numéros de poignée. `clear` efface tout le trousseau au locksyillage.

use serde::Deserialize;
use serde_json::{json, Value};
use std::cell::RefCell;
use std::collections::HashMap;
use locksy_core::crypto::{self, KdfParams, SecretKey};
use locksy_core::encoding::{b64d_array, b64e};
use locksy_core::generator::{self, PassphraseOptions, PasswordOptions};
use locksy_core::{strength, totp};
use zeroize::Zeroize;

// --------------------------------------------------------------- Aléa

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "locksy")]
extern "C" {
    fn random_fill(ptr: *mut u8, len: usize);
}

#[cfg(target_arch = "wasm32")]
fn js_getrandom(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    // SAFETY : le tampon est valide et exclusif pendant l'appel ; l'hôte
    // JavaScript le remplit avec crypto.getRandomValues.
    unsafe { random_fill(buf.as_mut_ptr(), buf.len()) };
    Ok(())
}

#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(js_getrandom);

// --------------------------------------------------------------- Mémoire

#[no_mangle]
pub extern "C" fn locksy_alloc(len: usize) -> *mut u8 {
    let layout = std::alloc::Layout::array::<u8>(len.max(1)).expect("taille d'allocation valide");
    // SAFETY : la taille est non nulle.
    unsafe { std::alloc::alloc_zeroed(layout) }
}

/// # Safety
/// `ptr` doit provenir de `locksy_alloc(len)` et ne pas avoir été libéré.
#[no_mangle]
pub unsafe extern "C" fn locksy_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    std::slice::from_raw_parts_mut(ptr, len).zeroize();
    let layout = std::alloc::Layout::array::<u8>(len.max(1)).expect("taille d'allocation valide");
    std::alloc::dealloc(ptr, layout);
}

/// # Safety
/// `ptr` doit désigner `len` octets lisibles. Le résultat est un pointeur et
/// une longueur empaquetés (`ptr << 32 | len`) à libérer avec `locksy_free`.
#[no_mangle]
pub unsafe extern "C" fn locksy_call(ptr: *const u8, len: usize) -> u64 {
    let input = std::slice::from_raw_parts(ptr, len);
    let mut out = handle(input).into_bytes();
    let out_len = out.len();
    let out_ptr = locksy_alloc(out_len);
    std::ptr::copy_nonoverlapping(out.as_ptr(), out_ptr, out_len);
    out.zeroize();
    ((out_ptr as u64) << 32) | out_len as u64
}

// --------------------------------------------------------------- Trousseau

#[derive(Default)]
struct Keyring {
    next: u32,
    keys: HashMap<u32, SecretKey>,
}

thread_local! {
    static KEYRING: RefCell<Keyring> = RefCell::new(Keyring { next: 1, keys: HashMap::new() });
}

fn store(key: SecretKey) -> u32 {
    KEYRING.with(|k| {
        let mut k = k.borrow_mut();
        let id = k.next;
        k.next = k.next.wrapping_add(1).max(1);
        k.keys.insert(id, key);
        id
    })
}

fn with_key<T>(id: u32, f: impl FnOnce(&SecretKey) -> Result<T, String>) -> Result<T, String> {
    KEYRING.with(|k| {
        let k = k.borrow();
        let key = k.keys.get(&id).ok_or_else(|| "clé inconnue ou effacée (coffre locksyillé ?)".to_string())?;
        f(key)
    })
}

fn with_two<T>(a: u32, b: u32, f: impl FnOnce(&SecretKey, &SecretKey) -> Result<T, String>) -> Result<T, String> {
    KEYRING.with(|k| {
        let k = k.borrow();
        let ka = k.keys.get(&a).ok_or("clé inconnue")?;
        let kb = k.keys.get(&b).ok_or("clé inconnue")?;
        f(ka, kb)
    })
}

// --------------------------------------------------------------- Opérations

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    NewKdf,
    DeriveMaster { password: String, kdf: KdfParams },
    GenerateKey,
    ImportKey { key: String },
    ExportKey { key: u32 },
    DropKey { key: u32 },
    Clear,
    Wrap { wrapping: u32, key: u32, aad: String },
    Unwrap { wrapping: u32, data: String, aad: String },
    Encrypt { key: u32, plaintext: String, aad: String },
    Decrypt { key: u32, data: String, aad: String },
    /// Données binaires (pièces jointes), transmises en base64.
    EncryptBytes { key: u32, data: String, aad: String },
    DecryptBytes { key: u32, data: String, aad: String },
    GenerateKeypair,
    PublicKey { key: u32 },
    Seal { public_key: String, key: u32, context: String },
    Open { private_key: u32, data: String, context: String },
    GenerateRecovery,
    ParseRecovery { recovery: String },
    RecoveryKeys { recovery: u32 },
    Fingerprint { public_key: String },
    Totp { secret: String, time: u64 },
    GeneratePassword { options: PasswordOptions },
    GeneratePassphrase { options: PassphraseOptions },
    Strength { password: String },
    ProtectExport { password: String, plaintext: String },
    UnprotectExport { password: String, data: String },
    NewUuid,
}

fn handle(input: &[u8]) -> String {
    let result = match serde_json::from_slice::<Request>(input) {
        Ok(req) => run(req),
        Err(e) => Err(format!("requête invalide : {e}")),
    };
    match result {
        Ok(v) => json!({ "ok": true, "result": v }).to_string(),
        Err(e) => json!({ "ok": false, "error": e }).to_string(),
    }
}

fn err(e: locksy_core::Error) -> String {
    e.to_string()
}

fn run(req: Request) -> Result<Value, String> {
    Ok(match req {
        Request::NewKdf => json!(KdfParams::recommended()),
        Request::DeriveMaster { mut password, kdf } => {
            let keys = crypto::derive_master_keys(&password, &kdf);
            password.zeroize();
            let keys = keys.map_err(err)?;
            json!({ "auth_key": keys.auth_key.to_b64(), "enc_key": store(keys.enc_key) })
        }
        Request::GenerateKey => json!(store(SecretKey::generate())),
        Request::ImportKey { key } => json!(store(SecretKey::from_b64(&key).map_err(err)?)),
        Request::ExportKey { key } => json!(with_key(key, |k| Ok(k.to_b64()))?),
        Request::DropKey { key } => {
            KEYRING.with(|k| k.borrow_mut().keys.remove(&key));
            Value::Null
        }
        Request::Clear => {
            KEYRING.with(|k| k.borrow_mut().keys.clear());
            Value::Null
        }
        Request::Wrap { wrapping, key, aad } => json!(with_two(wrapping, key, |w, k| Ok(crypto::wrap_key(w, k, &aad)))?),
        Request::Unwrap { wrapping, data, aad } => {
            let k = with_key(wrapping, |w| crypto::unwrap_key(w, &data, &aad).map_err(err))?;
            json!(store(k))
        }
        Request::Encrypt { key, mut plaintext, aad } => {
            let ct = with_key(key, |k| Ok(crypto::encrypt_str(k, &plaintext, &aad)));
            plaintext.zeroize();
            json!(ct?)
        }
        Request::Decrypt { key, data, aad } => json!(with_key(key, |k| crypto::decrypt_string(k, &data, &aad).map_err(err))?),
        Request::EncryptBytes { key, data, aad } => {
            let mut bytes = locksy_core::encoding::b64d(&data).map_err(err)?;
            let ct = with_key(key, |k| Ok(crypto::encrypt(k, &bytes, aad.as_bytes())));
            bytes.zeroize();
            json!(ct?)
        }
        Request::DecryptBytes { key, data, aad } => {
            let pt = with_key(key, |k| crypto::decrypt(k, &data, aad.as_bytes()).map_err(err))?;
            json!(b64e(&pt))
        }
        Request::GenerateKeypair => {
            let (sk, pk) = crypto::generate_keypair();
            json!({ "private_key": store(sk), "public_key": b64e(&pk) })
        }
        Request::PublicKey { key } => json!(with_key(key, |k| Ok(b64e(&crypto::public_key_of(k))))?),
        Request::Seal { public_key, key, context } => {
            let pk: [u8; 32] = b64d_array(&public_key).map_err(err)?;
            json!(with_key(key, |k| crypto::seal_key(&pk, k, &context).map_err(err))?)
        }
        Request::Open { private_key, data, context } => {
            let k = with_key(private_key, |sk| crypto::open_key(sk, &data, &context).map_err(err))?;
            json!(store(k))
        }
        Request::GenerateRecovery => {
            let (display, key) = crypto::generate_recovery_key();
            json!({ "display": display, "key": store(key) })
        }
        Request::ParseRecovery { mut recovery } => {
            let k = crypto::parse_recovery_key(&recovery);
            recovery.zeroize();
            json!(store(k.map_err(err)?))
        }
        Request::RecoveryKeys { recovery } => {
            let keys = with_key(recovery, |r| Ok(crypto::recovery_keys(r)))?;
            json!({ "wrap_key": store(keys.wrap_key.clone()), "auth_key": keys.auth_key.to_b64() })
        }
        Request::Fingerprint { public_key } => {
            let pk: [u8; 32] = b64d_array(&public_key).map_err(err)?;
            json!(crypto::fingerprint(&pk))
        }
        Request::Totp { secret, time } => {
            let cfg = totp::parse(&secret).map_err(err)?;
            json!({
                "code": totp::code_at(&cfg, time),
                "remaining": totp::seconds_remaining(&cfg, time),
                "period": cfg.period,
            })
        }
        Request::GeneratePassword { options } => json!(generator::generate_password(&options).map_err(err)?),
        Request::GeneratePassphrase { options } => json!(generator::generate_passphrase(&options).map_err(err)?),
        Request::Strength { mut password } => {
            let s = strength::estimate(&password);
            password.zeroize();
            json!(s)
        }
        Request::ProtectExport { mut password, mut plaintext } => {
            let r = crypto::protect_with_password(&password, plaintext.as_bytes());
            password.zeroize();
            plaintext.zeroize();
            json!(r.map_err(err)?)
        }
        Request::UnprotectExport { mut password, data } => {
            let r = crypto::unprotect_with_password(&password, &data);
            password.zeroize();
            let bytes = r.map_err(err)?;
            json!(String::from_utf8(bytes.to_vec()).map_err(|_| "export illisible".to_string())?)
        }
        Request::NewUuid => json!(crypto::new_uuid()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(v: Value) -> Value {
        serde_json::from_str(&handle(v.to_string().as_bytes())).unwrap()
    }

    #[test]
    fn keyring_flow() {
        let k = call(json!({"op":"generate_key"}))["result"].as_u64().unwrap();
        let ct = call(json!({"op":"encrypt","key":k,"plaintext":"bonjour","aad":"a"}));
        let ct = ct["result"].as_str().unwrap().to_string();
        let pt = call(json!({"op":"decrypt","key":k,"data":ct,"aad":"a"}));
        assert_eq!(pt["result"], "bonjour");
        let bad = call(json!({"op":"decrypt","key":k,"data":ct,"aad":"b"}));
        assert_eq!(bad["ok"], false);
        call(json!({"op":"clear"}));
        assert_eq!(call(json!({"op":"decrypt","key":k,"data":ct,"aad":"a"}))["ok"], false);
    }

    #[test]
    fn unknown_op_is_an_error() {
        assert_eq!(call(json!({"op":"nope"}))["ok"], false);
    }
}
