//! Vecteurs de test du noyau.
//!
//! 1. Vecteurs EXTERNES (RFC 7748, RFC 5869, RFC 9106, draft-irtf-cfrg-xchacha-03) :
//!    ils prouvent que les primitives employées par Locksy sont les bonnes.
//!    Un vecteur externe n'est jamais « corrigé » en recopiant la sortie du
//!    code : en cas d'écart, c'est la transcription ou le code qui est faux.
//! 2. Vecteurs FIGÉS du format Locksy (`v1.`, `s1.`, dérivation du mot de
//!    passe maître, clé de récupération, empreinte) : ils protègent les données
//!    déjà enregistrées. Valeurs figées le 17/11/2026, ne JAMAIS les régénérer :
//!    un échec signifie une casse de compatibilité (les coffres existants ne
//!    se déchiffreraient plus).

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use locksy_core::crypto::{self, KdfParams, SecretKey};
use locksy_core::encoding::{b64d, b64e};
use locksy_core::{aad, Error};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// Décode une chaîne hexadécimale (espaces ignorés).
fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    assert_eq!(s.len() % 2, 0, "hexadécimal de longueur impaire");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hexadécimal")).collect()
}

fn arr32(s: &str) -> [u8; 32] {
    hex(s).try_into().expect("32 octets")
}

/// Suite d'octets consécutifs `debut..=fin`.
fn plage(debut: u8, fin: u8) -> Vec<u8> {
    (debut..=fin).collect()
}

// =========================================================================
// 1. Vecteurs externes
// =========================================================================

/// RFC 7748 §6.1 : échange X25519 d'Alice et Bob.
#[test]
fn rfc7748_x25519_alice_et_bob() {
    let alice = arr32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let alice_pub = arr32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let bob = arr32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let bob_pub = arr32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let partage = arr32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    // Clé publique telle que Locksy la calcule.
    assert_eq!(crypto::public_key_of(&SecretKey::from_bytes(alice)), alice_pub);
    assert_eq!(crypto::public_key_of(&SecretKey::from_bytes(bob)), bob_pub);

    let ab = StaticSecret::from(alice).diffie_hellman(&PublicKey::from(bob_pub));
    let ba = StaticSecret::from(bob).diffie_hellman(&PublicKey::from(alice_pub));
    assert_eq!(ab.to_bytes(), partage);
    assert_eq!(ba.to_bytes(), partage);
}

/// RFC 7748 §5.2 : deux multiplications scalaires (scalaire « brut », réduit
/// par la fonction X25519 ; le bit de poids fort de u est ignoré).
#[test]
fn rfc7748_x25519_multiplication() {
    let cas = [
        (
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        ),
        (
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
        ),
    ];
    for (k, u, sortie) in cas {
        let out = StaticSecret::from(arr32(k)).diffie_hellman(&PublicKey::from(arr32(u)));
        assert_eq!(out.to_bytes(), arr32(sortie), "scalaire {k}");
    }
}

fn hkdf_sha256(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut okm = vec![0u8; len];
    Hkdf::<Sha256>::new(salt, ikm).expand(info, &mut okm).expect("longueur HKDF valide");
    okm
}

/// RFC 5869 annexe A.1 à A.3 : HKDF-SHA256.
#[test]
fn rfc5869_hkdf_sha256() {
    // A.1 : cas de base.
    let (prk, _) = Hkdf::<Sha256>::extract(Some(&plage(0x00, 0x0c)), &[0x0b; 22]);
    assert_eq!(prk.as_slice(), hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"));
    assert_eq!(
        hkdf_sha256(Some(&plage(0x00, 0x0c)), &[0x0b; 22], &plage(0xf0, 0xf9), 42),
        hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    );
    // A.2 : entrées et sortie longues.
    assert_eq!(
        hkdf_sha256(Some(&plage(0x60, 0xaf)), &plage(0x00, 0x4f), &plage(0xb0, 0xff), 82),
        hex(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87"
        )
    );
    // A.3 : sel et info vides.
    assert_eq!(
        hkdf_sha256(None, &[0x0b; 22], &[], 42),
        hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
    );
}

/// `derive_subkey` est exactement HKDF-SHA256 avec le sel « verrou-v1 » et le
/// libellé comme info, sur 32 octets (sel et usage figés).
#[test]
fn derive_subkey_est_hkdf_avec_le_sel_verrou_v1() {
    let k = SecretKey::from_bytes([0x5c; 32]);
    for label in ["verrou/v1/recovery-enc", "verrou/v1/recovery-auth", "un libellé quelconque"] {
        let attendu = hkdf_sha256(Some(b"verrou-v1"), k.as_bytes(), label.as_bytes(), 32);
        assert_eq!(crypto::derive_subkey(&k, label).as_bytes().as_slice(), attendu.as_slice(), "{label}");
    }
}

/// RFC 9106 §5.3 : Argon2id version 0x13, avec secret et données associées.
/// `derive_master_keys` refuse moins de 19 Mio : le vecteur passe par le crate.
#[test]
fn rfc9106_argon2id() {
    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .output_len(32)
        .data(AssociatedData::new(&[0x04; 12]).expect("données associées"))
        .build()
        .expect("paramètres");
    let argon = Argon2::new_with_secret(&[0x03; 8], Algorithm::Argon2id, Version::V0x13, params).expect("secret");
    let mut tag = [0u8; 32];
    argon.hash_password_into(&[0x01; 32], &[0x02; 16], &mut tag).expect("hachage");
    assert_eq!(tag, arr32("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"));
}

const XCHACHA_TEXTE: &str = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

/// draft-irtf-cfrg-xchacha-03 annexe A.3.1 : AEAD XChaCha20-Poly1305.
#[test]
fn xchacha20_poly1305_draft_a3_1() {
    let key = plage(0x80, 0x9f);
    let nonce = plage(0x40, 0x57);
    let aad = hex("50515253c0c1c2c3c4c5c6c7");
    let chiffre = hex(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
         731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
         2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
         21f9664c97637da9768812f615c68b13b52e",
    );
    let tag = hex("c0875924c1c7987947deafd8780acf49");
    let attendu = [chiffre.clone(), tag].concat();

    let aead = XChaCha20Poly1305::new_from_slice(&key).expect("clé");
    let out = aead
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: XCHACHA_TEXTE.as_bytes(), aad: &aad })
        .expect("chiffrement");
    assert_eq!(out, attendu);

    // Le format v1 vaut exactement base64url(nonce ‖ chiffré ‖ tag) : le
    // déchiffrement de Locksy accepte le vecteur du draft tel quel.
    let k = SecretKey::from_slice(&key).unwrap();
    let v1 = format!("v1.{}", b64e(&[nonce.clone(), attendu.clone()].concat()));
    assert_eq!(&*crypto::decrypt(&k, &v1, &aad).unwrap(), XCHACHA_TEXTE.as_bytes());
    // Données associées différentes : refus.
    assert_eq!(crypto::decrypt(&k, &v1, b"autre").unwrap_err(), Error::Decrypt);
}

// =========================================================================
// 2. Vecteurs figés du format Locksy (17/11/2026, ne JAMAIS régénérer)
// =========================================================================

const COFFRE: &str = "6f1c2a3b-4d5e-4f60-8172-839405a6b7c8";
const ELEMENT: &str = "0a1b2c3d-4e5f-4a6b-9c7d-8e9fa0b1c2d3";
const MEMBRE: &str = "11111111-2222-4333-8444-555555555555";
const ELEMENT_CLAIR: &str = r#"{"type":"login","name":"Messagerie","username":"jean@exemple.fr","password":"Été-2026!"}"#;

/// XChaCha20-Poly1305 avec un nonce imposé, dans le format `v1.` (comme
/// `crypto::encrypt`, qui tire le nonce au hasard).
fn v1_avec_nonce(key: &[u8; 32], nonce: &[u8; 24], msg: &[u8], aad: &[u8]) -> String {
    let ct = XChaCha20Poly1305::new_from_slice(key)
        .unwrap()
        .encrypt(XNonce::from_slice(nonce), Payload { msg, aad })
        .unwrap();
    format!("v1.{}", b64e(&[nonce.as_slice(), &ct].concat()))
}

/// Valeur figée le 17/11/2026, ne JAMAIS régénérer : un échec signifie une casse de compatibilité.
const V1_ELEMENT: &str = "v1.JCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk3nyjHB5BbpyAQ1BdZ-Yv5hCf79cZPU6_bASVPgp3vr999Kr0Fu4o-Q7b0Nac_xKuPShOkGct-bl_SuW2v3nG2sK2QkV1QqxvvvJPBBfn0459Ml3ylgpYhSHCwqOHxUHrJ_W-c9rou3uJpg";

#[test]
fn fige_v1_element() {
    let ad = aad::item(COFFRE, ELEMENT);
    assert_eq!(ad, format!("verrou:v1:item:{COFFRE}:{ELEMENT}"));
    let construit = v1_avec_nonce(&[0x42; 32], &[0x24; 24], ELEMENT_CLAIR.as_bytes(), ad.as_bytes());
    assert_eq!(construit, V1_ELEMENT);
    let k = SecretKey::from_bytes([0x42; 32]);
    assert_eq!(crypto::decrypt_string(&k, V1_ELEMENT, &ad).unwrap(), ELEMENT_CLAIR);
    assert!(crypto::is_well_formed_cipher(V1_ELEMENT, 4096));
    // Lié à sa place : un autre élément ou un autre coffre ne déchiffre pas.
    assert_eq!(crypto::decrypt_string(&k, V1_ELEMENT, &aad::item(COFFRE, MEMBRE)).unwrap_err(), Error::Decrypt);
    assert_eq!(crypto::decrypt_string(&k, V1_ELEMENT, &aad::item(MEMBRE, ELEMENT)).unwrap_err(), Error::Decrypt);
}

/// Valeur figée le 17/11/2026, ne JAMAIS régénérer : un échec signifie une casse de compatibilité.
const V1_CLE_UTILISATEUR: &str = "v1.ExMTExMTExMTExMTExMTExMTExMTExMTCeehMiJnO8mdgZowmWwJ0P7Nb-7Qb7qO4XbcTxcvEphQo6GjbMyRZvAq0wiriq-X";

#[test]
fn fige_cle_utilisateur_enveloppee() {
    let enveloppe = [0x31u8; 32];
    let cle = [0x9au8; 32];
    let construit = v1_avec_nonce(&enveloppe, &[0x13; 24], &cle, aad::user_key().as_bytes());
    assert_eq!(construit, V1_CLE_UTILISATEUR);
    let k = SecretKey::from_bytes(enveloppe);
    assert_eq!(crypto::unwrap_key(&k, V1_CLE_UTILISATEUR, &aad::user_key()).unwrap().as_bytes(), &cle);
    // Une clé enveloppée aujourd'hui se désenveloppe pareillement.
    let neuf = crypto::wrap_key(&k, &SecretKey::from_bytes(cle), &aad::user_key());
    assert_eq!(crypto::unwrap_key(&k, &neuf, &aad::user_key()).unwrap().as_bytes(), &cle);
    assert!(crypto::unwrap_key(&k, V1_CLE_UTILISATEUR, &aad::recovery_user_key()).is_err());
}

/// Scellement `s1.` reconstruit à la main (comme `crypto::seal`, avec une clé
/// éphémère et un nonce imposés).
fn s1_a_la_main(eph: [u8; 32], destinataire: &[u8; 32], nonce: &[u8; 24], msg: &[u8], contexte: &str) -> String {
    let eph = StaticSecret::from(eph);
    let eph_pub = PublicKey::from(&eph).to_bytes();
    let partage = eph.diffie_hellman(&PublicKey::from(*destinataire));
    let sel = [eph_pub.as_slice(), destinataire].concat();
    let cle: [u8; 32] = hkdf_sha256(Some(&sel), partage.as_bytes(), format!("verrou/v1/seal|{contexte}").as_bytes(), 32)
        .try_into()
        .unwrap();
    let ct = XChaCha20Poly1305::new_from_slice(&cle)
        .unwrap()
        .encrypt(XNonce::from_slice(nonce), Payload { msg, aad: contexte.as_bytes() })
        .unwrap();
    format!("s1.{}", b64e(&[eph_pub.as_slice(), nonce, &ct].concat()))
}

/// Valeur figée le 17/11/2026, ne JAMAIS régénérer : un échec signifie une casse de compatibilité.
const S1_CLE_DE_COFFRE: &str = "s1.OKtmS9hvd9fma92a4HkpE6lP2LM6EmACfktGwfSITGd3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3eooWwVThiVkhIbLCH0cAOqonezQopKvIWQ4o69a7u5_Vm0gc5kADgQ0h9x1ex8Jc8";

#[test]
fn fige_s1_cle_de_coffre() {
    let privee = SecretKey::from_bytes([0x66; 32]);
    let publique = crypto::public_key_of(&privee);
    let cle_coffre = [0x88u8; 32];
    let contexte = aad::collection_key(COFFRE, MEMBRE);
    let construit = s1_a_la_main([0x55; 32], &publique, &[0x77; 24], &cle_coffre, &contexte);
    assert_eq!(construit, S1_CLE_DE_COFFRE);
    assert!(crypto::is_well_formed_sealed(S1_CLE_DE_COFFRE));
    assert_eq!(crypto::open_key(&privee, S1_CLE_DE_COFFRE, &contexte).unwrap().as_bytes(), &cle_coffre);
    // Contexte lié au coffre ET au destinataire.
    assert!(crypto::open_key(&privee, S1_CLE_DE_COFFRE, &aad::collection_key(COFFRE, ELEMENT)).is_err());
    assert!(crypto::open_key(&SecretKey::from_bytes([0x67; 32]), S1_CLE_DE_COFFRE, &contexte).is_err());
    // Un scellement d'aujourd'hui s'ouvre de la même façon.
    let neuf = crypto::seal_key(&publique, &SecretKey::from_bytes(cle_coffre), &contexte).unwrap();
    assert_eq!(crypto::open_key(&privee, &neuf, &contexte).unwrap().as_bytes(), &cle_coffre);
}

/// Valeurs figées le 17/11/2026, ne JAMAIS régénérer : un échec signifie une casse de compatibilité.
const MAITRE_AUTH: &str = "rUyLGWYHh9gA_MZRyOOe0TsE0pV4WTPOHTf9oaiKcNc";
const MAITRE_ENC: &str = "MbrtkQZmerNOuOvew_F4abxqBPFSxi46PTT0pUU0MDQ";

#[test]
fn fige_derivation_du_mot_de_passe_maitre() {
    let kdf = KdfParams { alg: "argon2id".into(), m_kib: 19_456, t: 2, p: 1, salt: b64e(&[0x11; 16]) };
    let nfc = "Mot de passe d\u{e9}j\u{e0} \u{e9}t\u{e9} 2026";
    let nfd = "Mot de passe de\u{301}ja\u{300} e\u{301}te\u{301} 2026";
    assert_ne!(nfc, nfd);
    let a = crypto::derive_master_keys(nfc, &kdf).unwrap();
    assert_eq!(a.auth_key.to_b64(), MAITRE_AUTH);
    assert_eq!(a.enc_key.to_b64(), MAITRE_ENC);
    // Normalisation NFC : la forme décomposée donne les mêmes clés.
    let b = crypto::derive_master_keys(nfd, &kdf).unwrap();
    assert_eq!(b.auth_key.to_b64(), MAITRE_AUTH);
    assert_eq!(b.enc_key.to_b64(), MAITRE_ENC);
}

/// Valeurs figées le 17/11/2026, ne JAMAIS régénérer : un échec signifie une casse de compatibilité.
const RECUPERATION_LISIBLE: &str = "B9D5-MPJT-B9D5-MPJT-B9D5-MPJT-B9D5-MPJT-B9D5-MPJT-B9D5-MPJT-B9D6-0";
const RECUPERATION_WRAP: &str = "mPuySE9Ksi28e0Mo5gbSGEGxR4gGY18EO_YDfjImylY";
const RECUPERATION_AUTH: &str = "EM2YK1s-_2ovbuC-BTadKQxUv7Y3RPSRh14uaTNv174";

#[test]
fn fige_cle_de_recuperation() {
    let cle = SecretKey::from_bytes([0x5a; 32]);
    assert_eq!(crypto::format_recovery_key(&cle), RECUPERATION_LISIBLE);
    assert_eq!(crypto::parse_recovery_key(RECUPERATION_LISIBLE).unwrap().as_bytes(), cle.as_bytes());
    // Saisie tolérante : minuscules, sans tirets, O pour 0, L pour 1.
    let saisie = RECUPERATION_LISIBLE.replace('-', " ").to_lowercase().replace('0', "o").replace('1', "l");
    assert_eq!(crypto::parse_recovery_key(&saisie).unwrap().as_bytes(), cle.as_bytes());
    let rk = crypto::recovery_keys(&cle);
    assert_eq!(rk.wrap_key.to_b64(), RECUPERATION_WRAP);
    assert_eq!(rk.auth_key.to_b64(), RECUPERATION_AUTH);
}

/// Valeur figée le 17/11/2026, ne JAMAIS régénérer : un échec signifie une casse de compatibilité.
const EMPREINTE: &str = "427F-F2BD-08C0-C694-C7F5-4239";

#[test]
fn fige_empreinte_de_cle_publique() {
    let publique = crypto::public_key_of(&SecretKey::from_bytes([0x66; 32]));
    assert_eq!(crypto::fingerprint(&publique), EMPREINTE);
}

/// Forme exacte de l'encodage base64 : alphabet URL (`-` et `_`), sans `=`.
#[test]
fn base64_url_sans_remplissage() {
    assert_eq!(b64e(&[0xfb, 0xff]), "-_8");
    assert_eq!(b64e(b"verrou"), "dmVycm91");
    assert_eq!(b64e(b"ab"), "YWI");
    assert_eq!(b64d("-_8").unwrap(), vec![0xfb, 0xff]);
    // L'alphabet standard et le remplissage sont refusés.
    assert!(b64d("+/8").is_err());
    assert!(b64d("YWI=").is_err());
    // Espaces de début et de fin tolérés (copier-coller).
    assert_eq!(b64d("  YWI\n").unwrap(), b"ab");
}
