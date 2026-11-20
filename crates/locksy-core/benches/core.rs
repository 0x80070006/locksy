//! Micro-benchmarks du noyau (lot Q1, criterion).
//!
//! Les identifiants « groupe/mesure » sont un contrat : `bench/scripts/criterion-gate.mjs`
//! les relit dans `target/criterion/<groupe>/<mesure>/new/estimates.json` et les compare à
//! `bench/baselines/criterion-ref.json`. Ne pas les renommer sans mettre la référence à jour.
//!
//! Référence (profil 2 vCPU, même toolchain que le serveur) :
//! `cargo bench -p locksy-core --bench core -- --noplot` dans le conteneur `locksy-toolchain`
//! bridé par `--cpus 2 --cpuset-cpus 2,3` (recette complète dans `criterion-gate.mjs`).
//!
//! Sous Windows avec la toolchain GNU, criterion n'est pas compilé (voir Cargo.toml) : le
//! programme se contente alors d'indiquer où lancer le banc.

#[cfg(not(all(windows, target_env = "gnu")))]
mod banc {
    use std::hint::black_box;
    use std::time::Duration;

    use argon2::{Algorithm, Argon2, Params, Version};
    use criterion::{criterion_group, Criterion, Throughput};
    use locksy_core::crypto::{self, KdfParams, SecretKey};
    use locksy_core::encoding::b64e;
    use locksy_core::generator::{self, PassphraseOptions, PasswordOptions};
    use locksy_core::{aad, strength, totp};

    /// Mot de passe maître fictif, de longueur réaliste.
    const MASTER_PASSWORD: &str = "cheval agrafe batterie correcte";
    /// Instant fixe : les mesures TOTP ne dépendent pas de l'horloge.
    const TOTP_TIME: u64 = 1_763_400_000;
    /// Mot de passe de 32 caractères qui exerce toutes les règles de l'estimateur
    /// (mot courant, année, suite clavier, symboles).
    const STRENGTH_SAMPLE: &str = "Tr0ub4dour&3-cheval-agrafe-2026!";

    /// Dérivation du mot de passe maître (client) et re-hachage de la preuve (serveur).
    fn kdf(c: &mut Criterion) {
        let mut g = c.benchmark_group("kdf");
        g.sample_size(10);
        g.measurement_time(Duration::from_secs(10));

        // Paramètres réels d'un compte : 64 Mio, 3 passes, 1 voie (KdfParams::recommended),
        // avec un sel fixe pour que chaque itération fasse exactement le même travail.
        let client = KdfParams::with_salt(b64e(&[7u8; 16]));
        assert_eq!((client.m_kib, client.t, client.p), (64 * 1024, 3, 1), "paramètres KDF recommandés modifiés");
        g.bench_function("client_derive_master_64MiB_t3", |b| {
            b.iter(|| crypto::derive_master_keys(black_box(MASTER_PASSWORD), &client).expect("dérivation"))
        });

        // Coût du re-hachage de l'auth_key par le serveur (security.rs : 19 Mio, t=2, p=1).
        let server = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(19 * 1024, 2, 1, Some(32)).expect("paramètres Argon2 valides"),
        );
        g.bench_function("server_rehash_19MiB_t2", |b| {
            let mut out = [0u8; 32];
            b.iter(|| {
                server
                    .hash_password_into(black_box(&[7u8; 32]), b"sel-de-16-octets", &mut out)
                    .expect("re-hachage");
                out
            })
        });
        g.finish();
    }

    /// Chiffrement et déchiffrement d'un élément (XChaCha20-Poly1305 + AAD d'élément).
    fn aead(c: &mut Criterion) {
        let key = SecretKey::generate();
        let item_aad = aad::item("coffre-bench", "element-bench");
        let mut g = c.benchmark_group("aead");
        for (label, size) in [("1KiB", 1024usize), ("100KiB", 100 * 1024), ("10MiB", 10 * 1024 * 1024)] {
            if size >= 1024 * 1024 {
                g.sample_size(10);
            }
            let plaintext = vec![0x42u8; size];
            let ciphertext = crypto::encrypt(&key, &plaintext, item_aad.as_bytes());
            g.throughput(Throughput::Bytes(size as u64));
            g.bench_function(format!("encrypt_{label}"), |b| {
                b.iter(|| crypto::encrypt(&key, black_box(&plaintext), item_aad.as_bytes()))
            });
            g.bench_function(format!("decrypt_{label}"), |b| {
                b.iter(|| crypto::decrypt(&key, black_box(&ciphertext), item_aad.as_bytes()).expect("déchiffrement"))
            });
        }
        g.finish();
    }

    /// Scellement d'une clé de coffre pour un membre (X25519) : partage et rotation.
    fn sealing(c: &mut Criterion) {
        let (private, public) = crypto::generate_keypair();
        let collection_key = SecretKey::generate();
        let context = aad::collection_key("coffre-bench", "membre-bench");
        let sealed = crypto::seal_key(&public, &collection_key, &context).expect("scellement");
        let mut g = c.benchmark_group("sealing");
        g.bench_function("seal_key", |b| {
            b.iter(|| crypto::seal_key(black_box(&public), &collection_key, &context).expect("scellement"))
        });
        g.bench_function("open_key", |b| {
            b.iter(|| crypto::open_key(&private, black_box(&sealed), &context).expect("ouverture"))
        });
        g.finish();
    }

    /// Enveloppement symétrique d'une clé (clé utilisateur sous la clé maître).
    fn keywrap(c: &mut Criterion) {
        let wrapping = SecretKey::generate();
        let key = SecretKey::generate();
        let context = aad::user_key();
        let wrapped = crypto::wrap_key(&wrapping, &key, &context);
        let mut g = c.benchmark_group("keywrap");
        g.bench_function("wrap_key", |b| b.iter(|| crypto::wrap_key(&wrapping, black_box(&key), &context)));
        g.bench_function("unwrap_key", |b| {
            b.iter(|| crypto::unwrap_key(&wrapping, black_box(&wrapped), &context).expect("désenveloppement"))
        });
        g.finish();
    }

    /// Code TOTP d'un élément et vérification serveur sur la fenêtre de ±1 pas.
    fn otp(c: &mut Criterion) {
        let cfg = totp::parse("otpauth://totp/Exemple:bench?secret=JBSWY3DPEHPK3PXP&issuer=Exemple").expect("URI TOTP");
        let code = totp::code_at(&cfg, TOTP_TIME);
        let mut g = c.benchmark_group("totp");
        g.bench_function("generate", |b| b.iter(|| totp::code_at(black_box(&cfg), TOTP_TIME)));
        g.bench_function("verify_window", |b| {
            b.iter(|| totp::verify(&cfg.secret, black_box(&code), TOTP_TIME, None).expect("code valide"))
        });
        g.finish();
    }

    /// Générateur : mot de passe de 20 caractères et phrase de passe de 5 mots (réglages par défaut).
    fn generators(c: &mut Criterion) {
        let password = PasswordOptions::default();
        let passphrase = PassphraseOptions::default();
        assert_eq!((password.length, passphrase.words), (20, 5), "réglages par défaut du générateur modifiés");
        let mut g = c.benchmark_group("generator");
        g.bench_function("password_20", |b| {
            b.iter(|| generator::generate_password(black_box(&password)).expect("mot de passe"))
        });
        g.bench_function("passphrase_5", |b| {
            b.iter(|| generator::generate_passphrase(black_box(&passphrase)).expect("phrase de passe"))
        });
        g.finish();
    }

    /// Estimation de robustesse : elle tourne à chaque frappe dans les formulaires.
    fn strength_estimate(c: &mut Criterion) {
        let mut g = c.benchmark_group("strength");
        g.bench_function("strength_estimate", |b| b.iter(|| strength::estimate(black_box(STRENGTH_SAMPLE))));
        g.finish();
    }

    criterion_group!(benches, kdf, aead, sealing, keywrap, otp, generators, strength_estimate);
}

#[cfg(not(all(windows, target_env = "gnu")))]
criterion::criterion_main!(banc::benches);

#[cfg(all(windows, target_env = "gnu"))]
fn main() {
    eprintln!("Micro-benchmarks indisponibles avec la toolchain Windows GNU : lancez-les dans le conteneur locksy-toolchain (voir bench/scripts/criterion-gate.mjs).");
}
