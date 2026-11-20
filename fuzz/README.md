# Fuzzing du noyau Locksy

Cibles [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) sur les fonctions
du noyau qui lisent des données venues de l'extérieur (serveur, fichiers,
saisie). Ce dossier est un paquet à part : il n'appartient pas au workspace
racine et garde son propre `Cargo.lock`.

| Cible | Fonction testée |
| --- | --- |
| `decrypt` | `crypto::decrypt`, `decrypt_string`, `unwrap_key` (format `v1.`) |
| `open` | `crypto::open`, `open_key` (format `s1.`) |
| `b64d` | `encoding::b64d` (aller-retour avec `b64e`) |
| `crockford_decode` | `encoding::crockford_decode` |
| `totp_parse` | `totp::parse` (secret base32 ou URI `otpauth://`) |
| `parse_recovery_key` | `crypto::parse_recovery_key` |
| `percent_decode` | `encoding::percent_decode` |

## Lancer

Chaîne nightly et cargo-fuzz requis :

```sh
rustup toolchain install nightly
cargo install cargo-fuzz --locked
cd fuzz
cargo +nightly fuzz run decrypt                           # sans limite de durée
cargo +nightly fuzz run decrypt -- -max_total_time=30     # 30 secondes, comme la CI
```

Les entrées qui font paniquer une cible sont rangées dans
`fuzz/artifacts/<cible>/` ; les rejouer avec
`cargo +nightly fuzz run <cible> fuzz/artifacts/<cible>/<fichier>`.

Vérifier seulement que les cibles compilent (sans nightly) :
`cargo check --bins` depuis ce dossier.

La CI (job « fuzz » de `.github/workflows/ci.yml`) lance chaque cible 30 s ;
ce job n'est pas bloquant.
