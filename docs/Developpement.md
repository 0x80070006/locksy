# Développement

## Organisation du code

| Dossier | Contenu |
|---|---|
| `crates/locksy-core` | noyau : chiffrement, dérivation, TOTP, générateur, robustesse, modèle, contrat d'API |
| `crates/locksy-server` | serveur (axum, SQLite) : API, SSO, SCIM, Active Directory, Syslog, HTTPS |
| `crates/locksy-wasm` | pont WebAssembly vers le noyau, sans code généré |
| `crates/locksy-desktop` | client Windows (egui) |
| `web/` | interface web (JavaScript sans framework ni étape de construction) |
| `extension/` | extension Edge/Chrome (Manifest V3) |
| `branding/` | logo (SVG source, PNG, ICO) |
| `docs/` | cette documentation |
| `install.sh`, `install-client.ps1` | installation serveur et poste |
| `scripts/` | publication (`package-release.sh`), sauvegarde (`backup-locksy.sh`) |
| `fuzz/` | cibles de fuzzing du noyau (paquet hors du workspace) |
| `.github/` | CI (`ci.yml`), publication (`release.yml`), Dependabot |
| `deny.toml`, `rust-toolchain.toml` | politique des dépendances, version de Rust |

## Toolchain

`rust-toolchain.toml` épingle **Rust 1.100.0** (composant clippy, cibles
`wasm32-unknown-unknown` et `x86_64-pc-windows-gnu`, profil minimal). Les images Docker de
construction utilisent la même version, épinglée par empreinte
(`rust:1.100.0-trixie@sha256:…`) ; la CI vérifie que les deux concordent.

Sur un poste qui n'a qu'une autre toolchain, une commande `cargo` lancée dans le dépôt ferait
télécharger 1.100.0 par rustup. Pour utiliser la toolchain locale, forcez-la :

```bash
RUSTUP_TOOLCHAIN=stable cargo test -p locksy-core
```

## Construire

Tout se construit dans Docker, sans outil à installer sur le poste :

```bash
# Serveur + interface web (image Docker), tests compris
docker compose up -d --build

# Toutes les pièces d'une version : serveur Linux statique, locksy.wasm, locksy.exe
docker build -f Dockerfile.release --target export --output type=local,dest=dist/release .

# Archives de version (dist/assets) avec SHA256SUMS
bash scripts/package-release.sh 0x80070006/locksy v1.1.0

# Extension seule : zip déterministe et son .sha256 (extension/dist par défaut)
node extension/build.mjs --wasm dist/release/locksy.wasm
```

### Archives reproductibles

`scripts/package-release.sh <propriétaire/dépôt> <version>` lit
`dist/release/{locksy-server,locksy.wasm,locksy.exe}` et écrit dans `dist/assets/` :
`locksy-server-linux-x86_64.tar.gz`, `locksy-windows-x64.exe`, `locksy-extension.zip`,
`install.sh` (avec `__REPO__` et `__MINISIGN_PUBKEY__` remplacés), `install-client.ps1`, les
SBOM `*.cdx.json` de `dist/sbom/` s'il existe, et `SHA256SUMS` (format `sha256sum`, trié avec
`LC_ALL=C`). Les dates des fichiers viennent de `SOURCE_DATE_EPOCH` (défaut : date du dernier
commit, `git log -1 --format=%ct`, ou 0 hors git) : deux exécutions sur les mêmes entrées
donnent le même `SHA256SUMS`. `MINISIGN_PUBLIC_KEY`, si elle est définie, est inscrite dans
`install.sh`.

L'archive du serveur contient, sous `locksy-server/` : `bin/locksy-server`, `web/` (avec
`locksy.wasm` et `locksy-import.wasm`, sans `web/tests`), `LICENSE`, `VERSION`, `install.sh` et
`scripts/backup-locksy.sh`.

## Tests

```bash
# Noyau, en natif (toolchain locale)
RUSTUP_TOOLCHAIN=stable cargo test -p locksy-core

# Tout le workspace, dans Docker
docker run --rm -v "$PWD:/src" -w /src rust:1.100.0-trixie cargo test --workspace

# JavaScript (Node 26) : outils, interface web, extension, banc k6
node --test tools/test web/tests extension/src/test bench/k6/test

# Fichiers générés à jour, contrastes, textes en dur (bloquant)
node tools/gen-tokens.mjs --check && node tools/gen-icons.mjs --check && node tools/gen-i18n.mjs --check
node tools/check-contrast.mjs
node tools/lint-strings.mjs --strict web/js/views web/js/ui extension/src

# Bout en bout (Playwright dans Docker) : voir e2e/README.md
bash e2e/tools/run.sh -p <cle> --fast-server -- --project=chromium tests/smoke
```

Sur ce poste, le serveur et le client Windows se compilent dans l'image `locksy-toolchain`
(volumes `locksy-reg` et `locksy-tgt-<clé>`, `MSYS_NO_PATHCONV=1` sous Git Bash) :

```bash
docker run --rm --cpus=3 --memory=6g -e CARGO_BUILD_JOBS=3 -v "$PWD:/src"   -v locksy-reg:/usr/local/cargo/registry -v locksy-tgt-srv:/src/target -w /src locksy-toolchain   bash -c "cargo clippy --workspace --all-targets --exclude locksy-desktop -- -D warnings && cargo test -p locksy-server"
```

- **Noyau** : vecteurs officiels (RFC 6238 pour le TOTP, RFC 7748 pour X25519, RFC 5869 pour
  HKDF, RFC 9106 pour Argon2, XChaCha20-Poly1305), liaison des données associées, détection
  d'altération, unicité des nonces, refus de paramètres Argon2id faibles, clé de récupération,
  scellement. Les tests de `crates/locksy-core/tests/` figent aussi le **format `v1`** : des
  chiffrés produits une fois doivent toujours se déchiffrer.
- **Serveur** : tests unitaires des modules et tests HTTP de bout en bout
  (`crates/locksy-server/src/http_tests.rs` : contrôle d'accès, authentification, jeton
  d'installation). Un test ne doit ni lire ni modifier une variable d'environnement.
- **JavaScript** : `node --test` sur `web/tests` (presse-papiers, épinglage, parcours du coffre
  avec le vrai `locksy.wasm` de `dist/release/`) et `extension/src/test` (correspondance des
  sites, réglages, construction du zip).
- Les tests d'intégration (`#[ignore]`) rejouent les parcours réels contre un serveur, un
  fournisseur OpenID Connect et un contrôleur de domaine.

> **Vecteurs figés : ne jamais les régénérer.** Si un test de format échoue après une
> modification, c'est la modification qui casse la compatibilité des coffres existants, pas le
> vecteur qui est faux.

### Fuzzing

Le dossier `fuzz/` est un paquet `cargo-fuzz` (`locksy-core-fuzz`), avec son propre workspace
et son propre `Cargo.lock`. Cibles : `decrypt`, `open`, `b64d`, `crockford_decode`,
`totp_parse`, `parse_recovery_key` et `percent_decode` (détail dans `fuzz/README.md`).

```bash
cargo install cargo-fuzz --locked
cd fuzz && cargo +nightly fuzz run decrypt -- -max_total_time=60
```

## Intégration continue

`.github/workflows/ci.yml`, sur chaque push et demande de fusion vers `main` :

| Job | Contenu |
|---|---|
| `fmt` | `cargo fmt --check` (non bloquant tant que le reformatage global n'est pas fait) |
| `clippy` | clippy sur tout le workspace |
| `test-core`, `test-server` | tests du noyau et du serveur |
| `test-desktop` | tests du client Windows et `cargo check --target x86_64-pc-windows-gnu` |
| `wasm` | modules WebAssembly `locksy.wasm` (≤ 700 Ko, ≤ 260 Ko en gzip) et `locksy-import.wasm`, tests sans les lecteurs d'import (`wasm-opt` facultatif) |
| `js` | `node --check`, fichiers générés à jour, contrastes, textes en dur (bloquant), règles R1, `node --test` (outils, web, extension, banc k6), extension reproductible (deux constructions, même empreinte) |
| `shell` | `bash -n` (`install.sh`, `scripts/`, `e2e/tools/`, `bench/scripts/`) et `shellcheck -S warning` sur `install.sh` et `scripts/*.sh` |
| `deny`, `audit` | `cargo-deny` (`deny.toml`) et `cargo-audit` |
| `docker` | construction de `Dockerfile` et analyse Trivy (CRITICAL, HIGH, corrigeables) |
| `fuzz` | nightly, 30 s par cible, non bloquant |

Dependabot (`.github/dependabot.yml`) propose chaque semaine les mises à jour cargo, GitHub
Actions et Docker.

## Publier une version

1. Mettez à jour `version` dans le `Cargo.toml` racine (`X.Y.Z`) et le [CHANGELOG](../CHANGELOG.md)
   (date de la section), commitez.
2. Posez le tag `vX.Y.Z` et poussez-le : `.github/workflows/release.yml` refuse un tag
   différent de la version du workspace.
3. Le workflow construit (`Dockerfile.release`, `SOURCE_DATE_EPOCH` du commit), signe
   l'exécutable Windows si le certificat est configuré, produit les SBOM, assemble
   `dist/assets/` par `package-release.sh`, signe `SHA256SUMS` (cosign sans clé, puis minisign
   si la clé existe), ajoute les attestations de provenance et crée une **release en
   brouillon**.
4. Relisez le brouillon, vérifiez une signature ([SECURITY.md](../SECURITY.md#vérifier-une-version)),
   puis publiez.

Secrets et variables du dépôt (Settings > Secrets and variables > Actions) :

| Nom | Type | Rôle |
|---|---|---|
| `MINISIGN_SECRET_KEY` | secret | contenu de `minisign.key`, générée par `minisign -G -W` (sans mot de passe : protégée par le coffre de GitHub ; compromis assumé) |
| `MINISIGN_PUBLIC_KEY` | variable | clé publique minisign, inscrite dans `install.sh` |
| `WINDOWS_CERT_PFX` | secret | certificat Authenticode (PFX en base64) |
| `WINDOWS_CERT_PASSWORD` | secret | mot de passe du PFX |
| `WINDOWS_TIMESTAMP_URL` | variable | serveur d'horodatage (défaut `http://timestamp.digicert.com`) |

Sans `MINISIGN_SECRET_KEY`, seule la signature cosign est produite ; sans `WINDOWS_CERT_PFX`,
l'exécutable n'est pas signé Authenticode. La signature cosign n'a besoin d'aucun secret
(identité OIDC du workflow).

## Principes

- Aucun secret en clair hors du poste ; toute nouvelle donnée chiffrée a ses **données
  associées** propres (voir `aad.rs` et `web/js/aad.js`, à garder identiques).
- Les constantes de protocole `verrou:v1`, `verrou/v1`, `verrou-v1` ne doivent **jamais**
  changer (compatibilité des coffres existants).
- Le contenu utilisateur n'est jamais inséré en HTML (`textContent` uniquement), CSP stricte.
- Messages d'erreur et interface en français, sans détail technique pour l'utilisateur final.
