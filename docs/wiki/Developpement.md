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
| `docs/wiki/` | ce wiki |
| `install.sh`, `install-client.ps1` | installation serveur et poste |

## Construire

Tout se construit dans Docker, sans outil à installer sur le poste :

```bash
# Serveur + interface web (image Docker), tests compris
docker compose up -d --build

# Toutes les pièces d'une version : serveur Linux statique, locksy.wasm, locksy.exe
docker build -f Dockerfile.release --target export --output type=local,dest=dist/release .

# Archives de version (dist/assets) avec SHA256SUMS
bash scripts/package-release.sh 0x80070006/locksy v1.0.0

# Extension seule (le conteneur locksy doit tourner)
node extension/build.mjs
```

## Tests

```bash
docker run --rm -v "$PWD:/src" -w /src rust:1-trixie cargo test --workspace
```

Le noyau est vérifié contre les vecteurs officiels (RFC 6238 pour le TOTP) et teste la liaison
des données associées, la détection d'altération, l'unicité des nonces, le refus de paramètres
Argon2id faibles, la clé de récupération (contrôle d'erreur), le scellement. Les tests
d'intégration (`#[ignore]`) rejouent les parcours réels contre un serveur, un fournisseur
OpenID Connect et un contrôleur de domaine.

## Principes

- Aucun secret en clair hors du poste ; toute nouvelle donnée chiffrée a ses **données
  associées** propres (voir `aad.rs` et `web/js/aad.js`, à garder identiques).
- Les constantes de protocole `verrou:v1`, `verrou/v1`, `verrou-v1` ne doivent **jamais**
  changer (compatibilité des coffres existants).
- Le contenu utilisateur n'est jamais inséré en HTML (`textContent` uniquement), CSP stricte.
- Messages d'erreur et interface en français, sans détail technique pour l'utilisateur final.
