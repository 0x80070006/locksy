# Tests de sécurité automatisés (lot Q4)

Ce dossier vérifie, contre l'image livrée, les critères de sécurité G8 à G13
du cahier (§6.2 et §6.7) : en-têtes et CSP, autorisations, limites de débit,
anti-énumération, sessions, entrées hostiles, zero-knowledge, installation,
puis les scans ZAP, Trivy, `cargo audit` et `cargo deny`.

La matrice d'autorisation exhaustive est un test Rust :
`crates/locksy-server/src/tests/authz_matrix.rs`. Elle énumère les routes
depuis les sources du routeur (refus par défaut, constat #54) et joue la
matrice IDOR générée (15 routes, 8 acteurs). Elle tourne avec
`cargo test -p locksy-server tests::authz_matrix`.

## Recette

Depuis la racine du dépôt (Git Bash, Docker) :

```bash
# Tests Playwright et analyse de la base
bash e2e/security/run.sh -p q4-sec

# Scans seuls (sans les tests)
bash e2e/security/run.sh -p q4-sec --sans-tests --zap --trivy --cargo

# Un seul fichier, ou un filtre de Playwright
bash e2e/security/run.sh -p q4-sec -- limites.spec.ts
bash e2e/security/run.sh -p q4-sec -- -g "slowloris"
```

`run.sh` démarre l'environnement de test de base (`e2e/docker-compose.e2e.yml`)
plus la surcouche `docker-compose.securite.yml`. Il lance ensuite Playwright
avec `-c security/playwright.config.ts`, puis `zk-analyse.mjs` et les scans
demandés. Il finit toujours par `down -v`. Image testée :
`locksy-e2e-server:fast`, telle quelle. Le script ne la reconstruit jamais :
la reconstruire relève de l'intégrateur (voir `e2e/README.md`).

Code de sortie : celui de Playwright, sinon celui de l'analyse de la base,
sinon celui du premier scan en échec.

## Services

| Service | Adresse (réseau compose) | Rôle |
|---|---|---|
| `locksy` | `http://locksy:8743` | serveur de test amorcé par la fixture `org`, derrière un proxy de confiance (une adresse X-Forwarded-For par test) |
| `locksy-fresh` | `http://locksy-fresh:8743` | serveur neuf du fichier de base, inutilisé ici |
| `locksy-direct` | `http://locksy-direct:8743` | production SANS proxy de confiance : X-Forwarded-For ignoré, pas de HSTS en HTTP, `/api/test/*` absent, `LOCKSY_RATELIMIT_LOGIN_IP=5`, `LOCKSY_HEADER_TIMEOUT_SECS=3` |
| `locksy-vierge` | `http://locksy-vierge:8743` | serveur neuf réservé à `installation.spec.ts` |

Aucun port n'est publié sur l'hôte. Chaque service est borné à 2 processeurs
et 2 Go. Le lanceur reçoit `SECURITY_DIRECT_URL` et `SECURITY_VIERGE_URL`.
Sans eux, les tests qui en dépendent sont sautés, raison en clair.

## Spécifications

| Fichier | Projet | Ce qui est vérifié |
|---|---|---|
| `entetes.spec.ts` | securite-api | en-têtes EXACTS de `main.rs` (lus dans la source) sur `/`, `/share.html`, `/js/app.js`, `/locksy.wasm`, `/api/health`, un 401 et deux 404 ; `no-store` pour l'API, `no-cache` pour l'interface ; pas de HSTS en HTTP sans proxy, mais HSTS derrière un proxy TLS déclaré ; aucun en-tête `Server` avec une version ; aucune réponse CORS à `https://evil.test` ; `/api/test/counters` en 404 en production |
| `csp.spec.ts` | securite-chromium | script en ligne, gestionnaire en attribut, `eval`, `new Function` et style en ligne, injectés dans la vraie page : refusés, avec `securitypolicyviolation` ; page normale sans violation ; règles R1 sur `web/js` et `extension/src` (0 ligne) et pages HTML sans script ni style en ligne |
| `limites.spec.ts` | securite-api | N essais passent, le suivant reçoit 429 `rate_limited` avec `Retry-After` et `retry_after` égaux et un message en français. Couvre : pré-connexion, connexion (paire, e-mail, adresse), inscription, récupération (adresse, compte), lien, invitation, `sso/start`, `sso/redeem`, et un /64 IPv6. Les plafonds sont LUS dans `config.rs`, `sso.rs`, `auth.rs` et le registre. Sur `locksy-direct` : plafond réglé à 5, X-Forwarded-For falsifié sans effet, et une réussite ne remet pas le compteur à zéro |
| `idor.spec.ts` | securite-api | élément, pièce jointe et lien créés par l'interface ; un étranger et un administrateur non membre reçoivent le 404 uniforme (code et message d'un identifiant inexistant), sans effet ; un compte `user` est refusé sur `/api/admin/*`, une session sur `/scim/v2` |
| `enumeration.spec.ts` | securite-api | pré-connexion d'un e-mail inconnu : mêmes champs et paramètres qu'un vrai compte, stable, propre à l'adresse ; connexion, récupération et invitation : même code et même message ; temps (voir plus bas) |
| `sessions.spec.ts` | securite-api | jeton absent, `Bearer null`, vide, inconnu, de 129 caractères ou de 8 Kio : 401, jamais 500 ; déconnexion, révocation par le titulaire et par un administrateur ; compte désactivé ; changement du mot de passe maître qui ferme les autres sessions |
| `entrees.spec.ts` | securite-api | JSON invalide, mauvais type de contenu, types inattendus, profondeur extrême : 400, 413, 415 ou 422, jamais 500 ; plus de 16 Mio sur l'API et 21 Mo sur les pièces jointes, plus de 1 Mio sur `/scim/v2` : 413 ; chiffrés mal formés : 400 ; identifiants mal formés : 400, 403 ou 404 ; Unicode extrême dans un nom ; slowloris |
| `zero-knowledge.spec.ts` | securite-chromium | un compte dédié crée des contenus distinctifs `ZK-<aléa>` : élément, note, coffre partagé, pièce jointe, lien, préférences. L'API ne renvoie que des chiffrés, et le relevé des clairs est écrit dans `e2e/.state/<cle>/zk-clairs.json` |
| `installation.spec.ts` | securite-chromium | serveur vierge : inscription refusée sans jeton et avec un faux jeton ; 20 faux jetons bloquent l'installation, même avec le bon jeton ; après la création du propriétaire par l'interface, le jeton ne sert plus |

`zk-analyse.mjs` tourne après Playwright et avant `down -v`. Il fait une
sauvegarde à chaud dans le conteneur (`locksy-server backup /tmp/zk.db
--force`), puis copie la sauvegarde, `/data/locksy.db` et son WAL par
`exec cat`, car `docker cp` ne lit pas un tmpfs. Il cherche ensuite chaque
clair en UTF-8, ainsi que le jeton de session, le mot de passe maître et la
clé du lien. Attendu : 0 occurrence. Un témoin admis (l'e-mail du compte)
doit, lui, être trouvé, sinon l'analyse est déclarée invalide. Clairs admis :
e-mails et noms des comptes, journal d'audit.

## Mesures de temps (anti-énumération)

Chaque mesure entrelace les deux cas, en alternant l'ordre d'un essai à
l'autre. Les 20 essais de chauffe sont écartés, puis 200 essais de chaque
cas sont mesurés. On retire 10 % d'extrêmes (5 % de chaque côté). Il faut un
écart des médianes inférieur à 15 ms et un test de Mann-Whitney non
significatif (p > 0,01). U est calculé à la main, avec l'approximation
normale et les corrections des ex aequo et de continuité.

Les comptes réels sont 5 comptes dédiés, avec 44 échecs chacun, sous le
blocage par adresse e-mail (50). La récupération est mesurée sur 20 essais
seulement (ADAPTATION) : le serveur bloque un compte après 5 essais de clé.
Les médianes, U et p sont joints au rapport en annotations (« temps »).

## Scans

| Option | Outil | Attendu | Rapport (`e2e/test-results/<cle>-securite/`) |
|---|---|---|---|
| `--zap` | ZAP baseline 2.15.0, passif, contre `locksy-direct` | règles FAIL de `zap/zap-regles.tsv` (10038, 10020, 10021, 10098) respectées ; 0 alerte de risque élevé ou moyen (`zap/verdict.mjs`) | `zap/zap.json`, `zap/zap.txt` |
| `--trivy` | Trivy 0.57.1 sur `locksy-e2e-server:fast` | 0 vulnérabilité HIGH ou CRITICAL corrigeable | `trivy.txt` (base de Trivy en cache dans `e2e/.state/trivy-cache`) |
| `--cargo` | `cargo audit` 0.23.0 et `cargo deny` 0.21.0 (ADAPTATION : les versions 0.21.2 et 0.18.3 du cahier ne lisent pas les avis RustSec notés en CVSS 4.0), installés dans le volume `locksy-tgt-srv` (`target/outils-securite`) | 0 avis de sécurité, `deny.toml` respecté | `cargo-audit-deny.txt` |

La règle 10035 (HSTS) est ignorée par ZAP : le parcours rapide parle HTTP.
L'en-tête est vérifié par `entetes.spec.ts` derrière un proxy TLS déclaré.

## Durées et sobriété

Mesures du 18/11 sur le poste de développement, avec 2 workers :

- tests : 4 min 10 s de Playwright (56 tests), plus environ 1 minute pour
  démarrer les serveurs et faire `npm ci`. Ce total comprend les 31 s
  d'attente du blocage d'installation et environ 2 minutes de mesures de
  temps ;
- ZAP : environ 2 minutes, plus 1,6 Go d'image au premier lancement ;
- Trivy : environ 1 minute, plus la base de vulnérabilités (environ 60 Mo) au premier lancement ;
- `cargo audit` et `cargo deny` : environ 10 minutes au premier lancement (compilation des deux outils), puis moins d'une minute.

Résultats des mesures de temps du 18/11 (écart des médianes, p) :
connexion 2,0 ms (p = 0,47), récupération 0,5 ms (p = 1,00), invitation
0,7 ms (p = 0,28).

Une seule pile par clé. Elle est supprimée à la fin, même en cas d'échec.

## Lire les rapports

- Rapport Playwright : `e2e/playwright-report/<cle>-securite/index.html`.
  Les annotations portent les médianes (« temps ») et la coupure du slowloris.
  Depuis la correction de Q4-H2 (extracteur JSON de l'API, `invalid_body`),
  un refus en texte brut fait échouer `entrees.spec.ts`.
- Un test annoté `test.fail(true, "Défaut produit, handoff Q4-H<n> : …")`
  documente un défaut connu du produit. Il est vert tant que le défaut existe
  et devient rouge le jour où le produit est corrigé : retirer alors
  l'annotation.
- `zk-analyse.json` : fichiers analysés, nombre de valeurs cherchées, témoin
  et éventuels clairs trouvés.

## Défauts relevés et corrigés (intégration du 19/11)

| Handoff | Correction | Preuve |
|---|---|---|
| Q4-H1 refus par défaut (#54) | couche `security::refus_par_defaut` sur l'API, liste `security::PUBLIQUES` partagée avec la matrice | `security::tests::refus_par_defaut_ferme_une_route_oubliee`, `tests::authz_matrix` |
| Q4-H2 rejets JSON en texte brut | extracteur `error::Json` : 400 ou 415 `invalid_body`, 413 `payload_too_large` | `error::tests::corps_json_refuse_en_erreur_de_l_api`, `entrees.spec.ts` |
| Q4-H3 zlib1g dans l'image | `apt-get upgrade` à la construction (Dockerfile, e2e/tools/Dockerfile.server) | `run.sh --sans-tests --trivy` |
| Q4-H5 versions des outils de la CI | cargo-audit 0.23.0 et cargo-deny 0.21.0 dans `.github/workflows/ci.yml` | job `deny` et `audit` |
| Q4-H6 route d'API inconnue | 404 JSON `not_found` avec `no-store` | `entetes.spec.ts`, `tests_demarrage::route_d_api_inconnue_en_json` |
| Q4-H7 nom invisible | `clean_name` refuse un nom sans caractère visible | `entrees.spec.ts` (« espace sans chasse » : 400), `security::tests::nom_invisible_refuse` |

Reste ouvert : Q4-H4 (montée de rusqlite pour retirer l'exception RUSTSEC-2026-0459 de
`deny.toml`).

## Non couvert ici

- TLS (testssl) : le HTTPS intégré (`LOCKSY_TLS_CERT` et `LOCKSY_TLS_KEY`)
  n'est pas monté dans le parcours rapide. Le contrôle « TLS ≥ 1.2 » du
  critère G13 reste à faire pendant la campagne, avec
  `drwetter/testssl.sh:3.2` contre une instance HTTPS.
- Connexion Active Directory (`ldap/login`) dans l'anti-énumération : il faut
  le profil `ldap` (Samba), que ce lanceur ne démarre pas. Le test est sauté,
  raison en clair.
- `npm audit` de l'extension : relève de la CI de l'extension.
