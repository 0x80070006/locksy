# Tests de bout en bout (Playwright)

Harnais des tests de bout en bout de Locksy : Playwright 1.49.1 dans l'image
officielle `mcr.microsoft.com/playwright:v1.49.1-noble`, sur un réseau Docker
compose avec deux serveurs Locksy construits depuis le dépôt. Aucun port n'est
publié sur le poste : plusieurs exécutions peuvent tourner en même temps.

## Recette en une commande

Depuis la racine du dépôt, dans Git Bash :

```bash
bash e2e/tools/run.sh -p <cle> -- --project=chromium tests/smoke
```

`<cle>` nomme l'exécution (projet compose, image, dossiers de sortie) : prenez
la clé de votre lot, par exemple `-p q3a-e2e` ou `-p l3-ui`. La première
exécution construit l'image serveur (voir « Image serveur ») et télécharge
l'image Playwright (environ 2 Go) si elle manque.

À la fin :

- rapport HTML : `e2e/playwright-report/<cle>/index.html` ;
- traces, captures et pièces jointes des échecs : `e2e/test-results/<cle>/` ;
- l'environnement est supprimé (`down -v`) et le code de sortie est celui de Playwright.

Exemples :

```bash
bash e2e/tools/run.sh -p q3a-e2e -- --project=firefox tests/smoke
bash e2e/tools/run.sh -p q3a-e2e -- --project=mobile
bash e2e/tools/run.sh -p l3-ui -- --project=ui-gallery
bash e2e/tools/run.sh -p l6-id --profile sso --profile ldap -- --project=chromium tests/identite
bash e2e/tools/run.sh -p q3a-e2e --fast-server --keep -- --project=chromium -g "installe"
```

## Options de `run.sh`

| Option | Effet |
|---|---|
| `-p <cle>` | **Obligatoire.** Clé de l'exécution (mise en minuscules ; lettres, chiffres, `-`, `_`). |
| `--profile sso\|ldap\|mail` | Démarre aussi Dex, Samba AD ou mailpit. Répétable. |
| `--rebuild` | Reconstruit l'image serveur de base même si elle existe. |
| `--fast-server` | Image de base construite par `e2e/tools/Dockerfile.server` : release **sans** tests cargo. |
| `--keep` | Laisse l'environnement en place à la fin (la commande de nettoyage est affichée). |
| `-- …` | Tout ce qui suit va à `npx playwright test` (projets, fichiers, `-g`, `--repeat-each`…). |

Variables facultatives : `E2E_WORKERS` (2 par défaut, 4 au plus ; chaque service
compose est borné à 2 processeurs et 2 Go, prenez 1 worker pour Firefox si la
mémoire manque), `EXT_PATH` (extension construite, vue depuis le lanceur).

Extension : construire la **variante de test** (accès aux sites de test et
paramètre `?tab=`, jamais distribuée), puis lancer le projet `extension` :

```bash
node extension/build.mjs --test
E2E_WORKERS=1 EXT_PATH=/work/extension/dist/locksy-extension-test \
  bash e2e/tools/run.sh -p <cle> --fast-server -- --project=extension tests/extension
```

`popup.html?perf=1` pose les repères de performance `locksy:popup:*` (boot,
crypto, restored, synced, rendered, painted), lus par les tests de durée.

## Ce que fait `run.sh`

1. **Image serveur de base.** `locksy-e2e-server:local` est construite par le
   `Dockerfile` du dépôt, tests cargo compris (comme en production), seulement
   si elle manque ou avec `--rebuild`. Le `Dockerfile` n'a **pas** d'option pour
   sauter les tests cargo ; d'où `--fast-server`, qui construit
   `locksy-e2e-server:fast` depuis l'image locale `locksy-toolchain` (release,
   sans tests, cache BuildKit verrouillé, image d'exécution identique). Après
   une modification de `crates/`, relancez avec `--rebuild` (et `--fast-server`
   pour aller vite).
2. **Superposition de `web/`** sur l'image de base (`e2e/tools/Dockerfile.web`,
   quelques secondes, `locksy.wasm` conservé) : une modification de `web/` est
   prise en compte à chaque exécution, sans recompiler. L'image s'appelle
   `locksy-e2e-web:<cle>` et est supprimée à la fin.
3. `docker compose -p <cle> -f e2e/docker-compose.e2e.yml up -d --wait`.
4. `docker compose run --rm runner …` : le service `runner` installe les
   dépendances (`npm ci`, cache dans `e2e/.npm-cache`) dans un volume du projet,
   puis lance Playwright.
5. `down -v` (sauf `--keep`) et suppression de l'image superposée.

## Services

| Service | Adresse vue du lanceur | Rôle |
|---|---|---|
| `locksy` | `http://locksy:8743` (`BASE_URL`) | organisation amorcée par la fixture `org` |
| `locksy-fresh` | `http://locksy-fresh:8743` (`FRESH_URL`) | serveur neuf, pour l'installation (smoke) |
| `dex` (profil `sso`) | `http://dex:5556/dex` | fournisseur OIDC, client `locksy-e2e` |
| `samba` (profil `ldap`) | `ldap://samba:389`, `ldaps://samba:636` | Active Directory `E2E.LOCAL` |
| `mailpit` (profil `mail`) | `http://mailpit:8025`, SMTP `mailpit:1025` | boîte de réception de test |

Les deux serveurs Locksy tournent en lecture seule, `/data` en mémoire (base
neuve à chaque démarrage), avec `LOCKSY_SETUP_TOKEN=e2e-jeton-installation-0123456789`,
`LOCKSY_ENV=test` et la confiance aux proxys des réseaux privés : chaque test
envoie son propre `X-Forwarded-For`, le limiteur ne bloque donc pas la suite.

- **sso** : `fixtures/dex/config.yaml` ; redirection `http://locksy:8743/api/sso/callback` ;
  deux utilisateurs (`fixtures/annuaires.ts`, objet `dex`). `run.sh` passe
  `LOCKSY_SSO_ALLOW_HTTP=true` aux serveurs avec ce profil seulement.
- **ldap** : `nowsci/samba-domain` (conteneur privilégié, exigé par le
  provisionnement d'un contrôleur de domaine). Trois comptes dans
  `fixtures/ldap/comptes.tsv` (dont un désactivé), créés par `fixtures/ldap/start.sh`.
  Liaison : `cn=Administrator,cn=Users,dc=e2e,dc=local` (`fixtures/annuaires.ts`,
  objet `ldap`). Le certificat de l'autorité LDAPS est publié dans le volume
  `ldap-ca`, lisible par le lanceur en `/ldap-ca/ca.pem` (`ldap.caFile`), ou à
  la main : `docker compose -p <cle> -f e2e/docker-compose.e2e.yml exec samba cat /var/lib/samba/private/tls/ca.pem`.
  Le provisionnement prend une à deux minutes.
- **mail** : mailpit accepte tout envoi SMTP ; API `http://mailpit:8025/api/v1/messages`.

## Projets Playwright

| Projet | Fichiers | Remarques |
|---|---|---|
| `chromium` | `tests/**/*.spec.ts` hors `ui/`, `extension/`, `visual/` et `*.api.spec.ts` | presse-papiers autorisé |
| `firefox` | idem | |
| `mobile` | idem, **seulement** les tests marqués `@mobile` | Pixel 7 en 375 × 812 |
| `ui-gallery` | `tests/ui/**/*.spec.ts` | `baseURL` `http://127.0.0.1:4173` (`tools/static.mjs`) |
| `ui-gallery-firefox` | idem | mêmes composants sous Firefox (presse-papiers ouvert par préférences ; test CDP des écouteurs sauté) |
| `api` | `**/*.api.spec.ts` (dont `security/`) | sans navigateur |
| `visual` | `tests/visual/**` | captures de référence |
| `extension` | `tests/extension/**` | fixture `extensionContext` ; ignorés proprement sans `EXT_PATH` |

Réglages communs : `locale` fr-FR, fuseau Europe/Paris, `retries` 0,
`forbidOnly`, trace conservée en cas d'échec, délai de 90 s par test (le
KDF du navigateur prend environ 1 s par connexion).

### Galerie des composants

`tools/static.mjs` sert `web/` sous `/` et `e2e/ui-gallery/` sous `/gallery/`,
avec **les mêmes en-têtes de sécurité que Locksy** (CSP de
`crates/locksy-server/src/main.rs`, `nosniff`…) et les bons types MIME.
`/locksy.wasm` vient de l'image serveur (extrait par `run.sh` dans
`.state/<cle>/`). Le test `tests/smoke/statique.api.spec.ts` compare ces
en-têtes à ceux du vrai serveur : si la CSP de `main.rs` change, il échoue
jusqu'à la mise à jour de `static.mjs`.

La suite `tests/smoke` contient aussi les autocontrôles du harnais :
`gardes.spec.ts` (chaque garde détecte bien ce qu'elle doit détecter),
`axe.spec.ts`, `statique.api.spec.ts` et `profils.api.spec.ts` (services des
profils démarrés, ignorés sinon).

Hors Docker, pour regarder la galerie : `node e2e/tools/static.mjs --port 4173`
puis `http://127.0.0.1:4173/gallery/`.

## Écrire des tests

- Un lot ajoute ses tests dans `e2e/tests/<domaine>/` (par exemple
  `tests/coffre/`, `tests/admin/`, `tests/ui/` pour la galerie).
- Nommage : `<sujet>.spec.ts` en minuscules, mots séparés par des tirets
  (`editeur-element.spec.ts`) ; `<sujet>.api.spec.ts` pour un test sans
  navigateur. Titres de `describe` et de `test` en français.
- Étiquettes : `@mobile` pour qu'un test tourne aussi à 375 px, `@smoke` pour
  la suite de base.
- Sélecteurs : **noms accessibles français** (`getByRole`, `getByLabel`), jamais
  de `data-testid`. Une commande sans nom accessible se corrige dans le produit.
  Les libellés partagés sont dans `fixtures/libelles.ts` (annexe C du cahier).
- Importez toujours les fixtures du harnais :

```ts
import { test, expect } from "../../fixtures/index.ts";

test("ajoute un favori", { tag: "@mobile" }, async ({ loggedIn }) => {
  const page = await loggedIn("user");
  // …
});
```

- Un test qui **modifie** l'état partagé crée ses propres comptes (invitation
  par `apiAs("owner")`), ou travaille sur des noms uniques ; les comptes de
  `org` servent aux lectures et aux parcours sans effet de bord.

## Fixtures

| Fixture | Portée | Contrat |
|---|---|---|
| `cspGuard` | test, **auto** | Aucune violation de CSP (`securitypolicyviolation`, messages « Refused to » / « Content-Security-Policy ») sur les pages de Locksy. Les violations du code évalué par l'outillage (`page.evaluate`, axe-core : source vide ou « debugger eval code ») sont ignorées : sous la CSP de Locksy, le code du produit vient toujours d'un fichier. `cspGuard.violations` : relevé en cours. |
| `consoleGuard` | test, **auto** | Toute `console.error` ou exception non rattrapée fait échouer le test. `consoleGuard.allow(/motif/)` pour une erreur voulue (panne simulée, 4xx attendu). Seul message toléré d'office : l'avertissement de Chromium sur l'en-tête COOP ignoré en HTTP (artefact du réseau de test). `consoleGuard.errors` : relevé en cours. |
| `textGuard` | test, **auto** | Textes visibles et attributs lus (`aria-label`, `title`, `placeholder`, `alt`, titre) contrôlés contre `fixtures/termes-interdits.txt` et `fixtures/anglicismes.txt`, hors `[data-technical]` et hors pages tierces. Option `textGuardMode` : `"report"` (défaut en vague 1, constats joints au rapport en annotations et `textGuard.json`), `"strict"` (échec, à partir de Q3b), `"off"`. `textGuard.check(page)` force un relevé. |
| `xff` | test | `X-Forwarded-For` unique du test (`10.<worker>.<n>.<n>`), posé sur `page`, `context` et `request`. |
| `org` | worker | Organisation amorcée **une fois par exécution** sur `BASE_URL` par l'interface : propriétaire installé par le jeton, `admin@e2e.test` et `alice@e2e.test` invités par l'API puis inscrits par l'interface. Format : `{ baseURL, freshURL, accounts: { owner, admin, user: { email, password, name, id } } }`, écrit dans `e2e/.state/<cle>/org.json`. |
| `loggedIn(role)` | test | Nouvelle page (contexte séparé, gardes actives) connectée par l'interface avec le compte `owner`, `admin` ou `user`. |
| `apiAs(role)` | test | `APIRequestContext` sur `BASE_URL` avec le jeton de session de la page connectée (`Authorization: Bearer …`). |
| `clicks` | test | `clicks.click(l)`, `clicks.fill(l, v)`, `clicks.press(l, k)` comptent les gestes ; `await clicks.measure(async () => …)` renvoie le nombre de gestes du parcours. |
| `extensionContext` | test | Contexte Chromium persistant avec l'extension de `extensionPath` (`EXT_PATH`) ; test ignoré si elle est absente. |

Modules utiles : `fixtures/ui.ts` (installation, inscription, connexion,
déconnexion, ajout d'un élément), `fixtures/axe.ts` (`axe(page)` et
`seriousViolations(page)` : axe-core réglé pour les gardes, préchargement des
feuilles coupé car il résout mal les `@import` et provoque des 404),
`fixtures/totp.ts` (codes RFC 6238),
`fixtures/annuaires.ts` (comptes Dex et Samba), `fixtures/env.ts` (adresses),
`fixtures/fresh.ts` (propriétaire du serveur neuf).

## Exécutions simultanées

Chaque exécution a son projet compose (`-p <cle>`), son image superposée, son
volume `node_modules`, ses dossiers `test-results/<cle>`,
`playwright-report/<cle>` et `.state/<cle>`, et aucun port sur le poste. Deux
agents peuvent donc lancer leurs suites en même temps avec des clés
différentes. L'image de base est partagée : si deux exécutions la construisent
en même temps, la seconde attend le cache BuildKit (verrouillé).

## Nettoyage et espace disque

- Sans `--keep`, tout est supprimé à la fin (conteneurs, réseau, volumes,
  image superposée), même après une interruption (Ctrl+C).
- Avec `--keep`, la commande de suppression est affichée ; l'exécution
  suivante avec la même clé réutilise l'environnement et son `org.json`.
- Restent sur le poste : les images de base `locksy-e2e-server:local` /
  `:fast` (environ 140 Mo chacune), l'image Playwright (environ 3,5 Go une fois
  décompressée), le cache BuildKit de `--fast-server`
  (`docker builder prune --filter id=…` ou `docker builder prune` pour le vider)
  et `e2e/.npm-cache`.
- `e2e/test-results/`, `e2e/playwright-report/`, `e2e/.state/` et
  `e2e/.npm-cache/` sont ignorés par git et peuvent être supprimés à tout moment.

## Limites connues

- La suite smoke installe Locksy sur `locksy-fresh`, une seule fois par
  exécution. Si plusieurs projets tournent ensemble (`--project=chromium
  --project=firefox`), le premier fait l'installation et le test
  d'installation des autres est **ignoré** avec la raison ; connexion et ajout
  d'un élément tournent sur tous. Pour couvrir l'installation sur chaque
  navigateur, lancez un projet par exécution.
- `textGuard` est en mode rapport par défaut ; les specs des écrans de la
  vague 2 le passent en mode strict (`test.use({ textGuardMode: "strict" })`).
- Le profil `ldap` exige un conteneur privilégié et met une à deux minutes à
  démarrer.
- Les comptes de l'organisation dérivent leur clé avec les paramètres KDF par
  défaut (environ 1 s par connexion dans Chromium, un peu plus dans Firefox).
