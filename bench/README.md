# Banc de charge et semis de Locksy

Ce dossier mesure le serveur Locksy tel qu'il est livré : mêmes limites que
`deploiement/docker-compose.onprem.yml`, deux cœurs réservés, un injecteur sur
d'autres cœurs. Il remplit aussi des instances avec des jeux de données
réalistes, chiffrés par le **vrai** code client (`web/js/vault.js` et
`locksy.wasm`), puis vérifie que tout se relit.

Contenu :

| Élément | Rôle |
|---|---|
| `docker-compose.bench.yml` | serveur `locksy` (profils REF-PROD et REF-1G) et injecteur `k6` (profil `tools`) |
| `.env.example` | variables du banc, à copier en `bench/.env` pour les modifier |
| `scripts/bench-up.sh` | construit l'image si besoin, démarre le serveur, lance `preflight.sh` |
| `scripts/preflight.sh` | contrôles préalables d'une passe |
| `scripts/seed.sh` | semis d'un jeu, vérification, instantané |
| `scripts/snapshot.sh` | instantanés `save` et `restore` d'un jeu |
| `scripts/sample-stats.sh` | relevé CPU, mémoire, PID, OOM et redémarrages, en CSV |
| `seed/seed.mjs`, `seed/verify.mjs` | semis et vérification (Node 20 ou plus, sans dépendance) |
| `seed/datasets.mjs` | définition des jeux S, M, L et E2E |
| `seed/shim.mjs`, `seed/worker.mjs`, `seed/common.mjs` | environnement « navigateur » sous Node, fils de travail, outils communs |

Les micro-benchmarks du noyau (criterion, pont WebAssembly) sont décrits plus bas
(« Micro-benchmarks du noyau ») ; les scénarios k6, leurs seuils et la lecture des rapports
sont dans [`bench/k6/README.md`](k6/README.md).

## Prérequis

- Docker Desktop (WSL2) ou Docker Engine, avec **8 processeurs** et **4 Go** de
  mémoire pour Docker. Avec 6 ou 7 processeurs, le banc fonctionne mais les
  mesures ne sont qu'indicatives ; en dessous de 6, `preflight.sh` refuse la passe.
- Node 20 ou plus (le semis tourne aussi dans l'image
  `mcr.microsoft.com/playwright:v1.49.1-noble`, qui embarque Node 22).
- Git Bash sous Windows (ou un bash Linux), avec `curl`.
- Toutes les commandes se lancent depuis la racine du dépôt (`verrou/`).
  Les scripts posent eux-mêmes `MSYS_NO_PATHCONV=1` ; exportez-le aussi pour
  vos commandes `docker` manuelles sous Git Bash.

## Topologie

```
 poste (Node)                         Docker : réseau « bench » ${BENCH_SUBNET} (172.30.0.0/24)
 ┌──────────────────────┐ 127.0.0.1:<port aléatoire> ┌─────────────────────────────────────────┐
 │ bench/seed/seed.mjs  │─────────────────────────▶│ locksy ${BENCH_SERVER_IP} (172.30.0.10)  │
 │ vrai client + wasm   │  X-Forwarded-For         │ cœurs ${SERVER_CPUSET} (0,1), 2 vCPU      │
 └──────────────────────┘  par compte              │ 512 Mo (REF-PROD) ou 1 Go (REF-1G)       │
                                                   │ TRUST_PROXY, TRUSTED_PROXIES = sous-réseau│
 sample-stats.sh ── docker stats / inspect ──────▶│                                          │
                                                   │ k6 (profil tools), cœurs ${INJECTOR_CPUSET}│
                                                   │ (4-7) ──── X-Forwarded-For par VU ────▶  │
                                                   └─────────────────────────────────────────┘
```

Le banc s'adresse directement au serveur, sans proxy : il joue lui-même le
rôle du proxy de confiance. Chaque client virtuel annonce sa propre adresse
par `X-Forwarded-For`, sinon les limites par adresse IP (prelogin 60/min,
connexion 100/10 min, inscription 10/h) ne laisseraient mesurer que des 429.
Les connexions venues du poste par le port publié arrivent par la passerelle
du réseau du banc, qui fait partie du sous-réseau de confiance : le semis
depuis le poste peut donc lui aussi fixer son adresse. `preflight.sh` le vérifie.

Le port hôte est **tiré au sort** à chaque démarrage (aucun port fixe, plusieurs
bancs peuvent coexister). Il se lit par :

```bash
docker compose -p locksy-bench -f bench/docker-compose.bench.yml port locksy 8743
# 127.0.0.1:62604
```

Depuis le réseau du banc (k6, conteneur Playwright), l'adresse est `http://locksy:8743`.

## Variables et profils

Les valeurs par défaut sont celles de `.env.example`. Pour les changer, copiez
ce fichier en `bench/.env` (ignoré par git) ou exportez la variable : une
variable d'environnement l'emporte sur `bench/.env`, comme dans docker compose.

| Variable | Défaut | Rôle |
|---|---|---|
| `BENCH_PROJECT` | `locksy-bench` | nom du projet docker compose ; option `-p` de chaque script |
| `LOCKSY_IMAGE` | `locksy-bench:local` | image mesurée ; construite par `bench-up.sh` si absente |
| `LOCKSY_MEM` | `512m` | mémoire du serveur : `512m` = **REF-PROD**, `1g` = **REF-1G** |
| `BENCH_SUBNET` | `172.30.0.0/24` | réseau du banc, aussi liste des proxys de confiance |
| `BENCH_SERVER_IP` | `172.30.0.10` | adresse fixe du serveur, dans `BENCH_SUBNET` |
| `SERVER_CPUSET` | `0,1` | cœurs du serveur |
| `INJECTOR_CPUSET` | `4-7` | cœurs de l'injecteur (k6, Playwright) |
| `LOCKSY_SETUP_TOKEN` | `banc-jeton-installation-0123456789` | jeton d'installation (valeur de test) |
| `LOCKSY_ENV` | `production` | `test` expose `/api/test/counters` |
| `BUSYBOX_IMAGE` | `busybox:1.37.0` | conteneur utilitaire de la restauration |

Profils :

| Profil | Paramètres | Usage |
|---|---|---|
| **REF-PROD** | `cpus: 2`, `cpuset: 0,1`, `mem_limit` et `memswap_limit` 512 Mo, `pids_limit: 128`, `read_only`, `cap_drop: ALL`, `no-new-privileges` | seuils bloquants : on mesure ce qu'on livre |
| **REF-1G** | idem avec 1 Go | dimensionnement si REF-PROD échoue sur les gros jeux |
| **INJECTEUR** | cœurs `4-7` | ne partage jamais un cœur du serveur ; mesure invalide si son CPU dépasse 70 % |

`bash bench/scripts/bench-up.sh --profile REF-1G` fixe `LOCKSY_MEM=1g` et
recrée le conteneur ; le volume de données est conservé.

## Recette (testée sur ce poste)

Poste de référence : 8 processeurs et 3,7 Gio de mémoire vus par Docker
Desktop (WSL2), Node 26. Les durées ci-dessous ont été mesurées alors que
d'autres compilations tournaient sur le poste : elles sont **indicatives**.

```bash
cd verrou

# 1. Image et serveur, puis contrôles préalables (code 0, 1 ou 2, voir plus bas).
#    L'image est construite seulement si elle manque (ou avec --rebuild) ; le
#    Dockerfile exécute les tests cargo du noyau et du serveur : plusieurs minutes.
bash bench/scripts/bench-up.sh -p locksy-bench
#    Pour mesurer une image existante : LOCKSY_IMAGE=locksy:1.0.0 bash bench/scripts/bench-up.sh …

# 2. Semis du jeu S sur l'instance neuve : extraction de locksy.wasm, seed.mjs,
#    verify.mjs, puis instantané dans bench/snapshots/S/.
bash bench/scripts/seed.sh -p locksy-bench S

# 3. Avant chaque passe : retour à l'état exact de l'instantané.
bash bench/scripts/snapshot.sh -p locksy-bench restore S

# 4. Vérification à la demande (le port a changé au redémarrage : on le relit).
base="http://$(docker compose -p locksy-bench -f bench/docker-compose.bench.yml port locksy 8743)"
node bench/seed/verify.mjs --dataset S --base "$base" --out bench/seed/out/S

# 5. Fin : conteneurs, réseau ET volume de données supprimés.
docker compose -p locksy-bench -f bench/docker-compose.bench.yml down -v
```

Mesures de la validation de bout en bout (jeu S, profil REF-PROD, image
existante du chantier iso-prod passée par `LOCKSY_IMAGE` : la construction
par le Dockerfile n'est pas comprise dans ces durées) :

| Étape | Durée |
|---|---|
| `bench-up.sh` (image présente) : démarrage, santé, `preflight.sh` | 56 s |
| `seed.sh S` : semis | 33 à 42 s (dont environ 11 s d'invitations) |
| `seed.sh S` : vérification | 17 à 22 s |
| `seed.sh S` : instantané | 15 à 17 s |
| `snapshot.sh restore S`, serveur en marche (arrêt gracieux compris) | 50 à 63 s |
| `snapshot.sh restore S` après `down -v` (volume neuf) | 14 s |
| `verify.mjs` après restauration | 11 à 31 s |

Résultat de `preflight.sh` lors de cette validation : tous les contrôles
verts, sauf un avertissement « autres conteneurs actifs » (compilations
d'autres chantiers), donc code 1, mesures indicatives.

## Contrôles préalables (`preflight.sh`)

| Contrôle | En échec |
|---|---|
| processeurs de Docker : 8 et plus | 6 ou 7 : avertissement ; moins de 6 : bloquant |
| mémoire de Docker : 3,7 Gio et plus (4 Go déclarés) | avertissement |
| image `$LOCKSY_IMAGE` présente | bloquant |
| cœurs du serveur et de l'injecteur existants et disjoints | bloquant ; un serveur sans exactement 2 cœurs : avertissement |
| `BENCH_SERVER_IP` dans `BENCH_SUBNET`, sous-réseau sans chevauchement avec un autre réseau Docker | bloquant |
| serveur démarré et en bonne santé | bloquant |
| limites réellement appliquées au conteneur (cœurs, 2 vCPU, mémoire de REF-PROD ou de REF-1G, 128 PID, racine en lecture seule) | bloquant ; profil en service différent de `LOCKSY_MEM` : avertissement |
| processeurs vus dans le conteneur (`nproc`) = cœurs du serveur : la porte Argon2 en dépend | avertissement |
| `/api/health` joignable par le port publié | bloquant |
| **X-Forwarded-For** : 60 `prelogin` acceptés depuis une adresse, le 61e refusé en 429, l'adresse suivante acceptée | bloquant |
| aucun autre conteneur actif | avertissement |

Codes de sortie :

- **0** : conforme, les mesures sont valables ;
- **1** : avertissements, le banc fonctionne mais les mesures sont indicatives ;
- **2** : bloquant, ne lancez pas de passe (ou usage invalide).

Les deux adresses de contrôle sont tirées au hasard (`10.9.x.y` et `10.8.x.y`) :
deux contrôles successifs dans la même minute restent valables.

## Jeux de données

| Jeu | Comptes | Contenu | Usage |
|---|---|---|---|
| **S** | 50 (1 propriétaire, 2 administrateurs) | 200 éléments personnels chacun ; 5 coffres partagés de 100 éléments, 10 membres chacun ; 15 000 éléments déchiffrés à la vérification | smoke, CI nocturne |
| **M** | 500 (1 propriétaire, 5 administrateurs) | 150 éléments personnels ; 10 coffres d'équipe de 425 éléments, environ 100 membres chacun, chaque compte en rejoint 2 : **1 000 éléments visibles** par compte ; 4 pièces jointes de 50 Ko à 1 Mo par compte (2 000) | scénarios 03, 05, 07, 08, 09 |
| **L** | 520 | jeu M, plus 20 comptes « équipe IT » et un coffre « Infrastructure IT » de **10 000 éléments** partagé entre eux, avec 200 pièces jointes de 10 Mo envoyées par ses membres | scénarios 04, 06, restauration |
| **E2E** | 6 nommés | `proprietaire@`, `admin@`, `alice@`, `bob@`, `carole@`, `david@e2e.test` (voir plus bas) | Playwright |

Comptes de charge : `proprietaire@banc.test`, puis `utilisateur-0001@banc.test`
à `utilisateur-0499@banc.test`, et `it-01@banc.test` à `it-20@banc.test` pour L.
Les éléments couvrent les cinq types de l'interface (identifiant, note, carte,
identité, clé SSH), avec étiquettes, favoris, champs personnalisés, TOTP,
quelques mots de passe faibles et réutilisés. Leur contenu est reproductible
(générateur à graine) ; seuls les mots de passe des comptes changent à chaque semis.

Jeu **E2E** : `alice@e2e.test` a 40 éléments de tous types, dont 3 mots de
passe faibles différents et 2 réutilisés (écran Santé), et 2 pièces jointes ;
elle gère le coffre « Équipe » (10 éléments), où `bob@` est éditeur et
`carole@` lecteur. `david@e2e.test` a la double authentification active : son
secret est dans `users.json` (`totp_secret`). La clé de récupération de chaque
compte, dont celle du propriétaire, est conservée (`recovery`).

Écart assumé avec l'audit 05 (§3.4) : le jeu M y annonce des coffres de
50 membres ET 1 000 éléments visibles par compte, ce qui est incompatible
avec 500 comptes. Le banc retient les 1 000 éléments visibles (taille de la
synchronisation du scénario 03) : chaque coffre d'équipe a donc environ 100 membres.

### Dérivation de clé (KDF)

Le semis utilise **les paramètres de l'application** (Argon2id 64 Mio, t = 3,
tirés par `new_kdf`) : `vault.js` ne permet pas de les changer, et le banc ne
contourne pas le vrai client. Sur ce poste, une dérivation prend environ
0,3 s par fil sous Node ; chaque compte en coûte une au semis et une à la
vérification. Le coût côté serveur ne change pas (re-hachage en 19 Mio, t = 2).
La porte Argon2 du serveur (2 calculs simultanés en REF-PROD) borne le débit
des inscriptions : le semis réessaie poliment un 503 `server_busy`.

### Durées et espace disque

| Jeu | Semis | Vérification | Base | Instantané |
|---|---|---|---|---|
| S | 33 à 42 s (mesuré) | 17 à 22 s | 12 Mo | 13 Mo |
| M sans pièces jointes (`--no-attachments`) | 7 min (mesuré) | 5 min 30 s | 92 Mo | 93 Mo (67 s) |
| L sans pièces jointes | estimation : 9 min | estimation : 7 min | environ 110 Mo | environ 110 Mo |
| M complet (2 000 pièces jointes, 1 054 Mio) | 309 s (mesuré, 19/11) | 233 s | 1,5 Go | 1,5 Go (134 s) |
| L complet | non mesuré (au moins 3 fois M) | | environ 5 Go | environ 5 Go |

Pendant le semis et la vérification de M sans pièces jointes (REF-PROD,
4 fils), `sample-stats.sh` a relevé : mémoire maximale 340 Mio, 16 PID au plus,
CPU moyen 50 % (sur 200 %).

> **Pièces jointes : historique.** Le blocage décrit ci-dessous est corrigé par
> l'index couvrant `idx_attachments_quota` (schéma v3) : le semis M complet prend
> désormais 5 min environ. Le texte reste pour mémoire. Le contrôle
> de quota exécute `SUM(size)` sur toute la table `attachments`, où la
> colonne `size` est rangée APRÈS le contenu chiffré `data` : chaque envoi relit
> donc toutes les pièces jointes déjà stockées, sous le verrou d'écriture. Le
> coût d'un envoi croît avec le volume total : mesuré sur le jeu M, le semis
> passe d'environ 60 comptes par minute au départ à 4 comptes par minute après
> 500 Mo de pièces jointes (150 comptes sur 500 en 13 min), soit plusieurs
> heures pour M et bien davantage pour L. Pendant ce semis, la mémoire du
> serveur a atteint **506,6 Mio sur 512** (profil REF-PROD), au bord de
> l'arrêt pour manque de mémoire. Le correctif (index couvrant
> `attachments(created_by, size)`) est en place depuis le schéma v3.

**Attention à l'espace disque** : les pièces jointes sont stockées dans la base
(en base64, soit +33 %). Le jeu L occupe environ 5 Go dans le volume Docker,
autant dans `bench/snapshots/L/`, et la sauvegarde à chaud écrit temporairement
une copie de plus dans le volume. Prévoyez **15 Go libres** avant un semis L,
et supprimez les instantanés inutiles.

### Sorties

`bench/seed/out/<jeu>/` (ignoré par git) :

- `manifest.json` : jeu, version du serveur, paramètres KDF, totaux (comptes,
  coffres, éléments, pièces jointes, éléments visibles par compte), durées des
  étapes, puis pour chaque compte ses coffres visibles et pour chaque coffre
  son créateur, ses membres, son nombre d'éléments, l'empreinte SHA-256 de ses
  clairs triés et ses pièces jointes (nom, taille, SHA-256) ;
- `users.json` : pour chaque compte `{email, name, password, auth_key_b64, id,
  role, xff, collections[], sample_item_ids[], recovery, totp_secret?}`.
  `auth_key_b64` est la preuve d'authentification envoyée par le client à
  l'inscription : un injecteur se connecte avec elle sans recalculer Argon2.

`users.json` contient des **identifiants de test** : ne le commitez jamais, ne
le copiez pas hors du poste, ne réutilisez jamais ces valeurs ailleurs.

## Semis et vérification à la main

```bash
node bench/seed/seed.mjs --dataset S|M|L|E2E --base <url> --out bench/seed/out/<jeu>/ \
  [--wasm bench/.cache/locksy.wasm | --wasm-url <url>] [--workers N] [--xff-prefix 10.200] \
  [--setup-token <jeton>] [--no-attachments]
node bench/seed/verify.mjs --dataset <jeu> --base <url> --out bench/seed/out/<jeu>/ [--workers N]
```

- L'instance doit être **neuve** (aucun compte) : sinon `seed.mjs` s'arrête.
- Sans `--wasm` ni `--wasm-url`, le module est lu sur le serveur
  (`<base>/locksy.wasm`). `seed.sh` l'extrait plutôt de l'image en service
  (`docker create`, `docker cp /app/web/locksy.wasm`, `docker rm`) vers
  `bench/.cache/locksy.wasm` : client et serveur ont ainsi la même version.
- `--workers` : un fil `worker_threads` par compte en cours (défaut : la
  moitié des processeurs, 6 au plus). Chaque fil a son propre module `vault.js`.
- Chaque compte a son adresse `X-Forwarded-For` (`10.200.0.1`, `10.200.0.2`…).
- `--no-attachments` (aussi accepté par `seed.sh`) retire toutes les pièces
  jointes du jeu ; le manifeste l'indique (`attachments_skipped`) et
  `verify.mjs` n'en attend alors aucune.
- Étapes : propriétaire par le jeton d'installation ; invitations créées par
  le propriétaire ; inscription des autres comptes par invitation, avec leurs
  éléments (`importItems`, par envois de 2 000 au plus) et leurs pièces
  jointes ; coffres partagés (`createCollection`, éléments, `addMember`) ;
  pièces jointes des coffres partagés, réparties entre leurs membres éditeurs.
- `verify.mjs` reconnecte chaque compte par le chemin de l'interface
  (prelogin, Argon2, code TOTP si besoin), synchronise, déchiffre tout, et
  compare au manifeste : rôle, coffres visibles, nombre d'éléments, empreinte
  des clairs ; les pièces jointes d'un coffre sont téléchargées et comparées
  par son créateur ; les totaux du serveur (`/api/admin/stats`) aussi.
  Code 0 si tout correspond, 1 sinon (écarts listés), 2 pour un usage invalide.
- `npm --prefix bench run seed -- …` et `npm --prefix bench run verify -- …`
  font la même chose (chemins alors relatifs à `bench/`).

Depuis le réseau du banc, dans l'image Playwright (commande testée) :

```bash
docker run --rm --network locksy-bench_bench --cpuset-cpus 4-7 \
  -v "$PWD:/work:ro" -w /work mcr.microsoft.com/playwright:v1.49.1-noble \
  bash -c "node bench/seed/seed.mjs --dataset E2E --base http://locksy:8743 --out /tmp/out/E2E \
             --setup-token banc-jeton-installation-0123456789 \
        && node bench/seed/verify.mjs --dataset E2E --base http://locksy:8743 --out /tmp/out/E2E"
```

(sous Git Bash, remplacez `$PWD` par le chemin Windows du dépôt, par exemple
`C:/Users/…/verrou`).

## Instantanés (`snapshot.sh`)

```bash
bash bench/scripts/snapshot.sh -p locksy-bench save S      # serveur en marche
bash bench/scripts/snapshot.sh -p locksy-bench restore S   # serveur en marche ou supprimé
```

- `save` : sauvegarde à chaud **vérifiée** par le serveur
  (`locksy-server backup /data/instantane.db --with-key`, contrôle d'intégrité
  compris), copiée dans `bench/snapshots/<jeu>/` : `locksy.db`, `server.key`,
  `manifest.json`, `users.json`, `SHA256SUMS` et `instantane.json` (image,
  date, taille). La copie de travail est effacée du volume.
- `restore` : contrôle des empreintes, arrêt du serveur, remplacement de
  **tout** le contenu de `/data` par un conteneur `busybox` (flux tar, sans
  montage de chemin Windows), redémarrage et attente de la bonne santé. Le
  conteneur et le volume sont recréés s'ils ont été supprimés. `manifest.json`
  et `users.json` reviennent dans `bench/seed/out/<jeu>/` (un semis ultérieur
  a pu les remplacer).
- La clé serveur fait partie de l'instantané : sans elle, les secrets chiffrés
  par le serveur (2FA, configuration) seraient illisibles.

## Échantillonneur (`sample-stats.sh`)

```bash
bash bench/scripts/sample-stats.sh locksy-bench-locksy-1 bench/results/<passe>/stats.csv &
echantillonneur=$!
# … passe de charge …
kill "$echantillonneur"; wait "$echantillonneur"
```

- Colonnes : `horodatage` (UTC), `epoch_ms`, `cpu_pct` (200 = 2 vCPU saturés),
  `mem_mio`, `mem_limite_mio`, `pids`, `oom_killed`, `redemarrages`, `etat`.
- Un seul processus `docker stats` en flux continu (environ une mesure par
  seconde, jusqu'à deux secondes sur un Docker Desktop chargé : `epoch_ms`
  fait foi) ; `docker inspect` relu toutes les 2 s pour l'état, `OOMKilled`
  et le nombre de redémarrages. Un conteneur arrêté donne des lignes vides
  avec son état, et le relevé reprend à son redémarrage.
- Arrêt par `kill` (SIGTERM) ou Ctrl+C au premier plan. Un script lancé en
  arrière-plan par un autre script ignore SIGINT (règle de bash) : `kill -INT`
  serait sans effet.

## Injecteur k6

Le service `k6` (`grafana/k6:1.0.0`, profil `tools`, cœurs `INJECTOR_CPUSET`)
ne démarre jamais avec `up`. Il monte `bench/k6` en `/bench/k6` (lecture
seule), `bench/seed/out` en `/bench/out` (lecture seule, `users.json` des jeux)
et `bench/results` en `/bench/results`, et joint le serveur à
`http://locksy:8743` (`BASE_URL`).

Le passage normal se lance par `bench/scripts/run.sh` (restauration de l'instantané,
préflight, échantillonneur, rapport `rapport.md`, code de sortie = verdict) et la campagne
complète par `bench/scripts/campaign.sh` : voir [`bench/k6/README.md`](k6/README.md).
À la main :

```bash
docker compose -p locksy-bench -f bench/docker-compose.bench.yml run --rm \
  -e DATASET=S k6 run /bench/k6/scenarios/00-smoke.js
```

## Micro-benchmarks du noyau (criterion et pont WebAssembly)

| Fichier | Rôle |
|---|---|
| `crates/locksy-core/benches/core.rs` | 17 mesures criterion (KDF, AEAD, scellement, enveloppe de clé, TOTP, générateur, robustesse) |
| `baselines/criterion-ref.json` | référence mesurée sur 2 vCPU (médianes, plafonds et plancher absolus, section `wasm`) |
| `scripts/criterion-gate.mjs` | porte : échec si une médiane régresse de plus de 10 %, dépasse son plafond ou passe sous son plancher |
| `wasm/bench.mjs` | coût d'un appel au module WebAssembly sous Node et décision `decrypt_many` |

Recette (Git Bash, racine du dépôt). Le banc ne se compile pas en natif sous
Windows (`dlltool` absent) : il tourne dans `locksy-toolchain`, limité à 2 vCPU.

```bash
# 1. Mesure (environ 5 min) puis copie des résultats dans bench/.cache/criterion/.
MSYS_NO_PATHCONV=1 docker run --rm --cpus 2 --cpuset-cpus 2,3 -v "$PWD:/src"   -v locksy-reg:/usr/local/cargo/registry -v locksy-tgt-srv:/src/target -w /src locksy-toolchain   bash -c "cargo bench -p locksy-core --bench core -- --noplot            && mkdir -p bench/.cache/criterion && cp -r target/criterion/. bench/.cache/criterion/"

# 2. Porte (code 0 vert, 1 échec). Sur un runner partagé : --tolerance 20.
node bench/scripts/criterion-gate.mjs
node bench/scripts/criterion-gate.mjs --self-test     # contrôle de la porte elle-même

# 3. Pont WebAssembly (réutilise ou produit bench/.cache/locksy.wasm).
node bench/wasm/bench.mjs                              # affichage seul
```

`--update` (sur l'une ou l'autre commande) réécrit la référence : seulement
après une décision explicite, sur la machine de référence. Les mesures varient
de quelques pour cent d'une passe à l'autre ; le plancher de 150 ms de la
dérivation client dépend de la machine (172 ms mesurées ici).

## Règles

- **On ne réutilise jamais un volume de charge pour les E2E** : les scénarios
  k6 créent des éléments factices mais bien formés que l'interface ne sait
  pas déchiffrer. Les E2E repartent d'une instance neuve ou de l'instantané `E2E`.
- Chaque passe repart d'un instantané (`restore`) : résultats reproductibles.
- Un projet compose par usage (`-p`) ; aucun port fixe sur l'hôte.
- Serveur et injecteur ne partagent jamais un cœur ; aucune autre charge
  pendant une mesure (navigateur fermé, compilations arrêtées, antivirus
  suspendu sur le dossier). Sinon, les chiffres sont indicatifs : dites-le.

## Nettoyage

```bash
docker compose -p locksy-bench -f bench/docker-compose.bench.yml down -v   # conteneurs, réseau, volume
rm -rf bench/snapshots/<jeu> bench/seed/out/<jeu>                          # instantané et comptes de test
rm -rf bench/.cache                                                        # module WebAssembly extrait
docker image rm locksy-bench:local                                         # image, si elle n'est plus utile
```

## Dépannage

| Symptôme | Cause et remède |
|---|---|
| `preflight.sh` : X-Forwarded-For non pris en compte | la connexion n'arrive pas depuis le sous-réseau de confiance : vérifiez `BENCH_SUBNET` et le `LOCKSY_TRUSTED_PROXIES` du conteneur (`docker inspect`) |
| sous-réseau en conflit | changez `BENCH_SUBNET` **et** `BENCH_SERVER_IP` dans `bench/.env`, puis `down` et `bench-up.sh` |
| `seed.mjs` : « Le serveur contient déjà des comptes » | semez sur une instance neuve : `down -v`, puis `bench-up.sh` |
| 429 pendant un semis | `X-Forwarded-For` ignoré : lancez `preflight.sh` |
| le port a changé | normal après chaque redémarrage : relisez-le avec `docker compose … port locksy 8743` |
| `bench-up.sh` : échec de construction | le Dockerfile exécute les tests cargo : corrigez-les, ou mesurez une image existante avec `LOCKSY_IMAGE` |
| `verify.mjs` signale des écarts | l'instance ne correspond pas au manifeste : restaurez l'instantané du jeu, ou semez de nouveau |
