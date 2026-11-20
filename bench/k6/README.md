# Scénarios de charge k6 (lot Q2)

Ce dossier contient les scénarios de charge du serveur Locksy (cahier §6.3,
audit 05 §3) et leurs seuils. Il complète `bench/README.md` : topologie du
banc, jeux S, M et L, `bench-up.sh`, `seed.sh`, `snapshot.sh` et
`sample-stats.sh` y sont décrits.

| Élément | Rôle |
|---|---|
| `lib/common.js` | adresse du serveur, comptes semés (`users.json`), `X-Forwarded-For` par compte, connexion (code TOTP compris), réessai poli, routes génériques, chiffrés factices |
| `lib/metrics.js` | métriques du banc : 429, 503, autres 5xx, réussite des connexions, taille de `/sync`, 409, base verrouillée, propagation de la politique… |
| `lib/thresholds.js` | **seuils de chaque scénario**, source unique : k6 en tire ses `thresholds`, `report.mjs` les juge |
| `lib/journee.js` | journée type d'un utilisateur (audit 05 §10.1), partagée par 07, 08, 09 et 11 |
| `lib/summary.js` | fin de passe : `summary.json` pour le rapport, bilan court sur la console |
| `scenarios/*.js` | un fichier par scénario |
| `test/report.test.mjs` | tests du jugement et du rapport (`node --test bench/k6/test`) |
| `../scripts/run.sh` | une passe : restauration, preflight, échantillonneur, k6, rapport |
| `../scripts/campaign.sh` | campagne pré-release, avec reprise |
| `../scripts/report.mjs` | `rapport.md` et courbes SVG d'une passe |

## Recette

Toutes les commandes se lancent depuis la racine du dépôt (`verrou/`), sous
Git Bash ou bash.

```bash
# 1. Banc et jeu de données (une fois ; voir bench/README.md).
bash bench/scripts/bench-up.sh -p locksy-bench
bash bench/scripts/seed.sh -p locksy-bench M        # ou S pour une mise au point

# 2. Une passe (restaure le jeu, contrôle le poste, mesure, rapport).
bash bench/scripts/run.sh -p locksy-bench --dataset M --scenario 00
bash bench/scripts/run.sh -p locksy-bench --dataset M --scenario 07 --vus 200
bash bench/scripts/run.sh -p locksy-bench --dataset M --scenario 02c --server-env LOCKSY_RATELIMIT_LOGIN_IP=300

# 3. Campagne pré-release (environ 4 h 30 avec une endurance de 30 min).
bash bench/scripts/campaign.sh -p locksy-bench --dry-run      # plan et durée
bash bench/scripts/campaign.sh -p locksy-bench --endurance 2h

# 4. Fin : conteneurs, réseau et volume supprimés.
docker compose -p locksy-bench -f bench/docker-compose.bench.yml down -v
```

`run.sh` :

```
bash bench/scripts/run.sh [-p projet] --dataset S|M|L --scenario <nom> [--vus N] [--duration D]
     [--profile REF-PROD|REF-1G] [--env K=V]… [--server-env K=V]… [--reference DIR] [--no-restore] [--down]
```

1. restaure l'instantané du jeu (`snapshot.sh restore`) : chaque passe repart
   des mêmes données ;
2. applique les réglages du serveur (`--server-env`, fichier
   `compose.override.yml` de la passe) ;
3. lance `preflight.sh` : 2 annule la passe, 1 rend les seuils de
   performance indicatifs ;
4. lance `sample-stats.sh` en arrière-plan, 5 s avant k6 (mémoire de base) ;
5. lance k6 par `docker compose … --profile tools run --rm k6 run …`
   (`--summary-export` et `handleSummary`) ;
6. arrête l'échantillonneur, écrit `context.json`, puis `report.mjs` ;
7. `--down` supprime le banc ; sinon le serveur reste en service pour la
   passe suivante. Aucun conteneur k6 ni échantillonneur ne reste.

La configuration du conteneur en service (image, `LOCKSY_ENV`, mémoire) est
reprise si `LOCKSY_IMAGE`, `LOCKSY_ENV` et `LOCKSY_MEM` ne sont pas fixés.
Le scénario 11 passe le serveur en `LOCKSY_ENV=test` (compteurs).

Sorties : `bench/results/<horodatage>-<scénario>[-<N>vu]/` (ignoré par git) :
`summary.json`, `k6-export.json`, `k6.log`, `stats.csv`, `context.json`,
`preflight.txt`, `rapport.md`, `cpu.svg`, `memoire.svg`, `pids.svg` (et pour
le 10 : `k6-console.log`, `integrite.txt`, `summary-verification.json`).

Codes de sortie de `run.sh` et `report.mjs` :

| Code | Sens |
|---|---|
| 0 | passe, ou indicative sans seuil bloquant dépassé |
| 1 | échec d'au moins un seuil bloquant applicable |
| 2 | passe impossible ou inexploitable (usage, preflight bloquant, k6 en erreur) |
| 3 | indicative avec au moins un seuil bloquant dépassé |

### Variables

| Variable | Défaut | Rôle |
|---|---|---|
| `K6_CPUS`, `K6_MEM` | aucune | limite de l'injecteur (poste partagé : `K6_CPUS=2 K6_MEM=2g`) |
| `KILLS`, `INTERVAL` | 5, 120 | arrêts brutaux du scénario 10 et intervalle en secondes |
| `LOCKSY_IMAGE`, `LOCKSY_ENV`, `LOCKSY_MEM` | conteneur en service | voir `bench/README.md` |

Variables des scénarios (`--env K=V`, ou `--vus` et `--duration`) :

| Scénario | Variables (défaut) |
|---|---|
| 00 | `DURATION` (30s) |
| 02a | `RATE` (10/s), `RAMP` (2m), `DURATION` (3m), `MAX_VUS` (200) |
| 02b | `VUS` (200), `SPREAD` (5 s) |
| 02c | `ACCOUNTS` (150), `DURATION` (10m) |
| 02d | `START` (5/s), `STEP` (5), `MAX_RATE` (60), `PALIER` (1m), `MAX_VUS` (400) |
| 03 | `VUS` (50), `RATE` (100/s), `DUREE_SEUL` (60s), `DURATION` (5m) |
| 04 | `VUS` (20), `DUREE_SEUL` (60s), `DURATION` (5m) |
| 05 | `RATE` (20/s), `BATCH` (2000), `DURATION` (5m), `MAX_VUS` (150) |
| 06 | `N_100K` (20), `N_1M` (20), `N_10M` (10), `MAX_PER_ITEM` (20), `MAX_FILE_MIB` (10) |
| 07 | `VUS` (50 ; 200 ; 500), `RAMP` (3m), `DURATION` (20m), `PAUSE` (10 s) |
| 08 | `VUS` (200), `RAMP` (3m), `DURATION` (30m ; 2h pour G23), `PAUSE` (10 s) |
| 09 | `LEGIT` (50), `ATTACKERS` (50), `DURATION` (10m), `LOGIN_IP_LIMIT` (100), `NOMINAL_P95` (200 ms) |
| 10 | `VUS` (10), `DURATION` (calculée : (KILLS + 1) × INTERVAL) |
| 11 | `VUS` (200), `RAMP` (3m), `DURATION` (20m), `PERIODE` (30s), `PAUSE` (10 s) |

## Scénarios et seuils

Profil REF-PROD (2 vCPU, 512 Mo), jeu M sauf mention. Les seuils sont dans
`lib/thresholds.js` ; « fonctionnel » : jugé même sur un poste non conforme.

| # | Charge | Seuils bloquants |
|---|---|---|
| 00 | 1 VU, 30 s : santé, prelogin, login, sync, création, modification, corbeille, logout | 100 % des contrôles (fonctionnel, tout jeu) |
| 02a | 1 → 10 connexions/s en 2 min, plateau 3 min, une adresse par compte | p95(login) < 800 ms, p99 < 2 s, 0 réponse 429, 0 réponse 503, mémoire max < 350 Mio |
| 02b | 200 VU × 1 connexion en 5 s, réessai poli (503, Retry-After) | 100 % réussies, chacune en < 20 s, aucun 5xx autre que 503, mémoire < base + 150 Mio, PID < 100 ; taux de 503 publié |
| 02c | 150 comptes depuis une même adresse en 10 min | 100 % réussies et 0 réponse 429 avec le réglage (fonctionnel) ; plafond publié |
| 02d | paliers de 5 à 60 connexions/s | valeur publiée : plus haut palier tenu (p95 < 1 s, échecs < 1 %) |
| 03 | seul : 1 VU, 60 s ; charge : 100 req/s servies par 50 VU, 5 min | seul p95 < 80 ms ; charge p95 < 400 ms, débit ≥ 100 req/s, 0 erreur, mémoire < 400 Mio |
| 04 | jeu L : seul 1 VU ; 20 VU « équipe IT », 5 min | seul p95 < 700 ms, réponse < 12 Mo ; 20 VU p95 < 4 s ; aucun arrêt pour manque de mémoire |
| 05 | 20 écritures/s (60 % PUT, 30 % POST, 10 % corbeille, chacune suivie d'un /sync), import de 2 000/min, conflits | p95 PUT et POST < 150 ms, import < 3 s, 0 « database is locked » et 409 dans 100 % des conflits (fonctionnels) |
| 06 | 5 × 10 Mo simultanés ; 100 Ko, 1 Mo, 10 Mo ; limites | 1 Mo p95 < 400 ms, 10 Mo p95 < 3 s (envoi et lecture), aucun arrêt pour manque de mémoire, mémoire < 450 Mio, fichier au-delà de `attachment.max_file_mib` et corps de plus de 16 Mo refusés en < 200 ms, pièces hors limites refusées (fonctionnel) |
| 07 | journée type, 50, 200 ou 500 VU, montée 3 min, plateau 20 min | 50 : p95 < 200 ms, 0 erreur ; 200 : p95 < 400 ms, erreurs < 0,1 %, CPU < 140 %, mémoire < 450 Mio ; 500 : p95 < 1 s, erreurs < 0,5 %, aucun arrêt pour manque de mémoire |
| 08 | journée type, 200 VU, 30 min (2 h pour G23) | dérive mémoire < 10 %, PID ± 5, p95 ± 20 % (début / fin), aucun redémarrage ni arrêt pour manque de mémoire |
| 09 | 50 attaquants + 50 légitimes, 10 min | légitimes p95 < 2 × nominal, 100 % des connexions avec réessai, attaquants en 429 au-delà du plafond (fonctionnel), CPU moyen < 200 % |
| 10 | 10 écrivains, `kill -9` × 5 toutes les 2 min | integrity_check = ok et 100 % des écritures acquittées présentes (fonctionnels), redémarrage < 10 s |
| 11 | 200 VU + 1 administrateur qui enregistre un réglage toutes les 30 s | aucune lecture de l'ancien stockage ni chargement SQL des réglages par requête (compteurs `/api/test/counters`), `policy_revision` à jour dans 100 % des /sync, p95 de 07-200 inchangé (± 5 %) |

### Écarts assumés

- **01 (ligne de base par route)** n'est pas écrit dans ce lot (parcours
  rapide) ; le tableau « Par route » de chaque rapport en tient lieu.
- **03** : l'audit 05 prévoit 50 VU avec une pause de 1 s, ce qui plafonne
  l'injection à 50 req/s alors que le seuil exige 100 req/s. L'injecteur fixe
  donc le débit (100 req/s servies par 50 VU, `constant-arrival-rate`) ; un
  serveur trop lent se voit au p95 et aux itérations abandonnées.
- **06** se passe sur le jeu M (le cahier : « jeu M sauf mention ») ; les
  pièces jointes sont envoyées par le scénario, puis supprimées. Au-delà de
  16 Mo, le serveur refuse le corps sans le lire en entier : il répond 413
  ou ferme la connexion avant la fin de l'envoi (k6 voit alors « broken
  pipe »). Les deux comptent comme un refus ; le délai est mesuré par
  l'horloge du VU (`refus_corps_ms`). Le refus d'un fichier au-delà de
  `attachment.max_file_mib` (corps sous 16 Mo) est mesuré à part : 413
  `attachment_too_large` attendu, 400 sur un serveur antérieur à la
  vague 2 (le contrôle « refusé en 413 » le signale).
- **09** : le nominal est le p95 de la passe 07 à 50 VU de la campagne
  (`campaign.sh` le transmet par `NOMINAL_P95`) ; à défaut, le seuil de 07-50
  (200 ms). Les attaquants visent des e-mails inexistants : bloquer un compte
  réel fausserait la mesure des légitimes.
- **11** : « p95 inchangé (± 5 %) » est jugé contre une passe 07 à 200 VU
  (`--reference`, automatique en campagne) ; seule une hausse compte. Les
  sondes de politique (`GET /settings/policy`) sont hors du groupe mesuré.
- **02c** : avec le jeu S (50 comptes), le plafond de 100 n'est pas atteint ;
  la passe n'a de sens que sur M.

### Serveur sans les nouveautés de la vague 2

Sur une image sans `/sync?since` (champ `seq`) ni `policy_revision` dans
`/sync`, les mesures correspondantes sont **non mesurées** (verdict
INDICATIF) : `sync_delta` du 04 et propagation de la politique du 11. Les
compteurs du 11 exigent `LOCKSY_ENV=test` (posé par `run.sh`).

## Lecture du rapport

`rapport.md` contient :

- le **verdict global** : PASSE, ÉCHEC ou INDICATIF ;
- le **contexte** : image, version, profil, jeu, résultat de `preflight.sh`,
  variables, réglages du serveur, autres conteneurs actifs ;
- les **seuils** : mesuré, attendu, verdict, remarque ;
- les **mesures publiées** (taille de `/sync`, capacité, 503 de la rafale,
  plafond par adresse…) et, pour 02d, le tableau des paliers ;
- le **système** : CPU, mémoire, PID, arrêts, avec les courbes `cpu.svg`,
  `memoire.svg` et `pids.svg` (zone grisée : durée de k6 ; ligne rouge : seuil) ;
- le tableau **par route** : requêtes, p50, p95, p99, max, échecs ;
- les **contrôles k6** et, pour le 10, les durées de redémarrage.

Verdict de chaque seuil :

- **PASSE** / **ÉCHEC** : seuil applicable, respecté ou dépassé ;
- **INDICATIF** : seuil défini pour un autre jeu (03 sur S, par exemple),
  poste non conforme (`preflight.sh` à 1 : Docker partagé, moins de
  8 processeurs…) pour un seuil de performance, ou valeur non mesurée. La
  remarque dit si le seuil aurait été respecté.

Les seuils bloquants ne valent que sur le poste de référence avec
`preflight.sh` à 0 (cahier §6.6). Sur un poste partagé, notez-le dans le
rapport de campagne.

Pour refaire un rapport : `node bench/scripts/report.mjs bench/results/<passe> [--reference <passe 07-200>]`.

## Validation sur ce poste (18 novembre 2026)

Jeu S, profil REF-PROD, image `locksy-e2e-server:fast` (serveur 1.0.0,
schéma v3, sans les routes de la vague 2), injecteur limité à 2 CPU et 2 Go
(`K6_CPUS=2 K6_MEM=2g`). `preflight.sh` à 1 (Docker partagé avec d'autres
conteneurs) : **toutes les mesures sont indicatives**.

| Passe | Résultat |
|---|---|
| 00 (30 s) | PASSE : 100 % des contrôles, aucune réponse inattendue |
| 03 (60 s seul, 5 min à 100 req/s par 50 VU) | INDICATIF, tous les seuils respectés : p95 seul 3,3 ms ; p95 en charge 4,3 ms ; 100 req/s tenues ; 0 erreur ; mémoire max 38 Mio ; réponse de 320 Kio (jeu S : environ 300 éléments par compte) |

Passes courtes de mise au point (durées et VU réduits, `--no-restore`) :
02a, 02b (60 VU), 02c (50 comptes), 02d (jusqu'à 10/s), 04, 05, 06, 07
(50 VU), 08 (20 VU, 2 min), 09 (10 + 10), 10 (2 arrêts : redémarrages en
1,7 et 1,9 s, integrity_check = ok, 3 953 écritures acquittées toutes
retrouvées) et 11 (20 VU) se déroulent de bout en bout. Le 11 relève, sur
cette image antérieure à la vague 2, 306 lectures de l'ancien stockage des
réglages pendant la passe et l'absence de `policy_revision` dans `/sync`.

## Contrôles du code

```bash
for f in bench/k6/lib/*.js bench/k6/scenarios/*.js bench/scripts/report.mjs; do node --check "$f"; done
bash -n bench/scripts/run.sh && bash -n bench/scripts/campaign.sh
node --test bench/k6/test
# Options k6 de chaque scénario (jeu S présent) :
docker compose -p locksy-bench -f bench/docker-compose.bench.yml --profile tools run --rm --no-deps \
  k6 inspect -e DATASET=S /bench/k6/scenarios/07-journee-type.js
```

## Règles

- Les scénarios créent des éléments **factices mais bien formés** : ne
  réutilisez jamais un volume de charge pour les E2E.
- `users.json` contient des identifiants de test : `summary.json` n'en garde
  aucun (jetons exclus des données de setup).
- Un projet compose par usage (`-p`), aucun port fixe ; `run.sh --down` ou
  `docker compose … down -v` à la fin.
- Disque : un jeu L occupe environ 5 Go dans le volume et autant dans
  `bench/snapshots/L/` ; supprimez les résultats et instantanés inutiles.
