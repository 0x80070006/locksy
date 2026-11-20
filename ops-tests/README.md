# Recettes d'exploitation : sauvegarde, restauration, mise à jour

Ce dossier vérifie, sur de vrais conteneurs, ce que promet
[docs/Sauvegarde-et-mises-a-jour.md](../docs/Sauvegarde-et-mises-a-jour.md) :
une sauvegarde à chaud complète (base **et** `server.key`), une restauration
rapide et vérifiée, un refus clair quand la clé manque, la mise à jour depuis la
1.0.0 sans perte, et un retour arrière qui n'abîme rien.

Critères go-prod couverts (cahier, §6.7) : **G29** à **G33**. Stratégie de test :
`conception/05-strategie-benchmark-tests.md`, §6.

| Script | Critère | Ce qu'il démontre |
|---|---|---|
| `sauvegarde-restauration.sh` | G29, G30 | `backup --with-key` pendant des écritures (p95 < 3 × nominal, 0 erreur), aucune écriture acquittée perdue, restauration sur volume vide chronométrée (RTO), `check`, `verify-audit`, déchiffrement par le vrai client, connexion 2FA (jeu E2E) |
| `restauration-sans-cle.sh` | G31 | base restaurée sans `server.key` : refus de démarrer, message clair ; avec `LOCKSY_SERVER_KEY_RESET=true` : comptes sans 2FA intacts, comptes 2FA, `verify-audit` |
| `sauvegarde-naive.sh` | (test négatif) | une copie de `locksy.db` seule, à chaud, perd des écritures acquittées ; la documentation ne conseille jamais cette copie |
| `mise-a-jour.sh` | G32 | 1.0.0 reconstruite depuis git, semée par **son** client, puis version courante sur le même volume : indisponibilité, migrations, schéma, aucune perte, déchiffrement par le client courant, 2FA, lien de partage, anciens réglages |
| `retour-arriere.sh` | G33 | base d'un schéma trop récent refusée **sans écriture** ; constat de la 1.0.0 sur une base migrée ; retour par la sauvegarde d'avant mise à jour |

## Prérequis

- Docker (Docker Desktop sous WSL2 ou Docker Engine), Git Bash sous Windows ou un bash Linux, `curl`.
- Node 22.5 ou plus (module natif `node:sqlite` ; Node 26 sur le poste de référence). Aucune dépendance npm.
- Images : `locksy-e2e-server:fast` (version courante, variable `OPS_IMAGE`),
  `busybox:1.37.0`, `grafana/k6:1.0.0` ; pour la 1.0.0 : `locksy-toolchain` et
  `debian:trixie-slim` (construction de `locksy-ops:1.0.0`, voir plus bas).
- Les scripts se lancent depuis la racine du dépôt (`verrou/`), un à la fois.

## Fichiers

| Fichier | Rôle |
|---|---|
| `lib.sh` | sourcée par chaque script : mode strict, options communes, projets compose supprimés à la sortie, copies de volume (`busybox`), chronomètres, rapport |
| `compose.ops.yml` | serveur des recettes : limites du profil REF-PROD du banc (2 vCPU, 512 Mo, 128 PID, racine en lecture seule), port hôte aléatoire, `RUST_LOG=info` |
| `lib/base.mjs` | lecture d'une base SQLite **sur une copie** : `user_version`, `integrity_check`, lignes par table, écritures acquittées absentes d'une copie, base forgée |
| `lib/verif.mjs` | vérification déchiffrée par le vrai client courant (`bench/seed/worker.mjs`) : échantillon, liste de comptes ou tous, écritures factices de k6 tolérées |
| `lib/k6.mjs` | p50 et p95 des écritures de k6 par fenêtre de temps (nominal, pendant la sauvegarde) |
| `lib/connexion.mjs` | connexion brute d'un compte semé (preuve `auth_key`, code TOTP calculé) pour constater la réponse du serveur |
| `lib/semis-v100.mjs` | complément du semis de la 1.0.0 par son client (5 réglages, lien de partage) et contrôles après mise à jour |
| `lib/rapport.mjs` | `resultats.json` et `resultats.md` de chaque passe |
| `v100/Dockerfile`, `v100/construire.sh` | image `locksy-ops:1.0.0` reconstruite depuis `git archive HEAD` |

## Options et sorties communes

```
bash ops-tests/<script>.sh [-p projet] [--jeu E2E|M] [--garder] [-h]
```

- `-p` : préfixe des projets compose (défaut `q5-ops`). Chaque script ouvre ses propres
  projets (`q5-ops`, `q5-ops-r`, `q5-ops-sc`, `q5-ops-nv`, `q5-ops-nv-r`, `q5-ops-maj`,
  `q5-ops-ra`, `q5-ops-semis`) et les supprime à la sortie (`down -v`, volumes compris),
  même en cas d'échec ou d'interruption ; `--garder` les conserve pour enquêter.
- Aucun port fixe : le port hôte est tiré au sort. Les bancs (`bench/docker-compose.bench.yml`)
  reçoivent un sous-réseau propre au projet (`172.30.150.0/24` à `172.30.249.0/24`), jamais
  celui par défaut.
- Sorties : `bench/results/ops/<horodatage>-<script>/` (ignoré par git), ou `$OPS_OUT` :
  `resultats.md` et `resultats.json` (contrôles OK, ÉCHEC ou constat, et mesures), plus les
  pièces de chaque étape (journaux, sorties de `check` et `verify-audit`, bilans JSON).
  Les copies de base, clés et modules WebAssembly sont effacés à la fin, sauf avec `--garder`.
- Codes de sortie : **0** réussite, **1** au moins un contrôle en échec (ou arrêt sur
  erreur d'environnement), **2** usage invalide.

Variables : `OPS_IMAGE` (serveur courant, défaut `locksy-e2e-server:fast`),
`OPS_IMAGE_V100` (défaut `locksy-ops:1.0.0`), `OPS_OUT`, `BUSYBOX_IMAGE`,
`V100_REF` (révision git de la 1.0.0, défaut `HEAD`).

## Recettes

### sauvegarde-restauration.sh (G29, G30)

```bash
bash ops-tests/sauvegarde-restauration.sh --jeu M        # mesure du RTO (parcours rapide : M au lieu de L)
bash ops-tests/sauvegarde-restauration.sh --jeu E2E      # contrôle rapide, avec la connexion 2FA de david@e2e.test
```

Options propres : `--profil REF-PROD|REF-1G` (mémoire du serveur, 512 Mo par défaut ; aussi
pour la restauration), `--nominal S`, `--sans-pj`, `--resemer`, et `--malloc-arena N`, un
**diagnostic** qui lance les serveurs avec `MALLOC_ARENA_MAX=N` par une surcouche compose
(`surcouche.yml` dans le dossier de sortie) : configuration non livrée, signalée dans le rapport.

1. Banc `q5-ops` (`bench/scripts/bench-up.sh`, image `OPS_IMAGE`) et jeu semé par
   `bench/scripts/seed.sh --workers 2` ; si `bench/snapshots/<jeu>` existe, il est restauré à la
   place (`--resemer` force un semis neuf, `--sans-pj` sème sans pièce jointe).
2. `05-ecritures` (k6) en arrière-plan ; mesure nominale (`--nominal`, 60 s par défaut), puis
   `locksy-server backup /data/sauvegardes/locksy-<horodatage>.db --with-key` chronométré
   dans le conteneur (même horloge que k6). p95 des écritures pendant la sauvegarde
   (fenêtre d'au moins 10 s) contre nominal, erreurs, mémoire du serveur
   (`bench/scripts/sample-stats.sh`). Un serveur arrêté pendant la sauvegarde (manque de
   mémoire compris) est un échec. Une seconde sauvegarde, prise après l'arrêt des écritures,
   sert de référence : tout élément créé avant le début de la sauvegarde doit s'y trouver,
   et sa dernière modification aussi si elle précède la sauvegarde.
3. RTO, chronométré de « volume vide » à « service vérifié » : projet `q5-ops-r`, dépôt de la
   base et de la clé (flux tar, `busybox`), démarrage, santé, `check` = 0, `verify-audit` = 0,
   20 comptes tirés au sort (plus les comptes 2FA) reconnectés et déchiffrés.
4. Hors RTO : `integrity_check`, comptes, coffres et pièces jointes égaux au manifeste,
   éléments = semis + écritures de k6, déchiffrement de **tous** les comptes (les éléments
   factices de k6, indéchiffrables par construction, sont comptés à part et doivent tous être
   relus).

Limites du parcours rapide : jeu **M** au lieu de L ; annuaire AD non couvert (pas de profil
`ldap` sur le banc) ; le minuteur de sauvegarde de l'installateur (§6.2, point 9) n'est pas
testé ici.

### restauration-sans-cle.sh (G31)

```bash
bash ops-tests/restauration-sans-cle.sh            # jeu E2E (comptes avec et sans 2FA)
```

Base de `bench/snapshots/E2E` (semée sur un banc temporaire si elle manque) déposée **sans**
`server.key`. Attendu : refus de démarrer, code 1, message sur la sortie d'erreur qui cite
`server.key`, « Restaurez » et `LOCKSY_SERVER_KEY_RESET` ; aucune clé générée ; `check`
répond `ERREUR` et 1. Puis avec `LOCKSY_SERVER_KEY_RESET=true` : démarrage avec
avertissement, comptes sans 2FA reconnectés et déchiffrés, compte 2FA refusé par une
erreur claire (jamais une 500), `verify-audit` en code non nul avec la cause probable.
La liaison AD n'est pas couverte (pas de profil `ldap`).

### sauvegarde-naive.sh (test négatif)

```bash
bash ops-tests/sauvegarde-naive.sh [--essais 5]
```

Sous écritures (`05-ecritures`, jeu E2E), `locksy.db` seul est copié (ni `-wal` ni `-shm`)
`--essais` fois (5 par défaut) à 5 s d'écart. Chaque copie est comparée à une sauvegarde cohérente prise
après l'arrêt des écritures : éléments créés avant la copie et absents, `integrity_check`.
La première copie est restaurée et démarrée. Le test **réussit** s'il démontre une perte ou
une incohérence. Second contrôle : aucune commande de copie du fichier vivant `locksy.db`
(hors avertissement) dans les documents d'exploitation.

### mise-a-jour.sh (G32)

```bash
bash ops-tests/mise-a-jour.sh [--reconstruire]
```

1. Image 1.0.0 : `ops-tests/v100/construire.sh` (appelé si `locksy-ops:1.0.0` manque) extrait
   `git archive HEAD` dans un dossier temporaire **hors du dépôt** (aucun checkout), vérifie la
   version 1.0.0 du `Cargo.toml`, construit avec `ops-tests/v100/Dockerfile` (compilation dans
   `locksy-toolchain`, image d'exécution identique à celle de la 1.0.0, caches BuildKit
   `q5-ops-v100-*`), puis supprime le dossier. Repli : l'image locale `locksy:1.0.0`.
   Attention : la 1.0.0 ne connaît pas la sous-commande `version`, qui **démarre le serveur** ;
   les scripts ne la lancent jamais qu'avec un nom, en arrière-plan, puis l'arrêtent.
2. 1.0.0 démarrée (`q5-ops-maj`), jeu E2E semé par `bench/seed/seed.mjs` **copié à côté des
   sources 1.0.0** (il charge donc `web/js` et `locksy.wasm` de la 1.0.0), complété par
   `lib/semis-v100.mjs` (5 réglages de la 1.0.0, un lien de partage), relu par le
   `verify.mjs` de la même copie.
3. Arrêt de la 1.0.0, copie du volume (sauvegarde d'avant mise à jour, `avant-maj/`),
   démarrage de la version courante sur le **même** volume : indisponibilité chronométrée.
4. Contrôles : journal « schéma de la base migré », `user_version` = schéma du binaire, `check`
   = 0, tables identiques avant et après, déchiffrement de 100 % des éléments par le client
   courant (dont la connexion 2FA de david), lien de la 1.0.0 rouvert et déchiffré par le
   parcours de la page publique actuelle, anciens réglages présents dans
   `GET /api/admin/settings` avec la source `org`. La base migrée (`apres-maj/`) et les
   comptes (`semis/`) restent dans le dossier de sortie pour `retour-arriere.sh`.

Hors du parcours rapide : suite E2E « lecture seule » sur les données migrées, extension
N-1, client Windows N-1, `install.sh --upgrade`.

### retour-arriere.sh (G33)

```bash
bash ops-tests/retour-arriere.sh [--depuis bench/results/ops/<horodatage>-mise-a-jour]
```

Sans `--depuis`, la passe de `mise-a-jour.sh` la plus récente est reprise (ou lancée).

- **(a)** (ADAPTATION V1.6) La 1.0.0 n'a ni `PRAGMA user_version` ni contrôle de version :
  elle ne peut rien refuser. Le refus est donc testé sur le binaire courant, face à une copie
  de la base migrée forgée en `user_version` = schéma + 1 : code 1, message « plus récent »,
  `check` en `ERREUR` et 1, empreinte SHA-256 de `locksy.db` inchangée, aucun `-wal` non vide.
- **(b)** La 1.0.0 démarrée sur la base migrée : comportement **constaté** (démarre ou non,
  empreinte avant et après, erreurs du journal), consigné comme limite connue, sans verdict.
- **(c)** Procédure documentée : la sauvegarde d'avant mise à jour est restaurée, la 1.0.0
  démarre, `/api/health` répond 1.0.0 et le client 1.0.0 déchiffre tout.

## Nettoyage

Les scripts suppriment leurs projets et volumes. À la main, si un script a été tué :

```bash
for p in q5-ops q5-ops-r q5-ops-semis q5-ops-nv; do docker compose -p $p -f bench/docker-compose.bench.yml --profile tools down -v; done
for p in q5-ops-r q5-ops-sc q5-ops-nv-r q5-ops-maj q5-ops-ra; do docker compose -p $p -f ops-tests/compose.ops.yml down -v; done
docker image rm locksy-ops:1.0.0          # image 1.0.0, si elle n'est plus utile
```

Les caches BuildKit de la construction (`q5-ops-v100-registre`, `q5-ops-v100-cible`) ne sont
pas des volumes Docker ; `docker builder prune --filter type=exec.cachemount` les efface,
avec ceux des autres constructions du poste.

`bench/seed/out/<jeu>/users.json` et les dossiers `semis/` contiennent des **identifiants de
test** : ne les copiez pas hors du poste.

## Résultats du 18/11

Passes de la nuit du 18 au 19/11 (de 0 h 40 à 2 h 25), image courante
`locksy-e2e-server:fast` (reconstruite par l'intégrateur de la vague 2) et
`locksy-ops:1.0.0` (révision `764b26c`, construite en 462 s sur 3 CPU). Poste partagé
avec d'autres lots (une pile E2E tournait en parallèle) et `preflight.sh` à 1 : toutes
les durées sont **indicatives**. Rapports détaillés : `bench/results/ops/2026111*-<script>/`.

| Critère | Verdict | Mesures et constats |
|---|---|---|
| G29, jeu E2E (REF-PROD) | **réussite** | sauvegarde 0,1 s, 4,6 Mio, clé de 32 octets identique ; p95 des écritures 14,2 ms nominal, 18,6 ms pendant (fenêtre de 10 s, 215 écritures) ; 0 erreur ; 4 599 créations et 4 570 dernières modifications acquittées avant la sauvegarde toutes présentes ; mémoire maximale 290 Mio |
| G29, jeu M (REF-PROD 512 Mo, configuration livrée) | **échec** | le serveur est **tué pour manque de mémoire** dès le lancement de `backup`, 3 passes sur 3 ; p95 nominal des écritures avant la sauvegarde : environ 30 ms ; mémoire du serveur sous `05-ecritures` : 475 à 484 Mio sur 512 avant la sauvegarde. Défaut Q5-H2 |
| G29, jeu M (REF-1G) | **échec** | même arrêt pour manque de mémoire (1 013 Mio sur 1 Go) ; une passe manuelle à 1 Go a réussi, puis une autre a échoué : le serveur atteint 861 Mo de mémoire résidente sous `05-ecritures` |
| G29, jeu M, diagnostic `--malloc-arena 2` (non livré) | **échec** | plus d'arrêt (mémoire maximale 464 Mio, résidente stable vers 193 Mo) ; sauvegarde 86,7 s pour 1 514,9 Mio ; mais p95 nominal 1 125 ms, 6 513 ms pendant la sauvegarde, 4 connexions refusées en 503 `server_busy` |
| G30, jeu M (REF-PROD, avec le diagnostic ci-dessus) | **réussite** | **RTO 273,4 s** (4 min 33 s) du volume vide au service vérifié : dépôt de 1,5 Go, démarrage, `check` = 0, `verify-audit` = 0 (11 666 lignes, 2 ancrages), 20 comptes et 20 000 éléments déchiffrés ; hors RTO : `integrity_check` ok, comptes, coffres et pièces jointes égaux au manifeste, **500 000 éléments sur 500 000** et 2 000 pièces jointes déchiffrés en 279 s, 4 538 écritures de k6 toutes relues |
| G30, jeu E2E | **réussite** | RTO 10,1 à 12,0 s (2 passes) ; 95 éléments sur 95 ; connexion TOTP de david@e2e.test |
| G31 | **échec** | refus de démarrer sans `server.key` : code 1, message clair (« server.key », « Restaurez », `LOCKSY_SERVER_KEY_RESET`), aucune clé générée, `check` en `ERREUR` ; avec `LOCKSY_SERVER_KEY_RESET=true` : démarrage avec avertissement, comptes sans 2FA intacts (60 éléments sur 60), `verify-audit` code 1 avec la cause probable ; **mais le compte 2FA reçoit un 500 « Erreur interne du serveur. »** après le 401 `totp_required`. Défaut Q5-H1 |
| copie naïve (test négatif) | **réussite** | selon la passe, 1 à 3 copies sur 5 de `locksy.db` seul perdent des écritures acquittées (9 à 14 créations et 6 à 10 modifications : la dernière seconde avant la copie) ; `integrity_check` reste « ok » et le serveur redémarre sans rien signaler (`check` = 0) : la perte est silencieuse ; aucune copie de fichier conseillée dans les 5 documents relus |
| G32 | **réussite** | indisponibilité **6,5 à 9,1 s** sur 2 passes (arrêt de la 1.0.0, copie à froid du volume, démarrage de N), dont 5,8 s au plus pour démarrer N et migrer ; 3 paliers journalisés (v1, v2, v3) ; `user_version` 0 → 3 ; `check` = 0 ; tables identiques (6 comptes, 7 coffres, 9 adhésions, 75 éléments, 2 pièces jointes, 1 lien) ; 95 éléments sur 95 déchiffrés par le client courant, connexion TOTP, lien de la 1.0.0 rouvert et déchiffré ; réglages repris avec la source `org` (`session.idle_minutes` 45, `session.max_hours` 10, `retention.audit_days` 400, `retention.trash_days` 21 ; `twofa.required` à faux, valeur par défaut). N répond encore « 1.0.0 » : Q5-H3 |
| G33 | **réussite** | base forgée en v4 : refus, code 1, « plus récent », `check` code 1, empreinte SHA-256 inchangée, aucun `-wal` ; retour par la sauvegarde d'avant mise à jour : 1.0.0 en bonne santé en 9,4 s, son client relit tout |

Constat sur la 1.0.0 face à une base v3 (limite connue, aucun correctif possible dans
une version publiée) : elle **démarre** (`/api/health` en 200, version 1.0.0), sans erreur
au journal, et **modifie** le fichier (empreinte SHA-256 différente ; `user_version` reste
à 3). Seule la restauration de la sauvegarde d'avant mise à jour ramène une base que la
1.0.0 comprend : c'est la procédure de `install.sh --rollback`.

Semis du jeu M **complet** (2 000 pièces jointes, 1 054 Mio) : 309 s, vérification 233 s,
instantané 134 s, base de 1,5 Go. L'index couvrant des pièces jointes rend désormais ce semis
praticable (bench/README.md est mis à jour).

## Résultats après intégration (19/11)

Image `locksy-e2e-server:fast` reconstruite par l'intégrateur de la vague 3 (version 1.1.0,
`MALLOC_ARENA_MAX=2`, `SQLITE_TMPDIR=/data`, défauts Q5-H1, Q5-H3 et Q5-H4 corrigés), clé
d'exécution `-p v3i-ops`, même poste partagé : durées indicatives.

| Critère | Verdict | Mesures et constats |
|---|---|---|
| G29, jeu E2E | **réussite** | p95 des écritures 8,7 ms nominal, 6,9 ms pendant la sauvegarde ; 0 erreur |
| G29, jeu M (REF-PROD 512 Mo, configuration livrée) | **échec partiel** | plus d'arrêt pour manque de mémoire (maximum 396 Mio sur 512) ; sauvegarde 63,2 s pour 1 514,9 Mio ; p95 nominal **20,4 ms** ; 0 erreur, aucune écriture acquittée perdue (83 835 créations, 83 813 modifications) ; mais p95 **2 271,8 ms** pendant la sauvegarde (seuil : 3 × nominal). Cause : l'écriture de 1,5 Gio par `VACUUM INTO` sature le disque, et chaque écriture du serveur attend son `fsync`. Handoff V3I-H2 |
| G30, jeu M | **réussite** | RTO **192,4 s** ; `check` et `verify-audit` à 0 ; 500 000 éléments sur 500 000 et 2 000 pièces jointes déchiffrés (vérification complète 166,4 s) |
| G30, jeu E2E | **réussite** | RTO 9,8 s ; 95 éléments sur 95 ; connexion TOTP |
| G31 | **réussite** | refus clair sans clé ; après `LOCKSY_SERVER_KEY_RESET`, le compte 2FA reçoit 401 `totp_required` puis **409 `totp_unreadable`** (message clair), jamais 500 |
| G32 | **réussite** | indisponibilité 6,0 s ; 95 éléments sur 95 ; TOTP ; réglages repris (source `org`) ; N répond 1.1.0 |
| G33 | **réussite** | base forgée en v4 refusée sans écriture ; retour à la 1.0.0 par la sauvegarde d'avant mise à jour |
