# Budget du front (lot Q6)

Mesures du front de Locksy dans un vrai navigateur : cahier 00, §6.5, et
stratégie 05, §7. Les spécifications s'appellent `*.perf.ts`, pour que la
configuration générique (`*.spec.ts`) ne les lance jamais. Elles ont leur
propre configuration : `perf.config.ts`.

## Recette

Depuis la racine du dépôt, dans Git Bash :

```bash
# Tailles des ressources (wasm, JS, CSS), sans navigateur
node bench/scripts/budget-assets.mjs --image locksy-e2e-server:fast \
  --json bench/results/budget/$(date +%Y%m%d-%H%M%S).json
node bench/scripts/budget-assets.mjs --self-test

# Mesures dans le navigateur (seuil bloquant : perf-chromium)
E2E_WORKERS=1 bash e2e/tools/run.sh -p q6-perf --fast-server -- -c tests/perf/perf.config.ts --project=perf-chromium
# Firefox, à titre indicatif
E2E_WORKERS=1 bash e2e/tools/run.sh -p q6-perf --fast-server -- -c tests/perf/perf.config.ts --project=perf-firefox
```

`run.sh` supprime la pile (`down -v`) à la fin. Sorties :

- `e2e/test-results/q6-perf-perf/` : traces des échecs, `resultats.json` ;
- `e2e/playwright-report/q6-perf-perf/` : rapport HTML.

Les deux dossiers sont ignorés par git.

## Ce qui est mesuré

| Fichier | Mesure | Seuil | Nature |
|---|---|---|---|
| `deverrouillage.perf.ts` | Du clic sur « Déverrouiller » à la liste « Éléments » rendue avec « 1 000 éléments », 10 mesures | p50 < 1,5 s, p95 < 2,5 s (Chromium) | **bloquant (G27)** |
| | Même mesure sous Firefox | < 3,5 s | indicatif |
| | 10 000 éléments, 3 mesures ; tâche la plus longue ; mémoire JS | p95 < 5 s ; aucune tâche > 5 s ; < 150 Mo | indicatif |
| `fiche-recherche.perf.ts` | Du clic sur une ligne à l'image qui affiche le titre h1 de la fiche, 10 lignes, 1 000 éléments | médiane < 50 ms (Chromium) | G40 |
| | Frappe de 10 caractères dans « Rechercher dans tout le coffre », 1 000 éléments | p95 des intervalles entre images < 1,5 × la période au repos ; aucune tâche > 200 ms | G40 |
| | Coquille : navigation principale et en-tête restent les mêmes nœuds (coffre → fiche → bilan → coffre) | identité des nœuds | G40 |
| | Frappe à 10 000 éléments | p95 < 50 ms par image | indicatif |
| `budget-front.perf.ts` | Premier affichage de #/connexion : requêtes, octets JS, champ « Adresse e-mail » utilisable ; puis réseau bridé (CDP, Chromium) | ≤ 25 ; ≤ 120 Ko ; < 1,0 s ; < 2,0 s | indicatif |

Frappe dans la recherche (ADAPTATION) : à 60 Hz, deux images sont toujours
espacées de 16,7 ms. Le seuil « < 16 ms par image » se lit donc ainsi :
chaque image arrive à l'heure. On mesure la période au repos P, puis on
exige un p95 des intervalles sous 1,5 × P, c'est-à-dire aucune image manquée
au p95.

L'extension (popup jusqu'à la liste filtrée < 400 ms) n'est pas mesurée ici.
Le projet `extension` de la configuration générique l'a mesurée en vague 2,
entre 628 et 817 ms de médiane.

## Comptes et données

À la première mesure, deux comptes sont invités par l'administrateur de
l'organisation de test : 1 000 et 10 000 éléments. Ils s'inscrivent par
l'interface, avec les paramètres de dérivation par défaut (Argon2id réel).
Leurs éléments sont semés par le vrai client de la page :
`vault.importItems`, par lots de 500. Ces comptes sont créés une seule fois
par exécution. Ils sont consignés dans `e2e/.state/q6-perf/perf-comptes.json`,
qui est oublié dès que le serveur est recréé.

La page est chargée avec `/?perf=1` : `vault.js` pose alors les repères
`locksy:sync:start`, `sync:fetched` et `sync:decrypted`. Le déverrouillage est
découpé en trois phases :

- du clic à `sync:start` (GET /me et dérivation de la clé) ;
- de `sync:start` à `sync:decrypted` (/sync et déchiffrement) ;
- de `sync:decrypted` à la liste affichée (politique, préférences, rendu).

## Conditions de mesure

- Le poste est partagé. Chaque service compose est borné à 2 processeurs et
  2 Go, et un seul worker tourne (`workers: 1`). Les valeurs sont donc
  pessimistes par rapport au poste de référence du cahier.
- `bench/scripts/preflight.sh` ne s'applique pas ici : il contrôle le banc
  k6, pas le navigateur du lanceur.
- Les gardes CSP et console restent actives. Le relevé des textes est coupé
  (`textGuardMode: "off"`), mais la sonde des gardes observe toujours le DOM.
  Cela ajoute un léger surcoût aux mesures, au détriment du produit.
- Les tâches longues sont relevées par `PerformanceObserver` (« longtask »).
  Seul Chromium les expose ; sous Firefox, le rapport l'indique.

## Lire les résultats

Chaque série produit plusieurs traces :

- une annotation `mesure` dans le rapport HTML (médiane, p50, p95 au rang le
  plus proche, maximum, nombre de mesures) ;
- une ligne `[mesure] …` dans la sortie de la commande ;
- une pièce jointe JSON avec toutes les valeurs.

Un seuil indicatif est consigné avec son verdict, « conforme » ou « dépassé
(indicatif) », et ne fait jamais échouer la suite. Seuls les seuils bloquants
passent par `expect` : G27 sous Chromium, puis la fiche, la frappe et la
coquille de G40.
