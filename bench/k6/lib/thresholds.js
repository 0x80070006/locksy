// Seuils d'acceptation des scénarios de charge : cahier §6.3 (profil
// REF-PROD, jeu M sauf mention) et audit 05 §3.6. Source UNIQUE : les
// scénarios k6 en tirent leurs thresholds, et bench/scripts/report.mjs (Node)
// importe ce même fichier pour juger chaque seuil. Ce module n'importe donc
// rien de k6 et reste du JavaScript simple (k6 et Node).
//
// Un critère :
//   id, label            identifiant stable, libellé du rapport (français)
//   source               "k6"      : métrique k6 (metric) et expression (expr), jugée par k6
//                        "stats"   : relevé système de sample-stats.sh (stat, op, value)
//                        "derive"  : calcul du rapport sur des métriques k6 (kind, …)
//                        "run"     : produit par run.sh (intégrité, redémarrages, réglages)
//                        "reference" : comparaison à une passe de référence (--reference)
//   unit                 unité d'affichage
//   dataset              jeu pour lequel le seuil est défini ("M", "L") ; null = tout jeu
//   bloquant             seuil bloquant du cahier (sinon : souhaitable)
//   fonctionnel          comportement attendu quel que soit le poste (un preflight
//                        à 1 ne le rend pas indicatif)
//   mesure               valeur publiée sans seuil (table « Mesures » du rapport)

/** Statistiques de tendance exportées (p50 = med). */
export const TREND_STATS = ["avg", "min", "med", "max", "p(90)", "p(95)", "p(99)", "count"];

const num = (v, d) => {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : d;
};

function k6(id, label, metric, expr, extra) {
  return Object.assign({ id, label, source: "k6", metric, expr, dataset: "M", bloquant: true, fonctionnel: false }, extra || {});
}
function stats(id, label, stat, op, value, unit, extra) {
  return Object.assign({ id, label, source: "stats", stat, op, value, unit, dataset: "M", bloquant: true, fonctionnel: false }, extra || {});
}

/** Seuils de la journée type (07) selon le nombre d'utilisateurs actifs. */
function journee(vus) {
  const d = "http_req_duration{groupe:journee}";
  const f = "http_req_failed{groupe:journee}";
  if (vus >= 500) {
    return [
      k6("07-500-p95", "500 actifs : p95 < 1 s", d, "p(95)<1000", { unit: "ms" }),
      k6("07-500-erreurs", "500 actifs : erreurs < 0,5 %", f, "rate<0.005", { unit: "%" }),
      stats("07-500-oom", "500 actifs : aucun arrêt pour manque de mémoire", "oom", "==", 0, ""),
      stats("07-500-cpu", "500 actifs : CPU moyen < 180 %", "cpu_moy", "<", 180, "%", { bloquant: false }),
    ];
  }
  if (vus >= 200) {
    return [
      k6("07-200-p95", "200 actifs : p95 < 400 ms", d, "p(95)<400", { unit: "ms" }),
      k6("07-200-erreurs", "200 actifs : erreurs < 0,1 %", f, "rate<0.001", { unit: "%" }),
      stats("07-200-cpu", "200 actifs : CPU moyen < 140 %", "cpu_moy", "<", 140, "%"),
      stats("07-200-rss", "200 actifs : mémoire max < 450 Mio", "mem_max", "<", 450, "Mio"),
    ];
  }
  return [
    k6("07-50-p95", "50 actifs : p95 < 200 ms", d, "p(95)<200", { unit: "ms" }),
    k6("07-50-erreurs", "50 actifs : aucune erreur", f, "rate==0", { unit: "%" }),
    stats("07-50-cpu", "50 actifs : CPU moyen < 60 %", "cpu_moy", "<", 60, "%", { bloquant: false }),
  ];
}

/** Critères d'un scénario, selon l'environnement de la passe (VUS, NOMINAL_P95…). */
export function criteria(scenario, env) {
  const e = env || {};
  switch (scenario) {
    case "00-smoke":
      return [
        k6("00-checks", "100 % des contrôles réussis (prérequis de toute passe)", "checks", "rate==1", { unit: "%", dataset: null, fonctionnel: true }),
        k6("00-reponses", "aucune réponse inattendue", "http_req_failed", "rate==0", { unit: "%", dataset: null, fonctionnel: true }),
      ];
    case "02a-arrivee-matin":
      return [
        k6("02a-p95", "p95 de la connexion < 800 ms", "http_req_duration{name:connexion}", "p(95)<800", { unit: "ms" }),
        k6("02a-p99", "p99 de la connexion < 2 s", "http_req_duration{name:connexion}", "p(99)<2000", { unit: "ms" }),
        k6("02a-429", "aucune réponse 429", "statut_429", "count==0", { unit: "" }),
        k6("02a-503", "aucune réponse 503", "statut_503", "count==0", { unit: "" }),
        stats("02a-rss", "mémoire max < 350 Mio", "mem_max", "<", 350, "Mio"),
        stats("02a-cpu", "CPU moyen < 160 %", "cpu_moy", "<", 160, "%", { bloquant: false }),
        k6("02a-reussite", "toutes les connexions réussies", "connexion_reussie", "rate==1", { unit: "%", bloquant: false }),
      ];
    case "02b-rafale":
      return [
        k6("02b-reussite", "100 % des connexions réussies (réessai poli)", "connexion_reussie", "rate==1", { unit: "%" }),
        k6("02b-duree", "chaque connexion aboutit en moins de 20 s", "connexion_totale", "max<20000", { unit: "ms" }),
        k6("02b-5xx", "aucun 5xx autre que 503", "statut_5xx_autres", "count==0", { unit: "" }),
        stats("02b-rss", "mémoire max < base + 150 Mio (porte Argon2)", "mem_delta", "<", 150, "Mio"),
        stats("02b-pids", "fils (PID) max < 100", "pids_max", "<", 100, ""),
        k6("02b-503", "réponses 503 pendant la rafale (mesure)", "statut_503", "count>=0", { unit: "", mesure: true, bloquant: false }),
      ];
    case "02c-nat":
      return [
        k6("02c-reussite", "toutes les connexions derrière le NAT réussissent", "connexion_reussie", "rate==1", { unit: "%", fonctionnel: true }),
        k6("02c-429", "aucune réponse 429 avec le plafond réglé", "statut_429", "count==0", { unit: "", fonctionnel: true }),
        { id: "02c-plafond", label: "plafond de connexions par adresse (LOCKSY_RATELIMIT_LOGIN_IP)", source: "run", key: "plafond_connexion_ip",
          unit: "par 10 min", dataset: null, bloquant: false, fonctionnel: true, mesure: true },
      ];
    case "02d-capacite":
      return [
        { id: "02d-capacite", label: "connexions par seconde soutenables (p95 < 1 s, échecs < 1 %)", source: "derive", kind: "capacite",
          metric: "http_req_duration{name:connexion}", unit: "connexions/s", dataset: "M", bloquant: false, fonctionnel: false, mesure: true },
      ];
    case "03-sync-1000":
      return [
        k6("03-seul-p95", "seul : p95 de /sync < 80 ms", "http_req_duration{name:sync,scenario:seul}", "p(95)<80", { unit: "ms" }),
        k6("03-taille", "taille de la réponse de /sync (≈ 1 Mo attendu)", "sync_octets{scenario:seul}", "avg>=0", { unit: "o", mesure: true, bloquant: false }),
        k6("03-charge-p95", "50 VU : p95 de /sync < 400 ms", "http_req_duration{name:sync,scenario:charge}", "p(95)<400", { unit: "ms" }),
        { id: "03-debit", label: "50 VU : débit ≥ 100 requêtes/s", source: "derive", kind: "debit", metric: "http_reqs{name:sync,scenario:charge}",
          phase: "charge", op: ">=", value: 100, unit: "req/s", dataset: "M", bloquant: true, fonctionnel: false },
        k6("03-erreurs", "50 VU : aucune erreur", "http_req_failed{scenario:charge}", "rate==0", { unit: "%" }),
        stats("03-rss", "mémoire max < 400 Mio", "mem_max", "<", 400, "Mio"),
        k6("03-injecteur", "injecteur à l'heure (aucune itération abandonnée)", "dropped_iterations", "count==0", { unit: "", bloquant: false }),
      ];
    case "04-sync-10000":
      return [
        k6("04-seul-p95", "seul : p95 de /sync < 700 ms", "http_req_duration{name:sync,scenario:seul}", "p(95)<700", { unit: "ms", dataset: "L" }),
        k6("04-taille", "réponse de /sync < 12 Mo", "sync_octets{scenario:seul}", "max<12582912", { unit: "o", dataset: "L" }),
        k6("04-charge-p95", "20 VU : p95 de /sync < 4 s", "http_req_duration{name:sync,scenario:charge}", "p(95)<4000", { unit: "ms", dataset: "L" }),
        stats("04-oom", "aucun arrêt pour manque de mémoire", "oom", "==", 0, "", { dataset: "L" }),
        stats("04-rss", "mémoire max < 450 Mio (sinon R3 confirmé : 1 Go ou /sync incrémental)", "mem_max", "<", 450, "Mio", { dataset: "L", bloquant: false }),
        k6("04-delta", "/sync?since (si la réponse porte seq)", "http_req_duration{name:sync_delta}", "p(95)>=0", { unit: "ms", dataset: "L", mesure: true, bloquant: false }),
      ];
    case "05-ecritures":
      return [
        k6("05-maj-p95", "p95 des modifications (PUT) < 150 ms", "http_req_duration{name:element_maj}", "p(95)<150", { unit: "ms" }),
        k6("05-creation-p95", "p95 des créations (POST) < 150 ms", "http_req_duration{name:element_creation}", "p(95)<150", { unit: "ms" }),
        k6("05-lot-p95", "p95 de l'import de 2 000 éléments < 3 s", "http_req_duration{name:import_lot}", "p(95)<3000", { unit: "ms" }),
        k6("05-verrou", "aucune erreur « database is locked »", "base_verrouillee", "count==0", { unit: "", fonctionnel: true }),
        k6("05-conflit", "révision périmée refusée en 409 dans 100 % des cas", "conflit_409", "rate==1", { unit: "%", fonctionnel: true, dataset: null }),
        k6("05-erreurs", "réponses inattendues < 1 %", "http_req_failed", "rate<0.01", { unit: "%", bloquant: false }),
      ];
    case "06-pieces-jointes":
      return [
        k6("06-1m-envoi", "1 Mo : p95 de l'envoi < 400 ms", "http_req_duration{name:piece_jointe_envoi,taille:1m}", "p(95)<400", { unit: "ms" }),
        k6("06-1m-lecture", "1 Mo : p95 du téléchargement < 400 ms", "http_req_duration{name:piece_jointe_lecture,taille:1m}", "p(95)<400", { unit: "ms" }),
        k6("06-10m-envoi", "10 Mo : p95 de l'envoi < 3 s", "http_req_duration{name:piece_jointe_envoi,taille:10m}", "p(95)<3000", { unit: "ms" }),
        k6("06-10m-lecture", "10 Mo : p95 du téléchargement < 3 s", "http_req_duration{name:piece_jointe_lecture,taille:10m}", "p(95)<3000", { unit: "ms" }),
        stats("06-oom", "5 × 10 Mo simultanés : aucun arrêt pour manque de mémoire", "oom", "==", 0, ""),
        stats("06-rss", "mémoire max < 450 Mio", "mem_max", "<", 450, "Mio"),
        k6("06-413", "fichier au-delà de la taille permise : refusé en moins de 200 ms", "http_req_duration{name:piece_jointe_trop_grosse}", "max<200", { unit: "ms" }),
        k6("06-corps", "corps de plus de 16 Mo : refusé en moins de 200 ms", "refus_corps_ms", "max<200", { unit: "ms" }),
        k6("06-refus", "pièces jointes hors limites refusées (taille, nombre, corps)", "piece_jointe_refusee", "rate==1", { unit: "%", fonctionnel: true, dataset: null }),
      ];
    case "07-journee-type":
      return journee(num(e.VUS, 50));
    case "08-endurance":
      return [
        stats("08-rss", "dérive de la mémoire < 10 % (début → fin)", "derive_rss_pct", "<", 10, "%"),
        stats("08-pids", "fils (PID) stables (± 5)", "derive_pids", "<=", 5, ""),
        { id: "08-p95", label: "p95 stable (± 20 % entre début et fin)", source: "derive", kind: "ecart",
          metric: "http_req_duration{groupe:journee,periode:debut}", metric2: "http_req_duration{groupe:journee,periode:fin}",
          field: "p(95)", op: "<=", value: 20, unit: "%", dataset: "M", bloquant: true, fonctionnel: false },
        stats("08-redemarrage", "aucun redémarrage", "redemarrages", "==", 0, ""),
        stats("08-oom", "aucun arrêt pour manque de mémoire", "oom", "==", 0, ""),
        k6("08-erreurs", "erreurs < 0,1 %", "http_req_failed{groupe:journee}", "rate<0.001", { unit: "%", bloquant: false }),
      ];
    case "09-abus": {
      const nominal = num(e.NOMINAL_P95, 200);
      return [
        k6("09-p95", `légitimes : p95 < 2 × nominal (${2 * nominal} ms)`, "http_req_duration{groupe:journee}", `p(95)<${2 * nominal}`, { unit: "ms" }),
        k6("09-connexions", "légitimes : 100 % des connexions réussies avec réessai", "connexion_reussie", "rate==1", { unit: "%" }),
        k6("09-bloques", "attaquants : 429 au-delà du plafond par adresse", "attaque_bloquee", "rate==1", { unit: "%", fonctionnel: true }),
        stats("09-cpu", "CPU moyen < 200 % (porte Argon2)", "cpu_moy", "<", 200, "%"),
        stats("09-rss", "sans croissance mémoire (< base + 100 Mio)", "mem_delta", "<", 100, "Mio", { bloquant: false }),
      ];
    }
    case "10-arret-brutal":
      return [
        { id: "10-integrite", label: "PRAGMA integrity_check = ok après les arrêts brutaux", source: "run", key: "integrite",
          op: "==", value: "ok", unit: "", dataset: null, bloquant: true, fonctionnel: true },
        k6("10-acquittees", "100 % des écritures acquittées présentes", "ecriture_acquittee_presente", "rate==1", { unit: "%", dataset: null, fonctionnel: true }),
        { id: "10-redemarrage", label: "redémarrage en moins de 10 s", source: "run", key: "redemarrage_max_s",
          op: "<", value: 10, unit: "s", dataset: "M", bloquant: true, fonctionnel: false },
        k6("10-volume", "écritures acquittées (mesure)", "ecritures_acquittees", "count>=0", { unit: "", mesure: true, bloquant: false }),
      ];
    case "11-reglages":
      return [
        k6("11-historique", "aucune lecture de l'ancien stockage des réglages", "reglages_lectures_historiques", "value==0", { unit: "", fonctionnel: true }),
        k6("11-sql", "aucune lecture SQL des réglages par requête (chargements ≤ révisions écrites + 2)", "reglages_chargements_excedentaires", "value<=0", { unit: "", fonctionnel: true }),
        k6("11-propagation", "policy_revision à jour dans 100 % des /sync", "politique_a_jour", "rate==1", { unit: "%", fonctionnel: true }),
        { id: "11-p95", label: "p95 de 07-200 inchangé (± 5 %)", source: "reference", metric: "http_req_duration{groupe:journee}",
          field: "p(95)", op: "<=", value: 5, unit: "%", dataset: "M", bloquant: true, fonctionnel: false },
        k6("11-p95-abs", "p95 < 400 ms (seuil de 07-200)", "http_req_duration{groupe:journee}", "p(95)<400", { unit: "ms", bloquant: false }),
        k6("11-ecritures", "réglages enregistrés par l'administrateur (mesure)", "reglages_enregistres", "count>=0", { unit: "", mesure: true, bloquant: false }),
      ];
    default:
      throw new Error(`Scénario inconnu : ${scenario}`);
  }
}

/**
 * Thresholds k6 d'un scénario : ses critères « k6 », plus des seuils
 * d'observation (toujours vrais) qui forcent l'export des sous-métriques
 * utiles au rapport (tableau par route, débits, paliers).
 */
export function k6Thresholds(scenario, env, observe) {
  const out = {};
  const add = (metric, expr) => {
    if (!out[metric]) out[metric] = [];
    if (out[metric].indexOf(expr) < 0) out[metric].push(expr);
  };
  for (const c of criteria(scenario, env)) {
    if (c.source === "k6") add(c.metric, c.expr);
    if (c.metric && c.source !== "k6") add(c.metric, OBSERVE_TREND);
    if (c.metric2) add(c.metric2, OBSERVE_TREND);
  }
  for (const m of observe || []) add(m, m.indexOf("http_req_failed") === 0 ? OBSERVE_RATE : m.indexOf("http_reqs") === 0 ? OBSERVE_COUNT : OBSERVE_TREND);
  // Une sous-métrique http_reqs{…} se juge sur count, pas sur max.
  for (const m of Object.keys(out)) {
    if (m.indexOf("http_reqs") === 0) out[m] = out[m].map((x) => (x === OBSERVE_TREND ? OBSERVE_COUNT : x));
  }
  return out;
}

/** Sous-métriques par route (durée, échecs, nombre) pour le tableau du rapport. */
export function routeMetrics(routes, extraTags) {
  const t = extraTags ? `,${extraTags}` : "";
  const out = [];
  for (const r of routes) {
    out.push(`http_req_duration{name:${r}${t}}`, `http_req_failed{name:${r}${t}}`, `http_reqs{name:${r}${t}}`);
  }
  return out;
}

// Seuils d'observation : toujours vrais, ignorés par le rapport.
export const OBSERVE_TREND = "max>=0";
export const OBSERVE_RATE = "rate>=0";
export const OBSERVE_COUNT = "count>=0";
export const OBSERVATIONS = [OBSERVE_TREND, OBSERVE_RATE, OBSERVE_COUNT];

/** Libellé et jeu de référence de chaque scénario (rapport, campagne). */
export const SCENARIOS = {
  "00-smoke": { titre: "Smoke (1 VU, 30 s)", jeu: null },
  "02a-arrivee-matin": { titre: "Arrivée du matin (1 → 10 connexions/s, plateau)", jeu: "M" },
  "02b-rafale": { titre: "Rafale de connexions (200 VU en 5 s, réessai poli)", jeu: "M" },
  "02c-nat": { titre: "NAT d'entreprise (150 comptes, une même adresse)", jeu: "M" },
  "02d-capacite": { titre: "Capacité de connexion (rampe par paliers)", jeu: "M" },
  "03-sync-1000": { titre: "Synchronisation de 1 000 éléments", jeu: "M" },
  "04-sync-10000": { titre: "Synchronisation de 10 000 éléments", jeu: "L" },
  "05-ecritures": { titre: "Écritures (20/s, import de 2 000 par minute, conflits)", jeu: "M" },
  "06-pieces-jointes": { titre: "Pièces jointes (100 Ko, 1 Mo, 10 Mo, 5 × 10 Mo)", jeu: "M" },
  "07-journee-type": { titre: "Journée type", jeu: "M" },
  "08-endurance": { titre: "Endurance (journée type à 200 VU)", jeu: "M" },
  "09-abus": { titre: "Attaque et service (50 attaquants, 50 légitimes)", jeu: "M" },
  "10-arret-brutal": { titre: "Arrêt brutal sous écriture (kill -9 × 5)", jeu: "M" },
  "11-reglages": { titre: "Réglages et politique sous charge (200 VU + 1 administrateur)", jeu: "M" },
};
