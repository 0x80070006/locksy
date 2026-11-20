// 02d · Capacité de connexion : paliers de START (5) à MAX_RATE (60)
// connexions/s par pas de STEP (5), chacun tenu PALIER (1 min) après 5 s de
// transition ; une adresse par itération (les plafonds par adresse ne
// limitent pas la mesure). Chaque requête porte l'étiquette « palier » : le
// rapport publie le plus haut palier où le p95 de la connexion reste sous
// 1 s avec moins de 1 % d'échecs (valeur de la table de dimensionnement).
import exec from "k6/execution";
import { login, logout, ROUTES, USERS, ipFor, serverInfo, envInt, envDuration, seconds } from "../lib/common.js";
import { k6Thresholds, TREND_STATS } from "../lib/thresholds.js";
import { makeSummary } from "../lib/summary.js";

const SCENARIO = "02d-capacite";
const START = envInt("START", 5);
const STEP = envInt("STEP", 5);
const MAX_RATE = envInt("MAX_RATE", 60);
const PALIER = envDuration("PALIER", "1m");
const TRANSITION_S = 5;

const PALIERS = [];
for (let r = START; r <= MAX_RATE; r += STEP) PALIERS.push(r);
const stages = [];
for (const r of PALIERS) stages.push({ target: r, duration: `${TRANSITION_S}s` }, { target: r, duration: PALIER });

const observe = [];
for (const r of PALIERS) {
  observe.push(`http_req_duration{name:connexion,palier:${r}}`, `http_req_failed{name:connexion,palier:${r}}`, `http_reqs{name:connexion,palier:${r}}`);
}

export const options = {
  scenarios: {
    capacite: {
      executor: "ramping-arrival-rate",
      startRate: START,
      timeUnit: "1s",
      preAllocatedVUs: 50,
      maxVUs: envInt("MAX_VUS", 400),
      stages,
    },
  },
  thresholds: k6Thresholds(SCENARIO, __ENV, observe),
  summaryTrendStats: [...TREND_STATS],
};

const PALIER_S = seconds(PALIER) + TRANSITION_S;

/** Palier en cours d'après le temps écoulé depuis le début du scénario. */
function currentPalier() {
  const elapsed = (Date.now() - exec.scenario.startTime) / 1000;
  return PALIERS[Math.min(PALIERS.length - 1, Math.floor(elapsed / PALIER_S))];
}

export function setup() {
  return { public: { serveur: serverInfo() } };
}

export default function () {
  const n = exec.scenario.iterationInTest;
  const u = USERS[n % USERS.length];
  const ip = ipFor(120, (n % 65000) + 1);
  const tags = { palier: String(currentPalier()) };
  // Sans réessai : un 503 de la porte Argon2 est un échec du palier.
  const token = login(u, { ip, retry: false, tags });
  if (token) logout(token, ip, tags);
}

export const handleSummary = makeSummary(SCENARIO, { paliers: PALIERS, palier_s: seconds(PALIER), transition_s: TRANSITION_S });
