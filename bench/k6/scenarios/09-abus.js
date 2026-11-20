// 09 · Attaque et service, pendant DURATION (10 min) :
//   legitimes  : LEGIT utilisateurs (50) font leur journée type (07), avec
//                réessai poli des connexions (503 et 429) ;
//   attaquants : ATTACKERS adresses (50), chacune enchaîne prelogin sur un
//                e-mail inconnu et login avec une preuve fausse. Au-delà du
//                plafond par adresse (LOGIN_IP_LIMIT, 100 par 10 min), chaque
//                tentative doit recevoir 429.
// Les attaquants visent des comptes inexistants : bloquer un compte réel
// empêcherait la mesure des légitimes.
// Seuil des légitimes : p95 < 2 × NOMINAL_P95 (p95 de 07 à 50 VU ; 200 ms,
// seuil de 07-50, si la campagne ne le fournit pas).
import { sleep } from "k6";
import encoding from "k6/encoding";
import crypto from "k6/crypto";
import exec from "k6/execution";
import { api, ROUTES, ipFor, serverInfo, envInt, envDuration, seconds } from "../lib/common.js";
import { attackBlocked } from "../lib/metrics.js";
import { journeeIteration, JOURNEE_ROUTES } from "../lib/journee.js";
import { k6Thresholds, routeMetrics, TREND_STATS } from "../lib/thresholds.js";
import { makeSummary } from "../lib/summary.js";

const SCENARIO = "09-abus";
const DURATION = envDuration("DURATION", "10m");
const RAMP = "1m";
const LIMIT = envInt("LOGIN_IP_LIMIT", 100);
/** Fenêtre du plafond par adresse : au-delà, le compteur peut repartir. */
const WINDOW_MS = 9 * 60 * 1000;

export const options = {
  scenarios: {
    legitimes: {
      executor: "ramping-vus", startVUs: 0,
      stages: [{ target: envInt("LEGIT", 50), duration: RAMP }, { target: envInt("LEGIT", 50), duration: DURATION }],
      gracefulRampDown: "30s", exec: "legitime",
    },
    attaquants: {
      executor: "constant-vus", vus: envInt("ATTACKERS", 50), duration: `${seconds(RAMP) + seconds(DURATION)}s`, exec: "attaquant",
    },
  },
  thresholds: k6Thresholds(SCENARIO, __ENV, routeMetrics(JOURNEE_ROUTES, "groupe:journee").concat(routeMetrics([ROUTES.prelogin, ROUTES.login], "groupe:attaque"))),
  summaryTrendStats: [...TREND_STATS],
};

export function setup() {
  return { public: { serveur: serverInfo(), plafond: LIMIT } };
}

export function legitime() {
  journeeIteration({});
}

// État de l'attaquant : tentatives depuis son adresse et heure de la première.
const atk = { tries: 0, first: 0 };

export function attaquant() {
  const ip = ipFor(66, exec.vu.idInTest);
  const tags = { groupe: "attaque" };
  const email = `inconnu-${encoding.b64encode(crypto.randomBytes(6), "rawurl").toLowerCase()}@banc.test`;
  api("POST", "/auth/prelogin", { ip, name: ROUTES.prelogin, tags, body: { email }, expect: [200, 429] });
  const res = api("POST", "/auth/login", {
    ip, name: ROUTES.login, tags, expect: [401, 403, 429, 503],
    body: { email, auth_key: encoding.b64encode(crypto.randomBytes(32), "rawurl"), device: "k6" },
  });
  // Un 503 de la porte Argon2 n'a peut-être pas été compté par le plafond :
  // seules les tentatives traitées (401, 403, 429) avancent le compteur.
  if (res.status === 401 || res.status === 403 || res.status === 429) {
    if (atk.tries === 0) atk.first = Date.now();
    atk.tries += 1;
    if (atk.tries > LIMIT && Date.now() - atk.first < WINDOW_MS) attackBlocked.add(res.status === 429);
  }
  sleep(0.2);
}

export const handleSummary = makeSummary(SCENARIO);
