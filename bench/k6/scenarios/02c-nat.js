// 02c · NAT d'entreprise : ACCOUNTS comptes (150) se connectent chacun une fois
// en DURATION (10 min), tous depuis la MÊME adresse (10.250.0.1). Sans réglage,
// le serveur répond 429 dès la 101e connexion (100 par 10 min et par adresse) ;
// avec LOCKSY_RATELIMIT_LOGIN_IP réglé à au moins 2 fois l'effectif derrière le
// NAT (run.sh --server-env LOCKSY_RATELIMIT_LOGIN_IP=300), 0 erreur.
import exec from "k6/execution";
import { login, logout, ROUTES, USERS, NAT_IP, serverInfo, envInt, envDuration } from "../lib/common.js";
import { k6Thresholds, routeMetrics, TREND_STATS } from "../lib/thresholds.js";
import { makeSummary } from "../lib/summary.js";

const SCENARIO = "02c-nat";
const ACCOUNTS = Math.min(envInt("ACCOUNTS", 150), USERS.length);
const DURATION = envDuration("DURATION", "10m");

export const options = {
  scenarios: {
    nat: {
      executor: "constant-arrival-rate",
      rate: ACCOUNTS,
      timeUnit: DURATION,
      duration: DURATION,
      preAllocatedVUs: 5,
      maxVUs: 20,
    },
  },
  thresholds: k6Thresholds(SCENARIO, __ENV, routeMetrics([ROUTES.prelogin, ROUTES.login, ROUTES.logout])),
  summaryTrendStats: [...TREND_STATS],
};

export function setup() {
  return { public: { serveur: serverInfo(), comptes: ACCOUNTS, adresse: NAT_IP } };
}

export default function () {
  const n = exec.scenario.iterationInTest;
  if (n >= ACCOUNTS) return;
  const u = USERS[n];
  // Réessai poli des seuls 503 : un 429 est justement ce que l'on mesure.
  const token = login(u, { ip: NAT_IP });
  if (token) logout(token, NAT_IP);
}

export const handleSummary = makeSummary(SCENARIO);
