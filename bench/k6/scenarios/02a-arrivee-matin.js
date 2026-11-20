// 02a · Arrivée du matin : connexions de 1 à RATE par seconde (10) en RAMP
// (2 min), puis plateau de DURATION (3 min) ; une adresse par compte. Chaque
// itération enchaîne prelogin, login, sync et logout, sans réessai : le seuil
// exige 0 réponse 429 ou 503.
import exec from "k6/execution";
import { login, logout, sync, ROUTES, USERS, serverInfo, envInt, envDuration } from "../lib/common.js";
import { k6Thresholds, routeMetrics, TREND_STATS } from "../lib/thresholds.js";
import { makeSummary } from "../lib/summary.js";

const SCENARIO = "02a-arrivee-matin";
const RATE = envInt("RATE", 10);

export const options = {
  scenarios: {
    matin: {
      executor: "ramping-arrival-rate",
      startRate: 1,
      timeUnit: "1s",
      preAllocatedVUs: Math.max(20, RATE * 3),
      maxVUs: envInt("MAX_VUS", 200),
      stages: [
        { target: RATE, duration: envDuration("RAMP", "2m") },
        { target: RATE, duration: envDuration("DURATION", "3m") },
      ],
    },
  },
  thresholds: k6Thresholds(SCENARIO, __ENV, routeMetrics([ROUTES.prelogin, ROUTES.login, ROUTES.sync, ROUTES.logout])),
  summaryTrendStats: [...TREND_STATS],
};

export function setup() {
  return { public: { serveur: serverInfo(), comptes: USERS.length } };
}

export default function () {
  const u = USERS[exec.scenario.iterationInTest % USERS.length];
  const token = login(u, { retry: false });
  if (!token) return;
  sync(token, u.xff);
  logout(token, u.xff);
}

export const handleSummary = makeSummary(SCENARIO);
