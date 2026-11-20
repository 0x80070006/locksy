// 02b · Rafale : VUS (200) utilisateurs se connectent une fois, tous dans les
// SPREAD premières secondes (5), avec le réessai poli du client (503 et
// Retry-After). Mesure : réussite, durée de bout en bout (réessais compris),
// 5xx autres que 503 ; la mémoire et les PID viennent de sample-stats.sh.
import { sleep } from "k6";
import exec from "k6/execution";
import { login, logout, ROUTES, userFor, serverInfo, envInt } from "../lib/common.js";
import { loginTotal } from "../lib/metrics.js";
import { k6Thresholds, routeMetrics, TREND_STATS } from "../lib/thresholds.js";
import { makeSummary } from "../lib/summary.js";

const SCENARIO = "02b-rafale";
const SPREAD = envInt("SPREAD", 5);

export const options = {
  scenarios: {
    rafale: { executor: "per-vu-iterations", vus: envInt("VUS", 200), iterations: 1, maxDuration: "2m" },
  },
  thresholds: k6Thresholds(SCENARIO, __ENV, routeMetrics([ROUTES.prelogin, ROUTES.login, ROUTES.logout])),
  summaryTrendStats: [...TREND_STATS],
};

export function setup() {
  return { public: { serveur: serverInfo() } };
}

export default function () {
  const u = userFor(exec.vu.idInTest);
  sleep(Math.random() * SPREAD);
  const started = Date.now();
  // Réessai poli : au plus 20 s de bout en bout (10 essais espacés de 1 à 3 s ou du Retry-After).
  const token = login(u, { max: 10 });
  loginTotal.add(token ? Date.now() - started : 60000);
  if (token) logout(token, u.xff);
}

export const handleSummary = makeSummary(SCENARIO);
