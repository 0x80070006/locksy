// 03 · Synchronisation de 1 000 éléments (jeu M : chaque compte en voit
// environ 1 000).
//   seul   : 1 VU pendant DUREE_SEUL (60 s), /sync en boucle ;
//   charge : RATE requêtes/s (100) servies par VUS utilisateurs (50) pendant
//            DURATION (5 min), soit un /sync toutes les 0,5 s par utilisateur.
// Écart assumé avec l'audit 05 (« pause de 1 s ») : 50 VU espacés d'1 s ne
// peuvent pas produire les 100 req/s du seuil ; l'injecteur fixe donc le débit
// (constant-arrival-rate) et le seuil vérifie que le serveur le tient.
// Les sessions sont ouvertes dans setup() : les phases ne mesurent que /sync.
import { sleep } from "k6";
import exec from "k6/execution";
import { login, logout, sync, ROUTES, userFor, serverInfo, envInt, envDuration, seconds } from "../lib/common.js";
import { k6Thresholds, routeMetrics, TREND_STATS } from "../lib/thresholds.js";
import { makeSummary } from "../lib/summary.js";

const SCENARIO = "03-sync-1000";
const VUS = envInt("VUS", 50);
const RATE = envInt("RATE", 100);
const SEUL = envDuration("DUREE_SEUL", "60s");
const CHARGE = envDuration("DURATION", "5m");
const PAUSE_S = 10;

export const options = {
  setupTimeout: "5m",
  scenarios: {
    seul: { executor: "constant-vus", vus: 1, duration: SEUL, exec: "seul" },
    charge: {
      executor: "constant-arrival-rate",
      rate: RATE,
      timeUnit: "1s",
      duration: CHARGE,
      preAllocatedVUs: VUS,
      maxVUs: VUS,
      startTime: `${seconds(SEUL) + PAUSE_S}s`,
      exec: "charge",
    },
  },
  thresholds: k6Thresholds(SCENARIO, __ENV, routeMetrics([ROUTES.sync], "scenario:seul").concat(routeMetrics([ROUTES.sync], "scenario:charge"))),
  summaryTrendStats: [...TREND_STATS],
};

/** Une session par utilisateur de la phase de charge (le VU seul prend la première). */
export function setup() {
  const sessions = [];
  for (let i = 1; i <= VUS; i++) {
    const u = userFor(i);
    const token = login(u, { on429: true, tags: { groupe: "connexion_initiale" } });
    if (token) sessions.push({ token, ip: u.xff });
  }
  if (sessions.length === 0) throw new Error("Aucune session ouverte : vérifiez le jeu semé et preflight.sh.");
  return { public: { serveur: serverInfo(), sessions: sessions.length }, sessions };
}

function sessionOf(data) {
  return data.sessions[(exec.vu.idInTest - 1) % data.sessions.length];
}

export function seul(data) {
  const s = data.sessions[0];
  sync(s.token, s.ip);
  sleep(0.2);
}

export function charge(data) {
  const s = sessionOf(data);
  sync(s.token, s.ip);
}

export function teardown(data) {
  for (const s of data.sessions) logout(s.token, s.ip, { groupe: "fin" });
}

export const handleSummary = makeSummary(SCENARIO, { phases: { seul: seconds(SEUL), charge: seconds(CHARGE) } });
