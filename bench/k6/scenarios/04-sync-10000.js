// 04 · Synchronisation de 10 000 éléments (jeu L : coffre « Infrastructure
// IT » partagé par les 20 comptes it-NN).
//   seul   : 1 VU pendant DUREE_SEUL (60 s) ; si la réponse porte `seq`
//            (/sync incrémental livré), un /sync?since=<seq> suit chaque
//            /sync complet (route « sync_delta ») ;
//   charge : VUS utilisateurs (20, « équipe IT ») pendant DURATION (5 min),
//            pause de 1 s.
// Sur un autre jeu, les comptes it-NN manquent : les premiers comptes servent
// (passe indicative, le rapport le signale).
import { sleep } from "k6";
import exec from "k6/execution";
import { login, logout, sync, ROUTES, USERS, serverInfo, envInt, envDuration, seconds, jsonField } from "../lib/common.js";
import { k6Thresholds, routeMetrics, TREND_STATS } from "../lib/thresholds.js";
import { makeSummary } from "../lib/summary.js";

const SCENARIO = "04-sync-10000";
const VUS = envInt("VUS", 20);
const SEUL = envDuration("DUREE_SEUL", "60s");
const CHARGE = envDuration("DURATION", "5m");
const PAUSE_S = 10;
const TIMEOUT = "120s";

export const options = {
  setupTimeout: "5m",
  scenarios: {
    seul: { executor: "constant-vus", vus: 1, duration: SEUL, exec: "seul" },
    charge: { executor: "constant-vus", vus: VUS, duration: CHARGE, startTime: `${seconds(SEUL) + PAUSE_S}s`, exec: "charge" },
  },
  thresholds: k6Thresholds(
    SCENARIO,
    __ENV,
    routeMetrics([ROUTES.sync, ROUTES.syncDelta], "scenario:seul").concat(routeMetrics([ROUTES.sync], "scenario:charge")),
  ),
  summaryTrendStats: [...TREND_STATS],
};

/** Comptes de l'équipe IT (it-NN@), sinon les premiers comptes du jeu. */
function teamAccounts() {
  const it = [];
  for (let i = 0; i < USERS.length; i++) if (/^it-\d+@/.test(USERS[i].email)) it.push(USERS[i]);
  if (it.length > 0) return it;
  const all = [];
  for (let i = 0; i < Math.min(VUS, USERS.length); i++) all.push(USERS[i]);
  return all;
}

export function setup() {
  const team = teamAccounts();
  const sessions = [];
  for (let i = 0; i < Math.min(VUS, team.length); i++) {
    const token = login(team[i], { on429: true, tags: { groupe: "connexion_initiale" } });
    if (token) sessions.push({ token, ip: team[i].xff });
  }
  if (sessions.length === 0) throw new Error("Aucune session ouverte : vérifiez le jeu semé et preflight.sh.");
  return { public: { serveur: serverInfo(), sessions: sessions.length, equipe_it: /^it-/.test(team[0].email) }, sessions };
}

export function seul(data) {
  const s = data.sessions[0];
  const full = sync(s.token, s.ip, { timeout: TIMEOUT });
  const seq = full.status === 200 ? jsonField(full, "seq") : undefined;
  if (seq !== undefined && seq !== null) sync(s.token, s.ip, { since: seq });
  sleep(0.2);
}

export function charge(data) {
  const s = data.sessions[(exec.vu.idInTest - 1) % data.sessions.length];
  sync(s.token, s.ip, { timeout: TIMEOUT });
  sleep(1);
}

export function teardown(data) {
  for (const s of data.sessions) logout(s.token, s.ip, { groupe: "fin" });
}

export const handleSummary = makeSummary(SCENARIO, { phases: { seul: seconds(SEUL), charge: seconds(CHARGE) } });
