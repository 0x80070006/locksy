// 08 · Endurance : la journée type (07) à VUS utilisateurs (200) pendant
// DURATION (30 min par défaut ; 2h pour le critère G23, 8h la nuit avant une
// release majeure : --duration 2h). Chaque requête porte l'étiquette
// « periode » : montee, debut (premier cinquième du plateau), milieu, fin
// (dernier cinquième) ; le rapport compare le p95, la mémoire et les PID du
// début et de la fin.
import exec from "k6/execution";
import { serverInfo, envInt, envDuration, seconds } from "../lib/common.js";
import { journeeIteration, JOURNEE_ROUTES } from "../lib/journee.js";
import { k6Thresholds, routeMetrics, TREND_STATS } from "../lib/thresholds.js";
import { makeSummary } from "../lib/summary.js";

const SCENARIO = "08-endurance";
const VUS = envInt("VUS", 200);
const RAMP = envDuration("RAMP", "3m");
const PLATEAU = envDuration("DURATION", "30m");
const PAUSE = envInt("PAUSE", 10);
const RAMP_S = seconds(RAMP);
const PLATEAU_S = seconds(PLATEAU);
/** Part du plateau comparée au début et à la fin. */
const WINDOW = 0.2;

export const options = {
  scenarios: {
    endurance: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [{ target: VUS, duration: RAMP }, { target: VUS, duration: PLATEAU }],
      gracefulRampDown: "30s",
      gracefulStop: "30s",
    },
  },
  thresholds: k6Thresholds(SCENARIO, __ENV, routeMetrics(JOURNEE_ROUTES, "groupe:journee")),
  summaryTrendStats: [...TREND_STATS],
};

function periode() {
  const t = (Date.now() - exec.scenario.startTime) / 1000 - RAMP_S;
  if (t < 0) return "montee";
  if (t < WINDOW * PLATEAU_S) return "debut";
  if (t >= (1 - WINDOW) * PLATEAU_S) return "fin";
  return "milieu";
}

export function setup() {
  return { public: { serveur: serverInfo() } };
}

export default function () {
  journeeIteration({ pause: PAUSE, tags: { periode: periode() } });
}

export const handleSummary = makeSummary(SCENARIO, { vus: VUS, ramp_s: RAMP_S, plateau_s: PLATEAU_S, fenetre: WINDOW });
