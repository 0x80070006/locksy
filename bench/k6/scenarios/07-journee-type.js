// 07 · Journée type : VUS utilisateurs actifs (50, 200 ou 500), montée en
// RAMP (3 min), plateau de DURATION (20 min), pause de PAUSE s (10) ± 50 %
// entre deux actions ; répartition de l'audit 05 §10.1 (lib/journee.js).
// Les seuils dépendent de VUS (lib/thresholds.js).
import { serverInfo, envInt, envDuration, seconds } from "../lib/common.js";
import { journeeIteration, JOURNEE_ROUTES } from "../lib/journee.js";
import { k6Thresholds, routeMetrics, TREND_STATS } from "../lib/thresholds.js";
import { makeSummary } from "../lib/summary.js";

const SCENARIO = "07-journee-type";
const VUS = envInt("VUS", 50);
const RAMP = envDuration("RAMP", "3m");
const PLATEAU = envDuration("DURATION", "20m");
const PAUSE = envInt("PAUSE", 10);

export const options = {
  scenarios: {
    journee: {
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

export function setup() {
  return { public: { serveur: serverInfo() } };
}

export default function () {
  journeeIteration({ pause: PAUSE });
}

export const handleSummary = makeSummary(SCENARIO, { vus: VUS, ramp_s: seconds(RAMP), plateau_s: seconds(PLATEAU) });
