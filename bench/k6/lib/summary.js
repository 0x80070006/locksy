// Fin de passe commune : écrit le résumé JSON lu par bench/scripts/report.mjs
// (/bench/results/<RUN>/summary.json, ou summary-<PHASE>.json) et un court
// bilan en français sur la sortie standard.
import { criteria, OBSERVATIONS } from "./thresholds.js";

/** Variables de la passe reprises dans le résumé (aucun secret). */
const ENV_KEYS = ["DATASET", "VUS", "DURATION", "RAMP", "RATE", "PAUSE", "PHASE", "NOMINAL_P95", "MAX_RATE", "PALIER", "SIZES", "RUN"];

/** Fichier de résumé d'une passe. */
function summaryPath(phase) {
  const run = __ENV.RUN || "manuel";
  const dir = __ENV.RESULTS_DIR || `/bench/results/${run}`;
  return `${dir}/${phase ? `summary-${phase}` : "summary"}.json`;
}

function fmt(v) {
  if (typeof v !== "number") return String(v);
  return Math.abs(v) >= 100 ? v.toFixed(0) : v.toFixed(2);
}

/** Bilan texte : un critère k6 par ligne (le rapport complet juge aussi le système). */
function textReport(scenario, data, crit) {
  const lines = [`\nScénario ${scenario} : ${data.state && data.state.testRunDurationMs ? Math.round(data.state.testRunDurationMs / 1000) : "?"} s`];
  for (const c of crit) {
    if (c.source !== "k6") continue;
    const m = data.metrics[c.metric];
    const t = m && m.thresholds && m.thresholds[c.expr];
    const state = c.mesure ? "mesure" : !t ? "non mesuré" : t.ok ? "respecté" : "dépassé";
    const vals = m ? Object.keys(m.values).map((k) => `${k}=${fmt(m.values[k])}`).join(" ") : "";
    lines.push(`  [${state}] ${c.label} (${c.metric} ${c.expr}) ${vals}`);
  }
  lines.push("  Verdict complet (système, jeu, preflight) : rapport.md de la passe (bench/scripts/report.mjs).\n");
  return lines.join("\n");
}

/** handleSummary d'un scénario. `meta` : informations propres (phases, durées…). */
export function makeSummary(scenario, meta) {
  return function handleSummary(data) {
    const env = {};
    for (const k of ENV_KEYS) if (__ENV[k] !== undefined && __ENV[k] !== "") env[k] = __ENV[k];
    const crit = criteria(scenario, __ENV);
    const doc = {
      format: 1,
      scenario,
      phase: __ENV.PHASE || null,
      env,
      meta: meta || {},
      // Seule la partie « public » des données de setup est gardée (jamais de jeton).
      setup: data.setup_data && data.setup_data.public ? data.setup_data.public : null,
      criteria: crit.map((c) => c.id),
      observations: OBSERVATIONS,
      k6: { state: data.state, metrics: data.metrics, root_group: { checks: data.root_group ? data.root_group.checks : [] } },
    };
    return {
      stdout: textReport(scenario, data, crit),
      [summaryPath(__ENV.PHASE)]: JSON.stringify(doc, null, 1),
    };
  };
}
