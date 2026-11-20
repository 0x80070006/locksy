#!/usr/bin/env node
// Verdict du scan ZAP baseline (G13) : 0 alerte de risque élevé ou moyen.
//
//   node e2e/security/zap/verdict.mjs <rapport zap.json>
//
// Affiche chaque alerte (risque, identifiant, nom, nombre d'occurrences) et
// sort en 1 s'il en reste une de risque élevé ou moyen, en 2 si le rapport
// est illisible. Sans dépendance.

import { readFileSync } from "node:fs";

const fichier = process.argv[2];
if (!fichier) {
  console.error("Usage : node e2e/security/zap/verdict.mjs <zap.json>");
  process.exit(2);
}
let rapport;
try {
  rapport = JSON.parse(readFileSync(fichier, "utf8"));
} catch (e) {
  console.error(`verdict ZAP : rapport illisible (${fichier}) : ${e.message}`);
  process.exit(2);
}

const RISQUES = { 3: "élevé", 2: "moyen", 1: "faible", 0: "information" };
/** Alertes sur le scanner et non sur la cible : 10116 « ZAP is Out of Date » (version épinglée exprès). */
const HORS_CIBLE = new Set(["10116"]);
const alertes = (rapport.site || []).flatMap((s) => s.alerts || []).filter((a) => !HORS_CIBLE.has(String(a.pluginid)));
alertes.sort((a, b) => Number(b.riskcode) - Number(a.riskcode));
for (const a of alertes) {
  console.log(`  [${RISQUES[a.riskcode] ?? a.riskcode}] ${a.pluginid} ${a.alert} (${a.count ?? (a.instances || []).length} occurrence(s))`);
}
const graves = alertes.filter((a) => Number(a.riskcode) >= 2);
if (graves.length) {
  console.error(`verdict ZAP : ${graves.length} alerte(s) de risque élevé ou moyen.`);
  process.exit(1);
}
console.log(`verdict ZAP : 0 alerte de risque élevé ou moyen (${alertes.length} alerte(s) au total).`);
