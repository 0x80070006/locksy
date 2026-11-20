#!/usr/bin/env node
// Rapport d'une recette d'exploitation : lit les contrôles (.resultats.tsv) et
// les mesures (.mesures.tsv) écrits par ops-tests/lib.sh, puis produit
// resultats.json et resultats.md dans le même dossier.
//
//   node ops-tests/lib/rapport.mjs <dossier> <script> [jeu]
//
// Codes de sortie : 0 rapport écrit, 2 usage invalide.

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

const ETATS = { ok: "OK", echec: "ÉCHEC", info: "constat" };

function lireTsv(fichier) {
  if (!existsSync(fichier)) return [];
  return readFileSync(fichier, "utf8").split("\n").filter(Boolean).map((l) => l.split("\t"));
}

/** Échappe une cellule de tableau Markdown. */
const cellule = (s) => String(s ?? "").replace(/\|/g, "\\|");

function construire(dossier, script, jeu) {
  const controles = lireTsv(resolve(dossier, ".resultats.tsv")).map(([nom, etat, detail = ""]) => ({ nom, etat, detail }));
  const mesures = lireTsv(resolve(dossier, ".mesures.tsv")).map(([nom, valeur, unite = ""]) => ({ nom, valeur, unite }));
  const echecs = controles.filter((c) => c.etat === "echec").length;
  return {
    script,
    jeu: jeu || null,
    date: new Date().toISOString(),
    verdict: echecs === 0 && controles.length > 0 ? "réussite" : "échec",
    echecs,
    controles,
    mesures,
  };
}

function markdown(r) {
  const lignes = [
    `# Recette ${r.script}${r.jeu ? ` (jeu ${r.jeu})` : ""}`,
    "",
    `Date : ${r.date}. Verdict : **${r.verdict}**${r.echecs ? ` (${r.echecs} contrôle(s) en échec)` : ""}.`,
    "",
    "## Contrôles",
    "",
    "| Contrôle | État | Détail |",
    "|---|---|---|",
    ...r.controles.map((c) => `| ${cellule(c.nom)} | ${ETATS[c.etat] || c.etat} | ${cellule(c.detail)} |`),
  ];
  if (r.mesures.length) {
    lignes.push("", "## Mesures", "", "| Mesure | Valeur | Unité |", "|---|---|---|",
      ...r.mesures.map((m) => `| ${cellule(m.nom)} | ${cellule(m.valeur)} | ${cellule(m.unite)} |`));
  }
  return `${lignes.join("\n")}\n`;
}

function main(argv) {
  const [dossier, script, jeu] = argv;
  if (!dossier || !script) {
    process.stderr.write("Usage : node ops-tests/lib/rapport.mjs <dossier> <script> [jeu]\n");
    return 2;
  }
  const r = construire(dossier, script, jeu);
  writeFileSync(resolve(dossier, "resultats.json"), `${JSON.stringify(r, null, 2)}\n`);
  writeFileSync(resolve(dossier, "resultats.md"), markdown(r));
  process.stderr.write(`Rapport : ${resolve(dossier, "resultats.md")} (${r.verdict})\n`);
  return 0;
}

process.exitCode = main(process.argv.slice(2));
