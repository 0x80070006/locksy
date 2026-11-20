#!/usr/bin/env node
// Latences d'une passe k6 par fenêtre de temps, à partir de la sortie
// `k6 run --out json=<fichier>` (un point par ligne). Sert à comparer le p95
// des écritures avant et pendant une sauvegarde à chaud (critère G29).
//
//   node ops-tests/lib/k6.mjs --points <fichier> --fenetre nominal=<début ms>,<fin ms> \
//        --fenetre pendant=<début ms>,<fin ms> [--fenetre …]
//
// Pour chaque fenêtre : nombre de requêtes, p50 et p95 des écritures
// (création, modification, mise à la corbeille), p95 de /sync, requêtes en
// échec (http_req_failed) et statuts 5xx. Les bornes sont des millisecondes
// epoch, lues sur l'horloge des conteneurs (même machine virtuelle que k6).
//
// Codes de sortie : 0 réussite, 1 fichier illisible, 2 usage invalide.

import { createReadStream, existsSync } from "node:fs";
import { createInterface } from "node:readline";

const ECRITURES = new Set(["element_creation", "element_maj", "element_corbeille"]);
const SYNC = "sync";

const USAGE = `Latences d'une passe k6 par fenêtre de temps.

Usage : node ops-tests/lib/k6.mjs --points <fichier json k6> --fenetre <nom>=<début ms>,<fin ms> [--fenetre …]`;

function centile(valeurs, p) {
  if (!valeurs.length) return null;
  const tri = [...valeurs].sort((a, b) => a - b);
  const rang = Math.min(tri.length - 1, Math.max(0, Math.ceil((p / 100) * tri.length) - 1));
  return Math.round(tri[rang] * 10) / 10;
}

function lireOptions(argv) {
  const out = { fenetres: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const v = argv[i + 1];
    if (a === "--points" && v) { out.points = v; i++; continue; }
    if (a === "--fenetre" && v) {
      const m = /^([a-z0-9_-]+)=(\d+),(\d+)$/i.exec(v);
      if (!m) throw new Error(`fenêtre invalide : ${v} (attendu : nom=début,fin en millisecondes)`);
      out.fenetres.push({ nom: m[1], debut: Number(m[2]), fin: Number(m[3]) });
      i++;
      continue;
    }
    throw new Error(`option invalide : ${a}`);
  }
  if (!out.points || !out.fenetres.length) throw new Error("--points et au moins une --fenetre sont obligatoires");
  return out;
}

async function analyser({ points, fenetres }) {
  if (!existsSync(points)) throw new Error(`fichier de points introuvable : ${points}`);
  const acc = new Map(fenetres.map((f) => [f.nom, { ...f, requetes: 0, ecritures: [], sync: [], echecs: 0, statuts_5xx: 0 }]));
  const lignes = createInterface({ input: createReadStream(points), crlfDelay: Infinity });
  let premier = null;
  let dernier = null;
  for await (const ligne of lignes) {
    if (!ligne.includes('"metric":"http_req_')) continue;
    let p;
    try { p = JSON.parse(ligne); } catch { continue; }
    if (p.type !== "Point") continue;
    const m = p.metric;
    if (m !== "http_req_duration" && m !== "http_req_failed") continue;
    const t = Date.parse(p.data.time);
    premier ??= t;
    dernier = t;
    const tags = p.data.tags || {};
    for (const f of acc.values()) {
      if (t < f.debut || t > f.fin) continue;
      if (m === "http_req_failed") {
        if (p.data.value) f.echecs += 1;
        continue;
      }
      f.requetes += 1;
      if (String(tags.status || "").startsWith("5")) f.statuts_5xx += 1;
      if (ECRITURES.has(tags.name)) f.ecritures.push(p.data.value);
      else if (tags.name === SYNC) f.sync.push(p.data.value);
    }
  }
  return {
    points,
    premier_point_ms: premier,
    dernier_point_ms: dernier,
    fenetres: Object.fromEntries([...acc.values()].map((f) => [f.nom, {
      debut_ms: f.debut,
      fin_ms: f.fin,
      duree_s: Math.round((f.fin - f.debut) / 100) / 10,
      requetes: f.requetes,
      ecritures: f.ecritures.length,
      ecritures_p50_ms: centile(f.ecritures, 50),
      ecritures_p95_ms: centile(f.ecritures, 95),
      sync_p95_ms: centile(f.sync, 95),
      echecs: f.echecs,
      statuts_5xx: f.statuts_5xx,
    }])),
  };
}

async function main(argv) {
  let opts;
  try {
    opts = lireOptions(argv);
  } catch (e) {
    process.stderr.write(`Erreur : ${e.message}\n\n${USAGE}\n`);
    return 2;
  }
  try {
    process.stdout.write(`${JSON.stringify(await analyser(opts), null, 2)}\n`);
    return 0;
  } catch (e) {
    process.stderr.write(`Erreur : ${e.message}\n`);
    return 1;
  }
}

process.exitCode = await main(process.argv.slice(2));
