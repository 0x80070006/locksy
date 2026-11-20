#!/usr/bin/env node
// Rapport d'une passe de charge (Node 20 ou plus, sans dépendance) :
// lit bench/results/<passe>/{summary*.json, stats.csv, context.json,
// redemarrages.csv}, juge chaque seuil de bench/k6/lib/thresholds.js et écrit
// rapport.md avec les courbes cpu.svg, memoire.svg et pids.svg (SVG statiques,
// sans script). Mode d'emploi : bench/k6/README.md.
//
// Verdict par seuil :
//   PASSE      seuil applicable et respecté ;
//   ÉCHEC      seuil applicable et dépassé ;
//   INDICATIF  seuil non applicable à cette passe (jeu différent de celui du
//              seuil, preflight.sh à 1 ou inconnu pour un seuil de
//              performance) ou non mesuré ; la colonne « Mesuré » dit s'il
//              aurait été respecté.
// Code de sortie : 0 passe (ou indicative sans dépassement), 1 échec d'un
// seuil bloquant, 2 passe inexploitable (pas de résumé k6, usage), 3
// indicative avec au moins un seuil bloquant dépassé.
import { readFileSync, writeFileSync, existsSync, readdirSync } from "node:fs";
import { join, resolve, basename } from "node:path";
import { pathToFileURL } from "node:url";
import { criteria, SCENARIOS } from "../k6/lib/thresholds.js";

const USAGE = `Rapport d'une passe de charge Locksy.

Usage : node bench/scripts/report.mjs <dossier de la passe> [--reference <dossier d'une passe 07-200>]

  Écrit <dossier>/rapport.md, cpu.svg, memoire.svg et pids.svg.
  --reference  passe de comparaison du scénario 11 (p95 de la journée type)

Codes de sortie : 0 passe, 1 échec, 2 passe inexploitable ou usage, 3 indicative avec dépassement.`;

// ---------------------------------------------------------------- Lecture

function readJson(file) {
  return existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : null;
}

/** Une métrique k6 a-t-elle au moins un échantillon ? */
function hasSamples(m) {
  const v = m.values || {};
  if (m.type === "rate") return (v.passes || 0) + (v.fails || 0) > 0;
  if (m.type === "gauge") return v.value !== undefined;
  return (v.count || 0) > 0;
}

/** Résumés k6 de la passe (summary.json puis summary-<phase>.json), métriques fusionnées. */
export function loadSummaries(dir) {
  const files = existsSync(dir) ? readdirSync(dir).filter((f) => /^summary(-[a-z0-9_-]+)?\.json$/i.test(f)).sort() : [];
  if (files.length === 0) return null;
  const all = files.map((f) => readJson(join(dir, f)));
  const main = all.find((d) => !d.phase) || all[0];
  // Résumé principal d'abord : les phases suivantes (vérification du 10)
  // complètent ou remplacent ses métriques.
  const docs = [main, ...all.filter((d) => d !== main)];
  const metrics = {};
  const checks = [];
  for (const d of docs) {
    for (const [name, m] of Object.entries(d.k6.metrics)) {
      if (!metrics[name] || hasSamples(m)) metrics[name] = m;
    }
    for (const c of (d.k6.root_group && d.k6.root_group.checks) || []) checks.push(c);
  }
  return { scenario: main.scenario, env: main.env || {}, meta: main.meta || {}, setup: main.setup, metrics, checks, phases: docs.map((d) => d.phase || "principale"), state: main.k6.state };
}

/** Relevé de sample-stats.sh : une ligne par seconde environ. */
export function parseStats(text) {
  const lines = text.split(/\r?\n/).filter((l) => l.trim() !== "");
  if (lines.length < 2) return [];
  const head = lines[0].split(",");
  const idx = (k) => head.indexOf(k);
  const num = (v) => (v === undefined || v === "" ? null : Number(v));
  return lines.slice(1).map((l) => {
    const c = l.split(",");
    return {
      t: num(c[idx("epoch_ms")]),
      cpu: num(c[idx("cpu_pct")]),
      mem: num(c[idx("mem_mio")]),
      limit: num(c[idx("mem_limite_mio")]),
      pids: num(c[idx("pids")]),
      oom: c[idx("oom_killed")] === "true",
      restarts: num(c[idx("redemarrages")]),
      state: c[idx("etat")] || "",
    };
  }).filter((r) => r.t !== null);
}

// ---------------------------------------------------------------- Calculs

const mean = (a) => (a.length ? a.reduce((x, y) => x + y, 0) / a.length : null);
const median = (a) => {
  if (!a.length) return null;
  const s = [...a].sort((x, y) => x - y);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
};
const values = (rows, k) => rows.map((r) => r[k]).filter((v) => v !== null && Number.isFinite(v));
const maxOf = (a) => (a.length ? Math.max(...a) : null);

/**
 * Statistiques système de la passe. Fenêtre = durée de k6 (context.json) ;
 * base mémoire = médiane des relevés avant k6 (sinon le premier).
 */
export function systemStats(rows, ctx, meta) {
  const start = ctx && ctx.k6_debut_ms;
  const end = ctx && ctx.k6_fin_ms;
  const win = rows.filter((r) => (!start || r.t >= start) && (!end || r.t <= end));
  const before = start ? rows.filter((r) => r.t < start) : [];
  const memBase = median(values(before, "mem")) ?? (values(rows, "mem")[0] ?? null);
  const memMax = maxOf(values(win, "mem"));
  let stops = 0;
  for (let i = 1; i < win.length; i++) if (win[i - 1].state === "running" && win[i].state && win[i].state !== "running") stops += 1;
  const restarts = values(rows, "restarts");
  const out = {
    lignes: rows.length,
    cpu_moy: mean(values(win, "cpu")),
    cpu_max: maxOf(values(win, "cpu")),
    mem_base: memBase,
    mem_max: memMax,
    mem_delta: memMax !== null && memBase !== null ? memMax - memBase : null,
    mem_limite: maxOf(values(rows, "limit")),
    pids_max: maxOf(values(win, "pids")),
    oom: rows.filter((r) => r.oom).length,
    redemarrages: (restarts.length ? Math.max(...restarts) - Math.min(...restarts) : 0) + stops,
  };
  // Dérives (08, meta.fenetre) : premier et dernier cinquième du plateau
  // (sinon de la fenêtre de k6).
  if (meta && meta.fenetre && win.length) {
    const fen = meta.fenetre;
    const p0 = start && meta.plateau_s ? start + (meta.ramp_s || 0) * 1000 : win[0].t;
    const p = start && meta.plateau_s ? meta.plateau_s * 1000 : win[win.length - 1].t - win[0].t;
    const [a0, a1, b0, b1] = [p0, p0 + fen * p, p0 + (1 - fen) * p, p0 + p];
    const first = rows.filter((r) => r.t >= a0 && r.t <= a1);
    const last = rows.filter((r) => r.t >= b0 && r.t <= b1);
    const m0 = mean(values(first, "mem"));
    const m1 = mean(values(last, "mem"));
    out.derive_rss_pct = m0 && m1 !== null ? Math.abs(m1 - m0) / m0 * 100 : null;
    const q0 = median(values(first, "pids"));
    const q1 = median(values(last, "pids"));
    out.derive_pids = q0 !== null && q1 !== null ? Math.abs(q1 - q0) : null;
  }
  return out;
}

const EXPR = /^(avg|min|med|max|count|rate|value|p\(\d+(?:\.\d+)?\))\s*(<=|>=|===|==|!=|<|>)\s*(-?\d+(?:\.\d+)?)$/;

/** Comparaison d'une valeur à un seuil. */
export function compare(value, op, target) {
  switch (op) {
    case "<": return value < target;
    case "<=": return value <= target;
    case ">": return value > target;
    case ">=": return value >= target;
    case "==":
    case "===": return value === target;
    case "!=": return value !== target;
    default: throw new Error(`Opérateur inconnu : ${op}`);
  }
}

/** Valeur d'une métrique k6 ; un compteur absent vaut 0 (aucun évènement). */
function metricValue(metrics, name, field) {
  const m = metrics[name];
  if (!m) return field === "count" ? 0 : null;
  if (m.type === "rate" && (m.values.passes || 0) + (m.values.fails || 0) === 0) return null;
  if (m.type === "trend" && !m.values.count) return null;
  const v = m.values[field];
  return v === undefined ? null : v;
}

/** Mesure d'un critère : { value, ok (null = non mesuré), note }. */
export function measure(c, ctx) {
  const { metrics, sys, meta, env, run, reference } = ctx;
  switch (c.source) {
    case "k6": {
      const m = EXPR.exec(c.expr);
      if (!m) return { value: null, ok: null, note: `expression illisible : ${c.expr}` };
      const [, field, op, target] = m;
      const value = metricValue(metrics, c.metric, field);
      if (value === null) return { value: null, ok: null, note: "non mesuré" };
      const flag = metrics[c.metric] && metrics[c.metric].thresholds && metrics[c.metric].thresholds[c.expr];
      return { value, field, ok: flag ? flag.ok : compare(value, op, Number(target)) };
    }
    case "stats": {
      const value = sys ? sys[c.stat] : null;
      if (value === null || value === undefined) return { value: null, ok: null, note: "relevé système absent" };
      return { value, ok: compare(value, c.op, c.value) };
    }
    case "derive":
      return derive(c, metrics, meta, env);
    case "run": {
      const value = run ? run[c.key] : undefined;
      if (value === undefined || value === null) return { value: null, ok: null, note: "non mesuré par run.sh" };
      return { value, ok: c.op ? compare(value, c.op, c.value) : null };
    }
    case "reference": {
      const cur = metricValue(metrics, c.metric, c.field);
      const ref = reference ? metricValue(reference.metrics, c.metric, c.field) : null;
      if (cur === null) return { value: null, ok: null, note: "non mesuré" };
      if (ref === null) return { value: null, ok: null, note: "passe de référence absente (run.sh --reference)" };
      const pct = (cur - ref) / ref * 100;
      return { value: pct, ok: pct <= c.value, note: `${fmtNum(cur)} ms contre ${fmtNum(ref)} ms (${reference.name}) ; seule une hausse compte` };
    }
    default:
      return { value: null, ok: null, note: `source inconnue : ${c.source}` };
  }
}

/** Paliers du scénario 02d : débit obtenu, p95, échecs. */
export function capacityTable(metrics, meta) {
  const rows = [];
  for (const r of (meta && meta.paliers) || []) {
    const d = metrics[`http_req_duration{name:connexion,palier:${r}}`];
    const f = metrics[`http_req_failed{name:connexion,palier:${r}}`];
    const n = metrics[`http_reqs{name:connexion,palier:${r}}`];
    const count = n ? n.values.count : 0;
    if (!count) continue;
    const p95 = d ? d.values["p(95)"] : null;
    const errors = f ? f.values.rate : 0;
    rows.push({ palier: r, obtenu: count / ((meta.palier_s || 60) + (meta.transition_s || 0)), p95, erreurs: errors, ok: p95 !== null && p95 < 1000 && errors < 0.01 });
  }
  return rows;
}

function derive(c, metrics, meta, env) {
  if (c.kind === "debit") {
    const n = metricValue(metrics, c.metric, "count");
    const secs = meta && meta.phases ? meta.phases[c.phase] : null;
    if (!n || !secs) return { value: null, ok: null, note: "non mesuré" };
    const value = n / secs;
    return { value, ok: compare(value, c.op, c.value) };
  }
  if (c.kind === "ecart") {
    const a = metricValue(metrics, c.metric, c.field);
    const b = metricValue(metrics, c.metric2, c.field);
    if (!a || b === null) return { value: null, ok: null, note: "début ou fin non mesuré" };
    const value = Math.abs(b - a) / a * 100;
    return { value, ok: compare(value, c.op, c.value), note: `${fmtNum(a)} ms au début, ${fmtNum(b)} ms à la fin` };
  }
  if (c.kind === "capacite") {
    const rows = capacityTable(metrics, meta);
    if (!rows.length) return { value: null, ok: null, note: "aucun palier mesuré" };
    let best = null;
    for (const r of rows) {
      if (!r.ok) break;
      best = r.palier;
    }
    const top = rows[rows.length - 1];
    const note = best === null
      ? "p95 > 1 s dès le premier palier"
      : best === top.palier ? `aucune saturation jusqu'au dernier palier (MAX_RATE=${(env && env.MAX_RATE) || top.palier}) : relancer plus haut` : `saturation au palier suivant`;
    return { value: best, ok: null, note };
  }
  return { value: null, ok: null, note: `calcul inconnu : ${c.kind}` };
}

/**
 * Verdict d'un critère. Applicable si le jeu est celui du seuil (ou si le
 * seuil vaut pour tout jeu) et, pour un seuil de performance, si preflight.sh
 * a rendu 0.
 */
export function verdict(c, m, ctx) {
  const datasetOk = !c.dataset || c.dataset === ctx.dataset;
  const posteOk = c.fonctionnel || ctx.preflight === 0;
  const reasons = [];
  if (!datasetOk) reasons.push(`seuil défini pour le jeu ${c.dataset}`);
  if (!posteOk) reasons.push(ctx.preflight === 1 ? "preflight à 1 (mesures indicatives)" : "preflight inconnu");
  if (m.ok === null) return { verdict: "INDICATIF", depasse: false, raison: m.note || "non mesuré" };
  if (reasons.length) return { verdict: "INDICATIF", depasse: !m.ok, raison: `${m.ok ? "respecté" : "dépassé"} ; ${reasons.join(", ")}` };
  return { verdict: m.ok ? "PASSE" : "ÉCHEC", depasse: !m.ok, raison: m.note || "" };
}

/** Jugement complet d'une passe : critères, verdict global, code de sortie. */
export function judge(input) {
  const crit = criteria(input.scenario, input.env);
  const rows = crit.map((c) => {
    const m = measure(c, input);
    return Object.assign({ c, m }, c.mesure ? { verdict: "MESURE", depasse: false, raison: m.note || "" } : verdict(c, m, input));
  });
  const blocking = rows.filter((r) => !r.c.mesure && r.c.bloquant);
  let global = "PASSE";
  let code = 0;
  if (blocking.some((r) => r.verdict === "ÉCHEC")) {
    global = "ÉCHEC";
    code = 1;
  } else if (blocking.some((r) => r.verdict === "INDICATIF")) {
    global = "INDICATIF";
    code = blocking.some((r) => r.depasse) ? 3 : 0;
  }
  return { rows, global, code };
}

// ---------------------------------------------------------------- Mise en forme

export function fmtNum(v, digits) {
  if (v === null || v === undefined || Number.isNaN(v)) return "–";
  if (typeof v !== "number") return String(v);
  const d = digits === undefined ? (Math.abs(v) >= 100 ? 0 : Math.abs(v) >= 10 ? 1 : 2) : digits;
  return v.toLocaleString("fr-FR", { minimumFractionDigits: 0, maximumFractionDigits: d });
}

function fmtBytes(v) {
  if (v === null || v === undefined) return "–";
  if (v >= 1048576) return `${fmtNum(v / 1048576)} Mio`;
  if (v >= 1024) return `${fmtNum(v / 1024)} Kio`;
  return `${fmtNum(v)} o`;
}

/** Valeur mesurée lisible, selon l'unité du critère. */
function fmtMeasured(c, m) {
  if (m.value === null || m.value === undefined) return "–";
  if (c.source === "reference") return `${m.value >= 0 ? "+" : ""}${fmtNum(m.value, 1)} %`;
  if (c.unit === "%" && m.field === "rate") return `${fmtNum(m.value * 100, 3)} %`;
  if (c.unit === "o") return fmtBytes(m.value);
  if (typeof m.value === "number") return `${fmtNum(m.value)}${c.unit ? ` ${c.unit}` : ""}`;
  return String(m.value);
}

/** Seuil attendu lisible. */
function fmtExpected(c) {
  if (c.mesure) return "valeur publiée";
  if (c.source === "k6") {
    const m = EXPR.exec(c.expr);
    if (!m) return c.expr;
    const [, field, op, target] = m;
    const t = Number(target);
    const shown = c.unit === "%" && field === "rate" ? `${fmtNum(t * 100, 3)} %` : c.unit === "o" ? fmtBytes(t) : `${fmtNum(t)}${c.unit ? ` ${c.unit}` : ""}`;
    return `${field} ${op2(op)} ${shown}`;
  }
  if (c.op) return `${op2(c.op)} ${typeof c.value === "number" ? fmtNum(c.value) : c.value}${c.unit ? ` ${c.unit}` : ""}`;
  return "–";
}
const op2 = (op) => ({ "<": "<", "<=": "≤", ">": ">", ">=": "≥", "==": "=", "===": "=", "!=": "≠" })[op] || op;

const md = (s) => String(s).replace(/\|/g, "\\|");

/** Tableau par route : requêtes, p50, p95, p99, max, échecs. */
export function routeTable(metrics) {
  const out = [];
  for (const name of Object.keys(metrics)) {
    const m = /^http_req_duration\{name:([^,}]+)((?:,[^}]*)?)\}$/.exec(name);
    if (!m) continue;
    const suffix = m[2];
    const d = metrics[name].values;
    const reqs = metrics[`http_reqs{name:${m[1]}${suffix}}`];
    const failed = metrics[`http_req_failed{name:${m[1]}${suffix}}`];
    const count = reqs ? reqs.values.count : d.count;
    if (!count) continue;
    out.push({ route: m[1], tags: suffix.replace(/^,/, ""), count, p50: d.med, p95: d["p(95)"], p99: d["p(99)"], max: d.max, erreurs: failed ? failed.values.rate : 0 });
  }
  return out.sort((a, b) => a.route.localeCompare(b.route) || a.tags.localeCompare(b.tags));
}

// ---------------------------------------------------------------- Courbes SVG

const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/**
 * Courbe SVG statique (aucun script, aucune ressource externe) : valeur en
 * fonction du temps, fenêtre de k6 grisée, seuil éventuel en pointillés.
 */
export function svgChart({ title, unit, rows, key, start, end, limit, limitLabel }) {
  const W = 800;
  const H = 240;
  const L = 60;
  const R = 16;
  const T = 34;
  const B = 36;
  const pts = rows.filter((r) => r[key] !== null && Number.isFinite(r[key]));
  const t0 = rows.length ? rows[0].t : 0;
  const t1 = rows.length ? rows[rows.length - 1].t : 1;
  const span = Math.max(1, t1 - t0);
  const vmax = Math.max(1, limit || 0, ...pts.map((r) => r[key])) * 1.1;
  const x = (t) => L + (t - t0) / span * (W - L - R);
  const y = (v) => T + (1 - v / vmax) * (H - T - B);
  const parts = [];
  parts.push(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-labelledby="t d">`);
  parts.push(`<title id="t">${esc(title)}</title>`);
  parts.push(`<desc id="d">${esc(`${title} en ${unit}, de 0 à ${fmtNum(span / 60000, 1)} min ; maximum ${fmtNum(maxOf(pts.map((r) => r[key])))} ${unit}.`)}</desc>`);
  parts.push(`<rect x="0" y="0" width="${W}" height="${H}" fill="#ffffff"/>`);
  if (start && end) {
    parts.push(`<rect x="${x(Math.max(start, t0)).toFixed(1)}" y="${T}" width="${Math.max(0, x(Math.min(end, t1)) - x(Math.max(start, t0))).toFixed(1)}" height="${H - T - B}" fill="#eef1f6"/>`);
  }
  for (let i = 0; i <= 4; i++) {
    const v = vmax / 1.1 * i / 4;
    parts.push(`<line x1="${L}" y1="${y(v).toFixed(1)}" x2="${W - R}" y2="${y(v).toFixed(1)}" stroke="#d5d9e0" stroke-width="1"/>`);
    parts.push(`<text x="${L - 6}" y="${(y(v) + 4).toFixed(1)}" font-family="sans-serif" font-size="11" text-anchor="end" fill="#444b55">${esc(fmtNum(v, 0))}</text>`);
  }
  const minutes = span / 60000;
  const step = minutes > 60 ? 15 : minutes > 20 ? 5 : minutes > 5 ? 1 : 0.5;
  for (let mnt = 0; mnt <= minutes + 1e-9; mnt += step) {
    const xx = x(t0 + mnt * 60000);
    parts.push(`<text x="${xx.toFixed(1)}" y="${H - B + 16}" font-family="sans-serif" font-size="11" text-anchor="middle" fill="#444b55">${esc(fmtNum(mnt, 1))}</text>`);
  }
  parts.push(`<text x="${(L + W - R) / 2}" y="${H - 4}" font-family="sans-serif" font-size="11" text-anchor="middle" fill="#444b55">minutes</text>`);
  parts.push(`<text x="${L}" y="20" font-family="sans-serif" font-size="14" font-weight="bold" fill="#1d232b">${esc(`${title} (${unit})`)}</text>`);
  if (limit) {
    parts.push(`<line x1="${L}" y1="${y(limit).toFixed(1)}" x2="${W - R}" y2="${y(limit).toFixed(1)}" stroke="#b42318" stroke-width="1.5" stroke-dasharray="6 4"/>`);
    parts.push(`<text x="${W - R}" y="${(y(limit) - 5).toFixed(1)}" font-family="sans-serif" font-size="11" text-anchor="end" fill="#b42318">${esc(limitLabel || `seuil ${fmtNum(limit)}`)}</text>`);
  }
  // Une ligne brisée par segment continu (un relevé vide coupe la courbe).
  let seg = [];
  const flush = () => {
    if (seg.length > 1) parts.push(`<polyline fill="none" stroke="#1f5fbf" stroke-width="1.6" points="${seg.join(" ")}"/>`);
    else if (seg.length === 1) {
      const [px, py] = seg[0].split(",");
      parts.push(`<circle cx="${px}" cy="${py}" r="1.6" fill="#1f5fbf"/>`);
    }
    seg = [];
  };
  for (const r of rows) {
    if (r[key] === null || !Number.isFinite(r[key])) flush();
    else seg.push(`${x(r.t).toFixed(1)},${y(r[key]).toFixed(1)}`);
  }
  flush();
  parts.push(`<line x1="${L}" y1="${H - B}" x2="${W - R}" y2="${H - B}" stroke="#444b55" stroke-width="1"/>`);
  parts.push("</svg>");
  return `${parts.join("\n")}\n`;
}

/** Seuil système d'une statistique, pour la tracer sur sa courbe. */
function statLimit(rows, stat) {
  const c = rows.find((r) => r.c.source === "stats" && r.c.stat === stat);
  return c ? { limit: c.c.value, label: `seuil ${fmtNum(c.c.value)}` } : null;
}

// ---------------------------------------------------------------- Rapport

const PREFLIGHT = { 0: "0 : conforme, mesures valables", 1: "1 : avertissements, mesures indicatives", 2: "2 : bloquant" };

/** Texte du rapport (Markdown). */
export function renderReport(input, result) {
  const { scenario, ctx, sys, metrics } = input;
  const info = SCENARIOS[scenario] || { titre: scenario, jeu: null };
  const L = [];
  const label = { PASSE: "PASSE", "ÉCHEC": "ÉCHEC", INDICATIF: "INDICATIF" }[result.global];
  L.push(`# Rapport de charge : ${info.titre}`, "");
  const precision = result.global === "INDICATIF"
    ? (result.code === 3 ? " (au moins un seuil bloquant dépassé)" : " (aucun seuil bloquant dépassé)")
    : result.rows.some((r) => !r.c.mesure && r.c.bloquant) ? "" : " (aucun seuil bloquant : valeurs publiées)";
  L.push(`**Verdict : ${label}**${precision}`, "");
  L.push("## Contexte", "", "| Élément | Valeur |", "|---|---|");
  const row = (k, v) => L.push(`| ${md(k)} | ${md(v === undefined || v === null || v === "" ? "–" : v)} |`);
  row("Passe", ctx.run || input.name);
  row("Scénario", `${scenario}${input.phases && input.phases.length > 1 ? ` (phases : ${input.phases.join(", ")})` : ""}`);
  row("Jeu", `${ctx.dataset || input.env.DATASET || "?"}${info.jeu ? ` (seuils définis pour ${info.jeu})` : ""}`);
  row("Profil", ctx.profil ? `${ctx.profil} (mémoire ${ctx.memoire})` : ctx.memoire);
  row("Image", ctx.image ? `${ctx.image} (${String(ctx.image_id || "").replace(/^sha256:/, "").slice(0, 12)})` : null);
  row("Version du serveur", ctx.version_serveur || (input.setup && input.setup.serveur && input.setup.serveur.version));
  row("preflight.sh", ctx.preflight === undefined || ctx.preflight === null ? "inconnu (rapport hors run.sh)" : PREFLIGHT[ctx.preflight] || String(ctx.preflight));
  row("Début (UTC)", ctx.k6_debut_ms ? new Date(ctx.k6_debut_ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, "") : null);
  row("Durée de k6", input.state && input.state.testRunDurationMs ? `${fmtNum(input.state.testRunDurationMs / 1000, 0)} s` : null);
  row("Variables de la passe", Object.keys(input.env).filter((k) => k !== "RUN").map((k) => `${k}=${input.env[k]}`).join(", "));
  row("Réglages du serveur", ctx.server_env && Object.keys(ctx.server_env).length ? Object.keys(ctx.server_env).map((k) => `${k}=${ctx.server_env[k]}`).join(", ") : "par défaut");
  row("Docker", ctx.docker ? `${ctx.docker.cpus} processeurs, ${fmtNum(ctx.docker.memoire_gio, 1)} Gio` : null);
  if (ctx.autres_conteneurs) row("Autres conteneurs actifs", ctx.autres_conteneurs);
  L.push("");
  if (ctx.preflight !== 0) {
    L.push("> Docker est partagé avec d'autres charges (ou le poste n'est pas le poste de référence) : les seuils de performance sont **indicatifs**. Seuls les comportements fonctionnels (contrôles, 409, intégrité…) sont jugés.", "");
  }

  L.push("## Seuils", "", "| Critère | Nature | Mesuré | Attendu | Verdict | Remarque |", "|---|---|---|---|---|---|");
  for (const r of result.rows.filter((x) => !x.c.mesure)) {
    L.push(`| ${md(r.c.label)} | ${r.c.bloquant ? "bloquant" : "souhaitable"} | ${md(fmtMeasured(r.c, r.m))} | ${md(fmtExpected(r.c))} | **${r.verdict}** | ${md(r.raison || "")} |`);
  }
  L.push("");
  const mesures = result.rows.filter((x) => x.c.mesure);
  if (mesures.length) {
    L.push("## Mesures publiées", "", "| Mesure | Valeur | Remarque |", "|---|---|---|");
    for (const r of mesures) {
      let v = r.m.value;
      if (r.c.source === "k6" && metrics[r.c.metric] && r.m.value !== null) {
        const vals = metrics[r.c.metric].values;
        if (r.c.unit === "o") v = `moyenne ${fmtBytes(vals.avg)}, max ${fmtBytes(vals.max)}`;
        else if (vals["p(95)"] !== undefined && r.c.unit === "ms") v = `p95 ${fmtNum(vals["p(95)"])} ms (${vals.count} requêtes)`;
        else if (vals.count !== undefined) v = fmtNum(vals.count);
      }
      L.push(`| ${md(r.c.label)} | ${md(v === null || v === undefined ? "–" : typeof v === "number" ? `${fmtNum(v)} ${r.c.unit || ""}`.trim() : v)} | ${md(r.raison || "")} |`);
    }
    L.push("");
  }
  const cap = capacityTable(metrics, input.meta);
  if (cap.length) {
    L.push("### Paliers de connexion", "", "| Palier visé (/s) | Obtenu (/s) | p95 connexion | Échecs | Tenu |", "|---|---|---|---|---|");
    for (const p of cap) L.push(`| ${p.palier} | ${fmtNum(p.obtenu, 1)} | ${fmtNum(p.p95)} ms | ${fmtNum(p.erreurs * 100, 2)} % | ${p.ok ? "oui" : "non"} |`);
    L.push("");
  }

  L.push("## Système", "");
  if (sys) {
    L.push("| Relevé | Valeur |", "|---|---|");
    L.push(`| CPU moyen pendant k6 (200 % = 2 vCPU saturés) | ${fmtNum(sys.cpu_moy)} % |`);
    L.push(`| CPU max | ${fmtNum(sys.cpu_max)} % |`);
    L.push(`| Mémoire au repos (avant k6) | ${fmtNum(sys.mem_base)} Mio |`);
    L.push(`| Mémoire max | ${fmtNum(sys.mem_max)} Mio sur ${fmtNum(sys.mem_limite)} Mio |`);
    L.push(`| Fils (PID) max | ${fmtNum(sys.pids_max)} |`);
    L.push(`| Arrêts pour manque de mémoire | ${sys.oom} |`);
    L.push(`| Redémarrages ou arrêts | ${sys.redemarrages} |`);
    if (sys.derive_rss_pct !== undefined) L.push(`| Dérive de la mémoire (début → fin) | ${fmtNum(sys.derive_rss_pct, 1)} % |`, `| Dérive des PID (début → fin) | ${fmtNum(sys.derive_pids)} |`);
    L.push("", "La zone grisée des courbes est la durée de k6 ; avant elle, le serveur est au repos.", "");
    L.push("![CPU du serveur](cpu.svg)", "", "![Mémoire du serveur](memoire.svg)", "", "![Fils du serveur](pids.svg)", "");
  } else {
    L.push("Relevé système absent (stats.csv) : les seuils de mémoire, de CPU et de PID ne sont pas jugés.", "");
  }

  const routes = routeTable(metrics);
  if (routes.length) {
    L.push("## Par route", "", "| Route | Étiquettes | Requêtes | p50 | p95 | p99 | max | Échecs |", "|---|---|---|---|---|---|---|---|");
    for (const r of routes) {
      L.push(`| ${md(r.route)} | ${md(r.tags || "–")} | ${r.count} | ${fmtNum(r.p50)} ms | ${fmtNum(r.p95)} ms | ${fmtNum(r.p99)} ms | ${fmtNum(r.max)} ms | ${fmtNum(r.erreurs * 100, 2)} % |`);
    }
    L.push("");
  }
  if (input.checks.length) {
    L.push("## Contrôles k6", "", "| Contrôle | Réussis | Échoués |", "|---|---|---|");
    for (const c of input.checks) L.push(`| ${md(c.name)} | ${c.passes} | ${c.fails} |`);
    L.push("");
  }
  if (ctx.redemarrages && ctx.redemarrages.length) {
    L.push("## Arrêts brutaux", "", "| Arrêt | Redémarrage (s) |", "|---|---|");
    ctx.redemarrages.forEach((s, i) => L.push(`| ${i + 1} | ${fmtNum(s, 1)} |`));
    L.push("", `Intégrité de la base après les arrêts : ${ctx.integrite === "ok" ? "PRAGMA integrity_check = ok" : `ÉCHEC (${ctx.integrite || "non vérifiée"})`}.`, "");
  }
  L.push("## Lecture", "");
  L.push("- **PASSE** / **ÉCHEC** : seuil applicable à cette passe, respecté ou dépassé.");
  L.push("- **INDICATIF** : seuil défini pour un autre jeu, poste non conforme (preflight.sh ≠ 0) pour un seuil de performance, ou valeur non mesurée ; la remarque dit s'il aurait été respecté.");
  L.push("- Seuils : cahier §6.3 et audit 05 §3.6 (bench/k6/lib/thresholds.js). Mode d'emploi : bench/k6/README.md.");
  L.push("");
  return L.join("\n");
}

// ---------------------------------------------------------------- Entrée

/** Construit, écrit et juge le rapport d'une passe. Renvoie le code de sortie. */
export function buildReport(dir, opts) {
  const o = opts || {};
  const summary = loadSummaries(dir);
  const ctx = readJson(join(dir, "context.json")) || {};
  if (!summary) {
    writeFileSync(join(dir, "rapport.md"), `# Rapport de charge : passe inexploitable\n\nAucun résumé k6 (summary.json) dans ce dossier : k6 n'a pas terminé (voir k6.log).\n`);
    return { code: 2, global: "INEXPLOITABLE" };
  }
  const statsFile = join(dir, "stats.csv");
  const rows = existsSync(statsFile) ? parseStats(readFileSync(statsFile, "utf8")) : [];
  const sys = rows.length ? systemStats(rows, ctx, summary.meta) : null;
  const refDir = o.reference || ctx.reference;
  const refSummary = refDir ? loadSummaries(resolve(refDir)) : null;
  const run = {
    integrite: ctx.integrite,
    redemarrage_max_s: ctx.redemarrages && ctx.redemarrages.length ? Math.max(...ctx.redemarrages) : undefined,
    plafond_connexion_ip: ctx.plafond_connexion_ip,
  };
  const input = {
    name: basename(dir), scenario: summary.scenario, env: summary.env, meta: summary.meta, setup: summary.setup,
    metrics: summary.metrics, checks: summary.checks, phases: summary.phases, state: summary.state, ctx, sys, run,
    dataset: ctx.dataset || summary.env.DATASET, preflight: ctx.preflight === undefined ? null : ctx.preflight,
    reference: refSummary ? { metrics: refSummary.metrics, name: basename(resolve(refDir)) } : null,
  };
  const result = judge(input);
  writeFileSync(join(dir, "rapport.md"), renderReport(input, result));
  if (rows.length) {
    const chart = (file, title, unit, key, stat) => {
      const lim = statLimit(result.rows, stat);
      writeFileSync(join(dir, file), svgChart({ title, unit, rows, key, start: ctx.k6_debut_ms, end: ctx.k6_fin_ms, limit: lim && lim.limit, limitLabel: lim && lim.label }));
    };
    chart("cpu.svg", "CPU du serveur", "%", "cpu", "cpu_moy");
    chart("memoire.svg", "Mémoire du serveur", "Mio", "mem", "mem_max");
    chart("pids.svg", "Fils du serveur (PID)", "PID", "pids", "pids_max");
  }
  return result;
}

function main(argv) {
  const args = argv.slice(2);
  if (args.length === 0 || args.includes("-h") || args.includes("--help")) {
    console.log(USAGE);
    return args.length === 0 ? 2 : 0;
  }
  let dir = null;
  let reference = null;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--reference") reference = args[++i];
    else if (!dir) dir = args[i];
    else {
      console.error(`Argument inconnu : ${args[i]}\n\n${USAGE}`);
      return 2;
    }
  }
  if (!dir || !existsSync(dir)) {
    console.error(`Dossier de passe introuvable : ${dir}`);
    return 2;
  }
  const result = buildReport(resolve(dir), { reference });
  console.log(`Rapport écrit : ${join(dir, "rapport.md")} (verdict ${result.global}, code ${result.code}).`);
  return result.code;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  process.exitCode = main(process.argv);
}

