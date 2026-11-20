#!/usr/bin/env node
// Porte de qualité des micro-benchmarks du noyau (lot Q1, cahier 00 §6.3, critère G16).
//
// Lit les médianes mesurées par criterion (<dossier>/<groupe>/<mesure>/new/estimates.json,
// champ median.point_estimate, en nanosecondes) et les compare à la référence
// bench/baselines/criterion-ref.json. Une mesure échoue si :
//   - sa médiane dépasse celle de la référence de plus de 10 % (régression) ;
//   - elle dépasse son plafond absolu (max_ns) ;
//   - elle passe sous son plancher absolu (min_ns). Le seul plancher est celui de la
//     dérivation client : sous 150 ms, quelqu'un a affaibli les paramètres KDF ;
//   - elle figure dans la référence mais n'a pas été mesurée.
//
// Usage :
//   node bench/scripts/criterion-gate.mjs [--dir bench/.cache/criterion] [--ref bench/baselines/criterion-ref.json]
//                                         [--tolerance 10] [--update [--env clé=valeur]…] [--self-test]
//   --update     réécrit la référence avec les médianes mesurées et les seuils absolus
//                ci-dessous (la section « wasm » et l'environnement sont conservés ;
//                --env cpus=2 --env cpuset=2,3 --env note="…" les complète). Les seuils
//                absolus restent contrôlés : un dépassement fait toujours sortir en 1.
//   --tolerance  régression tolérée, en pourcentage (10 par défaut ; 20 sur un runner partagé).
//   --self-test  vérifie la porte elle-même sur des données synthétiques.
//
// Mesure de référence (profil 2 vCPU, même toolchain que le serveur) :
//   MSYS_NO_PATHCONV=1 docker run --rm --cpus 2 --cpuset-cpus 2,3 -v "$PWD:/src" \
//     -v locksy-reg:/usr/local/cargo/registry -v locksy-tgt-srv:/src/target -w /src locksy-toolchain \
//     bash -c "cargo bench -p locksy-core --bench core -- --noplot \
//              && mkdir -p bench/.cache/criterion && cp -r target/criterion/. bench/.cache/criterion/"
//   node bench/scripts/criterion-gate.mjs
//
// Sortie : un rapport lisible, puis le code 0 (vert) ou 1 (échec ou erreur). Aucune dépendance.

import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const MS = 1e6;
const US = 1e3;

/**
 * Identifiants contractuels (contrat C10) et seuils absolus du cahier 00 §6.3 et de
 * l'audit 05 §2.4, en nanosecondes. Un identifiant sans seuil n'est soumis qu'au
 * contrôle de régression.
 */
export const BENCHMARKS = {
  "kdf/client_derive_master_64MiB_t3": { min_ns: 150 * MS, max_ns: 900 * MS },
  "kdf/server_rehash_19MiB_t2": { max_ns: 60 * MS },
  "aead/encrypt_1KiB": { max_ns: 15 * US },
  "aead/decrypt_1KiB": { max_ns: 15 * US },
  "aead/encrypt_100KiB": { max_ns: 400 * US },
  "aead/decrypt_100KiB": { max_ns: 400 * US },
  "aead/encrypt_10MiB": { max_ns: 80 * MS },
  "aead/decrypt_10MiB": { max_ns: 80 * MS },
  "sealing/seal_key": { max_ns: 200 * US },
  "sealing/open_key": { max_ns: 200 * US },
  "keywrap/wrap_key": { max_ns: 15 * US },
  "keywrap/unwrap_key": { max_ns: 15 * US },
  "totp/generate": { max_ns: 10 * US },
  "totp/verify_window": { max_ns: 40 * US },
  "generator/password_20": { max_ns: 50 * US },
  "generator/passphrase_5": {},
  "strength/strength_estimate": { max_ns: 2 * MS },
};

// ------------------------------------------------------------------ Lecture

/** Médiane (ns) d'une mesure, ou null si criterion ne l'a pas produite. */
export function readMedian(dir, id) {
  const file = join(dir, ...id.split("/"), "new", "estimates.json");
  if (!existsSync(file)) return null;
  const estimates = JSON.parse(readFileSync(file, "utf8"));
  const value = estimates?.median?.point_estimate;
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    throw new Error(`${file} : médiane illisible.`);
  }
  return value;
}

/** Toutes les médianes connues : identifiants contractuels et ceux de la référence. */
export function readMeasurements(dir, ids) {
  const out = {};
  for (const id of ids) {
    const median = readMedian(dir, id);
    if (median !== null) out[id] = median;
  }
  return out;
}

// ------------------------------------------------------------------ Contrôle

/**
 * Compare les mesures à la référence. Renvoie une ligne par identifiant :
 * { id, median, ref, delta, min, max, failures: [texte…] }.
 */
export function evaluate(measured, reference, tolerancePct) {
  const refs = reference?.benchmarks ?? {};
  const ids = [...new Set([...Object.keys(BENCHMARKS), ...Object.keys(refs)])].sort();
  return ids.map((id) => {
    const ref = refs[id] ?? {};
    const limits = { ...BENCHMARKS[id], ...pick(ref, ["min_ns", "max_ns"]) };
    const median = measured[id] ?? null;
    const row = { id, median, ref: ref.median_ns ?? null, delta: null, min: limits.min_ns ?? null, max: limits.max_ns ?? null, failures: [] };
    if (median === null) {
      row.failures.push("mesure absente");
      return row;
    }
    if (row.ref !== null) {
      row.delta = (median / row.ref - 1) * 100;
      if (row.delta > tolerancePct) row.failures.push(`régression de ${pct(row.delta)} (tolérance ${fmtNumber(tolerancePct)} %)`);
    }
    if (row.max !== null && median > row.max) row.failures.push(`au-dessus du plafond de ${fmtDuration(row.max)}`);
    if (row.min !== null && median < row.min) row.failures.push(`sous le plancher de ${fmtDuration(row.min)} (paramètres affaiblis ?)`);
    return row;
  });
}

/** Seuls les seuils absolus comptent pour une mise à jour de la référence. */
export function absoluteFailures(rows) {
  return rows.filter((r) => r.failures.some((f) => !f.startsWith("régression")));
}

/** Nouvelle référence : médianes mesurées, seuils absolus, wasm et environnement conservés. */
export function buildReference(measured, previous, envOverrides, now = new Date()) {
  const benchmarks = {};
  for (const id of Object.keys(measured).sort()) {
    benchmarks[id] = { median_ns: Math.round(measured[id]), ...BENCHMARKS[id] };
  }
  const out = {
    format: 1,
    recorded_at: now.toISOString(),
    env: { ...(previous?.env ?? {}), ...envOverrides },
    benchmarks,
  };
  if (previous?.wasm) out.wasm = previous.wasm;
  return out;
}

// ------------------------------------------------------------------ Affichage

const nf = new Intl.NumberFormat("fr-FR", { maximumSignificantDigits: 3 });

function fmtNumber(n) {
  return nf.format(n);
}

/** Durée lisible à partir de nanosecondes : « 412 ms », « 3,21 µs ». */
export function fmtDuration(ns) {
  if (ns >= 1e9) return `${fmtNumber(ns / 1e9)} s`;
  if (ns >= MS) return `${fmtNumber(ns / MS)} ms`;
  if (ns >= US) return `${fmtNumber(ns / US)} µs`;
  return `${fmtNumber(ns)} ns`;
}

const pf = new Intl.NumberFormat("fr-FR", { minimumFractionDigits: 1, maximumFractionDigits: 1 });

/** Écart signé à une décimale : « +12,3 % », « −4,0 % », « ±0,0 % ». */
export function pct(d) {
  const text = pf.format(Math.abs(d));
  if (text === pf.format(0)) return `±${text} %`;
  return `${d > 0 ? "+" : "−"}${text} %`;
}

function pick(obj, keys) {
  return Object.fromEntries(keys.filter((k) => typeof obj[k] === "number").map((k) => [k, obj[k]]));
}

function report(rows, reference, tolerancePct) {
  const env = reference?.env ?? {};
  const where = [env.cpus && `${env.cpus} vCPU`, env.cpuset && `cœurs ${env.cpuset}`, env.rustc].filter(Boolean).join(", ");
  console.log(`Micro-benchmarks du noyau : ${rows.length} mesures, tolérance de régression ${fmtNumber(tolerancePct)} %.`);
  console.log(reference ? `Référence du ${String(reference.recorded_at).slice(0, 10)}${where ? ` (${where})` : ""}.` : "Aucune référence : seuls les seuils absolus sont contrôlés.");
  const width = Math.max(...rows.map((r) => r.id.length));
  for (const r of rows) {
    const status = r.failures.length ? "ÉCHEC" : "ok   ";
    const median = r.median === null ? "—" : fmtDuration(r.median);
    const vsRef = r.ref === null ? "sans référence" : `réf. ${fmtDuration(r.ref)}${r.delta === null ? "" : `, ${pct(r.delta)}`}`;
    const bounds = r.min !== null || r.max !== null ? `  [${r.min === null ? "" : `≥ ${fmtDuration(r.min)}`}${r.min !== null && r.max !== null ? ", " : ""}${r.max === null ? "" : `≤ ${fmtDuration(r.max)}`}]` : "";
    console.log(`  ${status}  ${r.id.padEnd(width)}  ${median.padStart(9)}  (${vsRef})${bounds}`);
    for (const f of r.failures) console.log(`         → ${f}`);
  }
  const wasm = reference?.wasm;
  if (wasm) {
    console.log(
      `Pont WebAssembly (Node ${wasm.node}) : ${fmtNumber(wasm.call_overhead_us)} µs par appel, 10 000 decrypt de 1 Kio en ${fmtNumber(wasm.decrypt_1KiB_x10000_ms)} ms : decrypt_many ${wasm.decrypt_many_required ? "NÉCESSAIRE" : "non nécessaire"}.`,
    );
  }
}

// ------------------------------------------------------------------ Auto-test

function selfTest() {
  const dir = mkdtempSync(join(tmpdir(), "criterion-gate-"));
  const write = (id, ns) => {
    const d = join(dir, ...id.split("/"), "new");
    mkdirSync(d, { recursive: true });
    writeFileSync(join(d, "estimates.json"), JSON.stringify({ median: { point_estimate: ns }, mean: { point_estimate: ns * 1.01 } }));
  };
  const base = {};
  for (const [id, lim] of Object.entries(BENCHMARKS)) {
    base[id] = lim.min_ns ? lim.min_ns * 2 : lim.max_ns ? lim.max_ns / 4 : 5 * US;
    write(id, base[id]);
  }
  const measured = readMeasurements(dir, Object.keys(BENCHMARKS));
  assert.deepEqual(measured, base, "lecture des médianes");

  const reference = buildReference(measured, { env: { cpus: 2 }, wasm: { node: "test" } }, { cpuset: "2,3" }, new Date(0));
  assert.equal(reference.format, 1);
  assert.deepEqual(reference.env, { cpus: 2, cpuset: "2,3" }, "environnement fusionné");
  assert.deepEqual(reference.wasm, { node: "test" }, "section wasm conservée");
  assert.equal(reference.benchmarks["kdf/client_derive_master_64MiB_t3"].min_ns, 150 * MS);
  assert.equal(evaluate(measured, reference, 10).filter((r) => r.failures.length).length, 0, "mesure identique : vert");

  const fails = (m, ref = reference, tol = 10) => evaluate(m, ref, tol).filter((r) => r.failures.length).map((r) => r.id);
  const id = "aead/encrypt_1KiB";
  assert.deepEqual(fails({ ...measured, [id]: base[id] * 1.09 }), [], "+9 % : toléré");
  assert.deepEqual(fails({ ...measured, [id]: base[id] * 1.11 }), [id], "+11 % : régression");
  assert.deepEqual(fails({ ...measured, [id]: base[id] * 1.11 }, reference, 20), [], "+11 % toléré à 20 %");
  assert.deepEqual(fails({ ...measured, [id]: base[id] * 0.5 }), [], "amélioration : vert");

  const kdf = "kdf/client_derive_master_64MiB_t3";
  const weak = evaluate({ ...measured, [kdf]: 120 * MS }, reference, 10).find((r) => r.id === kdf);
  assert.match(weak.failures.join(), /plancher/, "KDF sous 150 ms : échec");
  assert.equal(absoluteFailures([weak]).length, 1, "le plancher est un seuil absolu");
  const slow = evaluate({ ...measured, [kdf]: 950 * MS }, null, 10).find((r) => r.id === kdf);
  assert.match(slow.failures.join(), /plafond/, "KDF au-dessus de 900 ms : échec, même sans référence");

  const { [id]: _absent, ...partial } = measured;
  assert.deepEqual(fails(partial), [id], "mesure absente : échec");

  const extra = { ...reference, benchmarks: { ...reference.benchmarks, "divers/nouveau": { median_ns: 100, max_ns: 50 } } };
  assert.deepEqual(fails({ ...measured, "divers/nouveau": 80 }, extra), ["divers/nouveau"], "seuil propre à la référence appliqué");

  assert.equal(fmtDuration(412.3 * MS), "412 ms");
  assert.equal(fmtDuration(3214), "3,21 µs");
  assert.equal(pct(12.34), "+12,3 %");
  assert.equal(pct(-4), "−4,0 %");
  assert.equal(pct(-0.0001), "±0,0 %");
  console.log("Auto-test de la porte criterion : vert.");
}

// ------------------------------------------------------------------ Programme

function main() {
  const { values } = parseArgs({
    options: {
      dir: { type: "string", default: join(repo, "bench", ".cache", "criterion") },
      ref: { type: "string", default: join(repo, "bench", "baselines", "criterion-ref.json") },
      tolerance: { type: "string", default: "10" },
      update: { type: "boolean", default: false },
      env: { type: "string", multiple: true, default: [] },
      "self-test": { type: "boolean", default: false },
    },
  });
  if (values["self-test"]) return selfTest();

  const tolerance = Number(values.tolerance);
  if (!(tolerance >= 0 && tolerance <= 100)) throw new Error("--tolerance attend un pourcentage entre 0 et 100.");
  if (!existsSync(values.dir)) {
    throw new Error(`${values.dir} introuvable : lancez d'abord « cargo bench -p locksy-core --bench core » et copiez target/criterion.`);
  }
  const reference = existsSync(values.ref) ? JSON.parse(readFileSync(values.ref, "utf8")) : null;
  if (reference && reference.format !== 1) throw new Error(`${values.ref} : format ${reference.format} inconnu (attendu : 1).`);
  if (!reference && !values.update) throw new Error(`${values.ref} introuvable : enregistrez une référence avec --update.`);

  const ids = [...new Set([...Object.keys(BENCHMARKS), ...Object.keys(reference?.benchmarks ?? {})])];
  const measured = readMeasurements(values.dir, ids);
  const rows = evaluate(measured, reference, tolerance);
  report(rows, reference, tolerance);

  if (values.update) {
    const env = Object.fromEntries(
      values.env.map((kv) => {
        const at = kv.indexOf("=");
        if (at <= 0) throw new Error(`--env attend clé=valeur (reçu : ${kv}).`);
        return [kv.slice(0, at), kv.slice(at + 1)];
      }),
    );
    if (env.cpus !== undefined && /^\d+$/.test(env.cpus)) env.cpus = Number(env.cpus);
    const missing = rows.filter((r) => r.median === null).map((r) => r.id);
    if (missing.length) throw new Error(`référence non écrite, mesures absentes : ${missing.join(", ")}.`);
    mkdirSync(dirname(values.ref), { recursive: true });
    writeFileSync(values.ref, `${JSON.stringify(buildReference(measured, reference, env), null, 2)}\n`);
    console.log(`Référence réécrite : ${values.ref}.`);
    const broken = absoluteFailures(rows);
    if (broken.length) {
      console.log(`Verdict : ÉCHEC, ${broken.length} seuil(s) absolu(s) dépassé(s) malgré la mise à jour.`);
      return 1;
    }
    console.log("Verdict : vert (seuils absolus respectés).");
    return 0;
  }

  const failed = rows.filter((r) => r.failures.length);
  console.log(failed.length ? `Verdict : ÉCHEC, ${failed.length} mesure(s) hors seuil.` : "Verdict : vert.");
  return failed.length ? 1 : 0;
}

try {
  process.exitCode = main() ?? 0;
} catch (e) {
  console.error(`Erreur : ${e instanceof assert.AssertionError ? `auto-test en échec : ${e.message}` : e.message}`);
  process.exitCode = 1;
}
