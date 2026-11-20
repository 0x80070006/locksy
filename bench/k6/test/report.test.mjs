// Tests du jugement des passes de charge (bench/scripts/report.mjs) et des
// seuils (bench/k6/lib/thresholds.js). Lancement : node --test bench/k6/test
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { criteria, k6Thresholds, routeMetrics, SCENARIOS, OBSERVE_COUNT, OBSERVE_TREND, OBSERVE_RATE } from "../lib/thresholds.js";
import {
  loadSummaries, parseStats, systemStats, measure, verdict, judge, compare, capacityTable, routeTable, svgChart, buildReport,
} from "../../scripts/report.mjs";

const trend = (values, thresholds) => ({ type: "trend", contains: "time", values: { count: 10, ...values }, thresholds });
const rate = (r, passes, fails, thresholds) => ({ type: "rate", values: { rate: r, passes, fails }, thresholds });
const counter = (count) => ({ type: "counter", values: { count, rate: count / 10 } });

test("chaque scénario a des critères aux identifiants uniques et aux expressions lisibles", () => {
  for (const s of Object.keys(SCENARIOS)) {
    const list = criteria(s, { VUS: "200" });
    assert.ok(list.length > 0, s);
    const ids = list.map((c) => c.id);
    assert.equal(new Set(ids).size, ids.length, `identifiants en double dans ${s}`);
    for (const c of list) {
      assert.ok(c.label && c.source, `${s} ${c.id}`);
      if (c.source === "k6") {
        const m = measure(c, { metrics: { [c.metric]: trend({ avg: 1, min: 1, med: 1, max: 1, "p(95)": 1, "p(99)": 1, count: 1 }) } });
        assert.notEqual(m.note && m.note.startsWith("expression illisible"), true, `${s} ${c.expr}`);
      }
    }
  }
  assert.throws(() => criteria("99-inconnu", {}), /Scénario inconnu/);
});

test("les seuils de la journée type suivent le nombre d'utilisateurs", () => {
  const expr = (vus) => criteria("07-journee-type", { VUS: vus }).find((c) => c.metric === "http_req_duration{groupe:journee}").expr;
  assert.equal(expr("50"), "p(95)<200");
  assert.equal(expr("200"), "p(95)<400");
  assert.equal(expr("500"), "p(95)<1000");
  assert.equal(expr(undefined), "p(95)<200");
  const abus = criteria("09-abus", { NOMINAL_P95: "150" }).find((c) => c.id === "09-p95");
  assert.equal(abus.expr, "p(95)<300");
});

test("k6Thresholds reprend les critères et force l'export des sous-métriques par route", () => {
  const t = k6Thresholds("00-smoke", {}, routeMetrics(["sync"]));
  assert.deepEqual(t.checks, ["rate==1"]);
  assert.deepEqual(t["http_req_duration{name:sync}"], [OBSERVE_TREND]);
  assert.deepEqual(t["http_req_failed{name:sync}"], [OBSERVE_RATE]);
  assert.deepEqual(t["http_reqs{name:sync}"], [OBSERVE_COUNT]);
  // Un débit dérivé exporte le nombre de requêtes de sa phase, jugé sur count.
  const t3 = k6Thresholds("03-sync-1000", {}, []);
  assert.deepEqual(t3["http_reqs{name:sync,scenario:charge}"], [OBSERVE_COUNT]);
  assert.ok(t3["http_req_duration{name:sync,scenario:seul}"].includes("p(95)<80"));
});

test("relevé système : base avant k6, maximum, delta, moyenne, OOM et arrêts", () => {
  const csv = [
    "horodatage,epoch_ms,cpu_pct,mem_mio,mem_limite_mio,pids,oom_killed,redemarrages,etat",
    "a,1000,0.0,10.0,512.0,6,false,0,running",
    "a,2000,0.0,12.0,512.0,6,false,0,running",
    "a,3000,50.0,100.0,512.0,20,false,0,running",
    "a,4000,150.0,200.0,512.0,40,false,0,running",
    "a,5000,,,,,false,0,exited",
    "a,6000,100.0,150.0,512.0,30,true,0,running",
  ].join("\n");
  const rows = parseStats(csv);
  assert.equal(rows.length, 6);
  assert.equal(rows[4].cpu, null);
  const s = systemStats(rows, { k6_debut_ms: 2500, k6_fin_ms: 6000 }, {});
  assert.equal(s.mem_base, 11);
  assert.equal(s.mem_max, 200);
  assert.equal(s.mem_delta, 189);
  assert.equal(s.cpu_moy, 100);
  assert.equal(s.pids_max, 40);
  assert.equal(s.oom, 1);
  assert.equal(s.redemarrages, 1);
  assert.equal(s.derive_rss_pct, undefined);
  // Dérives de l'endurance (08) : début et fin du plateau.
  const d = systemStats(rows, { k6_debut_ms: 1000, k6_fin_ms: 6000 }, { ramp_s: 0, plateau_s: 5, fenetre: 0.2 });
  assert.equal(d.derive_rss_pct, (150 - 11) / 11 * 100);
  assert.equal(d.derive_pids, 24);
});

test("mesure : compteur absent = 0, taux sans échantillon = non mesuré, drapeau de k6 prioritaire", () => {
  const c429 = criteria("02a-arrivee-matin", {}).find((c) => c.id === "02a-429");
  assert.deepEqual(measure(c429, { metrics: {} }), { value: 0, field: "count", ok: true });
  assert.equal(measure(c429, { metrics: { statut_429: counter(3) } }).ok, false);
  const prop = criteria("11-reglages", {}).find((c) => c.id === "11-propagation");
  assert.equal(measure(prop, { metrics: { politique_a_jour: rate(0, 0, 0) } }).ok, null);
  const p95 = criteria("02a-arrivee-matin", {}).find((c) => c.id === "02a-p95");
  const metrics = { [p95.metric]: trend({ "p(95)": 900, "p(99)": 1000 }, { "p(95)<800": { ok: false } }) };
  assert.equal(measure(p95, { metrics }).ok, false);
  assert.equal(measure(p95, { metrics }).value, 900);
  // Tendance sans requête (ex. /sync?since sur un serveur sans seq) : non mesurée.
  const delta = criteria("04-sync-10000", {}).find((c) => c.id === "04-delta");
  assert.equal(measure(delta, { metrics: { [delta.metric]: trend({ count: 0, "p(95)": 0 }) } }).note, "non mesuré");
});

test("verdict : jeu, preflight et nature fonctionnelle", () => {
  const perf = { id: "x", dataset: "M", fonctionnel: false, bloquant: true };
  const func = { id: "y", dataset: null, fonctionnel: true, bloquant: true };
  assert.equal(verdict(perf, { ok: true }, { dataset: "M", preflight: 0 }).verdict, "PASSE");
  assert.equal(verdict(perf, { ok: false }, { dataset: "M", preflight: 0 }).verdict, "ÉCHEC");
  const s = verdict(perf, { ok: false }, { dataset: "S", preflight: 0 });
  assert.equal(s.verdict, "INDICATIF");
  assert.equal(s.depasse, true);
  assert.match(s.raison, /dépassé ; seuil défini pour le jeu M/);
  assert.match(verdict(perf, { ok: true }, { dataset: "M", preflight: 1 }).raison, /preflight à 1/);
  assert.equal(verdict(func, { ok: false }, { dataset: "S", preflight: 1 }).verdict, "ÉCHEC");
  assert.equal(verdict(func, { ok: null, note: "non mesuré" }, { dataset: "S", preflight: 0 }).verdict, "INDICATIF");
});

test("verdict global et code de sortie", () => {
  const base = { scenario: "00-smoke", env: {}, dataset: "S", preflight: 1 };
  const ok = { checks: rate(1, 10, 0), http_req_failed: rate(0, 0, 10) };
  assert.deepEqual([judge({ ...base, metrics: ok }).global, judge({ ...base, metrics: ok }).code], ["PASSE", 0]);
  const ko = { checks: rate(0.9, 9, 1), http_req_failed: rate(0, 0, 10) };
  assert.equal(judge({ ...base, metrics: ko }).code, 1);
  // Seuils de performance d'un autre jeu, dépassés : indicative avec dépassement.
  const p = judge({ scenario: "03-sync-1000", env: {}, dataset: "S", preflight: 0, sys: { mem_max: 900 }, meta: { phases: { charge: 10 } },
    metrics: { "http_req_duration{name:sync,scenario:seul}": trend({ "p(95)": 10 }), "http_reqs{name:sync,scenario:charge}": counter(2000) } });
  assert.equal(p.global, "INDICATIF");
  assert.equal(p.code, 3);
});

test("calculs dérivés : débit d'une phase, capacité par paliers, comparaison à une référence", () => {
  const debit = criteria("03-sync-1000", {}).find((c) => c.id === "03-debit");
  const m = measure(debit, { metrics: { [debit.metric]: counter(30000) }, meta: { phases: { charge: 300 } } });
  assert.equal(m.value, 100);
  assert.equal(m.ok, true);
  const meta = { paliers: [5, 10, 15], palier_s: 60, transition_s: 5 };
  const metrics = {};
  const set = (r, p95, err, n) => {
    metrics[`http_req_duration{name:connexion,palier:${r}}`] = trend({ "p(95)": p95 });
    metrics[`http_req_failed{name:connexion,palier:${r}}`] = rate(err, 0, n);
    metrics[`http_reqs{name:connexion,palier:${r}}`] = counter(n);
  };
  set(5, 200, 0, 325);
  set(10, 600, 0, 650);
  set(15, 1500, 0, 975);
  assert.deepEqual(capacityTable(metrics, meta).map((r) => r.ok), [true, true, false]);
  const cap = criteria("02d-capacite", {})[0];
  assert.equal(measure(cap, { metrics, meta, env: {} }).value, 10);
  const ref = criteria("11-reglages", {}).find((c) => c.id === "11-p95");
  const cur = { [ref.metric]: trend({ "p(95)": 103 }) };
  assert.equal(measure(ref, { metrics: cur, reference: { metrics: { [ref.metric]: trend({ "p(95)": 100 }) }, name: "r" } }).ok, true);
  assert.equal(measure(ref, { metrics: cur, reference: { metrics: { [ref.metric]: trend({ "p(95)": 90 }) }, name: "r" } }).ok, false);
  assert.equal(measure(ref, { metrics: cur, reference: null }).ok, null);
});

test("critères produits par run.sh : intégrité et redémarrage", () => {
  const [integ, , restart] = criteria("10-arret-brutal", {});
  assert.equal(measure(integ, { run: { integrite: "ok" } }).ok, true);
  assert.equal(measure(integ, { run: { integrite: "erreur" } }).ok, false);
  assert.equal(measure(restart, { run: { redemarrage_max_s: 4.2 } }).ok, true);
  assert.equal(measure(restart, { run: {} }).ok, null);
  assert.equal(compare(3, "<=", 3), true);
  assert.throws(() => compare(1, "~", 2));
});

test("tableau par route : sous-métriques name, étiquettes en plus, routes vides ignorées", () => {
  const rows = routeTable({
    "http_req_duration{name:sync}": trend({ med: 2, "p(95)": 3, "p(99)": 4, max: 5, count: 10 }),
    "http_reqs{name:sync}": counter(10),
    "http_req_failed{name:sync}": rate(0.1, 1, 9),
    "http_req_duration{name:sync,scenario:seul}": trend({ med: 1, "p(95)": 1, "p(99)": 1, max: 1, count: 4 }),
    "http_req_duration{name:vide}": trend({ count: 0 }),
    "http_req_duration": trend({ count: 99 }),
  });
  assert.deepEqual(rows.map((r) => `${r.route}|${r.tags}|${r.count}`), ["sync||10", "sync|scenario:seul|4"]);
  assert.equal(rows[0].erreurs, 0.1);
});

test("courbe SVG statique : titre, description, seuil, coupure sur relevé vide, aucun script", () => {
  const rows = [{ t: 0, mem: 10 }, { t: 1000, mem: 20 }, { t: 2000, mem: null }, { t: 3000, mem: 30 }];
  const svg = svgChart({ title: "Mémoire du serveur", unit: "Mio", rows, key: "mem", start: 500, end: 2500, limit: 350, limitLabel: "seuil 350" });
  assert.match(svg, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg"/);
  assert.match(svg, /<title id="t">Mémoire du serveur<\/title>/);
  assert.match(svg, /seuil 350/);
  assert.equal((svg.match(/<polyline/g) || []).length, 1);
  assert.equal((svg.match(/<circle/g) || []).length, 1);
  assert.doesNotMatch(svg, /<script|on[a-z]+=|href=/i);
});

test("résumés de plusieurs phases : une phase sans échantillon ne masque pas la principale", () => {
  const dir = mkdtempSync(join(tmpdir(), "locksy-phases-"));
  try {
    const doc = (phase, metrics) => ({ format: 1, scenario: "10-arret-brutal", phase, env: { DATASET: "M" }, meta: {}, k6: { state: {}, metrics, root_group: { checks: [] } } });
    writeFileSync(join(dir, "summary.json"), JSON.stringify(doc(null, {
      "http_req_duration{name:element_creation}": trend({ count: 50, "p(95)": 9 }),
      ecriture_acquittee_presente: rate(0, 0, 0),
    })));
    writeFileSync(join(dir, "summary-verification.json"), JSON.stringify(doc("verification", {
      "http_req_duration{name:element_creation}": trend({ count: 0, "p(95)": 0 }),
      ecriture_acquittee_presente: rate(1, 120, 0),
    })));
    const s = loadSummaries(dir);
    assert.equal(s.scenario, "10-arret-brutal");
    assert.deepEqual(s.phases, ["principale", "verification"]);
    assert.equal(s.metrics["http_req_duration{name:element_creation}"].values.count, 50);
    assert.equal(s.metrics.ecriture_acquittee_presente.values.passes, 120);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("rapport complet d'une passe, et passe inexploitable sans résumé", () => {
  const dir = mkdtempSync(join(tmpdir(), "locksy-rapport-"));
  try {
    const summary = {
      format: 1, scenario: "02a-arrivee-matin", phase: null, env: { DATASET: "M" }, meta: {}, setup: { serveur: { version: "1.0.0" } },
      k6: {
        state: { testRunDurationMs: 300000 },
        metrics: {
          "http_req_duration{name:connexion}": trend({ med: 300, "p(95)": 950, "p(99)": 1200, max: 1500, count: 100 }, { "p(95)<800": { ok: false }, "p(99)<2000": { ok: true } }),
          "http_reqs{name:connexion}": counter(100),
          connexion_reussie: rate(1, 100, 0),
        },
        root_group: { checks: [{ name: "connexion acceptée", passes: 100, fails: 0 }] },
      },
    };
    writeFileSync(join(dir, "summary.json"), JSON.stringify(summary));
    writeFileSync(join(dir, "context.json"), JSON.stringify({ run: "essai", dataset: "M", preflight: 0, k6_debut_ms: 2000, k6_fin_ms: 4000, memoire: "512m", profil: "REF-PROD" }));
    writeFileSync(join(dir, "stats.csv"), "horodatage,epoch_ms,cpu_pct,mem_mio,mem_limite_mio,pids,oom_killed,redemarrages,etat\na,1000,1,50,512,6,false,0,running\na,3000,120,300,512,20,false,0,running\n");
    const r = buildReport(dir);
    assert.equal(r.code, 1);
    const md = readFileSync(join(dir, "rapport.md"), "utf8");
    assert.match(md, /\*\*Verdict : ÉCHEC\*\*/);
    assert.match(md, /p95 de la connexion < 800 ms \| bloquant \| 950 ms \| p\(95\) < 800 ms \| \*\*ÉCHEC\*\*/);
    assert.match(md, /mémoire max < 350 Mio \| bloquant \| 300 Mio .*\*\*PASSE\*\*/);
    assert.match(md, /\| connexion \| – \| 100 \|/);
    for (const f of ["cpu.svg", "memoire.svg", "pids.svg"]) assert.ok(existsSync(join(dir, f)), f);
    rmSync(join(dir, "summary.json"));
    assert.equal(buildReport(dir).code, 2);
    assert.match(readFileSync(join(dir, "rapport.md"), "utf8"), /passe inexploitable/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
