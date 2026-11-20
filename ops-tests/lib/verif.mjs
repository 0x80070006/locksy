#!/usr/bin/env node
// Vérification déchiffrée d'une instance restaurée ou migrée, par le VRAI
// client courant (web/js et locksy.wasm, via bench/seed/worker.mjs) : chaque
// compte retenu se reconnecte (code TOTP compris), synchronise, déchiffre
// tout ce qu'il voit et compare au manifeste du semis (coffres visibles,
// nombre d'éléments, SHA-256 des clairs, pièces jointes du créateur).
//
// Différences avec bench/seed/verify.mjs :
// - --echantillon N : N comptes tirés au sort (graine fixe), plus tous les
//   comptes à double authentification ; --comptes a,b : ces comptes
//   seulement ; sans ces options, tous les comptes ;
// - --tolerer-illisibles : les éléments factices écrits par k6 (05-ecritures,
//   chiffrés aléatoires indéchiffrables) sont comptés à part au lieu d'être des
//   écarts. Les éléments du semis, eux, doivent TOUS se déchiffrer et avoir
//   l'empreinte du manifeste ;
// - pas de comparaison des totaux du serveur (les écritures de k6 les changent) :
//   ops-tests/lib/base.mjs compte les lignes de la base.
//
//   node ops-tests/lib/verif.mjs --base <url> --out <dossier du manifeste> [--wasm <fichier>]
//        [--echantillon N | --comptes a,b] [--graine texte] [--workers N] [--tolerer-illisibles] [--json <fichier>]
//
// Codes de sortie : 0 tout correspond, 1 écart ou échec, 2 usage invalide.

import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { createHash } from "node:crypto";
import { Pool, parseArgs, positiveInt, progress, formatDuration, describeError } from "../../bench/seed/common.mjs";

const USAGE = `Vérification déchiffrée d'une instance Locksy restaurée ou migrée.

Usage : node ops-tests/lib/verif.mjs --base <url> --out <dossier> [--wasm <fichier>]
          [--echantillon N | --comptes a,b] [--graine texte] [--workers N] [--tolerer-illisibles] [--json <fichier>]

  --base                adresse du serveur
  --out                 dossier qui contient manifest.json et users.json du semis
  --wasm                module locksy.wasm local (défaut : <base>/locksy.wasm)
  --echantillon N       N comptes tirés au sort, plus les comptes à double authentification
  --comptes a,b         ces comptes seulement (adresses séparées par des virgules)
  --graine              graine du tirage (défaut : ops)
  --workers N           fils de travail (défaut : 2)
  --tolerer-illisibles  éléments indéchiffrables (écritures factices de k6) comptés à part
  --json                écrit aussi le bilan dans ce fichier

Codes de sortie : 0 tout correspond, 1 écart ou échec, 2 usage invalide.`;

const OPTIONS = {
  base: "string", out: "string", wasm: "string", echantillon: "string", comptes: "string", graine: "string", workers: "string",
  "tolerer-illisibles": "boolean", json: "string", help: "boolean",
};

const ILLISIBLES = /^.+ : (\d+) élément\(s\) illisible\(s\) dans « .+ »$/;

function config(argv) {
  const a = parseArgs(argv, OPTIONS);
  if (a.help) return null;
  for (const k of ["base", "out"]) if (!a[k]) throw new Error(`Option obligatoire manquante : --${k}`);
  if (a.echantillon && a.comptes) throw new Error("--echantillon et --comptes s'excluent.");
  const base = a.base.replace(/\/+$/, "");
  return {
    comptes: a.comptes ? a.comptes.split(",").map((e) => e.trim()).filter(Boolean) : null,
    base,
    out: resolve(a.out),
    wasm: a.wasm ? { file: resolve(a.wasm) } : { url: `${base}/locksy.wasm` },
    echantillon: a.echantillon === undefined ? null : positiveInt(a.echantillon, "echantillon", 20),
    graine: a.graine || "ops",
    workers: positiveInt(a.workers, "workers", 2),
    tolerer: !!a["tolerer-illisibles"],
    json: a.json ? resolve(a.json) : null,
  };
}

/** Tirage reproductible : tri par empreinte de (graine, e-mail). */
function tirer(users, n, graine) {
  const cle = (u) => createHash("sha256").update(`${graine}:${u.email}`).digest("hex");
  const totp = users.filter((u) => u.totp_secret);
  const autres = users.filter((u) => !u.totp_secret).sort((x, y) => cle(x).localeCompare(cle(y)));
  return [...totp, ...autres.slice(0, Math.max(0, n - totp.length))];
}

async function lireJson(file) {
  try {
    return JSON.parse(await readFile(file, "utf8"));
  } catch (e) {
    throw new Error(`${file} illisible : ${e.message}`);
  }
}

async function verifier(cfg) {
  const t0 = Date.now();
  const manifest = await lireJson(resolve(cfg.out, "manifest.json"));
  const users = await lireJson(resolve(cfg.out, "users.json"));
  let retenus = cfg.echantillon ? tirer(users, cfg.echantillon, cfg.graine) : users;
  if (cfg.comptes) {
    retenus = cfg.comptes.map((email) => {
      const u = users.find((x) => x.email === email);
      if (!u) throw new Error(`${email} absent de users.json.`);
      return u;
    });
  }
  const collections = new Map(manifest.collections.map((c) => [c.id, c]));
  const comptes = new Map(manifest.accounts.map((a) => [a.email, a]));
  let attendus = 0;
  const tasks = retenus.map((u) => {
    const entry = comptes.get(u.email);
    if (!entry) throw new Error(`${u.email} absent du manifeste.`);
    const expected = entry.collections.map((id) => {
      const c = collections.get(id);
      attendus += c.items;
      return { id, name: c.name, items: c.items, digest: c.digest, attachments: c.creator === u.email ? c.attachments : null };
    });
    return {
      type: "verify",
      role: entry.role,
      account: { email: u.email, password: u.password, xff: u.xff, totp_secret: u.totp_secret },
      expected,
    };
  });
  process.stderr.write(`Vérification déchiffrée sur ${cfg.base} : ${tasks.length} compte(s) sur ${users.length}`
    + `${retenus.some((u) => u.totp_secret) ? " (dont les comptes à double authentification)" : ""}, ${cfg.workers} fil(s)\n`);

  const bilan = {
    base: cfg.base, comptes: tasks.length, comptes_totp: retenus.filter((u) => u.totp_secret).length,
    elements_attendus: attendus, elements_dechiffres: 0, pieces_jointes: 0, octets_pieces: 0, illisibles_toleres: 0, ecarts: [],
  };
  const pool = new Pool(cfg.workers, { base: cfg.base, wasm: cfg.wasm });
  const p = progress("comptes vérifiés");
  try {
    await pool.runAll(tasks, (i, r) => {
      for (const e of r.errors) {
        const m = ILLISIBLES.exec(e);
        if (m && cfg.tolerer) bilan.illisibles_toleres += Number(m[1]);
        else bilan.ecarts.push(e);
      }
      bilan.elements_dechiffres += r.items;
      bilan.pieces_jointes += r.attachments;
      bilan.octets_pieces += r.bytes;
      p.tick(i + 1, tasks.length, `${bilan.elements_dechiffres} éléments déchiffrés`);
    });
  } finally {
    await pool.close();
  }
  if (bilan.elements_dechiffres !== attendus) {
    bilan.ecarts.push(`${bilan.elements_dechiffres} éléments du semis déchiffrés, ${attendus} attendus`);
  }
  bilan.duree_ms = Date.now() - t0;
  bilan.taux_dechiffre = attendus ? Math.round((10000 * bilan.elements_dechiffres) / attendus) / 100 : 100;
  return bilan;
}

async function main() {
  let cfg;
  try {
    cfg = config(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(`${e.message}\n\n${USAGE}\n`);
    return 2;
  }
  if (!cfg) {
    process.stdout.write(`${USAGE}\n`);
    return 0;
  }
  try {
    const bilan = await verifier(cfg);
    const texte = `${JSON.stringify(bilan, null, 2)}\n`;
    if (cfg.json) await writeFile(cfg.json, texte);
    process.stdout.write(texte);
    const duree = formatDuration(bilan.duree_ms);
    if (bilan.ecarts.length) {
      process.stderr.write(`Vérification en échec en ${duree} : ${bilan.ecarts.length} écart(s)\n`);
      for (const e of bilan.ecarts.slice(0, 30)) process.stderr.write(`  - ${e}\n`);
      return 1;
    }
    process.stderr.write(`Vérification réussie en ${duree} : ${bilan.comptes} compte(s), ${bilan.elements_dechiffres} éléments `
      + `et ${bilan.pieces_jointes} pièce(s) jointe(s) déchiffrés (${bilan.taux_dechiffre} %)`
      + `${bilan.illisibles_toleres ? `, ${bilan.illisibles_toleres} écriture(s) factice(s) de k6 ignorée(s)` : ""}.\n`);
    return 0;
  } catch (e) {
    process.stderr.write(`Échec de la vérification : ${describeError(e)}\n`);
    return 1;
  }
}

process.exitCode = await main();
