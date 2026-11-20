#!/usr/bin/env node
// Vérification d'un jeu semé : chaque compte se reconnecte par le vrai code
// client, synchronise et déchiffre TOUT ce qu'il voit ; le résultat est
// comparé au manifeste (coffres visibles, nombre d'éléments, SHA-256 des
// clairs triés, pièces jointes). Les totaux du serveur sont aussi comparés.
//
//   node bench/seed/verify.mjs --dataset S --base http://127.0.0.1:61128 --out bench/seed/out/S/
//
// Codes de sortie : 0 tout correspond, 1 écart ou échec, 2 usage invalide.

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { DATASET_NAMES } from "./datasets.mjs";
import {
  MANIFEST_FORMAT, Pool, parseArgs, positiveInt, defaultWorkers, progress, formatDuration, rawApi, rawLogin, describeError,
} from "./common.mjs";

const USAGE = `Vérification d'un jeu de données Locksy semé par seed.mjs.

Usage : node bench/seed/verify.mjs --dataset S|M|L|E2E --base <url> --out <dossier>
          [--wasm <fichier> | --wasm-url <url>] [--workers N]

  --dataset   jeu attendu : ${DATASET_NAMES.join(", ")}
  --base      adresse du serveur
  --out       dossier qui contient manifest.json et users.json
  --wasm      module locksy.wasm local (défaut : <base>/locksy.wasm)
  --wasm-url  module locksy.wasm à télécharger
  --workers   fils de travail (défaut : ${defaultWorkers()})

Codes de sortie : 0 tout correspond, 1 écart ou échec, 2 usage invalide.`;

const OPTIONS = { dataset: "string", base: "string", out: "string", wasm: "string", "wasm-url": "string", workers: "string", help: "boolean" };

function config(argv) {
  const a = parseArgs(argv, OPTIONS);
  if (a.help) return null;
  for (const k of ["dataset", "base", "out"]) if (!a[k]) throw new Error(`Option obligatoire manquante : --${k}`);
  if (!DATASET_NAMES.includes(a.dataset)) throw new Error(`Jeu inconnu : « ${a.dataset} » (attendu : ${DATASET_NAMES.join(", ")}).`);
  if (a.wasm && a["wasm-url"]) throw new Error("--wasm et --wasm-url s'excluent.");
  const base = a.base.replace(/\/+$/, "");
  return {
    dataset: a.dataset,
    base,
    out: resolve(a.out),
    wasm: a.wasm ? { file: resolve(a.wasm) } : { url: a["wasm-url"] || `${base}/locksy.wasm` },
    workers: positiveInt(a.workers, "workers", defaultWorkers()),
  };
}

async function readJson(file) {
  try {
    return JSON.parse(await readFile(file, "utf8"));
  } catch (e) {
    throw new Error(`${file} illisible : ${e.message}`);
  }
}

/** Totaux du serveur (statistiques d'administration) comparés au manifeste. */
async function checkTotals(cfg, manifest, users) {
  const owner = users.find((u) => u.role === "owner");
  const token = await rawLogin(cfg.base, owner, owner.xff);
  try {
    const s = await rawApi(cfg.base, "GET", "/admin/stats", { token, xff: owner.xff });
    const c = manifest.counts;
    return [
      ["comptes", s.users, c.accounts],
      ["coffres", s.collections, c.collections],
      ["éléments", s.items, c.items],
    ].filter(([, got, want]) => got !== want).map(([what, got, want]) => `serveur : ${got} ${what}, ${want} attendus`);
  } finally {
    await rawApi(cfg.base, "POST", "/auth/logout", { token, xff: owner.xff }).catch(() => {});
  }
}

async function verify(cfg) {
  const t0 = Date.now();
  const manifest = await readJson(resolve(cfg.out, "manifest.json"));
  const users = await readJson(resolve(cfg.out, "users.json"));
  if (manifest.format !== MANIFEST_FORMAT) throw new Error(`Format de manifeste ${manifest.format} inconnu (attendu : ${MANIFEST_FORMAT}).`);
  if (manifest.dataset !== cfg.dataset) throw new Error(`Le manifeste décrit le jeu ${manifest.dataset}, pas ${cfg.dataset}.`);
  process.stderr.write(`Vérification du jeu ${cfg.dataset} sur ${cfg.base} : ${users.length} comptes, ${cfg.workers} fil(s)\n`);

  const errors = await checkTotals(cfg, manifest, users);
  const collections = new Map(manifest.collections.map((c) => [c.id, c]));
  const roles = new Map(manifest.accounts.map((a) => [a.email, a]));
  const tasks = users.map((u) => {
    const entry = roles.get(u.email);
    if (!entry) throw new Error(`${u.email} absent du manifeste.`);
    return {
      type: "verify",
      role: entry.role,
      account: { email: u.email, password: u.password, xff: u.xff, totp_secret: u.totp_secret },
      // Les pièces jointes d'un coffre sont relues par son créateur seulement.
      expected: entry.collections.map((id) => {
        const c = collections.get(id);
        return { id, name: c.name, items: c.items, digest: c.digest, attachments: c.creator === u.email ? c.attachments : null };
      }),
    };
  });
  const totals = { items: 0, attachments: 0, bytes: 0 };
  const pool = new Pool(cfg.workers, { base: cfg.base, wasm: cfg.wasm });
  const p = progress("comptes vérifiés");
  try {
    await pool.runAll(tasks, (i, r) => {
      errors.push(...r.errors);
      totals.items += r.items;
      totals.attachments += r.attachments;
      totals.bytes += r.bytes;
      p.tick(i + 1, tasks.length, `${totals.items} éléments déchiffrés`);
    });
  } finally {
    await pool.close();
  }
  if (totals.attachments !== manifest.counts.attachments) {
    errors.push(`${totals.attachments} pièces jointes relues, ${manifest.counts.attachments} attendues`);
  }
  const elapsed = formatDuration(Date.now() - t0);
  if (errors.length) {
    process.stderr.write(`Vérification ${cfg.dataset} : ${errors.length} écart(s) en ${elapsed}\n`);
    for (const e of errors.slice(0, 50)) process.stderr.write(`  - ${e}\n`);
    if (errors.length > 50) process.stderr.write(`  … et ${errors.length - 50} autre(s)\n`);
    return false;
  }
  process.stderr.write(`Vérification ${cfg.dataset} réussie en ${elapsed} : ${users.length} comptes, `
    + `${totals.items} éléments et ${totals.attachments} pièces jointes (${(totals.bytes / 1048576).toFixed(1).replace(".", ",")} Mio) déchiffrés, `
    + "conformes au manifeste.\n");
  return true;
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
    return (await verify(cfg)) ? 0 : 1;
  } catch (e) {
    process.stderr.write(`Échec de la vérification : ${describeError(e)}\n`);
    return 1;
  }
}

process.exitCode = await main();
