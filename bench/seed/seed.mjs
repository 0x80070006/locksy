#!/usr/bin/env node
// Semis d'un jeu de données par le VRAI code client (web/js/vault.js et
// locksy.wasm), sur une instance Locksy neuve. Mode d'emploi : bench/README.md.
//
//   node bench/seed/seed.mjs --dataset S --base http://127.0.0.1:61128 --out bench/seed/out/S/
//
// Étapes : propriétaire (jeton d'installation), invitations, inscription des
// autres comptes avec leurs éléments personnels, coffres partagés et membres,
// pièces jointes des coffres partagés. Écrit manifest.json (ce qui doit être
// relu) et users.json (comptes de TEST : mots de passe, preuves
// d'authentification ; fichier ignoré par git). La progression va sur stderr.

import { randomBytes } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { dataset, DATASET_NAMES } from "./datasets.mjs";
import {
  MANIFEST_FORMAT, Pool, parseArgs, positiveInt, defaultWorkers, xffFor, progress, formatDuration,
  rawApi, rawLogin, describeError,
} from "./common.mjs";

const USAGE = `Semis d'un jeu de données Locksy par le vrai code client.

Usage : node bench/seed/seed.mjs --dataset S|M|L|E2E --base <url> --out <dossier>
          [--wasm <fichier> | --wasm-url <url>] [--workers N] [--xff-prefix 10.200]
          [--setup-token <jeton>] [--no-attachments]

  --dataset      jeu à semer : ${DATASET_NAMES.join(", ")}
  --base         adresse du serveur, par exemple http://127.0.0.1:61128 (instance NEUVE)
  --out          dossier de sortie (manifest.json, users.json), par exemple bench/seed/out/S/
  --wasm         module locksy.wasm local (défaut : <base>/locksy.wasm, servi par le serveur)
  --wasm-url     module locksy.wasm à télécharger
  --workers      fils de travail, un compte en cours par fil (défaut : ${defaultWorkers()})
  --xff-prefix   deux premiers octets des adresses X-Forwarded-For, une par compte (défaut : 10.200)
  --setup-token  jeton d'installation (défaut : variable LOCKSY_SETUP_TOKEN)
  --no-attachments
                 aucune pièce jointe (jeux M et L plus rapides et plus légers ;
                 le manifeste le signale)

Codes de sortie : 0 semis terminé, 1 échec, 2 usage invalide.`;

const OPTIONS = {
  dataset: "string", base: "string", out: "string", wasm: "string", "wasm-url": "string",
  workers: "string", "xff-prefix": "string", "setup-token": "string", "no-attachments": "boolean", help: "boolean",
};

/** Mot de passe maître de TEST, tiré au hasard à chaque semis. */
const newPassword = () => `Banc-${randomBytes(18).toString("base64url")}`;

function config(argv) {
  const a = parseArgs(argv, OPTIONS);
  if (a.help) return null;
  for (const k of ["dataset", "base", "out"]) if (!a[k]) throw new Error(`Option obligatoire manquante : --${k}`);
  if (a.wasm && a["wasm-url"]) throw new Error("--wasm et --wasm-url s'excluent.");
  const base = a.base.replace(/\/+$/, "");
  const setupToken = a["setup-token"] || process.env.LOCKSY_SETUP_TOKEN;
  if (!setupToken) throw new Error("Jeton d'installation manquant : --setup-token ou variable LOCKSY_SETUP_TOKEN.");
  return {
    ds: dataset(a.dataset),
    base,
    out: resolve(a.out),
    wasm: a.wasm ? { file: resolve(a.wasm) } : { url: a["wasm-url"] || `${base}/locksy.wasm` },
    workers: positiveInt(a.workers, "workers", defaultWorkers()),
    xffPrefix: a["xff-prefix"] || "10.200",
    setupToken,
    noAttachments: Boolean(a["no-attachments"]),
  };
}

/** Répartit les pièces jointes d'un coffre entre ses membres qui peuvent écrire. */
function attachmentJobs(col, spec, accountsByEmail) {
  const writers = [spec.creator, ...spec.members.filter((m) => m.role !== "reader").map((m) => m.email)];
  const per = Math.ceil(spec.attachments.length / writers.length);
  const jobs = [];
  for (let w = 0; w * per < spec.attachments.length; w++) {
    const offset = w * per;
    const files = spec.attachments.slice(offset, offset + per)
      .map((size, j) => ({ size, name: `piece-${spec.key}-${String(offset + j + 1).padStart(4, "0")}.bin` }));
    jobs.push({ type: "attachments", account: accountsByEmail.get(writers[w]).creds, collection_id: col.id, files, offset });
  }
  return jobs;
}

async function seed(cfg) {
  const { ds, base } = cfg;
  if (cfg.noAttachments) {
    for (const x of [...ds.accounts, ...ds.collections]) x.attachments = [];
    ds.description += " ; pièces jointes NON semées (--no-attachments)";
  }
  const t0 = Date.now();
  const durations = {};
  const health = await rawApi(base, "GET", "/health");
  if (!health.needs_setup) {
    throw new Error("Le serveur contient déjà des comptes : le semis exige une instance neuve "
      + "(docker compose -p <projet> -f bench/docker-compose.bench.yml down -v, puis bench-up.sh).");
  }
  const now = Math.floor(Date.now() / 1000);
  process.stderr.write(`Semis du jeu ${ds.name} : ${ds.description}\n`
    + `  serveur ${base} (version ${health.version}), ${cfg.workers} fil(s), X-Forwarded-For ${cfg.xffPrefix}.x.y\n`);

  // Comptes : mot de passe de test et adresse propre à chacun.
  const accounts = ds.accounts.map((spec, i) => ({
    spec, index: i, password: newPassword(), xff: xffFor(cfg.xffPrefix, i + 1),
  }));
  const byEmail = new Map(accounts.map((a) => [a.spec.email, a]));
  const accountTask = (a, extra) => ({
    type: "account", index: a.index, email: a.spec.email, name: a.spec.name, password: a.password, xff: a.xff,
    personal: a.spec.personal, attachments: a.spec.attachments, totp: a.spec.totp, now, ...extra,
  });
  const pool = new Pool(cfg.workers, { base, wasm: cfg.wasm });
  let ownerToken = null;
  const [owner, ...others] = accounts;
  try {
    // 1. Propriétaire, par le jeton d'installation.
    let p = progress("propriétaire");
    owner.result = await pool.run(accountTask(owner, { setupToken: cfg.setupToken }));
    p.tick(1, 1);
    durations.owner_ms = p.elapsed();

    // 2. Invitations, créées par le propriétaire.
    p = progress("invitations");
    ownerToken = await rawLogin(base, { email: owner.spec.email, auth_key_b64: owner.result.auth_key }, owner.xff);
    for (const [i, a] of others.entries()) {
      const inv = await rawApi(base, "POST", "/admin/invites", { token: ownerToken, xff: owner.xff, body: { email: a.spec.email, role: a.spec.role } });
      a.inviteToken = inv.token;
      p.tick(i + 1, others.length);
    }
    durations.invites_ms = p.elapsed();

    // 3. Autres comptes : inscription, éléments personnels, pièces jointes, 2FA.
    p = progress("comptes");
    let items = 0;
    await pool.runAll(others.map((a) => accountTask(a, { inviteToken: a.inviteToken })), (i, r) => {
      others[i].result = r;
      items += r.items;
      p.tick(i + 1, others.length, `${items} éléments personnels`);
    });
    durations.accounts_ms = p.elapsed();
    for (const a of accounts) {
      a.creds = { email: a.spec.email, password: a.password, xff: a.xff, totp_secret: a.result.totp_secret };
    }

    // 4. Coffres partagés : création, éléments, membres.
    p = progress("coffres partagés");
    const collections = await pool.runAll(ds.collections.map((c) => ({
      type: "collection", name: c.name, items: c.items, now,
      creator: byEmail.get(c.creator).creds,
      members: c.members.map((m) => {
        const r = byEmail.get(m.email).result;
        return { id: r.id, email: m.email, public_key: r.public_key, role: m.role };
      }),
    })), (i) => p.tick(i + 1, ds.collections.length));
    durations.collections_ms = p.elapsed();

    // 5. Pièces jointes des coffres partagés, envoyées par leurs membres.
    p = progress("pièces jointes partagées");
    const jobs = ds.collections.flatMap((spec, i) => attachmentJobs(collections[i], spec, byEmail).map((job) => ({ job, i })));
    collections.forEach((c) => { c.attachments = []; });
    await pool.runAll(jobs.map((j) => j.job), (k, files) => {
      collections[jobs[k].i].attachments.push(...files);
      p.tick(k + 1, jobs.length);
    });
    collections.forEach((c) => c.attachments.sort((x, y) => x.name.localeCompare(y.name)));
    durations.shared_attachments_ms = p.elapsed();

    durations.total_ms = Date.now() - t0;
    await writeOutputs(cfg, { health, now, accounts, collections, durations });
  } finally {
    if (ownerToken) await rawApi(base, "POST", "/auth/logout", { token: ownerToken, xff: owner.xff }).catch(() => {});
    await pool.close();
  }
  process.stderr.write(`Semis ${ds.name} terminé en ${formatDuration(Date.now() - t0)} : ${cfg.out}\n`);
}

async function writeOutputs(cfg, { health, now, accounts, collections, durations }) {
  const { ds } = cfg;
  const visible = new Map(accounts.map((a) => [a.spec.email, [a.result.personal_collection]]));
  const samples = new Map(accounts.map((a) => [a.spec.email, [...a.result.sample_item_ids]]));
  ds.collections.forEach((spec, i) => {
    for (const email of [spec.creator, ...spec.members.map((m) => m.email)]) {
      visible.get(email).push(collections[i].id);
      samples.get(email).push(...collections[i].sample_item_ids);
    }
  });
  const personal = accounts.map((a) => ({
    id: a.result.personal_collection, key: `perso-${a.index}`, name: "Personnel", personal: true,
    creator: a.spec.email, members: [], items: a.result.items, digest: a.result.digest, attachments: a.result.attachments,
  }));
  const shared = ds.collections.map((spec, i) => ({
    id: collections[i].id, key: spec.key, name: spec.name, personal: false, creator: spec.creator,
    members: spec.members, items: collections[i].items, digest: collections[i].digest, attachments: collections[i].attachments,
  }));
  const all = [...personal, ...shared];
  const itemsById = new Map(all.map((c) => [c.id, c.items]));
  const perAccount = accounts.map((a) => visible.get(a.spec.email).reduce((n, id) => n + itemsById.get(id), 0));
  const files = all.flatMap((c) => c.attachments);
  const manifest = {
    format: MANIFEST_FORMAT,
    dataset: ds.name,
    description: ds.description,
    created_at: now,
    base: cfg.base,
    server_version: health.version,
    kdf: accounts[0].result.kdf,
    attachments_skipped: cfg.noAttachments,
    xff_prefix: cfg.xffPrefix,
    workers: cfg.workers,
    counts: {
      accounts: accounts.length,
      collections: all.length,
      items: all.reduce((n, c) => n + c.items, 0),
      attachments: files.length,
      attachment_bytes: files.reduce((n, f) => n + f.size, 0),
      visible_items_per_account: {
        min: Math.min(...perAccount), max: Math.max(...perAccount), avg: Math.round(perAccount.reduce((x, y) => x + y, 0) / perAccount.length),
      },
    },
    durations,
    accounts: accounts.map((a) => ({ email: a.spec.email, role: a.spec.role, id: a.result.id, collections: visible.get(a.spec.email) })),
    collections: all,
  };
  const users = accounts.map((a) => ({
    email: a.spec.email,
    name: a.spec.name,
    password: a.password,
    auth_key_b64: a.result.auth_key,
    id: a.result.id,
    role: a.spec.role,
    xff: a.xff,
    collections: visible.get(a.spec.email),
    sample_item_ids: samples.get(a.spec.email),
    recovery: a.result.recovery,
    ...(a.result.totp_secret ? { totp_secret: a.result.totp_secret } : {}),
  }));
  await mkdir(cfg.out, { recursive: true });
  await writeFile(resolve(cfg.out, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  await writeFile(resolve(cfg.out, "users.json"), `${JSON.stringify(users, null, 2)}\n`, { mode: 0o600 });
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
    await seed(cfg);
    return 0;
  } catch (e) {
    process.stderr.write(`Échec du semis : ${describeError(e)}\n`);
    return 1;
  }
}

process.exitCode = await main();
