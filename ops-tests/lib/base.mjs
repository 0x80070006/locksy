#!/usr/bin/env node
// Lecture d'une base Locksy (SQLite) pour les recettes d'exploitation, par le
// module natif node:sqlite (Node 22.5 ou plus, sans dépendance).
//
// Les commandes de lecture travaillent sur une COPIE temporaire du fichier :
// ouvrir une base en mode WAL crée des fichiers -wal et -shm à côté d'elle, et
// une pièce à conviction ne doit jamais être modifiée.
//
//   node ops-tests/lib/base.mjs info <base>
//       { octets, sha256, user_version, integrity, journal_mode, tables: {nom: lignes} }
//   node ops-tests/lib/base.mjs acquittes --avant <s epoch> --reference <base> --copie <base>
//       éléments créés avant <avant> dans la référence (écritures acquittées)
//       et absents de la copie : { attendus, presents, manquants, exemples }
//   node ops-tests/lib/base.mjs forger <base> <user_version>
//       écrit PRAGMA user_version DANS le fichier donné (à faire sur une copie)
//   node ops-tests/lib/base.mjs reglages <base>
//       réglages de l'organisation : ancien bloc « org » et registre org_settings
//
// Codes de sortie : 0 réussite, 1 échec (base illisible), 2 usage invalide.

import { DatabaseSync } from "node:sqlite";
import { copyFileSync, mkdtempSync, rmSync, readFileSync, statSync, existsSync, unlinkSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const USAGE = `Lecture d'une base Locksy pour les recettes d'exploitation.

Usage : node ops-tests/lib/base.mjs info <base>
        node ops-tests/lib/base.mjs acquittes --avant <secondes epoch> --reference <base> --copie <base>
        node ops-tests/lib/base.mjs forger <base> <user_version>
        node ops-tests/lib/base.mjs reglages <base>

Codes de sortie : 0 réussite, 1 échec, 2 usage invalide.`;

class Usage extends Error {}

const sha256 = (file) => createHash("sha256").update(readFileSync(file)).digest("hex");

/** Ouvre une copie temporaire de `file` (avec ses -wal et -shm éventuels) et appelle `fn(db)`. */
function surCopie(file, fn) {
  if (!existsSync(file)) throw new Error(`Base introuvable : ${file}`);
  const dir = mkdtempSync(join(tmpdir(), "locksy-ops-"));
  const copie = join(dir, "copie.db");
  try {
    copyFileSync(file, copie);
    for (const s of ["-wal", "-shm"]) if (existsSync(file + s)) copyFileSync(file + s, copie + s);
    const db = new DatabaseSync(copie);
    try {
      return fn(db);
    } finally {
      db.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const valeur = (db, sql) => Object.values(db.prepare(sql).get() ?? {})[0];

function tables(db) {
  const noms = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all().map((r) => r.name);
  return Object.fromEntries(noms.map((n) => [n, Number(valeur(db, `SELECT COUNT(*) FROM "${n.replace(/"/g, '""')}"`))]));
}

function info(file) {
  const octets = statSync(file).size;
  const empreinte = sha256(file);
  return surCopie(file, (db) => {
    const integrity = db.prepare("PRAGMA integrity_check").all().map((r) => Object.values(r)[0]);
    return {
      fichier: file,
      octets,
      sha256: empreinte,
      user_version: Number(valeur(db, "PRAGMA user_version")),
      integrity: integrity.length === 1 && integrity[0] === "ok" ? "ok" : integrity.slice(0, 5).join(" ; "),
      journal_mode: valeur(db, "PRAGMA journal_mode"),
      tables: tables(db),
    };
  });
}

function acquittes(args) {
  const avant = Number(args.avant);
  if (!Number.isFinite(avant) || !args.reference || !args.copie) throw new Usage("acquittes attend --avant, --reference et --copie");
  // Éléments créés strictement avant l'horodatage (secondes entières) : leur
  // création a été acquittée avant le début de la copie. Ceux dont la DERNIÈRE
  // écriture (modification, corbeille) précède aussi l'horodatage doivent avoir,
  // dans la copie, la même révision et le même état de corbeille.
  const lire = (db, sql, ...p) => db.prepare(sql).all(...p).map((r) => ({ id: r.id, rev: Number(r.revision), del: r.deleted_at ?? null }));
  const { ref, figes } = surCopie(args.reference, (db) => ({
    ref: lire(db, "SELECT id, revision, deleted_at FROM items WHERE created_at < ?", avant),
    figes: new Set(db.prepare("SELECT id FROM items WHERE created_at < ?1 AND updated_at < ?1 AND COALESCE(deleted_at, 0) < ?1")
      .all(avant).map((r) => r.id)),
  }));
  const copie = surCopie(args.copie, (db) => new Map(lire(db, "SELECT id, revision, deleted_at FROM items").map((r) => [r.id, r])));
  const manquants = ref.filter((r) => !copie.has(r.id)).map((r) => r.id);
  const perimes = ref.filter((r) => figes.has(r.id) && copie.has(r.id)
    && (copie.get(r.id).rev !== r.rev || copie.get(r.id).del !== r.del)).map((r) => r.id);
  return {
    avant,
    attendus: ref.length,
    presents: ref.length - manquants.length,
    manquants: manquants.length,
    exemples: manquants.slice(0, 10),
    modifications_attendues: figes.size,
    modifications_perdues: perimes.length,
    exemples_modifications: perimes.slice(0, 10),
    elements_copie: copie.size,
  };
}

function forger(file, version) {
  const v = Number(version);
  if (!Number.isInteger(v) || v < 0) throw new Usage("forger attend un entier positif");
  const db = new DatabaseSync(file);
  try {
    db.exec(`PRAGMA user_version = ${v}`);
    // Ramène tout dans le fichier principal : la copie forgée se suffit à elle-même.
    db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
  } finally {
    db.close();
  }
  for (const s of ["-wal", "-shm"]) if (existsSync(file + s) && statSync(file + s).size === 0) unlinkSync(file + s);
  return { fichier: file, user_version: v, sha256: sha256(file) };
}

function reglages(file) {
  return surCopie(file, (db) => {
    const ancien = db.prepare("SELECT value FROM settings WHERE key = 'org'").get();
    const registre = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'org_settings'").get()
      ? Object.fromEntries(db.prepare("SELECT key, value FROM org_settings ORDER BY key").all().map((r) => [r.key, JSON.parse(r.value)]))
      : null;
    return { org: ancien ? JSON.parse(ancien.value) : null, org_settings: registre };
  });
}

function options(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const m = /^--([a-z]+)$/.exec(argv[i]);
    if (!m || argv[i + 1] === undefined) throw new Usage(`option invalide : ${argv[i]}`);
    out[m[1]] = argv[++i];
  }
  return out;
}

function main(argv) {
  const [cmd, ...rest] = argv;
  try {
    let r;
    if (cmd === "info" && rest.length === 1) r = info(resolve(rest[0]));
    else if (cmd === "acquittes") {
      const o = options(rest);
      r = acquittes({ ...o, reference: o.reference && resolve(o.reference), copie: o.copie && resolve(o.copie) });
    } else if (cmd === "forger" && rest.length === 2) r = forger(resolve(rest[0]), rest[1]);
    else if (cmd === "reglages" && rest.length === 1) r = reglages(resolve(rest[0]));
    else if (cmd === "-h" || cmd === "--help") {
      process.stdout.write(`${USAGE}\n`);
      return 0;
    } else throw new Usage(cmd ? `commande inconnue ou arguments manquants : ${cmd}` : "commande manquante");
    process.stdout.write(`${JSON.stringify(r, null, 2)}\n`);
    return 0;
  } catch (e) {
    if (e instanceof Usage) {
      process.stderr.write(`Erreur : ${e.message}\n\n${USAGE}\n`);
      return 2;
    }
    process.stderr.write(`Erreur : ${e.message}\n`);
    return 1;
  }
}

process.exitCode = main(process.argv.slice(2));
