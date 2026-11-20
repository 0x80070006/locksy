#!/usr/bin/env node
// Zero-knowledge (G12), partie base : recherche, dans la base du serveur
// « locksy » de l'environnement de test, des clairs relevés par
// zero-knowledge.spec.ts (e2e/.state/<cle>/zk-clairs.json). Attendu :
// 0 occurrence. Clairs admis : e-mails et noms des comptes, journal d'audit.
//
//   node e2e/security/zk-analyse.mjs --cle <cle>
//
// Lancé par e2e/security/run.sh APRÈS Playwright et AVANT « down -v ».
// Étapes :
//   1. sauvegarde à chaud dans le conteneur (locksy-server backup /tmp/zk.db --force) ;
//   2. copie de la sauvegarde, de /data/locksy.db et de son journal WAL par
//      « exec cat » (docker cp ne lit pas un tmpfs) vers e2e/.state/<cle>/ ;
//   3. recherche de chaque clair (UTF-8) dans chaque copie.
// Code de sortie : 0 (aucun clair, ou relevé absent), 1 (clair trouvé ou
// analyse invalide), 2 (usage).
// Sans dépendance : Node 20 ou plus.

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const DEPOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

function usage(message) {
  if (message) console.error(`zk-analyse : ${message}`);
  console.error("Usage : node e2e/security/zk-analyse.mjs --cle <cle>");
  process.exit(2);
}

const args = process.argv.slice(2);
const i = args.indexOf("--cle");
const cle = i >= 0 ? args[i + 1] : "";
if (!cle || !/^[a-z0-9][a-z0-9_-]*$/.test(cle)) usage("clé absente ou invalide");

const etat = join(DEPOT, "e2e", ".state", cle);
const releve = join(etat, "zk-clairs.json");
if (!existsSync(releve)) {
  console.log("zk-analyse : aucun relevé (zero-knowledge.spec.ts n'a pas tourné) : rien à analyser.");
  process.exit(0);
}
const { clairs, secrets, temoin } = JSON.parse(readFileSync(releve, "utf8"));

const compose = ["compose", "-p", cle, "-f", "e2e/docker-compose.e2e.yml", "-f", "e2e/security/docker-compose.securite.yml"];

/** Commande dans le conteneur « locksy » ; renvoie la sortie brute (ou null si elle échoue). */
function dansLocksy(...commande) {
  const r = spawnSync("docker", [...compose, "exec", "-T", "locksy", ...commande], { cwd: DEPOT, maxBuffer: 512 * 1024 * 1024 });
  if (r.status !== 0) {
    const err = (r.stderr || Buffer.alloc(0)).toString("utf8").trim();
    return { ok: false, erreur: err || `code ${r.status}` };
  }
  return { ok: true, sortie: r.stdout };
}

// 1. Sauvegarde à chaud, vérifiée par le serveur.
const sauvegarde = dansLocksy("/app/locksy-server", "backup", "/tmp/zk.db", "--force");
if (!sauvegarde.ok) {
  console.error(`zk-analyse : sauvegarde impossible : ${sauvegarde.erreur}`);
  process.exit(1);
}

// 2. Copies (le WAL peut être absent après un point de contrôle).
mkdirSync(etat, { recursive: true });
const copies = [];
for (const [source, nom, obligatoire] of [
  ["/tmp/zk.db", "zk-sauvegarde.db", true],
  ["/data/locksy.db", "zk-locksy.db", true],
  ["/data/locksy.db-wal", "zk-locksy-wal.db", false],
]) {
  const r = dansLocksy("cat", source);
  if (!r.ok) {
    if (obligatoire) {
      console.error(`zk-analyse : lecture de ${source} impossible : ${r.erreur}`);
      process.exit(1);
    }
    console.log(`zk-analyse : ${source} absent (journal déjà intégré à la base).`);
    continue;
  }
  const chemin = join(etat, nom);
  writeFileSync(chemin, r.sortie);
  copies.push({ source, chemin, octets: r.sortie });
}

// 3. Recherche.
const occurrences = (octets, texte) => {
  const motif = Buffer.from(texte, "utf8");
  let n = 0;
  for (let p = octets.indexOf(motif); p >= 0; p = octets.indexOf(motif, p + 1)) n++;
  return n;
};
const cherches = [...clairs.map((c) => ["clair", c, c]), ...Object.entries(secrets).map(([nom, v]) => [nom, v, `${nom} (${v.length} caractères)`])];
const trouves = [];
for (const { source, octets } of copies) {
  for (const [genre, texte, affiche] of cherches) {
    const n = occurrences(octets, texte);
    if (n) trouves.push({ fichier: source, genre, valeur: affiche, occurrences: n });
  }
}

// Témoin : un clair admis (l'e-mail du compte) est bien présent dans la
// sauvegarde. Sinon la recherche ne prouve rien (copie vide ou illisible).
const temoinVu = occurrences(copies[0].octets, temoin);
const rapport = {
  cle,
  date: new Date().toISOString(),
  fichiers: copies.map((c) => ({ source: c.source, octets: c.octets.length })),
  recherches: cherches.length,
  temoin: { valeur: temoin, occurrences: temoinVu },
  trouves,
};
const sortie = join(DEPOT, "e2e", "test-results", `${cle}-securite`);
mkdirSync(sortie, { recursive: true });
writeFileSync(join(sortie, "zk-analyse.json"), JSON.stringify(rapport, null, 2));

console.log(`zk-analyse : ${cherches.length} valeurs cherchées dans ${copies.map((c) => `${c.source} (${c.octets.length} o)`).join(", ")}.`);
if (!temoinVu) {
  console.error(`zk-analyse : ANALYSE INVALIDE, le témoin « ${temoin} » (clair admis) est absent de la sauvegarde.`);
  process.exit(1);
}
if (trouves.length) {
  console.error("zk-analyse : CLAIRS TROUVÉS dans la base :");
  for (const t of trouves) console.error(`  - ${t.fichier} : ${t.genre} « ${t.valeur} » × ${t.occurrences}`);
  process.exit(1);
}
console.log(`zk-analyse : 0 clair connu dans la base (témoin admis trouvé ${temoinVu} fois). Rapport : e2e/test-results/${cle}-securite/zk-analyse.json`);
