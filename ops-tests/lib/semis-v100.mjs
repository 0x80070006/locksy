#!/usr/bin/env node
// Complément du semis d'une instance 1.0.0 (recette de mise à jour, G32).
//
// Le jeu E2E est semé par bench/seed/seed.mjs exécuté avec le client 1.0.0
// (copie de bench/seed à côté des sources 1.0.0, voir ops-tests/lib.sh
// sources_v100). Ce module ajoute ce que le jeu E2E ne contient pas, avec le
// MÊME client 1.0.0 (web/js et locksy.wasm de la 1.0.0) :
// - les 5 réglages de l'organisation de la 1.0.0 (PUT /api/admin/settings) ;
// - un lien de partage chiffré.
// Il écrit leur description (valeurs et empreinte du clair) dans
// <out>/v100.json. Après la mise à jour, `controler-lien` rouvre ce lien avec
// le client COURANT (parcours de la page publique : preuve de possession, puis
// lecture historique si le lien n'en a pas) et compare l'empreinte ;
// `controler-reglages` relit les 5 réglages dans le registre du serveur courant.
//
//   node ops-tests/lib/semis-v100.mjs completer --base <url> --client <dossier web/js> --wasm <fichier> --out <dossier>
//   node ops-tests/lib/semis-v100.mjs controler-lien --base <url> --client <dossier web/js> --wasm <fichier> --out <dossier>
//   node ops-tests/lib/semis-v100.mjs controler-reglages --base <url> --out <dossier>
//
// <out> contient users.json (bench/seed/seed.mjs). Les valeurs sont des
// valeurs de TEST, jamais des secrets de production.
// Codes de sortie : 0 réussite, 1 échec, 2 usage invalide.

import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { createHash, randomBytes } from "node:crypto";
import { setWasmSource, setForwardedFor } from "../../bench/seed/shim.mjs";

const USAGE = `Complément du semis 1.0.0 : réglages de l'organisation et lien de partage.

Usage : node ops-tests/lib/semis-v100.mjs completer      --base <url> --client <web/js> --wasm <fichier> --out <dossier>
        node ops-tests/lib/semis-v100.mjs controler-lien --base <url> --client <web/js> --wasm <fichier> --out <dossier>
        node ops-tests/lib/semis-v100.mjs controler-reglages --base <url> --out <dossier>

Codes de sortie : 0 réussite, 1 échec, 2 usage invalide.`;

/** Les 5 réglages de la 1.0.0, tous différents de leur valeur par défaut sauf require_2fa. */
const REGLAGES_V100 = {
  // Laissé à faux : à vrai, les comptes sans 2FA ne pourraient plus se connecter
  // pour la vérification déchiffrée d'après la mise à jour.
  require_2fa: false,
  session_idle_minutes: 45,
  session_max_hours: 10,
  audit_retention_days: 400,
  trash_retention_days: 21,
};

/** Clé du registre qui reprend chaque ancien réglage (settings_api.rs, table des anciens champs). */
const CLES_REGISTRE = {
  require_2fa: "twofa.required",
  session_idle_minutes: "session.idle_minutes",
  session_max_hours: "session.max_hours",
  audit_retention_days: "retention.audit_days",
  trash_retention_days: "retention.trash_days",
};

const sha256 = (s) => createHash("sha256").update(s).digest("hex");
class Usage extends Error {}

function options(argv) {
  const [cmd, ...rest] = argv;
  const avecClient = ["base", "client", "wasm", "out"];
  const requis = { completer: avecClient, "controler-lien": avecClient, "controler-reglages": ["base", "out"] }[cmd];
  if (!requis) throw new Usage(cmd ? `commande inconnue : ${cmd}` : "commande manquante");
  const o = { cmd };
  for (let i = 0; i < rest.length; i += 2) {
    const m = /^--(base|client|wasm|out)$/.exec(rest[i]);
    if (!m || !rest[i + 1]) throw new Usage(`option invalide : ${rest[i]}`);
    o[m[1]] = rest[i + 1];
  }
  for (const k of requis) if (!o[k]) throw new Usage(`option obligatoire manquante : --${k}`);
  o.base = o.base.replace(/\/+$/, "");
  return o;
}

/** Modules du client choisi (1.0.0 ou courant), chargés après l'environnement simulé. */
async function client(o) {
  setWasmSource({ file: resolve(o.wasm) });
  const dir = pathToFileURL(`${resolve(o.client)}/`);
  const W = await import(new URL("wasm.js", dir));
  const A = await import(new URL("api.js", dir));
  const V = await import(new URL("vault.js", dir));
  const AAD = await import(new URL("aad.js", dir));
  A.setBase(o.base);
  await W.loadCrypto("/locksy.wasm");
  return { W, A, V, AAD };
}

async function proprietaire(o) {
  const users = JSON.parse(await readFile(resolve(o.out, "users.json"), "utf8"));
  const owner = users.find((u) => u.role === "owner");
  if (!owner) throw new Error("aucun propriétaire dans users.json");
  return owner;
}

async function completer(o) {
  const { A, V } = await client(o);
  const owner = await proprietaire(o);
  setForwardedFor(owner.xff);
  const r = await V.login({ email: owner.email, password: owner.password });
  if (r.needTotp) throw new Error(`${owner.email} : double authentification inattendue`);
  try {
    await A.api("PUT", "/admin/settings", REGLAGES_V100);
    const relus = await A.api("GET", "/admin/settings");
    for (const [k, v] of Object.entries(REGLAGES_V100)) {
      if (relus[k] !== v) throw new Error(`réglage ${k} relu à ${relus[k]}, ${v} attendu`);
    }
    const charge = {
      name: "Lien de recette ops",
      username: "recette-ops",
      password: randomBytes(12).toString("base64url"),
      notes: "Créé par la version 1.0.0 avant la mise à jour.",
    };
    const lien = await V.createShareLink(charge, 7 * 24 * 60, 5);
    const id = /\/s\/([^#/?]+)#/.exec(lien.url)?.[1];
    if (!id) throw new Error(`adresse de lien inattendue : ${lien.url}`);
    const sortie = {
      version_client: "1.0.0",
      reglages: REGLAGES_V100,
      lien: { id, cle: lien.url.split("#")[1], expires_at: lien.expires_at, clair_sha256: sha256(JSON.stringify(charge)) },
    };
    await writeFile(resolve(o.out, "v100.json"), `${JSON.stringify(sortie, null, 2)}\n`, { mode: 0o600 });
    return { reglages: Object.keys(REGLAGES_V100).length, lien: id };
  } finally {
    await V.logout().catch(() => {});
    setForwardedFor(null);
  }
}

/** Requête publique, sans session, comme la page web/share.html. */
async function publique(o, method, path, body) {
  const res = await fetch(`${o.base}/api${path}`, {
    method,
    headers: body === undefined ? {} : { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = null;
  try { data = await res.json(); } catch { /* corps vide */ }
  return { status: res.status, data };
}

async function controlerLien(o) {
  const { W, AAD } = await client(o);
  const v100 = JSON.parse(await readFile(resolve(o.out, "v100.json"), "utf8"));
  const { id, cle, clair_sha256: attendu } = v100.lien;
  setForwardedFor("10.77.0.1");
  let parcours = "historique";
  let proof = null;
  try { proof = W.call("share_proof", { key: cle })?.proof || null; } catch { /* client sans preuve */ }
  let res = null;
  if (proof) {
    const peek = await publique(o, "POST", `/public/shares/${encodeURIComponent(id)}/peek`, { proof });
    if (peek.status !== 404) {
      parcours = "preuve";
      if (peek.status !== 200) throw new Error(`aperçu du lien : HTTP ${peek.status} ${peek.data?.error || ""}`);
      res = await publique(o, "POST", `/public/shares/${encodeURIComponent(id)}/open`, { proof, nonce: randomBytes(16).toString("base64url") });
    }
  }
  res ??= await publique(o, "GET", `/public/shares/${encodeURIComponent(id)}`);
  setForwardedFor(null);
  if (res.status !== 200 || !res.data?.data) throw new Error(`ouverture du lien (${parcours}) : HTTP ${res.status} ${res.data?.error || ""}`);
  const key = W.call("import_key", { key: cle });
  try {
    const clair = W.call("decrypt", { key, data: res.data.data, aad: AAD.share() });
    const obtenu = sha256(JSON.stringify(JSON.parse(clair)));
    if (obtenu !== attendu) throw new Error("clair du lien différent de celui créé par la 1.0.0");
  } finally {
    W.call("drop_key", { key });
  }
  return { lien: id, parcours, dechiffre: true };
}

/**
 * Réglages de la 1.0.0 relus après la mise à jour : valeur reprise dans le
 * registre, et source « org » pour ceux qui diffèrent du défaut.
 */
async function controlerReglages(o) {
  const owner = await proprietaire(o);
  const entete = { "content-type": "application/json", "x-forwarded-for": owner.xff };
  const login = await fetch(`${o.base}/api/auth/login`, {
    method: "POST", headers: entete, body: JSON.stringify({ email: owner.email, auth_key: owner.auth_key_b64, device: "Recette ops" }),
  });
  if (!login.ok) throw new Error(`connexion du propriétaire : HTTP ${login.status}`);
  const { token } = await login.json();
  const auth = { ...entete, authorization: `Bearer ${token}` };
  try {
    const res = await fetch(`${o.base}/api/admin/settings`, { headers: auth });
    if (!res.ok) throw new Error(`GET /api/admin/settings : HTTP ${res.status}`);
    const corps = await res.json();
    const lignes = Object.entries(REGLAGES_V100).map(([ancien, attendu]) => {
      const cle = CLES_REGISTRE[ancien];
      const v = corps.values?.[cle] || {};
      const sourceAttendue = attendu === v.default ? null : "org";
      const ok = v.value === attendu && (sourceAttendue === null || v.source === sourceAttendue);
      return { ancien, cle, attendu, valeur: v.value, defaut: v.default, source: v.source, ok };
    });
    return { reglages: lignes, conformes: lignes.every((l) => l.ok) };
  } finally {
    await fetch(`${o.base}/api/auth/logout`, { method: "POST", headers: auth }).catch(() => {});
  }
}

async function main() {
  let o;
  try {
    o = options(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(`Erreur : ${e.message}\n\n${USAGE}\n`);
    return 2;
  }
  try {
    const r = await { completer, "controler-lien": controlerLien, "controler-reglages": controlerReglages }[o.cmd](o);
    process.stdout.write(`${JSON.stringify(r, null, 2)}\n`);
    return r.conformes === false ? 1 : 0;
  } catch (e) {
    process.stderr.write(`Échec (${o.cmd}) : ${e.message}${e.code ? ` [${e.code}]` : ""}\n`);
    return 1;
  }
}

process.exitCode = await main();
