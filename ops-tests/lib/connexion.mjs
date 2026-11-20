#!/usr/bin/env node
// Tentative de connexion brute d'un compte semé, sans Argon2 : la preuve
// d'authentification (auth_key_b64 de users.json) est envoyée telle quelle,
// avec un code TOTP calculé ici (RFC 6238, SHA-1, 6 chiffres, 30 s) si le
// compte a la double authentification. Sert à constater la réponse du
// serveur quand sa clé a changé (restauration sans server.key, G31).
//
//   node ops-tests/lib/connexion.mjs --base <url> --out <dossier users.json> --email <adresse> [--sans-code]
//
// Sortie : { email, totp, etapes: [{ code_totp, status, error, message }] }.
// Code de sortie : 0 si les requêtes ont abouti (quel que soit le statut HTTP),
// 1 serveur injoignable, 2 usage invalide.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { createHmac } from "node:crypto";

const USAGE = `Connexion brute d'un compte semé (constat de la réponse du serveur).

Usage : node ops-tests/lib/connexion.mjs --base <url> --out <dossier> --email <adresse> [--sans-code]`;

function base32(s) {
  const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of s.replace(/[=\s]/g, "").toUpperCase()) {
    const v = alpha.indexOf(c);
    if (v < 0) throw new Error("secret TOTP invalide");
    bits += v.toString(2).padStart(5, "0");
  }
  const out = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}

function totp(secret, t = Date.now()) {
  const compteur = Buffer.alloc(8);
  compteur.writeBigUInt64BE(BigInt(Math.floor(t / 30000)));
  const h = createHmac("sha1", base32(secret)).update(compteur).digest();
  const o = h[h.length - 1] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

function options(argv) {
  const o = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--sans-code") { o.sansCode = true; continue; }
    const m = /^--(base|out|email)$/.exec(argv[i]);
    if (!m || !argv[i + 1]) throw new Error(`option invalide : ${argv[i]}`);
    o[m[1]] = argv[++i];
  }
  for (const k of ["base", "out", "email"]) if (!o[k]) throw new Error(`option obligatoire manquante : --${k}`);
  return o;
}

async function essai(base, user, code) {
  const res = await fetch(`${base.replace(/\/+$/, "")}/api/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-forwarded-for": user.xff || "10.78.0.1" },
    body: JSON.stringify({ email: user.email, auth_key: user.auth_key_b64, totp: code, device: "Recette ops" }),
  });
  const texte = await res.text();
  let corps = null;
  try { corps = JSON.parse(texte); } catch { /* corps non JSON */ }
  return { code_totp: code ? "fourni" : "aucun", status: res.status, error: corps?.error ?? null, message: corps?.message ?? texte.slice(0, 200) };
}

async function main() {
  let o;
  try {
    o = options(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(`Erreur : ${e.message}\n\n${USAGE}\n`);
    return 2;
  }
  const users = JSON.parse(readFileSync(resolve(o.out, "users.json"), "utf8"));
  const user = users.find((u) => u.email === o.email);
  if (!user) {
    process.stderr.write(`Erreur : ${o.email} absent de users.json\n`);
    return 2;
  }
  try {
    const etapes = [await essai(o.base, user, null)];
    if (user.totp_secret && !o.sansCode) etapes.push(await essai(o.base, user, totp(user.totp_secret)));
    process.stdout.write(`${JSON.stringify({ email: user.email, totp: !!user.totp_secret, etapes }, null, 2)}\n`);
    return 0;
  } catch (e) {
    process.stderr.write(`Erreur : serveur injoignable (${e.cause?.code || e.message})\n`);
    return 1;
  }
}

process.exitCode = await main();
