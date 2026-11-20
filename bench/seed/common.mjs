// Outils partagés par seed.mjs, verify.mjs et worker.mjs : lecture des
// arguments, empreintes du manifeste, adresses X-Forwarded-For, progression
// et réserve de fils (worker_threads). Aucune dépendance.

import { createHash } from "node:crypto";
import { availableParallelism } from "node:os";
import { Worker } from "node:worker_threads";

export const MANIFEST_FORMAT = 1;

/**
 * Lit `--nom valeur` et `--drapeau`. `spec` : { nom: "string" | "boolean" }.
 * Lève une erreur en français pour une option inconnue ou sans valeur.
 */
export function parseArgs(argv, spec) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const m = /^--([a-z][a-z0-9-]*)(?:=(.*))?$/.exec(arg);
    if (!m || !(m[1] in spec)) throw new Error(`Option inconnue : ${arg}`);
    const [, name, inline] = m;
    if (spec[name] === "boolean") {
      out[name] = true;
    } else {
      const value = inline ?? argv[++i];
      if (value === undefined || value === "") throw new Error(`Valeur manquante pour --${name}`);
      out[name] = value;
    }
  }
  return out;
}

/** Entier strictement positif lu dans une option, sinon `fallback`. */
export function positiveInt(value, name, fallback) {
  if (value === undefined) return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1) throw new Error(`--${name} attend un entier positif (reçu : ${value}).`);
  return n;
}

/** Nombre de fils par défaut : la moitié des processeurs, entre 1 et 6. */
export const defaultWorkers = () => Math.max(1, Math.min(6, Math.floor(availableParallelism() / 2)));

export const sha256 = (data) => createHash("sha256").update(data).digest("hex");

/** Contenu comparé d'un élément : ses données sans les pièces jointes (vérifiées à part). */
export function canonicalItem(data) {
  const { attachments: _ignored, ...rest } = data;
  return JSON.stringify(rest);
}

/** Empreinte d'un ensemble d'éléments, indépendante de leur ordre. */
export function itemsDigest(list) {
  return sha256(list.map((d) => sha256(canonicalItem(d))).sort().join("\n"));
}

/**
 * Adresse annoncée pour le compte n° `n` : `<préfixe>.<octet>.<octet>`. Chaque
 * compte a la sienne, si bien que les limites par IP (inscription 10/h,
 * connexion 100/10 min) ne se cumulent jamais entre comptes.
 */
export function xffFor(prefix, n) {
  if (!/^\d{1,3}\.\d{1,3}$/.test(prefix)) throw new Error(`--xff-prefix attend deux octets, par exemple 10.200 (reçu : ${prefix}).`);
  if (n < 0 || n > 65535) throw new Error(`Trop de comptes pour le préfixe ${prefix} (65 536 au plus).`);
  return `${prefix}.${(n >> 8) & 255}.${n & 255}`;
}

/** Durée lisible : « 1 min 05 s ». */
export function formatDuration(ms) {
  const s = Math.round(ms / 1000);
  return s < 60 ? `${s} s` : `${Math.floor(s / 60)} min ${String(s % 60).padStart(2, "0")} s`;
}

/** Progression sur la sortie d'erreur (la sortie standard reste libre). */
export function progress(label) {
  const start = Date.now();
  let last = 0;
  return {
    tick(done, total, extra = "") {
      const t = Date.now();
      if (done < total && t - last < 2000) return;
      last = t;
      process.stderr.write(`  ${label} : ${done}/${total}${extra ? ` · ${extra}` : ""} · ${formatDuration(t - start)}\n`);
    },
    elapsed: () => Date.now() - start,
  };
}

/**
 * Réserve de fils worker_threads exécutant worker.mjs. Chaque fil a son propre
 * module vault.js (dont l'état est global) : un compte en cours par fil.
 */
export class Pool {
  constructor(size, init) {
    this.size = size;
    this.init = init;
    this.idle = [];
    this.all = new Set();
    this.queue = [];
  }

  /** Exécute une tâche sur le premier fil libre ; renvoie son résultat. */
  run(task) {
    return new Promise((resolve, reject) => {
      this.queue.push({ task, resolve, reject });
      this.#dispatch();
    });
  }

  /** Exécute toutes les tâches, `onDone(i, résultat)` à chaque fin ; échoue à la première erreur. */
  async runAll(tasks, onDone = () => {}) {
    const results = new Array(tasks.length);
    await Promise.all(tasks.map((t, i) => this.run(t).then((r) => { results[i] = r; onDone(i, r); })));
    return results;
  }

  #spawn() {
    const w = new Worker(new URL("./worker.mjs", import.meta.url), { workerData: this.init });
    w.current = null;
    w.on("message", (msg) => {
      const job = w.current;
      w.current = null;
      this.idle.push(w);
      if (msg.ok) job.resolve(msg.result);
      else job.reject(Object.assign(new Error(msg.error.message), msg.error));
      this.#dispatch();
    });
    w.on("error", (e) => {
      this.all.delete(w);
      w.current?.reject(e);
      w.current = null;
      this.#dispatch();
    });
    this.all.add(w);
    return w;
  }

  #dispatch() {
    while (this.queue.length) {
      let w = this.idle.pop();
      if (!w && this.all.size < this.size) w = this.#spawn();
      if (!w) return;
      const job = this.queue.shift();
      w.current = job;
      w.postMessage(job.task);
    }
  }

  async close() {
    await Promise.all([...this.all].map((w) => w.terminate()));
    this.all.clear();
    this.idle = [];
  }
}

/**
 * Appel direct de l'API (fil principal, sans module WebAssembly) : création
 * des invitations et statistiques d'administration. Lève une erreur portant
 * `code` et `status` comme le client web.
 */
export async function rawApi(base, method, path, { token, xff, body } = {}) {
  const headers = { "user-agent": "locksy-banc-semis" };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (token) headers.authorization = `Bearer ${token}`;
  if (xff) headers["x-forwarded-for"] = xff;
  let res;
  try {
    res = await fetch(`${base}/api${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  } catch (e) {
    throw Object.assign(new Error(`Serveur injoignable (${base}) : ${e.cause?.code || e.message}`), { code: "network", status: 0 });
  }
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw Object.assign(new Error(data.message || `HTTP ${res.status} sur ${method} ${path}`), { code: data.error || "error", status: res.status });
  }
  return data;
}

/** Session ouverte avec la preuve d'authentification d'un compte semé (pas d'Argon2). */
export async function rawLogin(base, user, xff) {
  const res = await rawApi(base, "POST", "/auth/login", { xff, body: { email: user.email, auth_key: user.auth_key_b64, device: "Banc" } });
  return res.token;
}

/** Message d'une erreur du client ou du serveur, avec son code s'il existe. */
export const describeError = (e) => `${e.message}${e.code && e.code !== "error" ? ` [${e.code}${e.status ? ` ${e.status}` : ""}]` : ""}`;
