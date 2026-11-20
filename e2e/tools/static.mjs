#!/usr/bin/env node
// Serveur statique des tests d'interface (projet Playwright « ui-gallery »).
//
//   node tools/static.mjs [--port 4173] [--host 127.0.0.1] [--wasm <fichier>]
//
// - web/ est servi sous « / » et e2e/ui-gallery/ sous « /gallery/ » ;
// - chaque réponse porte les MÊMES en-têtes de sécurité que le serveur Locksy
//   (crates/locksy-server/src/main.rs, fonction security_headers), CSP comprise :
//   une page qui passe ici passe aussi en production ;
// - « /locksy.wasm » vient de web/ s'il existe, sinon du fichier donné par
//   --wasm ou par la variable E2E_WASM (tools/run.sh l'extrait de l'image serveur).
// Aucune dépendance : Node 20 ou plus.

import { createServer } from "node:http";
import { createReadStream, existsSync, statSync } from "node:fs";
import { extname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const here = fileURLToPath(new URL(".", import.meta.url));
const e2eDir = resolve(here, "..");
const repo = resolve(e2eDir, "..");

/** CSP de main.rs, recopiée à l'identique. Le test tests/smoke/statique.api.spec.ts
 * compare cette valeur à l'en-tête du vrai serveur : tout écart le fait échouer. */
export const CSP =
  "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; " +
  "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; " +
  "frame-ancestors 'none'";

export const SECURITY_HEADERS = Object.freeze({
  "content-security-policy": CSP,
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "x-robots-tag": "noindex, nofollow",
  "cache-control": "no-cache",
});

const MIME = Object.freeze({
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
  ".webmanifest": "application/manifest+json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".webp": "image/webp",
  ".ico": "image/x-icon",
  ".wasm": "application/wasm",
  ".woff2": "font/woff2",
  ".txt": "text/plain; charset=utf-8",
});

function parseArgs(argv) {
  const opts = { port: 4173, host: "127.0.0.1", wasm: process.env.E2E_WASM || "" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`Valeur manquante après ${a}.`);
      return v;
    };
    if (a === "--port") opts.port = Number(next());
    else if (a === "--host") opts.host = next();
    else if (a === "--wasm") opts.wasm = next();
    else throw new Error(`Option inconnue : ${a}`);
  }
  if (!Number.isInteger(opts.port) || opts.port < 1 || opts.port > 65535) throw new Error("Port invalide.");
  return opts;
}

/** Résout un chemin d'URL sous `root`, ou null s'il en sort. */
function inside(root, urlPath) {
  const target = normalize(join(root, urlPath));
  return target === root || target.startsWith(root + sep) ? target : null;
}

/** Fichier à servir pour un chemin d'URL déjà décodé, ou null. */
export function resolveFile(urlPath, { webRoot, galleryRoot, wasm }) {
  if (urlPath === "/locksy.wasm") {
    const own = join(webRoot, "locksy.wasm");
    if (existsSync(own)) return own;
    return wasm && existsSync(wasm) ? resolve(wasm) : null;
  }
  const [root, rest] = urlPath.startsWith("/gallery/") ? [galleryRoot, urlPath.slice("/gallery".length)] : [webRoot, urlPath];
  let file = inside(root, rest);
  if (!file || !existsSync(file)) return null;
  if (statSync(file).isDirectory()) file = join(file, "index.html");
  return existsSync(file) && statSync(file).isFile() ? file : null;
}

export function startServer({ port, host, wasm = "" }) {
  const roots = { webRoot: join(repo, "web"), galleryRoot: join(e2eDir, "ui-gallery"), wasm };
  const server = createServer((req, res) => {
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);
    const send = (status, body, type = "text/plain; charset=utf-8") => {
      res.writeHead(status, { "content-type": type });
      res.end(body);
    };
    if (req.method !== "GET" && req.method !== "HEAD") return send(405, "Méthode non autorisée.\n");
    let path;
    try {
      path = decodeURIComponent(new URL(req.url, "http://localhost").pathname);
    } catch {
      return send(400, "Adresse invalide.\n");
    }
    if (path.includes("\0")) return send(400, "Adresse invalide.\n");
    if (path === "/gallery") {
      res.writeHead(308, { location: "/gallery/" });
      return res.end();
    }
    const file = resolveFile(path, roots);
    if (!file) return send(404, "Introuvable.\n");
    res.writeHead(200, { "content-type": MIME[extname(file).toLowerCase()] || "application/octet-stream" });
    if (req.method === "HEAD") return res.end();
    createReadStream(file).on("error", () => res.destroy()).pipe(res);
  });
  return new Promise((ok, ko) => {
    server.once("error", ko);
    server.listen(port, host, () => ok(server));
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let opts;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (e) {
    console.error(e.message);
    process.exit(2);
  }
  await startServer(opts);
  console.log(`Serveur statique prêt : http://${opts.host}:${opts.port}/ (web) et /gallery/ (galerie)`);
}
