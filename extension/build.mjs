// Construit l'extension prête à charger : extension/dist/locksy-extension
// Usage : node extension/build.mjs   (le conteneur « locksy » doit tourner,
// il fournit le module WebAssembly compilé ; ou LOCKSY_WASM=chemin/locksy.wasm).
import { cpSync, mkdirSync, rmSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const web = join(here, "..", "web");
const out = join(here, "dist", "locksy-extension");

rmSync(out, { recursive: true, force: true });
mkdirSync(join(out, "lib"), { recursive: true });
mkdirSync(join(out, "icons"), { recursive: true });
cpSync(join(here, "src"), out, { recursive: true });
for (const f of ["wasm.js", "aad.js", "api.js", "dom.js", "vault.js", "prefs.js"]) cpSync(join(web, "js", f), join(out, "lib", f));
cpSync(join(web, "css", "app.css"), join(out, "lib", "app.css"));

const wasm = join(out, "lib", "locksy.wasm");
if (process.env.LOCKSY_WASM) cpSync(process.env.LOCKSY_WASM, wasm);
else execFileSync("docker", ["cp", "locksy:/app/web/locksy.wasm", wasm], { stdio: "inherit" });
if (!existsSync(wasm)) throw new Error("locksy.wasm introuvable : démarrez le serveur (docker compose up -d).");

// ---- Icônes : logo officiel (branding/png)
for (const size of [16, 32, 48, 128]) cpSync(join(here, "..", "branding", "png", `locksy-${size}.png`), join(out, "icons", `${size}.png`));

console.log(`Extension prête : ${out}`);
