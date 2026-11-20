// Règles du cahier sur web/js/ui/ : A1 (aria-live seulement « off »), R1
// (aucun HTML injecté, aucun style en ligne hors core.js), R3 (aucun texte en
// dur, toute clé t() existe) ; registres copiés (raccourcis, pastilles) égaux
// à leur source design/ ; empreintes du décodeur QR vendorisé.

import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { test, expect } from "../../fixtures/index.ts";
import { BASE_URL } from "../../fixtures/env.ts";
import { REPO, openGallery } from "./galerie.ts";

const UI_DIR = join(REPO, "web", "js", "ui");
const files = () => readdirSync(UI_DIR).filter((f) => f.endsWith(".js")).sort();
const source = (f: string) => readFileSync(join(UI_DIR, f), "utf8");
const lines = (f: string) => source(f).split(/\r?\n/).map((text, i) => ({ file: f, line: i + 1, text }));

/**
 * Identifiants de touches du standard KeyboardEvent (« Ctrl+K », « ArrowUp »,
 * « CapsLock ») : des noms techniques, pas des textes affichés. Le registre
 * design/hotkeys.json les impose sous cette forme.
 */
const KEY_IDENTIFIER = /^(?:(?:Ctrl|Alt|Shift)\+)*(?:[A-Z]|Enter|Escape|ArrowUp|ArrowDown|Home|End|Letter|CapsLock|\/|\?)$/;

test.describe("Règles du cahier sur web/js/ui", () => {
  test("A1 : aria-live n'apparaît que sous la forme « off »", () => {
    const found = files().flatMap(lines).filter((l) => l.text.includes("aria-live"));
    expect(found.length).toBeGreaterThan(0);
    expect(found.filter((l) => !/aria-live"?\s*[:=]\s*"off"|aria-live="off"/.test(l.text)).map((l) => `${l.file}:${l.line}`)).toEqual([]);
  });

  test("R1 : ni HTML injecté, ni eval, ni style en ligne (core.js refuse la clé style)", () => {
    const html = files().flatMap(lines).filter((l) => /innerHTML|outerHTML|insertAdjacentHTML|eval\(|new Function|document\.write/.test(l.text));
    expect(html.map((l) => `${l.file}:${l.line}`)).toEqual([]);
    const style = files().filter((f) => f !== "core.js").flatMap(lines).filter((l) => /style:|"style"|cssText|setAttribute\("style"/.test(l.text));
    expect(style.map((l) => `${l.file}:${l.line}`)).toEqual([]);
    expect(source("core.js")).toMatch(/k === "style"\) throw/);
  });

  test("aucun accès au stockage local ni import interdit", () => {
    const bad = files().flatMap(lines).filter((l) => /localStorage|sessionStorage|indexedDB|from "\.\.\/(vault|api|settings-client)\.js"|from "\.\.\/views\//.test(l.text));
    expect(bad.map((l) => `${l.file}:${l.line} ${l.text.trim()}`)).toEqual([]);
  });

  test("R3 : aucun texte en dur (lint-strings sur web/js/ui)", async () => {
    const { lintSource } = await import(pathToFileURL(join(REPO, "tools", "lint-strings.mjs")).href);
    const findings = files().flatMap((f) => lintSource(source(f), `web/js/ui/${f}`))
      .filter((x: { text: string }) => !KEY_IDENTIFIER.test(x.text));
    expect(findings.map((x: { file: string; line: number; text: string }) => `${x.file}:${x.line} ${x.text}`)).toEqual([]);
  });

  test("R3 : toute clé littérale passée à t(), plural() ou has() existe", async () => {
    const { default: catalog } = await import(pathToFileURL(join(REPO, "web", "js", "i18n", "fr.js")).href);
    const keys = new Set<string>();
    for (const f of files()) {
      for (const m of source(f).matchAll(/\b(?:t|plural|has|tr)\(\s*"((?:ui|common|errors|settings)\.[a-z0-9_.-]+)"/g)) keys.add(m[1]);
      for (const m of source(f).matchAll(/"(ui\.[a-z0-9_.-]+)"/g)) keys.add(m[1]);
    }
    // Clés des sections settings.* fournies par le lot L4 : lues avec repli (has()).
    const missing = [...keys].filter((k) => !k.startsWith("settings.") && !Object.hasOwn(catalog, k));
    expect(missing).toEqual([]);
    // Clés construites : chaque variante utilisée existe.
    const built = [
      ...["password", "username", "totp", "secret"].flatMap((k) => [`ui.copy.${k}`, `ui.copy.${k}_clear`]), "ui.copy.text",
      ...["very_weak", "weak", "medium", "strong", "very_strong"].map((k) => `ui.strength.${k}`),
      ...["global", "vault", "list", "editor"].map((k) => `ui.hotkeys.scope.${k}`),
      ...["seconds", "minutes", "hours", "days"].map((k) => `ui.duration.unit.${k}`),
      ...["user", "admin", "owner"].map((k) => `ui.role.${k}`),
      ...["free", "default", "enforced"].map((k) => `ui.setting.mode.${k}`),
      ...["cidrs", "domains", "emails", "words"].map((k) => `ui.setting.placeholder.${k}`),
    ];
    expect(built.filter((k) => !Object.hasOwn(catalog, k))).toEqual([]);
  });

  test("registre des raccourcis : ui/hotkeys.js = design/hotkeys.json, sans conflit navigateur", async ({ page }) => {
    await openGallery(page, "socle");
    const fromPage = await page.evaluate(() => (window as any).gallery.ui.HOTKEYS);
    const fromJson = JSON.parse(readFileSync(join(REPO, "design", "hotkeys.json"), "utf8"));
    expect(fromPage).toEqual(fromJson);
    const forbidden = /^Ctrl\+(N|T|W|L|R|B|C|V)$/i;
    expect(fromJson.flatMap((e: { keys: string[] }) => e.keys).filter((k: string) => forbidden.test(k))).toEqual([]);
    const ids = fromJson.map((e: { id: string }) => e.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  test("pastilles : colorFor() utilise les 8 couleurs de design/tokens.json, dans l'ordre", async ({ page }) => {
    await openGallery(page, "socle");
    const tokens = JSON.parse(readFileSync(join(REPO, "design", "tokens.json"), "utf8"));
    const inPage = await page.evaluate(() => {
      const { ui } = (window as any).gallery;
      return { tiles: [...ui.TILE_COLORS], sample: ["Gmail", "Hugo Martin", "Équipe IT"].map((n: string) => ui.colorFor(n)) };
    });
    expect(inPage.tiles).toEqual(tokens.tile);
    for (const c of inPage.sample) expect(tokens.tile).toContain(c);
  });
});

test.describe("Décodeur QR vendorisé (web/vendor/qr)", () => {
  const dir = join(REPO, "web", "vendor", "qr");
  const sums = () => readFileSync(join(dir, "SHA256SUMS"), "utf8").trim().split(/\r?\n/).map((l) => {
    const [hash, name] = l.split(/\s+\*?/);
    return { hash, name };
  });

  test("empreintes SHA-256 conformes à SHA256SUMS (disque et serveur)", async ({ request }) => {
    const list = sums();
    expect(list.map((s) => s.name).sort()).toEqual(["LICENSE", "SOURCE.txt", "jsqr-1.4.0.mjs"]);
    for (const { hash, name } of list) {
      expect(createHash("sha256").update(readFileSync(join(dir, name))).digest("hex"), name).toBe(hash);
    }
    const served = await request.get("/vendor/qr/jsqr-1.4.0.mjs");
    expect(served.status()).toBe(200);
    expect(served.headers()["content-type"]).toMatch(/javascript/);
    expect(createHash("sha256").update(await served.body()).digest("hex")).toBe(list.find((s) => s.name === "jsqr-1.4.0.mjs")!.hash);
    const meta = readFileSync(join(dir, "SOURCE.txt"), "utf8");
    expect(meta).toContain("Version     : 1.4.0");
    expect(meta).toContain("Apache-2.0");
    expect(readFileSync(join(dir, "LICENSE"), "utf8")).toContain("Apache License");
  });

  test("servi par le serveur Locksy avec un type JavaScript", async ({ request }) => {
    test.skip(process.env.E2E_NO_SERVER === "1", "Galerie seule : aucun serveur Locksy démarré.");
    const res = await request.get(`${BASE_URL}/vendor/qr/jsqr-1.4.0.mjs`);
    expect(res.status()).toBe(200);
    expect(res.headers()["content-type"]).toMatch(/javascript/);
    expect(res.headers()["x-content-type-options"]).toBe("nosniff");
    const expected = sums().find((s) => s.name === "jsqr-1.4.0.mjs")!.hash;
    expect(createHash("sha256").update(await res.body()).digest("hex")).toBe(expected);
  });

  test("chargé par import dynamique sous la CSP, sans eval", async ({ page }) => {
    await openGallery(page, "qr");
    const kind = await page.evaluate(async () => typeof (await import("/vendor/qr/jsqr-1.4.0.mjs")).default);
    expect(kind).toBe("function");
    expect(readFileSync(join(dir, "jsqr-1.4.0.mjs"), "utf8")).not.toMatch(/\beval\(|new Function/);
  });

  test("qrImport() lit un QR code otpauth:// collé, refuse un QR code ordinaire", async ({ page, browserName }) => {
    // Firefox ignore les données d'un événement « paste » synthétique : on y
    // passe par le dépôt (drop), l'autre chemin de la zone d'import.
    const drop = browserName === "firefox";
    await openGallery(page, "qr");
    await page.evaluate(pasteQr, { text: "otpauth://totp/Exemple:demo?secret=JBSWY3DPEHPK3PXP", drop });
    await expect(page.locator("[data-sortie=qr]")).toHaveText("QR code de configuration reçu");
    await expect(page.locator("#status")).toHaveText("QR code lu.");
    await page.evaluate(pasteQr, { text: "https://exemple.fr/une-page-sans-code", drop });
    await expect(page.locator(".c-qr-drop .c-field__error")).toHaveText(/ne contient pas de code de vérification/);
  });
});

/**
 * Dessine dans la page un QR code (version 3, correction L, masque 0, mode
 * octet : 53 octets au plus) et le colle (ou le dépose) dans la zone d'import. Encodeur
 * minimal autonome (exécuté dans la page), d'après la norme ISO/IEC 18004.
 */
async function pasteQr({ text, drop }: { text: string; drop: boolean }) {
  const size = 29;
  const DATA_CW = 55;
  const EC_CW = 15;
  const bytes = [...new TextEncoder().encode(text)];
  if (bytes.length > 53) throw new Error("texte trop long pour la version 3-L");
  // Flux de bits : mode octet, longueur sur 8 bits, données, terminaison, remplissage.
  const bits: number[] = [];
  const put = (v: number, n: number) => { for (let i = n - 1; i >= 0; i--) bits.push((v >>> i) & 1); };
  put(0b0100, 4);
  put(bytes.length, 8);
  for (const b of bytes) put(b, 8);
  put(0, Math.min(4, DATA_CW * 8 - bits.length));
  while (bits.length % 8) bits.push(0);
  const data: number[] = [];
  for (let i = 0; i < bits.length; i += 8) data.push(parseInt(bits.slice(i, i + 8).join(""), 2));
  for (let pad = 0xec; data.length < DATA_CW; pad ^= 0xec ^ 0x11) data.push(pad);
  // Reed-Solomon sur GF(256), polynôme 0x11D.
  const mul = (x: number, y: number) => {
    let z = 0;
    for (let i = 7; i >= 0; i--) {
      z = (z << 1) ^ ((z >>> 7) * 0x11d);
      z ^= ((y >>> i) & 1) * x;
    }
    return z & 0xff;
  };
  const divisor = new Array(EC_CW).fill(0);
  divisor[EC_CW - 1] = 1;
  let root = 1;
  for (let i = 0; i < EC_CW; i++) {
    for (let j = 0; j < EC_CW; j++) {
      divisor[j] = mul(divisor[j], root);
      if (j + 1 < EC_CW) divisor[j] ^= divisor[j + 1];
    }
    root = mul(root, 2);
  }
  const ec = new Array(EC_CW).fill(0);
  for (const b of data) {
    const factor = b ^ (ec.shift() as number);
    ec.push(0);
    divisor.forEach((c, i) => { ec[i] ^= mul(c, factor); });
  }
  const codewords = [...data, ...ec];
  // Matrice : motifs fixes, puis données en zigzag, masque 0, informations de format.
  const dark = Array.from({ length: size }, () => new Array(size).fill(false));
  const fixed = Array.from({ length: size }, () => new Array(size).fill(false));
  const set = (x: number, y: number, on: boolean) => { dark[y][x] = on; fixed[y][x] = true; };
  for (let i = 0; i < size; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
  for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]]) {
    for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
      const x = cx + dx; const y = cy + dy;
      const d = Math.max(Math.abs(dx), Math.abs(dy));
      if (x >= 0 && x < size && y >= 0 && y < size) set(x, y, d !== 2 && d !== 4);
    }
  }
  for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) set(22 + dx, 22 + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
  const format = (() => {
    const v = (1 << 3) | 0; // correction L (1), masque 0
    let rem = v;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    return ((v << 10) | rem) ^ 0x5412;
  })();
  const bit = (i: number) => ((format >>> i) & 1) === 1;
  for (let i = 0; i <= 5; i++) set(8, i, bit(i));
  set(8, 7, bit(6));
  set(8, 8, bit(7));
  set(7, 8, bit(8));
  for (let i = 9; i < 15; i++) set(14 - i, 8, bit(i));
  for (let i = 0; i < 8; i++) set(size - 1 - i, 8, bit(i));
  for (let i = 8; i < 15; i++) set(8, size - 15 + i, bit(i));
  set(8, size - 8, true);
  let n = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? size - 1 - vert : vert;
        if (fixed[y][x] || n >= codewords.length * 8) continue;
        dark[y][x] = ((codewords[n >>> 3] >>> (7 - (n & 7))) & 1) === 1;
        n++;
      }
    }
  }
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (!fixed[y][x] && (x + y) % 2 === 0) dark[y][x] = !dark[y][x];
  // Image : 8 px par module, marge de 4 modules.
  const scale = 8;
  const quiet = 4;
  const canvas = document.createElement("canvas");
  canvas.width = canvas.height = (size + 2 * quiet) * scale;
  const ctx = canvas.getContext("2d")!;
  ctx.fillStyle = "#fff";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "#000";
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (dark[y][x]) ctx.fillRect((x + quiet) * scale, (y + quiet) * scale, scale, scale);
  const blob: Blob = await new Promise((r) => canvas.toBlob((b) => r(b!), "image/png"));
  const transfer = new DataTransfer();
  transfer.items.add(new File([blob], "qr.png", { type: "image/png" }));
  const zone = document.querySelector(".c-qr-drop")!;
  zone.dispatchEvent(drop
    ? new DragEvent("drop", { dataTransfer: transfer, bubbles: true, cancelable: true })
    : new ClipboardEvent("paste", { clipboardData: transfer, bubbles: true, cancelable: true }));
}
