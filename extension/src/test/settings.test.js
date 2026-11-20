// Réglages de l'extension : politique du poste, adresse du serveur, règles de
// remplissage (la plus stricte gagne), échéances.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  MANAGED_KEYS, LEGACY_KEYS, ALARM_MIN_SECONDS, normalizeServer, normalizeDomain, readManaged, siteExcluded,
  extensionRules, lockDeadline, shortenedDeadline, clipboardPlan,
} from "../settings.js";

const here = dirname(fileURLToPath(import.meta.url));

/** Valeurs effectives simulées (forme de settings-client.effective). */
const eff = (values) => (key) => (key in values ? { value: values[key] } : { value: undefined });

test("adresse de serveur acceptée", () => {
  assert.equal(normalizeServer("https://coffre.example.com/chemin"), "https://coffre.example.com");
  assert.equal(normalizeServer(" http://localhost:8743 "), "http://localhost:8743");
  assert.equal(normalizeServer("http://127.0.0.1:8743"), "http://127.0.0.1:8743");
  assert.equal(normalizeServer("http://coffre.example.com"), null);
  assert.equal(normalizeServer("http://locksy:8743", { allowHttp: true }), "http://locksy:8743", "variante des tests seulement");
  assert.equal(normalizeServer("https://user:pw@coffre.example.com"), null);
  assert.equal(normalizeServer("ftp://coffre.example.com"), null);
  assert.equal(normalizeServer("coffre"), null);
  assert.equal(normalizeServer(42), null);
});

test("le schéma de politique porte les noms du serveur et les anciens noms", () => {
  const schema = JSON.parse(readFileSync(join(here, "..", "managed-schema.json"), "utf8"));
  const names = Object.keys(schema.properties).sort();
  assert.deepEqual(names, [...Object.keys(MANAGED_KEYS), ...Object.keys(LEGACY_KEYS)].sort());
  for (const key of Object.keys(MANAGED_KEYS)) assert.match(key, /^(server_url|client\.[a-z_]+|extension\.[a-z_]+)$/);
  const manifest = JSON.parse(readFileSync(join(here, "..", "manifest.json"), "utf8"));
  assert.equal(manifest.storage.managed_schema, "managed-schema.json");
});

test("politique du poste : valeurs valides seulement, bornées", () => {
  const p = readManaged({
    server_url: "https://coffre.entreprise.fr/",
    "client.autolock_minutes": 5000,
    "client.clipboard_clear_seconds": 1,
    "client.lock_on_os_lock": "oui",
    "extension.http_fill": "block",
    "extension.allow_mismatch_fill": false,
    "extension.excluded_sites": ["Banque.FR", "*.paie.example.com", "https://intranet.example.com/x", "", 42],
    inconnu: true,
  });
  assert.equal(p.server, "https://coffre.entreprise.fr");
  assert.deepEqual(p.machine, {
    "client.autolock_minutes": 1440,
    "client.clipboard_clear_seconds": 5,
    "extension.http_fill": "block",
    "extension.allow_mismatch_fill": false,
    "extension.excluded_sites": ["banque.fr", "paie.example.com", "intranet.example.com"],
  });
  assert.deepEqual(readManaged(undefined), { server: null, machine: {} });
  assert.equal(readManaged({ server_url: "http://coffre.entreprise.fr" }).server, null, "http public refusé");
  assert.equal(readManaged({ "extension.http_fill": "jamais" }).machine["extension.http_fill"], undefined);
});

test("politique du poste : anciens noms 1.0 toujours lus, le plus strict gagne", () => {
  assert.deepEqual(readManaged({ max_auto_lock_minutes: 10, clipboard_seconds: 60 }).machine,
    { "client.autolock_minutes": 10, "client.clipboard_clear_seconds": 60 });
  assert.equal(readManaged({ clipboard_seconds: 5 }).machine["client.clipboard_clear_seconds"], ALARM_MIN_SECONDS, "ancien plancher de 30 s");
  assert.equal(readManaged({ max_auto_lock_minutes: 10, "client.autolock_minutes": 30 }).machine["client.autolock_minutes"], 10);
  assert.equal(readManaged({ max_auto_lock_minutes: 30, "client.autolock_minutes": 10 }).machine["client.autolock_minutes"], 10);
});

test("domaines exclus : le domaine et ses sous-domaines, jamais un voisin", () => {
  assert.equal(normalizeDomain(" *.Exemple.FR. "), "exemple.fr");
  assert.equal(normalizeDomain("https://exemple.fr:8443/a"), "exemple.fr");
  assert.equal(normalizeDomain("pas un domaine"), null);
  const list = ["banque.fr"];
  assert.equal(siteExcluded("banque.fr", list), true);
  assert.equal(siteExcluded("compte.banque.fr", list), true);
  assert.equal(siteExcluded("BANQUE.fr.", list), true);
  assert.equal(siteExcluded("mabanque.fr", list), false);
  assert.equal(siteExcluded("banque.fr.evil.com", list), false);
  assert.equal(siteExcluded("", list), false);
});

test("règles effectives : valeurs du registre sans politique", () => {
  const r = extensionRules(eff({}), {});
  assert.deepEqual(r, {
    httpFill: "block", allowMismatchFill: false, excludedSites: [], offerSave: true, autofill: false, copyTotpAfterFill: true,
    autolockMinutes: 10, clipboardSeconds: 30, lockOnOsLock: true,
  });
});

test("règles effectives : bloquer et interdire gagnent, listes réunies", () => {
  const org = eff({
    "extension.http_fill": "warn", "extension.allow_mismatch_fill": true, "extension.excluded_sites": ["paie.example.com"],
    "extension.offer_save": false, "extension.copy_totp_after_fill": false, "client.autolock_minutes": 0,
    "client.clipboard_clear_seconds": 20, "client.lock_on_os_lock": false,
  });
  const libre = extensionRules(org, {});
  assert.equal(libre.httpFill, "warn");
  assert.equal(libre.allowMismatchFill, true);
  assert.equal(libre.offerSave, false);
  assert.equal(libre.copyTotpAfterFill, false);
  assert.equal(libre.autolockMinutes, 0, "« jamais » quand la politique le permet");
  assert.equal(libre.clipboardSeconds, 20);
  assert.equal(libre.lockOnOsLock, false);
  const poste = extensionRules(org, {
    "extension.http_fill": "block", "extension.allow_mismatch_fill": false, "extension.excluded_sites": ["banque.fr"],
    "client.lock_on_os_lock": true,
  });
  assert.equal(poste.httpFill, "block");
  assert.equal(poste.allowMismatchFill, false);
  assert.deepEqual(poste.excludedSites, ["banque.fr", "paie.example.com"]);
  assert.equal(poste.lockOnOsLock, true);
  // Le poste ne peut pas assouplir l'organisation.
  assert.equal(extensionRules(eff({ "extension.http_fill": "block" }), { "extension.http_fill": "warn" }).httpFill, "block");
  // Une lecture qui échoue retombe sur le registre.
  assert.equal(extensionRules(() => { throw new Error("x"); }, {}).httpFill, "block");
});

test("échéances de verrouillage : jamais prolongées par le poste", () => {
  assert.equal(lockDeadline(10, 1_000), 1_000 + 600_000);
  assert.equal(lockDeadline(0, 1_000), null);
  const now = 1_000_000;
  assert.equal(shortenedDeadline(now + 3_600_000, { "client.autolock_minutes": 5 }, now), now + 300_000);
  assert.equal(shortenedDeadline(now + 60_000, { "client.autolock_minutes": 5 }, now), null, "déjà plus court");
  assert.equal(shortenedDeadline(null, { "client.autolock_minutes": 5 }, now), now + 300_000, "« jamais » plafonné");
  assert.equal(shortenedDeadline(now + 3_600_000, {}, now), null);
});

test("effacement du presse-papiers : minuterie sous le minimum de chrome.alarms", () => {
  assert.deepEqual(clipboardPlan(5, 0), { timerMs: 5000, alarmAt: 5000 });
  assert.deepEqual(clipboardPlan(30, 0), { timerMs: null, alarmAt: 30_000 });
  assert.deepEqual(clipboardPlan(120, 10), { timerMs: null, alarmAt: 120_010 });
  assert.equal(clipboardPlan(0), null);
  assert.equal(clipboardPlan("30"), null);
});
