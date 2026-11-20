// Simulation des API du navigateur pour tester le popup comme une simple page
// (node extension/build.mjs --dev, puis ouvrir popup.html?page=<url>).
// N'est JAMAIS copié dans un build de production : build.mjs l'exclut et
// lib/build-flags.js y vaut DEV = false.

const memory = { local: {}, session: {} };
const area = (m) => ({
  get: async (k) => (k === null || k === undefined ? { ...m } : { [k]: m[k] }),
  set: async (o) => { Object.assign(m, o); },
  remove: async (k) => { delete m[k]; },
});
const noop = async () => {};
const listeners = { addListener: () => {}, removeListener: () => {} };
const pageUrl = () => new URLSearchParams(location.search).get("page") || location.href;

export const fake = {
  storage: {
    local: area(memory.local),
    session: area(memory.session),
    managed: { get: async () => ({}) },
    onChanged: listeners,
  },
  permissions: { request: async () => true, contains: async () => true },
  tabs: {
    query: async () => [{ id: 0, url: pageUrl() }],
    get: async () => ({ id: 0, url: pageUrl() }),
    create: async ({ url }) => { open(url); },
  },
  alarms: { create: noop, clear: noop },
  runtime: { id: "dev", onMessage: listeners, sendMessage: noop, getManifest: () => ({ version: "dev" }) },
  scripting: null,
  identity: null,
};
