// Fil de travail du semis et de la vérification. Il exécute le VRAI code
// client (web/js/vault.js et locksy.wasm) : inscription, chiffrement des
// éléments, coffres partagés, pièces jointes, puis reconnexion et
// déchiffrement complet. Un fil traite un compte à la fois (l'état de
// vault.js est global au module) et ferme sa session à la fin de chaque tâche.

import { parentPort, workerData } from "node:worker_threads";
import { randomBytes } from "node:crypto";
import { setWasmSource, setForwardedFor, takeAuthKey } from "./shim.mjs";
import { generateItems } from "./datasets.mjs";
import { itemsDigest, sha256 } from "./common.mjs";

const web = new URL("../../web/js/", import.meta.url);
const W = await import(new URL("wasm.js", web));
const A = await import(new URL("api.js", web));
const V = await import(new URL("vault.js", web));

setWasmSource(workerData.wasm);
A.setBase(workerData.base);
V.setDeviceLabel("Banc");
await W.loadCrypto("/locksy.wasm");

/** Taille d'un envoi groupé : importItems découpe ensuite en requêtes de 500. */
const IMPORT_CHUNK = 2000;
const TOTP_RETRIES = 3;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const unix = () => Math.floor(Date.now() / 1000);

/** Code TOTP courant, calculé par le noyau (même code que l'interface). */
const totpCode = (secret) => W.call("totp", { secret, time: unix() }).code;

/**
 * Connexion par le chemin de l'interface (prelogin, Argon2 côté client,
 * login). Un code refusé (anti-rejeu : déjà utilisé dans cette fenêtre) est
 * retenté à la fenêtre suivante.
 */
async function signIn({ email, password, totp_secret: secret }) {
  let r = await V.login({ email, password });
  for (let attempt = 0; r.needTotp; attempt++) {
    if (!secret) throw new Error(`${email} : code de double authentification demandé, secret inconnu.`);
    if (attempt >= TOTP_RETRIES) throw new Error(`${email} : code de double authentification refusé ${TOTP_RETRIES} fois.`);
    if (r.error) await sleep((30 - (unix() % 30) + 1) * 1000);
    r = await V.finishLogin(r.pending, totpCode(secret));
  }
}

/** Éléments d'un coffre, triés par nom (ordre stable pour les pièces jointes). */
function itemsOf(collectionId) {
  return [...V.state.items.values()]
    .filter((i) => i.collection_id === collectionId)
    .sort((a, b) => (a.data?.name || "").localeCompare(b.data?.name || "") || a.id.localeCompare(b.id));
}

async function importAll(collectionId, items) {
  for (let i = 0; i < items.length; i += IMPORT_CHUNK) {
    await V.importItems(collectionId, items.slice(i, i + IMPORT_CHUNK));
  }
}

/**
 * Ajoute des pièces jointes aléatoires (incompressibles, comme un chiffré)
 * aux éléments du coffre, un élément différent par pièce à partir de
 * `offset` (la révision de chaque élément n'est donc modifiée qu'une fois).
 * Renvoie nom, taille et SHA-256 du clair de chaque pièce.
 */
async function attach(collectionId, files, offset) {
  const targets = itemsOf(collectionId);
  if (offset + files.length > targets.length) {
    throw new Error(`${files.length} pièce(s) jointe(s) pour ${targets.length - offset} élément(s) disponibles.`);
  }
  const done = [];
  for (const [j, f] of files.entries()) {
    const bytes = randomBytes(f.size);
    const digest = sha256(bytes);
    await V.addAttachment(targets[offset + j], new File([bytes], f.name, { type: "application/octet-stream" }));
    done.push({ name: f.name, size: f.size, sha256: digest });
  }
  return done;
}

const sampleIds = (collectionId, n) => itemsOf(collectionId).slice(0, n).map((i) => i.id);

// ------------------------------------------------------------ Tâches

const tasks = {
  /** Inscription (jeton d'installation ou invitation), éléments personnels, pièces jointes, 2FA. */
  async account(t) {
    setForwardedFor(t.xff);
    const recovery = await V.register({
      email: t.email, name: t.name, password: t.password, setupToken: t.setupToken, inviteToken: t.inviteToken,
    });
    const authKey = takeAuthKey();
    await V.sync();
    const personal = [...V.state.collections.values()].find((c) => c.personal);
    if (!personal) throw new Error(`${t.email} : coffre personnel absent après l'inscription.`);
    const items = generateItems(t.personal, V.emptyItem, t.now);
    await importAll(personal.id, items);
    await V.sync();
    const files = t.attachments.map((size, j) => ({ size, name: `piece-perso-${t.index}-${j + 1}.bin` }));
    const attachments = files.length ? await attach(personal.id, files, 0) : [];
    let totpSecret = null;
    if (t.totp) {
      ({ secret: totpSecret } = await A.api("POST", "/me/2fa/setup"));
      await A.api("POST", "/me/2fa/enable", { code: totpCode(totpSecret) });
    }
    return {
      id: V.state.profile.id,
      public_key: V.state.profile.public_key,
      auth_key: authKey,
      recovery,
      totp_secret: totpSecret,
      kdf: (({ salt: _salt, ...params }) => params)(V.state.profile.kdf),
      personal_collection: personal.id,
      items: items.length,
      digest: itemsDigest(items),
      attachments,
      sample_item_ids: sampleIds(personal.id, 5),
    };
  },

  /** Coffre partagé : création, éléments, puis ajout des membres (clé scellée pour chacun). */
  async collection(t) {
    setForwardedFor(t.creator.xff);
    await signIn(t.creator);
    const id = await V.createCollection(t.name);
    await V.sync();
    const items = generateItems(t.items, V.emptyItem, t.now);
    await importAll(id, items);
    for (const m of t.members) {
      await V.addMember(id, { id: m.id, email: m.email, public_key: m.public_key }, m.role);
    }
    await V.sync();
    return { id, items: items.length, digest: itemsDigest(items), sample_item_ids: sampleIds(id, 3) };
  },

  /** Pièces jointes d'un coffre partagé, envoyées par l'un de ses membres. */
  async attachments(t) {
    setForwardedFor(t.account.xff);
    await signIn(t.account);
    await V.sync();
    return attach(t.collection_id, t.files, t.offset);
  },

  /** Reconnexion, synchronisation et déchiffrement de tout ce que voit le compte. */
  async verify(t) {
    setForwardedFor(t.account.xff);
    const errors = [];
    const fail = (msg) => errors.push(`${t.account.email} : ${msg}`);
    await signIn(t.account);
    if (V.state.profile.role !== t.role) fail(`rôle ${V.state.profile.role}, attendu ${t.role}`);
    await V.sync();
    const seen = new Set(V.state.collections.keys());
    for (const c of V.state.collections.values()) {
      if (c.error) fail(`coffre ${c.id} illisible (${c.error})`);
    }
    let items = 0;
    let attachments = 0;
    let bytes = 0;
    for (const exp of t.expected) {
      if (!seen.delete(exp.id)) {
        fail(`coffre « ${exp.name} » (${exp.id}) invisible`);
        continue;
      }
      const list = itemsOf(exp.id);
      const unreadable = list.filter((i) => i.error || !i.data);
      if (unreadable.length) fail(`${unreadable.length} élément(s) illisible(s) dans « ${exp.name} »`);
      const data = list.filter((i) => i.data).map((i) => i.data);
      items += data.length;
      if (data.length !== exp.items) fail(`« ${exp.name} » : ${data.length} éléments, ${exp.items} attendus`);
      else if (itemsDigest(data) !== exp.digest) fail(`« ${exp.name} » : contenu différent du manifeste`);
      if (!exp.attachments) continue;
      // Pièces jointes : vérifiées par un seul compte (le créateur du coffre).
      const expected = new Map(exp.attachments.map((a) => [a.name, a]));
      for (const att of data.flatMap((d) => d.attachments || [])) {
        const want = expected.get(att.name);
        expected.delete(att.name);
        if (!want) { fail(`pièce jointe inattendue « ${att.name} »`); continue; }
        const blob = await V.downloadAttachment(att);
        const buf = Buffer.from(await blob.arrayBuffer());
        attachments += 1;
        bytes += buf.length;
        if (buf.length !== want.size || sha256(buf) !== want.sha256) fail(`pièce jointe « ${att.name} » altérée`);
      }
      for (const name of expected.keys()) fail(`pièce jointe « ${name} » absente`);
    }
    for (const id of seen) fail(`coffre inattendu ${id}`);
    return { errors, items, attachments, bytes };
  },
};

parentPort.on("message", async (task) => {
  let reply;
  try {
    reply = { ok: true, result: await tasks[task.type](task) };
  } catch (e) {
    reply = { ok: false, error: { message: e.message, code: e.code || "", status: e.status || 0 } };
  }
  // Session fermée et clés effacées AVANT la réponse : la tâche suivante
  // trouve un fil vierge.
  if (V.state.profile) await V.logout();
  takeAuthKey();
  setForwardedFor(null);
  parentPort.postMessage(reply);
});
