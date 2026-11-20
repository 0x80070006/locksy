// Tests de la lecture des CSV (web/js/import.js) : séparateur unique détecté
// sur l'en-tête (correctif du bogue « a;b » coupé dans un fichier à virgules),
// guillemets RFC 4180, retours à la ligne dans un champ, BOM, rapport
// d'erreurs ligne par ligne, colonnes reconnues et envoi par lots avec reprise.
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseCsv, detectSeparator, detectMapping, csvToItems, importInBatches, importFile, normalizeFolder } from "../js/import.js";

const items = (text, opts) => {
  const p = parseCsv(text);
  return { parsed: p, ...csvToItems(p.rows, undefined, { lines: p.lines, ...opts }) };
};

test("virgule : un mot de passe « a;b » n'est jamais coupé", () => {
  const { parsed, items: out, errors } = items("name,username,password\nSite,alice,a;b\n");
  assert.equal(parsed.separator, ",");
  assert.deepEqual(errors, []);
  assert.equal(out.length, 1);
  assert.equal(out[0].data.password, "a;b");
  assert.equal(out[0].data.username, "alice");
});

test("point-virgule : un mot de passe « a,b » n'est jamais coupé", () => {
  const { parsed, items: out } = items("nom;identifiant;mot de passe\r\nBanque;bob;a,b\r\n");
  assert.equal(parsed.separator, ";");
  assert.equal(out[0].data.name, "Banque");
  assert.equal(out[0].data.password, "a,b");
});

test("tabulation : virgules et points-virgules restent dans les champs", () => {
  const { parsed, items: out } = items("title\tusername\tpassword\nNAS\tadmin\tx,y;z\n");
  assert.equal(parsed.separator, "\t");
  assert.equal(out[0].data.password, "x,y;z");
});

test("séparateur détecté hors guillemets sur l'en-tête seulement", () => {
  assert.equal(detectSeparator("\"a;b;c\",d,e\n1;2;3;4;5;6\n"), ",");
  assert.equal(detectSeparator("seul"), ",");
  assert.equal(detectSeparator("a;b,c;d"), ";");
});

test("indication « sep=; » d'Excel", () => {
  const p = parseCsv("sep=;\nname;password\nA;p,1\n");
  assert.equal(p.separator, ";");
  assert.deepEqual(p.rows, [["name", "password"], ["A", "p,1"]]);
  assert.deepEqual(p.lines, [2, 3]);
});

test("guillemets RFC 4180 : séparateur, guillemet doublé, champ vide", () => {
  const p = parseCsv("name,password,notes\n\"A, B\",\"il a dit \"\"oui\"\"\",\"\"\n");
  assert.deepEqual(p.rows[1], ["A, B", "il a dit \"oui\"", ""]);
});

test("retours à la ligne dans un champ : numéros de ligne exacts", () => {
  const text = "name,password,notes\nA,p1,\"ligne 1\nligne 2\r\nligne 3\"\nB,p2,x\n";
  const { parsed, items: out } = items(text);
  assert.equal(out.length, 2);
  // Fins de ligne du champ ramenées à « \n » (fichiers enregistrés sous Windows).
  assert.equal(out[0].data.notes, "ligne 1\nligne 2\nligne 3");
  assert.deepEqual(parsed.lines, [1, 2, 5]);
  assert.equal(out[1].line, 5);
});

test("BOM retiré : l'en-tête est reconnu", () => {
  const { items: out } = items("﻿name,password\nA,secret\n");
  assert.equal(out[0].data.name, "A");
  assert.equal(out[0].data.password, "secret");
});

test("lignes vides ignorées, fin de fichier sans saut de ligne", () => {
  const p = parseCsv("name,password\n\n,\nA,b");
  assert.deepEqual(p.rows, [["name", "password"], ["A", "b"]]);
  assert.deepEqual(p.errors, []);
});

test("guillemet jamais fermé : rapporté, la suite n'est pas importée", () => {
  const { parsed, items: out } = items("name,password\nA,ok\nB,\"cassé\nC,x\n");
  assert.deepEqual(parsed.errors, [{ line: 3, code: "unterminated_quote" }]);
  assert.equal(out.length, 1);
});

test("ligne invalide rapportée : colonnes en trop, ligne sans contenu utile", () => {
  const { items: out, errors } = items("name,username,password\nA,u,p\nB,u,p1,p2\n,,\nC,,\n");
  // « ,, » est une ligne vide (ignorée) ; « C,, » n'a qu'un nom.
  assert.deepEqual(errors, [{ line: 3, code: "extra_columns" }, { line: 5, code: "empty_entry" }]);
  assert.deepEqual(out.map((i) => i.data.name), ["A"]);
});

test("cellules vides au-delà de l'en-tête tolérées (séparateur final)", () => {
  const { items: out, errors } = items("name,password\nA,p,,\n");
  assert.deepEqual(errors, []);
  assert.equal(out[0].data.password, "p");
});

test("fichier vide ou sans données", () => {
  assert.deepEqual(csvToItems([]).errors, [{ line: 1, code: "no_header" }]);
  assert.deepEqual(csvToItems([["name", "password"]]).errors, [{ line: 1, code: "no_data" }]);
});

test("colonnes : domaine, description, champs libres, prénom et nom", () => {
  const text = "Titre,Domaine,Description,Notes,Numéro client,Prénom,Nom de famille,TOTP\n"
    + "Fournisseur,exemple.fr,Compte principal,Voir contrat,C-42,,,otpauth://totp/x?secret=ABC\n"
    + ",,,,,Camille,Durand,\n";
  const { items: out, errors } = items(text);
  assert.deepEqual(errors, []);
  const [a, b] = out.map((i) => i.data);
  assert.equal(a.kind, "login");
  assert.deepEqual(a.urls, ["https://exemple.fr"]);
  assert.equal(a.notes, "Compte principal\n\nVoir contrat");
  assert.deepEqual(a.fields, [{ label: "Numéro client", value: "C-42", hidden: false }]);
  assert.equal(a.totp, "otpauth://totp/x?secret=ABC");
  assert.equal(b.kind, "identity");
  assert.equal(b.name, "Camille Durand");
  assert.equal(b.identity.first_name, "Camille");
  assert.equal(b.identity.last_name, "Durand");
});

test("export de type Bitwarden : type, dossier, champs « nom: valeur »", () => {
  const text = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
    + "Équipe IT/Serveurs,1,login,NAS,,\"Port: 5001\nVLAN: 20\",0,https://nas.local,admin,p;w,\n"
    + ",,note,Codes alarme,1234,,,,,,\n";
  const { items: out } = items(text);
  assert.equal(out[0].data.name, "NAS");
  assert.equal(out[0].data.password, "p;w");
  assert.deepEqual(out[0].data.tags, ["Équipe IT", "Serveurs"]);
  assert.equal(out[0].folder, "Équipe IT/Serveurs");
  assert.deepEqual(out[0].data.fields, [{ label: "Port", value: "5001", hidden: false }, { label: "VLAN", value: "20", hidden: false }]);
  assert.equal(out[1].data.kind, "note");
  assert.equal(out[1].data.notes, "1234");
});

test("dossier vers coffre : gardé dans `folder`, pas d'étiquettes", () => {
  const { items: out } = items("name,password,folder\nA,p,Compta\\Banques\n", { folderMode: "vaults" });
  assert.equal(out[0].folder, "Compta/Banques");
  assert.deepEqual(out[0].data.tags, []);
});

test("correspondance : un champ connu une seule fois, e-mail en identifiant à défaut", () => {
  const m = detectMapping(["URL", "Site web", "E-mail", "Mot de passe", "guid"]);
  assert.deepEqual(m.map((c) => c.target), ["url", "field", "username", "password", "skip"]);
  const m2 = detectMapping(["username", "email"]);
  assert.deepEqual(m2.map((c) => c.target), ["username", "email"]);
  assert.equal(normalizeFolder(" A \\ B// C "), "A/B/C");
});

test("en-têtes français avec accents, tirets ou tirets bas", () => {
  const m = detectMapping(["Nom de domaine", "mot-de-passe", "Code de vérification", "NOM_DE_FAMILLE", "Prénom"]);
  assert.deepEqual(m.map((c) => c.target), ["domain", "password", "totp", "last_name", "first_name"]);
});

test("lots de 500 avec reprise au lot refusé", async () => {
  const entries = Array.from({ length: 1201 }, (_, i) => i);
  const sent = [];
  let fail = true;
  const send = async (chunk) => {
    if (chunk[0] === 500 && fail) {
      fail = false;
      throw new Error("réseau");
    }
    sent.push(chunk.length);
  };
  const progress = [];
  const first = await importInBatches(entries, { send, onProgress: (d, t) => progress.push([d, t]) });
  assert.equal(first.failedAt, 500);
  assert.equal(first.error.message, "réseau");
  const second = await importInBatches(entries, { send, start: first.failedAt });
  assert.equal(second.failedAt, null);
  assert.equal(second.done, 1201);
  // Lot 1 envoyé, lot 2 refusé puis repris, lot 3 : aucun lot envoyé deux fois.
  assert.deepEqual(sent, [500, 500, 201]);
  assert.deepEqual(progress, [[500, 1201]]);
});

test("importFile CSV : rapport trié et éléments prêts", async () => {
  const file = new Blob(["name,password\nA,a;b\nB,x,y\n"]);
  const res = await importFile(file, { format: "csv" });
  assert.equal(res.items.length, 1);
  assert.equal(res.items[0].data.password, "a;b");
  assert.deepEqual(res.errors, [{ line: 3, code: "extra_columns" }]);
  await assert.rejects(importFile(file, { format: "csv", maxBytes: 4 }), { code: "too_large" });
  await assert.rejects(importFile(file, { format: "zip" }), { code: "unsupported_format" });
});

test("plan d'import : favori retiré de l'élément, dossiers vers coffres existants, créés ou étiquettes", async () => {
  const { planImport } = await import("../js/views/settings/data.js");
  const vaults = [{ id: "perso", personal: true }, { id: "c-compta", name: "Comptabilité", role: "editor" }];
  const items = [
    { data: { name: "A", tags: [], favorite: true }, folder: "" },
    { data: { name: "B", tags: ["x"] }, folder: "comptabilite/Banques" },
    { data: { name: "C", tags: [] }, folder: "Nouveau" },
  ];
  const withCreate = planImport(items, { mode: "vaults", targetId: "perso", vaults, allowCreate: true });
  assert.equal("favorite" in withCreate.entries[0].data, false);
  assert.equal(withCreate.entries[0].favorite, true);
  assert.equal(withCreate.entries[1].favorite, false);
  // Coffre existant (sans accents ni casse), sous-dossier en étiquette.
  assert.equal(withCreate.entries[1].vault.id, "c-compta");
  assert.deepEqual(withCreate.entries[1].data.tags, ["Banques", "x"]);
  // Coffre à créer.
  assert.deepEqual(withCreate.entries[2].vault, { id: undefined, name: "Nouveau", created: true });
  // Création interdite : coffre de destination, dossier en étiquettes.
  const noCreate = planImport(items, { mode: "vaults", targetId: "perso", vaults, allowCreate: false });
  assert.equal(noCreate.entries[2].vault.id, "perso");
  assert.deepEqual(noCreate.entries[2].data.tags, ["Nouveau"]);
  // Mode étiquettes : tout dans le coffre choisi.
  const tags = planImport(items, { mode: "tags", targetId: "perso", vaults, allowCreate: true });
  assert.ok(tags.entries.every((e) => e.vault.id === "perso"));
  assert.deepEqual(tags.entries[1].data.tags, ["comptabilite", "Banques", "x"]);
});

test("préférences : la case de synchronisation n'apparaît que si l'apparence locale est prise en compte", async () => {
  const { syncChoiceSupported, syncEnabled } = await import("../js/views/settings/preferences.js");
  const ancien = { LOCAL_KEYS: ["ui.theme"], localOnly: () => { throw new RangeError("clé"); } };
  assert.equal(syncChoiceSupported(ancien), false);
  assert.equal(syncEnabled(ancien), true);
  let kept = null;
  const recent = { LOCAL_KEYS: ["ui.theme", "prefs.sync"], localOnly: (k, v) => (v === undefined ? kept : (kept = v)) };
  assert.equal(syncChoiceSupported(recent), true);
  assert.equal(syncEnabled(recent), true);
  recent.localOnly("prefs.sync", false);
  assert.equal(syncEnabled(recent), false);
});
