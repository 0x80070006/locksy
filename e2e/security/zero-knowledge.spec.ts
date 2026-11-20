// Zero-knowledge (G12), partie navigateur : un compte dédié crée, par
// l'interface et le vrai client de la page, des contenus aux valeurs
// DISTINCTIVES (préfixe ZK-<aléa>) : élément, note, coffre partagé et son
// élément, pièce jointe, lien de partage, préférences. La liste de ces
// clairs, le jeton de session et le mot de passe maître sont écrits dans
// e2e/.state/<cle>/zk-clairs.json. Après Playwright, zk-analyse.mjs (lancé
// par run.sh) copie la base du serveur et y cherche chaque clair : attendu 0.
// Ici, on vérifie déjà que l'API ne renvoie que des chiffrés.

import { test, expect } from "../fixtures/index.ts";
import { randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { statePath } from "../fixtures/env.ts";
import { addPasswordItem, expectInList } from "../fixtures/ui.ts";
import { avec, nouveauCompte } from "./outils.ts";

test("contenus distinctifs créés par l'interface, puis relevé des clairs pour l'analyse de la base", async ({ browser, apiAs, request }) => {
  test.setTimeout(240_000);
  const zk = `ZK-${randomBytes(6).toString("hex")}`;
  const v = (quoi: string) => `${zk}-${quoi}`;
  const compte = await nouveauCompte(browser, await apiAs("admin"), "zk");
  const page = compte.page;
  try {
    // Élément par l'éditeur de l'interface.
    const element = { name: v("nom-element"), username: v("identifiant"), password: v("mot-de-passe") };
    await addPasswordItem(page, element);
    await expectInList(page, element.name);

    // Le reste par le vrai client de la page (mêmes modules que l'interface).
    const produits = await page.evaluate(async (v) => {
      const V = await import("/js/vault.js");
      const S = await import("/js/settings-client.js");
      await V.sync();
      const perso = [...V.state.collections.values()].find((c) => c.personal);
      if (!perso) throw new Error("coffre personnel introuvable");
      const note = { ...V.emptyItem("note"), name: v.note, notes: v.texte };
      await V.createItem(perso.id, note);
      const coffre = await V.createCollection(v.coffre);
      await V.sync();
      await V.createItem(coffre, { ...V.emptyItem("login"), name: v.partage, password: v.mdpPartage, urls: [v.url] });
      await V.sync();
      const cible = [...V.state.items.values()].find((i) => i.data?.name === v.element);
      if (!cible) throw new Error("élément de l'éditeur introuvable");
      await V.addAttachment(cible, new File([v.contenu], v.fichier, { type: "text/plain" }));
      await V.sync();
      const lien = await V.createShareLink({ name: v.element, password: v.mdpLien }, 60, 2, { itemId: cible.id });
      await S.savePrefs({ links: { [lien.id]: v.etiquette }, favorites: [cible.id] });
      return { fragment: lien.url.split("#")[1], lien: lien.id };
    }, {
      element: element.name,
      note: v("titre-note"),
      texte: v("texte-de-la-note"),
      coffre: v("nom-coffre"),
      partage: v("element-du-coffre"),
      mdpPartage: v("secret-du-coffre"),
      url: `https://${zk.toLowerCase()}.exemple.fr/connexion`,
      contenu: v("contenu-piece-jointe"),
      fichier: `${v("fichier")}.txt`,
      mdpLien: v("secret-du-lien"),
      etiquette: v("etiquette-de-lien"),
    });

    // L'API ne rend que des chiffrés : préférences et coffre.
    const prefs = await request.get("/api/me/prefs", { headers: avec(compte.token) });
    expect(prefs.status()).toBe(200);
    const texte = await prefs.text();
    expect(texte).not.toContain(zk);
    expect(texte).toMatch(/"v1\.[A-Za-z0-9_-]{40,}"/);
    const sync = await (await request.get("/api/sync", { headers: avec(compte.token) })).text();
    expect(sync).not.toContain(zk);

    const clairs = [
      ...Object.values(element),
      v("titre-note"),
      v("texte-de-la-note"),
      v("nom-coffre"),
      v("element-du-coffre"),
      v("secret-du-coffre"),
      `${zk.toLowerCase()}.exemple.fr`,
      v("contenu-piece-jointe"),
      v("fichier"),
      v("secret-du-lien"),
      v("etiquette-de-lien"),
      // Le préfixe seul : aucun fragment de contenu, quel qu'il soit.
      zk,
    ];
    const secrets = { "jeton de session": compte.token, "mot de passe maître": compte.password, "clé du lien (fragment)": produits.fragment };
    writeFileSync(
      statePath("zk-clairs.json"),
      JSON.stringify({ cree_le: new Date().toISOString(), compte: compte.email, temoin: compte.email, clairs, secrets }, null, 2),
    );
    test.info().annotations.push({ type: "zk", description: `${clairs.length} clairs et ${Object.keys(secrets).length} secrets relevés pour zk-analyse.mjs` });
  } finally {
    await compte.context.close();
  }
});
