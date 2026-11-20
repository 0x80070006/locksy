// itemList (règle A5) : navigation au clavier, rendu par différence qui
// conserve focus, sélection et défilement, mise à jour de 10 000 éléments en
// moins de 50 ms, aucun écouteur par ligne.

import { test, expect } from "../../fixtures/index.ts";
import { openGallery, sortie } from "./galerie.ts";

const focusedTitle = (page: import("@playwright/test").Page) =>
  page.evaluate(() => document.activeElement?.closest("li")?.querySelector(".c-item-list__title")?.textContent ?? "");

test.describe("itemList()", () => {
  test.beforeEach(async ({ page }) => {
    await openGallery(page, "liste");
  });

  test("tabindex itinérant, flèches, Début, Fin et saut par lettre", async ({ page }) => {
    const list = page.getByRole("list", { name: "Éléments" });
    // Une seule ligne dans l'ordre de tabulation : la sélection (Banane).
    expect(await list.locator("a[tabindex='0']").count()).toBe(1);
    const banane = list.getByRole("link", { name: /Banane/ });
    await expect(banane).toHaveAttribute("aria-current", "true");
    await banane.focus();
    await page.keyboard.press("ArrowDown");
    expect(await focusedTitle(page)).toBe("Cassis");
    await page.keyboard.press("ArrowUp");
    expect(await focusedTitle(page)).toBe("Banane");
    await page.keyboard.press("End");
    expect(await focusedTitle(page)).toBe("Zeste");
    await page.keyboard.press("Home");
    expect(await focusedTitle(page)).toBe("Abricot");
    await page.keyboard.press("m");
    expect(await focusedTitle(page)).toBe("Mandarine");
    await page.keyboard.press("e");
    expect(await focusedTitle(page)).toBe("Melon");
    expect(await list.locator("a[tabindex='0']").count()).toBe(1);
    // Les boutons de la ligne active suivent le même tabindex.
    await page.keyboard.press("Tab");
    await expect(list.getByRole("button", { name: "Copier le mot de passe de Melon" })).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(sortie(page, "liste")).toHaveText("Copie demandée : Melon");
  });

  test("ouverture, menu de ligne construit à la demande", async ({ page }) => {
    const list = page.getByRole("list", { name: "Éléments" });
    await list.getByRole("link", { name: /Figue/ }).click();
    await expect(sortie(page, "liste")).toHaveText("Ouvert : Figue");
    await expect(list.getByRole("link", { name: /Figue/ })).toHaveAttribute("aria-current", "true");
    await expect(list.getByRole("link", { name: /Banane/ })).not.toHaveAttribute("aria-current", "true");
    await list.getByRole("button", { name: "Plus d'actions pour Figue" }).click();
    await page.getByRole("menuitem", { name: "Modifier" }).click();
    await expect(sortie(page, "liste")).toHaveText("Modifier : Figue");
    await expect(list.getByRole("button", { name: "Plus d'actions pour Figue" })).toBeFocused();
  });

  test("aucun écouteur d'événement sur une ligne (délégation)", async ({ page, browserName }) => {
    test.skip(browserName !== "chromium", "Inspection des écouteurs par le protocole CDP : Chromium seulement.");
    const cdp = await page.context().newCDPSession(page);
    const evalNode = async (expression: string) => (await cdp.send("Runtime.evaluate", { expression })).result.objectId!;
    const li = await evalNode("document.querySelector('[data-liste=demo] li[data-key]')");
    const { listeners } = await cdp.send("DOMDebugger.getEventListeners", { objectId: li, depth: -1, pierce: true });
    expect(listeners).toEqual([]);
    const ul = await evalNode("document.querySelector('[data-liste=demo] ul')");
    const own = await cdp.send("DOMDebugger.getEventListeners", { objectId: ul, depth: 0 });
    expect(own.listeners.map((l) => l.type).sort()).toEqual(["click", "focusin", "keydown"]);
  });

  test("update() de 1 000 éléments conserve focus, sélection et défilement", async ({ page }) => {
    await page.evaluate(() => {
      const { ui, makeItems, renderItem } = (window as any).gallery;
      const box = document.createElement("div");
      box.className = "g-scroll";
      box.dataset.liste = "mille";
      document.getElementById("galerie")!.append(box);
      const items = makeItems(1000);
      const list = ui.itemList({ label: "Mille éléments", items, render: renderItem, selectedKey: "el-104" });
      box.append(list.el);
      (window as any).mille = { list, items, box };
    });
    // Fenêtre virtuelle : on fait défiler jusqu'à la ligne 100, puis focus sur el-105.
    await page.evaluate(() => new Promise<void>((r) => requestAnimationFrame(() => r())));
    await page.evaluate(() => {
      const { box } = (window as any).mille;
      box.scrollTop = 100 * 56;
    });
    await page.evaluate(() => new Promise<void>((r) => requestAnimationFrame(() => requestAnimationFrame(() => r()))));
    await page.evaluate(() => (window as any).mille.list.focusKey("el-105"));
    const before = await page.evaluate(() => ({
      top: (window as any).mille.box.scrollTop,
      key: document.activeElement?.closest("li")?.dataset.key,
    }));
    expect(before.key).toBe("el-105");

    const after = await page.evaluate(() => {
      const { list, items, box } = (window as any).mille;
      const { makeItems } = (window as any).gallery;
      const next = items
        .filter((it: any) => it.id !== "el-3")
        .map((it: any, i: number) => (i % 10 === 0 ? { ...it, name: `${it.name} (modifié)` } : it))
        .concat(makeItems(1050).slice(1000));
      list.update(next);
      const ul = box.querySelector("ul");
      const focused = document.activeElement?.closest("li");
      return {
        top: box.scrollTop,
        key: focused?.dataset.key,
        selected: ul.querySelector("[aria-current='true']")?.closest("li")?.dataset.key,
        setsize: focused?.getAttribute("aria-setsize"),
        tabbable: ul.querySelectorAll("a[tabindex='0']").length,
      };
    });
    expect(after.key).toBe("el-105");
    expect(after.selected).toBe("el-104");
    expect(Math.abs(after.top - before.top)).toBeLessThanOrEqual(1);
    expect(after.setsize).toBe("1049");
    expect(after.tabbable).toBe(1);
    await page.keyboard.press("ArrowDown");
    expect(await page.evaluate(() => document.activeElement?.closest("li")?.dataset.key)).toBe("el-106");
  });

  test("update() de 10 000 éléments en moins de 50 ms", async ({ page }) => {
    // Montage, puis une image affichée : la première mise en page de la page n'est pas comptée.
    await page.evaluate(() => new Promise<void>((resolve) => {
      const { ui, makeItems, renderItem } = (window as any).gallery;
      const box = document.createElement("div");
      box.className = "g-scroll";
      document.getElementById("galerie")!.append(box);
      const items = makeItems(10000);
      const list = ui.itemList({ label: "Dix mille éléments", items, render: renderItem });
      box.append(list.el);
      (window as any).dixMille = { list, items };
      requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
    }));
    // Une mesure par passe, chacune dans sa propre tâche : le ramasse-miettes et
    // l'autre lanceur Playwright (exécution parallèle) ne pèsent que sur quelques passes.
    const out: number[] = [];
    for (let run = 0; run < 9; run++) {
      out.push(await page.evaluate((r) => {
        const w = (window as any).dixMille;
        // Données neuves à chaque passe : un élément sur 7 renommé, un ajouté, un retiré.
        w.items = w.items.slice(1).map((it: any, i: number) => (i % 7 === r % 7 ? { ...it, name: `${it.name}.` } : it))
          .concat({ id: `nouveau-${r}`, name: `Nouveau ${r}`, user: "nouveau@exemple.fr", kind: "login" });
        const t0 = performance.now();
        w.list.update(w.items);
        return performance.now() - t0;
      }, run));
    }
    expect(await page.evaluate(() => (window as any).dixMille.list.el.querySelector("li[data-key]")?.getAttribute("aria-setsize"))).toBe("10000");
    const sorted = [...out].sort((a, b) => a - b);
    const median = sorted[Math.floor(sorted.length / 2)];
    const description = `update(10 000) : médiane ${median.toFixed(2)} ms, min ${sorted[0].toFixed(2)} ms, max ${sorted[sorted.length - 1].toFixed(2)} ms (${out.map((x) => x.toFixed(1)).join(", ")})`;
    test.info().annotations.push({ type: "mesure", description });
    console.log(description);
    expect(median).toBeLessThan(50);
  });
});
