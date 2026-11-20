// Comportements des autres composants : socle h(), boutons, menus, onglets,
// recherche, notifications, chargement, assistant, tableau, filtres,
// réglages, politique, force, bulle.

import { test, expect } from "../../fixtures/index.ts";
import { openGallery, sortie } from "./galerie.ts";

test.describe("Socle", () => {
  test("h() refuse la clé style ; icon() décorative ou nommée ; initiales", async ({ page }) => {
    await openGallery(page, "socle");
    const r = await page.evaluate(() => {
      const { ui } = (window as any).gallery;
      let refused = false;
      try { ui.h("div", { style: "color: red" }); } catch { refused = true; }
      const deco = ui.icon("copy");
      const named = ui.icon("lock", { label: "Verrouillé" });
      return {
        refused,
        deco: [deco.getAttribute("aria-hidden"), deco.querySelector("use").getAttribute("href")],
        named: [named.getAttribute("role"), named.getAttribute("aria-label")],
        initials: [ui.initials("Hugo Martin"), ui.initials("gmail"), ui.initials("")],
        text: ui.h("p", {}, "<b>texte</b>").innerText,
      };
    });
    expect(r.refused).toBe(true);
    expect(r.deco).toEqual(["true", "/icons/sprite.svg#copy"]);
    expect(r.named).toEqual(["img", "Verrouillé"]);
    expect(r.initials).toEqual(["HM", "G", "?"]);
    expect(r.text).toBe("<b>texte</b>");
  });
});

test.describe("Boutons et menus", () => {
  test("bouton : état « en cours » pendant la promesse, raison d'un bouton désactivé", async ({ page }) => {
    await openGallery(page, "bouton");
    const send = page.getByRole("button", { name: "Envoyer l'invitation" });
    await send.click();
    await expect(page.getByRole("button", { name: "Envoi…" })).toHaveAttribute("aria-busy", "true");
    await expect(page.getByRole("button", { name: "Envoyer l'invitation" })).not.toHaveAttribute("aria-busy", "true");
    const edit = page.getByRole("button", { name: "Modifier" });
    await expect(edit).toHaveAttribute("aria-disabled", "true");
    await expect(edit).toHaveAccessibleDescription("Seuls les gestionnaires du coffre peuvent modifier.");
    const star = page.getByRole("button", { name: "Ajouter aux favoris" });
    await star.click();
    await expect(star).toHaveAttribute("aria-pressed", "true");
  });

  test("menu : flèches, lettre, action désactivée, Échap rend le focus", async ({ page }) => {
    await openGallery(page, "menu");
    const btn = page.getByRole("button", { name: "Plus d'actions", exact: true });
    await btn.focus();
    await page.keyboard.press("ArrowDown");
    await expect(btn).toHaveAttribute("aria-expanded", "true");
    await expect(page.getByRole("menuitem", { name: "Modifier" })).toBeFocused();
    await page.keyboard.press("End");
    await expect(page.getByRole("menuitem", { name: "Mettre à la corbeille" })).toBeFocused();
    await page.keyboard.press("p");
    await expect(page.getByRole("menuitem", { name: "Partager" })).toBeFocused();
    const move = page.getByRole("menuitem", { name: "Déplacer" });
    await expect(move).toHaveAttribute("aria-disabled", "true");
    await expect(move).toHaveAccessibleDescription("Vous n'avez accès à aucun autre coffre.");
    // Entrée sur une action désactivée : rien ne se passe, le menu reste ouvert.
    await page.keyboard.press("Home");
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("ArrowDown");
    await expect(move).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("menu")).toBeVisible();
    await expect(sortie(page, "menu")).toHaveText("");
    await page.keyboard.press("Escape");
    await expect(page.getByRole("menu")).toHaveCount(0);
    await expect(btn).toBeFocused();
    await btn.click();
    await page.getByRole("menuitem", { name: "Partager" }).click();
    await expect(sortie(page, "menu")).toHaveText("Action : Partager");
  });

  test("bulle : ouverture, Échap la ferme et rend le focus", async ({ page }) => {
    await openGallery(page, "bulle");
    const anchor = page.getByRole("button", { name: "Qui voit cet élément ?" });
    await anchor.click();
    await expect(anchor).toHaveAttribute("aria-expanded", "true");
    await expect(page.getByRole("button", { name: "Gérer l'accès" })).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog", { name: "Audience" })).toHaveCount(0);
    await expect(anchor).toBeFocused();
  });
});

test.describe("Navigation", () => {
  test("onglets : flèches, Début, Fin, aria-selected, panneau conservé", async ({ page }) => {
    await openGallery(page, "onglets");
    const first = page.getByRole("tab", { name: "Avec des collègues" });
    await expect(first).toHaveAttribute("aria-selected", "true");
    await page.getByRole("tabpanel").getByLabel("Avec qui ?").fill("Hugo");
    await first.focus();
    await page.keyboard.press("ArrowRight");
    const second = page.getByRole("tab", { name: "Par lien sécurisé" });
    await expect(second).toBeFocused();
    await expect(second).toHaveAttribute("aria-selected", "true");
    await expect(page.getByRole("tabpanel")).toHaveText("Le lien expire après 24 heures.");
    await page.keyboard.press("Home");
    await expect(first).toHaveAttribute("aria-selected", "true");
    await expect(page.getByLabel("Avec qui ?")).toHaveValue("Hugo");
  });

  test("navigation latérale : lien courant", async ({ page }) => {
    await openGallery(page, "navigation");
    const nav = page.getByRole("navigation", { name: "Navigation de démonstration" });
    await expect(nav.getByRole("link", { name: /Tout/ })).toHaveAttribute("aria-current", "page");
    await expect(nav.getByRole("link", { name: /Favoris/ })).not.toHaveAttribute("aria-current", "page");
  });

  test("assistant : étapes, retour, fin", async ({ page }) => {
    await openGallery(page, "assistant");
    await expect(page.getByRole("heading", { name: "Étape 1 sur 3 : Choisir la personne" })).toBeVisible();
    await page.getByRole("button", { name: "Continuer" }).click();
    await expect(page.getByRole("heading", { name: "Étape 2 sur 3 : Transférer les coffres" })).toBeFocused();
    await page.getByRole("button", { name: "Retour" }).click();
    await expect(page.getByRole("heading", { name: /Étape 1 sur 3/ })).toBeFocused();
    await page.getByRole("button", { name: "Continuer" }).click();
    await page.getByRole("button", { name: "Continuer" }).click();
    await page.getByRole("button", { name: "Terminer" }).click();
    await expect(sortie(page, "assistant")).toHaveText("Assistant terminé");
  });

  test("recherche : sans accents ni casse, Échap efface", async ({ page }) => {
    await openGallery(page, "recherche");
    const box = page.getByRole("searchbox", { name: "Rechercher dans tout le coffre" });
    await box.fill("Société Générale");
    await expect(sortie(page, "recherche")).toHaveText("Recherche : societe generale");
    await box.press("Escape");
    await expect(box).toHaveValue("");
    await expect(sortie(page, "recherche")).toHaveText("");
  });
});

test.describe("Notifications et états", () => {
  test("toast : 6 s, pause au survol, 10 s pour une erreur, F6 et Annuler", async ({ page }) => {
    await page.clock.install();
    await openGallery(page, "notification");
    await page.getByRole("button", { name: "Notification de succès" }).click();
    const ok = page.locator(".c-toast", { hasText: "Élément enregistré." });
    await expect(ok).toBeVisible();
    await expect(page.locator("#status")).toHaveText("Élément enregistré.");
    await ok.hover();
    await page.clock.runFor(8_000);
    await expect(ok).toBeVisible();
    await page.mouse.move(0, 0);
    await page.clock.runFor(6_500);
    await expect(ok).toHaveCount(0);

    await page.getByRole("button", { name: "Notification d'erreur" }).click();
    const bad = page.locator(".c-toast[data-tone=danger]");
    await expect(page.locator("#alert")).toHaveText(/Serveur injoignable/);
    await page.mouse.move(0, 0);
    await page.clock.runFor(8_000);
    await expect(bad).toBeVisible();
    await page.clock.runFor(2_500);
    await expect(bad).toHaveCount(0);

    const trigger = page.getByRole("button", { name: "Notification avec annulation" });
    await trigger.click();
    await page.keyboard.press("F6");
    await expect(page.locator(".c-toast").getByRole("button", { name: "Annuler" })).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(sortie(page, "notification")).toHaveText("Restauré");
    await expect(page.locator("#status")).toHaveText("Action annulée");
    await expect(trigger).toBeFocused();
  });

  test("withLoading : squelette seulement au-delà de 300 ms, aria-busy pendant l'attente", async ({ page }) => {
    await page.clock.install();
    await openGallery(page, "etat");
    await page.clock.pauseAt(new Date(Date.now() + 2_000));
    await page.evaluate(() => {
      const { ui } = (window as any).gallery;
      const box = document.createElement("div");
      box.id = "chargement";
      document.getElementById("galerie")!.append(box);
      let finish: (v: string) => void = () => {};
      (window as any).finir = (v: string) => finish(v);
      ui.withLoading(box, new Promise((r) => { finish = r; })).then((v: string) => { box.textContent = v; });
    });
    const box = page.locator("#chargement");
    await expect(box).toHaveAttribute("aria-busy", "true");
    await page.clock.runFor(200);
    await expect(box.locator(".c-skeleton")).toHaveCount(0);
    await page.clock.runFor(200);
    await expect(box.locator(".c-skeleton")).toHaveCount(1);
    await page.evaluate(() => (window as any).finir("Prêt"));
    await expect(box).toHaveText("Prêt");
    await expect(box).not.toHaveAttribute("aria-busy", "true");
  });

  test("état d'erreur : message d'erreur traduit et « Réessayer »", async ({ page }) => {
    await openGallery(page, "etat");
    await expect(page.getByText("Serveur injoignable. Vérifiez votre connexion puis réessayez.")).toBeVisible();
    await page.getByRole("button", { name: "Réessayer" }).click();
    await expect(sortie(page, "etat")).toHaveText("Nouvel essai");
  });
});

test.describe("Données", () => {
  test("tableau : tri annoncé, sélection et barre d'actions, pagination", async ({ page }) => {
    await openGallery(page, "tableau");
    const table = page.getByRole("table", { name: "Personnes" });
    const nameHeader = table.getByRole("columnheader", { name: /Nom/ });
    await expect(nameHeader).toHaveAttribute("aria-sort", "ascending");
    await nameHeader.getByRole("button").click();
    await expect(table.getByRole("columnheader", { name: /Nom/ })).toHaveAttribute("aria-sort", "descending");
    await expect(table.getByRole("columnheader", { name: /Nom/ }).getByRole("button")).toBeFocused();
    await table.getByRole("checkbox", { name: "Sélectionner Banane" }).check();
    await table.getByRole("checkbox", { name: "Sélectionner Cassis" }).check();
    const bar = page.getByRole("region", { name: "Actions sur la sélection" });
    await expect(bar).toContainText("2 lignes sélectionnées");
    await bar.getByRole("button", { name: "Désactiver" }).click();
    await expect(sortie(page, "tableau")).toHaveText("2 à désactiver");
    await table.getByRole("button", { name: "Abricot" }).click();
    await expect(sortie(page, "tableau")).toHaveText("Fiche : Abricot");
    const pager = page.getByRole("navigation", { name: "Pagination" });
    await expect(pager).toContainText("Page 1 sur 3");
    await pager.getByRole("button", { name: "Page suivante" }).click();
    await expect(pager).toContainText("Page 2 sur 3");
  });

  test("filtres : choix dans le menu, compteur et « Effacer les filtres »", async ({ page }) => {
    await openGallery(page, "filtres");
    await page.getByRole("button", { name: "Type", exact: true }).click();
    await expect(page.getByRole("menuitemradio", { name: "Tous" })).toHaveAttribute("aria-checked", "true");
    await page.getByRole("menuitemradio", { name: "Mots de passe" }).click();
    await expect(page.getByRole("button", { name: "Type : Mots de passe" })).toBeFocused();
    await expect(page.getByText("1 filtre actif")).toBeVisible();
    await expect(sortie(page, "filtres")).toHaveText("Filtres : login");
    await page.getByRole("button", { name: "Effacer les filtres" }).click();
    await expect(page.getByRole("button", { name: "Type", exact: true })).toBeVisible();
    await expect(page.getByText("1 filtre actif")).toHaveCount(0);
  });
});

test.describe("Réglages", () => {
  test("settingField : badges, mode, aperçu, Rétablir, lecture seule", async ({ page }) => {
    await openGallery(page, "reglage");
    const autolock = page.locator(".c-setting[data-key='client.autolock_minutes']");
    await expect(autolock.locator(".c-badge", { hasText: "Modifié" })).toBeVisible();
    await expect(autolock).toContainText("Limité à 30 minutes par votre organisation");
    await autolock.getByRole("radio", { name: "Imposé" }).check({ force: true });
    await expect(sortie(page, "reglage")).toHaveText('Changement : {"value":15,"mode":"enforced","min":null,"max":30}');
    await expect(autolock.locator(".c-badge", { hasText: "Imposé" })).toBeVisible();
    await autolock.getByRole("button", { name: /^Rétablir \(défaut : 10 minutes\)$/ }).click();
    await expect(sortie(page, "reglage")).toHaveText("Changement : null");
    await expect(autolock.locator(".c-badge", { hasText: "Modifié" })).toHaveCount(0);

    const twofa = page.locator(".c-setting[data-key='twofa.required']");
    await twofa.getByRole("switch").click();
    await expect(sortie(page, "reglage")).toHaveText("Changement : false");

    const syslog = page.locator(".c-setting[data-key='audit.syslog.url']");
    await expect(syslog.locator(".c-badge", { hasText: "Fixé par l'hébergeur" })).toHaveAttribute("title", "LOCKSY_SYSLOG");
    await expect(syslog.getByRole("textbox")).toHaveCount(0);
    await expect(syslog).toContainText("seul l'hébergeur peut le modifier");

    const ip = page.locator(".c-setting[data-key='access.ip_allowlist']");
    await expect(ip.locator(":scope > .c-field__error")).toHaveText("Votre adresse 10.0.0.4 n'est pas dans la liste.");

    const color = page.locator(".c-setting[data-key='branding.accent_color']");
    const hex = color.locator("input:not([type=color])");
    await hex.fill("#9fe0d0");
    await hex.press("Tab");
    await expect(color).toContainText("Contraste insuffisant");
    await color.getByRole("button", { name: "Utiliser la nuance conforme" }).click();
    await expect(color).toContainText("Lisible");
    // La clé technique n'apparaît que dans « Détails techniques ».
    await expect(autolock.locator("[data-technical]")).toContainText("client.autolock_minutes");
  });

  test("diffList et policyHint : baisse de sécurité écrite, mentions", async ({ page }) => {
    await openGallery(page, "differences");
    const lowered = page.locator(".c-diff__row[data-lowered]");
    await expect(lowered).toContainText("1 heure");
    await expect(lowered).toContainText("4 heures");
    await expect(lowered).toContainText("Sécurité abaissée");
    await openGallery(page, "politique");
    await expect(page.getByText("Limité à 30 minutes par votre organisation")).toBeVisible();
    await expect(page.getByText("Imposé par votre organisation")).toBeVisible();
    await expect(page.getByText("Imposé par votre poste de travail")).toBeVisible();
  });

  test("barre d'enregistrement : nombre de modifications", async ({ page }) => {
    await openGallery(page, "barre");
    const bar = page.getByRole("region", { name: "Modifications non enregistrées" });
    await expect(bar).toContainText("2 modifications non enregistrées");
    await bar.getByRole("button", { name: "Vérifier et enregistrer" }).click();
    await expect(sortie(page, "barre")).toHaveText("Enregistrement demandé");
  });
});

test.describe("Mots de passe", () => {
  test("Afficher (aria-pressed), Majuscules activées, Générer, jauge plafonnée", async ({ page }) => {
    await openGallery(page, "mot-de-passe");
    const field = page.getByLabel("Mot de passe", { exact: true });
    const show = page.getByRole("button", { name: "Afficher le mot de passe" }).first();
    await expect(field).toHaveAttribute("type", "password");
    await show.click();
    await expect(show).toHaveAttribute("aria-pressed", "true");
    await expect(field).toHaveAttribute("type", "text");
    await page.getByRole("button", { name: "Générer" }).click();
    await expect(field).toHaveValue("Tq7!vLp2#Rz9@Wm4");
    await expect(page.locator(".c-strength").first()).toHaveAttribute("data-level", "4");
    await expect(page.locator(".c-strength").first()).toContainText("Très solide");
    await field.fill("azertyazertyazerty");
    await expect(page.locator(".c-strength").first()).toHaveAttribute("data-level", "3");
    // Verr. Maj : l'état vient de getModifierState("CapsLock") de l'événement clavier.
    const caps = (on: boolean) => field.evaluate((el, value) => {
      el.dispatchEvent(new KeyboardEvent("keydown", { key: "A", bubbles: true, modifierCapsLock: value } as KeyboardEventInit));
    }, on);
    const hint = page.locator(".c-field", { has: field }).getByText("Majuscules activées");
    await caps(true);
    await expect(hint).toBeVisible();
    await expect(field).toHaveAccessibleDescription(/Majuscules activées/);
    await caps(false);
    await expect(hint).toBeHidden();
  });
});
