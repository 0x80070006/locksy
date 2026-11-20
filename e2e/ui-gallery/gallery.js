// Galerie des composants partagés (web/js/ui/), servie sous /gallery/ par
// e2e/tools/static.mjs avec la CSP de Locksy. Chaque composant est montré
// dans ses états (normal, focus, erreur, désactivé, chargement) ; les thèmes
// passent par l'adresse :
//   ?theme=light|dark  &contrast=more  &scale=100|112.5|125  &density=compact
//   &only=<composant>  (une seule section, pour les tests)
// window.gallery expose les composants et quelques aides aux tests Playwright.

import * as ui from "/js/ui/index.js";

const { h, t } = ui;
const params = new URLSearchParams(location.search);
const root = document.documentElement;

// ---------------------------------------------------------------- Apparence

const theme = params.get("theme");
if (theme === "light" || theme === "dark") root.dataset.theme = theme;
if (params.get("contrast") === "more") root.dataset.contrast = "more";
const scale = params.get("scale");
root.dataset.textScale = ["100", "112.5", "125"].includes(scale) ? scale : "100";
root.dataset.density = params.get("density") === "compact" ? "compact" : "comfortable";

// ---------------------------------------------------------------- Aides

const FRUITS = ["Abricot", "Ananas", "Banane", "Cassis", "Cerise", "Citron", "Datte", "Figue", "Fraise", "Framboise",
  "Goyave", "Grenade", "Groseille", "Kaki", "Kiwi", "Litchi", "Mandarine", "Mangue", "Melon", "Mirabelle",
  "Mûre", "Myrtille", "Nectarine", "Noix", "Olive", "Orange", "Pamplemousse", "Papaye", "Pastèque", "Pêche",
  "Poire", "Pomme", "Prune", "Quetsche", "Raisin", "Rhubarbe", "Tamarin", "Tomate", "Yuzu", "Zeste"];

/** n éléments de démonstration : { id, name, user, kind }. */
function makeItems(n, prefix = "") {
  return Array.from({ length: n }, (_, i) => ({
    id: `el-${i}`,
    name: n <= FRUITS.length ? `${prefix}${FRUITS[i]}` : `${prefix}${FRUITS[i % FRUITS.length]} ${String(i + 1).padStart(5, "0")}`,
    user: `compte${i + 1}@exemple.fr`,
    kind: "login",
  }));
}

const renderItem = (it) => ({
  title: it.name,
  subtitle: it.user,
  href: `#/element/${it.id}`,
  avatar: { name: it.name, kind: it.kind },
  primaryLabel: `Copier le mot de passe de ${it.name}`,
  menuLabel: `Plus d'actions pour ${it.name}`,
});

/** Générateur de codes de démonstration (déterministe, sans module de chiffrement). */
function demoTotp(_config, time) {
  const step = Math.floor(time / 30);
  return { code: String((step * 7919 + 273647) % 1000000).padStart(6, "0"), remaining: 30 - (time % 30), period: 30 };
}

const demoEstimate = (pw) => ({
  score: Math.min(4, Math.floor(pw.length / 4)),
  issues: /123|abc|azerty/i.test(pw) ? [{ code: "sequence", params: { seq: "azerty" } }] : [],
});

function output(name) {
  return h("p", { class: "g-output", "data-sortie": name });
}

function say(name, text) {
  document.querySelector(`[data-sortie="${name}"]`).textContent = text;
}

function section(id, title, ...content) {
  const hid = `titre-${id}`;
  return h("section", { class: "g-section", id: `composant-${id}`, "aria-labelledby": hid, "data-component": id },
    h("h2", { id: hid }, title), ...content);
}

function state(title, ...content) {
  return h("div", { class: "g-state" }, h("h3", {}, title), ...content);
}

// ---------------------------------------------------------------- Sections

const SECTIONS = {
  socle: () => section("socle", "Icônes et pastilles",
    h("div", { class: "g-demo" },
      state("Icônes décoratives", h("p", { class: "l-cluster" }, ["copy", "eye", "lock", "key", "shield", "users", "warn", "qr"].map((n) => ui.icon(n)))),
      state("Icône nommée", h("p", {}, ui.icon("shield", { label: "Protégé", size: "lg" }))),
      state("Couleurs des pastilles", h("div", { class: "g-tiles", "data-tiles": ui.TILE_COLORS.join(",") },
        ui.TILE_COLORS.map((c, i) => {
          const tile = h("span", { class: "c-avatar", "aria-hidden": "true" }, String(i + 1));
          tile.style.setProperty("--tile", c);
          return tile;
        }))))),

  bouton: () => section("bouton", "Boutons",
    h("div", { class: "g-demo" },
      state("Variantes", h("div", { class: "l-cluster" },
        ui.button({ label: "Enregistrer", variant: "primary", icon: "check" }),
        ui.button({ label: "Annuler" }),
        ui.button({ label: "Voir le détail", variant: "quiet" }),
        ui.button({ label: "Supprimer définitivement", variant: "danger", icon: "trash" }))),
      state("Icône seule et bascule", h("div", { class: "l-cluster" },
        ui.iconButton({ icon: "copy", label: "Copier la valeur de démonstration" }),
        ui.iconButton({ icon: "star", label: "Ajouter aux favoris", pressed: false, onClick: (e) => ui.setPressed(e.currentTarget, e.currentTarget.getAttribute("aria-pressed") !== "true") }),
        ui.iconButton({ icon: "star-filled", label: "Retirer des favoris", pressed: true }))),
      state("En cours", h("div", { class: "l-cluster" },
        ui.button({
          label: "Envoyer l'invitation", variant: "primary", busyLabel: "Envoi…",
          onClick: () => new Promise((resolve) => setTimeout(resolve, 1500)),
        }))),
      state("Désactivé", h("div", { class: "l-cluster" },
        ui.button({ label: "Partager", disabled: true }),
        ui.button({ label: "Modifier", disabled: true, reason: "Seuls les gestionnaires du coffre peuvent modifier." }))))),

  menu: () => section("menu", "Menus d'actions",
    h("div", { class: "g-demo" },
      state("Avec libellé", ui.menuButton({
        label: "Plus d'actions",
        items: [
          { label: "Modifier", icon: "edit", onSelect: () => say("menu", "Action : Modifier") },
          { label: "Partager", icon: "share", onSelect: () => say("menu", "Action : Partager") },
          { label: "Déplacer", icon: "folder", disabled: true, reason: "Vous n'avez accès à aucun autre coffre." },
          "separator",
          { label: "Mettre à la corbeille", icon: "trash", danger: true, onSelect: () => say("menu", "Action : corbeille") },
        ],
      })),
      state("Icône seule", ui.menuButton({ label: "Plus d'actions pour Gmail", iconOnly: true, items: [{ label: "Ouvrir le site", icon: "external", onSelect: () => say("menu", "Action : Ouvrir") }] })),
      output("menu"))),

  champ: () => {
    const err = ui.field({ label: "Adresse du site", input: ui.textInput({ value: "exemple", type: "url" }) });
    ui.fieldError(err, "Saisissez une adresse complète, par exemple https://exemple.fr.", { announce: false });
    return section("champ", "Champs de saisie",
      h("div", { class: "g-demo" },
        ui.field({ label: "Nom", help: "Le nom affiché dans la liste.", input: ui.textInput({ name: "nom", required: true, autocomplete: "off" }) }),
        ui.field({ label: "Notes", optional: true, count: true, input: ui.textArea({ maxlength: 200, value: "Accès réservé au service comptable." }) }),
        err,
        ui.field({ label: "Quota par personne", suffix: "Mio", input: ui.textInput({ type: "number", value: "1024" }) }),
        ui.field({ label: "Coffre", input: ui.selectInput({ options: [{ value: "perso", label: "Coffre personnel" }, { value: "it", label: "Équipe IT" }], value: "it" }) }),
        ui.field({ label: "Identifiant (désactivé)", input: ui.textInput({ value: "jdupont", disabled: true }) })));
  },

  "mot-de-passe": () => {
    const withError = ui.passwordField({ label: "Mot de passe maître", autocomplete: "current-password" });
    ui.fieldError(withError, "Mot de passe incorrect. Vérifiez la touche Verr. Maj puis réessayez.", { announce: false });
    return section("mot-de-passe", "Mots de passe",
      h("div", { class: "g-demo" },
        ui.passwordField({ label: "Mot de passe", value: "C0rrect-Cheval-Agrafe", autocomplete: "new-password", withStrength: true, estimate: demoEstimate, withGenerate: true, onGenerate: () => "Tq7!vLp2#Rz9@Wm4" }),
        withError));
  },

  code: () => section("code", "Code de vérification (saisie)",
    h("div", { class: "g-demo" },
      ui.otpInput({ label: "Code de vérification", onComplete: (code) => say("code", `Code reçu : ${code}`) }),
      output("code"))),

  choix: () => section("choix", "Choix",
    h("div", { class: "g-demo" },
      state("Interrupteurs",
        ui.toggle({ label: "Verrouiller quand l'onglet est masqué", checked: true, help: "Le coffre se verrouille dès que vous changez d'onglet." }),
        ui.toggle({ label: "Copie au clic", checked: false }),
        ui.toggle({ label: "Raccourcis à une touche", checked: true, disabled: true, reason: "Imposé par votre organisation" })),
      ui.segmented({ label: "Thème", options: [{ value: "system", label: "Système" }, { value: "light", label: "Clair" }, { value: "dark", label: "Sombre" }], value: "system" }),
      ui.radioCards({
        legend: "Profil de sécurité", value: "reinforced",
        options: [
          { value: "standard", label: "Standard", description: "Pour démarrer simplement.", icon: "shield" },
          { value: "reinforced", label: "Renforcé", description: "Recommandé pour la plupart des organisations.", icon: "lock" },
          { value: "strict", label: "Strict", description: "Pour les données les plus sensibles.", icon: "key" },
        ],
      }),
      ui.checkboxGroup({ legend: "Rôles concernés", values: ["admin", "owner"], options: [{ value: "user", label: "Utilisateur" }, { value: "admin", label: "Administrateur" }, { value: "owner", label: "Propriétaire" }] }))),

  duree: () => section("duree", "Durées",
    h("div", { class: "g-demo" },
      ui.durationSelect({
        label: "Verrouiller Locksy après", value: 10, unit: "minutes", min: 1, max: 30,
        presets: [1, 5, 10, 15, 30, 60, 240], disabledReason: "Limité à 30 min par votre organisation",
        onChange: (v) => say("duree", `Durée choisie : ${v} min`),
      }),
      ui.durationSelect({ label: "Effacer le presse-papiers après", value: 30, unit: "seconds", min: 5, max: 600, presets: [10, 30, 60, 300], allowNever: true }),
      output("duree"))),

  "liste-saisie": () => section("liste-saisie", "Listes de valeurs",
    h("div", { class: "g-demo" },
      ui.chipsInput({
        label: "Domaines autorisés", values: ["exemple.fr", "filiale.exemple.fr"], placeholderKey: "ui.setting.placeholder.domains",
        validate: (v) => (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(v) ? null : `« ${v} » n'est pas un nom de domaine.`),
        onChange: (values) => say("liste-saisie", `${values.length} domaines`),
      }),
      output("liste-saisie"))),

  recherche: () => section("recherche", "Recherche",
    h("div", { class: "g-demo" },
      ui.searchBox({ label: "Rechercher dans tout le coffre", placeholderKey: "ui.hotkeys.search_focus", onInput: (q) => say("recherche", q ? `Recherche : ${q}` : "") }),
      output("recherche"))),

  secret: () => section("secret", "Secrets",
    h("div", { class: "c-card" },
      ui.secretRow({ label: "Identifiant", value: "jdupont@exemple.fr", kind: "username" }),
      ui.secretRow({ label: "Mot de passe", value: "Tq7!vLp2#Rz9@Wm4", kind: "password", onCopied: () => say("secret", "Copie faite") })),
    h("p", {}, ui.formatSecret("Révélé:1234!abcd")),
    output("secret")),

  "code-site": () => {
    const totp = ui.totpCode({ config: "demo", generate: demoTotp });
    return section("code-site", "Code de vérification d'un site",
      h("div", { class: "g-demo" }, state("Code en cours", totp.el),
        state("Clé invalide", ui.totpCode({ config: "", generate: () => { throw new Error("clé"); } }).el)));
  },

  force: () => section("force", "Force et problèmes",
    h("div", { class: "g-demo" },
      state("Niveaux", [0, 1, 2, 3, 4].map((score) => ui.strengthMeter({ score }))),
      state("Très solide plafonné par un problème", ui.strengthMeter({ score: 4, issues: [{ code: "reused", n: 1 }] })),
      state("Problèmes", h("div", { class: "l-cluster" },
        ui.issueChip({ issue: { code: "reused", n: 1 }, onClick: () => say("force", "Ouvrir les réutilisations") }),
        ui.issueChip({ issue: { code: "sequence", params: { seq: "azerty" } }, href: "#/bilan" }),
        ui.issueChip({ issue: { code: "old", params: { age: "2 ans" } }, href: "#/bilan" }))),
      output("force"))),

  badge: () => section("badge", "Badges et audience",
    h("div", { class: "g-demo" },
      state("Tonalités", h("div", { class: "l-cluster" },
        ui.badge({ tone: "ok", label: "Active", icon: "check" }),
        ui.badge({ tone: "warn", label: "Expire bientôt", icon: "clock" }),
        ui.badge({ tone: "danger", label: "Désactivé", icon: "error" }),
        ui.badge({ tone: "info", label: "Imposé", icon: "lock" }),
        ui.badge({ tone: "neutral", label: "Avancé" }))),
      state("Audience",
        ui.audienceLine({ collection: { personal: true } }),
        ui.audienceLine({ collection: { name: "Équipe IT" }, members: 3 })))),

  carte: () => section("carte", "Cartes",
    h("div", { class: "l-grid" },
      ui.statCard({ value: 1204, label: "éléments", href: "#/coffre" }),
      ui.statCard({ value: 3, label: "personnes sans double authentification", tone: "warn" })),
    ui.alertCard({ tone: "warn", title: "3 personnes n'ont pas activé la double authentification", text: "Votre organisation l'impose depuis le 18 nov.", action: { label: "Voir les personnes", href: "#/admin/personnes" } }),
    ui.alertCard({ tone: "danger", text: "La connexion d'entreprise ne répond plus.", action: { label: "Tester maintenant", onClick: () => say("carte", "Test lancé") } }),
    ui.statusCard({ tone: "ok", title: "Sauvegarde vérifiée", detail: "Dernière vérification il y a 2 h." }),
    output("carte")),

  etat: () => section("etat", "États d'une vue",
    h("div", { class: "g-demo" },
      state("Vide", ui.emptyState({ icon: "star", title: "Aucun favori", text: "Ouvrez un élément et cliquez sur l'étoile.", level: 3 })),
      state("Chargement", ui.skeleton({ lines: 4 })),
      state("Erreur", ui.errorState({ error: { code: "network" }, title: "Impossible d'afficher le coffre", level: 3, onRetry: () => say("etat", "Nouvel essai") })),
      state("Hors ligne", ui.offlineBanner())),
    output("etat")),

  pastille: () => section("pastille", "Pastilles d'initiale",
    h("div", { class: "l-cluster" },
      ui.avatar({ name: "Camille Durand" }), ui.avatar({ name: "Hugo Martin", size: "lg" }),
      ui.itemAvatar({ item: { name: "Gmail", kind: "login" } }), ui.itemAvatar({ item: { name: "", kind: "card" } }))),

  fenetre: () => {
    const open = () => {
      const input = ui.textInput({ name: "coffre", autocomplete: "off" });
      ui.dialog({
        title: "Nouveau coffre",
        description: "Donnez un nom au coffre partagé.",
        body: h("div", { class: "l-stack", "data-gap": "3" },
          ui.field({ label: "Nom du coffre", input }),
          ui.button({
            label: "Ouvrir une seconde fenêtre",
            onClick: () => ui.dialog({ title: "Seconde fenêtre", body: h("p", {}, "Fenêtre ouverte par-dessus la première."), actions: [{ label: "Fermer", variant: "primary" }] }),
          })),
        dirty: () => input.value.trim() !== "",
        actions: [
          { label: "Annuler", value: "cancel", cancel: true },
          { label: "Créer", variant: "primary", onClick: () => { say("fenetre", `Créé : ${input.value}`); } },
        ],
        onClose: (value) => { if (value === "cancel") say("fenetre", "Fenêtre fermée"); },
      });
    };
    return section("fenetre", "Fenêtres",
      h("div", { class: "l-cluster" },
        ui.button({ label: "Ouvrir une fenêtre", variant: "primary", onClick: open }),
        ui.button({ label: "Afficher les raccourcis", onClick: () => ui.hotkeys.helpDialog() })),
      output("fenetre"));
  },

  confirmation: () => {
    const run = async (opts) => {
      const r = await ui.confirm(opts);
      say("confirmation", r.confirmed ? `Confirmé${r.reauth ? " avec preuve" : ""}` : "Annulé");
      if (r.undone) r.undone.then((undone) => say("confirmation", undone ? "Action annulée par l'utilisateur" : "Action conservée"));
    };
    return section("confirmation", "Confirmations",
      h("div", { class: "l-cluster" },
        ui.button({ label: "Niveau 0", onClick: () => run({ level: 0, message: "Élément mis à la corbeille.", undo: () => say("confirmation", "Restauré") }) }),
        ui.button({ label: "Niveau 1", onClick: () => run({ level: 1, title: "Mettre à la corbeille ?", message: "Vous pourrez le restaurer pendant 30 jours.", objectName: "Gmail", confirmLabel: "Mettre à la corbeille" }) }),
        ui.button({ label: "Niveau 2", onClick: () => run({ level: 2, title: "Révoquer tous les liens ?", objectName: "Équipe IT", impact: ["12 liens sécurisés ne fonctionneront plus.", "4 personnes seront prévenues."], confirmLabel: "Révoquer", danger: true }) }),
        ui.button({ label: "Niveau 3", onClick: () => run({ level: 3, title: "Supprimer définitivement le coffre ?", objectName: "Équipe IT", impact: "128 éléments seront supprimés pour 9 personnes.", confirmLabel: "Supprimer définitivement", danger: true, reauth: async (pw) => { if (pw !== "démo") throw { code: "wrong_password" }; return "preuve"; } }) })),
      output("confirmation"));
  },

  panneau: () => section("panneau", "Panneau latéral",
    ui.button({
      label: "Ouvrir le panneau",
      onClick: () => {
        const input = ui.textInput({ name: "titre" });
        ui.panel({
          title: "Modifier l'élément",
          body: h("div", { class: "l-stack" }, ui.field({ label: "Titre", input }), ui.field({ label: "Identifiant", input: ui.textInput({ name: "identifiant" }) })),
          dirty: () => input.value !== "",
          actions: [{ label: "Annuler", cancel: true }, { label: "Enregistrer", variant: "primary", onClick: () => say("panneau", `Panneau enregistré : ${input.value}`) }],
        });
      },
    }),
    output("panneau")),

  bulle: () => {
    const anchor = ui.button({ label: "Qui voit cet élément ?" });
    anchor.addEventListener("click", () => ui.popover({ anchor, label: "Audience", body: h("div", { class: "l-stack", "data-gap": "2" }, ui.audienceLine({ collection: { name: "Équipe IT" }, members: 3 }), ui.button({ label: "Gérer l'accès" })) }));
    return section("bulle", "Bulle", anchor);
  },

  onglets: () => section("onglets", "Onglets",
    ui.tabs({
      label: "Partager Gmail",
      tabs: [
        { id: "collegues", label: "Avec des collègues", render: (p) => p.append(ui.field({ label: "Avec qui ?", input: ui.textInput({}) })) },
        { id: "lien", label: "Par lien sécurisé", render: (p) => p.append(h("p", {}, "Le lien expire après 24 heures.")) },
      ],
    }).el),

  navigation: () => section("navigation", "Navigation latérale",
    ui.sideNav({
      label: "Navigation de démonstration", current: "tout",
      items: [
        { id: "tout", label: "Tout", icon: "vault", count: 1204, href: "#/coffre" },
        { id: "favoris", label: "Favoris", icon: "star", count: 12, href: "#/favoris" },
        { group: "Coffres" },
        { id: "it", label: "Équipe IT", icon: "folder", count: 128, href: "#/coffre/it", badge: { tone: "info", label: "Partagé" } },
        { id: "corbeille", label: "Corbeille", icon: "trash", href: "#/corbeille" },
      ],
    })),

  assistant: () => section("assistant", "Assistant",
    ui.wizard({
      label: "Départ de l'entreprise",
      steps: [
        { id: "personne", title: "Choisir la personne", render: (c) => c.append(h("p", {}, "Camille Durand, administratrice.")) },
        { id: "coffres", title: "Transférer les coffres", render: (c) => c.append(h("p", {}, "3 coffres seront transférés.")) },
        { id: "fin", title: "Confirmer", render: (c) => c.append(h("p", {}, "Le compte sera désactivé.")) },
      ],
      onFinish: () => say("assistant", "Assistant terminé"),
    }).el,
    output("assistant")),

  liste: () => {
    const list = ui.itemList({
      label: "Éléments", items: makeItems(40), render: renderItem, selectedKey: "el-2",
      onOpen: (it) => { list.select(it.id); say("liste", `Ouvert : ${it.name}`); },
      onPrimary: (it) => say("liste", `Copie demandée : ${it.name}`),
      onMenu: (it) => [{ label: "Modifier", icon: "edit", onSelect: () => say("liste", `Modifier : ${it.name}`) }],
    });
    window.gallery.list = list;
    return section("liste", "Liste d'éléments", h("div", { class: "g-scroll", "data-liste": "demo" }, list.el), output("liste"));
  },

  tableau: () => {
    const rows = makeItems(8).map((it, i) => ({ ...it, role: ["Utilisateur", "Administrateur"][i % 2], last: i + 1 }));
    let sort = { key: "name", dir: "ascending" };
    const table = ui.dataTable({
      caption: "Personnes", rows, selectable: true, rowLabel: (r) => r.name,
      columns: [
        { key: "name", label: "Nom", sortable: true },
        { key: "role", label: "Rôle" },
        { key: "last", label: "Dernière connexion (jours)", sortable: true, numeric: true },
      ],
      sort, onRowOpen: (r) => say("tableau", `Fiche : ${r.name}`),
      onSort: (s) => {
        sort = s;
        const sorted = [...rows].sort((a, b) => (a[s.key] > b[s.key] ? 1 : -1) * (s.dir === "ascending" ? 1 : -1));
        table.update({ rows: sorted, sort });
      },
      page: 1, pageSize: 8, total: 24, onPage: (p) => table.update({ page: p }),
      bulkActions: [{ label: "Désactiver", danger: true, onClick: (sel) => say("tableau", `${sel.length} à désactiver`) }],
    });
    return section("tableau", "Tableau", table.el,
      state("Chargement", ui.dataTable({ caption: "Journal", columns: [{ key: "a", label: "Action" }], rows: [], loading: true }).el),
      output("tableau"));
  },

  filtres: () => section("filtres", "Filtres",
    ui.filterBar({
      syncUrl: false,
      filters: [
        { key: "type", label: "Type", options: [{ value: "", label: "Tous" }, { value: "login", label: "Mots de passe" }, { value: "note", label: "Notes" }] },
        { key: "tri", label: "Tri", options: [{ value: "nom", label: "Nom" }, { value: "recent", label: "Récents" }] },
      ],
      onChange: (v) => say("filtres", `Filtres : ${Object.values(v).filter(Boolean).join(", ")}`),
    }).el,
    output("filtres")),

  reglage: () => {
    const changed = (c) => say("reglage", `Changement : ${JSON.stringify(c)}`);
    const defs = [
      { def: { key: "client.autolock_minutes", kind: { type: "int", min: 1, max: 1440, unit: "minutes" }, default: { value: 10, mode: "default", max: null }, modes: true, presets: [1, 5, 10, 15, 30, 60, 240], section: "sessions" }, value: 15, mode: "default", max: 30, source: "org" },
      { def: { key: "twofa.required", kind: { type: "bool" }, default: { value: false } }, value: true, source: "org" },
      { def: { key: "extension.http_fill", kind: { type: "enum", values: ["allow", "warn", "block"] }, default: { value: "warn" } }, value: "block", source: "org" },
      { def: { key: "access.ip_allowlist", kind: { type: "cidrs" }, default: { value: [] }, advanced: true }, value: ["192.168.0.0/24"], source: "org", error: "Votre adresse 10.0.0.4 n'est pas dans la liste." },
      { def: { key: "branding.accent_color", kind: { type: "color" }, default: { value: "#1b6b5f" } }, value: "#1b6b5f", source: "default" },
      { def: { key: "mail.smtp.password", kind: { type: "secret" }, default: { value: null }, owner_only: true }, hasSecret: true, source: "org" },
      { def: { key: "audit.syslog.url", kind: { type: "url", https_only: false }, default: { value: "" } }, value: "tcp://siem:514", source: "host_locked", lockedBy: "LOCKSY_SYSLOG" },
      { def: { key: "retention.audit_days", kind: { type: "int", min: 30, max: 3650, unit: "days" }, default: { value: 365 }, owner_only: true, presets: [90, 180, 365, 730] }, value: 365, source: "default", canEdit: false },
    ];
    return section("reglage", "Réglages générés", h("div", { class: "c-card" }, defs.map((d) => ui.settingField({ ...d, onChange: changed }).el)), output("reglage"));
  },

  politique: () => section("politique", "Mentions de politique",
    ui.policyHint({ policy: { value: 10, mode: "default", max: 30 }, format: (v) => ui.formatDuration(v, "minutes") }),
    ui.policyHint({ policy: { value: true, mode: "enforced" } }),
    ui.policyHint({ policy: { value: 5, source: "machine" } })),

  differences: () => section("differences", "Récapitulatif des modifications",
    ui.diffList({
      changes: [
        { key: "session.idle_minutes", label: "Déconnexion après inactivité", def: { kind: { type: "int", unit: "minutes" } }, old: 60, new: 240, lowered: true },
        { key: "twofa.required", label: "Double authentification obligatoire", def: { kind: { type: "bool" } }, old: false, new: true, lowered: false },
      ],
    })),

  barre: () => {
    const bar = ui.saveBar({ count: 2, onReset: () => say("barre", "Modifications annulées"), onSave: () => say("barre", "Enregistrement demandé") });
    return section("barre", "Barre d'enregistrement", bar.el, output("barre"));
  },

  qr: () => section("qr", "Import d'un QR code",
    ui.qrImport({ onResult: () => say("qr", "QR code de configuration reçu") }),
    output("qr")),

  notification: () => section("notification", "Notifications",
    h("div", { class: "l-cluster" },
      ui.button({ label: "Notification de succès", onClick: () => ui.notify({ text: "Élément enregistré.", tone: "ok" }) }),
      ui.button({ label: "Notification d'erreur", onClick: () => ui.notify({ text: ui.errorText({ code: "network" }), tone: "danger" }) }),
      ui.button({ label: "Notification avec annulation", onClick: () => ui.notify({ text: "Élément mis à la corbeille.", tone: "info", action: { run: () => say("notification", "Restauré") } }) })),
    output("notification")),

  raccourcis: () => {
    let count = 0;
    window.gallery.hotkeysCount = () => count;
    ui.hotkeys.register({ id: "item.new", run: () => { count += 1; say("raccourcis", `Nouvel élément demandé (${count})`); } });
    ui.hotkeys.register({ id: "help", run: () => ui.hotkeys.helpDialog() });
    ui.hotkeys.enterScope("vault");
    return section("raccourcis", "Raccourcis clavier",
      h("div", { class: "g-demo" },
        ui.toggle({ label: "Raccourcis à une touche", checked: true, onChange: (on) => ui.hotkeys.setEnabled(on) }),
        ui.field({ label: "Champ de test des raccourcis", input: ui.textInput({ name: "essai" }) })),
      h("dl", { class: "c-hotkeys" }, ui.hotkeys.list().slice(0, 3).flatMap((e) => [h("dt", {}, t(e.labelKey)), h("dd", {}, ui.keysLabel(e.keys))])),
      output("raccourcis"));
  },

  details: () => section("details", "Détails techniques",
    ui.technicalDetails({ body: "client.autolock_minutes · LOCKSY_SETTINGS_FILE" })),
};

// ---------------------------------------------------------------- Montage

window.gallery = { ui, makeItems, renderItem, demoTotp };

const only = params.get("only");
const target = document.getElementById("galerie");
const names = only && SECTIONS[only] ? [only] : Object.keys(SECTIONS);
for (const name of names) target.append(SECTIONS[name]());
target.removeAttribute("aria-busy");
document.documentElement.dataset.galleryReady = "true";
