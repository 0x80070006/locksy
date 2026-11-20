// Jeux de données du banc (audit 05, §3.4 et §4.4). Module pur : aucune
// entrée-sortie, aucune cryptographie. Les contenus sont pseudo-aléatoires mais
// reproductibles (générateur à graine) ; seuls les mots de passe des comptes,
// tirés par seed.mjs, changent d'un semis à l'autre.
//
// Forme d'un jeu :
//   accounts[]    { email, name, role, personal: SpecÉléments, attachments: [taille], totp: bool }
//   collections[] { key, name, creator, members: [{ email, role }], items: SpecÉléments,
//                   attachments: [taille] }     (pièces jointes envoyées par les membres éditeurs)
// SpecÉléments : { seed, count, weak?: [index], reused?: [index], kinds?: [type] }

export const DATASET_NAMES = ["S", "M", "L", "E2E"];

const KIB = 1024;
const MIB = 1024 * 1024;

/** Générateur pseudo-aléatoire 32 bits (mulberry32) à graine textuelle. */
export function rngFor(seed) {
  let h = 1779033703 ^ seed.length;
  for (let i = 0; i < seed.length; i++) {
    h = Math.imul(h ^ seed.charCodeAt(i), 3432918353);
    h = (h << 13) | (h >>> 19);
  }
  let a = h >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const pick = (rng, list) => list[Math.floor(rng() * list.length)];
const pad = (n, w) => String(n).padStart(w, "0");

// ------------------------------------------------------------ Comptes

function account(email, name, role, personal, extra = {}) {
  return { email, name, role, personal, attachments: [], totp: false, ...extra };
}

/** Rôle des comptes de charge : le n° 0 est propriétaire, les `admins` suivants administrateurs. */
const roleOf = (i, admins) => (i === 0 ? "owner" : i <= admins ? "admin" : "user");

function loadAccounts(ds, count, admins, personalCount) {
  return Array.from({ length: count }, (_, i) => {
    const email = i === 0 ? "proprietaire@banc.test" : `utilisateur-${pad(i, 4)}@banc.test`;
    const name = i === 0 ? "Propriétaire du banc" : `Utilisateur ${pad(i, 4)}`;
    return account(email, name, roleOf(i, admins), { seed: `${ds}:perso:${i}`, count: personalCount });
  });
}

/** Sépare un rôle de coffre : quelques lecteurs, sinon éditeurs. */
const memberRole = (i) => (i % 5 === 4 ? "reader" : "editor");

/** Coffres d'équipe : chaque compte rejoint `perAccount` coffres distincts. */
function teamCollections(ds, accounts, count, itemsPerCollection, perAccount) {
  const members = Array.from({ length: count }, () => []);
  accounts.forEach((a, i) => {
    const first = i % count;
    const chosen = [first];
    if (perAccount > 1) chosen.push((first + 1 + (Math.floor(i / count) % (count - 1))) % count);
    chosen.forEach((k) => members[k].push(a.email));
  });
  return members.map((emails, k) => ({
    key: `equipe-${k + 1}`,
    name: `Équipe ${k + 1}`,
    creator: emails[0],
    members: emails.slice(1).map((email, j) => ({ email, role: memberRole(j) })),
    items: { seed: `${ds}:equipe:${k + 1}`, count: itemsPerCollection },
    attachments: [],
  }));
}

/** Tailles pseudo-aléatoires (octets) entre `min` et `max`. */
function sizes(seed, count, min, max) {
  const rng = rngFor(seed);
  return Array.from({ length: count }, () => min + Math.floor(rng() * (max - min + 1)));
}

function datasetS() {
  const accounts = loadAccounts("S", 50, 2, 200);
  return {
    name: "S",
    description: "50 comptes, 200 éléments personnels chacun, 5 coffres partagés de 100 éléments",
    accounts,
    collections: teamCollections("S", accounts, 5, 100, 1),
  };
}

function datasetM() {
  const accounts = loadAccounts("M", 500, 5, 150);
  // 4 pièces jointes de 50 Ko à 1 Mo par compte : 2 000 au total.
  accounts.forEach((a, i) => { a.attachments = sizes(`M:pj:${i}`, 4, 50 * KIB, MIB); });
  return {
    name: "M",
    description: "500 comptes, 150 éléments personnels, 10 coffres d'équipe de 425 éléments "
      + "(chaque compte en rejoint 2 : 1 000 éléments visibles), 2 000 pièces jointes de 50 Ko à 1 Mo",
    accounts,
    collections: teamCollections("M", accounts, 10, 425, 2),
  };
}

function datasetL() {
  const m = datasetM();
  const it = Array.from({ length: 20 }, (_, i) =>
    account(`it-${pad(i + 1, 2)}@banc.test`, `Équipe IT ${pad(i + 1, 2)}`, "user", { seed: `L:it:${i}`, count: 20 }));
  return {
    name: "L",
    description: `${m.description} ; plus 20 comptes « équipe IT » et un coffre IT de 10 000 éléments `
      + "avec 200 pièces jointes de 10 Mo",
    accounts: [...m.accounts, ...it],
    collections: [
      ...m.collections,
      {
        key: "it",
        name: "Infrastructure IT",
        creator: it[0].email,
        members: it.slice(1).map((a) => ({ email: a.email, role: "editor" })),
        items: { seed: "L:it", count: 10000 },
        // Réparties entre les 20 membres : 100 Mo chacun, sous le quota personnel.
        attachments: Array(200).fill(10 * MIB),
      },
    ],
  };
}

function datasetE2E() {
  const few = (who) => ({ seed: `E2E:${who}`, count: 5 });
  const alice = account("alice@e2e.test", "Alice Martin", "user", {
    seed: "E2E:alice",
    count: 40,
    // Tous les types d'éléments, en boucle.
    kinds: ["login", "login", "login", "note", "card", "identity", "ssh", "login"],
    // Écran Santé : 3 mots de passe faibles et 2 réutilisés (une paire).
    weak: [2, 10, 18],
    reused: [1, 9],
  });
  alice.attachments = [24 * KIB, 180 * KIB];
  return {
    name: "E2E",
    description: "6 comptes nommés (§4.4 de l'audit 05) pour les tests Playwright",
    accounts: [
      account("proprietaire@e2e.test", "Propriétaire E2E", "owner", few("proprietaire")),
      account("admin@e2e.test", "Administrateur E2E", "admin", few("admin")),
      alice,
      account("bob@e2e.test", "Bob Durand", "user", few("bob")),
      account("carole@e2e.test", "Carole Petit", "user", few("carole")),
      account("david@e2e.test", "David Moreau", "user", few("david"), { totp: true }),
    ],
    collections: [{
      key: "equipe",
      name: "Équipe",
      creator: "alice@e2e.test",
      members: [{ email: "bob@e2e.test", role: "editor" }, { email: "carole@e2e.test", role: "reader" }],
      items: { seed: "E2E:equipe", count: 10 },
      attachments: [],
    }],
  };
}

/** Jeu nommé (S, M, L ou E2E), ou erreur explicite. */
export function dataset(name) {
  const build = { S: datasetS, M: datasetM, L: datasetL, E2E: datasetE2E }[name];
  if (!build) throw new Error(`Jeu inconnu : « ${name} » (attendu : ${DATASET_NAMES.join(", ")}).`);
  return build();
}

// ------------------------------------------------------------ Éléments

const SERVICES = [
  "Messagerie", "Intranet RH", "Gestion de la relation client", "Comptabilité", "VPN", "Wi-Fi invités",
  "Routeur du siège", "Stockage réseau", "Banque en ligne", "Fournisseur d'énergie", "Hébergeur",
  "Nom de domaine", "Supervision", "Assistance", "Paie", "Visioconférence", "Pare-feu", "Annuaire",
  "Sauvegardes", "Entrepôt de code", "Messagerie instantanée", "Signature électronique", "Achats",
  "Notes de frais", "Téléphonie", "Imprimantes", "Caméras", "Contrôle d'accès", "Site public", "Boutique",
];
const FIRST = ["camille", "louis", "lea", "hugo", "chloe", "lucas", "manon", "jules", "ines", "nathan", "sarah", "tom"];
const LAST = ["martin", "bernard", "dubois", "thomas", "robert", "richard", "petit", "durand", "leroy", "moreau"];
const TAGS = ["production", "recette", "client", "interne", "finance", "rh", "réseau", "fournisseur"];
const WEAK = ["azerty123", "Motdepasse1", "123456789", "soleil2024", "Bienvenue1"];
const CHARSET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#%&*+-=?@";
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const randomString = (rng, alphabet, length) =>
  Array.from({ length }, () => alphabet[Math.floor(rng() * alphabet.length)]).join("");

const slug = (s) => s.normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

/** Type de l'élément n° i : séquence imposée, sinon tirage (75 % identifiants). */
function kindOf(rng, spec, i) {
  if (spec.kinds?.length) return spec.kinds[i % spec.kinds.length];
  const r = rng();
  return r < 0.75 ? "login" : r < 0.83 ? "note" : r < 0.88 ? "card" : r < 0.93 ? "identity" : "ssh";
}

/**
 * Éléments d'une SpecÉléments, sur le modèle `emptyItem` du client
 * (web/js/vault.js), pour que le semis écrive exactement ce que l'interface lit.
 * `now` (secondes Unix) sert de référence aux dates.
 */
export function generateItems(spec, emptyItem, now) {
  const rng = rngFor(spec.seed);
  const weak = spec.weak || [];
  const reused = new Set(spec.reused || []);
  const sharedPassword = randomString(rngFor(`${spec.seed}:partage`), CHARSET, 18);
  const out = [];
  for (let i = 0; i < spec.count; i++) {
    const kind = kindOf(rng, spec, i);
    const service = pick(rng, SERVICES);
    const who = `${pick(rng, FIRST)}.${pick(rng, LAST)}`;
    const d = emptyItem(kind);
    d.name = `${service} ${pad(i + 1, 5)}`;
    d.favorite = rng() < 0.05;
    d.tags = rng() < 0.4 ? [pick(rng, TAGS)] : [];
    d.notes = rng() < 0.25 ? `Note de test n° ${i + 1} pour ${service.toLowerCase()}.` : "";
    if (kind === "login") {
      d.username = rng() < 0.5 ? `${who}@exemple.fr` : who;
      // Jeu imposé : un mot de passe faible DIFFÉRENT par index, pour des comptes exacts.
      d.password = weak.includes(i) ? WEAK[weak.indexOf(i) % WEAK.length]
        : !spec.weak && rng() < 0.04 ? pick(rng, WEAK)
        : reused.has(i) || (!spec.reused && rng() < 0.03) ? sharedPassword
          : randomString(rng, CHARSET, 14 + Math.floor(rng() * 11));
      d.urls = [`https://${slug(service)}.exemple.fr/connexion`];
      d.totp = rng() < 0.1 ? randomString(rng, BASE32, 32) : "";
      d.password_changed_at = now - Math.floor(rng() * 800) * 86400;
      if (rng() < 0.15) d.fields = [{ label: "Code client", value: `C-${pad(Math.floor(rng() * 1e5), 5)}`, hidden: false }];
    } else if (kind === "note") {
      d.notes = `Procédure n° ${i + 1} : ${service}.\nÉtape 1 : ouvrir la console.\nÉtape 2 : vérifier l'état.`;
    } else if (kind === "card") {
      d.card = {
        holder: who.replace(".", " ").toUpperCase(),
        number: `4970${randomString(rng, "0123456789", 12)}`,
        expiry: `${pad(1 + Math.floor(rng() * 12), 2)}/${28 + Math.floor(rng() * 5)}`,
        cvv: randomString(rng, "0123456789", 3),
        pin: randomString(rng, "0123456789", 4),
      };
    } else if (kind === "identity") {
      const [first, last] = who.split(".");
      d.identity = {
        first_name: first, last_name: last, email: `${who}@exemple.fr`, phone: `01 ${randomString(rng, "0123456789", 8).replace(/(..)(?=.)/g, "$1 ")}`,
        address: `${1 + Math.floor(rng() * 99)} rue de l'Exemple, 75000 Paris`, company: "Exemple SARL", document_number: randomString(rng, BASE32, 9),
      };
    } else {
      d.ssh = {
        private_key: `-----BEGIN OPENSSH PRIVATE KEY-----\n${randomString(rng, B64, 280)}\n-----END OPENSSH PRIVATE KEY-----`,
        public_key: `ssh-ed25519 ${randomString(rng, B64, 68)} ${who}@exemple.fr`,
        passphrase: rng() < 0.5 ? randomString(rng, CHARSET, 16) : "",
      };
    }
    out.push(d);
  }
  return out;
}
