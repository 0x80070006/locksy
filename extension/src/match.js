// Correspondance stricte entre l'adresse d'un identifiant et la page ouverte.
// Module pur (aucune API du navigateur) : testé par src/test/match.test.js.
//
// Règles :
//  - même schéma, ou montée http → https (jamais l'inverse : un identifiant
//    enregistré en https n'est jamais rempli sur une page http) ;
//  - mêmes ports effectifs (443/80 implicites normalisés par URL) ;
//  - même « domaine enregistrable » (eTLD+1) : login.example.com et
//    www.example.com correspondent, example.com.evil.com non.

// Suffixes publics à plusieurs niveaux reconnus. Liste volontairement courte :
// pour un ccSLD absent de la liste, la règle prudente de registrableDomain()
// retombe sur l'hôte complet (correspondance exacte), jamais sur un domaine
// trop large.
const MULTI_LEVEL_SUFFIXES = new Set([
  // ICANN
  "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk", "nhs.uk", "sch.uk",
  "com.fr", "gouv.fr", "asso.fr", "nom.fr",
  "com.au", "net.au", "org.au", "gov.au", "edu.au",
  "co.nz", "co.jp", "ne.jp", "or.jp",
  "com.br", "com.cn", "com.mx", "co.in", "co.za", "com.tr", "com.es", "co.il",
  // Domaines privés où chaque sous-domaine appartient à un client différent
  "github.io", "gitlab.io", "pages.dev", "workers.dev", "vercel.app", "netlify.app",
  "herokuapp.com", "azurewebsites.net", "cloudfront.net", "appspot.com", "web.app",
  "firebaseapp.com", "blogspot.com", "onrender.com", "s3.amazonaws.com",
]);

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * Domaine enregistrable d'un hôte (eTLD+1), ou l'hôte exact quand on ne peut
 * pas le déterminer sans risque (adresse IP, localhost, ccSLD inconnu…).
 */
export function registrableDomain(host) {
  const h = String(host || "").toLowerCase().replace(/\.+$/, "");
  if (!h) return "";
  // IPv6 (« [::1] » dans URL.hostname), IPv4, nom sans point (localhost, intranet).
  if (h.includes(":") || h.startsWith("[") || IPV4.test(h) || !h.includes(".")) return h;
  const labels = h.split(".");
  if (labels.some((l) => !l)) return h;
  if (h.endsWith(".localhost")) return h;
  // Suffixe connu le plus long (au plus 3 niveaux : s3.amazonaws.com).
  for (let n = Math.min(3, labels.length); n >= 2; n--) {
    const suffix = labels.slice(-n).join(".");
    if (MULTI_LEVEL_SUFFIXES.has(suffix)) {
      // L'hôte est le suffixe lui-même : rien d'enregistrable, correspondance exacte.
      if (labels.length === n) return h;
      return labels.slice(-(n + 1)).join(".");
    }
  }
  const tld = labels[labels.length - 1];
  const second = labels[labels.length - 2];
  // Règle prudente : TLD national (2 lettres) précédé d'un label court
  // inconnu (co.ke, or.kr…) : probablement un suffixe public absent de la
  // liste. On renvoie l'hôte complet, ce qui revient à une correspondance exacte.
  // Seule exception : un « www. » de tête est retiré (www.sfr.fr ≡ sfr.fr),
  // car « www » n'est jamais un label vendu à un tiers sous un suffixe.
  if (tld.length === 2 && second.length <= 3 && labels.length >= 3) {
    return labels[0] === "www" ? labels.slice(1).join(".") : h;
  }
  // TLD numérique : adresse mal formée, on ne regroupe rien.
  if (/^\d+$/.test(tld)) return h;
  return labels.slice(-2).join(".");
}

/** URL analysée d'un identifiant : sans schéma, on suppose https:// (comme safeUrl). */
function parseItemUrl(u) {
  const s = String(u || "").trim();
  if (!s) return null;
  try {
    return new URL(/^[a-z][a-z0-9+.-]*:/i.test(s) ? s : `https://${s}`);
  } catch {
    return null;
  }
}

function parsePageUrl(u) {
  try {
    return new URL(String(u || ""));
  } catch {
    return null;
  }
}

const WEB = new Set(["http:", "https:"]);
const effectivePort = (url) => url.port || (url.protocol === "https:" ? "443" : "80");

/**
 * Compare un identifiant à une page :
 *  - "match" : remplissage autorisé ;
 *  - "downgrade" : même site, mais la page est en http alors que
 *    l'identifiant est en https (remplissage refusé) ;
 *  - "nomatch" : autre site, autre port ou adresse non web.
 */
export function matchStatus(itemUrl, pageUrl) {
  const item = parseItemUrl(itemUrl);
  const page = parsePageUrl(pageUrl);
  if (!item || !page || !WEB.has(item.protocol) || !WEB.has(page.protocol)) return "nomatch";
  if (!item.hostname || !page.hostname) return "nomatch";
  const a = registrableDomain(item.hostname);
  const b = registrableDomain(page.hostname);
  if (!a || a !== b) return "nomatch";
  // Schémas différents : les ports implicites (80 et 443) sont considérés égaux.
  const crossScheme = item.protocol !== page.protocol;
  const samePort = effectivePort(item) === effectivePort(page) || (crossScheme && !item.port && !page.port);
  if (!samePort) return "nomatch";
  // Descente https → http : même site, mais jamais de remplissage.
  if (item.protocol === "https:" && page.protocol === "http:") return "downgrade";
  return "match";
}

/** Vrai si l'identifiant peut être rempli sur cette page. */
export function urlMatches(itemUrl, pageUrl) {
  return matchStatus(itemUrl, pageUrl) === "match";
}

/** Page en http hors boucle locale : le mot de passe y circulerait en clair. */
export function isInsecurePage(pageUrl) {
  const page = parsePageUrl(pageUrl);
  if (!page || page.protocol !== "http:") return false;
  const host = page.hostname.toLowerCase();
  return !(host === "localhost" || host.endsWith(".localhost") || host === "[::1]" || /^127\./.test(host));
}

/** Adresse web (http/https) de la page, sinon null (pages internes du navigateur, fichiers…). */
export function webPage(pageUrl) {
  const page = parsePageUrl(pageUrl);
  return page && WEB.has(page.protocol) && page.hostname ? page : null;
}
