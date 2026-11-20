// Métriques propres au banc, partagées par les scénarios (mode d'emploi :
// bench/k6/README.md). Les métriques HTTP standard de k6 (http_req_duration,
// http_req_failed, http_reqs) portent en plus l'étiquette « name » (route
// générique, voir ROUTES dans common.js) : le rapport en tire son tableau par route.
import { Counter, Gauge, Rate, Trend } from "k6/metrics";

// Statuts comptés à part : un 429 ou un 503 n'est pas une panne, mais
// plusieurs seuils les exigent nuls (02a) ou en mesurent le taux (02b).
export const status429 = new Counter("statut_429");
export const status503 = new Counter("statut_503");
/** 5xx autres que 503 (et réponses absentes : connexion refusée, délai dépassé). */
export const status5xxOther = new Counter("statut_5xx_autres");

/** Connexion réussie (prelogin + login, avec réessai poli si le scénario le prévoit). */
export const loginOk = new Rate("connexion_reussie");
/** Durée d'une connexion de bout en bout, réessais compris (02b). */
export const loginTotal = new Trend("connexion_totale", true);

/** Taille du corps de /sync, en octets. */
export const syncBytes = new Trend("sync_octets");

/** Révision périmée refusée en 409 (05) : doit valoir 100 %. */
export const conflict409 = new Rate("conflit_409");
/** Réponses qui trahissent une base verrouillée (« database is locked », SQLITE_BUSY). */
export const dbLocked = new Counter("base_verrouillee");

/** Refus attendu d'une pièce jointe hors limites (nombre, taille). */
export const attachmentRefused = new Rate("piece_jointe_refusee");
/**
 * Délai de refus d'un corps au-delà de la limite de l'hébergeur (16 Mo),
 * mesuré par l'horloge du VU : le serveur peut fermer la connexion avant la
 * fin de l'envoi, et k6 ne fournit alors pas de durée fiable.
 */
export const bodyRefusal = new Trend("refus_corps_ms", true);

/** Attaquant refusé en 429 une fois le plafond par adresse dépassé (09). */
export const attackBlocked = new Rate("attaque_bloquee");

/** Écriture acquittée retrouvée après les arrêts brutaux (10). */
export const ackPresent = new Rate("ecriture_acquittee_presente");
export const acked = new Counter("ecritures_acquittees");

/** /sync porte une révision de politique à jour (11). */
export const policyFresh = new Rate("politique_a_jour");
/** /sync sans policy_revision : propagation mesurée par /settings/policy seulement. */
export const policyNotInSync = new Counter("politique_hors_sync");
/** Réglages enregistrés par l'administrateur (11). */
export const settingsWrites = new Counter("reglages_enregistres");
/** Écart entre les chargements SQL des réglages et les révisions écrites (11). */
export const settingsExtraLoads = new Gauge("reglages_chargements_excedentaires");
/** Lectures de l'ancien stockage des réglages pendant la passe (11). */
export const settingsLegacyReads = new Gauge("reglages_lectures_historiques");
