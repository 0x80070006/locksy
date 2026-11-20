// Noms accessibles de l'interface, en un seul endroit (aucun data-testid).
//
// Les tests sélectionnent par rôle et nom accessible français : libellés
// contractuels de l'annexe C du cahier, tels que livrés par la vague 2
// (coquille L9, coffre L10). Les formes d'avant la refonte sont retirées.

const exact = (s: string) => new RegExp(`^${s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`);
const oneOf = (...xs: string[]) => new RegExp(`^(?:${xs.map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})$`);

export const L = {
  // Installation, inscription, récupération
  setupToken: "Jeton d'installation",
  email: "Adresse e-mail",
  displayName: oneOf("Nom affiché", "Votre nom"),
  masterPassword: exact("Mot de passe maître"),
  confirmMasterPassword: oneOf("Confirmez le mot de passe maître", "Confirmer le mot de passe maître"),
  createVault: exact("Créer mon coffre"),
  recoveryAck: /J'ai (?:mis cette clé en lieu sûr|conservé ma clé de récupération)/,
  continue: exact("Continuer"),

  // Connexion, verrouillage
  login: exact("Se connecter"),
  unlock: exact("Déverrouiller"),

  // Coquille
  mainNav: oneOf("Navigation", "Navigation principale"),
  mobileMenu: exact("Menu"),
  accountMenu: exact("Menu du compte"),
  logout: oneOf("Quitter", "Se déconnecter"),

  // Coffre : liste et éditeur (dans le panneau de la fiche, plus de fenêtre)
  itemList: { region: oneOf("Liste", "Liste des éléments"), list: exact("Éléments") },
  backToList: exact("Retour à la liste"),
  newItem: oneOf("Ajouter", "Ajouter un élément", "Nouveau"),
  /** Groupe radio du type d'élément, et sa carte « Mot de passe d'un site ». */
  itemTypeGroup: exact("Que voulez-vous enregistrer ?"),
  passwordType: exact("Mot de passe d'un site"),
  itemName: exact("Nom"),
  itemUsername: exact("Identifiant"),
  itemPassword: exact("Mot de passe"),
  save: exact("Enregistrer"),
  itemSaved: /Élément enregistré/,
} as const;
