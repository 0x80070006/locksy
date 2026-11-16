# Fonctionnalités

## Coffre

| Fonction | Détail |
|---|---|
| Types d'éléments | identifiant, note sécurisée, carte bancaire, identité, clé SSH |
| Identifiants | plusieurs sites, champs personnalisés (masqués ou non), étiquettes, favoris |
| Codes 2FA | clé TOTP (secret ou lien `otpauth://`), code affiché avec compte à rebours |
| Historique | 20 derniers mots de passe de chaque élément |
| Renouvellement | date « à renouveler avant », signalée dans la fiche et la page Santé |
| Pièces jointes | 10 Mo par fichier, 20 par élément, chiffrées avec une clé propre |
| Corbeille | restauration, purge automatique (30 jours par défaut) |
| Recherche | instantanée sur le nom, l'identifiant, les sites, les étiquettes, les notes |
| Tri et filtres | A → Z ou récents ; par type, coffre, favoris |
| Création rapide | « Créer « … » » depuis une recherche sans résultat ; duplication d'un élément |

## Générateur

Mots de passe jusqu'à 128 caractères (minuscules, majuscules, chiffres, symboles, sans
caractères ambigus) ou **phrases de passe** de mots prononçables. Tirage uniforme sans biais sur
l'aléa du système, entropie affichée.

## Santé des mots de passe

Calculée **sur le poste** (le serveur n'en sait rien) : mots de passe faibles, réutilisés,
inchangés depuis plus d'un an, date de renouvellement dépassée, sites sans 2FA enregistrée.
Score global.

## Partage

- **Coffres partagés** : rôles gestionnaire (membres et contenu), éditeur (contenu), lecteur
  (consultation et copie).
- **Empreinte de clé** affichée pour vérifier un destinataire.
- **Retirer un membre renouvelle la clé** et rechiffre tout le coffre.
- **Liens de partage externes** : contenu choisi, durée (1 heure à 30 jours), nombre de
  consultations (1 à 10), autodestruction ; clé dans le `#` du lien.

## Compte

- Double authentification TOTP (QR code), imposable par l'organisation.
- Clé de récupération, régénérable.
- Changement de mot de passe maître instantané (déconnecte les autres appareils).
- Appareils connectés, déconnexion à distance.
- Historique personnel des 200 dernières actions.
- Import CSV (Bitwarden, LastPass, 1Password, KeePass/KeePassXC, Dashlane, Chrome, Edge,
  Firefox) ; sauvegarde chiffrée par mot de passe ; export CSV en clair sur confirmation.

## Confort

- **Copie en un clic** depuis la liste (identifiant, mot de passe, code 2FA).
- **Raccourcis clavier** : `/` rechercher, `↑ ↓` parcourir, `u` `p` `c` copier, `e` modifier,
  `n` nouveau, `?` aide.
- Parcours **« Bien démarrer »** pour les nouveaux comptes.
- Verrouillage automatique (1 minute à 1 heure, ou au passage en arrière-plan), effacement du
  presse-papiers.
- Thème clair ou sombre selon le système ; interface adaptée aux téléphones ; **installable
  comme une application**.

## Connexion

| Mode | Remarques |
|---|---|
| Adresse + mot de passe maître (+ TOTP) | toujours disponible pour les propriétaires |
| Compte Windows (Active Directory) | identifiant et mot de passe AD, puis mot de passe maître |
| SSO OpenID Connect | ADFS, Entra ID, Okta, Google, Keycloak…, puis mot de passe maître |

Voir aussi : [Administration](Administration.md), [Client Windows](Client-Windows.md),
[Extension navigateur](Extension-navigateur.md).
