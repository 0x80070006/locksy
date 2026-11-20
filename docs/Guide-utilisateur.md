# Guide utilisateur

Locksy garde vos mots de passe dans un **coffre chiffré sur votre appareil**. Personne d'autre
que vous, et les collègues avec qui vous partagez, ne peut les lire : ni l'administrateur, ni
le serveur. Ce guide suit l'interface web ; l'extension du navigateur reprend les mêmes mots.

Les noms entre guillemets sont ceux des boutons et des champs de l'écran. Les adresses
`#/…` s'ajoutent à l'adresse de votre serveur Locksy (par exemple
`https://locksy.entreprise.fr/#/coffre`).

## Premiers pas

### Créer votre compte

1. Ouvrez le lien d'invitation reçu par e-mail ou transmis par votre administrateur. Il ne vaut
   que pour votre adresse et expire au bout de quelques jours.
2. Saisissez « Votre nom », puis choisissez votre **mot de passe maître** et confirmez-le
   (« Confirmer le mot de passe maître »). C'est la seule clé de votre coffre : personne ne
   peut le retrouver pour vous.
3. Locksy affiche votre **clé de récupération**. Téléchargez-la ou notez-la, rangez-la hors de
   l'ordinateur, puis cochez « J'ai conservé ma clé de récupération » et cliquez sur « Créer mon
   coffre ».

Si votre organisation a publié une charte d'utilisation, elle vous est présentée à la connexion.

### Se connecter

Page `#/connexion` : « Adresse e-mail », « Mot de passe maître », puis « Se connecter ». Selon
votre organisation, la page propose aussi « Continuer avec … » (connexion d'entreprise :
Microsoft Entra, Google, Okta) ou la connexion avec votre compte Windows. Dans ces deux cas,
le mot de passe maître reste demandé : lui seul ouvre le coffre.

Si la double authentification est active, saisissez ensuite le « Code de vérification » à 6
chiffres de votre application d'authentification.

### Installer l'extension du navigateur

Dans la plupart des entreprises, l'extension est **installée d'office** par le service
informatique : l'icône Locksy apparaît dans la barre d'outils d'Edge ou de Chrome. Sinon,
demandez-la à votre administrateur ([Extension navigateur](Extension-navigateur.md)).

Ouvrez-la avec **Ctrl+Maj+L**. Indiquez l'adresse de votre serveur si elle n'est pas déjà
remplie, puis connectez-vous. Sur la page de connexion d'un site, « Remplir » saisit
l'identifiant et le mot de passe ; « Remplir et copier le code » copie en plus le code de
vérification du site. L'extension ne remplit **que sur le site enregistré** dans l'élément :
c'est une protection contre les faux sites.

### Verrouiller et se déconnecter

- **Verrouiller** (bouton « Verrouiller », ou **Ctrl+Alt+L**) ferme le coffre sans fermer la
  session : votre mot de passe maître suffit pour le rouvrir (« Déverrouiller »).
- Le coffre se verrouille aussi seul après un temps sans utilisation (réglable dans les
  Préférences, dans la limite fixée par votre organisation). Juste avant, un avertissement
  propose « Rester déverrouillé ».
- **Se déconnecter** (menu du compte) ferme la session sur cet appareil.

## Le coffre

`#/coffre` affiche tous vos éléments. La barre latérale donne « Tout », « Favoris », vos
coffres (« Coffre personnel » et les coffres partagés), « Bilan de sécurité » et « Corbeille ».
Sur un petit écran, elle s'ouvre par le bouton « Menu ».

- **Rechercher** : champ « Rechercher dans tout le coffre », ou **Ctrl+K** (ou **/**). La
  recherche porte toujours sur tout le coffre, accents et majuscules ignorés. Depuis un coffre,
  une pastille « Dans : … » limite la recherche ; retirez-la pour chercher partout.
- **Ouvrir un élément** : cliquez sur la ligne, ou utilisez les flèches puis Entrée. La fiche
  s'ouvre à côté de la liste.
- **Copier** : « Copier le mot de passe de … » sur la ligne, ou « Copier l'identifiant »,
  « Copier le mot de passe », « Copier le code de vérification » dans la fiche. Le
  presse-papiers est effacé après le délai choisi dans vos préférences.
- **Favoris** : « Ajouter aux favoris » dans la fiche. Vos favoris ne sont visibles que par vous.
- **Corbeille** : « Mettre à la corbeille » garde l'élément récupérable (« Annuler » tout de
  suite, ou « Restaurer » depuis la corbeille) jusqu'à sa suppression définitive, après le
  délai fixé par votre organisation.

### Ajouter un élément

1. Cliquez sur « Nouveau » (ou touche **N**).
2. Répondez à « Que voulez-vous enregistrer ? » : Mot de passe d'un site, Note secrète, Carte
   bancaire, Identité ou Clé SSH.
3. Remplissez « Nom », « Adresse du site », « Identifiant ». Un mot de passe solide est déjà
   proposé ; « Saisir mon mot de passe actuel » vous laisse taper celui que vous avez.
4. Pour un code de vérification de site, utilisez « Scanner le QR code » ou « Coller la clé ».
5. Choisissez le coffre (« Rangé dans »), puis « Enregistrer » (ou **Ctrl+Entrée**).

Si vous quittez la fiche sans enregistrer, Locksy demande « Quitter sans enregistrer ? » :
« Rester », « Abandonner » ou « Enregistrer ».

## Partager

Dans la fiche, « Partager » ouvre la fenêtre « Partager « … » » avec deux onglets.

**Avec des collègues.** Dans « Avec qui ? », tapez un nom ou une adresse, puis « Ajouter … ».
Choisissez ce qu'ils pourront faire (voir et copier, ou aussi modifier) et où ranger l'élément :
un coffre existant qui réunit déjà ces personnes, ou un nouveau coffre dont vous serez
gestionnaire. Cliquez sur « Partager ». L'élément quitte alors votre coffre personnel pour le
coffre partagé, avec ses pièces jointes. Si un collègue a changé de clé depuis votre dernier
partage, Locksy vous demande de vérifier son empreinte avec lui avant de continuer.

**Par lien sécurisé.** Pour transmettre un secret à quelqu'un qui n'a pas Locksy : choisissez
la durée (« Expire dans ») et le « Nombre d'ouvertures », décochez « Inclure le nom » si le nom
de l'élément ne doit pas partir, puis « Créer et copier le lien ». Le lien est chiffré : la clé
est dans le lien lui-même et le serveur ne la voit jamais. Envoyez-le par un canal différent de
celui du contexte (par exemple, le lien par messagerie et l'usage par téléphone).

Retrouvez vos liens dans le menu du compte > « Liens envoyés » (`#/liens`). « Révoquer » coupe
un lien immédiatement, même s'il lui reste des ouvertures.

## Générateur

Le bouton « Générer » de la barre du haut ouvre la fenêtre « Générer un mot de passe » :
choisissez le « Style » (« Aléatoire », ou « Facile à taper (mots) » pour une phrase de passe),
réglez la « Longueur » ou le « Nombre de mots », puis « Copier », « Un autre » ou « Utiliser »
(dans l'éditeur). Le mot de passe généré n'est gardé nulle part tant que vous ne
l'enregistrez pas dans un élément. Votre organisation peut fixer une longueur minimale.

## Bilan de sécurité

`#/bilan` donne un score sur 100 et liste les mots de passe faibles, réutilisés ou inchangés
depuis longtemps, ainsi que vos liens sécurisés encore actifs.
L'analyse se fait dans votre navigateur. « Corriger … » ouvre l'élément en modification avec un
nouveau mot de passe proposé : changez-le d'abord sur le site concerné, puis enregistrez.

## Paramètres

Menu du compte > « Paramètres » (`#/parametres/compte`) :

| Section | Contenu |
|---|---|
| Mon compte | votre nom, le mot de passe maître (« Changer le mot de passe »), la clé de récupération, la double authentification et ses codes de secours, l'empreinte de votre compte |
| Préférences | apparence (« Thème », « Contraste », « Taille du texte », « Densité »), « Verrouiller Locksy après », « Effacer le presse-papiers après », générateur, durée et nombre d'ouvertures par défaut des liens sécurisés, extension du navigateur, « Raccourcis à une touche » ; case « Synchroniser mes préférences sur mes appareils » ; « Rétablir les valeurs recommandées » |
| Appareils et sessions | sessions ouvertes, « Fermer » ou « Fermer les autres sessions » ; lien « Voir mon activité » (`#/parametres/activite`) |
| Importer ou exporter | imports et exports (voir plus bas) |

Vos préférences sont **chiffrées** avant d'être synchronisées : le serveur ne les lit pas.
Quand votre organisation impose une valeur, elle s'affiche avec sa limite et ne se modifie pas.

## Double authentification et codes de secours

**Activer.** Paramètres > Mon compte > « Activer la double authentification ». Scannez le QR code
avec votre application d'authentification (ou saisissez la clé affichée), puis saisissez le code
à 6 chiffres. Votre organisation peut l'exiger : vous avez alors un délai pour l'activer.

**Codes de secours.** À l'activation, Locksy affiche des codes de secours, une seule fois.
Chaque code remplace une fois le code de l'application. Téléchargez-les ou notez-les, rangez-les
hors de l'ordinateur (imprimés, ou dans un coffre-fort), puis cochez « J'ai conservé mes codes
de secours ». La section indique combien il vous en reste.

**Utiliser un code de secours.** À la connexion, sur l'écran du code, cliquez sur « Utiliser un
code de secours » et saisissez l'un de vos codes. Il ne servira plus. « Utiliser le code de
l'application » revient au code habituel.

**Régénérer.** S'il vous reste peu de codes, ou si vous pensez qu'ils ont été vus : Paramètres
> Mon compte > « Générer de nouveaux codes ». Les anciens codes cessent aussitôt de fonctionner.

Plus d'application et plus de codes ? Demandez à votre administrateur de réinitialiser votre
double authentification, puis réactivez-la.

## Importer vos mots de passe

Paramètres > « Importer ou exporter » (`#/parametres/donnees`), partie « Importer ». Le fichier
est lu et chiffré **dans votre navigateur** : son contenu en clair n'est jamais envoyé au
serveur.

| « Format du fichier » | Ce qu'il faut savoir |
|---|---|
| Fichier CSV (tableur ou autre gestionnaire) | séparateur virgule, point-virgule ou tabulation, **détecté automatiquement** ; colonnes reconnues par leur nom (nom, adresse, identifiant, mot de passe, notes…) |
| Sauvegarde chiffrée Locksy (.json) | fichier créé par « Exporter » dans Locksy, avec son mot de passe d'export |
| Base KeePass (.kdbx) | formats 3.1 et 4 ; mot de passe de la base et, s'il y en a un, son fichier clé |
| Export Bitwarden (.json) | export protégé par un mot de passe, ou non chiffré |

1. Choisissez le format et le fichier (« Fichier à importer »). La taille maximale est affichée
   sous le champ ; elle est fixée par votre organisation (20 Mio par défaut).
2. « Lire le fichier » montre l'« Aperçu avant import » et les lignes qui ne seront pas reprises,
   avec leur motif.
3. Choisissez le « Coffre de destination ». Si le fichier a des dossiers : « Ajouter les
   dossiers en étiquettes », ou « Un coffre par dossier ».
4. Cliquez sur « Importer … éléments ». Un import interrompu peut être repris.
5. **Supprimez ensuite le fichier d'origine** : il contient vos mots de passe en clair.

Les pièces jointes des fichiers importés ne sont pas reprises : Locksy signale les éléments
concernés.

## Exporter

Même page, partie « Exporter ». Choisissez les « Éléments à exporter » et le « Format » :

- **Sauvegarde chiffrée (.json)** : protégée par un « Mot de passe d'export », réimportable dans
  Locksy. C'est le format conseillé.
- **CSV non chiffré** : lisible par un tableur, mais les mots de passe y sont **en clair**.
  Locksy demande de confirmer (« Exporter en clair »). Supprimez le fichier après usage.

L'export demande votre mot de passe maître et n'emporte pas les pièces jointes. Votre
organisation peut le désactiver.

## Raccourcis clavier et aide

La page « Aide et raccourcis » (`#/aide`, touche **?**, ou menu du compte) liste les raccourcis
et les mots de Locksy. Les principaux :

| Raccourci | Action |
|---|---|
| Ctrl+K ou / | Rechercher dans tout le coffre |
| Ctrl+Alt+L | Verrouiller |
| N | Nouvel élément |
| Ctrl+Maj+C | Copier le mot de passe de l'élément ouvert |
| Ctrl+Maj+U | Copier l'identifiant de l'élément ouvert |
| Ctrl+Entrée ou Ctrl+S | Enregistrer |
| Échap | Fermer la fenêtre du dessus ou effacer la recherche |

Les raccourcis à une touche (/, N, ?) se désactivent dans les Préférences. La déclaration
d'accessibilité est à l'adresse `#/accessibilite`.

## En cas de problème

- **Mot de passe maître oublié** : lien « Mot de passe maître oublié ? » de la page de connexion,
  avec votre clé de récupération. Voir aussi la [FAQ](FAQ.md).
- **Une session que vous ne reconnaissez pas** : Paramètres > Appareils et sessions, « Fermer »
  la session, puis changez votre mot de passe maître.
- Pour le reste, adressez-vous à l'administrateur de Locksy de votre organisation.
