# FAQ

**L'administrateur peut-il lire mes mots de passe ?**
Non. Il gère les comptes et les accès, mais n'a ni votre mot de passe maître ni les clés de vos
coffres. Il ne voit que des données chiffrées.

**J'ai oublié mon mot de passe maître.**
Utilisez votre **clé de récupération** (lien « Mot de passe maître oublié ? »). Sans elle,
personne ne peut rouvrir votre coffre personnel : c'est la contrepartie du chiffrement de bout
en bout. Les coffres partagés restent accessibles aux autres membres, qui peuvent vous y
réinviter une fois votre nouveau compte créé.

**J'ai perdu mon téléphone et mes codes de secours.**
Si vous avez encore des codes de secours, connectez-vous avec l'un d'eux (« Utiliser un code de
secours » sur l'écran du code), puis réactivez la double authentification sur votre nouveau
téléphone et générez de nouveaux codes (Paramètres > Mon compte). Sans aucun code, demandez à
votre administrateur de « Réinitialiser la double authentification » : vous vous reconnectez avec
votre mot de passe maître, puis vous la réactivez. Vos données ne sont pas touchées.

**Pourquoi ne puis-je pas changer un réglage de mes préférences ?**
Votre organisation l'a imposé (mention « Imposé par votre organisation »), ou l'a limité
(par exemple « Limité à 15 minutes par votre organisation » pour le verrouillage). C'est une décision de votre administrateur :
adressez-vous à lui. La liste des réglages est dans [Réglages](Reglages.md).

**L'extension est apparue toute seule dans mon navigateur.**
Votre service informatique l'a installée par GPO ou par Intune. Vous ne pouvez pas la retirer, et
certains de ses réglages peuvent être imposés (adresse du serveur, délai de verrouillage).
Ouvrez-la avec Ctrl+Maj+L et connectez-vous avec votre compte Locksy habituel. Côté
administrateur : [Extension navigateur](Extension-navigateur.md#déploiement-sur-les-postes).

**Le client Windows ne suit pas les réglages de l'organisation.**
C'est normal en version 1.1 : il applique seulement la politique locale du poste. Sa refonte, qui
lira les réglages de l'organisation et vos préférences, arrive en 1.2
([Client Windows](Client-Windows.md)).

**Pourquoi un mot de passe maître en plus de mon compte Windows ou du SSO ?**
L'annuaire et le fournisseur d'identité prouvent qui vous êtes, mais ils ne doivent pas pouvoir
déchiffrer vos secrets. Votre mot de passe maître, que l'entreprise ne connaît pas, est la clé
du chiffrement.

**Que se passe-t-il quand un collaborateur part ?**
Désactivez son compte dans l'AD (ou retirez-le du groupe Locksy) : à la synchronisation
suivante, **toutes ses sessions sont coupées**. Bouton « Synchroniser maintenant » pour agir
tout de suite. Sans annuaire, ou pour régler aussi ses coffres partagés, utilisez l'assistant
« Départ de l'entreprise » de sa fiche ([guide administrateur](Administration.md#départ-de-lentreprise)).

**Le serveur doit-il accéder à Internet ?**
Non. Avec l'installation hors ligne et le connecteur Active Directory, Locksy fonctionne dans un
réseau isolé.

**Où sont mes données ?**
Sur votre serveur, dans `/var/lib/locksy` (ou le volume Docker `locksy-data`), chiffrées.

**Pourquoi voit-on « verrou » dans les constantes de chiffrement ?**
C'est le nom de code d'origine du projet. Ces identifiants de protocole sont figés pour que les
coffres existants restent lisibles.

**Peut-on l'utiliser sur téléphone ?**
Oui, via l'interface web, adaptée aux petits écrans et installable comme une application. Il
n'y a pas encore d'application mobile native.

**Locksy a-t-il été audité ?**
Pas encore par un tiers. Le modèle est documenté dans [Chiffrement et sécurité](Chiffrement-et-securite.md) ;
les signalements de vulnérabilité sont bienvenus (voir `SECURITY.md`).
