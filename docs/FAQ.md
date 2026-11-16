# FAQ

**L'administrateur peut-il lire mes mots de passe ?**
Non. Il gère les comptes et les accès, mais n'a ni votre mot de passe maître ni les clés de vos
coffres. Il ne voit que des données chiffrées.

**J'ai oublié mon mot de passe maître.**
Utilisez votre **clé de récupération** (lien « Mot de passe maître oublié ? »). Sans elle,
personne ne peut rouvrir votre coffre personnel : c'est la contrepartie du chiffrement de bout
en bout. Les coffres partagés restent accessibles aux autres membres, qui peuvent vous y
réinviter une fois votre nouveau compte créé.

**Pourquoi un mot de passe maître en plus de mon compte Windows ou du SSO ?**
L'annuaire et le fournisseur d'identité prouvent qui vous êtes, mais ils ne doivent pas pouvoir
déchiffrer vos secrets. Votre mot de passe maître, que l'entreprise ne connaît pas, est la clé
du chiffrement.

**Que se passe-t-il quand un collaborateur part ?**
Désactivez son compte dans l'AD (ou retirez-le du groupe Locksy) : à la synchronisation
suivante, **toutes ses sessions sont coupées**. Bouton « Synchroniser maintenant » pour agir
tout de suite. Pour ses coffres partagés, retirez-le : la clé du coffre est renouvelée.

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
