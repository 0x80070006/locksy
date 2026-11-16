# Modèle de sécurité de Locksy

## Principe

Chiffrement **côté client** (« zero-knowledge ») : le serveur stocke des chiffrés opaques, des
empreintes Argon2id et des métadonnées (dates, rôles, appartenances). Une fuite complète de la
base ne révèle aucun secret sans les mots de passe maîtres.

Le même noyau Rust (`crates/locksy-core`) est utilisé par le serveur, par le client Windows et
par l'interface web (compilé en WebAssembly). Les primitives viennent des bibliothèques
RustCrypto et dalek, sans code `unsafe` dans le noyau.

## Primitives

| Usage | Algorithme |
|---|---|
| Mot de passe maître → clé | Argon2id, 64 Mio, 3 passes (paramètres stockés par compte, bornes min. imposées), normalisation Unicode NFC |
| Séparation des clés | HKDF-SHA256 : clé d'authentification ≠ clé de chiffrement |
| Chiffrement | XChaCha20-Poly1305, nonce aléatoire 192 bits, données associées obligatoires |
| Partage | X25519 éphémère + HKDF-SHA256 + XChaCha20-Poly1305 (ECIES), contexte lié au coffre et au destinataire |
| Vérification serveur | Argon2id sur la preuve d'authentification (déjà dérivée côté client) |
| 2FA | TOTP RFC 6238, fenêtre ±30 s, rejeu interdit |
| Jetons | 256 bits aléatoires, stockés hachés (SHA-256) |

## Hiérarchie des clés

```
mot de passe maître ──Argon2id──► clé maître ──HKDF──┬─► preuve d'authentification → serveur
                                                     └─► clé de chiffrement
clé de chiffrement ──protège──► clé utilisateur (aléatoire, 256 bits)
clé de récupération ──protège──► clé utilisateur (copie de secours)
clé utilisateur ──protège──► clé privée X25519
clé privée X25519 ──ouvre──► clé de chaque coffre (scellée pour chaque membre)
clé de coffre ──chiffre──► éléments et nom du coffre
```

Chaque chiffré est lié à sa place par ses données associées (`verrou:v1:item:<coffre>:<élément>`…) :
le serveur ne peut ni déplacer, ni échanger, ni rejouer un élément ailleurs sans que le
déchiffrement échoue. Au déverrouillage, le client vérifie que la clé publique annoncée par
le serveur correspond à sa clé privée.

## Protections du serveur

- Blocage progressif après 5 échecs par compte et 20 par adresse IP (30 s puis doublement,
  jusqu'à 1 h) ; plafonds de requêtes sur les routes publiques.
- Comptes inexistants indiscernables : sel factice stable, même temps de réponse.
- Sessions : expiration après inactivité et durée maximale ; un compte désactivé est coupé
  immédiatement.
- En-têtes : CSP stricte (aucun script en ligne, WebAssembly autorisé), `frame-ancestors 'none'`,
  `no-referrer`, `nosniff`, `no-store` sur l'API.
- Concurrence : chaque modification indique la révision lue ; une version périmée est refusée.
- SQLite en `secure_delete`, conteneur non-root, système de fichiers en lecture seule, aucune
  capacité Linux, port lié à `127.0.0.1`.

## Connexion unique et provisionnement

- Le SSO (OpenID Connect) authentifie la personne auprès du serveur ; il ne donne **aucun**
  accès aux données. Le mot de passe maître reste nécessaire pour dériver la clé qui déchiffre
  le coffre. Un fournisseur d'identité compromis permet d'ouvrir une session, pas de lire un
  coffre.
- Contrôles du jeton d'identité : signature (clés JWKS du fournisseur, RSA/RSA-PSS/ECDSA
  uniquement), émetteur, audience, expiration, `nonce` ; flux protégé par PKCE et `state`.
- Le ticket SSO est à usage unique, valable 5 minutes, lié à une adresse et à un compte.
  Redirections de retour limitées à l'adresse publique de Locksy, à `127.0.0.1` (client de
  bureau, RFC 8252) et aux adresses `*.chromiumapp.org` réservées aux extensions.
- SCIM : jeton porteur de 256 bits, stocké haché, comparaison en temps constant, blocage
  après 10 échecs. La désactivation supprime toutes les sessions du compte.
- Accès de secours : quand le SSO est imposé, seuls les propriétaires peuvent encore se
  connecter par mot de passe maître (avec leur double authentification).

## Active Directory

- Transport toujours chiffré (LDAPS ou STARTTLS), certificat du contrôleur vérifié avec
  l'autorité fournie (nom DNS obligatoire dans le certificat) ; LDAP en clair refusé.
- Mot de passe du compte de service chiffré au repos (clé du serveur), jamais réaffiché.
- Connexion Windows : mot de passe vide refusé (une liaison LDAP sans mot de passe
  « réussirait » de façon anonyme), valeurs échappées dans les filtres (RFC 4515), recherche
  limitée aux membres du groupe et aux comptes actifs, un seul résultat exigé, puis liaison au
  nom de la personne. Le mot de passe Windows n'est jamais stocké et est effacé de la mémoire.
- Blocage après 5 échecs par identifiant et 20 par adresse IP, avant le verrouillage AD.
- Synchronisation : aucune désactivation si l'annuaire ne renvoie aucun compte.

## Limites connues

- Le serveur peut **refuser, supprimer ou restaurer une ancienne version** des données : le
  chiffrement en garantit la confidentialité et l'intégrité, pas la disponibilité.
- L'interface web est servie par le serveur : un serveur compromis pourrait servir un code
  JavaScript modifié. Le client Windows n'a pas cette faiblesse.
- Les droits « lecteur » sont imposés par le serveur ; un lecteur possède la clé du coffre et
  peut donc lire tout son contenu (comme dans tout gestionnaire chiffré de bout en bout).
- Le transport doit être protégé par HTTPS dès que le serveur est joignable depuis le réseau.
- Pas d'audit externe à ce jour.
