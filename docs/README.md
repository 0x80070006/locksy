# Documentation de Locksy

<img src="../branding/locksy.svg" width="96" align="right" alt="Logo Locksy">

Gestionnaire de mots de passe d'entreprise, **chiffré de bout en bout** et **hébergé chez
vous** : serveur Rust, interface web, client Windows, extension Edge/Chrome, intégration
Active Directory sur site, SSO OpenID Connect et SCIM.

## Par où commencer

| Je veux… | Page |
|---|---|
| Installer le serveur (VM Linux ou Docker) | [Installation du serveur](Installation-du-serveur.md) |
| Brancher l'Active Directory, sans cloud | [Déploiement avec Active Directory](Deploiement-Active-Directory.md) |
| Comprendre le chiffrement | [Chiffrement et sécurité](Chiffrement-et-securite.md) |
| Découvrir les fonctionnalités | [Fonctionnalités](Fonctionnalites.md) |
| Administrer l'organisation | [Administration](Administration.md) |
| Équiper les postes | [Client Windows](Client-Windows.md) · [Extension navigateur](Extension-navigateur.md) |
| Utiliser Entra ID, Okta, ADFS, SCIM | [SSO et SCIM](SSO-et-SCIM.md) |
| Sauvegarder, mettre à jour | [Sauvegarde et mises à jour](Sauvegarde-et-mises-a-jour.md) |
| Intégrer Locksy à un autre outil | [API](API.md) |
| Compiler, contribuer | [Développement](Developpement.md) |
| Questions fréquentes | [FAQ](FAQ.md) |

## En bref

- **Rien en clair sur le serveur** : Argon2id, XChaCha20-Poly1305, X25519, HKDF ; même noyau
  Rust dans le navigateur (WebAssembly), le client Windows et le serveur.
- **Coffres partagés** avec rôles, renouvellement de clé au retrait d'un membre.
- **Active Directory** : synchronisation d'un groupe, connexion avec le compte Windows, coupure
  immédiate des comptes désactivés.
- **Administration sans accès aux secrets**, journal d'audit complet, envoi Syslog.
- Licence **MIT**.

## Architecture

```mermaid
flowchart LR
    subgraph Postes
      W["Navigateur<br/>(WebAssembly)"]
      D["Client Windows"]
      E["Extension"]
    end
    subgraph Serveur["Serveur Locksy (Linux)"]
      API["API HTTPS"] --> DB[("SQLite<br/>données chiffrées")]
    end
    AD["Active Directory<br/>(LDAPS)"]
    IDP["ADFS / Entra ID / Okta<br/>(facultatif)"]
    W & D & E -- "HTTPS : chiffrés uniquement" --> API
    API -- "lecture du groupe,<br/>vérification des comptes" --> AD
    API -. "OpenID Connect" .-> IDP
```
