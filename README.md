<p align="center">
  <img src="branding/locksy.svg" width="112" alt="Logo Locksy">
</p>

<h1 align="center">Locksy</h1>

<p align="center">
  Gestionnaire de mots de passe d'entreprise, chiffré de bout en bout, à héberger chez vous.<br>
  Serveur Rust · interface web · client Windows · extension Edge/Chrome · Active Directory sur site.
</p>

---

**Le serveur ne voit jamais un mot de passe en clair.** Tout est chiffré et déchiffré sur le poste
de l'utilisateur (navigateur, client Windows ou extension), avec le même noyau cryptographique
écrit en Rust. Une fuite complète de la base ne livre que des données chiffrées.

## Points forts

- **Chiffrement** : Argon2id (64 Mio), XChaCha20-Poly1305, X25519, HKDF-SHA256 ; chaque donnée
  chiffrée est liée à sa place (le serveur ne peut ni la déplacer ni l'échanger).
- **Coffres partagés** avec rôles (gestionnaire, éditeur, lecteur) ; retirer quelqu'un renouvelle
  la clé du coffre et rechiffre tout son contenu.
- **Active Directory sur site** (LDAPS) : synchronisation d'un groupe, connexion avec le compte
  Windows, **coupure immédiate** d'un compte désactivé dans l'AD. Aucun service cloud requis.
- **SSO OpenID Connect** (ADFS, Entra ID, Okta, Keycloak…) et **provisionnement SCIM 2.0**.
- Identifiants, notes, cartes, identités, clés SSH, **codes 2FA intégrés**, **pièces jointes
  chiffrées**, historique des mots de passe, corbeille, générateur, santé des mots de passe.
- **Liens de partage externes** à usage limité, chiffrés de bout en bout.
- **Administration** sans accès aux secrets : comptes, invitations, double authentification
  imposable, journal d'audit complet (export CSV, envoi Syslog vers votre SIEM).
- **Client Windows** natif et **extension** de navigateur avec remplissage des formulaires.

## Installation du serveur

Sur une VM Linux (Debian, Ubuntu, RHEL…), en une commande :

```bash
curl -fsSL https://github.com/0x80070006/locksy/releases/latest/download/install.sh | sudo bash
```

Le script propose deux modes : **service systemd** (sans Docker) ou **conteneur Docker**. Il
installe un certificat temporaire ou le vôtre (`--cert`, `--key`), démarre Locksy en HTTPS et
vérifie qu'il répond. Pour un réseau isolé, copiez `install.sh` et
`locksy-server-linux-x86_64.tar.gz` depuis la [dernière version](../../releases/latest) :

```bash
sudo bash install.sh --archive locksy-server-linux-x86_64.tar.gz --domain locksy.corp.local \
  --cert locksy.crt --key locksy.key
```

Ouvrez ensuite `https://locksy.corp.local` : **le premier compte créé devient propriétaire.**

Pour essayer sur un poste avec Docker Desktop : `docker compose up -d --build`, puis
<http://localhost:8743>.

## Postes de travail

| Composant | Fichier de la version | Installation |
|---|---|---|
| Client Windows | `locksy-windows-x64.exe` + `install-client.ps1` | `powershell -ExecutionPolicy Bypass -File install-client.ps1 -Server https://locksy.corp.local`, ou par GPO |
| Extension Edge / Chrome | `locksy-extension.zip` | mode développeur > « Charger l'extension non empaquetée », ou installation forcée par GPO |
| Interface web | — | tout navigateur récent ; installable comme application |

## Documentation

Tout est dans le **[wiki](../../wiki)** :

- [Installation du serveur](../../wiki/Installation-du-serveur) · [Déploiement sur site avec Active Directory](../../wiki/Deploiement-Active-Directory)
- [Chiffrement et modèle de sécurité](../../wiki/Chiffrement-et-securite)
- [Fonctionnalités](../../wiki/Fonctionnalites) · [Administration](../../wiki/Administration) · [Client Windows](../../wiki/Client-Windows) · [Extension](../../wiki/Extension-navigateur)
- [SSO et SCIM](../../wiki/SSO-et-SCIM) · [Sauvegarde et mises à jour](../../wiki/Sauvegarde-et-mises-a-jour) · [API](../../wiki/API) · [Développement](../../wiki/Developpement) · [FAQ](../../wiki/FAQ)

## Construire depuis les sources

```bash
docker build -f Dockerfile.release --target export --output type=local,dest=dist/release .
```

Produit le serveur Linux autonome, le module WebAssembly et le client Windows ; les tests
s'exécutent pendant la construction. Détails : [Développement](../../wiki/Developpement).

## Sécurité

Modèle cryptographique détaillé : [SECURITE.md](SECURITE.md) et le wiki. Pour signaler une
vulnérabilité, voir [SECURITY.md](SECURITY.md). Locksy n'a pas encore fait l'objet d'un audit
externe.

## Licence

[MIT](LICENSE)
