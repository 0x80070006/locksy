# Politique de sécurité

Ce document explique **comment signaler une vulnérabilité** et **comment vérifier une version**.
Le modèle de sécurité de Locksy, ses protections et ses limites connues sont décrits dans
[SECURITE.md](SECURITE.md) et, en détail, dans
[docs/Chiffrement-et-securite.md](docs/Chiffrement-et-securite.md).

## Signaler une vulnérabilité

Merci de **ne pas** ouvrir de ticket public, ni de discussion, ni de demande de fusion qui
décrive la faille.

- **Canal principal** : le signalement privé de GitHub, onglet **Security** du dépôt >
  **Report a vulnerability**.
- **Adresse de repli** : `securite@<votre-domaine>` (à remplacer par l'adresse réelle de
  l'équipe avant publication), si le signalement privé de GitHub vous est impossible.

### Ce qu'il faut fournir

- La version concernée (`locksy-server version`, version de l'extension ou du client
  Windows) et le mode d'installation (natif, Docker, derrière un proxy).
- Le composant : serveur, noyau cryptographique, interface web, extension, client Windows,
  scripts d'installation, chaîne de publication.
- Les étapes pour reproduire, avec une preuve de concept minimale si possible.
- L'impact estimé : ce qu'un attaquant obtient, et sous quelles conditions (compte requis,
  position réseau, serveur compromis…).
- Si vous le souhaitez, le nom ou le pseudonyme à citer dans l'avis de sécurité.

N'envoyez ni données personnelles réelles, ni secrets de production. Testez sur votre propre
instance, jamais sur celle d'un tiers.

### Délais

| Étape | Délai visé |
|---|---|
| Accusé de réception | 3 jours ouvrés |
| Première évaluation (recevabilité, gravité) | 10 jours |
| Correctif d'une faille critique ou haute | 30 jours |
| Divulgation coordonnée | 90 jours après le signalement, ou à la publication du correctif si elle est plus tôt |

Nous vous tenons informé de l'avancement, et nous convenons avec vous de la date de
publication de l'avis. Les correctifs sont annoncés dans le [CHANGELOG](CHANGELOG.md), à la
rubrique « Sécurité ».

## Versions maintenues

Seule la **dernière version mineure** publiée reçoit des correctifs de sécurité (par exemple,
toutes les versions 1.1.x tant que 1.2.0 n'est pas publiée). Mettez à jour avant de signaler
un problème qui pourrait déjà être corrigé.

## Vérifier une version

Chaque version publie un fichier `SHA256SUMS` qui couvre tous les fichiers distribués
(archive du serveur, client Windows, extension, scripts d'installation, SBOM). Il est signé
sans clé par cosign (`SHA256SUMS.sigstore.json`), et par minisign si l'éditeur a configuré une
clé (`SHA256SUMS.minisig`). Chaque fichier porte aussi une attestation de provenance GitHub.

```bash
# 1. Signature cosign de SHA256SUMS : seul le workflow release.yml du dépôt, lancé sur un tag v*,
#    peut l'avoir produite.
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/0x80070006/locksy/\.github/workflows/release\.yml@refs/tags/v' \
  SHA256SUMS

# 1 bis. Signature minisign, si elle est publiée (clé publique de l'éditeur)
minisign -Vm SHA256SUMS -P "<clé publique minisign>"

# 2. Empreintes des fichiers téléchargés
sha256sum --ignore-missing -c SHA256SUMS

# 3. Provenance (construit par le workflow du dépôt, à partir de quel commit)
gh attestation verify locksy-server-linux-x86_64.tar.gz --repo 0x80070006/locksy
```

Pour un dépôt dérivé (fork), remplacez `0x80070006/locksy` par son propriétaire et son nom.
`install.sh` fait ces vérifications lui-même (voir
[Installation du serveur](docs/Installation-du-serveur.md)).

## Périmètre

Les limites documentées dans [SECURITE.md](SECURITE.md#limites-connues) (par exemple, un
serveur compromis peut servir une interface web modifiée) ne sont pas des vulnérabilités en
soi. Toute idée pour les réduire est cependant bienvenue, par le même canal.
