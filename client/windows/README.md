# NeonRelay — client autonome : Windows

Ce dossier contient tout ce qu'il faut pour utiliser une boîte NeonRelay sans
`git`, sans arborescence à respecter et sans compétence technique : **une clé**
(tapée par le Digispark) suffit.

| Fichier | Rôle |
|---|---|
| `windows/install.cmd` / `install.ps1` | Installation, une seule fois, sans droits administrateur |
| `windows/uninstall.cmd` / `uninstall.ps1` | Désinstallation complète |
| `neonrelay.py` *(commun Windows/Linux)* | Le client : canal chiffré de bout en bout, en un seul fichier |
| `openssl-tls.cnf` *(commun)* | TLS 1.3 + échange de clés ML-KEM obligatoire |

## Utilisateur

1. Récupérer le dossier `client` (archive ZIP), double-cliquer sur
   **`windows\install.cmd`**.
2. Brancher le Digispark : il ouvre `Win+R`, lance `neonrelay` et tape la clé
   dans l'invite masquée « Clé : ».
3. Invite « PIN » (optionnelle) : taper le PIN de 12 caractères puis Entrée.
   `Entrée` seule, ou 7 secondes sans toucher le clavier (délai remis à zéro à
   chaque touche) = canal ouvert **sans PIN**.
4. Taper un message puis Entrée pour l'envoyer ; `Ctrl+C` pour quitter.

Sans Digispark : `Win+R` → `neonrelay` → coller la clé.

`install.ps1` télécharge environ 14 Mo, chaque fichier vérifié par son
empreinte SHA-256 (fixée dans le script) :

- le **Python officiel** de python.org (version « embeddable » 3.15.2, avec
  OpenSSL 3.5.9 : ML-DSA-87 + ML-KEM), dont la signature Authenticode
  (Python Software Foundation) est aussi vérifiée ;
- **PyNaCl** et **cffi** depuis PyPI. `pycparser` n'est pas installé :
  inutile, PyNaCl étant livré précompilé.

Les téléchargements se font en TLS 1.2 minimum (1.3 si Windows le permet).

Tout va dans `%LOCALAPPDATA%\NeonRelay` ; rien dans le système ni le registre.

## Opérateur : fabriquer une clé

Depuis Linux (Python avec OpenSSL ≥ 3.5 et PyNaCl) :

```bash
python3 neonrelay.py make-key --base https://179.197.84.173:8000 \
  --cert /chemin/cert.pem --creds /chemin/last-token.env \
  --clavier ca-fr --ino cle
```

- Demande la passphrase E2E (vide = aléatoire, recommandé).
- Vérifie contre le vrai serveur le certificat et les identifiants.
- Affiche la clé (une ligne `NR…`, ≈ 280 caractères) et écrit deux firmwares
  Digispark (droits `600`) : `cle-windows.ino` (`Win+R`) et `cle-linux.ino`
  (`Ctrl+Alt+T`, voir `linux/README.md`). Flasher celui du système du poste,
  **puis supprimer les deux**.
- **La même clé va dans les Digispark des deux correspondants.**

`python3 neonrelay.py check-key` décode une clé et affiche sa partie publique
(serveur, boîte, empreinte) pour contrôle.

### PIN (optionnel)

`python3 neonrelay.py make-pin` tire un PIN de 12 caractères (`XXXX-XXXX-XXXX`)
à imprimer pour le colis PIN. **Même PIN pour tout le canal**, envoyé dans un
colis séparé de la clé. Ne pas le conserver (ni fichier, ni historique).

### Disposition du clavier (`--clavier`)

Le Digispark envoie des **positions de touches**, pas des caractères : c'est la
disposition réglée dans Windows qui décide de ce qui est tapé. La clé est la
même pour tous ; seul le firmware change. `python3 neonrelay.py claviers`
affiche la liste :

| Option | Disposition Windows |
|---|---|
| `us` *(défaut)* | Anglais (États-Unis) |
| `ca-fr` | Français (Canada) — CSA |
| `ca-multi` | Multilingue canadien standard |
| `uk` | Anglais (Royaume-Uni) |
| `fr-azerty` | Français (France) — AZERTY |
| `be-azerty` | Français/néerlandais (Belgique) — AZERTY |
| `ch-qwertz` | Suisse (français/allemand) — QWERTZ |
| `de-qwertz` | Allemand — QWERTZ |

Trouver la disposition du poste : Paramètres → Heure et langue → Langue et
région, ou `Get-WinUserLanguageList` dans PowerShell. Le Verrouillage
majuscules n'a pas d'effet (la clé ignore la casse).

`--delai-python MS` (défaut 4000) : attente entre le lancement et la frappe de
la clé, à augmenter sur un poste lent.

## Sécurité

- La clé contient **tout** (serveur, boîte, mot de passe, empreinte du
  certificat, passphrase E2E) : la voler, c'est tout avoir. Risque accepté.
- Le certificat du serveur est **épinglé par empreinte** : s'il ne correspond
  pas, la connexion est coupée avant d'envoyer quoi que ce soit.
- Une faute de frappe est détectée (somme de contrôle) avant toute connexion.
- **PIN optionnel = seconde couche E2E.** La même clé marche avec ou sans
  PIN. Avec PIN, la clé de chiffrement vient d'**Argon2id** (passphrase + PIN,
  sel propre à la boîte, ~1 s et 256 Mio par essai) : sans le PIN, la boîte
  s'ouvre mais les messages protégés restent illisibles, et un message envoyé
  sans le PIN s'affiche « illisible — intrus possible » chez ceux qui l'ont.
  PIN = 12 caractères base32 Crockford (60 bits) ; à la saisie, la casse et les
  tirets sont ignorés, `O` vaut `0`, `I` et `L` valent `1`. Rien dans la clé ne
  permet de vérifier un PIN hors ligne.
- Sans PIN, chiffrement identique à `scripts/base/_crypto.py` : compatible
  avec `secure-shell.sh` sur la même boîte. Les scripts bash ne gèrent pas
  encore le PIN.
