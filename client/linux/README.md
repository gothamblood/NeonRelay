# NeonRelay — client autonome : Linux

| Fichier | Rôle |
|---|---|
| `linux/install.sh` | Installation, une seule fois, **sans root** |
| `linux/uninstall.sh` | Désinstallation complète |
| `neonrelay.py` *(commun Windows/Linux)* | Le client : canal chiffré de bout en bout, en un seul fichier |
| `openssl-tls.cnf` *(commun)* | TLS 1.3 + échange de clés ML-KEM obligatoire |

## Utilisateur

1. Récupérer le dossier `client` complet, puis dans un terminal :

   ```bash
   bash client/linux/install.sh
   ```

2. Lancer `neonrelay` (ou `~/.local/bin/neonrelay` si la commande n'est pas
   trouvée) et coller la clé dans l'invite masquée « Clé : ».
3. Invite « PIN » (optionnelle) : taper le PIN puis Entrée. `Entrée` seule, ou
   7 secondes sans toucher le clavier = canal ouvert **sans PIN**.
4. Taper un message puis Entrée pour l'envoyer ; `Ctrl+C` pour quitter.

Désinstaller : `bash client/linux/uninstall.sh`.

## Ce que fait `install.sh`

Environ 85 Mo téléchargés (x86_64), chaque fichier vérifié par son empreinte
SHA-256 fixée dans le script ; une empreinte différente = installation annulée :

- **Python 3.15.2 autonome** ([python-build-standalone](https://github.com/astral-sh/python-build-standalone),
  release `20261026`) avec son **propre OpenSSL 3.5** (ML-DSA-87 + ML-KEM) :
  le client ne dépend pas de l'OpenSSL de la distribution (Ubuntu 24.04 et
  Debian 12 sont encore en 3.0, sans ML-KEM). python.org ne publie pas de
  Python binaire pour Linux, d'où ce choix ;
- **PyNaCl** et **cffi** (roues `manylinux2014` de PyPI). `pycparser` n'est
  pas installé : inutile, PyNaCl étant livré précompilé.

Tout va dans `~/.local/share/NeonRelay` (`$XDG_DATA_HOME` respecté) et la
commande dans `~/.local/bin/neonrelay`. Aucun fichier du système ni de
configuration du shell (`.bashrc`, `.profile`) n'est modifié.

Le lanceur exécute Python en mode isolé (`-I` : `PYTHONPATH`, dossier courant
et site utilisateur ignorés). Une mise à jour se prépare à côté puis se met en
place d'un seul `mv` : une installation interrompue ou refusée laisse
l'ancienne intacte.

**Pris en charge :** Linux glibc (Debian, Ubuntu, Fedora, Arch, Kali…), x86_64
ou aarch64. Outils requis : `bash`, `curl` ou `wget`, `tar`, `sha256sum`.
Non pris en charge : Alpine et autres distributions musl.

## Digispark sous Linux

`make-key --ino cle` écrit deux firmwares : flasher **`cle-linux.ino`** sur le
Digispark d'un poste Linux. Séquence : `Ctrl+Alt+T` (ouvre un terminal) →
`neonrelay` → Entrée → attente → clé → Entrée.

- `Ctrl+Alt+T` doit ouvrir un terminal : c'est le cas sous GNOME/Ubuntu et Kali
  (XFCE) ; ailleurs, l'associer au terminal dans les raccourcis du bureau.
- `~/.local/bin` doit être dans le `PATH` (Debian, Ubuntu, Kali : automatique
  après une nouvelle ouverture de session, via `~/.profile`).
- `--clavier` : la disposition réglée sous Linux (mêmes valeurs que Windows).
- Délais à ajuster au besoin : 1,5 s pour l'ouverture du terminal,
  `--delai-python` (défaut 4000 ms) pour le démarrage du client.
