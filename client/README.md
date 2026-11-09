# NeonRelay — client autonome

Utiliser une boîte NeonRelay sans `git` ni compétence technique : **une clé**
(tapée par le Digispark) suffit, plus un PIN optionnel.

| Dossier / fichier | Rôle |
|---|---|
| `neonrelay.py` | Le client, **commun à Windows et Linux** : canal chiffré de bout en bout, en un seul fichier |
| `openssl-tls.cnf` | Config TLS commune : TLS 1.3 + échange de clés ML-KEM obligatoire |
| [`windows/`](windows/README.md) | Installation / désinstallation Windows (`install.cmd`) |
| [`linux/`](linux/README.md) | Installation / désinstallation Linux (`install.sh`, sans root) |

Les installeurs vont chercher `neonrelay.py` et `openssl-tls.cnf` dans ce
dossier : garder le dossier `client` complet.
