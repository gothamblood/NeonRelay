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

## Commandes de la console / Console commands

Une ligne qui commence par `$/` est une commande, jamais envoyée. `$$/…` envoie
un message qui commence vraiment par `$/`.

| Commande | Effet |
|---|---|
| `$/options` | Liste des commandes et état (correspondants en ligne, messages en attente) |
| `$/stash <message>` | Garde le message **dans le client** (RAM, 10 au plus) ; il part dès qu'un correspondant arrive. Perdu si le client se ferme |
| `$/stash` · `$/stash clear` | Voir · effacer les messages en attente dans le client |
| `$/stashserver <message>` | Laisse le message **sur le serveur**, chiffré de bout en bout, pour la prochaine session qui se connecte (y compris une relance de son propre client). Un seul par boîte, le dernier remplace le précédent ; 2,9 Ko au plus ; détruit après lecture ; en RAM seulement |
| `$/stashserver cancel` | Retire le message laissé sur le serveur, s'il n'a pas encore été lu |
| `$/selfdestruct <durée>` | La boîte sera **détruite** dans `30m`, `2h`, `3d`, `1d12h`… (heure du **serveur**, qui le fait même si plus personne n'est connecté). On peut seulement **avancer** l'échéance, jamais la reculer : une clé saisie ne prolonge pas la boîte. Sans durée : temps restant |
| `$/deadman <durée> <mot de passe>` | **Homme mort** : la boîte est détruite si personne ne remet le compteur à zéro avant l'échéance. La 1re fois, arme l'homme mort avec ce mot de passe (8 caractères au moins, haché sur le serveur, distinct de la clé) ; ensuite, la même commande avec le même mot de passe **remet le compteur à zéro** (« ✅ compteur remis à zéro »). La ligne tapée est effacée de l'écran ; sans mot de passe sur la ligne, il est demandé masqué |
| `$/deadman -c <mot de passe>` · `$/deadman` | Annuler l'homme mort (mot de passe requis) · voir le temps restant. Mot de passe faux : 5 essais, puis 1 par minute |
| `$/online` | Nombre de correspondants en ligne |
| `$/clear` | Vide l'écran et l'historique de défilement |
| `$/fingerprint` | Empreinte de la clé (PIN compris), à comparer à voix haute : même empreinte = même clé |
| `$/exit` | Ferme le canal (après l'envoi des messages déjà partis, 5 s au plus) et la console. Si des messages `$/stash` attendent, il faut le taper deux fois |
| `$/abort` · `$/abort!` | Urgence, sur ce poste seulement : efface l'écran et l'historique, abandonne les messages en attente, oublie les clés, ferme le client et la console. La boîte reste intacte. Confirmation par Entrée ; `!` = sans confirmation |
| `$/zeroize` · `$/zeroize!` | `$/abort` **+ suppression de la boîte** sur le serveur : tous les correspondants sont coupés, le message laissé sur le serveur est détruit, et aucune clé de cette boîte ne servira plus. **Définitif** : il faut de nouvelles clés pour tout le monde. Confirmation en tapant `ZEROIZE` ; `!` = sans confirmation. Si le serveur ne répond pas, le client le dit et laisse la console ouverte |

Ce que le serveur apprend avec `$/stashserver` : qu'un message attend dans la
boîte, jamais son contenu. Sur le réseau, rien ne le distingue du trafic normal
(chaque trame montante porte un octet de contrôle, taille constante).
`$/abort` et `$/zeroize` : Python ne garantit pas l'effacement réel de la mémoire ; le client
lâche les clés et se termine aussitôt. Fermer la console : Windows, la fenêtre ;
Linux, le shell du terminal (l'onglet ouvert par Ctrl+Alt+T se ferme).
