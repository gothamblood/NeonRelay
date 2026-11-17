#!/usr/bin/env bash
# Canal chiffré de bout en bout par-dessus NeonRelay : ÉCOUTE (déchiffre) et
# ENVOIE (chiffre) dans la même session, sur la boîte courante (last-token.env).
#
# Canal bruité (/channel) : une trame de 512 octets toutes les 0,2 s dans chaque
# sens, que tu parles ou non ; chaque trame est chiffrée XSalsa20-Poly1305 puis
# AES-256-GCM. NeonRelay ne voit que des octets aléatoires de taille constante :
# il ne peut ni lire, ni altérer, ni savoir quand tu écris. Même moteur que le
# client autonome (base/_channel.py importe client/neonrelay.py) : ils se parlent. La clé de chiffrement vient de NEONRELAY_KEY (en RAM, JAMAIS écrite
# sur disque). Lance-le de préférence via nr_launch (base/_launch.sh) pour
# fournir la clé sans la laisser dans l'historique du shell :
#
#   NEONRELAY_KEY=... ./secure-shell.sh
#
#   # ou via nr_launch : c'est une FONCTION définie dans base/_launch.sh, il faut
#   # donc SOURCER ce fichier UNE FOIS d'abord, sinon « nr_launch: command not found ».
#   source base/_launch.sh                            # charge la fonction nr_launch
#    nr_launch ~/.../scripts/secure-shell.sh <clé>    # espace en tête = hors historique
#
# PIN optionnel (même calcul que client/neonrelay.py, les deux se lisent) :
# invite masquée au démarrage ; Entrée seule ou 7 s sans toucher = sans PIN.
# Avec PIN, la clé est dérivée une fois (Argon2id) et gardée en RAM
# (NEONRELAY_E2E) ; un message envoyé sans le bon PIN s'affiche « illisible ».
#
# Affichage :
#   ← <msg>   message reçu (déchiffré) d'un correspondant
#   → <msg>   invite de saisie ; ce que tu tapes est chiffré puis relayé
#   🟢 / ⚪   un correspondant (même clé, même PIN) est en ligne / ne l'est plus
#
# Ctrl+D (ou Ctrl+C) pour quitter : la clé disparaît avec le process.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

# Sans clé, ce "canal sécurisé" enverrait tout EN CLAIR : on refuse plutôt que
# de donner une fausse impression de confidentialité.
if [ -z "${NEONRELAY_KEY:-}" ]; then
  echo "⚠️  NEONRELAY_KEY n'est pas définie : le canal circulerait EN CLAIR." >&2
  echo "    Lance via nr_launch (base/_launch.sh) pour fournir la clé." >&2
  echo "    Launch via nr_launch to provide the key in RAM only." >&2
  exit 1
fi

# BASE/TOKEN/PW (pour l'affichage) + crypto (vérif PyNaCl).
source "$HERE/base/_token.sh"
source "$HERE/base/_crypto.sh"
nr_crypto_check || exit 1

# PIN optionnel (même calcul que le client autonome : les deux se lisent).
nr_pin_setup || exit 1

# Le canal (voies montante et descendante, bruit, réassemblage) vit dans
# base/_channel.py. BASE / TOKEN / PW passent par l'environnement du process
# (jamais en argument : les arguments sont visibles dans ps).
BASE="$BASE" TOKEN="$TOKEN" PW="$PW" exec python3 "$HERE/base/_channel.py"
