#!/usr/bin/env bash
# Canal chiffré de bout en bout par-dessus NeonRelay : ÉCOUTE (déchiffre) et
# ENVOIE (chiffre) dans la même session, sur la boîte courante (last-token.env).
#
# NeonRelay ne voit que du base64 opaque : il ne peut ni lire ni altérer les
# messages. La clé de chiffrement vient de NEONRELAY_KEY (en RAM, JAMAIS écrite
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
# Affichage :
#   ← <msg>   message reçu (déchiffré) d'un expéditeur
#   → <msg>   invite de saisie ; ce que tu tapes est chiffré puis relayé
#
# Ctrl+D (ou Ctrl+C) pour quitter : l'écoute de fond est tuée et la clé
# disparaît avec le process.
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

echo "🔒 Canal chiffré sur la boîte / Encrypted channel on box $TOKEN"
echo "   → $BASE/relay/$TOKEN/hook"
echo "   Tape un message puis Entrée pour l'envoyer ; Ctrl+D pour quitter."
echo "   Type a message + Enter to send; Ctrl+D to quit."
echo

# Écoute (déchiffrement) en tâche de fond ; chaque entrant est préfixé « ← ».
"$HERE/stream.sh" | sed -u 's/^/← /' &
STREAM_PID=$!

# À la sortie (Ctrl+D, Ctrl+C, erreur) : on tue l'écoute de fond. La clé, en
# environnement de ce process, s'évapore quand il se termine.
cleanup() {
  kill "$STREAM_PID" 2>/dev/null || true
  wait "$STREAM_PID" 2>/dev/null || true
  echo
  echo "Canal fermé. / Channel closed."
}
trap cleanup EXIT

# Boucle d'envoi : chaque ligne tapée est chiffrée par relay.sh puis relayée.
while IFS= read -r -p "→ " line; do
  [ -z "$line" ] && continue
  if "$HERE/relay.sh" "$line" >/dev/null 2>&1; then
    echo "→ (envoyé / sent)"
  else
    echo "⚠️  Échec de l'envoi — boîte injoignable ? / Send failed." >&2
  fi
done
