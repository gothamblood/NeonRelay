#!/usr/bin/env bash
# Envoie un message dans la boîte NeonRelay EN LE GARDANT jusqu'au prochain
# stream : exactement comme relay.sh, mais si personne n'écoute au moment de
# l'envoi, le message est gardé en mémoire (un seul slot, le dernier gagne) et
# livré automatiquement au prochain ./stream.sh, puis détruit. Rien sur disque.
#
# Usage :
#   ./stash.sh <payload>                 # garde <payload> sur /hook
#   ./stash.sh <payload> mon/sous/chemin # ... sur un sous-chemin précis
#
# Exemple :
#   ./stash.sh "Le message à stash"
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "Usage: $(basename "$0") <payload> [sub/path] / Usage : $(basename "$0") <payload> [sous/chemin]" >&2
  echo "Example / Exemple : $(basename "$0") \"The enemy's gate is down\"" >&2
  exit 2
fi

# Charge BASE / TOKEN / PW (last-token.env) — base commune.
source "$(dirname "$0")/base/_token.sh"

BODY="$1"                 # 1er argument (obligatoire) = le payload
SUBPATH="${2:-hook}"      # 2e argument (optionnel)    = sous-chemin (défaut 'hook')

# __stash=1 : garder le message jusqu'au prochain stream s'il n'est livré à
# personne tout de suite. Envoi silencieux (rien si succès) ; -f fait remonter
# une erreur HTTP (ex : 401 mauvais mot de passe).
curl -fsS -o /dev/null -X POST "$BASE/relay/$TOKEN/$SUBPATH?__stash=1" \
  -H "X-NeonRelay-Password: $PW" -d "$BODY"
