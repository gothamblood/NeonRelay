#!/usr/bin/env bash
# Affiche combien d'auditeurs écoutent la boîte EN CE MOMENT (connexions
# /listen ouvertes à l'instant T). Pas un total cumulé : le relais est sans
# trace, donc on ne compte que les listeners connectés maintenant.
#
# Usage :
#   ./count.sh          # une seule fois
#   ./count.sh 5        # rafraîchit toutes les 5 secondes (Ctrl+C pour arrêter)
#   ./count.sh 10       # ... toutes les 10 s, etc.
set -euo pipefail

INTERVAL="${1:-}"   # 1er argument optionnel = intervalle en secondes
if [ -n "$INTERVAL" ] && ! [[ "$INTERVAL" =~ ^[0-9]+$ ]]; then
  echo "Usage: $(basename "$0") [interval_seconds] / Usage : $(basename "$0") [intervalle_en_secondes]" >&2
  echo "Example / Exemple : $(basename "$0") 5" >&2
  exit 2
fi

# Charge BASE / TOKEN / PW (last-token.env) — base commune.
source "$(dirname "$0")/base/_token.sh"

# Interroge l'API et renvoie juste le nombre d'auditeurs.
get_count() {
  curl -fsS "$BASE/listen/$TOKEN/count" -H "X-NeonRelay-Password: $PW" \
    | python3 -c 'import sys, json; print(json.load(sys.stdin)["listeners"])'
}

# Sans intervalle : une seule mesure, puis on sort.
if [ -z "$INTERVAL" ]; then
  get_count
  exit 0
fi

# Avec intervalle : rafraîchit sur place (\r) toutes les N secondes.
echo "Listeners (refreshed every ${INTERVAL}s, Ctrl+C to stop) / Auditeurs (rafraîchi toutes les ${INTERVAL}s, Ctrl+C pour arrêter) :"
while true; do
  printf '\r  %s listener(s)/auditeur(s) @ %s   ' "$(get_count)" "$(date '+%H:%M:%S')"
  sleep "$INTERVAL"
done
