#!/usr/bin/env bash
# Supprime DÉFINITIVEMENT la boîte courante (DELETE /config/{id}), avec le mot
# de passe du token. Aucune donnée n'est récupérable après.
#
# Usage :
#   ./delete.sh        # demande confirmation
#   ./delete.sh -y     # sans confirmation (scripts/CI)
set -euo pipefail

ASSUME_YES=0
if [ "${1:-}" = "-y" ] || [ "${1:-}" = "--yes" ]; then
  ASSUME_YES=1
fi

# Charge BASE / TOKEN / PW (last-token.env) — base commune.
source "$(dirname "$0")/base/_token.sh"

echo "⚠️  WARNING: this action is IRREVERSIBLE. / ATTENTION : cette action est IRRÉVERSIBLE."
echo "   Box $TOKEN will be permanently deleted — no recovery. / La boîte $TOKEN sera supprimée définitivement — aucune récupération possible."

if [ "$ASSUME_YES" != 1 ]; then
  read -r -p "Confirm deletion? / Confirmer la suppression ? [y/N] : " ok || true
  case "${ok:-n}" in y|Y|yes|YES|o|O|oui) ;; *) echo "Cancelled. / Annulé."; exit 0 ;; esac
fi

curl -fsS -o /dev/null -X DELETE "$BASE/config/$TOKEN" -H "X-NeonRelay-Password: $PW" \
  || { echo "Deletion failed (server up? right password?). / Échec de la suppression (serveur lancé ? mot de passe bon ?)." >&2; exit 1; }

echo "Box deleted ✅ / Boîte supprimée ✅"
