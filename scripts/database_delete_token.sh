#!/usr/bin/env bash
# Supprime un (ou tous) les tokens directement dans la base SQLite.
# ⚠️ Agit sur la base, sans passer par l'API ni le mot de passe du token.
#    Le registre ne garde que les tokens ; le trafic n'est jamais stocké.
#
# Usage :
#   ./database_delete_token.sh <token_id>     # supprime ce token
#   ./database_delete_token.sh --all          # supprime TOUS les tokens
#   ./database_delete_token.sh -y <token_id>  # sans demander confirmation
set -euo pipefail

DB="$(dirname "$0")/../neonrelay.db"

# -y / --yes : ne pas demander de confirmation.
ASSUME_YES=0
if [ "${1:-}" = "-y" ] || [ "${1:-}" = "--yes" ]; then
  ASSUME_YES=1
  shift
fi

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
  echo "Usage: $(basename "$0") [-y] <token_id | --all> / Usage : $(basename "$0") [-y] <token_id | --all>" >&2
  exit 2
fi

if [ ! -f "$DB" ]; then
  echo "Database not found / Base introuvable : $DB (has the server ever run? / le serveur a-t-il déjà tourné ?)" >&2
  exit 1
fi

# Construit la clause WHERE et affiche ce qui sera supprimé.
if [ "$TARGET" = "--all" ]; then
  WHERE="1=1"
  COUNT="$(sqlite3 "$DB" "SELECT COUNT(*) FROM tokens;")"
  echo "Target: ALL tokens / Cible : TOUS les tokens ($COUNT)."
else
  # Échappe les apostrophes pour la requête SQL.
  SAFE="${TARGET//\'/\'\'}"
  WHERE="id='$SAFE'"
  COUNT="$(sqlite3 "$DB" "SELECT COUNT(*) FROM tokens WHERE $WHERE;")"
  if [ "$COUNT" = "0" ]; then
    echo "No token with id / Aucun token avec l'id : $TARGET" >&2
    exit 1
  fi
  echo "Target: token / Cible : le token $TARGET."
fi

# Confirmation (sauf -y).
if [ "$ASSUME_YES" != 1 ]; then
  printf 'Delete %s token(s)? / Supprimer %s token(s) ? [y/N] ' "$COUNT" "$COUNT"
  read -r ans
  case "$ans" in
    y|Y|yes|YES|o|O|oui) ;;
    *) echo "Cancelled. / Annulé."; exit 0 ;;
  esac
fi

sqlite3 "$DB" "DELETE FROM tokens WHERE $WHERE;"
echo "$COUNT token(s) deleted / supprimé(s)."
