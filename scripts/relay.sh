#!/usr/bin/env bash
# Envoie une requête dans une boîte NeonRelay (côté expéditeur).
#
# Utilise le MÊME token que stream.sh : il lit last-token.env automatiquement,
# donc tu écoutes et tu envoies forcément sur la même boîte.
#
# Usage :
#   ./relay.sh <payload>                 # envoie <payload> sur /hook (silencieux)
#   ./relay.sh -v <payload>              # + affiche la réponse de la boîte
#   ./relay.sh <payload> mon/sous/chemin # ... sur un sous-chemin précis
#
# Exemples :
#   ./relay.sh "The enemy's gate is down"
#   ./relay.sh -v "The enemy's gate is down"
#   ./relay.sh '{"hello":"world"}' github/push
set -euo pipefail

# -v / --verbose : montre la réponse HTTP de la boîte (statut + corps, ex.
# "NeonRelay: relayed"). Accepté n'importe où dans les arguments. Sans ça,
# l'envoi est silencieux.
VERBOSE=0
ARGS=()
for a in "$@"; do
  case "$a" in
    -v|--verbose) VERBOSE=1 ;;
    *) ARGS+=("$a") ;;
  esac
done
set -- "${ARGS[@]+"${ARGS[@]}"}"

if [ "$#" -lt 1 ]; then
  echo "Usage: $(basename "$0") [-v] <payload> [sub/path] / Usage : $(basename "$0") [-v] <payload> [sous/chemin]" >&2
  echo "Example / Exemple : $(basename "$0") -v \"The enemy's gate is down\"" >&2
  exit 2
fi

# Charge BASE / TOKEN / PW (last-token.env) — base commune.
source "$(dirname "$0")/base/_token.sh"
# Fonctions de chiffrement (nr_encrypt) — clé via NEONRELAY_KEY, sinon clair.
source "$(dirname "$0")/base/_crypto.sh"

BODY="$1"                 # 1er argument (obligatoire) = le payload
SUBPATH="${2:-hook}"      # 2e argument (optionnel)    = sous-chemin (défaut 'hook')

# Chiffrement de bout en bout : si NEONRELAY_KEY est définie, le corps est
# chiffré AVANT l'envoi et NeonRelay ne relaie que du base64 opaque. Sans clé,
# nr_encrypt renvoie le texte inchangé (compatibilité envoi en clair).
BODY="$(printf '%s' "$BODY" | nr_encrypt)"

# Le -f fait échouer (code ≠ 0) sur une erreur HTTP, le -S laisse voir l'erreur.
# En mode verbeux on affiche la réponse de la boîte (corps + statut) ; sinon
# l'envoi est silencieux (rien en cas de succès).
if [ "$VERBOSE" = 1 ]; then
  curl -fsS -w '\n[HTTP %{http_code}]\n' -X POST "$BASE/relay/$TOKEN/$SUBPATH" \
    -H "X-NeonRelay-Password: $PW" -d "$BODY"
else
  curl -fsS -o /dev/null -X POST "$BASE/relay/$TOKEN/$SUBPATH" \
    -H "X-NeonRelay-Password: $PW" -d "$BODY"
fi
