#!/usr/bin/env bash
# Assistant interactif : configure le token COURANT (celui de last-token.env).
# Modifie la réponse que la boîte renvoie aux expéditeurs (statut, corps, type,
# délai). Utilise le mot de passe du token — PAS l'admin : un simple user ne
# peut pas créer de token (ça, c'est réservé à l'admin via token.sh), il
# peut seulement configurer la sienne.
#
# Usage :
#   ./config.sh            # Entrée = garder la valeur actuelle
set -euo pipefail

# Charge BASE / TOKEN / PW (last-token.env) — base commune.
source "$(dirname "$0")/base/_token.sh"

# Lit la config actuelle de la boîte (sert de valeurs par défaut).
current="$(curl -fsS "$BASE/config/$TOKEN" -H "X-NeonRelay-Password: $PW")" || {
  echo "Cannot read the token config (server up? right password?). / Impossible de lire la config du token (serveur lancé ? mot de passe bon ?)." >&2
  exit 1
}
get() { printf '%s' "$current" | python3 -c "import sys,json;print(json.load(sys.stdin)[\"$1\"])"; }

CUR_STATUS=$(get response_status)
CUR_BODY=$(get response_body)
CUR_CTYPE=$(get response_content_type)
CUR_DELAY=$(get response_delay_ms)

# Pose une question avec la valeur actuelle en défaut ; Entrée = on garde.
ask() {
  local prompt="$1" default="$2" reply
  read -r -p "$prompt [$default] : " reply || true
  printf '%s' "${reply:-$default}"
}
need_int() {
  if ! [[ "$1" =~ ^[0-9]+$ ]]; then
    echo "  '$2' must be an integer (got '$1'). / « $2 » doit être un entier (reçu : '$1')." >&2
    exit 2
  fi
}

echo "— Configure box / Configuration de la boîte $TOKEN (Enter = current value / Entrée = valeur actuelle) —"
STATUS=$(ask "HTTP status returned to senders / Code HTTP renvoyé aux expéditeurs" "$CUR_STATUS")
BODY=$(ask   "Response body / Corps de la réponse" "$CUR_BODY")
CTYPE=$(ask  "Response Content-Type / Content-Type de la réponse" "$CUR_CTYPE")
DELAY=$(ask  "Delay before response (ms) / Délai avant réponse (ms)" "$CUR_DELAY")

need_int "$STATUS" "Code HTTP"
need_int "$DELAY"  "Délai"

# Corps JSON du PATCH (échappement géré par Python).
BODY_JSON="$(
  STATUS="$STATUS" BODY="$BODY" CTYPE="$CTYPE" DELAY="$DELAY" python3 -c '
import os, json
print(json.dumps({
    "response_status": int(os.environ["STATUS"]),
    "response_body": os.environ["BODY"],
    "response_content_type": os.environ["CTYPE"],
    "response_delay_ms": int(os.environ["DELAY"]),
}))
'
)"

echo
echo "New config / Nouvelle config : $BODY_JSON"
read -r -p "Apply? / Appliquer ? [Y/n] : " ok || true
case "${ok:-y}" in y|Y|yes|YES|o|O|oui) ;; *) echo "Cancelled. / Annulé."; exit 0 ;; esac

curl -fsS -X PATCH "$BASE/config/$TOKEN" \
  -H "X-NeonRelay-Password: $PW" -H 'content-type: application/json' \
  -d "$BODY_JSON" -o /dev/null || { echo "Update failed. / Échec de la mise à jour." >&2; exit 1; }

echo "Config updated ✅ / Config mise à jour ✅"
