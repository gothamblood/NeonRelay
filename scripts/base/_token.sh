#!/usr/bin/env bash
# Base commune : charge les identifiants de la boîte COURANTE et pose BASE,
# TOKEN, PW. À sourcer en début de script (pas à exécuter) :
#
#   source "$(dirname "$0")/base/_token.sh"
#   # ... $BASE $TOKEN $PW sont prêts.
#
# Priorité : variables d'environnement déjà définies, sinon last-token.env
# (à la racine du projet, généré par token.sh). Si le token manque, on
# sort avec un message (via ${...:?}).

# Racine du projet (ce fichier vit dans scripts/base/).
_NEONRELAY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

CREDS="${NEONRELAY_CREDS:-$_NEONRELAY_ROOT/last-token.env}"
if [ -z "${NEONRELAY_TOKEN:-}" ] && [ -f "$CREDS" ]; then
  # shellcheck disable=SC1090
  source "$CREDS"
fi

# Le serveur est toujours en TLS (voir launch.sh), donc défaut en https.
BASE="${NEONRELAY_BASE:-https://localhost:8000}"
TOKEN="${NEONRELAY_TOKEN:?Set NEONRELAY_TOKEN / Définis NEONRELAY_TOKEN (run token.sh / source last-token.env)}"
PW="${NEONRELAY_PW:?Set NEONRELAY_PW / Définis NEONRELAY_PW (run token.sh / source last-token.env)}"

# TLS auto-signé : on épingle le cert du serveur. Par défaut on prend cert.pem à
# la racine du projet (généré par launch.sh) ; curl l'utilise via CURL_CA_BUNDLE,
# donc tous les appels curl des scripts en profitent sans option supplémentaire.
if [ -z "${NEONRELAY_CACERT:-}" ] && [ -f "$_NEONRELAY_ROOT/cert.pem" ]; then
  NEONRELAY_CACERT="$_NEONRELAY_ROOT/cert.pem"
fi
if [ -n "${NEONRELAY_CACERT:-}" ]; then
  export NEONRELAY_CACERT CURL_CA_BUNDLE="$NEONRELAY_CACERT"
fi
