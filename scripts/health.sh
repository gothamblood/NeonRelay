#!/usr/bin/env bash
# Vérifie que le serveur NeonRelay répond (GET /healthz). Aucun token requis.
#
# Usage :
#   ./health.sh                       # vérifie https://localhost:8000
#   NEONRELAY_BASE=https://host:9000 ./health.sh
#
# Sortie : la réponse JSON + "OK" (code 0) si sain, sinon un message d'erreur
# (code 1). Pratique en CI / supervision : `./health.sh && deploy`.
set -euo pipefail

# On peut réutiliser le BASE de last-token.env s'il est là, sinon défaut.
CREDS="${NEONRELAY_CREDS:-$(dirname "$0")/../last-token.env}"
if [ -z "${NEONRELAY_BASE:-}" ] && [ -f "$CREDS" ]; then
  # shellcheck disable=SC1090
  source "$CREDS"
fi
BASE="${NEONRELAY_BASE:-https://localhost:8000}"   # serveur toujours en TLS

# Épinglage du cert auto-signé (défaut cert.pem à la racine) pour curl.
_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ -z "${NEONRELAY_CACERT:-}" ] && [ -f "$_ROOT/cert.pem" ]; then
  NEONRELAY_CACERT="$_ROOT/cert.pem"
fi
[ -n "${NEONRELAY_CACERT:-}" ] && export CURL_CA_BUNDLE="$NEONRELAY_CACERT"

# -f : code ≠ 0 si HTTP ≥ 400 ; -S : montre l'erreur ; --max-time : ne pas traîner.
body="$(curl -fsS --max-time 5 "$BASE/healthz" 2>/dev/null)" || {
  echo "NeonRelay UNREACHABLE at / INJOIGNABLE sur $BASE/healthz" >&2
  exit 1
}

echo "$body"
echo "OK — $BASE is alive / est en vie"
