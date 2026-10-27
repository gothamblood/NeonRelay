#!/usr/bin/env bash
# Résolution des identifiants admin NeonRelay, factorisée pour être réutilisée
# par les autres scripts.
#
# Usage (depuis un autre script) :
#   source "$(dirname "$0")/base/_userpass.sh"
#   neonrelay_load_admin || exit 1
#   # ... $ADMIN_USER et $ADMIN_PW sont maintenant remplis.
#
# La fonction remplit ADMIN_USER et ADMIN_PW :
#   1) depuis NEONRELAY_ADMIN_USER / NEONRELAY_ADMIN_PASSWORD si définies,
#   2) sinon depuis admin-credentials.txt à la racine du projet.

# Racine du projet (ce fichier vit dans scripts/base/, donc deux niveaux au
# dessus), pour retrouver admin-credentials.txt quel que soit le CWD.
_NEONRELAY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# TLS auto-signé : épinglage du cert serveur pour tous les curl. Défaut = cert.pem
# à la racine (généré par launch.sh), sinon ce qui est dans NEONRELAY_CACERT.
if [ -z "${NEONRELAY_CACERT:-}" ] && [ -f "$_NEONRELAY_ROOT/cert.pem" ]; then
  NEONRELAY_CACERT="$_NEONRELAY_ROOT/cert.pem"
fi
if [ -n "${NEONRELAY_CACERT:-}" ]; then
  export NEONRELAY_CACERT CURL_CA_BUNDLE="$NEONRELAY_CACERT"
fi

neonrelay_load_admin() {
  local admin_file="${NEONRELAY_ADMIN_CREDS_FILE:-$_NEONRELAY_ROOT/admin-credentials.txt}"

  ADMIN_USER="${NEONRELAY_ADMIN_USER:-}"
  ADMIN_PW="${NEONRELAY_ADMIN_PASSWORD:-}"

  if [ -z "$ADMIN_USER" ] || [ -z "$ADMIN_PW" ]; then
    if [ -f "$admin_file" ]; then
      ADMIN_USER="$(grep '^username=' "$admin_file" | cut -d= -f2-)"
      ADMIN_PW="$(grep '^password=' "$admin_file" | cut -d= -f2-)"
    else
      echo "Admin credentials not found ($admin_file). Start the server once to generate them, / Identifiants admin introuvables ($admin_file). Lance le serveur une fois pour les générer," >&2
      echo "or export NEONRELAY_ADMIN_USER / NEONRELAY_ADMIN_PASSWORD. / ou exporte NEONRELAY_ADMIN_USER / NEONRELAY_ADMIN_PASSWORD." >&2
      return 1
    fi
  fi
}
