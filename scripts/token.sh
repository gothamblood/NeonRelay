#!/usr/bin/env bash
# Crée un token NeonRelay et enregistre TEMPORAIREMENT l'id + le password.
# ⚠️ Le password n'est renvoyé qu'UNE SEULE fois par l'API : ce fichier est
#    le seul endroit où il sera lisible ensuite. À ne pas committer.

set -euo pipefail

BASE="${NEONRELAY_BASE:-https://localhost:8000}"   # serveur toujours en TLS
OUT="${NEONRELAY_CREDS:-$(dirname "$0")/../last-token.env}"   # fichier temporaire (clé=valeur)

# Identifiants admin : factorisés dans base/_userpass.sh (remplit ADMIN_USER/ADMIN_PW).
source "$(dirname "$0")/base/_userpass.sh"
neonrelay_load_admin || exit 1

# Corps JSON optionnel passé en 1er argument, sinon {} (réponse par défaut).
BODY="${1:-{}}"

resp=$(curl -s -u "$ADMIN_USER:$ADMIN_PW" -X POST "$BASE/config/tokens" \
  -H 'content-type: application/json' \
  -d "$BODY")

# Extraction id + password depuis la réponse JSON.
read -r TOKEN PW < <(printf '%s' "$resp" | python3 -c '
import sys, json
d = json.load(sys.stdin)
print(d["id"], d["password"])
') || { echo "Creation failed. Raw response: / Échec de création. Réponse brute :"; echo "$resp"; exit 1; }

# Écrit les identifiants dans le fichier temporaire (sourçable).
umask 077   # fichier lisible par toi seul (contient un secret)
cat > "$OUT" <<EOF
# NeonRelay — identifiants temporaires (généré $(date '+%Y-%m-%d %H:%M:%S'))
NEONRELAY_TOKEN=$TOKEN
NEONRELAY_PW=$PW
NEONRELAY_BASE=$BASE
EOF

echo "Token created ✅ / Token créé ✅"
echo "  id       : $TOKEN"
echo "  password : $PW"
echo "  → saved to / sauvegardé dans $OUT (chmod 600)"




# curl --cacert ./cert.pem -X POST https://localhost:8000/config/tokens -H 'content-type: application/json' -d '{}'