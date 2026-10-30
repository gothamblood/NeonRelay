#!/usr/bin/env bash
# Lance le backend NeonRelay (FastAPI + uvicorn) en TLS. / Starts the NeonRelay
# backend over TLS. TLS is MANDATORY — there is no plaintext HTTP mode.
#
# Usage :
#   ./launch.sh                                   # HTTPS, host 0.0.0.0, port 8000
#   HOST=127.0.0.1 PORT=9000 ./launch.sh
#   NEONRELAY_TLS_HOST=203.0.113.5 ./launch.sh    # ajoute cette IP/DNS au cert
#   NEONRELAY_TLS_ALG=rsa:2048 ./launch.sh        # ancien cert RSA (non post-quantique)
#
# Le cert.pem / key.pem sont créés à la racine du projet au 1er lancement. Les
# scripts clients épinglent cert.pem (défaut auto, voir base/_token.sh).
#
# Cert ML-DSA-87 par défaut (signature post-quantique, catégorie 5) : OpenSSL
# ≥ 3.5 requis côté serveur ET côté clients.
set -euo pipefail

# Se placer dans le dossier backend, quel que soit le dossier d'appel.
cd "$(dirname "$0")/../backend"
ROOT="$(cd .. && pwd)"

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8000}"
VENV=".venv"
CERT="$ROOT/cert.pem"
KEY="$ROOT/key.pem"
TLS_ALG="${NEONRELAY_TLS_ALG:-ML-DSA-87}"

# Créer le venv s'il n'existe pas, puis installer les deps.
if [[ ! -d "$VENV" ]]; then
    echo "Creating virtualenv / Création de l'environnement virtuel ..."
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install --upgrade pip
    "$VENV/bin/pip" install -r ../requirements.txt
fi

# TLS obligatoire : openssl est indispensable pour générer/vérifier le cert.
if ! command -v openssl >/dev/null 2>&1; then
  echo "TLS is mandatory but openssl is not installed. Aborting. / TLS obligatoire mais openssl n'est pas installé. Arrêt." >&2
  exit 1
fi

# Générer un certificat auto-signé au premier lancement.
if [[ ! -f "$CERT" || ! -f "$KEY" ]]; then
  echo "Generating self-signed certificate ($TLS_ALG) / Génération du certificat auto-signé ($TLS_ALG) ..."
  # SAN : localhost + 127.0.0.1, plus l'hôte fourni (IP ou DNS) si défini.
  san="DNS:localhost,IP:127.0.0.1"
  if [ -n "${NEONRELAY_TLS_HOST:-}" ]; then
    if [[ "$NEONRELAY_TLS_HOST" =~ ^[0-9.]+$ ]]; then
      san="$san,IP:$NEONRELAY_TLS_HOST"
    else
      san="$san,DNS:$NEONRELAY_TLS_HOST"
    fi
  fi
  umask 077   # la clé privée ne doit être lisible que par toi
  if ! openssl req -x509 -newkey "$TLS_ALG" -nodes -days 365 \
         -keyout "$KEY" -out "$CERT" \
         -subj "/CN=neonrelay" -addext "subjectAltName=$san" 2>/dev/null; then
    rm -f "$CERT" "$KEY"   # ne pas laisser de fichiers partiels
    echo "Certificate generation failed. Aborting. / Échec de la génération du certificat. Arrêt." >&2
    exit 1
  fi
  echo "  → $CERT (à épingler côté client via NEONRELAY_CACERT)"
fi

# Vérifier que le TLS est réellement utilisable, sinon on FERME le programme :
#   - cert et clé présents et non vides
#   - certificat valide (parsable)
#   - la clé correspond bien au certificat (clés publiques comparées : marche
#     pour tout algorithme, RSA comme ML-DSA — -modulus était RSA-only)
if [[ ! -s "$CERT" || ! -s "$KEY" ]] \
   || ! openssl x509 -noout -in "$CERT" >/dev/null 2>&1 \
   || ! diff -q <(openssl x509 -noout -pubkey -in "$CERT" 2>/dev/null) \
                <(openssl pkey -pubout -in "$KEY" 2>/dev/null) >/dev/null 2>&1; then
  echo "TLS cert/key missing, invalid, or mismatched ($CERT / $KEY). Aborting. / Cert/clé TLS absent, invalide ou non concordant. Arrêt." >&2
  echo "  (delete both and relaunch to regenerate / supprime les deux et relance pour régénérer)" >&2
  exit 1
fi

echo "✅ TLS enabled and functional (cert/key verified) / TLS activé et fonctionnel (cert/clé vérifiés)."
echo "NeonRelay → https://$HOST:$PORT   (health: /healthz)"
echo "Clients : NEONRELAY_BASE=https://<hôte>:$PORT  NEONRELAY_CACERT=$CERT"
echo "(Ctrl+C to stop / pour arrêter)"
echo

exec "$VENV/bin/uvicorn" app.main:app --host "$HOST" --port "$PORT" --reload \
  --ssl-keyfile "$KEY" --ssl-certfile "$CERT"
