#!/usr/bin/env bash
# Écoute en direct une boîte NeonRelay (flux SSE /stream).
#
# Fire-and-forget : rien n'est stocké. Le SEUL moyen de voir une requête en
# mode normal est d'écouter au moment où elle arrive. (Pour récupérer la
# dernière requête APRÈS coup, c'est le stash : voir stash.sh.)
#
# Usage :
#   ./stream.sh                       # lit last-token.env automatiquement
#   source last-token.env && ./stream.sh
#   NEONRELAY_TOKEN=... NEONRELAY_PW=... ./stream.sh
#
# Puis, depuis un autre terminal :
#   curl -X POST "$NEONRELAY_BASE/relay/$NEONRELAY_TOKEN/hook" \
#        -H "X-NeonRelay-Password: $NEONRELAY_PW" -d "The enemy's gate is down"
set -euo pipefail

# -v / --verbose : réaffiche la bannière de démarrage (silencieux par défaut).
VERBOSE=0
if [ "${1:-}" = "-v" ] || [ "${1:-}" = "--verbose" ]; then
  VERBOSE=1
fi

# Charge BASE / TOKEN / PW (last-token.env) — base commune.
source "$(dirname "$0")/base/_token.sh"

# Bannière de démarrage seulement en mode verbeux (-v).
if [ "$VERBOSE" = 1 ]; then
  echo "Live listening on box / Écoute en direct de la boîte $TOKEN"
  echo "  → $BASE/listen/$TOKEN"
  echo "(send a request from another terminal; Ctrl+C to stop / envoie une requête depuis un autre terminal ; Ctrl+C pour arrêter)"
  echo
fi
# -f = échoue sur une erreur HTTP (401/404…) pour déclencher le message ci-dessous ;
# -N = pas de buffer (le flux SSE pousse chaque requête à son arrivée) ;
# -S = affiche les erreurs malgré -s (sinon un serveur injoignable sort en silence).
# Le lecteur (base/_stream_reader.py) n'affiche QUE le corps de chaque requête,
# DÉCHIFFRÉ si NEONRELAY_KEY est définie ; tout le reste (métadonnées,
# keep-alive, event ready) est ignoré, avec un flush pour le temps réel.
curl -fNsS "$BASE/listen/$TOKEN" -H "X-NeonRelay-Password: $PW" \
  | python3 "$(dirname "$0")/base/_stream_reader.py" || {
  echo >&2
  echo "⚠️  Connection failed. Check that: / Connexion échouée. Vérifie que :" >&2
  echo "    • the server is running / le serveur tourne → ./scripts/launch.sh" >&2
  echo "    • NEONRELAY_BASE is correct / est bon → currently/actuellement $BASE" >&2
  echo "      (fix it in last-token.env, or re-run token.sh / corrige-le dans last-token.env, ou relance token.sh)" >&2
  exit 1
}
