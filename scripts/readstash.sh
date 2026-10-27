#!/usr/bin/env bash
# Lit UNIQUEMENT le message gardé en stash, puis ressort immédiatement (ne reste
# pas à écouter le direct comme stream.sh, et ne traîne pas si le stash est vide).
#
# Rappel du modèle : un message envoyé avec stash.sh est gardé jusqu'au
# prochain stream. Se connecter au flux le récupère et le détruit. Ce script
# ouvre donc le flux juste le temps de prendre ce message (livré dès la
# connexion), puis ferme le socket aussitôt — « prend et s'en va ».
#
# Usage :
#   ./readstash.sh          # affiche le body_text gardé, ou rien si vide
#   TIMEOUT=5 ./readstash.sh
#
# Sortie : le message sur stdout (code 0), ou "stash vide" sur stderr (code 1).
set -euo pipefail

# Charge BASE / TOKEN / PW (last-token.env) — base commune.
source "$(dirname "$0")/base/_token.sh"
TIMEOUT="${TIMEOUT:-3}"   # secondes max pour établir la connexion

# Toute la logique en Python : on ouvre /listen, on lit l'event "ready" puis le
# message gardé (livré dans le même flush), et on FERME tout de suite. Si rien
# n'est gardé, on n'attend qu'une fraction de seconde après "ready" puis on sort.
# Codes : 0 = message trouvé (sur stdout), 1 = stash vide, 2 = erreur connexion.
set +e
result="$(
  BASE="$BASE" TOKEN="$TOKEN" PW="$PW" TIMEOUT="$TIMEOUT" NEONRELAY_CACERT="${NEONRELAY_CACERT:-}" python3 -c '
import os, sys, json, ssl, socket, http.client, urllib.parse

base = os.environ["BASE"]
token = os.environ["TOKEN"]
pw = os.environ["PW"]
timeout = float(os.environ.get("TIMEOUT", "3"))
u = urllib.parse.urlparse(base)
if u.scheme == "https":
    # TLS : épingle le cert auto-signé du serveur si NEONRELAY_CACERT est fourni.
    cafile = os.environ.get("NEONRELAY_CACERT") or None
    ctx = ssl.create_default_context(cafile=cafile)
    conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=timeout, context=ctx)
else:
    conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
try:
    conn.request("GET", "/listen/" + token,
                 headers={"X-NeonRelay-Password": pw})
    resp = conn.getresponse()
except Exception as e:
    print(f"Connection failed / Connexion échouée : {e}", file=sys.stderr)
    sys.exit(2)
if resp.status != 200:
    print(f"HTTP error / Erreur HTTP {resp.status}", file=sys.stderr)
    sys.exit(2)

found = None
ready = False
while found is None:
    if ready:                       # apres "ready" : courte attente du message gardé
        conn.sock.settimeout(0.4)
    try:
        raw = resp.readline()
    except (socket.timeout, TimeoutError):
        break
    if not raw:
        break
    line = raw.decode("utf-8", "replace")
    if not line.startswith("data:"):
        continue
    try:
        obj = json.loads(line[5:].strip())
    except ValueError:
        continue
    if obj == {}:                   # event "ready" -> le stash suit (ou rien)
        ready = True
        continue
    if "body_text" in obj:
        found = obj["body_text"]
    elif "body_base64" in obj:
        found = "[binary body, base64 / corps binaire, base64] " + obj["body_base64"]
conn.close()
if found is None:
    sys.exit(1)
print(found)
'
)"
rc=$?
set -e

case "$rc" in
  0) printf '%s\n' "$result" ;;
  1) echo "Stash empty (no held message). / Stash vide (aucun message gardé)." >&2; exit 1 ;;
  *) exit "$rc" ;;   # 2 : erreur déjà affichée par Python
esac
