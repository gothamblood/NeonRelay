#!/usr/bin/env bash
# NeonRelay — désinstallation du client Linux.
# Lancer : bash uninstall.sh
# Supprime ~/.local/share/NeonRelay et la commande ~/.local/bin/neonrelay.
set -euo pipefail

DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
DEST="$DATA/NeonRelay"
LAUNCHER="$HOME/.local/bin/neonrelay"

# Ne supprime le lanceur que s'il a été créé par install.sh.
if [ -f "$LAUNCHER" ] && grep -q '^# NeonRelay launcher' -- "$LAUNCHER"; then
  rm -f -- "$LAUNCHER"
elif [ -e "$LAUNCHER" ]; then
  echo "$LAUNCHER n'a pas été créé par install.sh : laissé en place." >&2
fi

rm -rf -- "$DEST"
# Restes d'une installation interrompue.
rm -rf -- "$DATA"/.NeonRelay.new.* "$DATA"/.NeonRelay.old.* 2>/dev/null || true

echo 'Client NeonRelay désinstallé.'
