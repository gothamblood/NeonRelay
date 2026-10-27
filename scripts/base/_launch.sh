#!/usr/bin/env bash
# Point d'entrée du canal chiffré : prend le CHEMIN de secure-shell.sh et la
# CLÉ, puis lance en gardant la clé UNIQUEMENT en RAM (variable d'environnement
# du process, jamais écrite sur disque).
#
# À SOURCER dans ton shell interactif (p. ex. depuis ~/.bashrc) :
#   source /chemin/vers/NeonRelay/scripts/base/_launch.sh
#
# Puis — et c'est exactement ce que le Digispark tape, AVEC UN ESPACE EN TÊTE
# pour que la ligne (donc la clé) n'entre pas dans l'historique :
#
#     nr_launch ~/projets/NeonRelay/scripts/secure-shell.sh <CLÉ>
#      ^ espace
#
# `exec` remplace le shell courant par le canal : quand tu quittes le canal
# (Ctrl+D), le terminal se ferme, et la clé disparaît avec le process.

nr_launch() {
  local shell_path="${1:?usage: nr_launch <chemin secure-shell.sh> <clé>}"
  local key="${2:?usage: nr_launch <chemin secure-shell.sh> <clé>}"

  if [ ! -x "$shell_path" ]; then
    echo "nr_launch: '$shell_path' introuvable ou non exécutable." >&2
    return 1
  fi

  # La clé ne vit que dans l'environnement du process enfant ; exec remplace le
  # shell, donc rien ne subsiste en mémoire après la fermeture du canal.
  NEONRELAY_KEY="$key" exec "$shell_path"
}

# Anti-historique : une commande préfixée d'un espace n'est pas enregistrée si
# HISTCONTROL contient ignorespace (ou ignoreboth). On s'en assure pour la
# session — c'est ce qui garde hors du .bash_history la ligne portant la clé.
case ":${HISTCONTROL:-}:" in
  *:ignorespace:*|*:ignoreboth:*) ;;
  *) export HISTCONTROL="${HISTCONTROL:+$HISTCONTROL:}ignorespace" ;;
esac
