#!/usr/bin/env bash
# Fonctions de chiffrement de bout en bout, partagées par relay.sh / stream.sh
# / secure-shell.sh. À SOURCER (pas exécuter) :
#
#   source "$(dirname "$0")/base/_crypto.sh"
#   CIPHER="$(printf '%s' "$msg"    | nr_encrypt)"   # clair  -> base64
#   CLEAR="$( printf '%s' "$cipher" | nr_decrypt)"   # base64 -> clair
#
# La clé vient de NEONRELAY_KEY (gardée en RAM). Vide => passthrough (clair).
# Toute la logique crypto vit dans _crypto.py (une seule source de vérité).

# Chemin absolu de _crypto.py (ce fichier vit à côté, dans scripts/base/).
_NR_CRYPTO_PY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_crypto.py"

nr_encrypt() { python3 "$_NR_CRYPTO_PY" encrypt; }
nr_decrypt() { python3 "$_NR_CRYPTO_PY" decrypt; }

# PIN optionnel (même règle que client/neonrelay.py) : saisie masquée, Entrée
# seule ou 7 s sans toucher (délai remis à zéro à chaque touche) = sans PIN.
# Avec PIN, la clé est dérivée UNE fois (Argon2id, ~1 s) et exportée en RAM
# dans NEONRELAY_E2E, que relay.sh / stream.sh héritent. Le PIN passe par stdin
# (printf est interne au shell : jamais visible dans ps) puis est effacé.
# Demande TOKEN (base/_token.sh) et NEONRELAY_KEY. Code ≠ 0 si la dérivation échoue.
nr_pin_setup() {
  local pin c tty_state key rc timed_out try
  [ -t 0 ] || return 0                          # pas de terminal : pas d'invite
  tty_state="$(stty -g)"
  for try in 1 2 3; do                          # 3 essais, comme le client autonome
    pin='' timed_out=1
    printf 'PIN (optionnel — Entrée ou 7 s sans toucher = sans PIN) : ' >&2
    stty -echo                                  # masqué pendant TOUTE la saisie
    while IFS= read -r -n1 -t 7 c; do
      case "$c" in
        '') timed_out=0; break ;;               # Entrée
        $'\x7f'|$'\b') pin="${pin%?}" ;;        # Retour arrière
        *) pin+="$c" ;;
      esac
    done
    stty "$tty_state"
    printf '\n' >&2
    if [ "$timed_out" -eq 1 ]; then             # délai : ce qui a été tapé est ignoré
      pin=''
      echo "   Délai écoulé : canal ouvert SANS PIN." >&2
      return 0
    fi
    if [ -z "$pin" ]; then
      echo "   Sans PIN, les messages protégés par un PIN s'affichent illisibles." >&2
      return 0
    fi
    echo "   Dérivation de la clé (Argon2id, ~1 s)…" >&2
    rc=0
    key="$(printf '%s\n' "$pin" | NEONRELAY_TOKEN="$TOKEN" python3 "$_NR_CRYPTO_PY" derive)" || rc=$?
    pin=''
    if [ "$rc" -eq 0 ]; then
      export NEONRELAY_E2E="$key"
      echo "🔐 PIN actif : seuls ceux qui ont ce PIN lisent ce canal." >&2
      return 0
    fi
    [ "$rc" -eq 1 ] || return 1                 # 1 = PIN mal formé : on redemande
  done
  return 1
}

# Vérifie que la crypto est utilisable dès qu'une clé est demandée. Sans clé,
# rien à vérifier (mode clair assumé). Avec clé mais sans PyNaCl : on prévient
# (et _crypto.py refusera de toute façon de tomber en clair).
nr_crypto_check() {
  [ -z "${NEONRELAY_KEY:-}" ] && return 0
  if ! python3 -c 'import nacl.secret' 2>/dev/null; then
    echo "⚠️  NEONRELAY_KEY est définie mais PyNaCl manque (pip install pynacl)." >&2
    echo "    NeonRelay refusera d'envoyer/recevoir en clair. / Will refuse plaintext." >&2
    return 1
  fi
  return 0
}
