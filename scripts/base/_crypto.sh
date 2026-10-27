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
