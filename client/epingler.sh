#!/usr/bin/env bash
# NeonRelay — (opérateur) épingle neonrelay.py et openssl-tls.cnf dans les deux
# installeurs, puis affiche leurs empreintes, celles que make-key --amorce grave
# dans la clé :
#   windows/install.ps1 (lignes « Name = '…'; Sha256 = '…' »)
#   linux/install.sh    (NEONRELAY_PY_SHA / OPENSSL_CNF_SHA)
#
# À relancer après TOUTE modification de neonrelay.py ou openssl-tls.cnf, avant de
# publier le dossier client/ et de fabriquer des clés. Changer un installeur
# change son empreinte : les Digispark déjà flashés refuseront la nouvelle version
# tant qu'ils ne sont pas reflashés (le manifeste signé Ed25519 lèvera cette limite).
set -euo pipefail

CLIENT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PS1="$CLIENT/windows/install.ps1"
SH="$CLIENT/linux/install.sh"

pin() {  # fichier motif-avant-l'empreinte empreinte
  local n; n="$(grep -c -- "$2[0-9a-f]\{64\}'" "$1" || true)"
  [ "$n" = 1 ] || { echo "❌ $(basename -- "$1") : ligne « $2… » introuvable ou en double" >&2; exit 1; }
  sed -i "s/\($2\)[0-9a-f]\{64\}'/\1$3'/" "$1"
}

py="$(sha256sum -- "$CLIENT/neonrelay.py" | cut -d' ' -f1)"
cnf="$(sha256sum -- "$CLIENT/openssl-tls.cnf" | cut -d' ' -f1)"
pin "$PS1" "Name = 'neonrelay.py'; Sha256 = '" "$py"
pin "$PS1" "Name = 'openssl-tls.cnf'; Sha256 = '" "$cnf"
pin "$SH" "NEONRELAY_PY_SHA='" "$py"
pin "$SH" "OPENSSL_CNF_SHA='" "$cnf"
echo "  neonrelay.py     $py" >&2
echo "  openssl-tls.cnf  $cnf" >&2

echo "windows/install.ps1  $(sha256sum -- "$PS1" | cut -d' ' -f1)"
echo "linux/install.sh     $(sha256sum -- "$SH" | cut -d' ' -f1)"
