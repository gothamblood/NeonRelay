#!/usr/bin/env bash
# NeonRelay — installation du client Linux (une seule fois, SANS root).
#
# Deux façons de le lancer :
#   - AMORÇAGE (cas normal) : le Digispark tape une commande qui télécharge ce
#     script, vérifie son SHA-256 contre l'empreinte gravée dans la clé, puis
#     l'exécute avec --source URL. Le client n'a jamais le dossier client/.
#   - LOCAL (opérateur) : bash install.sh   (depuis le dossier client/linux)
#
# Ce que fait ce script, dans ~/.local/share/NeonRelay ($XDG_DATA_HOME respecté) :
#   1. télécharge un Python AUTONOME 3.15 (python-build-standalone, OpenSSL 3.5 :
#      ML-DSA-87 + ML-KEM, indépendant de l'OpenSSL de la distribution) et
#      PyNaCl + cffi (PyPI, roues manylinux) ;
#   2. récupère neonrelay.py + openssl-tls.cnf (depuis --source, sinon depuis
#      le dossier parent client/) ;
#   3. vérifie l'empreinte SHA-256 de CHAQUE fichier (fixée ci-dessous) ;
#   4. crée la commande « neonrelay » dans ~/.local/bin.
#
# Chaîne de confiance : empreinte de CE fichier (dans la clé) → empreintes
# ci-dessous → chaque fichier installé. Après toute modification de
# neonrelay.py ou openssl-tls.cnf : client/epingler.sh.
#
# Rien n'est installé dans le système, aucun fichier de configuration du shell
# n'est modifié. Désinstaller : bash uninstall.sh.
# Jamais de « curl | bash » : ce script ne télécharge AUCUN code non épinglé.

set -euo pipefail
umask 077

# --source URL : dossier client publié (URL/neonrelay.py, URL/openssl-tls.cnf).
SOURCE=''
while [ $# -gt 0 ]; do
  case "$1" in
    --source) [ $# -ge 2 ] || { echo 'Erreur : --source sans URL.' >&2; exit 1; }
              SOURCE="${2%/}"; shift 2 ;;
    *) echo "Erreur : option inconnue : $1" >&2; exit 1 ;;
  esac
done
case "$SOURCE" in
  ''|http://*|https://*) ;;
  *) echo 'Erreur : --source doit commencer par http:// ou https://.' >&2; exit 1 ;;
esac

# --- Téléchargements épinglés ---------------------------------------------------
# Une empreinte différente = installation annulée. Mettre à jour une version =
# changer l'URL ET l'empreinte. Sources des empreintes :
#   Python : SHA256SUMS de la release python-build-standalone (recoupé avec
#            l'API GitHub) ; roues : PyPI.
PBS_RELEASE='20261026'
PY_VERSION='3.15.2'

PY_URL_x86_64="https://github.com/astral-sh/python-build-standalone/releases/download/${PBS_RELEASE}/cpython-${PY_VERSION}%2B${PBS_RELEASE}-x86_64-unknown-linux-gnu-install_only.tar.gz"
PY_SHA_x86_64='08d4ae9024a7cfbd3b70e559241afa2571cd3208d7bd5f96f88e0080dd4092aa'
PY_URL_aarch64="https://github.com/astral-sh/python-build-standalone/releases/download/${PBS_RELEASE}/cpython-${PY_VERSION}%2B${PBS_RELEASE}-aarch64-unknown-linux-gnu-install_only.tar.gz"
PY_SHA_aarch64='6fc73e8a4c80a65d2a0ed21535c65383f7b9f96bb58a5f40ed035bd7ee318616'

# manylinux2014 (glibc ≥ 2.17) : la cible la plus large.
NACL_URL_x86_64='https://files.pythonhosted.org/packages/7f/81/d60984052df5c97b1d24365bc1e30024379b42c4edcd79d2436b1b9806f2/pynacl-1.6.2-cp38-abi3-manylinux2014_x86_64.manylinux_2_17_x86_64.whl'
NACL_SHA_x86_64='22de65bb9010a725b0dac248f353bb072969c94fa8d6b1f34b87d7953cf7bbe4'
NACL_URL_aarch64='https://files.pythonhosted.org/packages/1e/b4/e927e0653ba63b02a4ca5b4d852a8d1d678afbf69b3dbf9c4d0785ac905c/pynacl-1.6.2-cp38-abi3-manylinux2014_aarch64.manylinux_2_17_aarch64.whl'
NACL_SHA_aarch64='8845c0631c0be43abdd865511c41eab235e0be69c81dc66a50911594198679b0'

CFFI_URL_x86_64='https://files.pythonhosted.org/packages/44/16/29e6d01b388bef055ecd6ca8244b3f4d336bd09e92d5d892187b9601084e/cffi-2.1.1-cp315-cp315-manylinux2014_x86_64.manylinux_2_17_x86_64.whl'
CFFI_SHA_x86_64='aeae0e330c9f6acd681f647d46cefd30c29f93e3392882e792e82080c9691399'
CFFI_URL_aarch64='https://files.pythonhosted.org/packages/e2/31/9e1313b0a6e30e91b3b3d3fff51ae99c857c07738e3afcce1f7334e1b7ab/cffi-2.1.1-cp315-cp315-manylinux2014_aarch64.manylinux_2_17_aarch64.whl'
CFFI_SHA_aarch64='507a24c282e0f42f8ed737cf048572cbf580468da5555764a8331735e9c736b6'

# pycparser n'est PAS installé : il ne sert qu'à compiler des modules cffi, or
# PyNaCl est livré précompilé (testé : SecretBox + Argon2id fonctionnent sans).

# Le client lui-même. Empreintes mises à jour par client/epingler.sh.
NEONRELAY_PY_SHA='53d0dbc960678b3644c87207b4c410e79668123f2f06579fc69cc82c3753a373'
OPENSSL_CNF_SHA='40fcb1b909e540eae22417442fa6e081ac6eff53d14d72cfbe43362a398de2ad'

# --- Chemins ---------------------------------------------------------------------
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(dirname -- "$HERE")"                       # client/ : neonrelay.py + openssl-tls.cnf
DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
DEST="$DATA/NeonRelay"
BIN="$HOME/.local/bin"
LAUNCHER="$BIN/neonrelay"
MARKER='# NeonRelay launcher'                     # permet à uninstall.sh de reconnaître le lanceur

die() { printf 'Erreur : %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -ne 0 ] || die "ne pas lancer en root : l'installation se fait dans ton dossier personnel."

case "$DEST$LAUNCHER" in
  *"'"*|*$'\n'*) die "chemin d'installation inattendu ($DEST) : apostrophe ou retour à la ligne." ;;
esac

if [ -z "$SOURCE" ]; then
  for f in neonrelay.py openssl-tls.cnf; do
    [ -f "$SRC/$f" ] || die "$f introuvable dans $SRC : garde le dossier client complet (client/linux/install.sh + client/$f)."
  done
fi

# --- Plate-forme -----------------------------------------------------------------
case "$(uname -s)" in Linux) ;; *) die "ce script est pour Linux (Windows : client/windows/install.cmd)." ;; esac
case "$(uname -m)" in
  x86_64|amd64)  ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
  *) die "architecture $(uname -m) non prise en charge (x86_64 ou aarch64 seulement)." ;;
esac
# Python autonome et roues manylinux = glibc. Alpine & co (musl) : non pris en charge.
getconf GNU_LIBC_VERSION >/dev/null 2>&1 || die "glibc introuvable (Alpine/musl ?) : distribution non prise en charge."

eval "PY_URL=\$PY_URL_$ARCH PY_SHA=\$PY_SHA_$ARCH"
eval "NACL_URL=\$NACL_URL_$ARCH NACL_SHA=\$NACL_SHA_$ARCH"
eval "CFFI_URL=\$CFFI_URL_$ARCH CFFI_SHA=\$CFFI_SHA_$ARCH"

# --- Outils ----------------------------------------------------------------------
# fetch : HTTPS seulement (Python, roues). fetch_source : la source du client
# peut être en HTTP (tests sur réseau local) : son intégrité tient aux empreintes.
if command -v curl >/dev/null 2>&1; then
  fetch() { curl --proto '=https' --tlsv1.2 -fsSL --retry 2 -o "$2" -- "$1"; }
  fetch_source() { curl --proto '=http,https' -fsSL --retry 2 -o "$2" -- "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget --https-only --secure-protocol=TLSv1_2 -q -O "$2" -- "$1"; }
  fetch_source() { wget -q -O "$2" -- "$1"; }
else
  die "ni curl ni wget : installe l'un des deux (ex. sudo apt install curl)."
fi
if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum -- "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 -- "$1" | cut -d' ' -f1; }
else
  die "sha256sum introuvable (coreutils)."
fi
command -v tar >/dev/null 2>&1 || die "tar introuvable."

get_verified() {  # url sha256 fichier
  printf '  - %s\n' "$(basename -- "$3")"
  fetch "$1" "$3" || die "téléchargement impossible : $1"
  local got; got="$(sha256 "$3")"
  [ "$got" = "$2" ] || die "empreinte SHA-256 inattendue pour $(basename -- "$3") : téléchargement altéré, installation annulée."
}

# --- Installation ----------------------------------------------------------------
echo "NeonRelay — première utilisation : installation du client ($ARCH, 1 à 2 minutes)."
echo "Ne touche à rien : la clé fait tout. Chaque fichier est vérifié avant usage."
mkdir -p -- "$DATA" "$BIN"

# Tout est préparé dans un dossier temporaire À CÔTÉ de la destination (même
# système de fichiers), puis mis en place d'un seul « mv » : une installation
# interrompue ne casse jamais celle qui marche déjà.
STAGE="$(mktemp -d -- "$DATA/.NeonRelay.new.XXXXXX")"
DL="$STAGE/.dl"
OLD=''
cleanup() {
  rm -rf -- "$STAGE"
  if [ -n "$OLD" ] && [ -d "$OLD" ]; then
    if [ -e "$DEST" ]; then rm -rf -- "$OLD"; else mv -- "$OLD" "$DEST"; fi
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM
mkdir -- "$DL"

echo 'Téléchargement (empreintes SHA-256 vérifiées) :'
get_verified "$PY_URL"   "$PY_SHA"   "$DL/python.tar.gz"
get_verified "$NACL_URL" "$NACL_SHA" "$DL/pynacl.whl"
get_verified "$CFFI_URL" "$CFFI_SHA" "$DL/cffi.whl"

# Le client : téléchargé depuis --source, ou copié depuis client/ ; vérifié dans les deux cas.
for pair in "neonrelay.py:$NEONRELAY_PY_SHA" "openssl-tls.cnf:$OPENSSL_CNF_SHA"; do
  f="${pair%%:*}"; want="${pair#*:}"
  printf '  - %s\n' "$f"
  if [ -n "$SOURCE" ]; then
    fetch_source "$SOURCE/$f" "$STAGE/$f" || die "téléchargement impossible : $SOURCE/$f"
  else
    cp -- "$SRC/$f" "$STAGE/$f"
  fi
  [ "$(sha256 "$STAGE/$f")" = "$want" ] || die "empreinte SHA-256 inattendue pour $f : fichier altéré, installation annulée."
done

tar -xzf "$DL/python.tar.gz" -C "$STAGE" --no-same-owner --no-same-permissions
PY="$STAGE/python/bin/python3"
[ -x "$PY" ] || die "archive Python inattendue (python/bin/python3 absent)."

# Une roue (.whl) est une archive zip : on la décompresse dans site-packages
# avec le zipfile du Python qu'on vient de vérifier (pas besoin d'unzip ni de pip).
SITE="$("$PY" -I -c 'import sysconfig; print(sysconfig.get_path("purelib"))')"
for whl in "$DL/pynacl.whl" "$DL/cffi.whl"; do
  "$PY" -I -m zipfile -e "$whl" "$SITE"
done
rm -rf -- "$DL"

chmod -R u+rwX,go-rwx -- "$STAGE"

echo 'Vérification :'
"$PY" -I - <<'EOF' || die "le Python installé ne démarre pas correctement."
import ssl, sys
import nacl.secret, nacl.pwhash
from nacl.pwhash import argon2id
if ssl.OPENSSL_VERSION_INFO < (3, 5):
    sys.exit("OpenSSL trop ancien : " + ssl.OPENSSL_VERSION)
box = nacl.secret.SecretBox(b"\0" * 32)
assert box.decrypt(box.encrypt(b"ok")) == b"ok"
argon2id.kdf(32, b"pin", b"\0" * argon2id.SALTBYTES,
             opslimit=argon2id.OPSLIMIT_MIN, memlimit=argon2id.MEMLIMIT_MIN)
print("  " + ssl.OPENSSL_VERSION + " + PyNaCl OK")
EOF

# Mise en place.
if [ -e "$DEST" ]; then
  OLD="$DATA/.NeonRelay.old.$$"
  mv -- "$DEST" "$OLD"
fi
mv -- "$STAGE" "$DEST"
if [ -n "$OLD" ]; then rm -rf -- "$OLD"; OLD=''; fi

# Lanceur : chemins figés entre apostrophes (vérifiés plus haut), -I = Python
# isolé (ignore PYTHONPATH, PYTHONHOME, le dossier courant et le site utilisateur).
TMP_LAUNCHER="$(mktemp -- "$BIN/.neonrelay.XXXXXX")"
cat > "$TMP_LAUNCHER" <<EOF
#!/bin/sh
$MARKER — généré par client/linux/install.sh ; supprimé par uninstall.sh
exec '$DEST/python/bin/python3' -I '$DEST/neonrelay.py' "\$@"
EOF
chmod 700 -- "$TMP_LAUNCHER"
mv -f -- "$TMP_LAUNCHER" "$LAUNCHER"

echo
echo "Installé dans $DEST"
# Amorçage : la commande tapée par le Digispark lance elle-même le client.
[ -z "$SOURCE" ] || exit 0
case ":$PATH:" in
  *":$BIN:"*)
    echo 'Lance « neonrelay » dans un terminal, puis colle la clé (ou branche le Digispark).' ;;
  *)
    echo "Lance : $LAUNCHER   (puis colle la clé)"
    echo "$BIN n'est pas dans ton PATH : la plupart des distributions l'ajoutent"
    echo 'à la prochaine ouverture de session ; sinon utilise le chemin complet ci-dessus.' ;;
esac
