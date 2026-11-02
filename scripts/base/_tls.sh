#!/usr/bin/env bash
# Réglages TLS communs à tous les scripts clients. À sourcer (pas à exécuter) ;
# déjà sourcé par _token.sh et _userpass.sh.
#
# 1) Épinglage du cert auto-signé du serveur : NEONRELAY_CACERT, sinon cert.pem
#    à la racine du projet (généré par launch.sh). curl l'utilise via
#    CURL_CA_BUNDLE, Python via NEONRELAY_CACERT.
# 2) Échange de clés post-quantique : OPENSSL_CONF → openssl-tls.cnf (TLS 1.3,
#    SecP384r1MLKEM1024 puis X25519MLKEM768). Appliqué par curl ET Python, et
#    limité aux processus lancés par les scripts. Autre fichier :
#    NEONRELAY_OPENSSL_CONF=/chemin/openssl.cnf.

_NEONRELAY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [ -z "${NEONRELAY_CACERT:-}" ] && [ -f "$_NEONRELAY_ROOT/cert.pem" ]; then
  NEONRELAY_CACERT="$_NEONRELAY_ROOT/cert.pem"
fi
if [ -n "${NEONRELAY_CACERT:-}" ]; then
  export NEONRELAY_CACERT CURL_CA_BUNDLE="$NEONRELAY_CACERT"
fi

export OPENSSL_CONF="${NEONRELAY_OPENSSL_CONF:-$_NEONRELAY_ROOT/scripts/base/openssl-tls.cnf}"
