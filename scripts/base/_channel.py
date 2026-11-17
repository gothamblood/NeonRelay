#!/usr/bin/env python3
"""Canal bruité pour secure-shell.sh.

Réutilise le moteur du client autonome (client/neonrelay.py) : même format de
trame, même chiffrement (XSalsa20-Poly1305 puis AES-256-GCM), même rythme. Les
scripts et le client autonome se parlent donc avec exactement le même code.

Entrées (environnement, posé par secure-shell.sh — rien en argument, car les
arguments sont visibles dans ps) :
    BASE, TOKEN, PW        boîte courante (base/_token.sh)
    NEONRELAY_CACERT       cert.pem du serveur, épinglé par son empreinte
    NEONRELAY_E2E          clé déjà dérivée avec le PIN (64 hex), prioritaire
    NEONRELAY_KEY          passphrase (sans PIN : clé = SHA-256 de la passphrase)
"""
import hashlib
import os
import ssl
import sys
import urllib.parse

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "..", "client"))

import neonrelay as nr  # noqa: E402


def _fail(msg: str) -> int:
    sys.stderr.write(f"NeonRelay: {msg}\n")
    return 1


def main() -> int:
    base = os.environ.get("BASE", "")
    token = os.environ.get("TOKEN", "")
    password = os.environ.get("PW", "")
    cacert = os.environ.get("NEONRELAY_CACERT", "")
    derived = os.environ.get("NEONRELAY_E2E", "")
    passphrase = os.environ.get("NEONRELAY_KEY", "")

    url = urllib.parse.urlsplit(base)
    if url.scheme != "https" or not url.hostname:
        return _fail(f"NEONRELAY_BASE doit être une URL https (actuellement : {base!r}).")
    if not token or not password:
        return _fail("TOKEN / PW manquants (last-token.env).")
    if not passphrase and not derived:
        return _fail("NEONRELAY_KEY manque : le canal circulerait en clair, refusé.")
    try:
        with open(cacert, encoding="ascii") as fh:
            der = ssl.PEM_cert_to_DER_cert(fh.read())
    except (OSError, ValueError):
        return _fail(f"certificat à épingler illisible : {cacert or '(NEONRELAY_CACERT vide)'}.")

    e2e = None
    if derived:
        try:
            e2e = bytes.fromhex(derived)
        except ValueError:
            e2e = b""
        if len(e2e) != 32:
            return _fail("NEONRELAY_E2E invalide (64 caractères hexadécimaux attendus).")

    key = nr.Key(
        host=url.hostname,
        port=url.port or 443,
        token=token,
        password=password,
        fingerprint=hashlib.sha256(der).digest(),
        passphrase=passphrase,
    )
    return nr.run_channel(key, e2e=e2e)


if __name__ == "__main__":
    raise SystemExit(main())
