#!/usr/bin/env python3
"""Chiffrement de bout en bout pour NeonRelay (côté client).

Le corps relayé est chiffré AVANT l'envoi et déchiffré APRÈS réception, avec
une clé symétrique partagée. NeonRelay ne voit que du base64 opaque : il ne
peut ni lire ni altérer le message (AEAD XSalsa20-Poly1305 via libsodium).

La clé n'est JAMAIS lue depuis un fichier : seulement depuis la variable
d'environnement NEONRELAY_KEY (gardée en RAM par le shell appelant). Si elle
est absente/vide, chiffrement et déchiffrement sont neutres (passthrough), pour
rester compatible avec un usage en clair. Si elle est définie mais que PyNaCl
manque, on REFUSE d'envoyer en clair (échec bruyant) plutôt que de fuiter.

Usage (filtre stdin -> stdout) :
    NEONRELAY_KEY=... python3 _crypto.py encrypt   # octets clairs -> base64
    NEONRELAY_KEY=... python3 _crypto.py decrypt   # base64 -> octets clairs
"""
import base64
import hashlib
import os
import sys

_KEY_ENV = "NEONRELAY_KEY"


class DecryptError(Exception):
    """Déchiffrement raté : mauvaise clé, message altéré, ou corps non chiffré."""


def _secretbox():
    """SecretBox dérivée de NEONRELAY_KEY, ou None si pas de clé (passthrough)."""
    secret = os.environ.get(_KEY_ENV, "")
    if not secret:
        return None
    try:
        from nacl.secret import SecretBox
    except ImportError:
        # Une clé est demandée mais la crypto manque : on ne tombe PAS en clair.
        raise SystemExit(
            "NeonRelay: NEONRELAY_KEY est définie mais PyNaCl manque "
            "(pip install pynacl) — envoi/réception en clair refusé."
        )
    # SHA-256 normalise n'importe quelle passphrase en une clé de 32 octets,
    # de façon déterministe des deux côtés (aucun sel à échanger).
    return SecretBox(hashlib.sha256(secret.encode("utf-8")).digest())


def encrypt(data: bytes) -> bytes:
    """Octets clairs -> jeton base64 (nonce + chiffré), ou passthrough sans clé."""
    box = _secretbox()
    if box is None:
        return data
    # SecretBox préfixe un nonce aléatoire de 24 octets ; on encode le tout en
    # base64 pour voyager comme un corps texte à travers le relai.
    return base64.b64encode(box.encrypt(data))


def decrypt(token: bytes) -> bytes:
    """Jeton base64 -> octets clairs, ou passthrough sans clé. Lève DecryptError."""
    box = _secretbox()
    if box is None:
        return token
    from nacl.exceptions import CryptoError

    try:
        return box.decrypt(base64.b64decode(token))
    except (CryptoError, ValueError, TypeError) as exc:
        raise DecryptError(str(exc))


def _main(argv):
    if len(argv) != 2 or argv[1] not in ("encrypt", "decrypt"):
        sys.stderr.write("usage: _crypto.py {encrypt|decrypt}  (filtre stdin->stdout)\n")
        return 2
    data = sys.stdin.buffer.read()
    try:
        out = encrypt(data) if argv[1] == "encrypt" else decrypt(data)
    except DecryptError as exc:
        sys.stderr.write(f"NeonRelay: déchiffrement impossible ({exc}).\n")
        return 1
    sys.stdout.buffer.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
