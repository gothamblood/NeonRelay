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

PIN optionnel (même calcul que client/neonrelay.py, les deux se lisent) :
    sans PIN : clé E2E = SHA-256(passphrase)
    avec PIN : clé E2E = Argon2id(passphrase + PIN, sel tiré du token de la boîte)
Argon2id coûte ~1 s et 256 Mio : on ne le calcule qu'UNE fois par session
(commande « derive », PIN lu sur stdin), puis la clé dérivée (hex) voyage en RAM
dans NEONRELAY_E2E, prioritaire sur NEONRELAY_KEY.

Usage (filtre stdin -> stdout) :
    NEONRELAY_KEY=... python3 _crypto.py encrypt   # octets clairs -> base64
    NEONRELAY_KEY=... python3 _crypto.py decrypt   # base64 -> octets clairs
    NEONRELAY_KEY=... NEONRELAY_TOKEN=... python3 _crypto.py derive   # PIN (stdin) -> clé hex
"""
import base64
import hashlib
import os
import sys

_KEY_ENV = "NEONRELAY_KEY"
_E2E_ENV = "NEONRELAY_E2E"   # clé déjà dérivée (64 hex), posée par secure-shell.sh

# PIN : 12 caractères base32 Crockford. Doit rester IDENTIQUE à client/neonrelay.py.
PIN_LEN = 12
PIN_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_PIN_FIX = str.maketrans({"O": "0", "I": "1", "L": "1"})
_PIN_SALT_CONTEXT = b"neonrelay-pin-v1\x00"


class DecryptError(Exception):
    """Déchiffrement raté : mauvaise clé, message altéré, ou corps non chiffré."""


def normalize_pin(text: str) -> str:
    """Casse, espaces et tirets ignorés ; O lu comme 0, I et L comme 1."""
    s = "".join(text.split()).replace("-", "").upper().translate(_PIN_FIX)
    if len(s) != PIN_LEN or any(c not in PIN_ALPHABET for c in s):
        raise ValueError(f"le PIN fait {PIN_LEN} caractères (chiffres et lettres)")
    return s


def derive_key(passphrase: str, token: str, pin: str = "") -> bytes:
    """Clé E2E de 32 octets : SHA-256 sans PIN, Argon2id avec (cf. neonrelay.py)."""
    if not pin:
        return hashlib.sha256(passphrase.encode("utf-8")).digest()
    from nacl.pwhash import argon2id

    raw = passphrase.encode("utf-8")
    if len(raw) > 255:
        raise ValueError("passphrase trop longue (255 octets max)")
    # Sel propre à la boîte ; passphrase préfixée de sa longueur (pas d'ambiguïté
    # entre passphrase et PIN).
    salt = hashlib.sha256(_PIN_SALT_CONTEXT + token.encode("utf-8")).digest()[:argon2id.SALTBYTES]
    return argon2id.kdf(
        32,
        bytes([len(raw)]) + raw + normalize_pin(pin).encode("ascii"),
        salt,
        opslimit=argon2id.OPSLIMIT_MODERATE,
        memlimit=argon2id.MEMLIMIT_MODERATE,
    )


def _secretbox():
    """SecretBox de NEONRELAY_E2E (clé dérivée) ou NEONRELAY_KEY, ou None (passthrough)."""
    derived = os.environ.get(_E2E_ENV, "")
    secret = os.environ.get(_KEY_ENV, "")
    if not derived and not secret:
        return None
    try:
        from nacl.secret import SecretBox
    except ImportError:
        # Une clé est demandée mais la crypto manque : on ne tombe PAS en clair.
        raise SystemExit(
            "NeonRelay: NEONRELAY_KEY est définie mais PyNaCl manque "
            "(pip install pynacl) — envoi/réception en clair refusé."
        )
    if derived:
        try:
            key = bytes.fromhex(derived)
        except ValueError:
            key = b""
        if len(key) != 32:
            raise SystemExit("NeonRelay: NEONRELAY_E2E invalide (64 caractères hexadécimaux attendus).")
        return SecretBox(key)
    # Sans PIN : SHA-256 normalise n'importe quelle passphrase en une clé de 32
    # octets, de façon déterministe des deux côtés (aucun sel à échanger).
    return SecretBox(derive_key(secret, ""))


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


def _derive_main() -> int:
    """PIN sur stdin (jamais en argument : visible dans ps) -> clé hex sur stdout."""
    secret = os.environ.get(_KEY_ENV, "")
    token = os.environ.get("NEONRELAY_TOKEN") or os.environ.get("TOKEN", "")
    if not secret or not token:
        sys.stderr.write("NeonRelay: derive demande NEONRELAY_KEY et NEONRELAY_TOKEN.\n")
        return 2
    try:
        key = derive_key(secret, token, sys.stdin.readline().strip())
    except ImportError:
        sys.stderr.write("NeonRelay: PyNaCl manque (pip install pynacl).\n")
        return 2
    except ValueError as exc:
        sys.stderr.write(f"NeonRelay: {exc}.\n")
        return 1
    sys.stdout.write(key.hex() + "\n")
    return 0


def _main(argv):
    if len(argv) == 2 and argv[1] == "derive":
        return _derive_main()
    if len(argv) != 2 or argv[1] not in ("encrypt", "decrypt"):
        sys.stderr.write("usage: _crypto.py {encrypt|decrypt|derive}  (filtre stdin->stdout)\n")
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
