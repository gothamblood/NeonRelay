#!/usr/bin/env python3
"""NeonRelay — client autonome (un seul fichier), canal chiffré de bout en bout.

Tout tient dans UNE clé « dumb » (tapée par le Digispark dans l'invite masquée) :
adresse du serveur, token + mot de passe de la boîte, empreinte SHA-256 du
certificat du serveur, passphrase E2E. Aucun autre fichier n'est nécessaire,
à part openssl-tls.cnf posé à côté de ce script (ML-KEM obligatoire).

Usage :
    python neonrelay.py                 # demande la clé, puis le PIN (optionnel), ouvre le canal
    python neonrelay.py check-key       # décode une clé, affiche son contenu public
    python neonrelay.py make-pin        # (opérateur) tire un PIN de 12 caractères à imprimer
    python neonrelay.py make-key --base https://IP:8000 --cert cert.pem [--creds last-token.env]
                                 [--clavier ca-fr --ino cle]
                                        # (opérateur) fabrique la clé (+ firmwares Digispark
                                        #  cle-windows.ino et cle-linux.ino)
    python neonrelay.py claviers        # dispositions de clavier prises en charge

Compatibilité : SANS PIN, même chiffrement que scripts/base/_crypto.py
(SecretBox, clé = SHA-256 de la passphrase, nonce + chiffré en base64), donc ce
client parle avec secure-shell.sh sur la même boîte. AVEC PIN, la clé E2E vient
d'Argon2id (voir « PIN optionnel ») : seuls les clients qui ont le PIN se lisent.

Prérequis : Python avec OpenSSL ≥ 3.5 (ML-DSA-87 + ML-KEM) et PyNaCl.
"""
import os
import sys

# Groupes TLS (ML-KEM obligatoire) : Python ne sait pas les régler lui-même, on
# passe par une config OpenSSL propre au process. Elle doit être posée AVANT le
# premier import de ssl (http.client l'importe), sinon OpenSSL l'ignore.
_HERE = os.path.dirname(os.path.abspath(__file__))
_TLS_CNF = os.path.join(_HERE, "openssl-tls.cnf")
if os.path.isfile(_TLS_CNF):
    os.environ["OPENSSL_CONF"] = _TLS_CNF

import argparse  # noqa: E402
import base64  # noqa: E402
import getpass  # noqa: E402
import hashlib  # noqa: E402
import hmac  # noqa: E402
import http.client  # noqa: E402
import json  # noqa: E402
import secrets  # noqa: E402
import ssl  # noqa: E402
import struct  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
import urllib.parse  # noqa: E402
from dataclasses import dataclass  # noqa: E402

KEY_PREFIX = "NR"
KEY_VERSION = 1
_CHECKSUM_LEN = 4
_PW_HEADER = "X-NeonRelay-Password"


class KeyError_(Exception):
    """Clé illisible : faute de frappe, clé tronquée ou format inconnu."""


class CertError(Exception):
    """Le serveur ne présente pas le certificat attendu (homme du milieu ?).
    (Épinglage du CERTIFICAT : sans rapport avec le PIN de l'utilisateur.)"""


# ---------------------------------------------------------------------------
# Format de la clé
#
#   "NR" + base32( payload + sha256(payload)[:4] )   (sans "=", insensible à la casse)
#   payload = version(1) | host(str) | port(u16) | token(str) | password(str)
#             | fingerprint(32) | passphrase(str)        str = longueur(u8) + UTF-8
#
# Base32 = lettres A-Z et chiffres 2-7 seulement : aucun symbole, donc rien qui
# change entre claviers QWERTY (US, canadien). La casse est ignorée au décodage
# (Verr. Maj. activé pendant que le Digispark tape = sans effet).
# ---------------------------------------------------------------------------


@dataclass
class Key:
    host: str
    port: int
    token: str
    password: str
    fingerprint: bytes
    passphrase: str


def _pack_str(value: str) -> bytes:
    raw = value.encode("utf-8")
    if len(raw) > 255:
        raise ValueError("champ trop long (255 octets max)")
    return bytes([len(raw)]) + raw


def encode_key(key: Key) -> str:
    if len(key.fingerprint) != 32:
        raise ValueError("empreinte SHA-256 attendue (32 octets)")
    payload = (
        bytes([KEY_VERSION])
        + _pack_str(key.host)
        + struct.pack(">H", key.port)
        + _pack_str(key.token)
        + _pack_str(key.password)
        + key.fingerprint
        + _pack_str(key.passphrase)
    )
    blob = payload + hashlib.sha256(payload).digest()[:_CHECKSUM_LEN]
    return KEY_PREFIX + base64.b32encode(blob).decode("ascii").rstrip("=")


def decode_key(text: str) -> Key:
    s = "".join(text.split()).replace("-", "").upper()
    if not s.startswith(KEY_PREFIX):
        raise KeyError_("ce n'est pas une clé NeonRelay")
    body = s[len(KEY_PREFIX):]
    try:
        blob = base64.b32decode(body + "=" * (-len(body) % 8))
    except (ValueError, TypeError):
        raise KeyError_("caractère invalide (faute de frappe ?)")
    if len(blob) <= _CHECKSUM_LEN:
        raise KeyError_("clé trop courte")
    payload, checksum = blob[:-_CHECKSUM_LEN], blob[-_CHECKSUM_LEN:]
    if not hmac.compare_digest(hashlib.sha256(payload).digest()[:_CHECKSUM_LEN], checksum):
        raise KeyError_("somme de contrôle fausse (clé mal tapée ou tronquée)")

    pos = 0

    def take(n: int) -> bytes:
        nonlocal pos
        if pos + n > len(payload):
            raise KeyError_("clé tronquée")
        chunk = payload[pos:pos + n]
        pos += n
        return chunk

    def take_str() -> str:
        return take(take(1)[0]).decode("utf-8")

    version = take(1)[0]
    if version != KEY_VERSION:
        raise KeyError_(f"version de clé {version} non prise en charge")
    host = take_str()
    (port,) = struct.unpack(">H", take(2))
    token = take_str()
    password = take_str()
    fingerprint = take(32)
    passphrase = take_str()
    if pos != len(payload):
        raise KeyError_("données en trop dans la clé")
    if not passphrase:
        # Sans passphrase, le canal circulerait en clair : on refuse.
        raise KeyError_("clé sans passphrase E2E")
    return Key(host, port, token, password, fingerprint, passphrase)


def _fmt_fingerprint(fp: bytes) -> str:
    return ":".join(f"{b:02X}" for b in fp)


# ---------------------------------------------------------------------------
# Dispositions de clavier (firmware Digispark)
#
# Le Digispark n'envoie pas des caractères mais des POSITIONS de touches (codes
# HID) : c'est la disposition choisie dans le système qui décide du caractère
# obtenu. La clé est donc la même pour tous ; seules les touches à presser
# changent. On tape tout en minuscules (le décodage ignore la casse), et seuls
# a-z et 2-7 apparaissent (« neonrelay » + base32).
# ---------------------------------------------------------------------------

_SHIFT = 0x02  # MOD_SHIFT_LEFT
_HID_ENTER = 40


def _qwerty(c: str) -> tuple[int, int]:
    if "a" <= c <= "z":
        return 4 + ord(c) - ord("a"), 0
    if "1" <= c <= "9":
        return 30 + ord(c) - ord("1"), 0
    if c == "0":
        return 39, 0
    raise ValueError(f"caractère non prévu : {c!r}")


def _azerty(c: str) -> tuple[int, int]:
    swap = {"a": "q", "q": "a", "z": "w", "w": "z"}
    if c == "m":
        return 51, 0  # touche « ; » du QWERTY
    if c in swap:
        return _qwerty(swap[c])
    if c.isdigit():
        code, _ = _qwerty(c)
        return code, _SHIFT  # chiffres en Maj sur la rangée du haut
    return _qwerty(c)


def _qwertz(c: str) -> tuple[int, int]:
    return _qwerty({"y": "z", "z": "y"}.get(c, c))


KEYBOARDS = {
    "us": ("Anglais (États-Unis)", _qwerty),
    "ca-fr": ("Français (Canada) — CSA", _qwerty),
    "ca-multi": ("Multilingue canadien standard", _qwerty),
    "uk": ("Anglais (Royaume-Uni)", _qwerty),
    "fr-azerty": ("Français (France) — AZERTY", _azerty),
    "be-azerty": ("Français/néerlandais (Belgique) — AZERTY", _azerty),
    "ch-qwertz": ("Suisse (français/allemand) — QWERTZ", _qwertz),
    "de-qwertz": ("Allemand — QWERTZ", _qwertz),
}


def _hid_bytes(text: str, layout) -> list[int]:
    out = []
    for c in text.lower():
        out.extend(layout(c))
    return out


# Systèmes visés par le firmware : comment ouvrir l'endroit où taper « neonrelay ».
#   windows : Win+R (boîte « Exécuter ») ;
#   linux   : Ctrl+Alt+T (terminal ; GNOME/Ubuntu, Kali XFCE…), ~/.local/bin
#             devant être dans le PATH (Debian/Ubuntu/Kali : via ~/.profile).
# La touche T et la touche R sont au même endroit en QWERTY, AZERTY et QWERTZ.
SKETCH_OS = {
    "windows": ("Windows", "Win+R",
                "DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);                  // Win+R",
                800),
    "linux": ("Linux", "Ctrl+Alt+T",
              "DigiKeyboard.sendKeyStroke(KEY_T, MOD_CONTROL_LEFT | MOD_ALT_LEFT); // Ctrl+Alt+T",
              1500),
}


def digispark_sketch(key_text: str, clavier: str, python_delay_ms: int,
                     target: str = "windows") -> str:
    label, layout = KEYBOARDS[clavier]
    os_label, shortcut, open_stroke, open_delay_ms = SKETCH_OS[target]

    def array(name: str, data: list[int]) -> str:
        rows = [", ".join(f"{b:3d}" for b in data[i:i + 16]) for i in range(0, len(data), 16)]
        return f"const uint8_t {name}[] PROGMEM = {{\n  " + ",\n  ".join(rows) + "\n};"

    return f"""// NeonRelay — firmware Digispark ({os_label}) généré par : neonrelay.py make-key --clavier {clavier}
// Disposition clavier visée ({os_label}) : {label}
//
// ⚠️ CE FICHIER CONTIENT LA CLÉ COMPLÈTE : aussi secret que le Digispark lui-même.
//    Flasher, puis supprimer le fichier.
//
// Séquence : {shortcut} → « neonrelay » → Entrée → attente → clé → Entrée.
// Les tableaux contiennent des paires (code de touche HID, modificateur).
#include "DigiKeyboard.h"
#include <avr/pgmspace.h>

{array("LAUNCH", _hid_bytes("neonrelay", layout))}

{array("KEY", _hid_bytes(key_text, layout))}

static void typeSeq(const uint8_t *seq, uint16_t len) {{
  for (uint16_t i = 0; i < len; i += 2) {{
    DigiKeyboard.sendKeyStroke(pgm_read_byte(seq + i), pgm_read_byte(seq + i + 1));
  }}
}}

void setup() {{
  DigiKeyboard.sendKeyStroke(0);
  DigiKeyboard.delay(1500);                         // le système reconnaît le « clavier »
  {open_stroke}
  DigiKeyboard.delay({open_delay_ms});
  typeSeq(LAUNCH, sizeof(LAUNCH));
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay({python_delay_ms});                         // démarrage du client
  typeSeq(KEY, sizeof(KEY));
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
}}

void loop() {{
  DigiKeyboard.delay(10000);
}}
"""


# ---------------------------------------------------------------------------
# Chiffrement de bout en bout (identique à scripts/base/_crypto.py)
# ---------------------------------------------------------------------------


def _secretbox(passphrase: str, token: str = "", pin: str = ""):
    try:
        from nacl.secret import SecretBox
    except ImportError:
        raise SystemExit("PyNaCl manque : réinstalle le client (install.cmd).")
    return SecretBox(e2e_key(passphrase, token, pin))


def encrypt(box, text: str) -> bytes:
    return base64.b64encode(box.encrypt(text.encode("utf-8")))


def decrypt(box, token: str):
    """Texte en clair, ou None si le message ne se déchiffre pas avec cette clé."""
    from nacl.exceptions import CryptoError

    try:
        return box.decrypt(base64.b64decode(token)).decode("utf-8", "replace")
    except (CryptoError, ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# PIN optionnel : seconde couche de chiffrement de bout en bout
#
# La MÊME clé fonctionne avec ou sans PIN :
#   sans PIN : clé E2E = SHA-256(passphrase)                (scripts bash)
#   avec PIN : clé E2E = Argon2id(passphrase + PIN, sel de la boîte)
# Sans le PIN, la boîte s'ouvre mais les messages protégés restent illisibles ;
# un message envoyé sans le PIN s'affiche « illisible » chez ceux qui l'ont
# (alarme). Rien dans la clé ne permet de vérifier un PIN hors ligne : seul un
# message déchiffré confirme qu'il est bon.
#
# PIN = 12 caractères base32 Crockford (0-9 et A-Z sans I, L, O, U) = 60 bits.
# À la saisie : casse, espaces et tirets ignorés ; O lu comme 0, I et L comme 1.
# Argon2id « MODERATE » de libsodium : 3 passes, 256 Mio par essai.
# ---------------------------------------------------------------------------

PIN_LEN = 12
PIN_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
PIN_TIMEOUT = 7.0
_PIN_FIX = str.maketrans({"O": "0", "I": "1", "L": "1"})
_PIN_SALT_CONTEXT = b"neonrelay-pin-v1\x00"


def normalize_pin(text: str) -> str:
    s = "".join(text.split()).replace("-", "").upper().translate(_PIN_FIX)
    if len(s) != PIN_LEN or any(c not in PIN_ALPHABET for c in s):
        raise ValueError(f"le PIN fait {PIN_LEN} caractères (chiffres et lettres)")
    return s


def format_pin(pin: str) -> str:
    return "-".join(pin[i:i + 4] for i in range(0, len(pin), 4))


def make_pin() -> str:
    return "".join(secrets.choice(PIN_ALPHABET) for _ in range(PIN_LEN))


def e2e_key(passphrase: str, token: str = "", pin: str = "") -> bytes:
    if not pin:
        return hashlib.sha256(passphrase.encode("utf-8")).digest()
    from nacl.pwhash import argon2id

    # Sel propre à la boîte : un calcul fait pour une boîte ne sert à rien
    # pour une autre. La passphrase est préfixée de sa longueur (pas d'ambiguïté
    # entre passphrase et PIN).
    salt = hashlib.sha256(_PIN_SALT_CONTEXT + token.encode("utf-8")).digest()[:argon2id.SALTBYTES]
    return argon2id.kdf(
        32,
        _pack_str(passphrase) + normalize_pin(pin).encode("ascii"),
        salt,
        opslimit=argon2id.OPSLIMIT_MODERATE,
        memlimit=argon2id.MEMLIMIT_MODERATE,
    )


def _read_masked(prompt: str, timeout: float) -> tuple[str, bool]:
    """Saisie masquée (une « * » par caractère). Le délai repart à chaque touche.
    Renvoie (texte, délai_écoulé)."""
    sys.stdout.write(prompt)
    sys.stdout.flush()
    if not sys.stdin.isatty():  # tests / redirection : une ligne, sans délai
        return sys.stdin.readline().strip(), False

    buf: list[str] = []
    timed_out = False

    def key(ch: str) -> bool:
        """Traite une touche ; True = saisie terminée."""
        if ch in ("\r", "\n"):
            return True
        if ch == "\x03":
            raise KeyboardInterrupt
        if ch in ("\b", "\x7f"):
            if buf:
                buf.pop()
                sys.stdout.write("\b \b")
        elif ch.isprintable():
            buf.append(ch)
            sys.stdout.write("*")
        sys.stdout.flush()
        return False

    if os.name == "nt":
        import msvcrt

        deadline = time.monotonic() + timeout
        while True:
            if msvcrt.kbhit():
                ch = msvcrt.getwch()
                deadline = time.monotonic() + timeout
                if ch in ("\x00", "\xe0"):  # flèches, F1… : touche spéciale, ignorée
                    msvcrt.getwch()
                    continue
                if key(ch):
                    break
            elif time.monotonic() >= deadline:
                timed_out = True
                break
            else:
                time.sleep(0.02)
    else:
        import select
        import termios
        import tty

        fd = sys.stdin.fileno()
        saved = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)  # caractère par caractère, sans écho
            while True:
                ready, _, _ = select.select([fd], [], [], timeout)
                if not ready:
                    timed_out = True
                    break
                if key(os.read(fd, 1).decode("utf-8", "ignore")):
                    break
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, saved)
    sys.stdout.write("\n")
    sys.stdout.flush()
    return ("" if timed_out else "".join(buf)), timed_out


def _ask_pin() -> str:
    """PIN normalisé, ou "" pour continuer sans PIN (Entrée seule ou délai écoulé)."""
    for _ in range(3):
        text, timed_out = _read_masked(
            f"PIN (optionnel — Entrée ou {int(PIN_TIMEOUT)} s sans toucher = sans PIN) : ", PIN_TIMEOUT)
        if not text:
            if timed_out:
                print("   Délai écoulé : canal ouvert SANS PIN.")
            return ""
        try:
            return normalize_pin(text)
        except ValueError as exc:
            print(f"❌ PIN invalide : {exc}.")
    raise SystemExit(1)


# ---------------------------------------------------------------------------
# Transport : TLS 1.3 + ML-KEM (openssl-tls.cnf), certificat épinglé par empreinte
# ---------------------------------------------------------------------------


def _tls_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    # Pas d'autorité de certification : la confiance vient de l'empreinte
    # vérifiée ci-dessous. La poignée de main prouve quand même que le serveur
    # détient la clé privée de ce certificat (signature ML-DSA-87).
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


_CTX = None


def connect(key: Key, timeout: float = 15) -> http.client.HTTPSConnection:
    """Connexion TLS dont le certificat est vérifié AVANT d'envoyer quoi que ce soit."""
    global _CTX
    if _CTX is None:
        _CTX = _tls_context()
    conn = http.client.HTTPSConnection(key.host, key.port, context=_CTX, timeout=timeout)
    conn.connect()
    der = conn.sock.getpeercert(binary_form=True)
    if not der or not hmac.compare_digest(hashlib.sha256(der).digest(), key.fingerprint):
        conn.close()
        raise CertError("certificat du serveur inattendu : connexion coupée, rien n'a été envoyé")
    return conn


def _http_error(status: int) -> str:
    return {
        401: "boîte inconnue ou mot de passe refusé (clé périmée ?)",
        410: "boîte expirée",
        429: "trop de messages, réessaie dans un instant",
    }.get(status, f"erreur HTTP {status}")


def send(key: Key, box, text: str) -> None:
    conn = connect(key)
    try:
        conn.request(
            "POST",
            f"/relay/{key.token}/hook",
            body=encrypt(box, text),
            headers={_PW_HEADER: key.password, "Content-Type": "text/plain"},
        )
        resp = conn.getresponse()
        resp.read()
        if resp.status >= 300:
            raise RuntimeError(_http_error(resp.status))
    finally:
        conn.close()


def _listen_once(key: Key, on_message, on_ready) -> None:
    """on_message reçoit le corps chiffré (base64) de chaque message."""
    conn = connect(key)
    try:
        conn.request("GET", f"/listen/{key.token}", headers={_PW_HEADER: key.password})
        resp = conn.getresponse()
        if resp.status != 200:
            raise RuntimeError(_http_error(resp.status))
        conn.sock.settimeout(None)  # flux SSE : on attend aussi longtemps qu'il faut
        on_ready()
        while True:
            line = resp.readline()
            if not line:
                raise ConnectionError("flux fermé par le serveur")
            if not line.startswith(b"data:"):
                continue
            try:
                event = json.loads(line[5:].strip())
            except ValueError:
                continue
            if "body_text" in event:
                on_message(event["body_text"])
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Canal interactif
# ---------------------------------------------------------------------------


def _say(text: str) -> None:
    sys.stdout.write("\r" + text + "\n→ ")
    sys.stdout.flush()


def run_channel(key: Key, pin: str = "") -> int:
    if pin:
        print("   Dérivation de la clé (Argon2id)…", flush=True)
    box = _secretbox(key.passphrase, key.token, pin)
    mode = "AVEC PIN" if pin else "SANS PIN"
    print(f"🔒 Canal chiffré {mode} — boîte {key.token[:8]}… sur {key.host}:{key.port}")
    if pin:
        unreadable = "⚠️  [message illisible : envoyé sans le bon PIN — intrus possible]"
    else:
        print("   Sans PIN, les messages protégés par un PIN s'affichent illisibles.")
        unreadable = "[message illisible : protégé par un PIN, autre passphrase ou altéré]"
    print("   Tape un message puis Entrée pour l'envoyer ; Ctrl+C pour quitter.\n")

    def show(token: str) -> None:
        text = decrypt(box, token)
        _say(f"← {text}" if text is not None else unreadable)

    stop = threading.Event()
    ready = threading.Event()
    fatal: list[str] = []

    def listener() -> None:
        delay = 2
        while not stop.is_set():
            try:
                _listen_once(key, show, ready.set)
            except CertError as exc:
                fatal.append(str(exc))
                ready.set()
                return
            except RuntimeError as exc:  # 401 / 410 : inutile d'insister
                fatal.append(str(exc))
                ready.set()
                return
            except (OSError, ConnectionError, http.client.HTTPException):
                if not ready.is_set():
                    fatal.append("serveur injoignable")
                    ready.set()
                    return
                _say(f"⚠️  écoute coupée, reconnexion dans {delay} s…")
                if stop.wait(delay):
                    return
                delay = min(delay * 2, 60)
            else:
                delay = 2

    threading.Thread(target=listener, daemon=True).start()
    ready.wait(20)
    if fatal:
        print(f"❌ {fatal[0]}")
        return 1

    try:
        while True:
            text = input("→ ")
            if not text:
                continue
            try:
                send(key, box, text)
            except CertError as exc:
                print(f"❌ {exc}")
                return 1
            except (RuntimeError, OSError, http.client.HTTPException) as exc:
                print(f"⚠️  non envoyé : {exc}")
    except (KeyboardInterrupt, EOFError):
        print("\nCanal fermé.")
        return 0
    finally:
        stop.set()


def _ask_key() -> Key:
    for attempt in range(3):
        try:
            return decode_key(getpass.getpass("Clé : "))
        except KeyError_ as exc:
            print(f"❌ Clé invalide : {exc}.")
    raise SystemExit(1)


# ---------------------------------------------------------------------------
# Commandes
# ---------------------------------------------------------------------------


def cmd_run(_args) -> int:
    key = _ask_key()
    return run_channel(key, _ask_pin())


def cmd_make_pin(_args) -> int:
    print("PIN à imprimer pour le colis PIN (même PIN pour tout le canal).", file=sys.stderr)
    print("Ne pas le conserver : ni fichier, ni historique, ni photo.", file=sys.stderr)
    print(format_pin(make_pin()))
    return 0


def cmd_check(_args) -> int:
    key = _ask_key()
    print(f"Serveur    : {key.host}:{key.port}")
    print(f"Boîte      : {key.token}")
    print(f"Empreinte  : {_fmt_fingerprint(key.fingerprint)}")
    print("Secrets    : mot de passe de boîte + passphrase E2E présents (non affichés)")
    return 0


def _read_env_file(path: str) -> dict:
    values = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                values[k.strip()] = v.strip().strip('"').strip("'")
    return values


def cmd_make(args) -> int:
    url = urllib.parse.urlsplit(args.base)
    if url.scheme != "https" or not url.hostname:
        raise SystemExit("--base doit être de la forme https://HÔTE:PORT")
    with open(args.cert, encoding="ascii") as fh:
        fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(fh.read())).digest()

    creds = _read_env_file(args.creds) if args.creds else {}
    token = creds.get("NEONRELAY_TOKEN") or input("Token (id de la boîte) : ").strip()
    password = creds.get("NEONRELAY_PW") or getpass.getpass("Mot de passe de la boîte : ")
    passphrase = getpass.getpass("Passphrase E2E (vide = aléatoire) : ")
    if not passphrase:
        passphrase = secrets.token_urlsafe(32)
    elif len(passphrase) < 16:
        raise SystemExit("Passphrase trop courte (16 caractères minimum ; vide = aléatoire).")

    key = Key(url.hostname, url.port or 443, token, password, fingerprint, passphrase)
    text = encode_key(key)
    assert decode_key(text) == key

    if not args.offline:
        conn = connect(key)  # vérifie l'empreinte contre le vrai serveur
        try:
            conn.request("GET", f"/listen/{token}/count", headers={_PW_HEADER: password})
            resp = conn.getresponse()
            resp.read()
            if resp.status != 200:
                raise SystemExit(f"Le serveur refuse ces identifiants : {_http_error(resp.status)}.")
        finally:
            conn.close()
        print("✅ Serveur joint, certificat et identifiants vérifiés.", file=sys.stderr)

    print(f"Serveur   : {key.host}:{key.port}", file=sys.stderr)
    print(f"Empreinte : {_fmt_fingerprint(fingerprint)}", file=sys.stderr)
    print(f"Longueur  : {len(text)} caractères", file=sys.stderr)
    print("La même clé va dans les Digispark des deux correspondants.", file=sys.stderr)
    if args.ino:
        # Deux firmwares, un par système : cle.ino → cle-windows.ino + cle-linux.ino.
        base = args.ino[:-4] if args.ino.lower().endswith(".ino") else args.ino
        for target in SKETCH_OS:
            path = f"{base}-{target}.ino"
            # Fichier secret (il contient la clé) : lisible par son seul propriétaire.
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(digispark_sketch(text, args.clavier, args.delai_python, target))
            print(f"Firmware  : {path} ({SKETCH_OS[target][0]}, {SKETCH_OS[target][1]} ; "
                  f"clavier {args.clavier} — {KEYBOARDS[args.clavier][0]})", file=sys.stderr)
    print(text)
    return 0


def cmd_keyboards(_args) -> int:
    for code, (label, _) in KEYBOARDS.items():
        print(f"{code:10}  {label}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="neonrelay", description="Client NeonRelay (canal chiffré).")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("check-key", help="décode une clé et affiche son contenu public")
    mk = sub.add_parser("make-key", help="(opérateur) fabrique une clé à flasher")
    mk.add_argument("--base", required=True, help="https://HÔTE:PORT du serveur")
    mk.add_argument("--cert", required=True, help="cert.pem du serveur (pour l'empreinte)")
    mk.add_argument("--creds", help="fichier last-token.env (sinon demandé)")
    mk.add_argument("--offline", action="store_true", help="ne pas tester contre le serveur")
    mk.add_argument("--clavier", choices=sorted(KEYBOARDS), default="us",
                    help="disposition clavier du poste client (défaut : us ; voir « claviers »)")
    mk.add_argument("--ino", metavar="NOM",
                    help="écrire aussi les firmwares Digispark : NOM-windows.ino et NOM-linux.ino")
    mk.add_argument("--delai-python", type=int, default=4000, metavar="MS",
                    help="attente entre le lancement et la frappe de la clé (défaut : 4000)")
    sub.add_parser("claviers", help="liste les dispositions de clavier prises en charge")
    sub.add_parser("make-pin", help="(opérateur) tire un PIN de 12 caractères à imprimer")
    args = parser.parse_args(argv)

    handler = {"check-key": cmd_check, "make-key": cmd_make, "claviers": cmd_keyboards,
               "make-pin": cmd_make_pin}.get(args.cmd, cmd_run)
    try:
        return handler(args)
    except CertError as exc:
        print(f"❌ {exc}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nAnnulé.", file=sys.stderr)
        return 130
    except (OSError, http.client.HTTPException) as exc:
        print(f"❌ Serveur injoignable : {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    code = main()
    # Lancé par Win+R, la fenêtre se fermerait avant qu'on lise l'erreur.
    if code and os.name == "nt" and sys.stdin.isatty():
        input("\nEntrée pour fermer…")
    raise SystemExit(code)
