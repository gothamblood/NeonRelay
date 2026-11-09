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
                                 [--clavier ca-multi --ino cle] [--amorce URL]
                                        # (opérateur) fabrique la clé (+ firmwares Digispark
                                        #  cle-windows.ino et cle-linux.ino ; avec --amorce,
                                        #  le Digispark Windows installe le client si absent)
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
import re  # noqa: E402
import secrets  # noqa: E402
import ssl  # noqa: E402
import struct  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
import urllib.parse  # noqa: E402
import urllib.request  # noqa: E402
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


_ALTGR = 0x40  # MOD_ALT_RIGHT : AltGr sous Windows
_HID_SPACE = 44

# Symboles de la commande d'amorçage (Windows) : caractère → (code HID, modificateur).
# Contrairement aux lettres et chiffres, ils changent de place d'un clavier à
# l'autre : seuls les claviers listés ici acceptent --amorce. Toute table neuve
# se valide d'abord avec « neonrelay.py test-clavier » (frappe sans clé, sans exécution).
SYMBOLS = {
    "us": {
        "!": (30, _SHIFT), "@": (31, _SHIFT), "#": (32, _SHIFT), "$": (33, _SHIFT),
        "%": (34, _SHIFT), "&": (36, _SHIFT), "*": (37, _SHIFT), "(": (38, _SHIFT),
        ")": (39, _SHIFT), "-": (45, 0), "_": (45, _SHIFT), "=": (46, 0), "+": (46, _SHIFT),
        "[": (47, 0), "{": (47, _SHIFT), "]": (48, 0), "}": (48, _SHIFT),
        "\\": (49, 0), "|": (49, _SHIFT), ";": (51, 0), ":": (51, _SHIFT),
        "'": (52, 0), '"': (52, _SHIFT), ",": (54, 0), ".": (55, 0),
        "/": (56, 0), "?": (56, _SHIFT),
    },
    # Multilingue canadien standard (CSA) : « / \ | » sur la touche à gauche du 1,
    # ' et " en Maj sur , et . ; { } [ ] en AltGr sur 7 8 9 0.
    "ca-multi": {
        "/": (53, 0), "\\": (53, _SHIFT), "|": (53, _ALTGR),
        "!": (30, _SHIFT), "@": (31, _SHIFT), "#": (32, _SHIFT), "$": (33, _SHIFT),
        "%": (34, _SHIFT), "?": (35, _SHIFT), "&": (36, _SHIFT), "*": (37, _SHIFT),
        "(": (38, _SHIFT), ")": (39, _SHIFT),
        "{": (36, _ALTGR), "}": (37, _ALTGR), "[": (38, _ALTGR), "]": (39, _ALTGR),
        "-": (45, 0), "_": (45, _SHIFT), "=": (46, 0), "+": (46, _SHIFT),
        ";": (51, 0), ":": (51, _SHIFT),
        ",": (54, 0), "'": (54, _SHIFT), ".": (55, 0), '"': (55, _SHIFT),
    },
}


# Windows : frappe UNIVERSELLE, indépendante de la disposition du clavier.
# Les lettres ci-dessous sont à la même place en QWERTY, AZERTY et QWERTZ : tapées
# normalement (Maj pour les majuscules). Tout le reste (chiffres, symboles,
# a q z w m y) passe par un code Alt : Alt maintenu + code décimal sur le pavé
# numérique, que Windows traduit lui-même quelle que soit la disposition.
# Marqueur dans les tableaux : modificateur ALT_CODE, code = caractère ASCII.
# ⚠️ Dépend du Verr. Num. (à valider : neonrelay.py test-clavier, firmware Windows).
_WIN_SAFE_LETTERS = set("bcdefghijklnoprstuvx")
ALT_CODE = 0xFF


def _win_bytes(text: str) -> list[int]:
    out = []
    for c in text:
        if c == " ":
            out.extend((_HID_SPACE, 0))
        elif c.lower() in _WIN_SAFE_LETTERS:
            code, _ = _qwerty(c.lower())
            out.extend((code, _SHIFT if c.isupper() else 0))
        elif 32 < ord(c) < 127:
            out.extend((ord(c), ALT_CODE))
        else:
            raise ValueError(f"caractère non prévu : {c!r}")
    return out


def _hid_bytes(text: str, layout, symbols: dict | None = None,
               keep_case: bool = False) -> list[int]:
    out = []
    for c in (text if keep_case else text.lower()):
        if c == " ":
            out.extend((_HID_SPACE, 0))
        elif c.isascii() and c.isalnum():
            code, mod = layout(c.lower())
            out.extend((code, mod | (_SHIFT if c.isupper() else 0)))
        elif symbols and c in symbols:
            out.extend(symbols[c])
        else:
            raise ValueError(f"caractère non prévu pour ce clavier : {c!r}")
    return out


# ---------------------------------------------------------------------------
# Amorçage : le Digispark installe le client s'il est absent (Windows ici, Linux plus bas)
# ---------------------------------------------------------------------------
# Tapé dans cmd (Win+R → cmd) : cmd ne garde aucun historique sur disque et
# l'historique Win+R ne retient que « cmd » ; une console PowerShell, elle,
# écrirait la ligne dans ConsoleHost_history.txt.
#   - client installé → lancé directement ;
#   - sinon → install.ps1 téléchargé depuis SOURCE, exécuté SEULEMENT si son
#     SHA-256 est celui gravé dans la clé (install.ps1 épingle à son tour
#     Python, PyNaCl, cffi, neonrelay.py, openssl-tls.cnf).
#   - en cas d'échec : boucle qui avale toutes les touches, pour que la clé,
#     déjà tapée en avance, n'atterrisse jamais en clair à une invite.
# ASCII seulement, et pas de « % » (cmd le développerait même entre guillemets).
_SOURCE_RE = re.compile(r"https?://[A-Za-z0-9.:/_-]+")

# Seul message TAPÉ par le Digispark : celui d'échec (aucun fichier vérifié
# n'existe alors pour l'afficher). Les autres sont dans install.ps1 / install.sh
# (exécutés seulement après contrôle de l'empreinte) et dans le client : moins à
# taper, donc plus rapide, et accents permis. ASCII ici, ni apostrophe ni « ! ».
_MSG_FAIL = "Echec : installation annulee. Debranche la cle et previens ton contact NeonRelay."

# La clé ne grave que les 32 premiers caractères hex (128 bits) de l'empreinte de
# l'installeur : -32 caractères à taper. Faire passer un autre fichier exigerait
# de retrouver ce préfixe (~2^128 essais) ; une collision (2^64) ne servirait
# qu'à l'opérateur lui-même, hors modèle de menace. Hex et non base64 : calculer
# du base64 dans la commande coûterait plus cher que ce qu'il fait gagner.
HASH_PREFIX = 32


def windows_bootstrap(source: str, install_sha256: str) -> str:
    source = source.rstrip("/")
    if not _SOURCE_RE.fullmatch(source):
        raise ValueError("URL d'amorçage invalide (http(s)://, lettres, chiffres, . : / _ - seulement)")
    if not re.fullmatch(r"[0-9a-f]{64}", install_sha256):
        raise ValueError("empreinte SHA-256 d'install.ps1 invalide")
    return (
        'powershell -nop -ep bypass -c "'
        "$ErrorActionPreference='Stop';cls;$f=$env:TEMP+'\\nr.ps1';"
        "try{$d=$env:LOCALAPPDATA+'\\NeonRelay\\bin\\neonrelay.cmd';"
        "if(!(test-path $d)){"
        f"iwr -useb '{source}/windows/install.ps1' -OutFile $f;"
        f"if((get-filehash $f).Hash -notlike '{install_sha256[:HASH_PREFIX]}*')"
        "{throw 'Installeur refuse : empreinte invalide.'};"
        f"&$f -Source '{source}';ri $f}};&$d}}"
        f"catch{{ri $f -ea 0;write-host $_ '{_MSG_FAIL}';"
        "while(1){$null=$host.ui.rawui.readkey(6)}}"  # 6 = NoEcho + IncludeKeyDown
        '"'
    )


# ---------------------------------------------------------------------------
# Amorçage Linux : même principe, tapé dans le terminal (Ctrl+Alt+T)
# ---------------------------------------------------------------------------
#   - espace en tête : ignorée par l'historique (zsh hist_ignore_space sous
#     Kali, bash HISTCONTROL=ignoreboth sous Debian/Ubuntu) + « unset HISTFILE »
#     (bash n'écrit rien en quittant) ;
#   - « stty -echo » : sous Linux le terminal affiche une touche DÈS son
#     arrivée ; sans lui, la clé tapée pendant l'installation s'afficherait en
#     clair. Il reste coupé jusqu'à ce que le client ait lu la clé (_read_key
#     le rétablit ensuite) ; en cas d'échec une boucle avale tout ;
#   - bash ET zsh : « =http,https » entre apostrophes (zsh développe « =mot »),
#     ni « ! » (historique), ni « ~ | < > [ ] » ; « * » sert au motif du préfixe
#     d'empreinte (case … in PREFIXE*). Messages : voir _MSG_FAIL.
def linux_bootstrap(source: str, install_sha256: str) -> str:
    source = source.rstrip("/")
    if not _SOURCE_RE.fullmatch(source):
        raise ValueError("URL d'amorçage invalide (http(s)://, lettres, chiffres, . : / _ - seulement)")
    if not re.fullmatch(r"[0-9a-f]{64}", install_sha256):
        raise ValueError("empreinte SHA-256 d'install.sh invalide")
    # « test "$(command -v curl)" » : choisit curl ou wget sans rien afficher.
    return (
        " unset HISTFILE;clear;n=$HOME/.local/bin/neonrelay;"
        f"u={source};f=$(mktemp);ok=;stty -echo;"
        "if test -x $n;then ok=1;else "
        'if test "$(command -v curl)";then curl -fsSL --proto \'=http,https\' -o $f $u/linux/install.sh;'
        "else wget -q -O $f $u/linux/install.sh;fi;"
        f"case $(sha256sum $f) in {install_sha256[:HASH_PREFIX]}*)bash $f --source $u&&ok=1;;esac;fi;"
        'rm -f $f;if test "$ok";then $n;stty echo;'
        f'else echo "{_MSG_FAIL}";while :;do read -r k;done;fi'
    )


# Installeur par système : chemin dans client/, et motifs des empreintes du
# client qu'il épingle (mises à jour par client/epingler.sh).
INSTALLERS = {
    "windows": ("windows/install.ps1", windows_bootstrap, {
        "neonrelay.py": r"Name = 'neonrelay\.py'; Sha256 = '([0-9a-f]{64})'",
        "openssl-tls.cnf": r"Name = 'openssl-tls\.cnf'; Sha256 = '([0-9a-f]{64})'",
    }),
    "linux": ("linux/install.sh", linux_bootstrap, {
        "neonrelay.py": r"NEONRELAY_PY_SHA='([0-9a-f]{64})'",
        "openssl-tls.cnf": r"OPENSSL_CNF_SHA='([0-9a-f]{64})'",
    }),
}
CLIENT_DIR = os.path.dirname(os.path.abspath(__file__))


def check_installer(target: str, client_dir: str = CLIENT_DIR) -> str:
    """Vérifie que l'installeur épingle bien les neonrelay.py / openssl-tls.cnf
    voisins ; renvoie son SHA-256 (celui que la clé grave)."""
    rel, _, patterns = INSTALLERS[target]
    path = os.path.join(client_dir, rel)
    with open(path, "rb") as fh:
        data = fh.read()
    text = data.decode("utf-8-sig")
    for name, pattern in patterns.items():
        m = re.search(pattern, text)
        if not m:
            raise SystemExit(f"❌ {rel} : empreinte de {name} introuvable.")
        with open(os.path.join(client_dir, name), "rb") as fh:
            if hashlib.sha256(fh.read()).hexdigest() != m.group(1):
                raise SystemExit(f"❌ {name} a changé depuis son épinglage dans {rel} : "
                                 "lancer client/epingler.sh, puis republier client/.")
    return hashlib.sha256(data).hexdigest()


def bootstraps(source: str, client_dir: str = CLIENT_DIR) -> dict[str, tuple[str, str]]:
    """{système: (commande d'amorçage, SHA-256 de l'installeur)}."""
    out = {}
    for target, (_, build, _) in INSTALLERS.items():
        sha = check_installer(target, client_dir)
        out[target] = (build(source, sha), sha)
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


def _c_array(name: str, data: list[int]) -> str:
    rows = [", ".join(f"{b:3d}" for b in data[i:i + 16]) for i in range(0, len(data), 16)]
    return f"const uint8_t {name}[] PROGMEM = {{\n  " + ",\n  ".join(rows) + "\n};"


# Frappe d'une séquence (paires code HID, modificateur). « pace » ajoute une
# courte pause entre les touches pour les longues commandes (rien ne se perd).
# Modificateur ALT_CODE (0xFF, Windows) : code Alt — Alt maintenu, chiffres du
# code décimal sur le pavé numérique (HID 89-97 = 1-9, 98 = 0), Alt relâché.
# Sans zéro en tête : page OEM, identique à l'ASCII pour 33-126.
_TYPE_SEQ = """#define ALT_CODE 0xFF
static void altCode(uint8_t c) {
  uint8_t d[3], n = 0;
  do { d[n++] = c % 10; c /= 10; } while (c);
  while (n) {
    uint8_t k = d[--n];
    DigiKeyboard.sendKeyPress(k ? 88 + k : 98, MOD_ALT_LEFT);
    DigiKeyboard.sendKeyPress(0, MOD_ALT_LEFT);
  }
  DigiKeyboard.sendKeyPress(0, 0);                  // Alt relâché : Windows produit le caractère
}

static void typeSeq(const uint8_t *seq, uint16_t len, uint8_t pace) {
  for (uint16_t i = 0; i < len; i += 2) {
    uint8_t k = pgm_read_byte(seq + i), m = pgm_read_byte(seq + i + 1);
    if (m == ALT_CODE) altCode(k); else DigiKeyboard.sendKeyStroke(k, m);
    if (pace) DigiKeyboard.delay(pace);
  }
}"""


def digispark_sketch(key_text: str, clavier: str, python_delay_ms: int,
                     target: str = "windows", bootstrap: str | None = None) -> str:
    """Firmware de la clé. Avec « bootstrap » (commande d'amorçage : installe le
    client si besoin, puis le lance) :
      windows : Win+R → « cmd » → commande → attente → clé ;
      linux   : Ctrl+Alt+T → commande (tapée dans le terminal) → attente → clé."""
    label, layout = KEYBOARDS[clavier]
    os_label, shortcut, open_stroke, open_delay_ms = SKETCH_OS[target]
    if target == "windows":  # frappe universelle : la disposition n'importe plus
        label = "toutes (codes Alt, Verr. Num. requis)"
        enc = lambda text, **_: _win_bytes(text)  # noqa: E731
    else:
        enc = lambda text, keep_case=False: _hid_bytes(  # noqa: E731
            text, layout, SYMBOLS.get(clavier), keep_case)
    launch_pace = 0
    boot_decl = boot_steps = ""
    if bootstrap and target == "windows":
        launch = enc("cmd")
        boot = enc(bootstrap, keep_case=True)
        sequence = f"{shortcut} → « cmd » → commande d'amorçage → attente → clé → Entrée"
        boot_decl = "\n" + _c_array("BOOT", boot) + "\n"
        boot_steps = """
  DigiKeyboard.delay(1500);                         // ouverture de cmd
  typeSeq(BOOT, sizeof(BOOT), 4);                   // amorçage (installe si besoin, lance)
  DigiKeyboard.sendKeyStroke(KEY_ENTER);"""
    elif bootstrap:
        launch = enc(bootstrap, keep_case=True)
        launch_pace = 4
        sequence = f"{shortcut} → commande d'amorçage → attente → clé → Entrée"
    else:
        launch = enc("neonrelay")
        sequence = f"{shortcut} → « neonrelay » → Entrée → attente → clé → Entrée"

    return f"""// NeonRelay — firmware Digispark ({os_label}) généré par : neonrelay.py make-key --clavier {clavier}
// Disposition clavier visée ({os_label}) : {label}
//
// ⚠️ CE FICHIER CONTIENT LA CLÉ COMPLÈTE : aussi secret que le Digispark lui-même.
//    Flasher, puis supprimer le fichier.
//
// Séquence : {sequence}.
// Les tableaux contiennent des paires (code de touche HID, modificateur ;
// 255 = code Alt du caractère ASCII).
#include "DigiKeyboard.h"
#include <avr/pgmspace.h>

{_c_array("LAUNCH", launch)}
{boot_decl}
{_c_array("KEY", enc(key_text.lower()))}

{_TYPE_SEQ}

void setup() {{
  DigiKeyboard.sendKeyStroke(0);
  DigiKeyboard.delay(1500);                         // le système reconnaît le « clavier »
  {open_stroke}
  DigiKeyboard.delay({open_delay_ms});
  typeSeq(LAUNCH, sizeof(LAUNCH), {launch_pace});
  DigiKeyboard.sendKeyStroke(KEY_ENTER);{boot_steps}
  DigiKeyboard.delay({python_delay_ms});                         // démarrage du client
  typeSeq(KEY, sizeof(KEY), 0);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
}}

void loop() {{
  DigiKeyboard.delay(10000);
}}
"""


def windows_cmd_sample(bootstrap: str) -> str:
    """Échantillon tapé dans cmd par le test Windows : tous les caractères passés
    en code Alt (chiffres, symboles, a q z w m y), précédés de « rem »."""
    risky = sorted({c for c in bootstrap if c != " " and c.lower() not in _WIN_SAFE_LETTERS
                    and not c.isdigit()})
    return "rem " + "".join(risky) + " 0123456789 aqzwmy AQZWMY"


def windows_test_sketch(bootstrap: str) -> str:
    """Firmware SANS clé pour valider la frappe universelle (codes Alt) :
    1) Win+R → notepad → commande d'amorçage complète (à comparer) ;
    2) Win+R → cmd → échantillon « rem … » SANS Entrée (rien n'est exécuté)."""
    sample = windows_cmd_sample(bootstrap)
    return f"""// NeonRelay — TEST DE FRAPPE WINDOWS (sans clé) généré par : neonrelay.py test-clavier
// Frappe universelle : codes Alt, quelle que soit la disposition du clavier.
//
// 1) Bloc-notes : la commande d'amorçage complète, SANS l'exécuter.
//    Comparer à NOM-test-clavier-windows.txt (identique au caractère près).
// 2) cmd : l'échantillon ci-dessous (NOM-test-clavier-windows-cmd.txt), SANS Entrée :
//    {sample}
//
// À jouer : Verr. Num. ALLUMÉ, puis ÉTEINT ; et sous plusieurs dispositions.
#include "DigiKeyboard.h"
#include <avr/pgmspace.h>

{_c_array("NOTEPAD", _win_bytes("notepad"))}

{_c_array("BOOT", _win_bytes(bootstrap))}

{_c_array("CMD", _win_bytes("cmd"))}

{_c_array("SAMPLE", _win_bytes(sample))}

{_TYPE_SEQ}

void setup() {{
  DigiKeyboard.sendKeyStroke(0);
  DigiKeyboard.delay(1500);
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);                  // Win+R
  DigiKeyboard.delay(800);
  typeSeq(NOTEPAD, sizeof(NOTEPAD), 0);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(2500);                         // ouverture du Bloc-notes
  typeSeq(BOOT, sizeof(BOOT), 4);
  DigiKeyboard.delay(1000);
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);                  // Win+R
  DigiKeyboard.delay(800);
  typeSeq(CMD, sizeof(CMD), 0);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(2000);                         // ouverture de cmd
  typeSeq(SAMPLE, sizeof(SAMPLE), 4);               // PAS d'Entrée
}}

void loop() {{
  DigiKeyboard.delay(10000);
}}
"""


def keyboard_test_sketch(bootstrap: str, clavier: str, target: str = "windows") -> str:
    """Firmware SANS clé : tape la commande d'amorçage SANS l'exécuter, pour
    vérifier la table de symboles du clavier avant de flasher la vraie clé.
      windows : Win+R → notepad → texte dans le Bloc-notes ;
      linux   : Ctrl+Alt+T → « tee nrtestclavier » → texte → Ctrl+D
                (enregistré dans ~/nrtestclavier, jamais exécuté)."""
    if target == "windows":
        return windows_test_sketch(bootstrap)
    label, layout = KEYBOARDS[clavier]
    boot = _hid_bytes(bootstrap, layout, SYMBOLS[clavier], keep_case=True)
    if target == "linux":
        launch, where = "tee nrtestclavier", "~/nrtestclavier (via tee)"
        open_stroke = "DigiKeyboard.sendKeyStroke(KEY_T, MOD_CONTROL_LEFT | MOD_ALT_LEFT); // Ctrl+Alt+T"
        open_ms, ready_ms = 1500, 800
        finish = """
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.sendKeyStroke(KEY_D, MOD_CONTROL_LEFT);                // Ctrl+D : fin de tee"""
        check = "diff ~/nrtestclavier NOM-test-clavier-linux.txt  (aucune sortie = identique)"
    else:
        launch, where = "notepad", "le Bloc-notes"
        open_stroke = "DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);                  // Win+R"
        open_ms, ready_ms = 800, 2500
        finish = ""
        check = "comparer le Bloc-notes à NOM-test-clavier-windows.txt"
    return f"""// NeonRelay — TEST DE CLAVIER (sans clé) généré par : neonrelay.py test-clavier / make-key --amorce
// Disposition clavier visée ({SKETCH_OS[target][0]}) : {label}
//
// Tape la commande d'amorçage dans {where}, SANS l'exécuter et SANS la clé.
// Vérifier : {check}.
// Le texte doit être identique au caractère près ; sinon corriger
// SYMBOLS["{clavier}"] dans neonrelay.py.
#include "DigiKeyboard.h"
#include <avr/pgmspace.h>

{_c_array("LAUNCH", _hid_bytes(launch, layout))}

{_c_array("BOOT", boot)}

{_TYPE_SEQ}

void setup() {{
  DigiKeyboard.sendKeyStroke(0);
  DigiKeyboard.delay(1500);
  {open_stroke}
  DigiKeyboard.delay({open_ms});
  typeSeq(LAUNCH, sizeof(LAUNCH), 0);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay({ready_ms});
  typeSeq(BOOT, sizeof(BOOT), 4);{finish}
}}

void loop() {{
  DigiKeyboard.delay(10000);
}}
"""


def write_keyboard_tests(base: str, boots: dict, clavier: str) -> None:
    """NOM-test-clavier-SYSTÈME.ino + NOM-test-clavier-SYSTÈME.txt (texte attendu),
    chacun avec la commande d'amorçage de son système. Sans clé : ni secret, ni
    restriction de droits."""
    for target, (bootstrap, _) in boots.items():
        with open(f"{base}-test-clavier-{target}.ino", "w", encoding="utf-8") as fh:
            fh.write(keyboard_test_sketch(bootstrap, clavier, target))
        with open(f"{base}-test-clavier-{target}.txt", "w", encoding="ascii") as fh:
            fh.write(bootstrap + "\n")
        if target == "windows":  # échantillon attendu dans cmd (sans Entrée)
            with open(f"{base}-test-clavier-windows-cmd.txt", "w", encoding="ascii") as fh:
                fh.write(windows_cmd_sample(bootstrap) + "\n")
        print(f"Test      : {base}-test-clavier-{target}.ino (sans clé) ; "
              f"texte attendu : {base}-test-clavier-{target}.txt", file=sys.stderr)


def _check_keyboard(clavier: str) -> None:
    if clavier not in SYMBOLS:
        raise SystemExit(f"--amorce : clavier {clavier} sans table de symboles "
                         f"(disponibles : {', '.join(sorted(SYMBOLS))}).")


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
            tty.setcbreak(fd, termios.TCSANOW)  # caractère par caractère, sans écho, sans vider le tampon
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


def _read_key(prompt: str) -> str:
    """Saisie masquée de la clé. Sous Linux/macOS, PAS getpass : il vide le
    tampon du terminal (TCSAFLUSH) et efface la clé que le Digispark a tapée en
    avance pendant l'installation (T-21). Ici : écho coupé SANS vider (TCSANOW),
    puis écho rétabli seulement après la lecture (l'amorçage l'avait coupé)."""
    if os.name == "nt" or not sys.stdin.isatty():
        return getpass.getpass(prompt)
    import termios

    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    quiet = termios.tcgetattr(fd)
    quiet[3] = (quiet[3] & ~termios.ECHO) | termios.ICANON  # ligne entière, sans écho
    sys.stdout.write(prompt)
    sys.stdout.flush()
    try:
        termios.tcsetattr(fd, termios.TCSANOW, quiet)
        line = sys.stdin.readline()
    finally:
        saved[3] |= termios.ECHO | termios.ICANON  # pour la suite (messages tapés)
        termios.tcsetattr(fd, termios.TCSANOW, saved)
        sys.stdout.write("\n")
        sys.stdout.flush()
    if not line:
        raise EOFError
    return line.rstrip("\r\n")


def _ask_key() -> Key:
    for attempt in range(3):
        try:
            return decode_key(_read_key("Clé : "))
        except KeyError_ as exc:
            print(f"❌ Clé invalide : {exc}.")
    raise SystemExit(1)


# ---------------------------------------------------------------------------
# Commandes
# ---------------------------------------------------------------------------


def cmd_run(_args) -> int:
    if sys.stdin.isatty():
        print("🔒 NeonRelay — ouverture du canal chiffré.")
        print("   La clé est saisie par le Digispark : rien ne s'affiche, c'est normal.")
        print("   Ensuite, tape ton PIN s'il est demandé.\n")
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

    boots = {}
    if args.amorce:
        _check_keyboard(args.clavier)
        boots = bootstraps(args.amorce)
        for target, (_, sha) in boots.items():
            rel = INSTALLERS[target][0]
            if not args.offline:
                # La source publiée doit servir exactement l'installeur local.
                src = args.amorce.rstrip("/") + "/" + rel
                with urllib.request.urlopen(src, timeout=15) as resp:
                    if hashlib.sha256(resp.read()).hexdigest() != sha:
                        raise SystemExit(f"❌ {src} diffère de client/{rel} : republier client/.")
            print(f"Amorçage  : {rel} {sha[:16]}…"
                  + ("" if args.offline else " ✅ identique sur la source"), file=sys.stderr)

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
                boot = boots[target][0] if boots else None
                fh.write(digispark_sketch(text, args.clavier, args.delai_python, target, boot))
            print(f"Firmware  : {path} ({SKETCH_OS[target][0]}, {SKETCH_OS[target][1]} ; "
                  f"clavier {args.clavier} — {KEYBOARDS[args.clavier][0]})", file=sys.stderr)
        if boots:
            write_keyboard_tests(base, boots, args.clavier)
    print(text)
    return 0


def cmd_test_keyboard(args) -> int:
    """Firmwares de test du clavier seuls : ni clé, ni serveur, ni identifiants."""
    _check_keyboard(args.clavier)
    base = args.ino[:-4] if args.ino.lower().endswith(".ino") else args.ino
    write_keyboard_tests(base, bootstraps(args.amorce), args.clavier)
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
    mk.add_argument("--amorce", metavar="URL",
                    help="URL du dossier client/ publié : le Digispark installe le client s'il "
                         "est absent (install.ps1 / install.sh vérifié par son SHA-256)")
    tk = sub.add_parser("test-clavier",
                        help="(opérateur) firmwares de test du clavier pour l'amorçage, SANS clé")
    tk.add_argument("--clavier", choices=sorted(SYMBOLS), required=True)
    tk.add_argument("--amorce", metavar="URL", required=True, help="même URL que pour make-key")
    tk.add_argument("--ino", metavar="NOM", default="cle",
                    help="NOM-test-clavier-windows.ino / -linux.ino (défaut : cle)")
    sub.add_parser("claviers", help="liste les dispositions de clavier prises en charge")
    sub.add_parser("make-pin", help="(opérateur) tire un PIN de 12 caractères à imprimer")
    args = parser.parse_args(argv)

    handler = {"check-key": cmd_check, "make-key": cmd_make, "claviers": cmd_keyboards,
               "make-pin": cmd_make_pin, "test-clavier": cmd_test_keyboard}.get(args.cmd, cmd_run)
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
