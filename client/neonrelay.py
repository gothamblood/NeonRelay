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

Canal bruité (/channel, format de trame v2) : une trame de 512 octets toutes
les 0,2 s dans chaque sens, vraie ou fausse, chiffrée XSalsa20-Poly1305 puis
AES-256-GCM (voir « Trames du canal bruité »). Le serveur complète la voie
descendante par de l'aléatoire. scripts/secure-shell.sh utilise ce même code
(scripts/base/_channel.py importe ce fichier) : les deux se parlent. SANS PIN,
clé E2E = SHA-256 de la passphrase ; AVEC PIN, elle vient d'Argon2id (voir
« PIN optionnel ») : seuls les clients qui ont le PIN se lisent.

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
import collections  # noqa: E402
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
#
# Frappe rapide (chaque rapport USB attend une interrogation de l'hôte, 10 ms) :
#   - rapport() attend l'hôte sans les pauses de 5 ms de DigiKeyboard ;
#   - pas de rapport « touche relâchée » entre deux touches différentes : passer
#     de « a » à « b » relâche a et enfonce b. On relâche seulement si la même
#     touche revient (sinon l'hôte n'y voit qu'une touche maintenue) ou si les
#     modificateurs changent pendant qu'une touche est enfoncée (Maj/Alt posés
#     ou levés à part). Touche + modificateur dans un même rapport, à partir de
#     « rien d'enfoncé », comme le faisait déjà DigiKeyboard.sendKeyStroke.
_TYPE_SEQ = """#define ALT_CODE 0xFF
static uint8_t heldKey, heldMod;

static void rapport(uint8_t k, uint8_t m) {
  while (!usbInterruptIsReady()) usbPoll();         // attente active, sans _delay_ms(5)
  uint8_t r[2] = {m, k};
  usbSetInterrupt(r, sizeof(r));
  heldKey = k;
  heldMod = m;
}

static void tape(uint8_t k, uint8_t m) {
  if (heldKey && (k == heldKey || m != heldMod))
    rapport(0, m);                                  // relâche, et pose les modificateurs à part
  rapport(k, m);
}

static void altCode(uint8_t c) {
  uint8_t d[3], n = 0;
  do { d[n++] = c % 10; c /= 10; } while (c);
  while (n) {
    uint8_t k = d[--n];
    tape(k ? 88 + k : 98, MOD_ALT_LEFT);
  }
  rapport(0, 0);                                    // Alt relâché : Windows produit le caractère
}

static void typeSeq(const uint8_t *seq, uint16_t len, uint8_t pace) {
  for (uint16_t i = 0; i < len; i += 2) {
    uint8_t k = pgm_read_byte(seq + i), m = pgm_read_byte(seq + i + 1);
    if (m == ALT_CODE) altCode(k); else tape(k, m);
    if (pace) DigiKeyboard.delay(pace);
  }
  rapport(0, 0);                                    // tout relâché
}

// Voyants (bibliothèque NeonRelayKeyboard : l'hôte envoie leur état, ledState).
// Avant de taper : Verr. Maj. éteint (sinon les lettres tapées en direct sont
// inversées), et sous Windows Verr. Num. allumé (codes Alt). Après : état rendu.
// Si l'hôte n'a rien envoyé, un appui sur Verr. Maj. le provoque ; s'il ne
// répond toujours pas, on tape à l'aveugle comme avant.
#define HID_CAPS_LOCK 57
#define HID_NUM_LOCK  83
static uint8_t ledsBefore, ledsKnown;

static bool attendVoyants(uint8_t mask, uint8_t want, uint16_t maxMs = 500) {
  for (uint16_t ms = 0; ms < maxMs; ms += 10) {
    if (ledSeen && (ledState & mask) == want) return true;
    DigiKeyboard.delay(10);
  }
  return false;
}

static void bascule(uint8_t k, uint8_t bit) {
  uint8_t want = (ledState & bit) ^ bit;
  tape(k, 0);
  rapport(0, 0);
  attendVoyants(bit, want);
}

static void preparerVoyants(bool numLock) {
  bool provoque = false;
  // L'hôte envoie l'état des voyants une fois son pilote clavier prêt : c'est
  // le signal qu'il recevra les touches (1er branchement : installation du
  // pilote, plusieurs secondes). Puis un temps de stabilisation.
  if (attendVoyants(0, 0, 8000)) DigiKeyboard.delay(500);
  else {                                            // rien reçu : on provoque l'envoi
    tape(HID_CAPS_LOCK, 0);
    rapport(0, 0);
    if (!attendVoyants(0, 0)) {                     // hôte muet : on annule l'appui,
      tape(HID_CAPS_LOCK, 0);                       // puis frappe à l'aveugle
      rapport(0, 0);
      return;
    }
    provoque = true;
  }
  ledsKnown = 1;
  ledsBefore = ledState ^ (provoque ? LED_CAPS_LOCK : 0);
  if (ledState & LED_CAPS_LOCK) bascule(HID_CAPS_LOCK, LED_CAPS_LOCK);
  if (numLock && !(ledState & LED_NUM_LOCK)) bascule(HID_NUM_LOCK, LED_NUM_LOCK);
  DigiKeyboard.delay(200);                          // avant le raccourci d'ouverture
}

static void rendreVoyants() {
  if (!ledsKnown) return;
  if ((ledState ^ ledsBefore) & LED_CAPS_LOCK) bascule(HID_CAPS_LOCK, LED_CAPS_LOCK);
  if ((ledState ^ ledsBefore) & LED_NUM_LOCK) bascule(HID_NUM_LOCK, LED_NUM_LOCK);
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
    num_lock = "true" if target == "windows" else "false"  # codes Alt : Verr. Num. requis
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
#include "NeonRelayKeyboard.h"   // DigiKeyboard + voyants : neonrelay/digispark/NeonRelayKeyboard
#include <avr/pgmspace.h>

{_c_array("LAUNCH", launch)}
{boot_decl}
{_c_array("KEY", enc(key_text.lower()))}

{_TYPE_SEQ}

void setup() {{
  DigiKeyboard.sendKeyStroke(0);
  DigiKeyboard.delay(1500);                         // le système reconnaît le « clavier »
  preparerVoyants({num_lock});
  {open_stroke}
  DigiKeyboard.delay({open_delay_ms});
  typeSeq(LAUNCH, sizeof(LAUNCH), {launch_pace});
  DigiKeyboard.delay(300);                          // la fenêtre finit de traiter la frappe
  DigiKeyboard.sendKeyStroke(KEY_ENTER);{boot_steps}
  DigiKeyboard.delay({python_delay_ms});                         // démarrage du client
  typeSeq(KEY, sizeof(KEY), 0);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  rendreVoyants();
}}

void loop() {{
  DigiKeyboard.delay(10000);
}}
"""


def windows_test_line(bootstrap: str) -> str:
    """Ligne tapée dans cmd par le test Windows : la commande d'amorçage
    précédée de « rem », et SANS Entrée (rien n'est exécuté)."""
    return "rem " + bootstrap


def windows_test_sketch(bootstrap: str) -> str:
    """Firmware SANS clé pour valider la frappe universelle (codes Alt) dans cmd,
    là même où la vraie clé tape : Win+R → cmd → « rem » + commande d'amorçage
    complète, SANS Entrée (rien n'est exécuté)."""
    line = windows_test_line(bootstrap)
    return f"""// NeonRelay — TEST DE FRAPPE WINDOWS (sans clé) généré par : neonrelay.py test-clavier
// Frappe universelle : codes Alt, quelle que soit la disposition du clavier.
//
// Win+R → cmd → « rem » + commande d'amorçage complète, SANS Entrée (rien
// n'est exécuté). Comparer à NOM-test-clavier-windows.txt (identique au
// caractère près).
//
// À jouer avec Verr. Num. et Verr. Maj. dans tous les états (la clé les règle,
// puis les rend à la fin) ; et sous plusieurs dispositions.
#include "NeonRelayKeyboard.h"   // DigiKeyboard + voyants : neonrelay/digispark/NeonRelayKeyboard
#include <avr/pgmspace.h>

{_c_array("CMD", _win_bytes("cmd"))}

{_c_array("LINE", _win_bytes(line))}

{_TYPE_SEQ}

void setup() {{
  DigiKeyboard.sendKeyStroke(0);
  DigiKeyboard.delay(1500);
  preparerVoyants(true);
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);                  // Win+R
  DigiKeyboard.delay(800);
  typeSeq(CMD, sizeof(CMD), 0);
  DigiKeyboard.delay(300);                          // Win+R finit de traiter la frappe
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(2000);                         // ouverture de cmd
  typeSeq(LINE, sizeof(LINE), 4);                   // PAS d'Entrée
  rendreVoyants();
}}

void loop() {{
  DigiKeyboard.delay(10000);
}}
"""


def keyboard_test_sketch(bootstrap: str, clavier: str, target: str = "windows") -> str:
    """Firmware SANS clé : tape la commande d'amorçage SANS l'exécuter, pour
    vérifier la table de symboles du clavier avant de flasher la vraie clé.
      windows : Win+R → cmd → « rem » + texte, sans Entrée ;
      linux   : Ctrl+Alt+T → « tee nrtestclavier » → texte → Ctrl+D
                (enregistré dans ~/nrtestclavier, jamais exécuté)."""
    if target == "windows":
        return windows_test_sketch(bootstrap)
    label, layout = KEYBOARDS[clavier]
    num_lock = "true" if target == "windows" else "false"
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
#include "NeonRelayKeyboard.h"   // DigiKeyboard + voyants : neonrelay/digispark/NeonRelayKeyboard
#include <avr/pgmspace.h>

{_c_array("LAUNCH", _hid_bytes(launch, layout))}

{_c_array("BOOT", boot)}

{_TYPE_SEQ}

void setup() {{
  DigiKeyboard.sendKeyStroke(0);
  DigiKeyboard.delay(1500);
  preparerVoyants({num_lock});
  {open_stroke}
  DigiKeyboard.delay({open_ms});
  typeSeq(LAUNCH, sizeof(LAUNCH), 0);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay({ready_ms});
  typeSeq(BOOT, sizeof(BOOT), 4);{finish}
  rendreVoyants();
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
        expected = windows_test_line(bootstrap) if target == "windows" else bootstrap
        with open(f"{base}-test-clavier-{target}.txt", "w", encoding="ascii") as fh:
            fh.write(expected + "\n")
        print(f"Test      : {base}-test-clavier-{target}.ino (sans clé) ; "
              f"texte attendu : {base}-test-clavier-{target}.txt", file=sys.stderr)


def _check_keyboard(clavier: str) -> None:
    if clavier not in SYMBOLS:
        raise SystemExit(f"--amorce : clavier {clavier} sans table de symboles "
                         f"(disponibles : {', '.join(sorted(SYMBOLS))}).")


# ---------------------------------------------------------------------------
# Chiffrement de bout en bout : trames du canal bruité (format v2)
#
# Chaque trame fait FRAME_BYTES = 512 octets sur le fil, vraie ou fausse :
#   nonce AES (12) | AES-256-GCM(K2)( nonce XSalsa (24) | XSalsa20-Poly1305(K1)(clair) | tag (16) ) | tag AES (16)
# Clair (444 octets) = version(1) | drapeaux(1) | id(8) | n°(2) | total(2) | longueur(2)
#                      | nb de destinataires(1) | 8 adresses de session (8 x 8)
#                      | morceau du message (363 max) | remplissage à zéro
# Drapeau 0x02 = message de boîte ($/stashserver) : gardé par le serveur pour la
# prochaine session, sans adresse de destinataire (accepté par toute session,
# jamais deux fois le même id dans une session).
# Sur le fil, chaque trame montante est précédée d'1 octet de contrôle lu par le
# serveur (0 relayer, 1/3 garder, 2 oublier le message gardé) : taille constante.
# Drapeau 0x01 = fausse trame (bruit chiffré). Le marqueur est DANS le chiffré :
# le serveur et le réseau ne voient que 512 octets aléatoires, comme pour une
# vraie trame. K1 et K2 sont tirées de la clé E2E (SHA-256 ou Argon2id, voir
# « PIN optionnel ») par BLAKE2b avec deux étiquettes différentes : deux clés
# indépendantes pour deux familles de chiffrement (il faudrait casser les deux).
#
# Anti-rejeu SANS horloge (un horodatage trahirait le décalage d'horloge de
# l'expéditeur, donc une empreinte) : chaque client tire au démarrage une
# « adresse de session » aléatoire de 8 octets et l'annonce dans ses fausses
# trames (champ id). Un vrai message porte les adresses des correspondants en
# ligne au moment de l'envoi ; un destinataire n'accepte que les messages qui
# portent SON adresse du moment (une trame d'une session passée est refusée) et
# jamais deux fois le même id (rejeu dans la session, mémoire en RAM seulement).
#
# Même code pour scripts/secure-shell.sh (scripts/base/_channel.py importe ce
# fichier) : les deux se parlent.
# ---------------------------------------------------------------------------

FRAME_BYTES = 512
TICK = 0.2
FRAME_VERSION = 2
_FRAME_AAD = b"neonrelay-frame-v2"
_HDR = struct.Struct(">BB8sHHHB")
MAX_RECIPIENTS = 8
_ADDR = 8
_RCPT_BYTES = MAX_RECIPIENTS * _ADDR
_PLAIN_BYTES = FRAME_BYTES - 12 - 16 - 24 - 16             # 444
PAYLOAD_MAX = _PLAIN_BYTES - _HDR.size - _RCPT_BYTES       # 363
MAX_MESSAGE_FRAMES = 64
_FLAG_FAKE = 0x01
_FLAG_BOX = 0x02
CTL_RELAY, CTL_STASH, CTL_CANCEL, CTL_STASH_MORE = 0, 1, 2, 3
STASH_SERVER_FRAMES = 8          # = CHANNEL_STASH_FRAMES du serveur


class FrameCodec:
    """Scelle / ouvre les trames de 512 octets (XSalsa20-Poly1305 puis AES-256-GCM)."""

    def __init__(self, e2e: bytes):
        try:
            from nacl import bindings
            from nacl._sodium import lib
            from nacl.secret import SecretBox
        except ImportError:
            raise SystemExit("PyNaCl manque : réinstalle le client.")
        if not hasattr(bindings, "crypto_aead_aes256gcm_encrypt") or not lib.crypto_aead_aes256gcm_is_available():
            raise SystemExit("AES-256-GCM indisponible (processeur sans AES matériel, "
                             "ou PyNaCl < 1.6) : canal refusé.")
        if len(e2e) != 32:
            raise ValueError("clé E2E de 32 octets attendue")
        k1 = hashlib.blake2b(key=e2e, digest_size=32, person=b"nr-k1-xsalsa").digest()
        self._k2 = hashlib.blake2b(key=e2e, digest_size=32, person=b"nr-k2-aes256gcm").digest()
        self._box = SecretBox(k1)
        self._aes_enc = bindings.crypto_aead_aes256gcm_encrypt
        self._aes_dec = bindings.crypto_aead_aes256gcm_decrypt

    def forget(self) -> None:
        """$/abort, $/zeroize : lâche les clés. Python ne garantit pas l'effacement de la
        mémoire (objets immuables) : le processus se termine juste après."""
        self._k2 = b""
        self._box = None

    def _seal(self, plain: bytes) -> bytes:
        inner = bytes(self._box.encrypt(plain))
        nonce = os.urandom(12)
        frame = nonce + self._aes_enc(inner, _FRAME_AAD, nonce, self._k2)
        if len(frame) != FRAME_BYTES:
            raise AssertionError("taille de trame inattendue")
        return frame

    @staticmethod
    def _plain(flags: int, msg_id: bytes, seq: int, total: int, chunk: bytes = b"",
               recipients: tuple = ()) -> bytes:
        rcpt = b"".join(recipients[:MAX_RECIPIENTS])
        head = _HDR.pack(FRAME_VERSION, flags, msg_id, seq, total, len(chunk), len(recipients[:MAX_RECIPIENTS]))
        body = head + rcpt.ljust(_RCPT_BYTES, b"\0") + chunk
        return body + bytes(_PLAIN_BYTES - len(body))

    def fake(self, address: bytes) -> bytes:
        """Fausse trame : chiffrée comme une vraie, marquée « fake » à l'intérieur ;
        elle annonce l'adresse de session de son expéditeur."""
        return self._seal(self._plain(_FLAG_FAKE, address, 0, 0))

    def message(self, text: str, recipients, box: bool = False) -> list:
        """Découpe un message en trames de taille fixe, adressées aux sessions
        données ; box=True : message de boîte ($/stashserver), sans adresse."""
        data = text.encode("utf-8")
        chunks = [data[i:i + PAYLOAD_MAX] for i in range(0, len(data), PAYLOAD_MAX)] or [b""]
        if len(chunks) > MAX_MESSAGE_FRAMES:
            raise ValueError(f"message trop long ({MAX_MESSAGE_FRAMES * PAYLOAD_MAX} octets max)")
        msg_id = os.urandom(8)
        rcpt = () if box else tuple(recipients)[:MAX_RECIPIENTS]
        flags = _FLAG_BOX if box else 0
        return [self._seal(self._plain(flags, msg_id, i, len(chunks), c, rcpt)) for i, c in enumerate(chunks)]

    def open(self, frame: bytes):
        """(fausse, id, n°, total, morceau, destinataires, boîte), ou None : bruit du serveur,
        autre clé ou PIN, trame altérée. Dans tous ces cas : rejet silencieux."""
        from nacl.exceptions import CryptoError

        if len(frame) != FRAME_BYTES:
            return None
        try:
            inner = self._aes_dec(frame[12:], _FRAME_AAD, frame[:12], self._k2)
            plain = self._box.decrypt(inner)
        except (CryptoError, ValueError, TypeError):
            return None
        if len(plain) != _PLAIN_BYTES:
            return None
        version, flags, msg_id, seq, total, length, nrcpt = _HDR.unpack_from(plain)
        if version != FRAME_VERSION or length > PAYLOAD_MAX or nrcpt > MAX_RECIPIENTS:
            return None
        r0 = _HDR.size
        rcpt = tuple(plain[r0 + i * _ADDR:r0 + (i + 1) * _ADDR] for i in range(nrcpt))
        c0 = r0 + _RCPT_BYTES
        return (bool(flags & _FLAG_FAKE), msg_id, seq, total, plain[c0:c0 + length], rcpt,
                bool(flags & _FLAG_BOX))


class Reassembler:
    """Regroupe les morceaux par id de message ; oublie un message incomplet après TTL."""

    TTL = 120.0
    MAX_PENDING = 64

    def __init__(self) -> None:
        self._parts: dict = {}

    def add(self, msg_id: bytes, seq: int, total: int, chunk: bytes):
        now = time.monotonic()
        for k in [k for k, (t, _, _) in self._parts.items() if now - t > self.TTL]:
            del self._parts[k]
        if not 1 <= total <= MAX_MESSAGE_FRAMES or seq >= total:
            return None
        entry = self._parts.get(msg_id)
        if entry is None:
            if len(self._parts) >= self.MAX_PENDING:
                return None
            entry = self._parts[msg_id] = (now, total, {})
        _, expected, parts = entry
        if expected != total:
            return None
        parts[seq] = chunk
        if len(parts) < total:
            return None
        del self._parts[msg_id]
        return b"".join(parts[i] for i in range(total)).decode("utf-8", "replace")


class Inbox:
    """Côté réception : adresse de session, correspondants en ligne, anti-rejeu.

    Tout vit en RAM, le temps de la session : rien n'est écrit sur disque."""

    PEER_TTL = 30.0          # un correspondant silencieux depuis 30 s n'est plus adressé
    MAX_DONE = 100_000       # ids de messages déjà affichés (8 octets chacun)

    def __init__(self) -> None:
        self.address = os.urandom(_ADDR)
        self._peers: dict = {}
        self._done: collections.OrderedDict = collections.OrderedDict()
        self._reasm = Reassembler()
        self._lock = threading.Lock()

    def recipients(self) -> tuple:
        """Adresses des correspondants entendus récemment (les plus récents d'abord)."""
        now = time.monotonic()
        with self._lock:
            live = [(t, a) for a, t in self._peers.items() if now - t <= self.PEER_TTL and a != self.address]
        return tuple(a for _, a in sorted(live, reverse=True)[:MAX_RECIPIENTS])

    def accept(self, opened):
        """opened = FrameCodec.open(...) non nul. Renvoie ("fake", None),
        ("msg", texte), ("box", texte) (message laissé sur le serveur), ou None
        (trame à ignorer : pas pour nous, rejeu, morceau)."""
        fake, msg_id, seq, total, chunk, rcpt, box = opened
        with self._lock:
            if fake:
                self._peers[msg_id] = time.monotonic()
                return "fake", None
            if (not box and self.address not in rcpt) or msg_id in self._done:
                return None          # session passée (rejeu différé) ou déjà affiché (rejeu)
            text = self._reasm.add(msg_id, seq, total, chunk)
            if text is None:
                return None
            self._done[msg_id] = None
            while len(self._done) > self.MAX_DONE:
                self._done.popitem(last=False)
            return ("box" if box else "msg"), text


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

        # Vider ce que le Digispark a tapé EN AVANCE (notamment l'Entrée qui a
        # validé la clé) : sans ça, cette touche résiduelle satisfait l'invite
        # dès son affichage et le PIN est sauté en silence (("", False), donc pas
        # même le message « Délai écoulé »). Côté Linux, _read_key lit la clé en
        # ICANON et consomme déjà le saut de ligne : rien ne traîne.
        while msvcrt.kbhit():
            ch = msvcrt.getwch()
            if ch in ("\x00", "\xe0"):  # touche spéciale : code sur 2 lectures
                msvcrt.getwch()
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


_SESSION_HEADER = "X-NeonRelay-Session"
SILENCE_ALERT = 30.0   # s sans trame valide avant l'alerte locale


def _channel_headers(key: Key, sid: str) -> dict:
    # sid : identifiant aléatoire de CETTE session, le même sur les deux
    # connexions, pour que le serveur ne nous renvoie pas nos propres trames.
    return {_PW_HEADER: key.password, _SESSION_HEADER: sid}


def _read_exact(resp, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        part = resp.read(n - len(buf))
        if not part:
            raise ConnectionError("flux fermé par le serveur")
        buf += part
    return buf


def _channel_down(key: Key, sid: str, on_frame, on_ready) -> None:
    """Voie descendante : le serveur écrit des trames à chaque tic (vraies + bruit)."""
    conn = connect(key)
    try:
        conn.request("GET", f"/channel/{key.token}", headers=_channel_headers(key, sid))
        resp = conn.getresponse()
        if resp.status != 200:
            raise RuntimeError(_http_error(resp.status))
        # Le serveur écrit toutes les TICK secondes : un long silence = lien mort.
        conn.sock.settimeout(15)
        on_ready()
        while True:
            on_frame(_read_exact(resp, FRAME_BYTES))
    finally:
        conn.close()


class Outbox:
    """Trames à envoyer. Vide => une fausse trame part à la place : le débit montant
    ne dépend jamais de ce que tu écris."""

    def __init__(self, codec: FrameCodec, address: bytes) -> None:
        self._codec = codec
        self._address = address
        self._q: collections.deque = collections.deque()
        self._lock = threading.Lock()

    def put(self, frames: list, ctl: int = CTL_RELAY) -> None:
        """ctl=CTL_STASH : message laissé sur le serveur (1re trame CTL_STASH,
        suivantes CTL_STASH_MORE)."""
        if ctl == CTL_STASH:
            items = [(CTL_STASH if i == 0 else CTL_STASH_MORE, f) for i, f in enumerate(frames)]
        else:
            items = [(ctl, f) for f in frames]
        with self._lock:
            self._q.extend(items)

    def cancel_stash(self) -> None:
        """$/stashserver cancel : une fausse trame, marquée « oublier »."""
        with self._lock:
            self._q.append((CTL_CANCEL, self._codec.fake(self._address)))

    def take(self) -> tuple:
        """(octet de contrôle, trame, vraie ?)."""
        with self._lock:
            if self._q:
                ctl, frame = self._q.popleft()
                return ctl, frame, True
        return CTL_RELAY, self._codec.fake(self._address), False

    def give_back(self, ctl: int, frame: bytes) -> None:
        with self._lock:
            self._q.appendleft((ctl, frame))

    def pending(self) -> int:
        with self._lock:
            return len(self._q)

    def clear(self) -> None:
        with self._lock:
            self._q.clear()


def _channel_up(key: Key, sid: str, outbox: Outbox, stop: threading.Event) -> None:
    """Voie montante : UNE requête chunked, une trame de 512 octets par tic."""
    conn = connect(key)
    try:
        conn.putrequest("POST", f"/channel/{key.token}", skip_accept_encoding=True)
        for name, value in _channel_headers(key, sid).items():
            conn.putheader(name, value)
        conn.putheader("Content-Type", "application/octet-stream")
        conn.putheader("Transfer-Encoding", "chunked")
        conn.endheaders()
        head = b"%X\r\n" % (1 + FRAME_BYTES)   # octet de contrôle + trame
        next_tick = time.monotonic()
        while not stop.is_set():
            ctl, frame, real = outbox.take()
            try:
                conn.send(head + bytes((ctl,)) + frame + b"\r\n")
            except Exception:
                if real:
                    outbox.give_back(ctl, frame)  # renvoyée après reconnexion
                raise
            next_tick += TICK
            delay = next_tick - time.monotonic()
            if delay > 0:
                stop.wait(delay)
            else:
                next_tick = time.monotonic()  # retard : on se recale, sans rafale
        try:
            conn.send(b"0\r\n\r\n")
            conn.getresponse().read()
        except (OSError, http.client.HTTPException):
            pass
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Canal interactif
# ---------------------------------------------------------------------------


def _say(text: str) -> None:
    sys.stdout.write("\r" + text + "\n→ ")
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# Commandes de la console : une ligne qui commence par « $/ ». « $$/… » envoie
# « $/… » tel quel. Messages en français puis en anglais.
# ---------------------------------------------------------------------------

CMD_PREFIX = "$/"
STASH_MAX = 10
_FP_ALPHABET = PIN_ALPHABET  # base32 Crockford, comme le PIN

OPTIONS_TEXT = """\
   $/stash <message>        garde le message ICI (RAM) ; envoyé dès qu'un correspondant arrive
                            keep the message HERE (RAM); sent as soon as someone comes online
   $/stash                  messages en attente ici / messages waiting here
   $/stash clear            les effacer / delete them
   $/stashserver <message>  laisser sur le serveur pour le prochain qui se connecte (1 seul, chiffré)
                            leave on the server for the next one to connect (one, encrypted)
   $/stashserver cancel     le retirer / remove it
   $/selfdestruct <durée>   détruire la boîte dans 30m, 2h, 3d… (heure du serveur ; seulement avancer)
                            destroy the box in 30m, 2h, 3d… (server time; can only be brought forward)
   $/selfdestruct           temps restant / time left
   $/deadman <durée> <mdp>  homme mort : détruite si le compteur n'est pas remis à zéro à temps ;
                            la même commande remet à zéro / dead man: destroyed unless reset in time;
                            the same command resets it
   $/deadman -c <mdp>       annuler l'homme mort / cancel the dead man
   $/online                 correspondants en ligne / peers online
   $/clear                  vider l'écran et l'historique / clear screen and scrollback
   $/fingerprint            empreinte de la clé, à comparer à voix haute / key fingerprint, compare aloud
   $/abort                  tout effacer ici et fermer (Entrée pour confirmer) ; la boîte reste
                            wipe everything here and close (Enter to confirm); the box stays
   $/abort!                 idem, sans confirmation / same, no confirmation
   $/zeroize                abort + SUPPRIME LA BOÎTE pour tous, définitif (taper ZEROIZE)
                            abort + DELETES THE BOX for everyone, permanent (type ZEROIZE)
   $/zeroize!               idem, sans confirmation / same, no confirmation
   $/exit                   fermer le canal et la console / close the channel and the console
   $/options                ce menu / this menu
   $$/…                     envoyer un message qui commence par « $/ » / send a message starting with « $/ »"""


def delete_box(key: Key, timeout: float = 8) -> str:
    """$/zeroize : supprime la boîte (DELETE /config/{id}, mot de passe de la
    boîte). Le serveur coupe aussitôt les flux ouverts. "" si supprimée, sinon
    la raison."""
    try:
        conn = connect(key, timeout=timeout)
        try:
            conn.request("DELETE", f"/config/{key.token}", headers={_PW_HEADER: key.password})
            status = conn.getresponse().status
        finally:
            conn.close()
    except (OSError, http.client.HTTPException, CertError) as exc:
        return f"serveur injoignable / server unreachable ({exc})"
    if status in (204, 404, 410):   # 404 / 410 : déjà supprimée ou expirée
        return ""
    return _http_error(status)


_DUR_RE = re.compile(r"(\d+)\s*([dhm])", re.IGNORECASE)
_DUR_UNITS = {"d": 86400, "h": 3600, "m": 60}


def parse_duration(text: str) -> int | None:
    """« 30m », « 2h », « 3d », « 1d12h » → secondes ; None si illisible."""
    text = text.strip().lower().replace(" ", "")
    if not text or _DUR_RE.sub("", text):
        return None
    return sum(int(n) * _DUR_UNITS[u] for n, u in _DUR_RE.findall(text)) or None


def format_duration(seconds: int) -> str:
    d, rest = divmod(max(0, int(seconds)), 86400)
    h, rest = divmod(rest, 3600)
    m = rest // 60
    parts = ([f"{d} j/d"] if d else []) + ([f"{h} h"] if h or d else []) + [f"{m:02d} min"]
    return " ".join(parts)


def box_api(key: Key, method: str, path: str, body: dict | None = None,
            timeout: float = 10) -> tuple[int, dict]:
    """Requête JSON vers /config/{boîte}{path}, avec le mot de passe de la boîte."""
    headers = {_PW_HEADER: key.password}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    conn = connect(key, timeout=timeout)
    try:
        conn.request(method, f"/config/{key.token}{path}", body=data, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
    finally:
        conn.close()
    try:
        return resp.status, json.loads(raw or b"{}")
    except ValueError:
        return resp.status, {}


def lifecycle_text(st: dict) -> str:
    lines = []
    if st.get("destroy_in") is not None:
        lines.append(f"   💣 destruction dans / destroyed in {format_duration(st['destroy_in'])}")
    if st.get("deadman_armed"):
        lines.append(f"   🕯️  homme mort : destruction sans remise à zéro dans / dead man: destroyed "
                     f"unless reset in {format_duration(st['deadman_in'] or 0)}")
    return "\n".join(lines) or "   Aucune échéance / No deadline."


def fingerprint(e2e: bytes) -> str:
    """Empreinte de la clé E2E (PIN compris) : 80 bits, 16 caractères base32.
    À sens unique : elle ne révèle rien de la clé (les trames chiffrées
    permettent déjà de tester une clé devinée)."""
    n = int.from_bytes(hashlib.blake2b(e2e, digest_size=10, person=b"nr-fingerprint").digest(), "big")
    chars = "".join(_FP_ALPHABET[(n >> (5 * i)) & 31] for i in range(15, -1, -1))
    return "-".join(chars[i:i + 4] for i in range(0, 16, 4))


def clear_screen() -> None:
    """Vide l'écran ET l'historique de défilement du terminal."""
    if os.name == "nt":
        os.system("cls")
    sys.stdout.write("\033[H\033[2J\033[3J")
    sys.stdout.flush()
    try:
        import readline  # historique des lignes tapées (Linux), en RAM
        readline.clear_history()
    except Exception:
        pass


def _close_console_window() -> None:
    """Ferme la console : Windows, la fenêtre (cmd lancé par le Digispark
    compris) ; Linux, le shell du terminal (meneur de session : la fenêtre ou
    l'onglet ouvert par Ctrl+Alt+T se ferme)."""
    try:
        if os.name == "nt":
            import ctypes
            hwnd = ctypes.windll.kernel32.GetConsoleWindow()
            if hwnd:
                ctypes.windll.user32.PostMessageW(hwnd, 0x0010, 0, 0)  # WM_CLOSE
        elif sys.stdin.isatty():
            import signal
            leader = os.getsid(0)
            if leader not in (0, 1, os.getpid()):
                os.kill(leader, signal.SIGHUP)
    except Exception:
        pass


def run_channel(key: Key, pin: str = "", e2e: bytes | None = None) -> int:
    """Ouvre le canal bruité. e2e : clé déjà dérivée (scripts bash, PIN compris) ;
    sinon elle est dérivée ici de la passphrase et du PIN."""
    with_pin = bool(pin) or e2e is not None
    if e2e is None:
        if pin:
            print("   Dérivation de la clé (Argon2id)…", flush=True)
        e2e = e2e_key(key.passphrase, key.token, pin)
    codec = FrameCodec(e2e)
    mode = "AVEC PIN" if with_pin else "SANS PIN"
    print(f"🔒 Canal chiffré {mode} — boîte {key.token[:8]}… sur {key.host}:{key.port}")
    print((f"   Trafic constant : une trame de {FRAME_BYTES} octets toutes les "
          f"{TICK:g} s dans chaque sens, que tu parles ou non.").replace("0.", "0,"))
    if not with_pin:
        print("   Sans PIN, tu ne lis pas les correspondants qui ont un PIN (et inversement).")
    print("   Tape un message puis Entrée pour l'envoyer ; Ctrl+C pour quitter.")
    print("   Commandes / Commands : $/options\n")

    sid = secrets.token_hex(16)
    inbox = Inbox()
    outbox = Outbox(codec, inbox.address)
    stop = threading.Event()
    ready = threading.Event()
    fatal: list[str] = []
    state = {"last_valid": 0.0, "online": False, "since": time.monotonic(), "told_alone": False}
    lock = threading.Lock()

    def on_frame(frame: bytes) -> None:
        opened = codec.open(frame)
        if opened is None:
            return  # bruit du serveur, autre clé/PIN, ou trame altérée : rejet silencieux
        with lock:
            state["last_valid"] = time.monotonic()
            if not state["online"]:
                state["online"] = True
                _say("🟢 un correspondant est en ligne (même clé, même PIN)")
        got = inbox.accept(opened)
        if got and got[0] == "msg":
            _say(f"← {got[1]}")
        elif got and got[0] == "box":
            _say(f"📦 ← {got[1]}   (laissé sur le serveur / left on the server)")
        # "fake" : bruit d'un correspondant (battement de cœur + son adresse de
        # session) ; None : pas pour cette session, rejeu, ou morceau en attente.

    def supervise() -> None:
        # Alerte LOCALE uniquement (rien n'est envoyé) : un silence peut vouloir
        # dire « personne en ligne », ou « clé / PIN différents ».
        while not stop.wait(5):
            now = time.monotonic()
            with lock:
                if state["online"] and now - state["last_valid"] > SILENCE_ALERT:
                    state["online"] = False
                    _say(f"⚪ aucune trame lisible depuis {SILENCE_ALERT:g} s : correspondant "
                         "parti, ou clé / PIN différents")
                elif (not state["online"] and not state["told_alone"]
                        and now - state["since"] > SILENCE_ALERT and not state["last_valid"]):
                    state["told_alone"] = True
                    _say("⏳ aucun correspondant pour l'instant (ou clé / PIN différents) ; "
                         "tes messages partent quand même")

    def run_with_retry(target, name: str) -> None:
        delay = 2
        while not stop.is_set():
            try:
                target()
            except (CertError, RuntimeError) as exc:  # cert inattendu, 401 / 410 : inutile d'insister
                first = not fatal
                fatal.append(str(exc))
                if first and ready.is_set():  # en pleine session (boîte supprimée…) : le dire tout de suite
                    _say(f"❌ {exc} — Entrée pour fermer / Enter to close")
                ready.set()
                stop.set()
                return
            except (OSError, ConnectionError, http.client.HTTPException):
                if stop.is_set():
                    return
                if not ready.is_set():
                    fatal.append("serveur injoignable")
                    ready.set()
                    return
                _say(f"⚠️  {name} coupée, reconnexion dans {delay} s…")
                if stop.wait(delay):
                    return
                delay = min(delay * 2, 60)
            else:
                delay = 2

    threading.Thread(target=run_with_retry, daemon=True, name="down",
                     args=(lambda: _channel_down(key, sid, on_frame, ready.set), "réception")).start()
    ready.wait(20)
    if fatal or not ready.is_set():
        print(f"❌ {fatal[0] if fatal else 'serveur injoignable'}")
        stop.set()
        return 1
    up = threading.Thread(target=run_with_retry, daemon=True, name="up",
                          args=(lambda: _channel_up(key, sid, outbox, stop), "émission"))
    up.start()
    threading.Thread(target=supervise, daemon=True, name="supervise").start()

    stash: collections.deque = collections.deque()   # $/stash : RAM seulement
    stash_lock = threading.Lock()
    key_fp = fingerprint(e2e)

    def send(text: str, recipients: tuple) -> bool:
        try:
            frames = codec.message(text, recipients)
        except ValueError as exc:
            print(f"⚠️  non envoyé / not sent : {exc}")
            return False
        outbox.put(frames)
        if len(frames) > 1:
            print(f"   (envoi en {len(frames)} trames, environ {len(frames) * TICK:.1f} s)")
        return True

    def flush_stash() -> None:
        # Messages mis de côté : partent dès qu'un correspondant est en ligne,
        # comme des messages ordinaires (mêmes trames, même rythme).
        while not stop.wait(1):
            recipients = inbox.recipients()
            if not recipients:
                continue
            with stash_lock:
                todo = list(stash)
                stash.clear()
            for text in todo:
                outbox.put(codec.message(text, recipients))
            if todo:
                _say(f"📤 {len(todo)} message(s) mis de côté envoyé(s) / stashed message(s) sent")

    threading.Thread(target=flush_stash, daemon=True, name="stash").start()

    def wipe_local() -> None:
        stop.set()
        with stash_lock:
            stash.clear()
        outbox.clear()
        codec.forget()
        clear_screen()

    def abort(confirm: bool) -> None:
        if confirm:
            print("⚠️  ABORT : efface l'écran et l'historique, abandonne les messages en attente,\n"
                  "    oublie les clés, ferme le client et la console. La boîte reste intacte.\n"
                  "    ABORT: wipes screen and scrollback, drops pending messages, forgets keys,\n"
                  "    closes the client and the console. The box stays intact.")
            if input("    Entrée pour confirmer, autre chose pour annuler / "
                     "Enter to confirm, anything else to cancel : ") != "":
                print("   Annulé / Cancelled.")
                return
        wipe_local()
        _close_console_window()
        os._exit(0)   # sans attendre les fils ni afficher quoi que ce soit

    def zeroize(confirm: bool) -> None:
        if confirm:
            print("☢️  ZEROIZE : ABORT + SUPPRESSION DE LA BOÎTE sur le serveur. Tous les\n"
                  "    correspondants sont coupés, le message laissé sur le serveur est détruit,\n"
                  "    et cette clé (comme les leurs) ne servira plus jamais. DÉFINITIF.\n"
                  "    ZEROIZE: ABORT + DELETES THE BOX on the server. Every peer is cut off, the\n"
                  "    message left on the server is destroyed, and this key (and theirs) will\n"
                  "    never work again. PERMANENT.")
            if input("    Tape ZEROIZE pour confirmer / Type ZEROIZE to confirm : ") != "ZEROIZE":
                print("   Annulé / Cancelled.")
                return
        wipe_local()
        error = delete_box(key)
        if error:
            # La boîte n'est PAS supprimée : on le dit, et la console reste
            # ouverte pour qu'on le voie (clés déjà oubliées, client fermé).
            print(f"❌ boîte NON supprimée / box NOT deleted : {error}\n"
                  "   Préviens l'opérateur NeonRelay / Tell the NeonRelay operator.")
            sys.stdout.flush()
            os._exit(1)
        _close_console_window()
        os._exit(0)

    def lifecycle(call) -> dict | None:
        try:
            status, st = call()
        except (OSError, http.client.HTTPException, CertError) as exc:
            print(f"❌ serveur injoignable / server unreachable : {exc}")
            return None
        if status == 403:
            print("❌ mot de passe de l'homme mort refusé / dead-man password refused.")
            return None
        if status == 429:
            print("❌ trop d'essais, réessaie plus tard / too many attempts, try again later.")
            return None
        if status == 422:
            print("❌ refusé : durée de 1 min à 1 an, mot de passe de 8 caractères au moins /\n"
                  "   refused: duration 1 min to 1 year, password 8 characters at least.")
            return None
        if status != 200:
            print(f"❌ {_http_error(status)}")
            return None
        result = st.get("result")
        if result == "set":
            print("   💣 compte à rebours lancé (heure du serveur) / countdown started (server time).")
        elif result == "unchanged":
            print("   Inchangé : l'échéance actuelle est déjà plus proche (on ne peut qu'avancer) /\n"
                  "   Unchanged: the current deadline is already sooner (it can only be brought forward).")
        if result == "armed":
            print("   🕯️  homme mort ARMÉ / dead man ARMED.")
        elif result == "reset":
            print("   ✅ compteur remis à zéro / counter reset to zero.")
        elif result == "cancelled":
            print("   🗑️  homme mort annulé / dead man cancelled.")
        elif result == "not-armed":
            print("   Aucun homme mort armé / No dead man armed.")
        print(lifecycle_text(st))
        return st

    def hide_typed_line() -> None:
        # La ligne tapée contenait un mot de passe : on l'efface de l'écran et de
        # l'historique des lignes (readline).
        sys.stdout.write("\033[1A\033[2K\r→ $/deadman …\n")
        sys.stdout.flush()
        try:
            import readline
            n = readline.get_current_history_length()
            if n:
                readline.remove_history_item(n - 1)
        except Exception:
            pass

    def deadman(arg: str) -> None:
        if not arg:
            lifecycle(lambda: box_api(key, "GET", "/lifecycle"))
            return
        first, _, password = arg.partition(" ")
        password = password.strip()
        if password:
            hide_typed_line()
        else:
            password = getpass.getpass("   Mot de passe de l'homme mort / Dead-man password : ")
        if first.lower() == "-c":
            lifecycle(lambda: box_api(key, "POST", "/deadman/cancel", {"password": password}))
            return
        secs = parse_duration(first)
        if secs is None or secs < 60:
            print("   Usage : $/deadman <durée / duration> <mot de passe / password>  ·  "
                  "$/deadman -c <mot de passe / password>")
            return
        lifecycle(lambda: box_api(key, "POST", "/deadman", {"seconds": secs, "password": password}))

    exit_warned = [False]

    def command(line: str) -> bool:
        """True : $/exit, fermer le canal et la console."""
        name, _, arg = line[len(CMD_PREFIX):].strip().partition(" ")
        name, arg = name.lower(), arg.strip()
        if name == "exit":
            with stash_lock:
                waiting = len(stash)
            if waiting and not exit_warned[0]:
                exit_warned[0] = True
                print(f"⚠️  {waiting} message(s) en attente ici seront perdus : retape $/exit pour confirmer.\n"
                      f"    {waiting} message(s) waiting here will be lost: type $/exit again to confirm.")
                return False
            return True
        exit_warned[0] = False
        if name == "stash":
            with stash_lock:
                if arg.lower() == "clear":
                    n = len(stash)
                    stash.clear()
                    print(f"   {n} message(s) effacé(s) / deleted.")
                elif not arg:
                    if not stash:
                        print("   Aucun message en attente ici / No message waiting here.")
                    for i, text in enumerate(stash, 1):
                        print(f"   {i}. {text[:60]}{'…' if len(text) > 60 else ''}")
                elif len(stash) >= STASH_MAX:
                    print(f"⚠️  {STASH_MAX} messages en attente au plus / at most {STASH_MAX} waiting.")
                elif len(arg.encode("utf-8")) > MAX_MESSAGE_FRAMES * PAYLOAD_MAX:
                    print(f"⚠️  message trop long / too long ({MAX_MESSAGE_FRAMES * PAYLOAD_MAX} octets max).")
                else:
                    stash.append(arg)
                    print(f"   📥 gardé ici ({len(stash)}/{STASH_MAX}), part dès qu'un correspondant "
                          f"arrive / kept here, sent when someone comes online.")
        elif name == "stashserver":
            if arg.lower() == "cancel":
                outbox.cancel_stash()
                print("   🗑️  message laissé sur le serveur retiré (s'il n'a pas encore été lu) /\n"
                      "      message left on the server removed (if not read yet).")
            elif not arg:
                print("   Usage : $/stashserver <message>  ·  $/stashserver cancel")
            elif len(arg.encode("utf-8")) > STASH_SERVER_FRAMES * PAYLOAD_MAX:
                print(f"⚠️  trop long pour le serveur / too long for the server "
                      f"({STASH_SERVER_FRAMES * PAYLOAD_MAX} octets max).")
            else:
                outbox.put(codec.message(arg, (), box=True), CTL_STASH)
                print("   📦 laissé sur le serveur : le prochain qui se connecte le recevra (un seul\n"
                      "      message, remplace le précédent) / left on the server for the next one to\n"
                      "      connect (one message, replaces the previous one).")
        elif name == "selfdestruct":
            if not arg:
                lifecycle(lambda: box_api(key, "GET", "/lifecycle"))
                return False
            secs = parse_duration(arg)
            if secs is None or secs < 60:
                print("   Usage : $/selfdestruct <durée / duration>  (ex. 30m, 2h, 3d, 1d12h ; 1 min au moins)")
                return False
            lifecycle(lambda: box_api(key, "POST", "/selfdestruct", {"seconds": secs}))
        elif name == "deadman":
            deadman(arg)
        elif name == "online":
            n = len(inbox.recipients())
            print(f"   {n} correspondant(s) en ligne / peer(s) online.")
        elif name == "clear":
            clear_screen()
        elif name == "fingerprint":
            print(f"   🔑 {key_fp}")
            print("   Même empreinte des deux côtés = même clé (et même PIN).\n"
                  "   Same fingerprint on both sides = same key (and same PIN).")
        elif name in ("abort", "abort!"):
            abort(confirm=(name == "abort"))
        elif name in ("zeroize", "zeroize!"):
            zeroize(confirm=(name == "zeroize"))
        elif name == "options":
            print(OPTIONS_TEXT)
            with stash_lock:
                waiting = len(stash)
            print(f"   État / Status : {len(inbox.recipients())} en ligne / online · "
                  f"{waiting} en attente ici / waiting here · {mode}")
        else:
            print(f"⚠️  commande inconnue / unknown command : {CMD_PREFIX}{name} — voir / see $/options")
        return False

    exiting = False
    try:
        while not stop.is_set():
            text = input("→ ")
            if fatal:
                break
            if not text:
                continue
            if text.startswith(CMD_PREFIX):
                if command(text):
                    exiting = True
                    break
                continue
            if text.startswith("$" + CMD_PREFIX):
                text = text[1:]          # « $$/… » : message qui commence par « $/ »
            recipients = inbox.recipients()
            if not recipients:
                print("⚠️  aucun correspondant en ligne : message non envoyé (rien n'est stocké).\n"
                      "    No peer online: not sent. « $/stash <message> » l'enverra à son arrivée / "
                      "will send it when someone arrives.")
                continue
            send(text, recipients)
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        if exiting:  # $/exit : laisser partir les trames déjà en file (5 s au plus)
            deadline = time.monotonic() + 5
            while outbox.pending() and time.monotonic() < deadline and not fatal:
                time.sleep(TICK)
        stop.set()
        up.join(2)
    if exiting:
        print("\nCanal fermé / Channel closed.")
        sys.stdout.flush()
        _close_console_window()
        return 0
    if fatal:
        print(f"\n❌ {fatal[0]}")
        return 1
    left = outbox.pending()
    if left:
        print(f"\n⚠️  {left} trame(s) non envoyée(s).")
    print("\nCanal fermé.")
    return 0


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
