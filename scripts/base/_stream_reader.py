#!/usr/bin/env python3
"""Lecteur du flux SSE de /listen.

N'affiche QUE le corps de chaque requête, déchiffré si NEONRELAY_KEY est
définie. Tout le reste (métadonnées, keep-alive, event ready) est ignoré.
readline() + flush gardent l'affichage en temps réel.

Lancé par stream.sh en bout de pipe :  curl ... | python3 _stream_reader.py
_crypto.py vit dans le même dossier, donc `import _crypto` le trouve.
"""
import json
import sys

import _crypto


def main():
    for line in iter(sys.stdin.readline, ""):
        if not line.startswith("data:"):
            continue
        try:
            obj = json.loads(line[5:].strip())
        except ValueError:
            continue

        if "body_text" in obj:
            # Corps texte : chiffré (base64) si une clé est en jeu, sinon clair.
            try:
                clear = _crypto.decrypt(obj["body_text"].encode("utf-8"))
            except _crypto.DecryptError as exc:
                print(f"[message illisible / unreadable: {exc}]", flush=True)
                continue
            # Le clair déchiffré peut être binaire : on décode au mieux.
            print(clear.decode("utf-8", "replace"), flush=True)
        elif "body_base64" in obj:
            # Corps binaire NON chiffré (le chiffrement produit toujours du
            # texte base64 -> body_text). On l'affiche tel quel.
            print(
                "[binary body, base64 / corps binaire, base64] " + obj["body_base64"],
                flush=True,
            )


if __name__ == "__main__":
    main()
