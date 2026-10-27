#!/usr/bin/env bash
# Affiche le registre des tokens depuis la base SQLite (lecture seule).
set -euo pipefail
DB="$(dirname "$0")/../neonrelay.db"
sqlite3 "$DB" -cmd ".mode line" "SELECT * FROM tokens;"
