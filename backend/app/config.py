"""Runtime configuration, read from environment variables with safe defaults."""

import os

# Project root: this file is backend/app/config.py, so three levels up. Used to
# anchor on-disk defaults (DB, admin creds) at the repo root regardless of the
# working directory the server is launched from.
PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)


class Settings:
    # Database (async SQLite). Persists ONLY the token registry (id, password
    # hash, response config). Incoming traffic is NEVER stored (fire-and-forget).
    # Default lives at the project root, not the launch directory.
    DATABASE_URL: str = os.getenv(
        "NEONRELAY_DATABASE_URL",
        f"sqlite+aiosqlite:///{os.path.join(PROJECT_ROOT, 'neonrelay.db')}",
    )

    # Plaintext file where the default admin credentials are written on first
    # boot (temporary convenience). Also at the project root by default.
    ADMIN_CREDS_FILE: str = os.getenv(
        "NEONRELAY_ADMIN_CREDS_FILE",
        os.path.join(PROJECT_ROOT, "admin-credentials.txt"),
    )

    # Max incoming body size in bytes (larger bodies are truncated before relay).
    MAX_BODY_BYTES: int = int(os.getenv("NEONRELAY_MAX_BODY_BYTES", 10 * 1024 * 1024))

    # Stash (hold-until-next-stream). A request relayed with ?__stash, if nobody
    # is listening, is kept in memory in a SINGLE slot per token (keep-latest:
    # each new one overwrites it) and delivered to the next listener, then
    # destroyed. Each slot is capped at this size, so the total memory ceiling is
    # (number of tokens) x this cap -- and tokens are admin-created only. Nothing
    # is ever written to disk.
    STASH_MAX_BYTES: int = int(os.getenv("NEONRELAY_STASH_MAX_BYTES", 256 * 1024))

    # Anti-spam / anti-DDoS: per-token token bucket on the relay endpoint.
    # RATE_LIMIT = sustained requests/second allowed per token; RATE_BURST =
    # how many may arrive back-to-back before the sustained rate kicks in
    # (defaults to RATE_LIMIT). Set RATE_LIMIT to 0 to disable rate limiting.
    RATE_LIMIT: float = float(os.getenv("NEONRELAY_RATE_LIMIT", 25))
    RATE_BURST: float = float(os.getenv("NEONRELAY_RATE_BURST", 0)) or RATE_LIMIT
    # When a token keeps hitting the limit, the Retry-After it gets back grows
    # exponentially (1s, 2s, 4s, 8s, ...) up to this cap, and resets once the
    # token behaves again. Punishes sustained abuse without a permanent ban.
    RATE_RETRY_MAX: float = float(os.getenv("NEONRELAY_RATE_RETRY_MAX", 600))

    # Canal bruité (/channel) : trames de taille fixe, à rythme fixe, dans les
    # deux sens. Un client envoie 1 trame par tic ; le serveur en renvoie SLOTS
    # par tic à chaque auditeur (les trames en attente, complétées par de
    # l'aléatoire). Bande passante descendante par client :
    # SLOTS x FRAME_BYTES / TICK (défaut 2 x 512 / 0,2 s = 5 Kio/s).
    # FRAME_BYTES doit rester égal à celui des clients (format de trame v2).
    CHANNEL_FRAME_BYTES: int = int(os.getenv("NEONRELAY_CHANNEL_FRAME_BYTES", 512))
    CHANNEL_TICK: float = float(os.getenv("NEONRELAY_CHANNEL_TICK", 0.2))
    CHANNEL_SLOTS: int = int(os.getenv("NEONRELAY_CHANNEL_SLOTS", 2))
    # Trames en attente par auditeur avant d'en jeter (auditeur trop lent).
    CHANNEL_QUEUE_FRAMES: int = int(os.getenv("NEONRELAY_CHANNEL_QUEUE_FRAMES", 200))
    # Débit montant toléré par boîte, toutes sessions confondues (trames/s) :
    # au-delà, la connexion montante est coupée (429).
    CHANNEL_FRAME_RATE: float = float(os.getenv("NEONRELAY_CHANNEL_FRAME_RATE", 20))
    CHANNEL_FRAME_BURST: float = float(os.getenv("NEONRELAY_CHANNEL_FRAME_BURST", 40))
    # Plafonds par boîte : flux descendants (auditeurs) et montants (émetteurs)
    # simultanés. Au-delà : 429 et connexion fermée. Une boîte sert à quelques
    # correspondants ; sans plafond, un seul mot de passe de boîte suffirait à
    # ouvrir des centaines de flux (bande passante et mémoire du serveur).
    CHANNEL_MAX_LISTENERS: int = int(os.getenv("NEONRELAY_CHANNEL_MAX_LISTENERS", 8))
    CHANNEL_MAX_SENDERS: int = int(os.getenv("NEONRELAY_CHANNEL_MAX_SENDERS", 8))
    # $/stashserver : trames gardées par boîte pour la prochaine session (UN
    # message, le dernier gagne ; 8 trames = ~2,9 Ko de texte, 4 Kio de RAM).
    CHANNEL_STASH_FRAMES: int = int(os.getenv("NEONRELAY_CHANNEL_STASH_FRAMES", 8))

    # PBKDF2 iterations for password hashing.
    PBKDF2_ITERATIONS: int = int(os.getenv("NEONRELAY_PBKDF2_ITERATIONS", 200_000))

    # Interactive API docs (/docs, /redoc) and the OpenAPI schema (/openapi.json)
    # are OFF by default: they would expose the whole API surface to anyone.
    # Set NEONRELAY_ENABLE_DOCS=true for local development only.
    ENABLE_DOCS: bool = os.getenv("NEONRELAY_ENABLE_DOCS", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


settings = Settings()
