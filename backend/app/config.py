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
