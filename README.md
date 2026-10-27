<p align="center">
  <img src="assets/spider_logo.png" alt="NeonRelay" width="160">
</p>

<h1 align="center">NeonRelay</h1>
<p align="center"><em>Received, pushed, forgotten.</em></p>

A **fire-and-forget** HTTP relay, in the spirit of Webhook.site but
**backend-only** and **near-zero-retention**. Every box is a private inbox: you
need *both* the token id **and** its password to send to it or to listen on it.

An incoming request is **pushed live** to any connected SSE listener, then
**discarded**. Nothing the sender transmits is written to disk — no traffic
database, no file, no access log. If someone was listening, they get it; if
not, it's gone.

The one exception is the opt-in **stash** (`?__stash`): a request sent this way
is, if nobody is listening, held in a single in-memory slot and delivered to the
next listener that connects, then destroyed. Still never written to disk. See
[Stash](#stash-hold-until-next-stream).

- **Stack**: Python + FastAPI, async SQLAlchemy over **SQLite**
- **Real-time**: Server-Sent Events (SSE), one stream per token
- **Auth**: admin-gated creation + a password per token (PBKDF2-SHA256 hashed)
- **No trace**: only the token registry (id, password hash, response config) is
  persisted — never the traffic.

## Layout

```
neonrelay/
├── backend/app/        FastAPI application
├── scripts/            helper shell scripts (see below)
├── requirements.txt    Python dependencies
├── neonrelay.db        SQLite registry (git-ignored, created on first boot)
└── admin-credentials.txt  default admin creds (git-ignored, first boot only)
```

## Install & run

`launch.sh` creates the venv on first run and starts uvicorn. **TLS is
mandatory — there is no plaintext HTTP mode.** On first launch it generates a
self-signed `cert.pem` / `key.pem` at the project root (both git-ignored);
`key.pem` is the private key — keep it secret. If any TLS check fails (openssl
missing, bad or mismatched cert/key), it **aborts** instead of starting.

```bash
./scripts/launch.sh                                 # https://0.0.0.0:8000
HOST=127.0.0.1 PORT=9000 ./scripts/launch.sh
NEONRELAY_TLS_HOST=203.0.113.5 ./scripts/launch.sh  # add this IP/DNS to the cert
```

On success it prints `✅ TLS enabled and functional`. Health check:
`GET /healthz`. The interactive API docs (`/docs`, `/redoc`, `/openapi.json`)
are **off by default**; set `NEONRELAY_ENABLE_DOCS=true` for local development.

### How TLS works here (self-signed + pinning, no domain)

Clients **pin** the server's certificate instead of trusting a public CA —
which is actually stronger (you trust exactly one key you control, not ~150
CAs). The helper scripts do this automatically: they default to an `https://`
base and pin `cert.pem` at the project root. So on the same machine:

```bash
./scripts/token.sh      # talks HTTPS, verifies the pinned cert — nothing to set
```

On another machine, copy `cert.pem` over and point the scripts at it:

```bash
export NEONRELAY_BASE="https://203.0.113.5:8000"
export NEONRELAY_CACERT="/path/to/cert.pem"
./scripts/stream.sh
```

This encrypts everything on the wire (the password header, the body) and proves
the server's identity (no MITM), without a domain or Let's Encrypt. Anonymity is
a separate, higher layer: a user can route this HTTPS through Tor/VPN on top —
the two stack cleanly.

### Configuration (env vars)

| Variable | Default | Meaning |
|---|---|---|
| `NEONRELAY_DATABASE_URL` | `sqlite+aiosqlite:///<project>/neonrelay.db` | DB connection (registry only) |
| `NEONRELAY_MAX_BODY_BYTES` | `10485760` (10 MB) | Incoming bodies capped at this size |
| `NEONRELAY_STASH_MAX_BYTES` | `262144` (256 KB) | Stash slot size cap (per token) |
| `NEONRELAY_RATE_LIMIT` | `25` | Sustained relay req/s allowed per token (`0` disables) |
| `NEONRELAY_RATE_BURST` | = `RATE_LIMIT` | Back-to-back burst allowed before the sustained rate applies |
| `NEONRELAY_RATE_RETRY_MAX` | `600` | Cap (s) for the exponential `Retry-After` on repeated abuse |
| `NEONRELAY_PBKDF2_ITERATIONS` | `200000` | Password hashing cost |
| `NEONRELAY_ADMIN_USER` | `neonrelayadmin` | Default admin username (first boot) |
| `NEONRELAY_ADMIN_PASSWORD` | *(random)* | Default admin password (first boot) |
| `NEONRELAY_ADMIN_CREDS_FILE` | `<project>/admin-credentials.txt` | Where first-boot admin creds are written |
| `NEONRELAY_ENABLE_DOCS` | `false` | Expose `/docs`, `/redoc`, `/openapi.json` (dev only) |

## Logging (always anonymised)

Logs are **always** anonymised — there is no switch to turn that off, on purpose:

- uvicorn per-request **access logs are permanently disabled**. Those lines
  carry the peer IP (and the request path), so enabling them could deanonymise
  a user relying on Tor/VPN.
- only a minimal action line is printed, carrying the **token id** (to spot
  abuse) but never an IP, URL, body or secret, e.g.
  `[neonrelay] action=relay token=<id> method=POST delivered=1` and
  `[neonrelay] action=relay.throttled token=<id> retry_after=2`.

Nothing is persisted; the lines go to stdout only.

## Authentication

**Admin** (creating tokens) — `POST /config/tokens` requires admin credentials
via HTTP Basic. On first boot a default admin is created and written once to
`admin-credentials.txt` (`chmod 600`); the password is stored **hashed**.

**Token password** (sending / listening) — supplied two ways (first wins): the
`X-NeonRelay-Password` header, or HTTP Basic `base64(<token>:<password>)`.
Missing/wrong password → `401`. The password is **not** accepted in the URL
query: a password in a URL leaks into access logs, browser history and the
`Referer` header, so that path is removed, not just discouraged.

## API

Each concern lives under its own prefix (no catch-all at the root):

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/config/tokens` | 🔑 admin | Create a token; returns `id` + one-time `password` |
| GET | `/config/{id}` | 🔑 token | Token config |
| PATCH | `/config/{id}` | 🔑 token | Change the response returned to senders |
| DELETE | `/config/{id}` | 🔑 token | Delete the token |
| GET | `/listen/{id}` | 🔑 token | **SSE: listen live** (first receives any held `__stash` message) |
| ANY | `/relay/{id}/{any/sub/path}` | 🔑 token | The relay: push the request live, then forget it |
| ANY | `/relay/{id}/…?__stash=1` | 🔑 token | Relay **and hold** until the next listener if nobody is on now |

> There is **no** request-history endpoint. The only persisted state is the
> token registry; traffic is relayed live and (optionally) held in one
> in-memory slot until the next stream picks it up.

### Stash (hold until next stream)

Normally, a request that arrives while nobody is listening is lost. Add
`?__stash=1` to the relay URL and, **if nobody is listening at that moment**, the
request is held in the token's single in-memory slot and delivered to the **next
listener that connects** — then destroyed.

- **Per request**: the sender decides, with `?__stash=1`. No token config.
- **Only when unheard**: if a listener is already connected, the message is
  delivered live and nothing is held (no replay to later listeners).
- **Keep-latest**: while held, each new stash overwrites the slot — a flood
  never piles up, at most one payload is ever kept.
- **Delivered through the stream**: the first `/listen/{id}` to connect receives
  it as an ordinary request event, then the slot is empty again.
- **Bounded**: each slot is capped at `NEONRELAY_STASH_MAX_BYTES` (256 KB), so
  the total memory ceiling is `(number of tokens) × cap`, and tokens are
  admin-created only. Nothing is ever written to disk.

### Token TTL (expiry)

Create a token with `ttl_seconds` and it is rejected everywhere once that many
seconds have passed, with **`410 Gone`** (relay, listen, config alike). Omit it
(or `null`) for a token that never expires. `expires_at` is returned on create
and on `GET /config/{id}`.

```bash
curl -u admin:pw -X POST .../config/tokens \
  -H 'content-type: application/json' -d '{"ttl_seconds": 3600}'   # dies in 1h
```

### Rate limiting (anti-spam / DDoS)

Each token has a **token bucket** on the relay endpoint: `NEONRELAY_RATE_LIMIT`
requests/second sustained, with a burst of `NEONRELAY_RATE_BURST`. Past that, the
relay returns **`429 Too Many Requests`** with a `Retry-After` that **grows
exponentially** (1s, 2s, 4s, 8s, …, capped at `NEONRELAY_RATE_RETRY_MAX`) the
longer a token keeps abusing, and resets the moment it is back within budget.

Every relay logs the **token used** (`action=relay token=<id> …`) and every
rejection (`action=relay.throttled token=<id> retry_after=<s>`), so a flood is
easy to spot — and attribute to a box — even with access logs off. Set
`NEONRELAY_RATE_LIMIT=0` to disable. In-process (one bucket per token); use a
shared store for multi-instance.

## Helper scripts (`scripts/`)

| Script | What it does |
|---|---|
| `launch.sh` | Create the venv (first run) and start the server |
| `token.sh` | Create a token (admin), save creds to `last-token.env` |
| `config.sh` | Configure the current box's response (owner, interactive) |
| `relay.sh` | Send a payload to the box (lost if nobody is listening) |
| `stash.sh` | Send a payload, but hold it until the next `stream.sh` |
| `stream.sh` | Listen live (auto-sources `last-token.env`); receives any held message first |
| `readstash.sh` | Grab only the held stash message, then exit immediately |
| `count.sh` | How many listeners are connected now (optional refresh interval) |
| `delete.sh` | **Delete the current box for good** (owner; irreversible, confirms first) |
| `health.sh` | Check the server responds (`GET /healthz`); no token needed |
| `database_read_token.sh` | Dump the token registry from SQLite |
| `database_delete_token.sh` | Delete a token (or `--all`) straight from SQLite |

Scripts stay tiny by sourcing shared helpers from **`scripts/base/`** (sourced,
not run): `base/_token.sh` loads `BASE`/`TOKEN`/`PW` from `last-token.env`, and
`base/_userpass.sh` resolves the admin credentials.

## Quick example

```bash
B=https://localhost:8000
C=--cacert ./cert.pem            # pin the self-signed cert (at the project root)

# 1. Create a token (admin credentials from admin-credentials.txt)
AU=$(grep '^username=' admin-credentials.txt | cut -d= -f2-)
AP=$(grep '^password=' admin-credentials.txt | cut -d= -f2-)
resp=$(curl -s $C -u "$AU:$AP" -X POST $B/config/tokens -H 'content-type: application/json' -d '{}')
TOKEN=$(echo "$resp" | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")
PW=$(echo "$resp"    | python3 -c "import sys,json;print(json.load(sys.stdin)['password'])")

# 2. Listen live in one terminal…
curl $C -N "$B/listen/$TOKEN" -H "X-NeonRelay-Password: $PW"

# 3. …and send a request from another (it's relayed live, then forgotten)
curl $C -X POST "$B/relay/$TOKEN/my/hook" -H "X-NeonRelay-Password: $PW" -d '{"hello":"world"}'
```

(Or just: `./scripts/token.sh` then `./scripts/stream.sh`.)

## Notes & scaling

- SSE pub/sub and the stash are **in-process**: fine for a single instance. For
  multiple workers/instances, replace `app/events.py` with Redis pub/sub (same
  `publish`/`subscribe` interface) and a shared store for the stash.
- SQLite holds only the token registry; switch `NEONRELAY_DATABASE_URL` to
  PostgreSQL (`postgresql+asyncpg://…`) for high concurrency.
