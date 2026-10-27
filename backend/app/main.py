"""NeonRelay application entrypoint (fire-and-forget relay).

Each concern lives under its own prefix, so there is no catch-all at the root
and no route-ordering hazard:
  * /relay/{token}/...  -- senders push traffic here
  * /listen/{token}     -- owner streams it live (also flushes a held __stash)
  * /config/...         -- owner creates and manages tokens
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from . import __version__
from .admin import ensure_admin
from .config import settings
from .database import init_db
from .logging_setup import configure_logging, log_action
from .routes import capture, tokens


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()  # access logs off by default; minimal action line on
    await init_db()
    await ensure_admin()  # create default admin + write credentials on first boot
    log_action("startup")
    yield


app = FastAPI(
    title="NeonRelay",
    version=__version__,
    description="Fire-and-forget HTTP relay with per-token password auth. "
    "Incoming traffic is pushed live to listeners and never stored.",
    lifespan=lifespan,
    # Docs/schema off unless explicitly enabled (don't expose the API surface).
    docs_url="/docs" if settings.ENABLE_DOCS else None,
    redoc_url="/redoc" if settings.ENABLE_DOCS else None,
    openapi_url="/openapi.json" if settings.ENABLE_DOCS else None,
)


@app.get("/healthz", tags=["meta"])
async def healthz():
    return {"status": "ok", "service": "neonrelay", "version": __version__}


# Owner-side APIs: managing tokens and receiving their traffic.
app.include_router(tokens.config_router)  # /config/...
app.include_router(tokens.listen_router)  # /listen/...
# Sender-side relay: where incoming traffic is captured.
app.include_router(capture.router)  # /relay/...
