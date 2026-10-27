"""Logging policy for the fire-and-forget relay.

Logs are ALWAYS anonymised, with no switch to turn that off:
  - uvicorn per-request ACCESS logs are permanently disabled. Those lines carry
    the peer IP (and the request path), so enabling them could
    deanonymise a user who relies on Tor/VPN. Not an option here, by design.
  - a minimal "event" logger prints ONE concise line per action
    (e.g. `[neonrelay] action=relay token=<id> delivered=1`): the token id (to
    spot abuse), never an IP, URL, body or secret. Nothing is persisted.
"""

import logging

# Minimal, always-on action logger. Emits non-sensitive one-liners.
event_log = logging.getLogger("neonrelay.event")


def configure_logging() -> None:
    # Our own always-on event logger (uvicorn configures its loggers, not ours).
    event_log.setLevel(logging.INFO)
    event_log.propagate = False
    if not event_log.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(levelname)s:     [neonrelay] %(message)s"))
        event_log.addHandler(handler)

    # Permanently silence uvicorn's per-request access logging (it would reveal
    # the peer IP). This is deliberate and not configurable.
    access = logging.getLogger("uvicorn.access")
    access.disabled = True
    access.handlers.clear()


def log_action(action: str, **fields) -> None:
    """One concise, non-sensitive line: `action=<action> k=v ...`."""
    extra = " ".join(f"{k}={v}" for k, v in fields.items())
    event_log.info("action=%s %s", action, extra)
