"""Mitmproxy DumpMaster embedding and ScrubAddon.

This module provides a ``MitmproxyBackend`` that runs an embedded mitmproxy
``DumpMaster`` in a background thread, routing intercepted HTTPS traffic
through the scrub pipeline via a custom addon (``ScrubAddon``).

mitmproxy is an *optional* dependency — the module gracefully degrades and
raises clear errors if ``mitmproxy`` is not installed.
"""
from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any

logger = logging.getLogger(__name__)


class MitmproxyNotInstalled(RuntimeError):
    """Raised when mitmproxy is not available."""


def _check_mitmproxy_available() -> None:
    """Raise ``MitmproxyNotInstalled`` if the package is missing."""
    try:
        import mitmproxy  # noqa: F401
    except ImportError as exc:
        raise MitmproxyNotInstalled(
            "mitmproxy is not installed. "
            "Install with: pip install scruxy[mitmproxy]"
        ) from exc


class ScrubAddon:
    """mitmproxy addon that routes intercepted requests through the scrub pipeline.

    Parameters
    ----------
    pipeline_engine:
        The scrubbing pipeline engine instance. Expected to expose an
        ``async scrub(text, session_id)`` interface.
    session_store:
        The concurrent session store for token map lookups.
    """

    def __init__(
        self,
        pipeline_engine: Any = None,
        session_store: Any = None,
    ) -> None:
        # TODO: replace with real imports when modules are available
        # from scruxy.pipeline.engine import PipelineEngine
        # from scruxy.tokenmap.service import ConcurrentSessionStore
        self.pipeline_engine = pipeline_engine
        self.session_store = session_store

    def request(self, flow: Any) -> None:
        """Intercept and scrub an outgoing request.

        Called by mitmproxy for every intercepted request.

        .. warning:: Mitmproxy mode is not supported. The proxy will reject
           this mode at startup. This method raises if reached.
        """
        raise RuntimeError(
            "Mitmproxy scrubbing is not implemented — traffic would pass "
            "through without PII protection. Use reverse or forward proxy mode."
        )

    def response(self, flow: Any) -> None:
        """Intercept and unscrub an incoming response.

        Called by mitmproxy for every intercepted response.

        .. warning:: Mitmproxy mode is not supported. This method raises if reached.
        """
        raise RuntimeError(
            "Mitmproxy unscrubbing is not implemented — traffic would pass "
            "through without PII protection. Use reverse or forward proxy mode."
        )


class MitmproxyBackend:
    """Embedded mitmproxy backend for HTTPS interception fallback mode.

    Starts a mitmproxy ``DumpMaster`` in a background thread with the
    ``ScrubAddon`` installed.

    Parameters
    ----------
    listen_host:
        Host to bind the proxy to.
    listen_port:
        Port to bind the proxy to.
    allow_hosts:
        List of host patterns to intercept (e.g. ``["api.anthropic.com"]``).
        All other HTTPS traffic passes through as opaque tunnels.
    pipeline_engine:
        The scrubbing pipeline engine (passed through to ``ScrubAddon``).
    session_store:
        The session store (passed through to ``ScrubAddon``).
    """

    def __init__(
        self,
        listen_host: str = "localhost",
        listen_port: int = 8081,
        allow_hosts: list[str] | None = None,
        pipeline_engine: Any = None,
        session_store: Any = None,
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.allow_hosts = allow_hosts or []
        self.pipeline_engine = pipeline_engine
        self.session_store = session_store

        self._master: Any | None = None
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    async def start(self) -> None:
        """Start mitmproxy DumpMaster in a background thread.

        Raises ``MitmproxyNotInstalled`` if mitmproxy is not available.
        """
        _check_mitmproxy_available()

        from mitmproxy import options as mitmproxy_options
        from mitmproxy.tools.dump import DumpMaster

        opts = mitmproxy_options.Options(
            listen_host=self.listen_host,
            listen_port=self.listen_port,
            ssl_insecure=False,
        )

        if self.allow_hosts:
            opts.allow_hosts = self.allow_hosts

        addon = ScrubAddon(
            pipeline_engine=self.pipeline_engine,
            session_store=self.session_store,
        )

        self._master = DumpMaster(opts)
        self._master.addons.add(addon)

        self._thread = threading.Thread(
            target=self._run_master,
            name="mitmproxy-backend",
            daemon=True,
        )
        self._thread.start()

        logger.info(
            "mitmproxy backend started on %s:%s (allow_hosts=%s)",
            self.listen_host,
            self.listen_port,
            self.allow_hosts,
        )

    def _run_master(self) -> None:
        """Run the DumpMaster event loop (blocking, called in thread)."""
        try:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(self._master.run())
        except Exception:
            logger.exception("mitmproxy backend crashed")
        finally:
            if self._loop and not self._loop.is_closed():
                self._loop.close()

    async def stop(self) -> None:
        """Stop the mitmproxy DumpMaster and wait for its thread to finish."""
        if self._master is not None:
            self._master.shutdown()
            logger.info("mitmproxy backend shutdown signal sent")

        if self._thread is not None and self._thread.is_alive():
            # Give the thread a moment to finish
            self._thread.join(timeout=5.0)
            if self._thread.is_alive():
                logger.warning("mitmproxy backend thread did not stop within timeout")

        self._master = None
        self._thread = None
        logger.info("mitmproxy backend stopped")

    @property
    def is_running(self) -> bool:
        """Return ``True`` if the backend thread is alive."""
        return self._thread is not None and self._thread.is_alive()
