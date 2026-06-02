"""Statistics collection and reporting."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)


class EventBus:
    """Lightweight pub/sub event bus for SSE broadcasting.

    Subscribers are ``asyncio.Queue`` instances added by SSE endpoint
    connections.  ``publish()`` pushes events to all subscriber queues
    without blocking the caller.
    """

    def __init__(self) -> None:
        self.subscribers: list[asyncio.Queue[dict[str, Any]]] = []

    async def publish(self, event: dict[str, Any]) -> None:
        """Send *event* to all current subscribers (non-blocking)."""
        for queue in list(self.subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                logger.debug("Dropped event for slow SSE subscriber (queue full)")
