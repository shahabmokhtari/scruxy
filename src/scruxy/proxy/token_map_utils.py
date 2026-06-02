"""Shared helpers for session-scoped response deanonymization."""
from __future__ import annotations

import inspect
from typing import Any


async def resolve_response_token_map(
    session_store: Any | None,
    session_id: str,
    fallback: Any | None,
) -> Any | None:
    """Return the session-scoped deanonymization map when available."""
    if session_store is None or not hasattr(session_store, "get_session_token_map"):
        return fallback
    candidate = session_store.get_session_token_map(session_id)
    if inspect.isawaitable(candidate):
        candidate = await candidate
    if candidate is None:
        return fallback
    try:
        unscrub_map = candidate.unscrub_map if hasattr(candidate, "unscrub_map") else None
    except Exception:
        unscrub_map = None
    return candidate if isinstance(unscrub_map, dict) else fallback
