"""FastAPI routes for the web UI: page serving, REST API endpoints, and SSE feed."""
from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import secrets
import re as _re
import shutil
import tempfile
import time
from pathlib import Path
from typing import AsyncGenerator

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static"

_NO_CACHE_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
}

_BUILTIN_PROVIDER_NAMES = frozenset({"anthropic", "openai", "openai_responses", "copilot_chat", "copilot_responses"})
_WHITESPACE_CHARS = " \t\n\r"
_whitelist_file_locks: dict[str, asyncio.Lock] = {}

router = APIRouter(prefix="/ui")


# HTTP methods that mutate state
_WRITE_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})


def _extract_host_header_host(host_header: str) -> str:
    """Return the host component from a Host header, handling IPv6 safely."""
    host_value = (host_header or "").strip().lower()
    if not host_value:
        return ""
    if host_value.startswith("["):
        closing = host_value.find("]")
        if closing != -1:
            return host_value[1:closing]
    if host_value.count(":") == 1:
        return host_value.split(":", 1)[0]
    return host_value


def _validate_local_ui_origin_and_host(
    request: Request,
    allowed_hosts: set[str],
    *,
    allowed_origin_hosts: set[str] | None = None,
) -> None:
    """Reject requests with untrusted Host/Origin headers."""
    req_host = _extract_host_header_host(request.headers.get("host") or "")
    if req_host not in allowed_hosts:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=403,
            detail=f"Host header '{req_host}' not allowed. Use localhost.",
        )

    if request.method in _WRITE_METHODS:
        origin = request.headers.get("origin", "")
        if origin:
            # Reject the literal "null" origin (sandboxed iframes, file://,
            # data:, opaque origins).  ``urlparse("null").hostname`` is
            # ``None`` which would otherwise normalise to ``""`` and pass
            # the membership check below if ``""`` is in ``allowed_hosts``.
            if origin.strip().lower() == "null":
                from fastapi import HTTPException
                raise HTTPException(
                    status_code=403,
                    detail="Origin 'null' is not allowed.",
                )
            from urllib.parse import urlparse as _urlparse_origin
            try:
                parsed_origin = _urlparse_origin(origin)
            except ValueError:
                parsed_origin = None
            origin_scheme = (parsed_origin.scheme.lower() if parsed_origin else "")
            origin_host = (parsed_origin.hostname.lower() if parsed_origin and parsed_origin.hostname else "")
            origin_allowlist = allowed_origin_hosts if allowed_origin_hosts is not None else allowed_hosts
            # Origin must parse as http/https with a real hostname in the
            # origin-specific allowlist.  An empty hostname (unparseable
            # Origin) is rejected unconditionally — write requests must
            # not be allowed from opaque origins.
            if (
                not origin_host
                or origin_scheme not in {"http", "https"}
                or origin_host not in origin_allowlist
            ):
                from fastapi import HTTPException
                raise HTTPException(
                    status_code=403,
                    detail=f"Cross-origin requests from '{origin}' are not allowed.",
                )


async def _localhost_write_guard(request: Request) -> None:
    """Block sensitive requests from non-loopback clients on public binds.

    Protects all mutating methods (POST/PUT/DELETE/PATCH) and sensitive
    GET endpoints that expose raw PII data (token maps, recordings).
    When bound to localhost, all requests are allowed.  When bound to
    0.0.0.0 or a public IP, only loopback client IPs are allowed for
    sensitive operations.
    """
    # Determine if this request needs protection
    is_write = request.method in _WRITE_METHODS
    is_sensitive_read = False
    if request.method == "GET":
        path = request.url.path
        # Endpoints that expose raw PII / unsanitized data
        _SENSITIVE_GET_PREFIXES = (
            "/ui/api/sessions/",    # token maps and recordings
            "/ui/api/sessions",     # session collection listing
            "/ui/api/token-map",    # shared token map
            "/ui/api/config",       # app configuration with paths/URLs
            "/ui/api/plugins/",     # plugin source code
            "/ui/api/scripts",      # replacement scripts
            "/ui/api/passthrough",  # raw passthrough traffic logs
            "/ui/api/recordings/",  # recent recordings with raw PII
            "/ui/api/dashboard",    # dashboard metadata (provider URLs, cert paths)
            "/ui/api/tester/state", # persisted tester payloads (real PII)
        )
        is_sensitive_read = any(path.startswith(p) for p in _SENSITIVE_GET_PREFIXES)

    if not is_write and not is_sensitive_read:
        return

    # Allow safe POST paths that don't mutate state
    if is_write:
        path = request.url.path
        _SAFE_POST_PATHS = {"/ui/api/cert/check"}
        if path in _SAFE_POST_PATHS:
            return

    host = getattr(request.app.state, "_listen_host", None)
    _LOOPBACK_BINDS = {"localhost", "127.0.0.1", "::1"}
    # Host header allowlist (includes "" for proxied/empty Host and the
    # ASGI test-client sentinel hosts).  Origin header has a stricter
    # allowlist that does NOT include "" or "null" so opaque origins
    # cannot bypass the CSRF guard on write requests.
    _ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1", "", "testserver", "test"}
    _ALLOWED_ORIGIN_HOSTS = {"localhost", "127.0.0.1", "::1", "testserver", "test"}

    # If bound to a loopback address, validate Host header to prevent
    # DNS rebinding attacks (attacker resolves evil.com to 127.0.0.1)
    if host in _LOOPBACK_BINDS:
        _validate_local_ui_origin_and_host(
            request, _ALLOWED_HOSTS, allowed_origin_hosts=_ALLOWED_ORIGIN_HOSTS,
        )
        return

    # If bound to 0.0.0.0 or a public IP, check the actual client IP
    client_ip = request.client.host if request.client else None
    _LOOPBACK_IPS = {"127.0.0.1", "::1", "localhost", "::ffff:127.0.0.1"}
    if client_ip in _LOOPBACK_IPS:
        _validate_local_ui_origin_and_host(
            request, _ALLOWED_HOSTS, allowed_origin_hosts=_ALLOWED_ORIGIN_HOSTS,
        )
        return

    from fastapi import HTTPException
    raise HTTPException(
        status_code=403,
        detail="This endpoint is restricted to loopback clients. Connect from localhost or configure authentication.",
    )


from fastapi import Depends

router.dependencies = [Depends(_localhost_write_guard)]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_stats(request: Request) -> object | None:
    """Return the stats service from app state, or None."""
    return getattr(request.app.state, "stats", None)


def _get_session_store(request: Request) -> object | None:
    """Return the session store from app state, or None."""
    return getattr(request.app.state, "session_store", None)


def _get_recording(request: Request) -> object | None:
    """Return the recording service from app state, or None."""
    return getattr(request.app.state, "recording", None)


def _get_pipeline(request: Request) -> object | None:
    """Return the pipeline engine from app state, or None."""
    return getattr(request.app.state, "pipeline", None)


def _get_providers(request: Request) -> object | None:
    """Return the provider registry from app state, or None."""
    return getattr(request.app.state, "providers", None)


def _get_config(request: Request) -> object | None:
    """Return the app config from app state, or None."""
    return getattr(request.app.state, "config", None)


def _get_event_bus(request: Request) -> object | None:
    """Return the SSE event bus from app state, or None."""
    return getattr(request.app.state, "event_bus", None)


def _get_config_path(request: Request) -> Path | None:
    """Return the config file path from app state, or None."""
    return getattr(request.app.state, "config_path", None)


def _set_live_recorder(request: Request, recorder: object | None) -> None:
    """Swap the live recorder across reverse- and forward-proxy paths.

    All fields are updated together so in-flight requests cannot observe
    a half-swapped state.
    """
    forward_proxy = getattr(request.app.state, "forward_proxy", None)
    if forward_proxy is not None:
        if hasattr(forward_proxy, "set_recorder"):
            forward_proxy.set_recorder(recorder)
        else:
            try:
                forward_proxy._recorder = recorder
            except Exception:
                logger.debug("Failed to update forward proxy recorder", exc_info=True)

    # Update both references last so forward-proxy is already consistent.
    request.app.state.recorder = recorder
    request.app.state.recording = recorder


def _apply_recording_runtime_config(request: Request) -> None:
    """Apply the current recording config to the live recorder instance.

    Replace the recorder object atomically instead of mutating it in place so
    in-flight request/response pairs keep writing to a consistent destination.
    """
    config = _get_config(request)
    if config is None:
        return

    recording_cfg = getattr(config, "recording", None)
    sessions_cfg = getattr(config, "sessions", None)
    enabled = bool(getattr(recording_cfg, "enabled", True))

    if not enabled:
        _set_live_recorder(request, None)
        return

    from scruxy.recording.recorder import SessionRecorder

    storage_dir = str(getattr(sessions_cfg, "storage_dir", "~/.scruxy/sessions"))
    store_body_original = bool(getattr(recording_cfg, "store_body_original", False))

    recorder = SessionRecorder(
        storage_dir=storage_dir,
        store_body_original=store_body_original,
    )
    _set_live_recorder(request, recorder)


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge *override* into *base*, returning a new dict.

    For keys present in both dicts where both values are themselves dicts, the
    merge recurses.  A ``None`` value in *override* deletes the key from *base*
    (used for null-deletion of replacement rules).  Otherwise the *override*
    value wins.
    """
    merged = dict(base)
    for key, value in override.items():
        if value is None:
            merged.pop(key, None)
        elif key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------

_VALID_PAGES = {
    "pipeline", "plugins", "providers", "tokens",
    "recordings", "logs", "settings", "tester", "passthrough",
}


@router.get("", include_in_schema=False)
async def dashboard_redirect() -> HTMLResponse:
    """Redirect /ui (no trailing slash) to /ui/."""
    from starlette.responses import RedirectResponse
    return RedirectResponse(url="/ui/", status_code=301)  # type: ignore[return-value]


@router.get("/", response_class=HTMLResponse)
async def dashboard_page() -> HTMLResponse:
    """Serve the main dashboard page."""
    index_path = STATIC_DIR / "index.html"
    return HTMLResponse(content=index_path.read_text(encoding="utf-8"), headers=_NO_CACHE_HEADERS)


@router.get("/api/dashboard", response_class=JSONResponse)
async def api_dashboard(request: Request) -> JSONResponse:
    """Return dashboard summary statistics."""
    stats = _get_stats(request)
    config = _get_config(request)
    session_store = _get_session_store(request)

    mode = "primary"
    providers: dict = {}
    if config is not None:
        mode = getattr(getattr(config, "interception", None), "mode", "primary")
    # Get providers from the live registry (includes builtin + config + YAML-only)
    registry = getattr(request.app.state, "registry", None)
    if registry is not None:
        for p in getattr(registry, "providers", []):
            providers[p.name] = {
                "enabled": getattr(p, "enabled", True),
                "upstream_url": getattr(p, "upstream_url", ""),
            }

    listen_host = "localhost"
    listen_port = 8080
    forward_proxy_port = 0
    forward_proxy_enabled = False
    https_port = 0
    https_enabled = False
    ca_cert_path = ""
    if config is not None:
        listen_host = getattr(getattr(config, "interception", None), "listen_host", "localhost")
        listen_port = getattr(getattr(config, "interception", None), "listen_port", 8080)
        fwd_cfg = getattr(getattr(config, "interception", None), "forward_proxy", None)
        if fwd_cfg is not None:
            forward_proxy_enabled = getattr(fwd_cfg, "enabled", False)
            forward_proxy_port = getattr(fwd_cfg, "listen_port", 8081)
            import os.path as _osp
            ca_cert_path = _osp.join(getattr(fwd_cfg, "ca_cert_dir", ""), "scruxy-ca.pem")
        https_cfg = getattr(getattr(config, "interception", None), "https", None)
        if https_cfg is not None:
            https_enabled = getattr(https_cfg, "enabled", False)
            https_port = getattr(https_cfg, "listen_port", 8443)

    active_sessions: list[str] = []
    if session_store is not None:
        active_sessions = list(getattr(session_store, "sessions", {}).keys())

    total_requests = 0
    total_entities = 0
    latency_history: list[float] = []
    unscrub_latency_history: list[float] = []
    network_latency_history: list[float] = []
    total_latency_history: list[float] = []
    recent_events: list[dict] = []
    latency_stats: dict = {}
    provider_latency: dict = {}
    if stats is not None:
        total_requests = getattr(stats, "total_requests", 0)
        total_entities = getattr(stats, "total_entities", 0)
        latency_history = list(getattr(stats, "latency_history", []))
        unscrub_latency_history = list(getattr(stats, "unscrub_latency_history", []))
        network_latency_history = list(getattr(stats, "network_latency_history", []))
        total_latency_history = list(getattr(stats, "total_latency_history", []))
        recent_events = list(getattr(stats, "recent_events", []))
        # Windowed latency stats
        get_ws = getattr(stats, "get_windowed_stats", None)
        if get_ws is not None:
            for label, minutes in [("5m", 5), ("15m", 15), ("30m", 30), ("1h", 60)]:
                latency_stats[label] = get_ws(minutes)
        # Per-provider latency histories
        get_plh = getattr(stats, "get_provider_latency_history", None)
        provider_total = getattr(stats, "provider_total_samples", {})
        if get_plh is not None:
            for pname in provider_total:
                provider_latency[pname] = get_plh(pname)

    cert_status = getattr(request.app.state, "cert_status", None)

    return JSONResponse(content={
        "mode": mode,
        "providers": providers,
        "active_sessions": active_sessions,
        "total_requests": total_requests,
        "total_entities": total_entities,
        "latency_history": latency_history,
        "unscrub_latency_history": unscrub_latency_history,
        "network_latency_history": network_latency_history,
        "total_latency_history": total_latency_history,
        "latency_stats": latency_stats,
        "provider_latency": provider_latency,
        "recent_events": recent_events,
        "listen_host": listen_host,
        "listen_port": listen_port,
        "forward_proxy_enabled": forward_proxy_enabled,
        "forward_proxy_port": forward_proxy_port,
        "https_enabled": https_enabled,
        "https_port": https_port,
        "ca_cert_path": ca_cert_path,
        "cert_status": cert_status,
    })


@router.post("/api/cert/check", response_class=JSONResponse)
async def api_cert_check(request: Request) -> JSONResponse:
    """Re-check cert status and return fresh info."""
    config = _get_config(request)
    if config is None:
        return JSONResponse(content={"error": "config not available"}, status_code=500)

    fwd_cfg = getattr(getattr(config, "interception", None), "forward_proxy", None)
    if fwd_cfg is None or not getattr(fwd_cfg, "enabled", False):
        return JSONResponse(content={"error": "forward proxy not enabled"}, status_code=400)

    from pathlib import Path as _Path

    from scruxy.cert.manager import CertManager

    ca_cert_dir = _Path(getattr(fwd_cfg, "ca_cert_dir", "~/.scruxy/certs")).expanduser()
    ca_cert_path = ca_cert_dir / "scruxy-ca.pem"

    mgr = CertManager(
        cert_dir=str(ca_cert_dir),
        auto_uninstall_on_exit=False,
        cert_path=ca_cert_path,
        cert_cn="Scruxy PII Proxy CA",
    )

    cert_status = await asyncio.to_thread(mgr.get_cert_info)
    # Update app state so dashboard picks up fresh status
    request.app.state.cert_status = cert_status
    return JSONResponse(content=cert_status)


@router.get("/api/sessions", response_class=JSONResponse)
async def api_sessions(request: Request) -> JSONResponse:
    """List all known sessions from both in-memory session store and on-disk recordings."""
    session_store = _get_session_store(request)
    recording = _get_recording(request)
    stats = _get_stats(request)

    seen: set[str] = set()
    sessions: list[dict] = []
    per_session_stats = getattr(stats, "per_session", {}) if stats else {}

    # 1. In-memory sessions from session_store (active sessions with token maps)
    if session_store is not None:
        session_ids = getattr(session_store, "session_ids", [])
        for sid in session_ids:
            seen.add(sid)
            ss = per_session_stats.get(sid, {})
            token_map = None
            get_tm = getattr(session_store, "get_token_map", None)
            if get_tm is not None:
                token_map = get_tm(sid)
            entity_count = ss.get("entities", 0)
            if entity_count == 0 and token_map is not None:
                entity_count = getattr(token_map, "size", 0)
            sessions.append({
                "session_id": sid,
                "provider": ss.get("provider", "unknown"),
                "created": "",
                "entity_count": entity_count,
            })

    # 2. On-disk sessions from recorder (persisted across restarts)
    if recording is not None:
        list_fn = getattr(recording, "list_sessions", None)
        if list_fn is not None:
            try:
                disk_sessions = list_fn()
                if asyncio.iscoroutine(disk_sessions):
                    disk_sessions = await disk_sessions
                for ds in (disk_sessions or []):
                    sid = ds.get("session_id", "")
                    if sid and sid not in seen:
                        seen.add(sid)
                        sessions.append({
                            "session_id": sid,
                            "provider": ds.get("provider", "unknown"),
                            "created": ds.get("started_at", ""),
                            "entity_count": ds.get("request_count", 0),
                        })
            except Exception:
                pass

        # 3. Scan storage directories for sessions not in the index
        storage_dir = getattr(recording, "storage_dir", None)
        if storage_dir is not None:
            try:
                from pathlib import Path
                sd = Path(storage_dir)
                if sd.exists():
                    for child in sd.iterdir():
                        if child.is_dir() and not child.name.startswith("_"):
                            sid = child.name
                            if sid not in seen:
                                seen.add(sid)
                                # Try to read provider from metadata.json
                                prov = "unknown"
                                meta_file = child / "metadata.json"
                                if meta_file.is_file():
                                    try:
                                        import json as _j
                                        with open(meta_file, encoding="utf-8") as _f:
                                            meta = _j.load(_f)
                                        prov = meta.get("provider", "unknown")
                                    except Exception:
                                        pass
                                sessions.append({
                                    "session_id": sid,
                                    "provider": prov,
                                    "created": "",
                                    "entity_count": 0,
                                })
            except Exception:
                pass

    # Infer provider from session ID prefix when still unknown
    for s in sessions:
        if s["provider"] == "unknown":
            sid = s["session_id"]
            if sid.startswith("claude-"):
                s["provider"] = "anthropic"
            elif sid.startswith("copilot-"):
                s["provider"] = "copilot"

    # For sessions still showing "unknown" provider, peek at their first recording entry
    if recording is not None:
        for s in sessions:
            if s["provider"] != "unknown":
                continue
            try:
                get_fn = getattr(recording, "get_session_recordings", None)
                if get_fn is None:
                    continue
                raw = get_fn(s["session_id"])
                if asyncio.iscoroutine(raw):
                    raw = await raw
                entries = list(raw) if raw else []
                for entry in entries:
                    prov = entry.get("provider", "")
                    if prov:
                        s["provider"] = prov
                        break
            except Exception:
                pass

    # Resolve session titles from Claude/Copilot transcripts
    title_resolver = getattr(request.app.state, "session_title_resolver", None)
    if title_resolver is not None:
        titles = title_resolver.resolve_all([s["session_id"] for s in sessions])
        for s in sessions:
            t = titles.get(s["session_id"], "")
            if t:
                s["title"] = t

    return JSONResponse(content={"sessions": sessions})


@router.get("/api/sessions/{session_id}/tokens", response_class=JSONResponse)
async def api_session_tokens(session_id: str, request: Request) -> JSONResponse:
    """Return the token map for a specific session (or full shared map for '_shared')."""
    session_store = _get_session_store(request)
    tokens: dict = {}
    entity_types: dict = {}
    token_meta_map: dict = {}
    token_map = None
    if session_store is not None:
        token_map = getattr(session_store, "shared_map", None)
        if token_map is not None:
            if session_id == "_shared":
                # Return the full shared map
                tokens = getattr(token_map, "scrub_map", {})
                entity_types = getattr(token_map, "entity_types", {})
                token_meta_map = getattr(token_map, "token_meta", {})
            else:
                # Filter to PII tagged to this session only
                session_pii: set[str] = set()
                if hasattr(session_store, "_session_pii_lock"):
                    with session_store._session_pii_lock:
                        session_pii = set(session_store._session_pii.get(session_id, set()))
                # No fallback: if no lock exists, skip filtering to avoid data races
                if session_pii:
                    all_tokens = getattr(token_map, "scrub_map", {})
                    all_types = getattr(token_map, "entity_types", {})
                    all_meta = getattr(token_map, "token_meta", {})
                    tokens = {k: v for k, v in all_tokens.items() if k in session_pii}
                    entity_types = {k: v for k, v in all_types.items() if k in session_pii}
                    token_meta_map = {k: v for k, v in all_meta.items() if k in session_pii}
    return JSONResponse(content={
        "session_id": session_id,
        "tokens": tokens,
        "entity_types": entity_types,
        "token_meta": {
            pii: meta.get("first_seen_request_id", "")
            for pii, meta in token_meta_map.items()
        },
    })


@router.get("/api/sessions/{session_id}/recordings", response_class=JSONResponse)
async def api_session_recordings(session_id: str, request: Request) -> JSONResponse:
    """Return recording entries for a specific session, grouped by request_id."""
    recording = _get_recording(request)
    entries: list[dict] = []
    if recording is not None:
        # Try get_session_recordings (actual method), fallback to get_entries
        get_fn = getattr(recording, "get_session_recordings", None) or getattr(recording, "get_entries", None)
        if get_fn is not None:
            raw = get_fn(session_id)
            if asyncio.iscoroutine(raw):
                raw = await raw
            entries = list(raw) if raw else []

    # Group entries by request_id into pairs
    pairs_map: dict[str, dict] = {}
    unpaired: list[dict] = []
    for entry in entries:
        rid = entry.get("request_id", "")
        if rid:
            if rid not in pairs_map:
                pairs_map[rid] = {"request_id": rid, "request": None, "response": None}
            if entry.get("dir") == "request":
                pairs_map[rid]["request"] = entry
            elif entry.get("dir") == "response":
                pairs_map[rid]["response"] = entry
        else:
            unpaired.append(entry)

    pairs = list(pairs_map.values())

    return JSONResponse(content={
        "session_id": session_id,
        "recordings": entries,
        "pairs": pairs,
        "unpaired": unpaired,
    })


@router.get("/api/recordings/recent", response_class=JSONResponse)
async def api_recent_recordings(request: Request) -> JSONResponse:
    """Return recent recording entries across all sessions, newest first.

    Query params:
        limit: Maximum entries to return (default 50, max 200).
    """
    try:
        limit = min(int(request.query_params.get("limit", "50")), 200)
    except (ValueError, TypeError):
        limit = 50
    recording = _get_recording(request)
    entries: list[dict] = []
    if recording is not None:
        get_fn = getattr(recording, "get_recent_recordings", None)
        if get_fn is not None:
            raw = get_fn(limit)
            if asyncio.iscoroutine(raw):
                raw = await raw
            entries = list(raw) if raw else []

    # Group entries by request_id into pairs (same logic as per-session endpoint)
    pairs_map: dict[str, dict] = {}
    unpaired: list[dict] = []
    for entry in entries:
        rid = entry.get("request_id", "")
        if rid:
            if rid not in pairs_map:
                pairs_map[rid] = {
                    "request_id": rid,
                    "session_id": entry.get("session_id", ""),
                    "request": None,
                    "response": None,
                }
            if entry.get("dir") == "request":
                pairs_map[rid]["request"] = entry
            elif entry.get("dir") == "response":
                pairs_map[rid]["response"] = entry
        else:
            unpaired.append(entry)

    pairs = sorted(pairs_map.values(), key=lambda p: (p.get("request") or p.get("response") or {}).get("ts", ""))

    return JSONResponse(content={
        "pairs": pairs,
        "unpaired": unpaired,
    })


@router.get("/api/pipeline/config", response_class=JSONResponse)
async def api_pipeline_config(request: Request) -> JSONResponse:
    """Return the current pipeline configuration."""
    config = _get_config(request)
    stages: list[dict] = []
    if config is not None:
        pipeline_cfg = getattr(config, "pipeline", None)
        if pipeline_cfg is not None:
            for stage in getattr(pipeline_cfg, "stages", []):
                stages.append({
                    "name": getattr(stage, "name", ""),
                    "enabled": getattr(stage, "enabled", True),
                    "config": getattr(stage, "config", {}),
                })
    return JSONResponse(content={"stages": stages})


def _find_stage_config(request: Request, stage_name: str) -> dict:
    """Find the config dict for a named stage from the app config."""
    config = _get_config(request)
    if config is not None:
        pipeline_cfg = getattr(config, "pipeline", None)
        if pipeline_cfg is not None:
            for stage_cfg in getattr(pipeline_cfg, "stages", []):
                if getattr(stage_cfg, "name", "") == stage_name:
                    return getattr(stage_cfg, "config", {})
    return {}


def _find_stage_config_by_type(config: object | None, stage_type: str) -> dict:
    """Find the first persisted config dict for a plugin base type."""
    if config is None:
        return {}
    pipeline_cfg = getattr(config, "pipeline", None)
    if pipeline_cfg is None:
        return {}
    for stage_cfg in getattr(pipeline_cfg, "stages", []):
        if _get_stage_type_from_config(stage_cfg) == stage_type:
            return dict(getattr(stage_cfg, "config", {}) or {})
    return {}


def _serialize_config_schema(schema_raw: list) -> list[dict]:
    """Serialize a list of ConfigField instances to dicts for JSON output."""
    return [
        {
            "name": f.name,
            "field_type": f.field_type,
            "default": f.default,
            "description": f.description,
            "choices": f.choices,
            "min_value": f.min_value,
            "max_value": f.max_value,
            "label": getattr(f, "label", ""),
            "details": getattr(f, "details", ""),
        }
        for f in schema_raw
    ]


def _get_entity_types(stage: object) -> list[str]:
    """Extract entity types from a stage.

    For stages with ``_entities`` (e.g. PresidioPlugin), return those.
    For stages with ``_patterns`` (e.g. RegexPlugin), extract from patterns.
    Otherwise return the ``entity_types`` attribute or empty list.
    """
    # Presidio: configured entity list
    entities = getattr(stage, "_entities", None)
    if entities:
        return list(entities)
    # Regex: extract from compiled patterns
    patterns = getattr(stage, "_patterns", None)
    if patterns is not None:
        return sorted({getattr(p, "entity_type", "") for p in patterns} - {""})
    # Fallback
    return getattr(stage, "entity_types", [])


_BUILTIN_DISPLAY_NAMES = {
    "whitelist": "Whitelist",
    "presidio": "Microsoft Presidio",
    "regex": "Regex Patterns",
    "file_path": "File Path Detection",
}


def _resolve_base_type(name: str) -> str:
    """Resolve a stage name (e.g. ``whitelist_copy``) to its base plugin type."""
    for base in _BUILTIN_DISPLAY_NAMES:
        if name == base or name.startswith(base + "_copy"):
            return base
    return name


def _get_whitelist_lock(file_path: Path) -> asyncio.Lock:
    """Return a per-file lock for whitelist updates."""
    key = str(file_path.resolve()) if file_path.is_absolute() else str(file_path)
    lock = _whitelist_file_locks.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _whitelist_file_locks[key] = lock
    return lock


def _get_stage_type_from_config(stage_cfg: object) -> str:
    """Return the persisted stage type, falling back to legacy name inference."""
    stage_type = getattr(stage_cfg, "stage_type", "")
    if stage_type:
        return stage_type
    return _resolve_base_type(getattr(stage_cfg, "name", ""))


def _get_stage_type(request: Request, stage_name: str) -> str:
    """Resolve a stage's plugin type from persisted config or runtime metadata."""
    config = _get_config(request)
    if config is not None:
        for stage_cfg in getattr(getattr(config, "pipeline", None), "stages", []):
            if getattr(stage_cfg, "name", "") == stage_name:
                return _get_stage_type_from_config(stage_cfg)

    pipeline = _get_pipeline(request)
    if pipeline is not None:
        for stage in getattr(pipeline, "stages", []):
            if getattr(stage, "name", "") == stage_name:
                if getattr(stage, "plugin_type", "") == "builtin":
                    for base_name, cls in _get_builtin_plugin_classes().items():
                        if isinstance(stage, cls):
                            return base_name
                return getattr(stage, "name", "")

    return stage_name


def _is_whitelist_type(stage_type: str) -> bool:
    return stage_type == "whitelist"


def _get_plugin_stage_config(config: object | None) -> object | None:
    if config is None:
        return None
    for stage_cfg in getattr(getattr(config, "pipeline", None), "stages", []):
        if getattr(stage_cfg, "name", "") == "plugins":
            return stage_cfg
    return None


def _get_user_plugin_config(
    config: object | None,
    plugin_name: str,
    *,
    create: bool = False,
) -> dict | None:
    """Return persisted config for a user plugin under the plugins stage."""
    plugin_stage_cfg = _get_plugin_stage_config(config)
    if plugin_stage_cfg is None:
        return None
    stage_config = getattr(plugin_stage_cfg, "config", {})
    plugin_configs = (
        stage_config.setdefault("plugin_configs", {})
        if create
        else stage_config.get("plugin_configs", {})
    )
    if create:
        plugin_cfg = plugin_configs.setdefault(plugin_name, {})
        plugin_stage_cfg.config = stage_config
        return plugin_cfg
    return plugin_configs.get(plugin_name)


def _normalize_stage_order_in_place(stages: list[object], stage_type_resolver) -> None:
    """Keep whitelist stages ahead of all other detectors while preserving order."""
    whitelists = [stage for stage in stages if _is_whitelist_type(stage_type_resolver(stage))]
    others = [stage for stage in stages if not _is_whitelist_type(stage_type_resolver(stage))]
    stages[:] = whitelists + others


def _normalize_pipeline_order(request: Request) -> None:
    pipeline = _get_pipeline(request)
    if pipeline is None:
        return
    _normalize_stage_order_in_place(
        getattr(pipeline, "stages", []),
        lambda stage: _get_stage_type(request, getattr(stage, "name", "")),
    )


def _normalize_config_stage_order(config: object | None) -> None:
    if config is None:
        return
    cfg_stages = getattr(getattr(config, "pipeline", None), "stages", [])
    _normalize_stage_order_in_place(cfg_stages, _get_stage_type_from_config)


def _write_text_atomically(path: Path, content: str, *, encoding: str = "utf-8") -> None:
    """Write text atomically so readers never observe a partial file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=".scruxy_ui_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding=encoding) as handle:
            handle.write(content)
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _get_display_name(name: str, request: Request) -> str:
    """Return the display name for a stage, checking persisted config first."""
    config = _get_config(request)
    if config is not None:
        for stage_cfg in getattr(getattr(config, "pipeline", None), "stages", []):
            if getattr(stage_cfg, "name", "") == name:
                dn = getattr(stage_cfg, "display_name", "")
                if dn:
                    return dn
                user_plugin_cfg = _get_user_plugin_config(config, name)
                if user_plugin_cfg:
                    user_display_name = (user_plugin_cfg.get("_display_name") or "").strip()
                    if user_display_name:
                        return user_display_name
                base = _get_stage_type_from_config(stage_cfg)
                builtin_dn = _BUILTIN_DISPLAY_NAMES.get(base)
                if builtin_dn:
                    return builtin_dn if name == base else name.replace("_", " ").title()
                break
        user_plugin_cfg = _get_user_plugin_config(config, name)
        if user_plugin_cfg:
            user_display_name = (user_plugin_cfg.get("_display_name") or "").strip()
            if user_display_name:
                return user_display_name
    # Fallback: builtin display names, then title-case for user plugins
    base = _get_stage_type(request, name)
    builtin_dn = _BUILTIN_DISPLAY_NAMES.get(base)
    if builtin_dn:
        return builtin_dn if name == base else name.replace("_", " ").title()
    return name.replace("_", " ").title()


def _serialize_detector_plugin(stage: object, request: Request) -> dict:
    """Serialize a DetectorPlugin (or compatible stage) to a JSON-friendly dict."""
    name = getattr(stage, "name", "unknown")
    config_schema_raw = getattr(stage, "config_schema", [])
    payload: dict = {
        "name": name,
        "display_name": _get_display_name(name, request),
        "type": getattr(stage, "plugin_type", "user"),
        "version": getattr(stage, "version", "0.0.0"),
        "enabled": getattr(stage, "enabled", True),
        "description": getattr(stage, "description", ""),
        "entity_types": _get_entity_types(stage),
        "config": _find_stage_config(request, name),
        "config_schema": _serialize_config_schema(config_schema_raw),
    }
    # OPF carries an optional ML dependency.  Surface install status so
    # the Plugins page can render an "Install" button or "Loading
    # model on first request" hint instead of just letting the plugin
    # silently fail.
    if name == "openai_privacy_filter":
        try:
            import importlib.util as _util
            opf_installed = _util.find_spec("opf") is not None
        except Exception:
            opf_installed = False
        payload["install_status"] = {
            "package_installed": opf_installed,
            "import_failed": bool(getattr(stage, "_import_failed", not opf_installed)),
            "runtime_loaded": getattr(stage, "_opf", None) is not None,
            "install_endpoint": "/ui/api/plugins/openai_privacy_filter/install",
        }
    return payload


@router.get("/api/plugins", response_class=JSONResponse)
async def api_plugins(request: Request) -> JSONResponse:
    """Return all detection stages (builtin and user plugins).

    Builtin plugins that exist in code but are not in the pipeline config
    are included as disabled entries so users can enable them from the UI.
    """
    pipeline = _get_pipeline(request)
    plugins: list[dict] = []
    seen_names: set[str] = set()

    if pipeline is not None:
        # Add pre_filter as a virtual plugin (first in list)
        plugins.append({
            "name": "pre_filter",
            "display_name": "Known PII Pre-Filter",
            "type": "builtin",
            "version": "1.0.0",
            "enabled": getattr(pipeline, "pre_filter_enabled", True),
            "description": "Bulk-replaces known PII from the global token map before running detection stages. Improves performance on repeated PII.",
            "entity_types": [],
            "config": {},
            "config_schema": [],
        })
        seen_names.add("pre_filter")

        for stage in getattr(pipeline, "stages", []):
            # Check if this stage is a DetectorPlugin (has name, plugin_type, etc.)
            if hasattr(stage, "name") and hasattr(stage, "plugin_type"):
                plugins.append(_serialize_detector_plugin(stage, request))
                seen_names.add(getattr(stage, "name", ""))
            elif hasattr(stage, "plugins"):
                # PluginStage: iterate its wrapped user plugins
                raw_plugins = getattr(stage, "plugins", [])
                for p in raw_plugins:
                    plugins.append(_serialize_detector_plugin(p, request))
                    seen_names.add(getattr(p, "name", ""))

    return JSONResponse(content={"plugins": plugins})


@router.put("/api/plugins/reorder", response_class=JSONResponse)
async def api_plugins_reorder(request: Request) -> JSONResponse:
    """Reorder pipeline stages. Accepts JSON body with ``order``: list of stage names.

    The pre_filter virtual plugin is excluded from reordering (always runs first).
    Only reorders the real pipeline stages and persists the new order to config.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})

    order = body.get("order")
    if not isinstance(order, list):
        return JSONResponse(status_code=400, content={"error": "'order' must be a list of stage names"})

    # Filter out pre_filter (virtual, not a real stage)
    order = [name for name in order if name != "pre_filter"]

    pipeline = _get_pipeline(request)
    config = _get_config(request)
    if pipeline is None or config is None:
        return JSONResponse(status_code=500, content={"error": "Pipeline not loaded"})

    # Build name→stage lookup for runtime stages
    stage_by_name: dict[str, object] = {}
    for stage in getattr(pipeline, "stages", []):
        name = getattr(stage, "name", None)
        if name:
            stage_by_name[name] = stage
        elif hasattr(stage, "plugins"):
            stage_by_name["plugins"] = stage

    # Reorder runtime stages
    new_stages = []
    for name in order:
        if name in stage_by_name:
            new_stages.append(stage_by_name.pop(name))
    # Append any stages not in the order list (shouldn't happen, but safety)
    for stage in stage_by_name.values():
        new_stages.append(stage)
    pipeline.stages = new_stages
    _normalize_pipeline_order(request)

    # Reorder config stages to match
    pipeline_cfg = getattr(config, "pipeline", None)
    if pipeline_cfg is not None:
        cfg_by_name = {getattr(s, "name", ""): s for s in getattr(pipeline_cfg, "stages", [])}
        new_cfg_stages = []
        for name in order:
            if name in cfg_by_name:
                new_cfg_stages.append(cfg_by_name.pop(name))
        for s in cfg_by_name.values():
            new_cfg_stages.append(s)
        pipeline_cfg.stages = new_cfg_stages
        _normalize_config_stage_order(config)
        _persist_config(request, config)

    return JSONResponse(content={"order": order})


@router.put("/api/pipeline/stages/{name}", response_class=JSONResponse)
async def api_pipeline_stage_toggle(name: str, request: Request) -> JSONResponse:
    """Enable or disable a pipeline stage by name.

    Accepts a JSON body with ``enabled`` (bool).  Updates both the config
    model (persisted to disk) and the live pipeline stage object.
    """
    config = _get_config(request)
    if config is None:
        return JSONResponse(status_code=500, content={"error": "No configuration loaded"})

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})

    if not isinstance(body, dict) or "enabled" not in body:
        return JSONResponse(status_code=400, content={"error": "Request body must contain 'enabled' boolean"})

    raw_enabled = body["enabled"]
    if not isinstance(raw_enabled, bool):
        return JSONResponse(status_code=400, content={"error": "'enabled' must be a boolean (true/false), not a string"})
    enabled = raw_enabled
    pipeline_cfg = getattr(config, "pipeline", None)
    if pipeline_cfg is None:
        return JSONResponse(status_code=500, content={"error": "No pipeline configuration"})

    stage_found = False
    for stage_cfg in getattr(pipeline_cfg, "stages", []):
        if getattr(stage_cfg, "name", "") == name:
            stage_cfg.enabled = enabled
            stage_found = True
            break

    if not stage_found:
        return JSONResponse(status_code=404, content={"error": f"Stage '{name}' not found"})

    # Also toggle the runtime stage object
    pipeline = _get_pipeline(request)
    if pipeline is not None:
        for stage in getattr(pipeline, "stages", []):
            if getattr(stage, "name", None) == name:
                stage.enabled = enabled
                break

    # Persist to disk
    _persist_config(request, config)

    return JSONResponse(content={"name": name, "enabled": enabled})


@router.put("/api/plugins/{plugin_name}/toggle", response_class=JSONResponse)
async def api_plugin_toggle(plugin_name: str, request: Request) -> JSONResponse:
    """Enable or disable a plugin by name.

    Works for both builtin stages (presidio, regex) and user plugins
    inside the PluginStage wrapper.  Accepts JSON body with ``enabled`` (bool).
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})

    if not isinstance(body, dict) or "enabled" not in body:
        return JSONResponse(status_code=400, content={"error": "Request body must contain 'enabled' boolean"})

    raw_enabled = body["enabled"]
    if not isinstance(raw_enabled, bool):
        return JSONResponse(status_code=400, content={"error": "'enabled' must be a boolean (true/false), not a string"})
    enabled = raw_enabled

    # Handle pre_filter virtual plugin
    pipeline = _get_pipeline(request)
    if plugin_name == "pre_filter" and pipeline is not None:
        pipeline.pre_filter_enabled = enabled
        return JSONResponse(content={"name": plugin_name, "enabled": enabled})

    # Try as a builtin stage first
    config = _get_config(request)

    # Check builtin stages
    if config is not None:
        pipeline_cfg = getattr(config, "pipeline", None)
        if pipeline_cfg is not None:
            for stage_cfg in getattr(pipeline_cfg, "stages", []):
                if getattr(stage_cfg, "name", "") == plugin_name:
                    stage_cfg.enabled = enabled
                    # Toggle the runtime stage
                    if pipeline is not None:
                        for stage in getattr(pipeline, "stages", []):
                            if getattr(stage, "name", None) == plugin_name:
                                stage.enabled = enabled
                                break
                    _persist_config(request, config)
                    return JSONResponse(content={"name": plugin_name, "enabled": enabled})

    # Check user plugins inside PluginStage
    if pipeline is not None:
        for stage in getattr(pipeline, "stages", []):
            if hasattr(stage, "plugins"):
                for p in getattr(stage, "plugins", []):
                    if getattr(p, "name", "") == plugin_name:
                        p.enabled = enabled
                        # Persist disabled_plugins list in config
                        if config is not None:
                            pipeline_cfg = getattr(config, "pipeline", None)
                            if pipeline_cfg is not None:
                                for stage_cfg in getattr(pipeline_cfg, "stages", []):
                                    if getattr(stage_cfg, "name", "") == "plugins":
                                        disabled = set(stage_cfg.config.get("disabled_plugins", []))
                                        if enabled:
                                            disabled.discard(plugin_name)
                                        else:
                                            disabled.add(plugin_name)
                                        stage_cfg.config["disabled_plugins"] = sorted(disabled)
                                        break
                            _persist_config(request, config)
                        return JSONResponse(content={"name": plugin_name, "enabled": enabled})

    return JSONResponse(status_code=404, content={"error": f"Plugin '{plugin_name}' not found"})


@router.put("/api/replacements/{entity_type}/toggle", response_class=JSONResponse)
async def api_replacement_toggle(entity_type: str, request: Request) -> JSONResponse:
    """Enable or disable a replacement rule by entity type."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})

    if not isinstance(body, dict) or "enabled" not in body:
        return JSONResponse(status_code=400, content={"error": "Request body must contain 'enabled' boolean"})

    raw_enabled = body["enabled"]
    if not isinstance(raw_enabled, bool):
        return JSONResponse(status_code=400, content={"error": "'enabled' must be a boolean (true/false), not a string"})
    enabled = raw_enabled
    config = _get_config(request)
    if config is None:
        return JSONResponse(status_code=500, content={"error": "Config not available"})

    replacements = getattr(getattr(config, "tokens", None), "replacements", None)
    if replacements is None or entity_type not in replacements:
        return JSONResponse(status_code=404, content={"error": f"Replacement rule '{entity_type}' not found"})

    replacements[entity_type].enabled = enabled

    # Rebuild runtime strategies
    _reload_all_stages(request)
    _persist_config(request, config)

    return JSONResponse(content={"entity_type": entity_type, "enabled": enabled})


@router.get("/api/plugins/regex/patterns-file", response_class=JSONResponse)
async def api_regex_patterns_file_get_legacy(request: Request) -> JSONResponse:
    """Legacy endpoint — redirects to generic file endpoint."""
    return await api_plugin_file_get("regex", "patterns_file", request)


@router.put("/api/plugins/regex/patterns-file", response_class=JSONResponse)
async def api_regex_patterns_file_put_legacy(request: Request) -> JSONResponse:
    """Legacy endpoint — redirects to generic file endpoint."""
    return await api_plugin_file_put("regex", "patterns_file", request)


@router.get("/api/plugins/{plugin_name}/file/{field_name}", response_class=JSONResponse)
async def api_plugin_file_get(plugin_name: str, field_name: str, request: Request) -> JSONResponse:
    """Return the file path, content, and existence status for a plugin's file field."""
    file_path_str = _find_plugin_file_path(request, plugin_name, field_name)

    if not file_path_str:
        return JSONResponse(content={"path": "", "content": "", "exists": False})

    file_path = Path(file_path_str).expanduser()
    exists = file_path.exists()
    content = ""
    if exists:
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as exc:
            logger.warning("Failed to read file %s: %s", file_path, exc)

    return JSONResponse(content={"path": str(file_path), "content": content, "exists": exists})


@router.put("/api/plugins/{plugin_name}/file/{field_name}", response_class=JSONResponse)
async def api_plugin_file_put(plugin_name: str, field_name: str, request: Request) -> JSONResponse:
    """Write content to a plugin's file field.

    Accepts a JSON body with ``content`` (str).  Validates YAML syntax
    before writing.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})

    content = body.get("content")
    if content is None:
        return JSONResponse(status_code=400, content={"error": "Missing 'content' in request body"})

    # Validate YAML
    import yaml as _yaml

    try:
        _yaml.safe_load(content)
    except _yaml.YAMLError as exc:
        return JSONResponse(status_code=400, content={"error": f"Invalid YAML: {exc}"})

    file_path_str = _find_plugin_file_path(request, plugin_name, field_name)
    if not file_path_str:
        return JSONResponse(status_code=400, content={"error": f"No '{field_name}' configured for {plugin_name}"})

    file_path = Path(file_path_str).expanduser()

    # Sandbox: file must be under the scruxy config directory, the app's
    # config directory, or in the same directory as the configured path
    # for this specific stage/field (which the admin set at startup).
    config_dir = Path("~/.scruxy").expanduser().resolve()
    config_path = _get_config_path(request)
    alt_dir = config_path.parent.resolve() if config_path else None
    resolved = file_path.resolve()
    allowed = False
    try:
        allowed = resolved.is_relative_to(config_dir)
        if not allowed and alt_dir:
            allowed = resolved.is_relative_to(alt_dir)
    except AttributeError:
        allowed = str(resolved).startswith(str(config_dir) + os.sep)
        if not allowed and alt_dir:
            allowed = str(resolved).startswith(str(alt_dir) + os.sep)
    # Also allow the exact configured path itself (but NOT arbitrary
    # siblings — compare against the resolved configured path, not its parent)
    if not allowed:
        configured = _find_plugin_file_path(request, plugin_name, field_name)
        if configured:
            configured_resolved = Path(configured).expanduser().resolve()
            allowed = resolved == configured_resolved
    if not allowed:
        return JSONResponse(status_code=400, content={"error": "File path must be within an allowed config directory"})

    try:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        _write_text_atomically(file_path, content)
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": f"Failed to write file: {exc}"})

    # Reload the stage so it picks up the new file content immediately
    _reload_stage(request, plugin_name)

    return JSONResponse(content={"message": "File updated", "path": str(file_path)})


def _find_plugin_file_path(request: Request, plugin_name: str, field_name: str) -> str:
    """Look up the file path for a plugin's file-type config field."""
    config = _get_config(request)
    if config is None:
        return ""
    pipeline_cfg = getattr(config, "pipeline", None)
    if pipeline_cfg is None:
        return ""
    for stage_cfg in getattr(pipeline_cfg, "stages", []):
        if getattr(stage_cfg, "name", "") == plugin_name:
            return getattr(stage_cfg, "config", {}).get(field_name, "")
    # Check user plugin configs
    for stage_cfg in getattr(pipeline_cfg, "stages", []):
        if getattr(stage_cfg, "name", "") == "plugins":
            plugin_configs = getattr(stage_cfg, "config", {}).get("plugin_configs", {})
            return plugin_configs.get(plugin_name, {}).get(field_name, "")
    return ""


# ---------------------------------------------------------------------------
# Tester endpoints
# ---------------------------------------------------------------------------

_TESTER_SAMPLES: dict = {
    "anthropic": {
        "display_name": "Anthropic Claude",
        "request_body": {
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "system": "You are a helpful assistant for Acme Corp. The IT admin is John Smith (john.smith@acme.com, ext. 4521).",
            "messages": [
                {
                    "role": "user",
                    "content": "Hi, my name is Sarah Johnson. My email is sarah.j@example.com and my phone is 555-867-5309. Can you help me reset my password? My employee badge is BADGE-4872 and I work on Project Phoenix.",
                }
            ],
        },
        "response_body": {
            "id": "msg_test_001",
            "type": "message",
            "role": "assistant",
            "content": [
                {
                    "type": "text",
                    "text": "Hello REDACTED_PERSON_2! I can help you reset your password. I'll send the reset link to REDACTED_EMAIL_ADDRESS_2. For verification, I see your badge is REDACTED_BADGE_NUMBER_1 and you're part of REDACTED_PROJECT_CODENAME_1. Please check your email.",
                }
            ],
            "model": "claude-sonnet-4-20250514",
            "stop_reason": "end_turn",
        },
        "request_text_paths": [
            "$.system",
            "$.messages[*].content",
            "$.messages[*].content[*].text",
            "$.messages[*].content[*].content",
        ],
        "response_text_paths": ["$.content[*].text"],
    },
    "openai": {
        "display_name": "OpenAI / Copilot",
        "request_body": {
            "model": "gpt-4o",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a helpful assistant for Acme Corp. The IT admin is John Smith (john.smith@acme.com, ext. 4521).",
                },
                {
                    "role": "user",
                    "content": "Hi, my name is Sarah Johnson. My email is sarah.j@example.com and my phone is 555-867-5309. Can you help me reset my password? My employee badge is BADGE-4872 and I work on Project Phoenix.",
                },
            ],
        },
        "response_body": {
            "id": "chatcmpl-test001",
            "object": "chat.completion",
            "model": "gpt-4o",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "Hello REDACTED_PERSON_2! I can help you reset your password. I'll send the reset link to REDACTED_EMAIL_ADDRESS_2. For verification, I see your badge is REDACTED_BADGE_NUMBER_1 and you're part of REDACTED_PROJECT_CODENAME_1. Please check your email.",
                    },
                    "finish_reason": "stop",
                }
            ],
        },
        "request_text_paths": [
            "$.messages[*].content",
            "$.messages[*].content[*].text",
        ],
        "response_text_paths": [
            "$.choices[*].message.content",
            "$.choices[*].message.tool_calls[*].function.arguments",
        ],
    },
}


@router.get("/api/tester/samples", response_class=JSONResponse)
async def api_tester_samples() -> JSONResponse:
    """Return available provider samples with default JSON paths."""
    return JSONResponse(content={
        "providers": list(_TESTER_SAMPLES.keys()),
        "samples": _TESTER_SAMPLES,
    })


class _TesterProvider:
    """Lightweight provider implementing ProviderLike + ResponseProviderLike.

    Extracts and replaces text fields using user-supplied JSONPath expressions.
    """

    def __init__(self, text_paths: list[str]) -> None:
        self._text_paths = text_paths

    def extract_text_fields(self, body: dict) -> list:
        from jsonpath_ng import parse as jsonpath_parse
        from scruxy.providers.base import TextField

        fields: list[TextField] = []
        for path_str in self._text_paths:
            try:
                compiled = jsonpath_parse(path_str)
                for match in compiled.find(body):
                    value = match.value
                    if isinstance(value, str) and value.strip():
                        fields.append(TextField(
                            json_path=str(match.full_path),
                            text_value=value,
                        ))
            except Exception:
                pass
        return fields

    def extract_response_text_fields(self, body: dict) -> list:
        return self.extract_text_fields(body)

    def replace_text_fields(self, body: dict, replacements: dict[str, str]) -> dict:
        from jsonpath_ng import parse as jsonpath_parse

        for path_str, replacement_text in replacements.items():
            try:
                jsonpath_parse(path_str).update(body, replacement_text)
            except Exception:
                pass
        return body


@router.post("/api/tester/run", response_class=JSONResponse)
async def api_tester_run(request: Request) -> JSONResponse:
    """Run a full scrub/unscrub test using the real RequestScrubber + ResponseUnscrubber.

    Uses the persistent shared TokenMap with session_id="test" so that mappings
    persist across runs and are shared with proxy sessions.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})

    if not isinstance(body, dict):
        return JSONResponse(status_code=400, content={"error": "Request body must be a JSON object"})

    request_body = body.get("request_body")
    if request_body is None:
        return JSONResponse(status_code=400, content={"error": "Missing 'request_body'"})

    response_body = body.get("response_body", {})
    request_text_paths = body.get("request_text_paths", [])
    response_text_paths = body.get("response_text_paths", [])
    stage_overrides = body.get("stages", {})

    pipeline = _get_pipeline(request)
    if pipeline is None:
        return JSONResponse(status_code=500, content={"error": "Pipeline not loaded"})

    import copy as _copy

    from scruxy.pipeline.models import PipelineContext
    from scruxy.scrubber.request_scrubber import RequestScrubber
    from scruxy.scrubber.response_unscrubber import ResponseUnscrubber

    start_time = time.time()

    # Use the persistent shared token map with session_id="test"
    session_store = _get_session_store(request)
    if session_store is not None and hasattr(session_store, "get_or_create_session"):
        token_map = await session_store.get_or_create_session("test")
    else:
        from scruxy.tokenmap.token_map import TokenMap
        replacement_strategies = getattr(request.app.state, "replacement_strategies", None) or {}
        token_map = TokenMap(replacements=replacement_strategies)

    context = PipelineContext(
        session_id="test", provider_name=body.get("provider", "test"),
    )

    # Create TesterProvider instances for request and response paths
    req_provider = _TesterProvider(request_text_paths)
    resp_provider = _TesterProvider(response_text_paths)

    # Create a tester-local pipeline that won't interfere with proxy traffic.
    # We wrap each stage in a lightweight proxy that overrides 'enabled' without
    # mutating the shared stage objects.
    import copy as _copy
    from scruxy.pipeline.engine import PipelineEngine as _PE

    class _StageOverride:
        """Thin wrapper that overrides 'enabled' without mutating the original stage."""
        def __init__(self, stage, enabled):
            self._stage = stage
            self.enabled = enabled
            self.name = getattr(stage, "name", None)
        def detect(self, text, language="en"):
            return self._stage.detect(text, language)
        def __getattr__(self, name):
            return getattr(self._stage, name)

    tester_stages = []
    stages_run: list[str] = []
    original_enabled: dict[str, bool] = {}
    for stage in getattr(pipeline, "stages", []):
        stage_name = getattr(stage, "name", None)
        original_enabled[stage_name or ""] = getattr(stage, "enabled", True)
        if stage_name in stage_overrides:
            tester_stages.append(_StageOverride(stage, bool(stage_overrides[stage_name])))
        else:
            tester_stages.append(_StageOverride(stage, getattr(stage, "enabled", True)))

    tester_pipeline = _PE(stages=tester_stages)
    tester_pipeline.pre_filter_enabled = getattr(pipeline, "pre_filter_enabled", True)
    pipeline = tester_pipeline  # shadow the variable for this request

    try:
        # 1. Scrub each field individually so we can track per-field entities
        original_fields = req_provider.extract_text_fields(request_body)
        all_entities: list[dict] = []
        replacements: dict[str, str] = {}

        for tf in original_fields:
            result = await pipeline.scrub_text(tf.text_value, token_map, context)
            replacements[tf.json_path] = result.scrubbed_text

            # Pipeline returns detected_pii: list of (pii_text, token) parallel to entities
            detected_pii = getattr(result, "detected_pii", [])
            for i, entity in enumerate(result.entities):
                pii_text, token = detected_pii[i] if i < len(detected_pii) else ("", "")
                all_entities.append({
                    "entity_type": entity.entity_type,
                    "text": pii_text,
                    "token": token,
                    "start": 0,
                    "end": 0,
                    "score": round(entity.score, 3),
                    "source": entity.source,
                    "field_path": tf.json_path,
                })

        # Build scrubbed body
        scrubbed_body = req_provider.replace_text_fields(
            _copy.deepcopy(request_body), replacements,
        )

        # 3. Unscrub the scrubbed request (round-trip verification)
        unscrubber = ResponseUnscrubber()
        unscrubbed_request = unscrubber.unscrub_response(
            body=_copy.deepcopy(scrubbed_body),
            provider=req_provider,
            token_map=token_map,
        )

        # 4. Unscrub response
        unscrubbed_response = {}
        rescrubbed_response = {}
        if response_body:
            unscrubbed_response = unscrubber.unscrub_response(
                body=_copy.deepcopy(response_body),
                provider=resp_provider,
                token_map=token_map,
            )

            # 4b. Re-scrub the unscrubbed response (round-trip verification)
            rescrubbed_body, _, _, _ = await RequestScrubber().scrub_request(
                body=_copy.deepcopy(unscrubbed_response),
                provider=resp_provider,
                pipeline=pipeline,
                token_map=token_map,
                context=context,
            )
            rescrubbed_response = rescrubbed_body

        # 5. Tag session PII + mark dirty + flush immediately
        if session_store is not None and hasattr(session_store, "tag_session_pii"):
            test_pii = {e["text"] for e in all_entities if e["text"]}
            if test_pii:
                if inspect.iscoroutinefunction(session_store.tag_session_pii):
                    await session_store.tag_session_pii("test", test_pii)
                else:
                    await asyncio.to_thread(session_store.tag_session_pii, "test", test_pii)
            maybe_dirty = session_store.mark_dirty("test")
            if inspect.isawaitable(maybe_dirty):
                await maybe_dirty
            await session_store.flush_all()

        # Which stages actually ran
        for stage in getattr(pipeline, "stages", []):
            stage_name = getattr(stage, "name", None)
            if stage_name and getattr(stage, "enabled", True):
                stages_run.append(stage_name)

        elapsed_ms = (time.time() - start_time) * 1000

    except Exception:
        logger.exception("Tester run failed")
        return JSONResponse(status_code=500, content={"error": "Tester run failed"})

    return JSONResponse(content={
        "scrubbed_request": scrubbed_body,
        "unscrubbed_request": unscrubbed_request,
        "unscrubbed_response": unscrubbed_response,
        "rescrubbed_response": rescrubbed_response,
        "entities": all_entities,
        "token_map": token_map.scrub_map,
        "mapping_count": token_map.size,
        "latency_ms": round(elapsed_ms, 2),
        "stages_run": stages_run,
    })


# ---------------------------------------------------------------------------
# Tester state persistence
# ---------------------------------------------------------------------------

_TESTER_STATE_FILE = "tester_state.json"


def _get_tester_state_path() -> Path:
    """Return the path to the tester state file (~/.scruxy/tester_state.json)."""
    from scruxy.config.loader import DEFAULT_CONFIG_DIR

    return DEFAULT_CONFIG_DIR / _TESTER_STATE_FILE


@router.get("/api/tester/state", response_class=JSONResponse)
async def api_tester_state_get() -> JSONResponse:
    """Return the persisted tester state, or empty object if none exists."""
    state_path = _get_tester_state_path()
    if not state_path.exists():
        return JSONResponse(content={})

    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to read tester state: %s", exc)
        return JSONResponse(content={})

    return JSONResponse(content=data)


@router.put("/api/tester/state", response_class=JSONResponse)
async def api_tester_state_put(request: Request) -> JSONResponse:
    """Persist tester state (textarea values, provider, paths) to disk."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})

    if not isinstance(body, dict):
        return JSONResponse(status_code=400, content={"error": "Request body must be a JSON object"})

    state_path = _get_tester_state_path()
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(body, indent=2), encoding="utf-8")
    except OSError as exc:
        logger.exception("Failed to save tester state")
        return JSONResponse(status_code=500, content={"error": f"Failed to save state: {exc}"})

    return JSONResponse(content={"message": "Tester state saved"})


# ---------------------------------------------------------------------------
# Token map management endpoints
# ---------------------------------------------------------------------------

@router.delete("/api/sessions/{session_id}/mappings", response_class=JSONResponse)
async def api_delete_session_mappings(session_id: str, request: Request) -> JSONResponse:
    """Delete a session's exclusive entries from the shared token map."""
    session_store = _get_session_store(request)
    if session_store is None or not hasattr(session_store, "delete_session_mappings"):
        return JSONResponse(status_code=500, content={"error": "Session store not available"})

    removed = await session_store.delete_session_mappings(session_id)
    return JSONResponse(content={
        "session_id": session_id,
        "removed": removed,
        "remaining": session_store.shared_map.size,
    })


@router.delete("/api/token-map", response_class=JSONResponse)
async def api_clear_token_map(request: Request) -> JSONResponse:
    """Clear the entire shared token map and all session PII sets."""
    session_store = _get_session_store(request)
    if session_store is None or not hasattr(session_store, "clear_all_mappings"):
        return JSONResponse(status_code=500, content={"error": "Session store not available"})

    await session_store.clear_all_mappings()
    return JSONResponse(content={"message": "Token map cleared", "remaining": 0})


@router.delete("/api/sessions", response_class=JSONResponse)
async def api_clear_all_sessions(request: Request) -> JSONResponse:
    """Clear all sessions: token mappings, session tracking, recordings, and stats."""
    session_store = _get_session_store(request)
    recording = _get_recording(request)
    stats = _get_stats(request)

    sessions_cleared = 0
    recordings_cleared = 0

    # Clear session store (tokens + session tracking)
    if session_store is not None and hasattr(session_store, "clear_all_sessions"):
        sessions_cleared = await session_store.clear_all_sessions()

    # Clear recording files on disk.  When ``recording.enabled`` is
    # false the live recorder is None, but historical session
    # directories may still exist on disk from a prior run.  Always
    # sweep the configured storage_dir so Clear All actually clears.
    if recording is not None and hasattr(recording, "clear_all"):
        recordings_cleared = await recording.clear_all()
    else:
        # Fallback: construct a transient recorder pointing at the
        # configured storage_dir and let it do the cleanup.  Same
        # safe sweep logic, just without needing the live recorder.
        try:
            from scruxy.recording.recorder import SessionRecorder
            cfg = _get_config(request)
            if cfg is not None:
                _storage_dir = str(cfg.sessions.storage_dir)
                _transient = SessionRecorder(storage_dir=_storage_dir)
                recordings_cleared = await _transient.clear_all()
        except Exception:
            logger.exception("Failed to clear historical recordings on disk")

    # Clear per-session stats and recent events
    if stats is not None:
        if hasattr(stats, "_lock"):
            async with stats._lock:
                stats.per_session.clear()
                if hasattr(stats, "recent_events"):
                    stats.recent_events.clear()
                stats.total_requests = 0
                stats.total_entities = 0
                stats.total_unscrub_events = 0
                stats.total_tokens_unscrubbed = 0
                stats.entities_by_type.clear()
                stats.entities_by_provider.clear()
                stats.entities_by_source.clear()
                if hasattr(stats, "_requests_by_provider"):
                    stats._requests_by_provider.clear()
                stats.latency_samples.clear()
                # Clear all latency sample deques
                if hasattr(stats, "unscrub_latency_samples"):
                    stats.unscrub_latency_samples.clear()
                if hasattr(stats, "network_latency_samples"):
                    stats.network_latency_samples.clear()
                if hasattr(stats, "total_latency_samples"):
                    stats.total_latency_samples.clear()
                # Clear timestamped samples
                if hasattr(stats, "ts_scrub_samples"):
                    stats.ts_scrub_samples.clear()
                if hasattr(stats, "ts_unscrub_samples"):
                    stats.ts_unscrub_samples.clear()
                if hasattr(stats, "ts_network_samples"):
                    stats.ts_network_samples.clear()
                if hasattr(stats, "ts_total_samples"):
                    stats.ts_total_samples.clear()
                # Clear per-provider latency histories
                if hasattr(stats, "provider_total_samples"):
                    stats.provider_total_samples.clear()
                if hasattr(stats, "provider_network_samples"):
                    stats.provider_network_samples.clear()
        if hasattr(stats, "save_to_disk"):
            await stats.save_to_disk()

    return JSONResponse(content={
        "message": "All sessions cleared",
        "sessions_cleared": sessions_cleared,
        "recordings_cleared": recordings_cleared,
    })


# ---------------------------------------------------------------------------
# Provider endpoints
# ---------------------------------------------------------------------------

@router.get("/api/providers", response_class=JSONResponse)
async def api_providers(request: Request) -> JSONResponse:
    """Return the list of registered providers."""
    providers_registry = _get_providers(request)
    config = _get_config(request)
    providers: list[dict] = []

    if providers_registry is not None:
        raw = getattr(providers_registry, "providers", [])
        for p in raw:
            name = getattr(p, "name", "unknown")
            # Get upstream_url from config (source of truth for persistence)
            cfg_upstream = ""
            if config is not None:
                prov_cfg = getattr(config, "providers", {}).get(name)
                if prov_cfg is not None:
                    cfg_upstream = getattr(prov_cfg, "upstream_url", "")
            # User-configured text path overrides (None = using defaults)
            req_paths = getattr(p, "user_request_text_paths", None)
            resp_paths = getattr(p, "user_response_text_paths", None)
            # Provider's built-in default paths from YAML config
            default_req_paths = getattr(p, "default_request_text_paths", [])
            default_resp_paths = getattr(p, "default_response_text_paths", [])
            # Determine if this is a built-in provider (not deletable)
            is_builtin = name in _BUILTIN_PROVIDER_NAMES
            providers.append({
                "name": name,
                "url_patterns": list(getattr(p, "_url_patterns", [])),
                "match_headers": list(getattr(p, "_match_headers", [])),
                "auth_headers": list(getattr(p, "_auth_headers", [])),
                "session_id_headers": list(getattr(p, "_session_id_headers", [])),
                "session_id_body_path": getattr(p, "_session_id_body_path", ""),
                "session_id_body_regex": getattr(p, "_session_id_body_regex", ""),
                "session_id_body_prefix": getattr(p, "_session_id_body_prefix", ""),
                "enabled": getattr(p, "enabled", True),
                "upstream_url": getattr(p, "upstream_url", "") or cfg_upstream,
                "request_text_paths": req_paths,
                "response_text_paths": resp_paths,
                "default_request_text_paths": list(default_req_paths),
                "default_response_text_paths": list(default_resp_paths),
                "builtin": is_builtin,
            })
    elif config is not None:
        raw_providers = getattr(config, "providers", {})
        if isinstance(raw_providers, dict):
            for name, p in raw_providers.items():
                providers.append({
                    "name": name,
                    "url_patterns": list(getattr(p, "url_patterns", None) or []),
                    "match_headers": list(getattr(p, "match_headers", None) or []),
                    "auth_headers": list(getattr(p, "auth_headers", None) or []),
                    "session_id_headers": list(getattr(p, "session_id_headers", None) or []),
                    "enabled": getattr(p, "enabled", True),
                    "upstream_url": getattr(p, "upstream_url", ""),
                    "builtin": name in _BUILTIN_PROVIDER_NAMES,
                })

    return JSONResponse(content={"providers": providers})


@router.put("/api/providers/{name}", response_class=JSONResponse)
async def api_provider_update(name: str, request: Request) -> JSONResponse:
    """Update a provider's settings.

    Accepts a JSON body with optional fields: ``enabled``, ``upstream_url``,
    ``url_patterns``, ``match_headers``, ``auth_headers``, ``session_id_headers``,
    ``request_text_paths``, ``response_text_paths``.
    """
    config = _get_config(request)
    if config is None:
        return JSONResponse(status_code=500, content={"error": "No configuration loaded"})

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})

    if not isinstance(body, dict):
        return JSONResponse(status_code=400, content={"error": "Request body must be a JSON object"})

    # R70-8 fix: PUT must validate ``name`` like POST does.  Without
    # this check, the auto-create branch below persists arbitrary
    # unicode/dotfile keys to the YAML config (POST validates at
    # line ~2085 but PUT bypassed the same guard).
    if not name or not name.replace("_", "").replace("-", "").isalnum():
        return JSONResponse(
            status_code=400,
            content={"error": "Provider name must be alphanumeric (hyphens/underscores allowed)"},
        )

    providers = getattr(config, "providers", {})
    if not isinstance(providers, dict):
        return JSONResponse(status_code=500, content={"error": "Invalid providers config"})

    # Auto-create config entry for built-in providers not yet in config
    if name not in providers:
        # Check if the provider exists in the runtime registry
        providers_registry = _get_providers(request)
        runtime_exists = False
        if providers_registry is not None:
            for p in getattr(providers_registry, "providers", []):
                if getattr(p, "name", "") == name:
                    runtime_exists = True
                    break
        if not runtime_exists:
            return JSONResponse(status_code=404, content={"error": f"Provider '{name}' not found"})
        # Create a default config entry from the runtime provider
        from scruxy.config.models import ProviderConfig
        providers[name] = ProviderConfig(
            enabled=True,
            upstream_url=getattr(p, "upstream_url", ""),
        )

    provider_cfg = providers[name]

    if "enabled" in body:
        provider_cfg.enabled = bool(body["enabled"])
    if "upstream_url" in body:
        provider_cfg.upstream_url = str(body["upstream_url"])

    # Simple string-list fields on the config model
    for field_name in ("url_patterns", "match_headers", "auth_headers", "session_id_headers"):
        if field_name not in body:
            continue
        val = body[field_name]
        if isinstance(val, list):
            setattr(provider_cfg, field_name, [str(v) for v in val])
        else:
            setattr(provider_cfg, field_name, None)

    # Simple string fields for body-based session ID extraction
    for field_name in ("session_id_body_path", "session_id_body_regex", "session_id_body_prefix"):
        if field_name in body:
            setattr(provider_cfg, field_name, str(body[field_name] or ""))

    # Validate and apply text path overrides (JSONPath validation)
    # R69-1 fix: also normalize displayed-default paths → None at the
    # persisted-config layer.  GPT-5.5 caught a sibling: the runtime
    # fix at the registry update below only patches in-memory provider
    # state, but ``provider_cfg.request_text_paths`` was still set to
    # the defaults list and saved to disk → on restart, ``app.py``
    # re-applied that list as a user override, silently disabling
    # AnthropicProvider/OpenAIProvider's custom extractors again.
    providers_registry_for_defaults = _get_providers(request)
    runtime_provider = None
    if providers_registry_for_defaults is not None:
        for _rp in getattr(providers_registry_for_defaults, "providers", []):
            if getattr(_rp, "name", "") == name:
                runtime_provider = _rp
                break

    for field_name in ("request_text_paths", "response_text_paths"):
        if field_name not in body:
            continue
        val = body[field_name]
        if isinstance(val, list):
            from jsonpath_ng import parse as _jp_parse
            for path_str in val:
                if not isinstance(path_str, str):
                    return JSONResponse(
                        status_code=400,
                        content={"error": f"Each {field_name} entry must be a string"},
                    )
                try:
                    _jp_parse(path_str)
                except Exception as e:
                    return JSONResponse(
                        status_code=400,
                        content={"error": f"Invalid JSONPath in {field_name} '{path_str}': {e}"},
                    )
            normalized: list[str] | None = list(val)
            if runtime_provider is not None:
                default_attr = (
                    "default_request_text_paths" if field_name == "request_text_paths"
                    else "default_response_text_paths"
                )
                default_paths = list(getattr(runtime_provider, default_attr, []) or [])
                if normalized == default_paths:
                    normalized = None
            setattr(provider_cfg, field_name, normalized)
        else:
            setattr(provider_cfg, field_name, None)

    # Also update the runtime provider object
    providers_registry = _get_providers(request)
    if providers_registry is not None:
        for p in getattr(providers_registry, "providers", []):
            if getattr(p, "name", "") == name:
                if "enabled" in body:
                    p.enabled = bool(body["enabled"])
                if "upstream_url" in body:
                    p.upstream_url = str(body["upstream_url"])
                if "url_patterns" in body:
                    val = body["url_patterns"]
                    p._url_patterns = [str(v) for v in val] if isinstance(val, list) else []
                if "match_headers" in body:
                    val = body["match_headers"]
                    p._match_headers = [str(v) for v in val] if isinstance(val, list) else []
                if "auth_headers" in body:
                    val = body["auth_headers"]
                    p._auth_headers = [str(v) for v in val] if isinstance(val, list) else []
                if "session_id_headers" in body:
                    val = body["session_id_headers"]
                    p._session_id_headers = [str(v) for v in val] if isinstance(val, list) else []
                # Body-based session ID extraction fields
                for _sid_field in ("session_id_body_path", "session_id_body_regex", "session_id_body_prefix"):
                    if _sid_field in body:
                        setattr(p, "_" + _sid_field, str(body[_sid_field] or ""))
                # Recompile regex if changed.  R70-7 fix: pre-screen
                # the user-supplied regex with the same ReDoS
                # heuristic the regex plugin uses for plugin
                # patterns.  Without this, a pathological pattern
                # from the admin UI stalls the proxy on every
                # matching request — denial-of-service via session
                # extraction.
                if "session_id_body_regex" in body:
                    raw_re = str(body["session_id_body_regex"] or "")
                    if raw_re:
                        try:
                            from scruxy.plugin.regex import _looks_catastrophic
                            redos_reason = _looks_catastrophic(raw_re)
                        except Exception:
                            redos_reason = None
                        if redos_reason:
                            return JSONResponse(
                                status_code=400,
                                content={
                                    "error": (
                                        f"session_id_body_regex looks ReDoS-prone "
                                        f"({redos_reason}); rewrite to avoid "
                                        f"catastrophic backtracking."
                                    ),
                                },
                            )
                        try:
                            p._compiled_session_id_body_regex = _re.compile(raw_re)
                        except _re.error:
                            p._compiled_session_id_body_regex = None
                    else:
                        p._compiled_session_id_body_regex = None
                if "request_text_paths" in body:
                    val = body["request_text_paths"]
                    new_paths = list(val) if isinstance(val, list) else None
                    # R69-1 fix: if the saved paths are byte-equal to
                    # the provider's default paths, store ``None``
                    # instead of an explicit override.  Otherwise the
                    # built-in Python providers (Anthropic, OpenAI)
                    # silently lose their custom extractors that
                    # scrub fields the YAML defaults don't list
                    # (e.g. Anthropic ``tool_use.input``, OpenAI
                    # ``tool_calls.function.arguments``) — saving the
                    # form as displayed disables tool-argument
                    # scrubbing → PII forwarded raw upstream.
                    default_req = list(getattr(p, "default_request_text_paths", []) or [])
                    if new_paths is not None and new_paths == default_req:
                        new_paths = None
                    p.user_request_text_paths = new_paths
                if "response_text_paths" in body:
                    val = body["response_text_paths"]
                    new_paths = list(val) if isinstance(val, list) else None
                    default_resp = list(getattr(p, "default_response_text_paths", []) or [])
                    if new_paths is not None and new_paths == default_resp:
                        new_paths = None
                    p.user_response_text_paths = new_paths
                break

    # Persist to disk.
    config_path = _get_config_path(request)
    from scruxy.config.loader import save_config

    try:
        save_config(config, path=config_path)  # type: ignore[arg-type]
    except Exception as exc:
        logger.exception("Failed to persist provider config to disk")
        return JSONResponse(status_code=500, content={"error": f"Failed to save configuration: {exc}"})

    return JSONResponse(content={
        "name": name,
        "enabled": provider_cfg.enabled,
        "upstream_url": provider_cfg.upstream_url,
        "url_patterns": provider_cfg.url_patterns,
        "match_headers": provider_cfg.match_headers,
        "request_text_paths": provider_cfg.request_text_paths,
        "response_text_paths": provider_cfg.response_text_paths,
    })


@router.post("/api/providers", response_class=JSONResponse)
async def api_provider_create(request: Request) -> JSONResponse:
    """Create a new custom YAML-based provider at runtime.

    Required: ``name``, ``url_patterns``.
    Optional: ``upstream_url``, ``match_headers``, ``auth_headers``,
    ``session_id_headers``, ``request_text_paths``, ``response_text_paths``.
    """
    config = _get_config(request)
    if config is None:
        return JSONResponse(status_code=500, content={"error": "No configuration loaded"})

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})

    if not isinstance(body, dict):
        return JSONResponse(status_code=400, content={"error": "Request body must be a JSON object"})

    name = body.get("name", "").strip()
    if not name:
        return JSONResponse(status_code=400, content={"error": "'name' is required"})
    if not name.replace("_", "").replace("-", "").isalnum():
        return JSONResponse(status_code=400, content={"error": "Provider name must be alphanumeric (hyphens/underscores allowed)"})

    # Check for duplicate
    providers_map = getattr(config, "providers", {})
    if name in providers_map:
        return JSONResponse(status_code=409, content={"error": f"Provider '{name}' already exists"})

    url_patterns = body.get("url_patterns", [])
    if not isinstance(url_patterns, list) or not url_patterns:
        return JSONResponse(status_code=400, content={"error": "'url_patterns' must be a non-empty list"})

    upstream_url = body.get("upstream_url", "")
    match_headers = body.get("match_headers", [])
    auth_headers = body.get("auth_headers", [])
    session_id_headers = body.get("session_id_headers", [])
    session_id_body_path = body.get("session_id_body_path", "")
    session_id_body_regex = body.get("session_id_body_regex", "")
    # R71-7 fix: same ReDoS guard as PUT (R70-7) on POST.
    if session_id_body_regex:
        try:
            from scruxy.plugin.regex import _looks_catastrophic as _lc
            _redos = _lc(str(session_id_body_regex))
        except Exception:
            _redos = None
        if _redos:
            return JSONResponse(
                status_code=400,
                content={
                    "error": (
                        f"session_id_body_regex looks ReDoS-prone "
                        f"({_redos}); rewrite to avoid catastrophic "
                        f"backtracking."
                    ),
                },
            )
    session_id_body_prefix = body.get("session_id_body_prefix", "")
    req_paths = body.get("request_text_paths", [])
    resp_paths = body.get("response_text_paths", [])

    # Validate JSONPaths
    from jsonpath_ng import parse as _jp_parse
    for field_name, paths in (("request_text_paths", req_paths), ("response_text_paths", resp_paths)):
        if isinstance(paths, list):
            for path_str in paths:
                try:
                    _jp_parse(path_str)
                except Exception as e:
                    return JSONResponse(
                        status_code=400,
                        content={"error": f"Invalid JSONPath in {field_name} '{path_str}': {e}"},
                    )

    # 1. Add to config model
    from scruxy.config.models import ProviderConfig
    prov_cfg = ProviderConfig(
        enabled=True,
        upstream_url=upstream_url,
        url_patterns=url_patterns,
        match_headers=match_headers if match_headers else None,
        auth_headers=auth_headers if auth_headers else None,
        session_id_headers=session_id_headers if session_id_headers else None,
        session_id_body_path=session_id_body_path,
        session_id_body_regex=session_id_body_regex,
        session_id_body_prefix=session_id_body_prefix,
        request_text_paths=req_paths if req_paths else None,
        response_text_paths=resp_paths if resp_paths else None,
    )
    providers_map[name] = prov_cfg

    # 2. Create and register runtime provider
    from scruxy.providers.yaml_provider import YAMLProvider
    yaml_config: dict = {
        "name": name,
        "display_name": name,
        "upstream_url": upstream_url,
        "enabled": True,
        "url_patterns": url_patterns,
        "match_headers": match_headers or [],
        "auth_headers": auth_headers or [],
        "session_id_headers": session_id_headers or [],
        "session_id_body_path": session_id_body_path,
        "session_id_body_regex": session_id_body_regex,
        "session_id_body_prefix": session_id_body_prefix,
        "request_text_paths": req_paths or [],
        "response_text_paths": resp_paths or [],
    }
    provider = YAMLProvider(yaml_config)

    providers_registry = _get_providers(request)
    if providers_registry is not None:
        providers_registry.register(provider)

    # 3. Persist to disk
    config_path = _get_config_path(request)
    from scruxy.config.loader import save_config
    try:
        save_config(config, path=config_path)  # type: ignore[arg-type]
    except Exception as exc:
        logger.exception("Failed to persist new provider config to disk")
        return JSONResponse(status_code=500, content={"error": f"Failed to save configuration: {exc}"})

    return JSONResponse(status_code=201, content={
        "name": name,
        "enabled": True,
        "upstream_url": upstream_url,
        "url_patterns": url_patterns,
    })


@router.delete("/api/providers/{name}", response_class=JSONResponse)
async def api_provider_delete(name: str, request: Request) -> JSONResponse:
    """Delete a custom provider. Built-in providers cannot be deleted."""
    if name in _BUILTIN_PROVIDER_NAMES:
        return JSONResponse(status_code=400, content={"error": "Cannot delete built-in provider"})

    config = _get_config(request)
    if config is None:
        return JSONResponse(status_code=500, content={"error": "No configuration loaded"})

    providers_map = getattr(config, "providers", {})
    if not isinstance(providers_map, dict) or name not in providers_map:
        return JSONResponse(status_code=404, content={"error": f"Provider '{name}' not found"})

    # Remove from config
    del providers_map[name]

    # Remove from runtime registry
    providers_registry = _get_providers(request)
    if providers_registry is not None:
        providers_registry.unregister(name)

    # Persist to disk
    config_path = _get_config_path(request)
    from scruxy.config.loader import save_config
    try:
        save_config(config, path=config_path)  # type: ignore[arg-type]
    except Exception as exc:
        logger.exception("Failed to persist provider deletion to disk")
        return JSONResponse(status_code=500, content={"error": f"Failed to save configuration: {exc}"})

    return JSONResponse(content={"deleted": name})


# ---------------------------------------------------------------------------
# Passthrough log
# ---------------------------------------------------------------------------

@router.get("/api/passthrough-log", response_class=JSONResponse)
async def api_passthrough_log(request: Request) -> JSONResponse:
    """Return passthrough log entries (non-provider requests)."""
    pt_log = getattr(request.app.state, "passthrough_log", None)
    enabled = getattr(request.app.state, "passthrough_enabled", False)
    entries = list(pt_log) if pt_log is not None else []
    config = _get_config(request)
    max_entries = 500
    if config:
        max_entries = getattr(getattr(config.interception, "passthrough", None), "max_entries", 500)
    return JSONResponse(content={
        "enabled": enabled,
        "entries": entries,
        "count": len(entries),
        "max_entries": max_entries,
    })


@router.delete("/api/passthrough-log", response_class=JSONResponse)
async def api_passthrough_log_clear(request: Request) -> JSONResponse:
    """Clear the passthrough log (in-memory and on disk)."""
    pt_log = getattr(request.app.state, "passthrough_log", None)
    if pt_log is not None:
        pt_log.clear()
    # Also clear the persisted file
    storage_file = getattr(request.app.state, "passthrough_storage_file", None)
    if storage_file:
        from pathlib import Path
        p = Path(storage_file)
        if p.is_file():
            try:
                p.unlink()
            except Exception:
                pass
    return JSONResponse(content={"cleared": True})


@router.put("/api/passthrough-toggle", response_class=JSONResponse)
async def api_passthrough_toggle(request: Request) -> JSONResponse:
    """Toggle passthrough logging at runtime without restart."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})

    enabled = body.get("enabled")
    if enabled is None:
        return JSONResponse(status_code=400, content={"error": "Missing 'enabled'"})

    request.app.state.passthrough_enabled = bool(enabled)
    return JSONResponse(content={"enabled": bool(enabled)})


@router.get("/api/stats", response_class=JSONResponse)
async def api_stats(request: Request) -> JSONResponse:
    """Return global proxy statistics."""
    stats = _get_stats(request)
    data: dict = {}
    if stats is not None:
        data = {
            "total_requests": getattr(stats, "total_requests", 0),
            "total_entities": getattr(stats, "total_entities", 0),
            "entities_by_type": getattr(stats, "entities_by_type", {}),
            "latency_history": list(getattr(stats, "latency_history", [])),
            "unscrub_latency_history": list(getattr(stats, "unscrub_latency_history", [])),
            "network_latency_history": list(getattr(stats, "network_latency_history", [])),
            "total_latency_history": list(getattr(stats, "total_latency_history", [])),
            "requests_by_provider": getattr(stats, "requests_by_provider", {}),
            "uptime_seconds": getattr(stats, "uptime_seconds", 0),
            "recent_events": list(getattr(stats, "recent_events", [])),
        }
    return JSONResponse(content=data)


@router.get("/api/logs", response_class=JSONResponse)
async def api_app_logs(request: Request) -> JSONResponse:
    """Return recent application log entries from the in-memory ring buffer."""
    from scruxy.ui.log_buffer import get_buffer_handler

    handler = get_buffer_handler()
    if handler is None:
        return JSONResponse(content={"entries": []})

    after_id = int(request.query_params.get("after", "0"))
    limit = min(int(request.query_params.get("limit", "200")), 500)
    entries = handler.get_entries(after_id=after_id, limit=limit)
    return JSONResponse(content={"entries": entries})


@router.get("/api/config", response_class=JSONResponse)
async def api_config(request: Request) -> JSONResponse:
    """Return the current application configuration (sanitised)."""
    config = _get_config(request)
    if config is not None:
        if hasattr(config, "model_dump"):
            return JSONResponse(content=config.model_dump(mode="json"))
        return JSONResponse(content={})
    return JSONResponse(content={})


@router.put("/api/config", response_class=JSONResponse)
async def api_config_update(request: Request) -> JSONResponse:
    """Partially update the application configuration."""
    config = _get_config(request)
    if config is None:
        return JSONResponse(status_code=500, content={"error": "No configuration loaded"})

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})

    if not isinstance(body, dict):
        return JSONResponse(status_code=400, content={"error": "Request body must be a JSON object"})

    # Deep-merge incoming data into the current config.
    current_data = config.model_dump(mode="json")
    merged_data = _deep_merge(current_data, body)

    incoming_interception = body.get("interception")
    if (
        isinstance(incoming_interception, dict)
        and incoming_interception.get("mode") == "mitmproxy"
    ):
        return JSONResponse(
            status_code=400,
            content={
                "error": "interception.mode='mitmproxy' is currently unsupported in this build. Use 'primary'."
            },
        )

    # Validate file paths in the merged config — prevent arbitrary file access
    _config_dir = Path("~/.scruxy").expanduser().resolve()
    _FILE_PATH_KEYS = {"whitelist_file", "patterns_file", "custom_plugins_dir", "custom_providers_dir", "plugin_dir"}
    def _validate_paths(data: dict, parent_key: str = "", _depth: int = 0) -> str | None:
        # R65-6 fix: depth cap to prevent RecursionError on
        # adversarial deeply-nested config dicts.  200 is generous
        # for any legitimate scruxy config.
        if _depth > 200:
            return f"Configuration nested too deeply at '{parent_key}' (>200 levels)"
        for key, val in data.items():
            if key in _FILE_PATH_KEYS and isinstance(val, str) and val:
                resolved = Path(val).expanduser().resolve()
                try:
                    if not (resolved.is_relative_to(_config_dir) or
                            resolved.is_relative_to(Path.cwd().resolve())):
                        return f"Path '{val}' for '{key}' must be within ~/.scruxy or the working directory"
                except AttributeError:
                    # Python < 3.9 fallback
                    config_prefix = str(_config_dir) + os.sep
                    cwd_prefix = str(Path.cwd().resolve()) + os.sep
                    if not (str(resolved).startswith(config_prefix) or
                            str(resolved).startswith(cwd_prefix)):
                        return f"Path '{val}' for '{key}' must be within ~/.scruxy or the working directory"
            elif isinstance(val, dict):
                err = _validate_paths(val, key, _depth + 1)
                if err:
                    return err
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, dict):
                        err = _validate_paths(item, key, _depth + 1)
                        if err:
                            return err
        return None
    path_err = _validate_paths(merged_data)
    if path_err:
        return JSONResponse(status_code=400, content={"error": path_err})

    # Validate through Pydantic.
    from scruxy.config.models import AppConfig as _AppConfig

    try:
        new_config = _AppConfig.model_validate(merged_data)
    except Exception as exc:
        return JSONResponse(status_code=400, content={"error": f"Invalid configuration: {exc}"})

    # Persist to disk.
    config_path = _get_config_path(request)
    from scruxy.config.loader import save_config

    try:
        save_config(new_config, path=config_path)
    except Exception as exc:
        logger.exception("Failed to persist config to disk")
        return JSONResponse(status_code=500, content={"error": f"Failed to save configuration: {exc}"})

    # Update in-memory config.
    request.app.state.config = new_config

    # Apply runtime recorder changes immediately so toggles take effect
    # without requiring a restart.
    _apply_recording_runtime_config(request)

    # Reload all stages so runtime reflects the new config
    _reload_all_stages(request)

    return JSONResponse(content=new_config.model_dump(mode="json"))


@router.get("/api/config/files", response_class=JSONResponse)
async def api_config_files(request: Request) -> JSONResponse:
    """Return the paths and contents of editable configuration files."""
    config = _get_config(request)
    result: dict[str, dict] = {}

    # Main config.yaml
    config_path = _get_config_path(request)
    if config_path and config_path.exists():
        try:
            result["config"] = {
                "path": str(config_path),
                "content": config_path.read_text(encoding="utf-8"),
                "exists": True,
            }
        except Exception:
            result["config"] = {"path": str(config_path), "content": "", "exists": True}
    else:
        result["config"] = {"path": str(config_path) if config_path else "", "content": "", "exists": False}

    # Whitelist and regex patterns from pipeline stage configs
    if config:
        for stage in getattr(getattr(config, "pipeline", None), "stages", []):
            stage_config = getattr(stage, "config", {})
            name = getattr(stage, "name", "")
            for field_key, label in [("whitelist_file", "whitelist"), ("patterns_file", "regex_patterns")]:
                file_path_str = stage_config.get(field_key, "")
                if file_path_str:
                    fp = Path(file_path_str).expanduser()
                    content = ""
                    exists = fp.exists()
                    if exists:
                        try:
                            content = fp.read_text(encoding="utf-8")
                        except Exception:
                            pass
                    result[label] = {"path": str(fp), "content": content, "exists": exists, "plugin": name, "field": field_key}

    return JSONResponse(content=result)


@router.put("/api/config/files/{file_key}", response_class=JSONResponse)
async def api_config_file_update(file_key: str, request: Request) -> JSONResponse:
    """Write content to a configuration file (whitelist, regex_patterns, or config)."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})

    content = body.get("content")
    if content is None:
        return JSONResponse(status_code=400, content={"error": "Missing 'content'"})

    import yaml as _yaml

    try:
        _yaml.safe_load(content)
    except _yaml.YAMLError as exc:
        return JSONResponse(status_code=400, content={"error": f"Invalid YAML: {exc}"})

    config = _get_config(request)

    if file_key == "config":
        config_path = _get_config_path(request)
        if not config_path:
            return JSONResponse(status_code=400, content={"error": "No config path available"})
        # Validate the new config BEFORE writing to disk
        from scruxy.config.models import AppConfig as _AppConfig
        from scruxy.config.loader import load_config, _expand_paths

        try:
            parsed = _yaml.safe_load(content)
            if not isinstance(parsed, dict):
                return JSONResponse(status_code=400, content={"error": "Config must be a YAML mapping (dict), not a list or scalar"})
            expanded = _expand_paths(parsed)
            _AppConfig.model_validate(expanded)
        except Exception as exc:
            return JSONResponse(status_code=400, content={"error": f"Invalid config: {exc}"})
        # Config is valid — now write atomically
        try:
            config_path.parent.mkdir(parents=True, exist_ok=True)
            _write_text_atomically(config_path, content)
        except Exception as exc:
            return JSONResponse(status_code=500, content={"error": f"Write failed: {exc}"})
        # Reload config from disk
        try:
            new_config = load_config(path=config_path)
            request.app.state.config = new_config
            _reload_all_stages(request)
        except Exception as exc:
            return JSONResponse(status_code=400, content={"error": f"Config reload failed: {exc}"})
        return JSONResponse(content={"message": "Config updated"})

    # For whitelist/regex_patterns, find the file path from pipeline config
    if not config:
        return JSONResponse(status_code=500, content={"error": "No configuration loaded"})

    field_map = {"whitelist": "whitelist_file", "regex_patterns": "patterns_file"}
    field_key_name = field_map.get(file_key, "")
    if not field_key_name:
        return JSONResponse(status_code=400, content={"error": f"Unknown file key: {file_key}"})

    file_path_str = ""
    plugin_name = ""
    for stage in getattr(getattr(config, "pipeline", None), "stages", []):
        val = getattr(stage, "config", {}).get(field_key_name, "")
        if val:
            file_path_str = val
            plugin_name = getattr(stage, "name", "")
            break

    if not file_path_str:
        return JSONResponse(status_code=400, content={"error": f"No file configured for {file_key}"})

    fp = Path(file_path_str).expanduser()
    try:
        fp.parent.mkdir(parents=True, exist_ok=True)
        _write_text_atomically(fp, content)
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": f"Write failed: {exc}"})

    if plugin_name:
        _reload_stage(request, plugin_name)

    return JSONResponse(content={"message": f"{file_key} updated", "path": str(fp)})


@router.post("/api/whitelist/add", response_class=JSONResponse)
async def api_whitelist_add(request: Request) -> JSONResponse:
    """Add a term to a whitelist YAML file and reload the whitelist plugin.

    Accepts optional ``stage_name`` in the JSON body to target a specific
    whitelist instance.  When omitted, uses the first whitelist stage found
    (backward compatible).
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})

    term = body.get("term", "").strip()
    if not term:
        return JSONResponse(status_code=400, content={"error": "Missing or empty 'term'"})

    target_stage_name = (body.get("stage_name") or "").strip()

    import yaml as _yaml

    config = _get_config(request)
    if not config:
        return JSONResponse(status_code=500, content={"error": "No configuration loaded"})

    # Find whitelist file path from pipeline config
    whitelist_path_str = ""
    matched_stage_name = ""
    for stage in getattr(getattr(config, "pipeline", None), "stages", []):
        val = getattr(stage, "config", {}).get("whitelist_file", "")
        if val:
            sname = getattr(stage, "name", "")
            if target_stage_name:
                if sname == target_stage_name:
                    whitelist_path_str = val
                    matched_stage_name = sname
                    break
            else:
                whitelist_path_str = val
                matched_stage_name = sname
                break

    if not whitelist_path_str:
        return JSONResponse(status_code=400, content={"error": "No whitelist file configured"})

    fp = Path(whitelist_path_str).expanduser()

    async with _get_whitelist_lock(fp):
        existing_terms: list[str] = []
        if fp.exists():
            try:
                raw_text = await asyncio.to_thread(fp.read_text, encoding="utf-8")
                raw = _yaml.safe_load(raw_text) or {}
                existing_terms = raw.get("whitelist", [])
                if not isinstance(existing_terms, list):
                    return JSONResponse(
                        status_code=500,
                        content={"error": "Whitelist file is malformed: 'whitelist' must be a list"},
                    )
            except Exception as exc:
                return JSONResponse(
                    status_code=500,
                    content={"error": f"Failed to read existing whitelist file: {exc}"},
                )

        lower_terms = {t.lower() for t in existing_terms if isinstance(t, str)}
        if term.lower() in lower_terms:
            return JSONResponse(content={"message": "Term already in whitelist", "term": term, "added": False})

        existing_terms.append(term)
        try:
            rendered = _yaml.dump({"whitelist": existing_terms}, default_flow_style=False, allow_unicode=True)
            await asyncio.to_thread(_write_text_atomically, fp, rendered)
        except Exception as exc:
            return JSONResponse(status_code=500, content={"error": f"Write failed: {exc}"})

    _reload_stage(request, matched_stage_name)

    return JSONResponse(content={"message": "Term added to whitelist", "term": term, "added": True})


_UI_SSE_MAX_CONNECTIONS = 32
_ui_sse_active_count = 0
_ui_sse_count_lock = asyncio.Lock()


@router.get("/api/events")
async def api_events(request: Request) -> StreamingResponse:
    """Server-Sent Events stream for real-time updates.

    Concurrent connections are capped at :data:`_UI_SSE_MAX_CONNECTIONS`
    so a buggy or hostile local process cannot exhaust asyncio task
    slots / memory by opening unbounded SSE streams.
    """
    global _ui_sse_active_count
    # Cap check first.  We do NOT increment here — the increment must
    # happen INSIDE the generator's try/finally pair (C7 fix) so that
    # any exception between the check and the generator's first
    # __anext__ cannot leak the counter.
    async with _ui_sse_count_lock:
        if _ui_sse_active_count >= _UI_SSE_MAX_CONNECTIONS:
            return JSONResponse(
                {"error": "Too many active SSE connections"},
                status_code=503,
            )

    async def _event_generator() -> AsyncGenerator[str, None]:
        global _ui_sse_active_count
        # R63-4 fix: initialize ``incremented`` BEFORE any branch
        # so the ``finally`` block's ``if incremented`` check is
        # well-defined even on code paths that return before the
        # increment.  (Currently the early-return at line 2616 is
        # inside the same ``async with`` block so the outer
        # ``finally`` at line 2661 isn't reached, but defensive
        # init eliminates the NameError-class risk if this code is
        # later refactored.)
        incremented = False
        # Re-check the cap inside the generator under the lock and
        # increment atomically.  Decrement is bound to this same
        # generator's lifecycle via try/finally, so there is no
        # window where increment and decrement can drift out of
        # balance even if the response object is dropped before its
        # body is iterated.
        async with _ui_sse_count_lock:
            if _ui_sse_active_count >= _UI_SSE_MAX_CONNECTIONS:
                # Race lost — another connection just hit the cap.
                # Yield a single rejection event and exit.  The
                # finally below will not double-decrement because we
                # never incremented.
                yield f"data: {json.dumps({'type': 'rejected'})}\n\n"
                return
            _ui_sse_active_count += 1
            incremented = True
        try:
            event_bus = _get_event_bus(request)

            # Send an initial heartbeat
            yield f"data: {json.dumps({'type': 'connected', 'timestamp': time.time()})}\n\n"

            if event_bus is not None:
                queue: asyncio.Queue = asyncio.Queue(maxsize=256)  # type: ignore[type-arg]
                subscribers: list = getattr(event_bus, "subscribers", [])
                subscribers.append(queue)
                try:
                    while True:
                        try:
                            if await request.is_disconnected():
                                break
                        except asyncio.CancelledError:
                            break
                        try:
                            event = await asyncio.wait_for(queue.get(), timeout=15.0)
                            yield f"data: {json.dumps(event)}\n\n"
                        except asyncio.TimeoutError:
                            # Send keep-alive
                            yield f"data: {json.dumps({'type': 'heartbeat', 'timestamp': time.time()})}\n\n"
                        except asyncio.CancelledError:
                            break
                finally:
                    if queue in subscribers:
                        subscribers.remove(queue)
            else:
                # No event bus: just send periodic heartbeats
                while True:
                    try:
                        if await request.is_disconnected():
                            break
                    except asyncio.CancelledError:
                        break
                    yield f"data: {json.dumps({'type': 'heartbeat', 'timestamp': time.time()})}\n\n"
                    try:
                        await asyncio.sleep(15)
                    except asyncio.CancelledError:
                        break
        finally:
            if incremented:
                async with _ui_sse_count_lock:
                    _ui_sse_active_count = max(0, _ui_sse_active_count - 1)

    return StreamingResponse(
        _event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Plugin template creation
# ---------------------------------------------------------------------------

_PLUGIN_TEMPLATE = '''"""Custom PII detector plugin: {name}.

Drop this file into ~/.scruxy/plugins/ to activate.

Configuration (in config.yaml under the plugins stage):
    pipeline:
      stages:
        - name: plugins
          config:
            plugin_configs:
              {name}:
                pattern: "TODO-\\\\d+"
                score: 0.9

Testing:
    Use the Pipeline Tester page (/ui/tester) to verify detection.
"""
from __future__ import annotations

import re

from scruxy.plugin.base import ConfigField, DetectorPlugin, PiiEntity


class {class_name}(DetectorPlugin):
    """{display_name} — custom PII detector.

    TODO: Describe what PII this plugin detects and why.
    """

    name = "{name}"
    version = "0.1.0"
    description = "TODO: Brief description of what this plugin detects"

    # Declare configurable fields — the UI renders these as a form.
    # See ConfigField for field_type options: string, number, boolean,
    # select, list, text, file.
    config_schema = [
        ConfigField(
            name="pattern",
            field_type="string",
            default=r"TODO-\\d+",
            description="Regex pattern to match",
            label="Detection Pattern",
            details="Python regex pattern. Escape backslashes in YAML config.",
        ),
        ConfigField(
            name="score",
            field_type="number",
            default=0.9,
            description="Confidence score for detections",
            label="Detection Score",
            min_value=0.0,
            max_value=1.0,
        ),
    ]

    def setup(self, config: dict) -> None:
        """Initialize the detector — called once at startup.

        Access per-plugin key-value storage via config["_storage"]:
            storage = config.get("_storage")
            if storage:
                storage.set("key", "value", ttl_seconds=3600)
                val = storage.get("key", default="fallback")
        """
        self._storage = config.get("_storage")
        self._pattern = re.compile(config.get("pattern", r"TODO-\\d+"))
        self._score = config.get("score", 0.9)

    def detect(self, text: str, language: str) -> list[PiiEntity]:
        """Detect PII entities in the given text.

        Must be fast (< 50ms) and stateless with respect to sessions.
        Return a PiiEntity for each match with accurate start/end offsets.
        """
        if not text:
            return []

        entities: list[PiiEntity] = []
        for match in self._pattern.finditer(text):
            entities.append(PiiEntity(
                entity_type="{entity_type}",
                start=match.start(),
                end=match.end(),
                score=self._score,
                source=self.name,
            ))
        return entities

    def teardown(self) -> None:
        """Release resources on shutdown (optional)."""
'''


def _to_class_name(plugin_name: str) -> str:
    """Convert a snake_case plugin name to PascalCase class name."""
    return "".join(word.capitalize() for word in plugin_name.split("_")) + "Detector"


def _get_plugin_dir(request: Request) -> str | None:
    """Get the plugin directory path from config."""
    config = _get_config(request)
    if config is not None:
        pipeline_cfg = getattr(config, "pipeline", None)
        if pipeline_cfg is not None:
            for stage_cfg in getattr(pipeline_cfg, "stages", []):
                if getattr(stage_cfg, "name", "") == "plugins":
                    plugin_dir = getattr(stage_cfg, "config", {}).get("plugin_dir", "")
                    if plugin_dir:
                        return str(Path(plugin_dir).expanduser())
    return None


@router.post("/api/plugins/openai_privacy_filter/install", response_class=JSONResponse)
async def api_install_opf(request: Request) -> JSONResponse:
    """Install the optional ``opf`` extra on demand.

    Runs ``pip install -e '.[opf]'`` (or the equivalent depending on
    install layout) in a worker thread.  The OPF detector + ~2GB of
    torch dependencies are pulled from PyPI / GitHub.  The 1.5GB
    model checkpoint itself is downloaded lazily on the first
    detection call after the daemon restarts.

    Returns ``{"installed": true}`` on success or
    ``{"installed": false, "error": "..."}`` on failure.

    Security note: this endpoint runs ``pip`` in the same Python
    environment Scruxy is running in.  It's intended for
    single-operator local installs, not multi-tenant deployments.
    """
    import asyncio
    import shutil
    import subprocess
    import sys

    # Quick check: is opf already importable?  Skip the install.
    try:
        import importlib
        if importlib.util.find_spec("opf") is not None:  # type: ignore[attr-defined]
            return JSONResponse(
                content={"installed": True, "already_installed": True}
            )
    except Exception:
        pass

    # Locate the project root so 'pip install -e .[opf]' works.
    project_root = Path(__file__).resolve().parents[3]
    has_pyproject = (project_root / "pyproject.toml").is_file()

    def _run_pip() -> tuple[bool, str]:
        """Run pip install, returning (success, combined_output)."""
        # Prefer ``uv`` when available; it's noticeably faster and is
        # the install method documented in the README.
        if shutil.which("uv"):
            cmd = ["uv", "sync", "--extra", "opf"]
        elif has_pyproject:
            cmd = [sys.executable, "-m", "pip", "install", "-e", f"{project_root}[opf]"]
        else:
            # Fall back to a direct install of the extra's contents.
            cmd = [
                sys.executable, "-m", "pip", "install",
                "opf @ git+https://github.com/openai/privacy-filter@main",
            ]
        logger.info("OPF install: running %s", cmd)
        try:
            # Long-running: capture both streams; cap at 30 minutes
            # (torch + model checkpoint can be slow on first install).
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800,
                cwd=str(project_root) if has_pyproject else None,
            )
        except subprocess.TimeoutExpired:
            return False, "pip install exceeded 30-minute timeout"
        except Exception as exc:
            return False, f"pip install failed to launch: {exc}"
        ok = result.returncode == 0
        tail = (result.stdout + "\n" + result.stderr)[-2000:]
        return ok, tail

    success, output = await asyncio.to_thread(_run_pip)

    if not success:
        logger.warning("OPF install failed: %s", output)
        return JSONResponse(
            status_code=500,
            content={
                "installed": False,
                "error": output,
                "hint": (
                    "Install manually: pip install -e '.[opf]' "
                    "(or uv sync --extra opf).  Then restart Scruxy."
                ),
            },
        )

    logger.info("OPF install succeeded; restart the daemon to load the plugin.")
    return JSONResponse(
        content={
            "installed": True,
            "restart_required": True,
            "hint": (
                "Restart Scruxy so the openai_privacy_filter plugin "
                "picks up the newly-installed 'opf' package.  The "
                "1.5GB model checkpoint downloads lazily on the first "
                "detection request after restart."
            ),
        }
    )


@router.post("/api/plugins/create", response_class=JSONResponse)
async def api_create_plugin(request: Request) -> JSONResponse:
    """Create a new plugin template file."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})

    name = (body.get("name") or "").strip()

    if not name:
        return JSONResponse(status_code=400, content={"error": "Plugin name is required"})

    if not _re.match(r"^[a-zA-Z][a-zA-Z0-9_]*$", name):
        return JSONResponse(
            status_code=400,
            content={"error": "Plugin name must start with a letter and contain only letters, digits, and underscores"},
        )

    plugin_dir = _get_plugin_dir(request)
    if not plugin_dir:
        return JSONResponse(status_code=500, content={"error": "Plugin directory not configured"})

    plugin_path = Path(plugin_dir) / f"{name}.py"
    if plugin_path.exists():
        return JSONResponse(status_code=409, content={"error": f"Plugin '{name}' already exists"})

    # Create plugin directory if it doesn't exist
    Path(plugin_dir).mkdir(parents=True, exist_ok=True)

    # Write template
    class_name = _to_class_name(name)
    display_name = name.replace("_", " ").title()
    entity_type = name.upper()
    content = _PLUGIN_TEMPLATE.format(
        name=name,
        class_name=class_name,
        display_name=display_name,
        entity_type=entity_type,
    )
    plugin_path.write_text(content, encoding="utf-8")

    # Hot-reload the PluginStage so the new plugin appears immediately.
    await _reload_user_plugins(request)

    return JSONResponse(
        status_code=201,
        content={"name": name, "path": str(plugin_path), "message": f"Plugin '{name}' created successfully"},
    )


@router.put("/api/plugins/{plugin_name}/config", response_class=JSONResponse)
async def api_update_plugin_config(plugin_name: str, request: Request) -> JSONResponse:
    """Update a plugin/stage configuration and persist to disk.

    For builtin stages (presidio, regex, plugins) the config is updated
    directly on the stage entry.  For user plugins, the config is stored
    under ``plugin_configs`` within the ``plugins`` stage config so that
    per-plugin overrides survive restarts.
    """
    try:
        new_config = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})

    config = _get_config(request)
    if config is None:
        return JSONResponse(status_code=500, content={"error": "No configuration loaded"})

    pipeline_cfg = getattr(config, "pipeline", None)
    if pipeline_cfg is None:
        return JSONResponse(status_code=500, content={"error": "No pipeline configuration"})

    # Check if plugin_name matches a top-level stage (builtin stages)
    for stage_cfg in getattr(pipeline_cfg, "stages", []):
        if getattr(stage_cfg, "name", "") == plugin_name:
            existing = getattr(stage_cfg, "config", {})
            # Reject attempts to change file-backed config paths to
            # locations outside the existing file's directory.
            for fkey in _FILE_CONFIG_KEYS:
                if fkey in new_config and fkey in existing:
                    old_p = Path(existing[fkey]).expanduser().resolve()
                    new_p = Path(new_config[fkey]).expanduser().resolve()
                    if new_p.parent != old_p.parent:
                        return JSONResponse(
                            status_code=400,
                            content={"error": f"'{fkey}' must remain in the same directory as the original file"},
                        )
            existing.update(new_config)
            stage_cfg.config = existing
            # Apply to runtime stage
            _apply_config_to_runtime_stage(request, plugin_name, existing)
            # Persist to disk
            _persist_config(request, config)
            return JSONResponse(content={"message": f"Configuration for '{plugin_name}' updated", "config": existing})

    # Not a builtin stage -- treat as a user plugin config.
    # Store under plugins stage -> plugin_configs -> {plugin_name}.
    for stage_cfg in getattr(pipeline_cfg, "stages", []):
        if getattr(stage_cfg, "name", "") == "plugins":
            existing = getattr(stage_cfg, "config", {})
            plugin_configs = existing.setdefault("plugin_configs", {})
            plugin_cfg = plugin_configs.get(plugin_name, {})
            plugin_cfg.update(new_config)
            plugin_configs[plugin_name] = plugin_cfg
            stage_cfg.config = existing
            # Persist to disk
            _persist_config(request, config)
            return JSONResponse(content={"message": f"Configuration for plugin '{plugin_name}' updated", "config": plugin_cfg})

    return JSONResponse(status_code=404, content={"error": f"Stage or plugin '{plugin_name}' not found"})


def _apply_config_to_runtime_stage(request: Request, stage_name: str, new_config: dict) -> None:
    """Push updated config values onto the live runtime stage object.

    For Presidio, hot-swaps detection parameters without reinitialising
    the NLP engine.  For regex, re-reads the patterns file and recompiles.
    """
    pipeline = _get_pipeline(request)
    if pipeline is None:
        return

    for stage in getattr(pipeline, "stages", []):
        if getattr(stage, "name", None) != stage_name:
            continue

        # Presidio: update detection parameters without reinit
        if stage_name == "presidio":
            if "entities" in new_config:
                entities = new_config["entities"]
                stage._entities = entities if entities else None
            if "score_threshold" in new_config:
                stage._score_threshold = float(new_config["score_threshold"])
            if "language" in new_config:
                stage._language = new_config["language"]
        # Regex and others: full setup() reload
        elif hasattr(stage, "setup"):
            try:
                stage.setup(new_config)
            except Exception:
                logger.warning("Failed to reload stage '%s' at runtime", stage_name)

        logger.debug("Applied runtime config update to stage '%s'", stage_name)
        break


async def _reload_user_plugins(request: Request) -> None:
    """Re-scan the plugin directory and reload user plugins into the PluginStage.

    Called after creating or deleting a plugin file so the change is visible
    immediately without a full proxy restart.  Uses atomic swap so concurrent
    requests always see a valid plugin list.
    """
    pipeline = _get_pipeline(request)
    if pipeline is None:
        return

    for stage in getattr(pipeline, "stages", []):
        if hasattr(stage, "load_plugins") and hasattr(stage, "_plugins"):
            old_plugins = list(stage._plugins)
            old_storages = dict(getattr(stage, "_storages", {}))

            # Flush existing storages before discarding to avoid data loss
            for storage in old_storages.values():
                try:
                    storage.flush()
                except Exception:
                    logger.debug("Error flushing storage during reload")

            # Build new plugin list using a separate temporary PluginStage
            # so concurrent requests always see either all-old or all-new.
            # The live stage._plugins is NEVER cleared to [].
            def _do_reload() -> tuple[list, dict]:
                try:
                    from scruxy.pipeline.plugin_stage import PluginStage
                    temp = PluginStage(
                        plugin_dir=str(stage._plugin_dir),
                        timeout_ms=int(stage._timeout_s * 1000),
                        disabled_plugins=list(stage._disabled_plugins),
                        storage_base_dir=getattr(stage, "_storage_base_dir", None),
                        plugin_configs=getattr(stage, "_plugin_configs", {}),
                    )
                    temp.load_plugins()
                    return list(temp._plugins), dict(temp._storages)
                except (AttributeError, TypeError):
                    # Fallback for mocks / non-standard stages: reload in-place
                    stage.load_plugins()
                    return list(stage._plugins), dict(getattr(stage, "_storages", {}))

            reload_ok = False
            try:
                new_plugins, new_storages = await asyncio.to_thread(_do_reload)
                # Atomic swap — concurrent detect() calls see old list until
                # this single assignment completes (GIL guarantees atomicity)
                stage._plugins = new_plugins
                stage._storages = new_storages
                reload_ok = True
                # Teardown old plugins after successful swap
                for plugin in old_plugins:
                    try:
                        plugin.teardown()
                    except Exception:
                        logger.debug("Error tearing down plugin %s during reload",
                                     getattr(plugin, "name", "unknown"))
                logger.info("Reloaded user plugins: %d loaded", len(new_plugins))
            except Exception:
                logger.exception("Failed to reload user plugins — keeping previous state")
            return reload_ok


def _reload_all_stages(request: Request) -> None:
    """Reload all runtime stages and replacement strategies from the current config model."""
    config = _get_config(request)
    if config is None:
        return
    pipeline_cfg = getattr(config, "pipeline", None)
    if pipeline_cfg is None:
        return
    for stage_cfg in getattr(pipeline_cfg, "stages", []):
        name = getattr(stage_cfg, "name", "")
        if name:
            _apply_config_to_runtime_stage(request, name, dict(getattr(stage_cfg, "config", {})))

    # Rebuild replacement strategies and update the shared token map
    from scruxy.tokenmap.replacer import ScriptReplacement, build_strategies

    new_strategies = build_strategies(config.tokens.replacements)
    old_strategies = getattr(request.app.state, "replacement_strategies", None) or {}
    request.app.state.replacement_strategies = new_strategies
    session_store = _get_session_store(request)
    if session_store is not None:
        shared_map = getattr(session_store, "shared_map", None)
        if shared_map is not None:
            # Determine which entity types gained or changed a strategy
            changed_types: set[str] = set()
            all_types = set(new_strategies) | set(old_strategies)
            for etype in all_types:
                old_s = old_strategies.get(etype)
                new_s = new_strategies.get(etype)
                if type(old_s) is not type(new_s):
                    changed_types.add(etype)
                elif isinstance(new_s, ScriptReplacement) and isinstance(old_s, ScriptReplacement):
                    if new_s._command_parts != old_s._command_parts:
                        changed_types.add(etype)
            shared_map._replacements = new_strategies
            if changed_types:
                shared_map.invalidate_entity_types(changed_types)


def _reload_stage(request: Request, stage_name: str) -> None:
    """Reload a runtime stage using its current config from the config model.

    Call this after any change that affects a stage's behaviour (e.g. editing
    a patterns file) to ensure the running pipeline picks up the changes
    without a full restart.
    """
    config = _get_config(request)
    if config is None:
        return
    pipeline_cfg = getattr(config, "pipeline", None)
    if pipeline_cfg is None:
        return

    # Find the stage's config dict
    stage_config: dict = {}
    for stage_cfg in getattr(pipeline_cfg, "stages", []):
        if getattr(stage_cfg, "name", "") == stage_name:
            stage_config = dict(getattr(stage_cfg, "config", {}))
            break

    _apply_config_to_runtime_stage(request, stage_name, stage_config)


def _persist_config(request: Request, config: object) -> bool:
    """Persist the current config to disk.

    Returns True on success, False on failure.  Errors are logged but not
    raised so callers can still complete the in-memory update.
    """
    config_path = _get_config_path(request)
    try:
        from scruxy.config.loader import save_config
        save_config(config, path=config_path)  # type: ignore[arg-type]
        logger.debug("Config persisted to %s", config_path or "~/.scruxy/config.yaml")
        return True
    except Exception:
        logger.exception("Failed to persist config to disk (path=%s)", config_path)
        return False


# ---------------------------------------------------------------------------
# Plugin source read / edit / delete
# ---------------------------------------------------------------------------

@router.get("/api/plugins/{name}/source", response_class=JSONResponse)
async def api_plugin_source(name: str, request: Request) -> JSONResponse:
    """Return the source code of a user plugin file."""
    if not _re.match(r"^[a-zA-Z][a-zA-Z0-9_]*$", name) or _is_windows_reserved_name(name):
        return JSONResponse(status_code=400, content={"error": "Invalid plugin name"})

    plugin_dir = _get_plugin_dir(request)
    if not plugin_dir:
        return JSONResponse(status_code=500, content={"error": "Plugin directory not configured"})

    plugin_path = Path(plugin_dir) / f"{name}.py"
    if not plugin_path.exists():
        return JSONResponse(status_code=404, content={"error": f"Plugin '{name}' not found"})

    source = plugin_path.read_text(encoding="utf-8")
    return JSONResponse(content={"name": name, "source": source})


@router.put("/api/plugins/{name}/source", response_class=JSONResponse)
async def api_update_plugin_source(name: str, request: Request) -> JSONResponse:
    """Write new source code to a user plugin file."""
    plugin_dir = _get_plugin_dir(request)
    if not plugin_dir:
        return JSONResponse(status_code=500, content={"error": "Plugin directory not configured"})

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})

    if not _re.match(r"^[a-zA-Z][a-zA-Z0-9_]*$", name) or _is_windows_reserved_name(name):
        return JSONResponse(status_code=400, content={"error": "Invalid plugin name"})

    source = body.get("source")
    if source is None:
        return JSONResponse(status_code=400, content={"error": "Missing 'source' in request body"})

    plugin_path = Path(plugin_dir) / f"{name}.py"
    Path(plugin_dir).mkdir(parents=True, exist_ok=True)
    plugin_path.write_text(source, encoding="utf-8")

    # Hot-reload so the updated source takes effect immediately.
    reload_ok = await _reload_user_plugins(request)

    if reload_ok:
        return JSONResponse(content={"message": f"Plugin '{name}' source updated successfully"})
    else:
        return JSONResponse(
            status_code=200,
            content={
                "message": f"Plugin '{name}' source saved but reload failed — check logs. Changes will take effect on next restart.",
                "warning": "reload_failed",
            },
        )


@router.delete("/api/plugins/{name}", response_class=JSONResponse)
async def api_delete_plugin(name: str, request: Request) -> JSONResponse:
    """Delete a user plugin file."""
    if not _re.match(r"^[a-zA-Z][a-zA-Z0-9_]*$", name) or _is_windows_reserved_name(name):
        return JSONResponse(status_code=400, content={"error": "Invalid plugin name"})

    plugin_dir = _get_plugin_dir(request)
    if not plugin_dir:
        return JSONResponse(status_code=500, content={"error": "Plugin directory not configured"})

    plugin_path = Path(plugin_dir) / f"{name}.py"
    if not plugin_path.exists():
        return JSONResponse(status_code=404, content={"error": f"Plugin '{name}' not found"})

    plugin_path.unlink()

    # Hot-reload the PluginStage so the deleted plugin disappears immediately.
    await _reload_user_plugins(request)

    return JSONResponse(content={"message": f"Plugin '{name}' deleted successfully"})


# ---------------------------------------------------------------------------
# Script CRUD endpoints (replacement scripts in ~/.scruxy/scripts/)
# ---------------------------------------------------------------------------

_SCRIPT_NAME_RE = _re.compile(r"^[\w.-]+\.py$")
_WIN_RESERVED_BASENAMES_UI = frozenset({
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
})


def _is_windows_reserved_name(name: str) -> bool:
    """72-5 fix: True if *name*'s basename (before any extension) is a
    Windows reserved device name (``CON``, ``NUL``, ``COM1``-``LPT9``).
    """
    if not name:
        return False
    base = name.split(".")[0].upper()
    return base in _WIN_RESERVED_BASENAMES_UI


def _get_scripts_dir() -> Path:
    """Return the scripts directory path (~/.scruxy/scripts/)."""
    from scruxy.config.loader import DEFAULT_CONFIG_DIR

    return DEFAULT_CONFIG_DIR / "scripts"


_SCRIPT_TEMPLATE = '''\
#!/usr/bin/env python3
"""Custom replacement script.

Protocol: argv[1]=entity_type, argv[2]=count (1-based), stdin=original PII, stdout=replacement.
"""
import sys


def main():
    entity_type = sys.argv[1] if len(sys.argv) > 1 else "UNKNOWN"
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    original = sys.stdin.read().strip()

    # TODO: implement your replacement logic here
    print(f"REPLACED_{entity_type}_{count}")


if __name__ == "__main__":
    main()
'''


@router.get("/api/scripts", response_class=JSONResponse)
async def api_scripts_list() -> JSONResponse:
    """List .py files in the scripts directory."""
    scripts_dir = _get_scripts_dir()
    if not scripts_dir.exists():
        return JSONResponse(content={"scripts": []})

    try:
        scripts = sorted(
            f.name for f in scripts_dir.iterdir() if f.is_file() and f.suffix == ".py"
        )
    except OSError as exc:
        logger.exception("Failed to list scripts in '%s'", scripts_dir)
        return JSONResponse(status_code=500, content={"error": f"Failed to list scripts: {exc}"})

    return JSONResponse(content={"scripts": scripts})


@router.get("/api/scripts/{name}", response_class=JSONResponse)
async def api_script_get(name: str) -> JSONResponse:
    """Read the content of a script file."""
    if not _SCRIPT_NAME_RE.match(name) or _is_windows_reserved_name(name):
        return JSONResponse(status_code=400, content={"error": "Invalid script name"})

    script_path = _get_scripts_dir() / name
    if not script_path.exists():
        return JSONResponse(status_code=404, content={"error": f"Script '{name}' not found"})

    try:
        content = script_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        logger.exception("Failed to read script '%s'", name)
        return JSONResponse(status_code=500, content={"error": f"Failed to read script: {exc}"})

    return JSONResponse(content={"name": name, "content": content})


@router.put("/api/scripts/{name}", response_class=JSONResponse)
async def api_script_update(name: str, request: Request) -> JSONResponse:
    """Write or update a script file."""
    if not _SCRIPT_NAME_RE.match(name) or _is_windows_reserved_name(name):
        return JSONResponse(status_code=400, content={"error": "Invalid script name"})

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})

    content = body.get("content")
    if content is None:
        return JSONResponse(status_code=400, content={"error": "Missing 'content' in request body"})

    scripts_dir = _get_scripts_dir()
    try:
        scripts_dir.mkdir(parents=True, exist_ok=True)
        (scripts_dir / name).write_text(content, encoding="utf-8")
    except OSError as exc:
        logger.exception("Failed to write script '%s'", name)
        return JSONResponse(status_code=500, content={"error": f"Failed to save script: {exc}"})

    return JSONResponse(content={"message": f"Script '{name}' saved successfully"})


@router.post("/api/scripts", response_class=JSONResponse)
async def api_script_create(request: Request) -> JSONResponse:
    """Create a new script file with a template."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})

    name = body.get("name", "").strip()
    if not name:
        return JSONResponse(status_code=400, content={"error": "Missing 'name' in request body"})

    # Ensure .py extension
    if not name.endswith(".py"):
        name = name + ".py"

    if not _SCRIPT_NAME_RE.match(name) or _is_windows_reserved_name(name):
        return JSONResponse(status_code=400, content={"error": "Invalid script name"})

    scripts_dir = _get_scripts_dir()
    try:
        scripts_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.exception("Failed to create scripts directory")
        return JSONResponse(status_code=500, content={"error": f"Failed to create scripts directory: {exc}"})

    script_path = scripts_dir / name
    try:
        with open(script_path, "x", encoding="utf-8") as f:
            f.write(_SCRIPT_TEMPLATE)
    except FileExistsError:
        return JSONResponse(status_code=409, content={"error": f"Script '{name}' already exists"})
    except OSError as exc:
        logger.exception("Failed to create script '%s'", name)
        return JSONResponse(status_code=500, content={"error": f"Failed to create script: {exc}"})

    return JSONResponse(content={"message": f"Script '{name}' created", "name": name})


@router.delete("/api/scripts/{name}", response_class=JSONResponse)
async def api_script_delete(name: str) -> JSONResponse:
    """Delete a script file."""
    if not _SCRIPT_NAME_RE.match(name) or _is_windows_reserved_name(name):
        return JSONResponse(status_code=400, content={"error": "Invalid script name"})

    script_path = _get_scripts_dir() / name
    try:
        script_path.unlink()
    except FileNotFoundError:
        return JSONResponse(status_code=404, content={"error": f"Script '{name}' not found"})
    except OSError as exc:
        logger.exception("Failed to delete script '%s'", name)
        return JSONResponse(status_code=500, content={"error": f"Failed to delete script: {exc}"})

    return JSONResponse(content={"message": f"Script '{name}' deleted successfully"})


# ---------------------------------------------------------------------------
# Plugin repository & pipeline instance management
# ---------------------------------------------------------------------------

# Mapping from builtin plugin name → class for instantiation
_BUILTIN_PLUGIN_CLASSES: dict[str, type] = {}


def _get_builtin_plugin_classes() -> dict[str, type]:
    """Lazy-load builtin plugin classes to avoid circular imports at module level."""
    if not _BUILTIN_PLUGIN_CLASSES:
        from scruxy.plugin.whitelist import WhitelistPlugin
        from scruxy.plugin.presidio import PresidioPlugin
        from scruxy.plugin.regex import RegexPlugin
        from scruxy.plugin.file_path import FilePathDetector

        _BUILTIN_PLUGIN_CLASSES.update({
            "whitelist": WhitelistPlugin,
            "presidio": PresidioPlugin,
            "regex": RegexPlugin,
            "file_path": FilePathDetector,
        })
    return _BUILTIN_PLUGIN_CLASSES


def _get_all_pipeline_instance_names(pipeline: object) -> list[str]:
    """Return all instance names currently in the pipeline."""
    names: list[str] = []
    for stage in getattr(pipeline, "stages", []):
        name = getattr(stage, "name", None)
        if name:
            names.append(name)
        if hasattr(stage, "plugins"):
            for p in getattr(stage, "plugins", []):
                pn = getattr(p, "name", None)
                if pn:
                    names.append(pn)
    return names


def _count_instances_in_pipeline(pipeline: object, base_name: str) -> int:
    """Count how many instances of a plugin type are in the pipeline.

    Matches the exact name or names that start with ``base_name`` followed
    by ``_copy``, ``_2``, etc.
    """
    count = 0
    for inst_name in _get_all_pipeline_instance_names(pipeline):
        if inst_name == base_name or inst_name.startswith(base_name + "_copy"):
            count += 1
    return count


def _generate_copy_name(base_name: str, existing_names: set[str]) -> str:
    """Generate a unique copy name: ``{base}_copy``, ``{base}_copy2``, etc."""
    candidate = f"{base_name}_copy"
    if candidate not in existing_names:
        return candidate
    n = 2
    while True:
        candidate = f"{base_name}_copy{n}"
        if candidate not in existing_names:
            return candidate
        n += 1


@router.get("/api/plugin-repository", response_class=JSONResponse)
async def api_plugin_repository(request: Request) -> JSONResponse:
    """Return all available plugin types that can be added to the pipeline.

    Each entry describes a plugin type (builtin or user) with metadata and
    the count of instances currently active in the pipeline.
    """
    pipeline = _get_pipeline(request)
    repository: list[dict] = []

    builtin_classes = _get_builtin_plugin_classes()

    # Builtin plugins
    _BUILTIN_DISPLAY_NAMES = {
        "whitelist": "Whitelist",
        "presidio": "Microsoft Presidio",
        "regex": "Regex Patterns",
        "file_path": "File Path Detection",
    }
    for name, cls in builtin_classes.items():
        try:
            instance = cls()
        except Exception:
            continue
        config_schema_raw = getattr(instance, "config_schema", [])
        repo_entry = {
            "name": name,
            "display_name": _BUILTIN_DISPLAY_NAMES.get(name, name),
            "type": "builtin",
            "description": getattr(instance, "description", ""),
            "config_schema": _serialize_config_schema(config_schema_raw),
            "instances_in_pipeline": _count_instances_in_pipeline(pipeline, name) if pipeline else 0,
        }
        repository.append(repo_entry)

    # User plugins (from PluginStage)
    if pipeline is not None:
        for stage in getattr(pipeline, "stages", []):
            if hasattr(stage, "plugins"):
                for p in getattr(stage, "plugins", []):
                    pname = getattr(p, "name", "unknown")
                    config_schema_raw = getattr(p, "config_schema", [])
                    repo_entry = {
                        "name": pname,
                        "display_name": _get_display_name(pname, request),
                        "type": "user",
                        "description": getattr(p, "description", ""),
                        "config_schema": _serialize_config_schema(config_schema_raw),
                        "instances_in_pipeline": _count_instances_in_pipeline(pipeline, pname) if pipeline else 0,
                    }
                    repository.append(repo_entry)

    return JSONResponse(content={"plugins": repository})


@router.post("/api/pipeline/add", response_class=JSONResponse)
async def api_pipeline_add(request: Request) -> JSONResponse:
    """Add a new plugin instance to the active pipeline.

    Expects JSON body:
        ``{"plugin_name": "presidio", "instance_name": "presidio_2", "config": {...}}``

    Creates a new instance of the plugin, calls ``setup()`` with the given
    config, and appends it to the pipeline stages list.
    """
    pipeline = _get_pipeline(request)
    if pipeline is None:
        return JSONResponse(status_code=500, content={"error": "Pipeline not loaded"})

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})

    plugin_name = (body.get("plugin_name") or "").strip()
    instance_name = (body.get("instance_name") or "").strip()
    config_dict = body.get("config") or {}

    if not plugin_name:
        return JSONResponse(status_code=400, content={"error": "'plugin_name' is required"})
    if not instance_name:
        return JSONResponse(status_code=400, content={"error": "'instance_name' is required"})

    # Validate uniqueness of instance_name
    existing_names = set(_get_all_pipeline_instance_names(pipeline))
    if instance_name in existing_names:
        return JSONResponse(
            status_code=409,
            content={"error": f"Instance name '{instance_name}' already exists in the pipeline"},
        )

    config = _get_config(request)

    # Try builtin plugins first
    builtin_classes = _get_builtin_plugin_classes()
    if plugin_name in builtin_classes:
        cls = builtin_classes[plugin_name]
        try:
            config_dict = await _prepare_file_backed_config(plugin_name, config_dict, config)
            new_instance = cls()
            new_instance.setup(config_dict)
            new_instance.name = instance_name
        except Exception as exc:
            logger.exception("Failed to create instance of builtin plugin '%s'", plugin_name)
            return JSONResponse(
                status_code=500,
                content={"error": f"Failed to create plugin instance: {exc}"},
            )
        # Persist to config
        if config is not None:
            from scruxy.config.models import PipelineStageConfig
            new_stage_cfg = PipelineStageConfig(
                name=instance_name,
                stage_type=plugin_name,
                config=config_dict,
            )
            getattr(getattr(config, "pipeline", None), "stages", []).append(new_stage_cfg)
            _normalize_config_stage_order(config)
            _persist_config(request, config)
        pipeline.stages.append(new_instance)
        _normalize_pipeline_order(request)
        return JSONResponse(
            status_code=201,
            content={"plugin": _serialize_detector_plugin(new_instance, request)},
        )

    # User plugins are managed by the plugins stage and cannot be instantiated
    # as standalone stages without restart-safe persistence.
    for stage in getattr(pipeline, "stages", []):
        if hasattr(stage, "plugins"):
            for p in getattr(stage, "plugins", []):
                if getattr(p, "name", "") == plugin_name:
                    return JSONResponse(
                        status_code=400,
                        content={"error": f"User plugin '{plugin_name}' cannot be added as a standalone pipeline stage"},
                    )

    return JSONResponse(status_code=404, content={"error": f"Plugin type '{plugin_name}' not found"})


@router.delete("/api/pipeline/{instance_name}", response_class=JSONResponse)
async def api_pipeline_remove(instance_name: str, request: Request) -> JSONResponse:
    """Remove a plugin instance from the active pipeline by name.

    Does NOT delete user plugin files — only removes the instance from the
    runtime pipeline stages list.  Persists the change to config.
    """
    pipeline = _get_pipeline(request)
    if pipeline is None:
        return JSONResponse(status_code=500, content={"error": "Pipeline not loaded"})

    stages = getattr(pipeline, "stages", [])

    # Search for the instance in top-level stages
    for i, stage in enumerate(stages):
        if getattr(stage, "name", None) == instance_name:
            stages.pop(i)
            # Also remove from config and persist
            config = _get_config(request)
            if config is not None:
                cfg_stages = getattr(getattr(config, "pipeline", None), "stages", [])
                for j, sc in enumerate(cfg_stages):
                    if getattr(sc, "name", "") == instance_name:
                        cfg_stages.pop(j)
                        break
                _persist_config(request, config)
            return JSONResponse(content={"message": f"Instance '{instance_name}' removed from pipeline"})

    return JSONResponse(status_code=404, content={"error": f"Instance '{instance_name}' not found in pipeline"})


_FILE_CONFIG_KEYS = {"whitelist_file", "patterns_file"}


def _generate_unique_file_path(original_path: str, existing_paths: set[str]) -> str:
    """Generate a collision-resistant unique file path.

    Keeps the first copy readable as ``*_2`` for UX continuity, then falls
    back to an unbounded random suffix instead of hard-failing after many
    historical copies.
    """
    p = Path(original_path)
    stem, suffix = p.stem, p.suffix
    parent = p.parent

    preferred = str(parent / f"{stem}_2{suffix}")
    if preferred not in existing_paths and not Path(preferred).expanduser().exists():
        return preferred

    while True:
        candidate = str(parent / f"{stem}_{secrets.token_hex(6)}{suffix}")
        if candidate not in existing_paths and not Path(candidate).expanduser().exists():
            return candidate


async def _copy_file_if_present(original_path: str, new_path: str) -> None:
    try:
        src = Path(original_path).expanduser()
        dst = Path(new_path).expanduser()
        if await asyncio.to_thread(src.exists):
            await asyncio.to_thread(dst.parent.mkdir, parents=True, exist_ok=True)
            await asyncio.to_thread(shutil.copy2, src, dst)
    except Exception:
        logger.warning("Could not copy '%s' → '%s'", original_path, new_path)


async def _prepare_file_backed_config(
    stage_type: str,
    config_dict: dict,
    config: object | None,
) -> dict:
    """Ensure new file-backed builtin instances get independent backing files."""
    prepared = dict(config_dict)
    template_cfg = _find_stage_config_by_type(config, stage_type)
    existing_file_paths = _collect_existing_file_paths(config)

    for key in _FILE_CONFIG_KEYS:
        original_path = prepared.get(key) or template_cfg.get(key)
        if not original_path:
            continue
        new_path = _generate_unique_file_path(str(original_path), existing_file_paths)
        prepared[key] = new_path
        existing_file_paths.add(new_path)
        await _copy_file_if_present(str(original_path), new_path)

    return prepared


def _collect_existing_file_paths(config: object) -> set[str]:
    """Collect all file paths already used by pipeline stages."""
    paths: set[str] = set()
    if config is None:
        return paths
    for stage_cfg in getattr(getattr(config, "pipeline", None), "stages", []):
        cfg = getattr(stage_cfg, "config", {})
        for key in _FILE_CONFIG_KEYS:
            val = cfg.get(key, "")
            if val:
                paths.add(val)
    return paths


@router.post("/api/pipeline/duplicate/{instance_name}", response_class=JSONResponse)
async def api_pipeline_duplicate(instance_name: str, request: Request) -> JSONResponse:
    """Duplicate an existing pipeline instance.

    Creates a copy with name ``{instance_name}_copy`` (or ``_copy2``,
    ``_copy3``, etc. if taken).  Copies the current config, inserts right
    after the original in the pipeline, and returns the new instance.

    For file-backed stages (whitelist, regex), generates a unique file path
    and copies the original file contents.
    """
    pipeline = _get_pipeline(request)
    if pipeline is None:
        return JSONResponse(status_code=500, content={"error": "Pipeline not loaded"})

    config = _get_config(request)

    stages = getattr(pipeline, "stages", [])
    existing_names = set(_get_all_pipeline_instance_names(pipeline))

    # Find the original instance
    original = None
    original_index = -1
    for i, stage in enumerate(stages):
        if getattr(stage, "name", None) == instance_name:
            original = stage
            original_index = i
            break

    if original is None:
        return JSONResponse(status_code=404, content={"error": f"Instance '{instance_name}' not found in pipeline"})

    # Generate a unique copy name
    copy_name = _generate_copy_name(instance_name, existing_names)

    # Determine the plugin base type for instantiation
    original_name = getattr(original, "name", "")
    plugin_type = getattr(original, "plugin_type", "user")

    # Build config dict from the current stage config (deep copy)
    import copy as _copy
    config_dict = _copy.deepcopy(_find_stage_config(request, original_name))

    # For file-backed stages, generate unique file paths and copy contents
    existing_file_paths = _collect_existing_file_paths(config)
    for key in _FILE_CONFIG_KEYS:
        original_path = config_dict.get(key, "")
        if original_path:
            new_path = _generate_unique_file_path(original_path, existing_file_paths)
            config_dict[key] = new_path
            existing_file_paths.add(new_path)
            await _copy_file_if_present(original_path, new_path)

    try:
        if plugin_type == "builtin":
            # For builtins, identify the class from explicit stage type first, then runtime type.
            builtin_classes = _get_builtin_plugin_classes()
            original_stage_type = _get_stage_type(request, original_name)
            cls = builtin_classes.get(original_stage_type)
            if cls is None:
                for _, bcls in builtin_classes.items():
                    if isinstance(original, bcls):
                        cls = bcls
                        break
            if cls is None:
                return JSONResponse(
                    status_code=500,
                    content={"error": f"Cannot determine builtin plugin class for '{instance_name}'"},
                )
            new_instance = cls()
            new_instance.setup(config_dict)
            new_instance.name = copy_name
        else:
            return JSONResponse(
                status_code=400,
                content={"error": f"User plugin '{original_name}' cannot be duplicated as a standalone pipeline stage"},
            )

        # Insert right after the original
        stages.insert(original_index + 1, new_instance)
        _normalize_pipeline_order(request)

    except Exception as exc:
        logger.exception("Failed to duplicate instance '%s'", instance_name)
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to duplicate plugin instance: {exc}"},
        )

    # Persist the new stage to config
    if config is not None:
        from scruxy.config.models import PipelineStageConfig
        new_stage_cfg = PipelineStageConfig(
            name=copy_name,
            stage_type=_get_stage_type(request, original_name),
            config=config_dict,
        )
        # Find original's position in config stages and insert after it
        cfg_stages = getattr(getattr(config, "pipeline", None), "stages", [])
        insert_at = len(cfg_stages)
        for idx, sc in enumerate(cfg_stages):
            if getattr(sc, "name", "") == original_name:
                insert_at = idx + 1
                break
        cfg_stages.insert(insert_at, new_stage_cfg)
        _normalize_config_stage_order(config)
        _persist_config(request, config)

    return JSONResponse(
        status_code=201,
        content={"plugin": _serialize_detector_plugin(new_instance, request)},
    )


# ---------------------------------------------------------------------------
# Plugin display_name rename
# ---------------------------------------------------------------------------

@router.put("/api/plugins/{plugin_name}/display_name", response_class=JSONResponse)
async def api_plugin_rename(plugin_name: str, request: Request) -> JSONResponse:
    """Rename a plugin instance's display name.

    Accepts JSON body: ``{"display_name": "My Custom Whitelist"}``.
    Updates ``PipelineStageConfig.display_name`` and persists to config.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})

    new_display_name = (body.get("display_name") or "").strip()
    if not new_display_name:
        return JSONResponse(status_code=400, content={"error": "Missing or empty 'display_name'"})

    config = _get_config(request)
    if config is None:
        return JSONResponse(status_code=500, content={"error": "No configuration loaded"})

    for stage_cfg in getattr(getattr(config, "pipeline", None), "stages", []):
        if getattr(stage_cfg, "name", "") == plugin_name:
            stage_cfg.display_name = new_display_name
            _persist_config(request, config)
            return JSONResponse(content={
                "message": "Display name updated",
                "name": plugin_name,
                "display_name": new_display_name,
            })

    user_plugin_cfg = _get_user_plugin_config(config, plugin_name, create=False)
    if user_plugin_cfg is not None:
        user_plugin_cfg["_display_name"] = new_display_name
        _persist_config(request, config)
        return JSONResponse(content={
            "message": "Display name updated",
            "name": plugin_name,
            "display_name": new_display_name,
        })

    return JSONResponse(status_code=404, content={"error": f"Stage '{plugin_name}' not found in config"})


@router.put("/api/plugins/{plugin_name}/file/{field_name}/rename", response_class=JSONResponse)
async def api_plugin_file_rename(plugin_name: str, field_name: str, request: Request) -> JSONResponse:
    """Rename (move) a plugin's backing config file.

    Accepts JSON body: ``{"new_path": "~/.scruxy/my_custom_whitelist.yaml"}``.
    Moves the existing file to the new path and updates the config reference.
    The new path must stay within the same parent directory as the original.
    """
    # Restrict field_name to known file config keys
    if field_name not in _FILE_CONFIG_KEYS:
        return JSONResponse(status_code=400, content={"error": f"Invalid field name '{field_name}'"})

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})

    new_path_str = (body.get("new_path") or "").strip()
    if not new_path_str:
        return JSONResponse(status_code=400, content={"error": "Missing or empty 'new_path'"})

    config = _get_config(request)
    if config is None:
        return JSONResponse(status_code=500, content={"error": "No configuration loaded"})

    # Find the stage config that owns this field
    stage_cfg_match = None
    for stage_cfg in getattr(getattr(config, "pipeline", None), "stages", []):
        if getattr(stage_cfg, "name", "") == plugin_name:
            stage_cfg_match = stage_cfg
            break

    if stage_cfg_match is None:
        return JSONResponse(status_code=404, content={"error": f"Stage '{plugin_name}' not found"})

    cfg = getattr(stage_cfg_match, "config", {})
    old_path_str = cfg.get(field_name, "")
    if not old_path_str:
        return JSONResponse(status_code=400, content={"error": f"No file configured for field '{field_name}'"})

    old_path = Path(old_path_str).expanduser().resolve()
    new_path = Path(new_path_str).expanduser().resolve()

    # Sandbox: new path must be in the same directory as the original
    if new_path.parent != old_path.parent:
        return JSONResponse(
            status_code=400,
            content={"error": "New path must be in the same directory as the original file"},
        )

    if old_path == new_path:
        return JSONResponse(content={"message": "Path unchanged", "path": new_path_str})

    # Move the file if it exists
    try:
        if await asyncio.to_thread(old_path.exists):
            await asyncio.to_thread(shutil.move, str(old_path), str(new_path))
    except Exception as exc:
        logger.exception("Failed to move '%s' → '%s'", old_path, new_path)
        return JSONResponse(status_code=500, content={"error": f"Failed to move file: {exc}"})

    # Update config and persist
    cfg[field_name] = new_path_str
    stage_cfg_match.config = cfg

    # Also reconfigure the runtime stage so it reads from the new path
    pipeline = _get_pipeline(request)
    if pipeline is not None:
        for stage in getattr(pipeline, "stages", []):
            if getattr(stage, "name", None) == plugin_name and hasattr(stage, "setup"):
                try:
                    stage.setup(cfg)
                except Exception:
                    logger.warning("Failed to reconfigure stage '%s' after file rename", plugin_name)

    _persist_config(request, config)
    return JSONResponse(content={
        "message": f"File renamed to {new_path_str}",
        "old_path": old_path_str,
        "new_path": new_path_str,
    })


# ---------------------------------------------------------------------------
# Whitelist instances (for tokens page per-instance buttons)
# ---------------------------------------------------------------------------

@router.get("/api/whitelist/instances", response_class=JSONResponse)
async def api_whitelist_instances(request: Request) -> JSONResponse:
    """Return all enabled whitelist stage instances.

    Each entry has ``name`` (internal) and ``display_name`` (user-facing).
    The tokens page uses this to show one Whitelist button per instance.
    """
    config = _get_config(request)
    instances: list[dict] = []
    if config is not None:
        for stage_cfg in getattr(getattr(config, "pipeline", None), "stages", []):
            cfg = getattr(stage_cfg, "config", {})
            if "whitelist_file" in cfg and getattr(stage_cfg, "enabled", True):
                instances.append({
                    "name": getattr(stage_cfg, "name", ""),
                    "display_name": _get_display_name(getattr(stage_cfg, "name", ""), request),
                })
    return JSONResponse(content={"instances": instances})


# Sub-page route (must be last to avoid capturing /api/* paths)
@router.get("/{page}", response_class=HTMLResponse)
async def sub_page(page: str) -> HTMLResponse:
    """Serve sub-pages (plugins, providers, etc.)."""
    # Redirect pipeline → plugins (merged)
    if page == "pipeline":
        from starlette.responses import RedirectResponse
        return RedirectResponse(url="/ui/plugins", status_code=301)  # type: ignore[return-value]

    if page not in _VALID_PAGES:
        return HTMLResponse(content="<h1>404 Not Found</h1>", status_code=404)
    page_path = STATIC_DIR / f"{page}.html"
    if not page_path.exists():
        return HTMLResponse(content="<h1>404 Not Found</h1>", status_code=404)
    return HTMLResponse(content=page_path.read_text(encoding="utf-8"), headers=_NO_CACHE_HEADERS)


class _NoCacheStaticFiles(StaticFiles):
    """StaticFiles subclass that adds no-cache headers to every response.

    During development the browser aggressively caches JS/CSS served by
    Starlette's ``StaticFiles``.  Adding ``Cache-Control: no-store`` ensures
    the latest file on disk is always served.
    """

    async def get_response(self, path: str, scope: dict) -> StreamingResponse:  # type: ignore[override]
        resp = await super().get_response(path, scope)
        resp.headers.update(_NO_CACHE_HEADERS)
        return resp


def mount_static(app: object) -> None:
    """Mount the static files directory on the FastAPI app.

    Call this during app startup after the router has been included.
    The ``app`` parameter is typed as ``object`` to avoid importing FastAPI
    at module level; the caller should pass the real ``FastAPI`` instance.
    """
    from fastapi import FastAPI

    assert isinstance(app, FastAPI)
    app.mount(
        "/ui/static",
        _NoCacheStaticFiles(directory=str(STATIC_DIR)),
        name="ui_static",
    )
