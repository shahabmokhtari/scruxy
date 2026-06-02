"""FastAPI catch-all route: identify provider, scrub, forward, unscrub."""
from __future__ import annotations

import asyncio
import inspect
import logging
import time
import uuid
from dataclasses import dataclass, field
from collections.abc import AsyncGenerator
from typing import Any, AsyncIterator

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from scruxy.proxy.token_map_utils import resolve_response_token_map
from scruxy.recording.recorder import append_capped_text
from scruxy.scrubber.response_unscrubber import deanonymize_text

logger = logging.getLogger(__name__)

router = APIRouter()
_MAX_SSE_RECORD_TEXT_CHARS = 16_384
# R55-2 fix: same per-connection SSE buffer cap as the forward proxy
# (`forward_proxy._MAX_SSE_LINE_BUFFER_BYTES`).  Constant duplicated
# (not imported) to avoid a circular import; the round-55 regression
# tests assert both values stay equal.
_MAX_SSE_LINE_BUFFER_BYTES = 1 * 1024 * 1024
# R56-2 fix: hold back this many trailing bytes when flushing a cap
# overflow so a ``REDACTED_<TYPE>_<N>`` token literal split at the
# cap boundary still re-joins the next chunk for the unscrubber.
# R57-3 fix: bumped from 128 → 4096 bytes to cover script-replacement
# tokens (``tokenmap/replacer.py``) and custom regex/plugin entity
# types whose token literal can exceed the default length.  The R56-2
# regression test asserts both modules' constants stay equal.
_MAX_TOKEN_HOLDBACK_BYTES = 4096

# Hard cap on raw request-body size for the reverse proxy.  Without
# this cap a client could POST an arbitrarily large body to a
# provider-looking path (``/v1/messages``, ``/v1/chat/completions``)
# and exhaust the proxy's memory before the 404/413/scrub decision.
_MAX_REQUEST_BODY_SIZE = 50 * 1024 * 1024  # 50 MiB


def _redact_url_for_log(url: str) -> str:
    """Strip the query string AND userinfo from a URL before logging.

    D3 fix + E2 follow-up: query strings frequently carry PII or
    secrets (email, OAuth code, API key, reset token, session id) AND
    HTTP Basic credentials embedded as ``user:password@host`` would
    otherwise survive the redaction.  Keep scheme + bare host[:port]
    + path; drop userinfo, query, and fragment.
    """
    if not url:
        return url
    try:
        from urllib.parse import urlsplit, urlunsplit
        parts = urlsplit(url)
        if not parts.query and not parts.fragment and "@" not in (parts.netloc or ""):
            return url
        # Rebuild netloc from hostname + port only — drop user/password.
        host = parts.hostname or ""
        # Preserve IPv6 brackets if necessary.
        if ":" in host and not host.startswith("["):
            host_part = f"[{host}]"
        else:
            host_part = host
        netloc = host_part
        if parts.port is not None:
            netloc = f"{netloc}:{parts.port}"
        return urlunsplit((parts.scheme, netloc, parts.path, "", ""))
    except Exception:
        # R54-1 fix: mirror the success path's guarantees (drop
        # userinfo + query + fragment) when urlsplit raises.  Pure
        # string ops since urlsplit is what failed.
        out = url.split("?", 1)[0].split("#", 1)[0]
        if "://" in out and "@" in out:
            scheme, _sep, rest = out.partition("://")
            netloc, slash, path = rest.partition("/")
            if "@" in netloc:
                netloc = netloc.rsplit("@", 1)[1]
            out = f"{scheme}://{netloc}{slash}{path}"
        return out


async def _scrub_url_query(
    url: str,
    pipeline: Any,
    token_map: Any,
    request_id: str,
) -> tuple[str, set[str]]:
    """Scrub PII out of URL query parameter keys AND values.

    E1 fix (round 47) + F1/F2 (round 52): scrubs both keys and
    values, AND returns the set of PII strings detected so the
    caller can ``tag_session_pii`` / ``absorb_pii`` for the
    response-deanonymize path.

    Returns ``(scrubbed_url, detected_pii)``.  When the URL has no
    query string the original URL is returned with an empty PII set.

    Failure modes (fail-closed for PII):
    - On per-pair scrub failure: the value (or key) is replaced
      with an empty string — never forwards raw bytes.
    - On parse failure: the entire query string is dropped.
    """
    if not url:
        return url, set()
    # R54-4 fix: strip URL fragment up-front so EVERY return path
    # (including the early-return branches below for ``"?" not in url``,
    # empty parsed query, and empty pairs) drops the fragment.  R53-8
    # only stripped it on the success path, leaving fragments through
    # all three early returns.
    if "#" in url:
        url = url.split("#", 1)[0]
    if "?" not in url:
        return url, set()
    try:
        from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
        parts = urlsplit(url)
        if not parts.query:
            return url, set()
        # keep_blank_values=True so we don't drop empty params accidentally.
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        if not pairs:
            return url, set()
        scrubbed_pairs: list[tuple[str, str]] = []
        detected_pii: set[str] = set()

        def _absorb(result: Any) -> None:
            """Pull every PII string we can find from a PipelineResult.

            F2 r52 residual fix: the production ``PipelineEngine``
            populates ``result.detected_pii`` (list[(pii_text, token)])
            and ``result.pre_filter_matches`` (list with ``.pii_text``)
            — NOT ``entity._matched_text``.  The original
            implementation only checked the latter and missed every
            real production entity.
            """
            for pair in getattr(result, "detected_pii", None) or []:
                # detected_pii: list[(pii_text, token)]
                if isinstance(pair, tuple) and len(pair) >= 1 and pair[0]:
                    detected_pii.add(pair[0])
            for m in getattr(result, "pre_filter_matches", None) or []:
                pt = getattr(m, "pii_text", None)
                if pt:
                    detected_pii.add(pt)
            # Compatibility fallback for tests that build entities
            # with ``_matched_text``.
            for ent in getattr(result, "entities", None) or []:
                matched = getattr(ent, "_matched_text", None)
                if matched:
                    detected_pii.add(matched)

        for k, v in pairs:
            # Scrub the KEY (F1 fix): a request like
            # `?alice@example.com=1` would otherwise URL-encode
            # the email and forward it raw.
            scrubbed_k = k
            if k:
                try:
                    k_result = await pipeline.scrub_text(
                        k, token_map, None, request_id=request_id,
                    )
                    scrubbed_k = k_result.scrubbed_text
                    _absorb(k_result)
                except Exception:
                    # F4 r52 residual fix: do NOT log the raw key —
                    # it may itself contain PII (the very reason we
                    # were trying to scrub it).  Emit a key-shape
                    # marker instead.
                    logger.exception(
                        "Failed to scrub query key (len=%d, pos=%d)",
                        len(k), len(scrubbed_pairs),
                    )
                    scrubbed_k = ""
            scrubbed_v = v
            if v:
                try:
                    v_result = await pipeline.scrub_text(
                        v, token_map, None, request_id=request_id,
                    )
                    scrubbed_v = v_result.scrubbed_text
                    _absorb(v_result)
                except Exception:
                    logger.exception(
                        "Failed to scrub query value (key_len=%d, val_len=%d, pos=%d)",
                        len(k), len(v), len(scrubbed_pairs),
                    )
                    scrubbed_v = ""
            scrubbed_pairs.append((scrubbed_k, scrubbed_v))
        new_query = urlencode(scrubbed_pairs, doseq=False)
        # R53-8 fix: drop URL fragment.  Per HTTP spec fragments are
        # never sent to servers and the log redactor already strips
        # them; preserving them here would let a non-compliant client
        # smuggle PII through `_scrub_url_query` unscanned.
        return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, "")), detected_pii
    except Exception:
        logger.exception("Failed to scrub URL query string; redacting query entirely")
        # On parse failure, drop the query string entirely (fail closed).
        return url.split("?", 1)[0], set()

# Hard cap on decompressed body size for logging/inspection. Prevents
# compression-bomb DoS where a small compressed input expands to GBs.
_DECOMPRESS_LIMIT = 64 * 1024 * 1024  # 64 MiB
_DECOMPRESS_CHUNK = 64 * 1024
# Brotli one-shot has no output cap, so we cap compressed input size
# at _DECOMPRESS_LIMIT / _BROTLI_MAX_RATIO bytes to bound expansion.
_BROTLI_MAX_RATIO = 200


class RequestBodyTooLarge(Exception):
    """Raised when the incoming reverse-proxy body exceeds the cap."""


def _bounded_zlib_stream(decompressor: Any, raw_body: bytes) -> bytes:
    """Decompress ``raw_body`` through ``decompressor`` with a size cap.

    Returns the original bytes if decompression would exceed
    ``_DECOMPRESS_LIMIT``.  Used only for logging/UI display, so bounded
    failure mode is to leave bytes compressed rather than raise.
    """
    out = bytearray()
    remaining: bytes = raw_body
    while remaining:
        chunk = decompressor.decompress(remaining, _DECOMPRESS_CHUNK)
        out.extend(chunk)
        if len(out) > _DECOMPRESS_LIMIT:
            logger.debug("decompressed body exceeded %d bytes; returning raw", _DECOMPRESS_LIMIT)
            return raw_body
        remaining = decompressor.unconsumed_tail
        if not chunk and not remaining:
            break
    tail = decompressor.flush()
    if tail:
        out.extend(tail)
        if len(out) > _DECOMPRESS_LIMIT:
            return raw_body
    return bytes(out)


# ---------------------------------------------------------------------------
# Minimal compatible types used by the route handler.
# These mirror the real types from other modules so this module can be tested
# and developed independently.
# ---------------------------------------------------------------------------


@dataclass
class ProxyRequest:
    """Lightweight representation of an incoming proxy request.

    This is the object that providers receive for matching and field
    extraction.
    """

    method: str
    url: str
    path: str
    headers: dict[str, str]
    body: bytes | None = None
    body_json: dict | None = None  # Populated lazily if body is valid JSON.


@dataclass
class ScrubResult:
    """Result returned by the request scrubber."""

    scrubbed_body: bytes
    scrubbed_body_json: dict | None = None
    pii_entities_found: int = 0
    scrub_latency_ms: float = 0.0


@dataclass
class UnscrubResult:
    """Result returned by the response unscrubber."""

    unscrubbed_body: bytes
    unscrubbed_body_json: dict | None = None
    tokens_unscrubbed: int = 0
    unscrub_latency_ms: float = 0.0


# ---------------------------------------------------------------------------
# Helper: build ProxyRequest from a FastAPI Request
# ---------------------------------------------------------------------------

async def _build_proxy_request(request: Request, path: str) -> ProxyRequest:
    """Convert a FastAPI ``Request`` into a ``ProxyRequest``.

    Stream-reads the body with a hard size cap (``_MAX_REQUEST_BODY_SIZE``)
    so a malicious client cannot exhaust memory by POSTing an arbitrarily
    large body to a provider-looking path before the routing/scrubbing
    decision is made.  Raises :class:`RequestBodyTooLarge` on overflow.
    """
    import json as _json

    headers = dict(request.headers)

    # Reject up front if the client advertised a Content-Length above the cap.
    cl_header = headers.get("content-length")
    if cl_header:
        try:
            cl = int(cl_header)
            if cl > _MAX_REQUEST_BODY_SIZE:
                raise RequestBodyTooLarge(
                    f"Content-Length {cl} exceeds cap {_MAX_REQUEST_BODY_SIZE}"
                )
        except ValueError:
            pass

    # Stream the body with a running byte counter so we can abort early
    # on chunked / unknown-length bodies that try to overrun the cap.
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        if not chunk:
            continue
        total += len(chunk)
        if total > _MAX_REQUEST_BODY_SIZE:
            raise RequestBodyTooLarge(
                f"Streamed body exceeded cap {_MAX_REQUEST_BODY_SIZE} bytes"
            )
        chunks.append(chunk)
    body = b"".join(chunks)

    # NOTE: Request body decompression is deferred to the scrubbing path.
    # Passthrough traffic must not be decompressed to preserve signatures,
    # HMACs, and other integrity checks on non-LLM traffic.

    body_json: dict | None = None
    if body:
        # Try parsing JSON from raw body (works for uncompressed bodies)
        try:
            parsed_json = _json.loads(body)
            if isinstance(parsed_json, dict):
                body_json = parsed_json
        except (ValueError, TypeError):
            pass
        # If body is compressed and couldn't parse, try decompressing for JSON
        content_encoding = headers.get("content-encoding")
        if body_json is None and content_encoding:
            decompressed = _decompress_body(body, content_encoding)
            if decompressed is not body:
                try:
                    parsed_json = _json.loads(decompressed)
                    if isinstance(parsed_json, dict):
                        body_json = parsed_json
                except (ValueError, TypeError):
                    pass

    return ProxyRequest(
        method=request.method,
        url=str(request.url),
        path=path,
        headers=headers,
        body=body if body else None,
        body_json=body_json,
    )


# ---------------------------------------------------------------------------
# Helper: build a transparent passthrough response
# ---------------------------------------------------------------------------

def _build_passthrough_headers(upstream_headers: dict[str, str]) -> dict[str, str]:
    """Filter upstream response headers for the client response.

    Removes hop-by-hop headers and content-encoding/content-length
    (since we may modify the body during scrub/unscrub).
    """
    from scruxy.proxy.forwarder import HOP_BY_HOP_HEADERS, STRIP_RESPONSE_HEADERS

    exclude = HOP_BY_HOP_HEADERS | STRIP_RESPONSE_HEADERS
    return {
        key: value
        for key, value in upstream_headers.items()
        if key.lower() not in exclude
    }


def _build_transparent_passthrough_headers(
    upstream_headers: dict[str, str],
) -> dict[str, str]:
    """Filter upstream response headers for transparent passthrough.

    Preserves ``content-encoding`` so the client receives the original
    compressed bytes.  Only strips true hop-by-hop headers and
    ``content-length`` (Starlette recomputes it for non-streaming).
    """
    from scruxy.proxy.forwarder import PASSTHROUGH_STRIP_RESPONSE_HEADERS

    return {
        key: value
        for key, value in upstream_headers.items()
        if key.lower() not in PASSTHROUGH_STRIP_RESPONSE_HEADERS
    }


class DecompressFailed(Exception):
    """Raised by :func:`_decompress_body_strict` when decompression cannot
    safely produce plaintext for the matched-provider scrubbing path
    (limit exceeded, brotli, or decompressor error)."""


def _decompress_body(raw_body: bytes, content_encoding: str | None) -> bytes:
    """Best-effort decompress *raw_body* for logging/display purposes.

    Bounded to ``_DECOMPRESS_LIMIT`` bytes to avoid compression-bomb DoS.
    Returns the original bytes if decompression fails or exceeds the limit.
    """
    if not content_encoding or not raw_body:
        return raw_body
    encoding = content_encoding.lower().strip()
    try:
        if encoding == "gzip" or encoding == "x-gzip":
            import zlib
            decompressor = zlib.decompressobj(31)  # 31 = gzip
            return _bounded_zlib_stream(decompressor, raw_body)
        elif encoding == "deflate":
            import zlib
            decompressor = zlib.decompressobj()
            return _bounded_zlib_stream(decompressor, raw_body)
        elif encoding == "br":
            # Brotli's Python binding has no streaming output cap and can
            # achieve very high ratios on crafted inputs.  For the
            # logging/UI display path we choose simplicity over fidelity
            # and return raw bytes for brotli rather than risk a
            # compression-bomb expansion.
            logger.debug("br body decompression skipped for logging (returning raw)")
            return raw_body
    except Exception:
        logger.debug("Failed to decompress %s body for logging", encoding)
    return raw_body


def _decompress_body_strict(raw_body: bytes, content_encoding: str | None) -> bytes:
    """Strict decompress for the matched-provider scrubbing path.

    Unlike :func:`_decompress_body` (which falls back to raw bytes on any
    error to keep the logging/UI tolerant), this variant **fails closed**:

    * brotli (``br``) is rejected outright — Python's brotli binding lacks
      a streaming output cap and can be coerced into very large
      allocations on crafted inputs.
    * gzip/deflate that exceed ``_DECOMPRESS_LIMIT`` raise
      :class:`DecompressFailed` (so the caller can return ``413`` rather
      than forwarding compressed bytes to the upstream provider
      uninspected).
    * Any other decompressor error also raises :class:`DecompressFailed`.

    Returns the (possibly already-plaintext) body when no encoding is set
    or when ``raw_body`` is empty.
    """
    if not content_encoding or not raw_body:
        return raw_body
    encoding = content_encoding.lower().strip()
    if encoding == "identity":
        return raw_body
    import zlib
    try:
        if encoding == "gzip" or encoding == "x-gzip":
            decompressor = zlib.decompressobj(31)
        elif encoding == "deflate":
            decompressor = zlib.decompressobj()
        elif encoding == "br":
            raise DecompressFailed("brotli decompression is disabled for the scrubbing path")
        else:
            # Unsupported encoding (e.g. zstd, compress).  We cannot
            # safely produce plaintext, so we must NOT forward this
            # body to the LLM upstream uninspected.  Fail closed so the
            # caller returns 413/415 to the client.
            raise DecompressFailed(f"unsupported Content-Encoding: {encoding!r}")
    except DecompressFailed:
        raise
    except Exception as exc:
        raise DecompressFailed(f"decompressor init failed: {exc}") from exc

    out = bytearray()
    view = memoryview(raw_body)
    pos = 0
    n = len(view)
    is_gzip_family = encoding in ("gzip", "x-gzip")
    try:
        # Outer loop: handle multi-member gzip per RFC 1952 §2.2.
        # ``pigz`` and several HTTP servers emit such streams; without
        # this loop we'd silently truncate to the first member (B7).
        # For deflate this loop runs exactly once.
        while True:
            while pos < n or decompressor.unconsumed_tail:
                # C1 fix: pass max_length so zlib produces output in
                # bounded chunks.  Without max_length zlib can emit the
                # ENTIRE expanded payload from a single feed (multi-GB
                # for a compression bomb), making _DECOMPRESS_LIMIT
                # unreachable until after the unbounded allocation.
                # We also check the cap BEFORE extending out, so
                # allocation never exceeds limit + chunk.
                tail = decompressor.unconsumed_tail
                if tail:
                    chunk = tail
                else:
                    chunk = bytes(view[pos:pos + _DECOMPRESS_CHUNK])
                    pos += _DECOMPRESS_CHUNK
                if not chunk:
                    break
                piece = decompressor.decompress(chunk, _DECOMPRESS_CHUNK)
                if piece:
                    if len(out) + len(piece) > _DECOMPRESS_LIMIT:
                        raise DecompressFailed(
                            f"decompressed size exceeded limit ({_DECOMPRESS_LIMIT} bytes)"
                        )
                    out.extend(piece)
                if decompressor.eof:
                    break
            tail_out = decompressor.flush()
            if tail_out:
                if len(out) + len(tail_out) > _DECOMPRESS_LIMIT:
                    raise DecompressFailed(
                        f"decompressed size exceeded limit ({_DECOMPRESS_LIMIT} bytes)"
                    )
                out.extend(tail_out)
            # C8 fix: refuse a stream that the decompressor never
            # marked EOF — a truncated gzip body would otherwise be
            # accepted as plaintext.
            if not decompressor.eof:
                raise DecompressFailed(
                    f"{encoding} stream truncated (decompressor did not reach EOF)"
                )
            # Multi-member gzip: drain any remaining input through a
            # fresh decompressor.  ``unused_data`` is the bytes after
            # the current member's trailer.
            unused = decompressor.unused_data or b""
            if is_gzip_family and (unused or pos < n):
                # Splice the unused bytes back into the input stream
                # and start a new gzip member.
                view = memoryview(unused + bytes(view[pos:]))
                pos = 0
                n = len(view)
                if not view:
                    break
                decompressor = zlib.decompressobj(31)
                continue
            break
    except DecompressFailed:
        raise
    except Exception as exc:
        raise DecompressFailed(f"decompression error: {exc}") from exc
    return bytes(out)


def _is_sse_response(response_headers: dict[str, str]) -> bool:
    """Return ``True`` if the response is a server-sent events stream."""
    content_type = ""
    for key, value in response_headers.items():
        if key.lower() == "content-type":
            content_type = value.lower()
            break
    return "text/event-stream" in content_type


# Paths that browsers request but are clearly not LLM API traffic.
_NON_API_PATHS = frozenset({
    "favicon.ico",
    "robots.txt",
    "apple-touch-icon.png",
    "apple-touch-icon-precomposed.png",
    ".well-known/security.txt",
})


def _is_non_api_request(path: str) -> bool:
    """Return True for browser-initiated requests that should get a 404."""
    return path in _NON_API_PATHS


def _append_passthrough_entry(storage_file: str, entry_json: str) -> None:
    """Append a single passthrough log entry to disk (fire-and-forget)."""
    try:
        from pathlib import Path
        p = Path(storage_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(entry_json + "\n")
    except Exception:
        logger.debug("Failed to persist passthrough entry to %s", storage_file)


def _emit_recording_complete(event_bus: Any | None, session_id: str, provider: str) -> None:
    """Push a recording_complete event to all SSE subscribers."""
    if event_bus is None:
        return
    subscribers = getattr(event_bus, "subscribers", [])
    event = {
        "type": "recording_complete",
        "session_id": session_id,
        "provider": provider,
        "timestamp": time.time(),
    }
    # R62-2 fix: snapshot the subscribers list with `list(...)`
    # before iterating.  The SSE handler may mutate the underlying
    # list (`subscribers.append`/`.remove`) across `await` yield
    # points concurrent with this iteration; without the snapshot,
    # `list.remove()` mid-iteration silently skips elements →
    # recording events lost under load.
    for queue in list(subscribers):
        try:
            queue.put_nowait(event)
        except Exception:
            pass


async def _read_response_body(upstream_resp: Any) -> bytes:
    """Return the full upstream response body, buffering streamed responses."""
    try:
        body_bytes = upstream_resp.content
        if isinstance(body_bytes, (bytes, bytearray)):
            return bytes(body_bytes)
    except Exception:
        pass

    aread = getattr(upstream_resp, "aread", None)
    if aread is not None:
        maybe_bytes = aread()
        if inspect.isawaitable(maybe_bytes):
            maybe_bytes = await maybe_bytes
        if isinstance(maybe_bytes, (bytes, bytearray)):
            return bytes(maybe_bytes)

    return b""


# ---------------------------------------------------------------------------
# Catch-all route
# ---------------------------------------------------------------------------

@router.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
)
async def proxy_catch_all(request: Request, path: str) -> Response:
    """Catch-all route: identify provider -> scrub -> forward -> unscrub -> respond.

    Flow
    ----
    1. Build ``ProxyRequest`` from the incoming FastAPI ``Request``.
    2. Match provider via the ``ProviderRegistry``.
    3. **No match** -- transparent passthrough (forward unmodified).
    4. **Match**:
       a. Extract session ID from provider.
       b. Get/create token map from session store.
       c. Scrub request body via the ``RequestScrubber``.
       d. Forward to upstream via the ``UpstreamForwarder``.
       e. If SSE response -- stream with ``SSEStreamUnscrubber``.
       f. If JSON response -- unscrub and return.
       g. Record request/response via the ``SessionRecorder``.

    All service dependencies are obtained from ``request.app.state``.
    """
    import json as _json

    # ------------------------------------------------------------------
    # Resolve dependencies from application state
    # ------------------------------------------------------------------
    state = request.app.state

    registry = getattr(state, "registry", None)
    pipeline = getattr(state, "pipeline", None)
    session_store = getattr(state, "session_store", None)
    request_scrubber = getattr(state, "request_scrubber", None)
    response_unscrubber = getattr(state, "response_unscrubber", None)
    sse_unscrubber = getattr(state, "sse_unscrubber", None)
    forwarder = getattr(state, "forwarder", None)
    recorder = getattr(state, "recorder", None)
    stats = getattr(state, "stats", None)
    event_bus = getattr(state, "event_bus", None)
    _config = getattr(state, "config", None)
    _sse_buf_size = getattr(getattr(_config, "tokens", None), "max_token_length", 40) if _config else 40

    if forwarder is None:
        logger.error("503: forwarder unavailable for %s /%s", request.method, path)
        return JSONResponse(
            status_code=503,
            content={"error": "Proxy not initialised: forwarder unavailable"},
        )

    # ------------------------------------------------------------------
    # 0. Never proxy UI / static-asset requests — they belong to the
    #    UI router / StaticFiles mount.  This guard is a safety net in
    #    case the catch-all is reached before the UI routes (e.g. when
    #    the path lacks a trailing slash).
    # ------------------------------------------------------------------
    if path == "ui" or path.startswith("ui/"):
        return Response(status_code=404)

    # R60-4 / R61-2 / R62-3 fix: reject paths containing ``..`` or
    # ``.`` segments BEFORE provider matching.  Iterate ``unquote``
    # until idempotent so multi-encoded variants are caught.
    # R63-6 fix: fail-closed if path encoding doesn't converge in
    # the bounded number of rounds — likely an attacker probing.
    from urllib.parse import unquote as _unquote
    _decoded_path = path
    _converged = False
    for _ in range(8):
        _next = _unquote(_decoded_path)
        if _next == _decoded_path:
            _converged = True
            break
        _decoded_path = _next
    if not _converged:
        logger.warning(
            "Path encoding did not converge in 8 rounds (decoded_len=%d) -- 400 fail-closed",
            len(_decoded_path),
        )
        return Response(
            status_code=400,
            content="Bad Request: path encoding did not converge",
        )
    _path_segments = _decoded_path.replace("\\", "/").split("/")
    if ".." in _path_segments or "." in _path_segments:
        logger.warning(
            "Rejecting path with traversal segments (decoded_len=%d)",
            len(_decoded_path),
        )
        return Response(status_code=400, content="Bad Request: path contains traversal segments")

    # ------------------------------------------------------------------
    # 0b. Reject browser-initiated requests that are not LLM API traffic
    # ------------------------------------------------------------------
    if _is_non_api_request(path):
        return Response(status_code=404)

    # ------------------------------------------------------------------
    # 0c. Reject oversized advertised Content-Length BEFORE buffering
    #     any body bytes.  Without this an attacker can OOM the proxy
    #     by claiming Content-Length: 10GB and dripping bytes.
    # ------------------------------------------------------------------
    _cl_header = request.headers.get("content-length")
    if _cl_header:
        try:
            _cl = int(_cl_header)
            if _cl > _MAX_REQUEST_BODY_SIZE:
                logger.warning(
                    "Reverse proxy: rejecting Content-Length=%d (cap=%d)",
                    _cl, _MAX_REQUEST_BODY_SIZE,
                )
                return JSONResponse(
                    {"error": "request body too large"},
                    status_code=413,
                )
        except ValueError:
            pass

    # ------------------------------------------------------------------
    # 1. Build ProxyRequest (stream-reads with a hard size cap)
    # ------------------------------------------------------------------
    try:
        proxy_req = await _build_proxy_request(request, path)
    except RequestBodyTooLarge as exc:
        logger.warning("Reverse proxy: rejecting oversized request body: %s", exc)
        return JSONResponse(
            {"error": "request body too large"},
            status_code=413,
        )

    logger.info("Proxy: %s /%s", request.method, path)

    # ------------------------------------------------------------------
    # 2. Match provider
    # ------------------------------------------------------------------
    provider = None
    if registry is not None:
        provider = registry.match(proxy_req)

    if provider is not None:
        logger.info(
            "Matched provider '%s' (upstream=%s)",
            provider.name,
            getattr(provider, "upstream_url", "?"),
        )

    # ------------------------------------------------------------------
    # 3. No match -> passthrough only on non-main ports (8081, 8443)
    #    On the main port (dashboard), return 404 for unmatched requests.
    # ------------------------------------------------------------------
    if provider is None:
        # Determine if this request arrived on the main dashboard port.
        main_port = getattr(state, "main_listen_port", None)
        server_port = (request.scope.get("server") or (None, None))[1]
        is_main_port = main_port is not None and server_port == main_port

        if is_main_port:
            logger.info("No provider matched for %s /%s on main port — 404", request.method, path)
            return JSONResponse(
                status_code=404,
                content={"error": f"No provider matched for {request.method} /{path}"},
            )

        passthrough_log = getattr(state, "passthrough_log", None)
        passthrough_enabled = getattr(state, "passthrough_enabled", False)

        # Check if a disabled provider would have matched (for logging).
        disabled_match = None
        if registry is not None:
            disabled_match = registry.match_disabled(proxy_req)

        # Try to find a provider for upstream routing (host or header match).
        # This handles the case where the host matches a known provider
        # (e.g. api.openai.com) but the specific API path doesn't match
        # any scrubbing pattern (e.g. /v1/models instead of /v1/chat/completions).
        passthrough_provider = disabled_match
        if passthrough_provider is None and registry is not None:
            passthrough_provider = registry.find_passthrough_provider(proxy_req)

        if passthrough_provider is not None:
            upstream_url = _resolve_upstream_url(passthrough_provider, proxy_req)
            if disabled_match is not None:
                logger.info(
                    "Provider '%s' matched %s /%s but is DISABLED — passthrough → %s",
                    disabled_match.name,
                    request.method,
                    path,
                    upstream_url,
                )
            else:
                logger.info(
                    "No scrub match for %s /%s — passthrough via provider '%s' → %s",
                    request.method,
                    path,
                    passthrough_provider.name,
                    upstream_url,
                )
            # Build a modified proxy_req with the resolved upstream URL.
            passthrough_req = ProxyRequest(
                method=proxy_req.method,
                url=upstream_url,
                path=proxy_req.path,
                headers=proxy_req.headers,
                body=proxy_req.body,
                body_json=proxy_req.body_json,
            )
            resp, resp_body = await _passthrough(forwarder, passthrough_req)
        else:
            logger.info("No provider matched for %s /%s — passthrough", request.method, path)
            resp, resp_body = await _passthrough(forwarder, proxy_req)

        _PT_BODY_MAX = 1_000  # Limit passthrough body logging to reduce PII exposure
        if passthrough_enabled and passthrough_log is not None:
            import datetime as _dt
            entry: dict = {
                "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds"),
                "method": proxy_req.method,
                "path": f"/{path}",
                "url": _redact_url_for_log(proxy_req.url),
                "status": resp.status_code,
                "request_content_type": proxy_req.headers.get("content-type", ""),
                "response_content_type": "",
            }
            # Extract response content-type from the response object
            if hasattr(resp, "headers"):
                entry["response_content_type"] = resp.headers.get("content-type", "")
            if disabled_match is not None:
                entry["matched_provider"] = disabled_match.name
                entry["provider_disabled"] = True
            # Body capture is opt-in.  When disabled (default) the
            # passthrough log records request metadata but NEVER persists
            # raw request / response bodies — those may contain real PII
            # for unmatched non-LLM traffic, which the design contract
            # says must not be written to disk.
            capture_bodies = bool(getattr(state, "passthrough_capture_bodies", False))
            if capture_bodies:
                try:
                    req_body_str = proxy_req.body[:_PT_BODY_MAX].decode("utf-8", errors="replace") if proxy_req.body else ""
                    entry["request_body"] = req_body_str
                except Exception:
                    entry["request_body"] = ""
                try:
                    resp_body_str = resp_body[:_PT_BODY_MAX].decode("utf-8", errors="replace") if resp_body else ""
                    entry["response_body"] = resp_body_str
                except Exception:
                    entry["response_body"] = ""
            passthrough_log.append(entry)

            # Persist to disk in a thread to avoid blocking the event loop.
            pt_storage = getattr(state, "passthrough_storage_file", None)
            if pt_storage:
                _entry_json = _json.dumps(entry, separators=(",", ":"))
                asyncio.create_task(
                    asyncio.to_thread(_append_passthrough_entry, pt_storage, _entry_json)
                )

        return resp

    # ------------------------------------------------------------------
    # 4. Matched provider -> full scrub/forward/unscrub pipeline
    # ------------------------------------------------------------------
    try:
        return await _handle_matched_request(
            proxy_req=proxy_req,
            provider=provider,
            session_store=session_store,
            pipeline=pipeline,
            request_scrubber=request_scrubber,
            response_unscrubber=response_unscrubber,
            sse_unscrubber=sse_unscrubber,
            forwarder=forwarder,
            recorder=recorder,
            stats=stats,
            event_bus=event_bus,
            sse_buffer_size=_sse_buf_size,
        )
    except Exception as exc:
        logger.error(
            "Error processing %s /%s for provider %s: %s",
            request.method, path, provider.name, exc,
            exc_info=True,
        )
        return JSONResponse(
            status_code=502,
            content={"error": "Proxy error while processing request"},
        )


# ---------------------------------------------------------------------------
# Transparent passthrough (no provider match)
# ---------------------------------------------------------------------------

async def _passthrough(forwarder: Any, proxy_req: ProxyRequest) -> tuple[Response, bytes | None]:
    """Forward an unmatched request to upstream without modification.

    Uses ``forward_raw`` so that ``Accept-Encoding`` is preserved on the
    request and the upstream's compressed bytes are forwarded to the client
    untouched (no httpx auto-decompression).

    Returns ``(response, decompressed_body_bytes)`` where the body is
    decompressed for logging/display purposes (``None`` for SSE streams).
    """
    upstream_url = proxy_req.url
    is_stream = "text/event-stream" in proxy_req.headers.get("accept", "")
    # Also check body for stream:true (OpenAI convention)
    if not is_stream and isinstance(proxy_req.body_json, dict):
        is_stream = proxy_req.body_json.get("stream") is True

    try:
        upstream_resp = await forwarder.forward_raw(
            method=proxy_req.method,
            url=upstream_url,
            headers=proxy_req.headers,
            body=proxy_req.body,
        )
        resp_headers = _build_transparent_passthrough_headers(
            dict(upstream_resp.headers),
        )
        content_encoding = None
        for k, v in upstream_resp.headers.items():
            if k.lower() == "content-encoding":
                content_encoding = v
                break

        if is_stream:
            async def _stream() -> AsyncIterator[bytes]:
                try:
                    async for chunk in upstream_resp.aiter_raw():
                        yield chunk
                finally:
                    await upstream_resp.aclose()

            return StreamingResponse(
                content=_stream(),
                status_code=upstream_resp.status_code,
                headers=resp_headers,
            ), None

        # Non-streaming: collect raw bytes, always close upstream
        raw_chunks: list[bytes] = []
        try:
            async for chunk in upstream_resp.aiter_raw():
                raw_chunks.append(chunk)
        finally:
            await upstream_resp.aclose()
        raw_body = b"".join(raw_chunks)

        # Decompress for the logging body (display in UI)
        log_body = _decompress_body(raw_body, content_encoding)

        return Response(
            content=raw_body,
            status_code=upstream_resp.status_code,
            headers=resp_headers,
        ), log_body
    except Exception:
        logger.exception("Passthrough upstream error for %s %s", proxy_req.method, _redact_url_for_log(upstream_url))
        return JSONResponse(
            status_code=502,
            content={"error": "Upstream request failed"},
        ), None


# ---------------------------------------------------------------------------
# Matched-provider pipeline
# ---------------------------------------------------------------------------

async def _handle_matched_request(
    *,
    proxy_req: ProxyRequest,
    provider: Any,
    session_store: Any | None,
    pipeline: Any | None,
    request_scrubber: Any | None,
    response_unscrubber: Any | None,
    sse_unscrubber: Any | None,
    forwarder: Any,
    recorder: Any | None,
    stats: Any | None = None,
    event_bus: Any | None = None,
    sse_buffer_size: int = 40,
) -> Response:
    """Execute the full scrub -> forward -> unscrub pipeline for a matched request."""
    import json as _json

    request_start = time.monotonic()

    # 4a. Extract session ID
    session_id = provider.extract_session_id(proxy_req)
    logger.debug(
        "Provider %s matched request %s %s (session=%s)",
        provider.name,
        proxy_req.method,
        proxy_req.path,
        session_id,
    )

    # 4b. Get/create token map for this session
    token_map = None
    if session_store is not None:
        token_map = await session_store.get_or_create_session(session_id)
    response_token_map = await resolve_response_token_map(
        session_store,
        session_id,
        token_map,
    )

    # Generate a unique request_id for token provenance and recording pairing.
    request_id = str(uuid.uuid4())

    # 4b.5. Scrub URL query string (E1 + F1/F2 residuals).  Run this
    # BEFORE the body branch so bodyless matched requests (GET, or
    # POST with non-JSON body) still get their query string scrubbed.
    # F2 fix: also tag/absorb any PII detected in the query so the
    # response unscrubber can reverse it.
    query_pii: set[str] = set()
    if pipeline is not None and token_map is not None and "?" in proxy_req.url:
        scrubbed_url, query_pii = await _scrub_url_query(
            proxy_req.url, pipeline, token_map, request_id,
        )
        if scrubbed_url != proxy_req.url:
            proxy_req.url = scrubbed_url
        if query_pii and session_store is not None and hasattr(session_store, "tag_session_pii"):
            if inspect.iscoroutinefunction(session_store.tag_session_pii):
                await session_store.tag_session_pii(session_id, query_pii)
            else:
                await asyncio.to_thread(
                    session_store.tag_session_pii, session_id, query_pii,
                )
            if response_token_map is not None and hasattr(response_token_map, "absorb_pii"):
                response_token_map.absorb_pii(query_pii)

    # 4c. Scrub request body
    scrubbed_body = proxy_req.body
    scrub_result: ScrubResult | None = None
    scrub_entities: list = []
    _stage_timings: list[dict] = []
    if request_scrubber is not None and proxy_req.body is not None and pipeline is not None:
        import json as _json_mod
        # Decompress body for scrubbing if Content-Encoding is set.
        # Use the *strict* variant: this is a matched-provider request
        # being sent to an LLM upstream, so we MUST inspect plaintext;
        # raw compressed bytes that we can't decompress safely would
        # smuggle PII past the scrubber.  Fail closed with 413 instead.
        scrub_body = proxy_req.body
        _was_decompressed = False
        content_encoding = proxy_req.headers.get("content-encoding")
        if content_encoding:
            try:
                decompressed = _decompress_body_strict(scrub_body, content_encoding)
            except DecompressFailed as exc:
                logger.warning(
                    "Matched provider '%s' but request body decompression failed (%s) — refusing to forward compressed body to LLM upstream",
                    provider.name, exc,
                )
                return JSONResponse(
                    {"error": "request body too large or unsupported encoding"},
                    status_code=413,
                )
            if decompressed is not scrub_body:
                scrub_body = decompressed
                _was_decompressed = True
        try:
            body_dict = _json_mod.loads(scrub_body)
        except (ValueError, TypeError):
            body_dict = None

        if body_dict is not None and isinstance(body_dict, dict) and token_map is not None:
            import time as _time_mod
            _scrub_start = _time_mod.perf_counter()
            scrubbed_dict, entities, _stage_timings, _prefilter_reused = await request_scrubber.scrub_request(
                body=body_dict,
                provider=provider,
                pipeline=pipeline,
                token_map=token_map,
                request_id=request_id,
            )
            _scrub_ms = (_time_mod.perf_counter() - _scrub_start) * 1000
            scrubbed_body = _json_mod.dumps(scrubbed_dict).encode("utf-8")
        elif body_dict is not None and not isinstance(body_dict, dict):
            # Matched provider with a non-dict JSON body (array/string/etc).
            # Fail closed — we don't know how to scrub it, and forwarding
            # raw PII to the upstream LLM would violate the design contract.
            logger.warning(
                "Matched provider '%s' but request body is %s (not dict) — failing closed (415).",
                provider.name, type(body_dict).__name__,
            )
            return JSONResponse(
                {"error": "request body must be a JSON object for matched providers"},
                status_code=415,
            )
        elif body_dict is None and proxy_req.body:
            # Matched provider with an unparseable body (non-JSON or
            # malformed).  Fail closed — round-47's A4/A5 only covered
            # the decompression-failure subcase; this covers JSON parse
            # failure for an otherwise-decoded body.
            logger.warning(
                "Matched provider '%s' but request body is not valid JSON — failing closed (415).",
                provider.name,
            )
            return JSONResponse(
                {"error": "request body must be valid JSON for matched providers"},
                status_code=415,
            )

        # Body was rewritten as plain JSON — strip Content-Encoding (only after successful scrub)
        if body_dict is not None and isinstance(body_dict, dict) and token_map is not None:
            if _was_decompressed:
                proxy_req.headers = {
                    k: v for k, v in proxy_req.headers.items()
                    if k.lower() != "content-encoding"
                }
            scrub_result = ScrubResult(
                scrubbed_body=scrubbed_body,
                scrubbed_body_json=scrubbed_dict,
                pii_entities_found=len(entities),
                scrub_latency_ms=_scrub_ms,
            )
            scrub_entities = entities

            # Tag PII from this request for session-level tracking
            if session_store is not None and hasattr(session_store, "tag_session_pii"):
                request_pii = set()
                for e in entities:
                    matched = getattr(e, "_matched_text", None)
                    if matched:
                        request_pii.add(matched)
                # Include PII reused via the second-pass prefilter — those
                # entries don't produce new entities but must still be tagged
                # so response deanonymization works for this session.
                if _prefilter_reused:
                    request_pii.update(_prefilter_reused)
                if request_pii:
                    if inspect.iscoroutinefunction(session_store.tag_session_pii):
                        await session_store.tag_session_pii(session_id, request_pii)
                    else:
                        await asyncio.to_thread(
                            session_store.tag_session_pii, session_id, request_pii
                        )
                    # E4 r51 residual fix: seed the response view's
                    # snapshot with this request's PII so eviction
                    # between tag and the first deanonymize call
                    # cannot un-mask the tokens we just minted.
                    if response_token_map is not None and hasattr(
                        response_token_map, "absorb_pii"
                    ):
                        response_token_map.absorb_pii(request_pii)
                    maybe_dirty = session_store.mark_dirty(session_id)
                    if inspect.isawaitable(maybe_dirty):
                        await maybe_dirty

    # Use actual per-stage timing from the pipeline for the breakdown.
    pipeline_breakdown: list[dict] | None = None
    if scrub_result is not None and _stage_timings:
        pipeline_breakdown = _stage_timings

    # 4c-ii. Record stats and push SSE event
    if scrub_entities and stats is not None:
        try:
            await stats.record_scrub_event(
                session_id=session_id,
                provider=provider.name,
                entities=scrub_entities,
                latency_ms=scrub_result.scrub_latency_ms if scrub_result else 0,
            )
        except Exception:
            logger.debug("Failed to record scrub stats", exc_info=True)

    if scrub_entities and event_bus is not None:
        now = time.time()
        subscribers = getattr(event_bus, "subscribers", [])
        for entity in scrub_entities:
            event = {
                "type": "scrub_event",
                "session_id": session_id,
                "provider": provider.name,
                "entity_type": getattr(entity, "entity_type", "UNKNOWN"),
                "direction": "request",
                "confidence": round(getattr(entity, "score", 0.0), 3),
                "timestamp": now,
            }
            # R62-2 fix: snapshot subscribers before iterating.
            for queue in list(subscribers):
                try:
                    queue.put_nowait(event)
                except Exception:
                    pass

    # Use the request_id generated earlier (before scrubbing) for recording pairing.
    # Clear it if we don't have a recorder to avoid unnecessary storage.
    if recorder is None:
        request_id = ""

    # Determine upstream URL from provider configuration.
    # The provider's ``upstream_url`` gives the base; reconstruct the path.
    upstream_url = _resolve_upstream_url(provider, proxy_req)

    # 4c-iii. Record request
    if recorder is not None and scrub_result is not None:
        try:
            await recorder.record_request(
                session_id=session_id,
                provider=provider.name,
                method=proxy_req.method,
                path=proxy_req.path,
                body_scrubbed=scrub_result.scrubbed_body_json or {},
                pii_entities_found=scrub_result.pii_entities_found,
                latency_ms=scrub_result.scrub_latency_ms,
                request_id=request_id,
                body_original=body_dict,
                url=upstream_url,
                headers=dict(proxy_req.headers),
                pipeline_breakdown=pipeline_breakdown,
                proxy_type="reverse",
            )
        except Exception:
            logger.warning("Failed to record request", exc_info=True)
        # Update session metadata and index for fast listing
        try:
            harness = proxy_req.headers.get("user-agent", "unknown")
            await recorder.write_metadata(
                session_id=session_id,
                provider=provider.name,
                harness=harness,
            )
        except Exception:
            logger.debug("Failed to write session metadata", exc_info=True)

    # Decide whether we expect an SSE response.
    # Check both Accept header and request body "stream": true.
    wants_stream = "text/event-stream" in proxy_req.headers.get("accept", "")
    if not wants_stream and proxy_req.body_json is not None:
        wants_stream = proxy_req.body_json.get("stream") is True

    # 4d. Forward scrubbed request to upstream
    _scrub_ms_total = scrub_result.scrub_latency_ms if scrub_result else 0.0
    try:
        import time as _time_fwd
        _network_start = _time_fwd.perf_counter()
        upstream_resp = await forwarder.forward(
            method=proxy_req.method,
            url=upstream_url,
            headers=proxy_req.headers,
            body=scrubbed_body,
            stream=wants_stream,
        )
        _network_ms = (_time_fwd.perf_counter() - _network_start) * 1000
    except Exception:
        logger.exception("Upstream request failed for %s %s", proxy_req.method, _redact_url_for_log(upstream_url))
        # Record a failed response so the pair isn't orphaned in recordings.
        if recorder is not None and request_id:
            try:
                _fail_total = (time.monotonic() - request_start) * 1000
                await recorder.record_response(
                    session_id=session_id,
                    status=502,
                    streaming=False,
                    body_scrubbed={"error": "upstream request failed"},
                    tokens_unscrubbed=0,
                    request_id=request_id,
                    total_ms=_fail_total,
                )
            except Exception:
                pass
        return JSONResponse(
            status_code=502,
            content={"error": "Upstream request failed"},
        )

    resp_headers = _build_passthrough_headers(dict(upstream_resp.headers))

    # 4e / 4f. Unscrub response
    # Use SSE path when the upstream actually responds with SSE.
    # When the client requested streaming but upstream returns JSON
    # (e.g. 400/429 error), fall through to the JSON handler to
    # preserve the correct Content-Type.
    #
    # Narrow fallback: if the client requested streaming AND the upstream
    # returned a 2xx chunked body that is NOT clearly JSON, treat it as
    # SSE.  This guards against upstreams that emit SSE-framed bytes
    # under a non-``text/event-stream`` content type — the JSON handler
    # would otherwise buffer indefinitely and fail to deanonymize.
    upstream_is_sse = _is_sse_response(dict(upstream_resp.headers))
    if (
        not upstream_is_sse
        and wants_stream
        and 200 <= upstream_resp.status_code < 300
    ):
        _hdrs_lc = {k.lower(): v.lower() for k, v in upstream_resp.headers.items()}
        _ct = _hdrs_lc.get("content-type", "")
        _te = _hdrs_lc.get("transfer-encoding", "")
        if "chunked" in _te and "application/json" not in _ct:
            logger.debug(
                "Streaming client + chunked non-JSON 2xx response — using SSE path (content-type=%r)",
                _ct,
            )
            upstream_is_sse = True
    if upstream_is_sse:
        # ------ SSE streaming response ------
        return await _handle_sse_response(
            upstream_resp=upstream_resp,
            resp_headers=resp_headers,
            provider=provider,
            token_map=response_token_map,
            sse_unscrubber=sse_unscrubber,
            recorder=recorder,
            session_id=session_id,
            proxy_req=proxy_req,
            scrub_result=scrub_result,
            request_start=request_start,
            request_id=request_id,
            stats=stats,
            scrub_ms=_scrub_ms_total,
            network_ms=_network_ms,
            event_bus=event_bus,
            sse_buffer_size=sse_buffer_size,
        )

    # ------ Non-streaming JSON response ------
    return await _handle_json_response(
        upstream_resp=upstream_resp,
        resp_headers=resp_headers,
        provider=provider,
        token_map=response_token_map,
        response_unscrubber=response_unscrubber,
        recorder=recorder,
        session_id=session_id,
        proxy_req=proxy_req,
        scrub_result=scrub_result,
        request_start=request_start,
        request_id=request_id,
        stats=stats,
        scrub_ms=_scrub_ms_total,
        network_ms=_network_ms,
        event_bus=event_bus,
    )


# ---------------------------------------------------------------------------
# SSE streaming response
# ---------------------------------------------------------------------------

async def _handle_sse_response(
    *,
    upstream_resp: Any,
    resp_headers: dict[str, str],
    provider: Any,
    token_map: Any | None,
    sse_unscrubber: Any | None,
    recorder: Any | None,
    session_id: str,
    proxy_req: ProxyRequest,
    scrub_result: ScrubResult | None,
    request_start: float,
    request_id: str = "",
    stats: Any | None = None,
    scrub_ms: float = 0.0,
    network_ms: float = 0.0,
    event_bus: Any | None = None,
    sse_buffer_size: int = 40,
) -> StreamingResponse:
    """Stream an SSE response while unscrubbing tokens on the fly."""

    # Capture upstream response headers eagerly (before aclose).
    _upstream_headers: dict[str, str] = {}
    try:
        _upstream_headers = dict(upstream_resp.headers)
    except Exception:
        pass

    async def _stream() -> AsyncIterator[bytes]:
        event_count = 0
        tokens_unscrubbed = 0
        scrubbed_text_parts: list[str] = []
        unscrubbed_text_parts: list[str] = []
        scrubbed_text_len = 0
        unscrubbed_text_len = 0
        scrubbed_text_truncated = False
        scrubbed_text_event_count = 0
        # Individual SSE event parts for detailed recording view
        _SSE_PARTS_LIMIT = 200
        scrubbed_sse_parts: list[dict] = []
        try:
            if token_map is not None:
                from scruxy.scrubber.sse_stream_unscrubber import SSEStreamUnscrubber

                unscrub_map = (
                    token_map.unscrub_map
                    if hasattr(token_map, "unscrub_map")
                    else {}
                )
                logger.debug(
                    "SSE unscrub: session=%s, tokens in map=%d",
                    session_id,
                    len(unscrub_map),
                )

                stream_unscrubber = SSEStreamUnscrubber(
                    provider=provider,
                    token_map=token_map,
                    buffer_size=sse_buffer_size,
                )

                # Split raw byte stream into individual SSE lines.
                # aiter_bytes() returns arbitrary chunks that may contain
                # multiple lines; the unscrubber expects one line per iteration.
                async def _sse_lines() -> AsyncGenerator[bytes, None]:
                    nonlocal scrubbed_text_len, scrubbed_text_truncated, scrubbed_text_event_count
                    buf = b""
                    async for raw_chunk in upstream_resp.aiter_bytes():
                        buf += raw_chunk
                        while b"\n" in buf:
                            line, buf = buf.split(b"\n", 1)
                            # Collect SCRUBBED text for recording (before unscrub)
                            if recorder is not None:
                                try:
                                    line_str = line.decode("utf-8", errors="replace")
                                    if line_str.startswith("data: ") or line_str.startswith("data:"):
                                        data_part = line_str[6:] if line_str.startswith("data: ") else line_str[5:]
                                        if data_part.strip() not in ("[DONE]", ""):
                                            sse_field = provider.parse_sse_event(data_part)
                                            if sse_field is not None and sse_field.text_value:
                                                txt = sse_field.text_value
                                                scrubbed_text_len, was_truncated = append_capped_text(
                                                    scrubbed_text_parts,
                                                    txt,
                                                    scrubbed_text_len,
                                                    _MAX_SSE_RECORD_TEXT_CHARS,
                                                )
                                                scrubbed_text_truncated = scrubbed_text_truncated or was_truncated
                                                scrubbed_text_event_count += 1
                                                if len(scrubbed_sse_parts) < _SSE_PARTS_LIMIT:
                                                    scrubbed_sse_parts.append({"i": len(scrubbed_sse_parts), "t": txt})
                                except Exception:
                                    pass
                            yield line
                            # Stop after the terminal [DONE] marker so the
                            # unscrubber can flush its rolling buffer
                            # immediately instead of waiting for the upstream
                            # to close the connection.
                            stripped = line.rstrip()
                            if stripped == b"data: [DONE]" or stripped == b"data:[DONE]":
                                return
                        # R55-2 fix: same OOM-safety cap as the forward
                        # proxy's `_sse_lines` (R54-3).  Apply ONLY to
                        # the residual after the newline-drain loop —
                        # never on a buffer that still has newlines —
                        # to avoid yielding a multi-event blob that
                        # would slip past per-line unscrubbing.
                        # R56-2 fix: hold back the trailing
                        # ``_MAX_TOKEN_HOLDBACK_BYTES`` so a token
                        # literal bisected at the cap boundary still
                        # re-joins the next chunk for the unscrubber's
                        # trie matcher.
                        if len(buf) > _MAX_SSE_LINE_BUFFER_BYTES:
                            logger.warning(
                                "SSE residual buffer exceeded %d bytes "
                                "without newline -- flushing partial line",
                                _MAX_SSE_LINE_BUFFER_BYTES,
                            )
                            # R58-7 fix: removed the dead ``else`` —
                            # the outer guard ensures the holdback
                            # slice is always defined.
                            yield buf[:-_MAX_TOKEN_HOLDBACK_BYTES]
                            buf = buf[-_MAX_TOKEN_HOLDBACK_BYTES:]
                    if buf:
                        yield buf

                async for unscrubbed_chunk in stream_unscrubber.process_sse_stream(_sse_lines()):
                    # B8: skip the synthesized blank-chunk separator
                    # emitted by the unscrubber after a buffer flush.
                    # The separator's purpose is to let our framing
                    # produce the spec-required "\n\n" event terminator
                    # via the next yielded chunk; counting it as a
                    # distinct event would inflate the recorder metric
                    # and emit a stray "\n" byte to the wire.
                    if not unscrubbed_chunk:
                        # Emit just the newline that completes the
                        # PREVIOUS event (turning its trailing "\n"
                        # into the required "\n\n").
                        yield b"\n"
                        continue
                    # Re-add newline stripped by line splitting
                    yield unscrubbed_chunk + b"\n"
                    event_count += 1
                    # Capture unscrubbed text for recording and count tokens
                    if recorder is not None:
                        try:
                            chunk_str = unscrubbed_chunk.decode("utf-8", errors="replace")
                            if chunk_str.startswith("data: ") or chunk_str.startswith("data:"):
                                data_part = chunk_str[6:] if chunk_str.startswith("data: ") else chunk_str[5:]
                                if data_part.strip() != "[DONE]":
                                    sse_field = provider.parse_sse_event(data_part)
                                    if sse_field is not None and sse_field.text_value:
                                        txt = sse_field.text_value
                                        unscrubbed_text_len, was_truncated = append_capped_text(
                                            unscrubbed_text_parts,
                                            txt,
                                            unscrubbed_text_len,
                                            _MAX_SSE_RECORD_TEXT_CHARS,
                                        )
                        except Exception:
                            pass
                # Count unscrubbed tokens from the joined text.
                # Sort longest-first so REDACTED_PERSON_12 is checked before
                # REDACTED_PERSON_1, preventing substring false positives.
                joined_scrubbed = "".join(scrubbed_text_parts)
                joined_unscrubbed = "".join(unscrubbed_text_parts)
                if joined_scrubbed != joined_unscrubbed and token_map is not None:
                    unscrub_map = token_map.unscrub_map if hasattr(token_map, "unscrub_map") else {}
                    for tok in sorted(unscrub_map, key=len, reverse=True):
                        count = joined_scrubbed.count(tok)
                        if count > 0:
                            tokens_unscrubbed += count
                            # Remove to prevent substring double-counting
                            joined_scrubbed = joined_scrubbed.replace(tok, "")
            else:
                async for raw_chunk in upstream_resp.aiter_bytes():
                    yield raw_chunk
                    event_count += 1
        finally:
            await upstream_resp.aclose()

            # Record granular latencies for SSE stream
            # For SSE, unscrub happens incrementally so we approximate total
            _total_ms = (time.monotonic() - request_start) * 1000
            if stats is not None:
                try:
                    await stats.record_latencies(
                        scrub_ms=scrub_ms,
                        network_ms=network_ms,
                        total_ms=_total_ms,
                        provider=provider.name,
                    )
                except Exception:
                    logger.debug("Failed to record SSE latencies", exc_info=True)

            # 4g. Record after stream completes
            if recorder is not None:
                try:
                    body_record: dict = {
                        "event_count": event_count,
                        "streaming": True,
                    }
                    if scrubbed_text_parts:
                        full_text = "".join(scrubbed_text_parts)
                        if scrubbed_text_truncated or len(full_text) > 4096:
                            body_record["text"] = full_text[:4096]
                            body_record["truncated"] = True
                        else:
                            body_record["text"] = full_text
                    if scrubbed_sse_parts:
                        body_record["sse_parts"] = scrubbed_sse_parts
                        if scrubbed_text_event_count > _SSE_PARTS_LIMIT:
                            body_record["sse_parts_truncated"] = True
                    # Build unscrubbed (original) version by deanonymizing
                    # the joined scrubbed text.  This is more reliable than
                    # capturing from the stream output (the rolling buffer
                    # emits empty deltas for buffered fragments).
                    original_record: dict | None = None
                    if scrubbed_text_parts and token_map is not None:
                        full_scrubbed = "".join(scrubbed_text_parts)
                        full_unscrubbed = deanonymize_text(full_scrubbed, token_map)
                        if full_unscrubbed != full_scrubbed:
                            original_record = {
                                "event_count": event_count,
                                "streaming": True,
                            }
                            if scrubbed_text_truncated or len(full_unscrubbed) > 4096:
                                original_record["text"] = full_unscrubbed[:4096]
                                original_record["truncated"] = True
                            else:
                                original_record["text"] = full_unscrubbed
                    _unscrub_ms_approx = max(0, _total_ms - scrub_ms - network_ms)
                    await recorder.record_response(
                        session_id=session_id,
                        status=upstream_resp.status_code,
                        streaming=True,
                        body_scrubbed=body_record,
                        tokens_unscrubbed=tokens_unscrubbed,
                        request_id=request_id,
                        body_original=original_record,
                        headers=_upstream_headers,
                        network_ms=network_ms,
                        unscrub_ms=_unscrub_ms_approx,
                        total_ms=_total_ms,
                    )
                except Exception:
                    logger.warning("Failed to record SSE response", exc_info=True)

            # Notify UI that a recording pair is complete
            _emit_recording_complete(event_bus, session_id, provider.name)

    # Ensure Content-Type is correct for SSE regardless of upstream header
    resp_headers.pop("content-type", None)
    resp_headers.pop("Content-Type", None)

    return StreamingResponse(
        content=_stream(),
        status_code=upstream_resp.status_code,
        headers=resp_headers,
        media_type="text/event-stream",
    )


# ---------------------------------------------------------------------------
# Non-streaming JSON response
# ---------------------------------------------------------------------------

async def _handle_json_response(
    *,
    upstream_resp: Any,
    resp_headers: dict[str, str],
    provider: Any,
    token_map: Any | None,
    response_unscrubber: Any | None,
    recorder: Any | None,
    session_id: str,
    proxy_req: ProxyRequest,
    scrub_result: ScrubResult | None,
    request_start: float,
    request_id: str = "",
    stats: Any | None = None,
    scrub_ms: float = 0.0,
    network_ms: float = 0.0,
    event_bus: Any | None = None,
) -> Response:
    """Unscrub a non-streaming (JSON) response and return it."""
    import json as _json_mod

    try:
        body_bytes = await _read_response_body(upstream_resp)
    except BaseException:
        try:
            await upstream_resp.aclose()
        except Exception:
            pass
        raise

    scrubbed_body_bytes = body_bytes
    tokens_unscrubbed = 0
    scrubbed_resp_dict: dict | None = None
    unscrubbed_dict: dict | None = None

    _unscrub_ms = 0.0
    try:
        if response_unscrubber is not None and token_map is not None and body_bytes:
            import time as _time_mod
            try:
                resp_dict = _json_mod.loads(body_bytes)
            except (ValueError, TypeError):
                resp_dict = None

            if resp_dict is not None:
                # Deep-copy before unscrub mutates the dict in place.
                # The copy retains the scrubbed tokens for recording.
                # R59-6 / R68-3 fix: use JSON round-trip instead of
                # recursive ``copy.deepcopy`` to avoid RecursionError
                # on deeply-nested upstream JSON responses.
                import copy as _copy
                import json as _json_mod
                try:
                    scrubbed_resp_dict = _json_mod.loads(_json_mod.dumps(resp_dict))
                except (TypeError, ValueError):
                    scrubbed_resp_dict = _copy.deepcopy(resp_dict)
                _unscrub_start = _time_mod.perf_counter()
                unscrubbed_dict = response_unscrubber.unscrub_response(
                    body=resp_dict,
                    provider=provider,
                    token_map=token_map,
                )
                _unscrub_ms = (_time_mod.perf_counter() - _unscrub_start) * 1000
                body_bytes = _json_mod.dumps(unscrubbed_dict).encode("utf-8")
                # Count tokens by comparing original vs unscrubbed.
                # Sort longest-first to avoid substring false positives.
                upstream_text = scrubbed_body_bytes.decode("utf-8", errors="replace")
                unscrub_map = token_map.unscrub_map if hasattr(token_map, "unscrub_map") else {}
                remaining_text = upstream_text
                for tok in sorted(unscrub_map, key=len, reverse=True):
                    count = remaining_text.count(tok)
                    if count > 0:
                        tokens_unscrubbed += count
                        remaining_text = remaining_text.replace(tok, "")
    except BaseException:
        try:
            await upstream_resp.aclose()
        except Exception:
            pass
        raise

    # Record granular latencies
    _total_ms = (time.monotonic() - request_start) * 1000
    if stats is not None:
        try:
            await stats.record_latencies(
                scrub_ms=scrub_ms,
                unscrub_ms=_unscrub_ms,
                network_ms=network_ms,
                total_ms=_total_ms,
                provider=provider.name,
            )
        except Exception:
            logger.debug("Failed to record latencies", exc_info=True)

    # 4g. Record (JSON response)
    if recorder is not None:
        try:
            # Pass the actual scrubbed response body (truncated) instead of a placeholder
            body_for_recording: str | dict = scrubbed_resp_dict or {}
            # Capture the unscrubbed (original) response for before/after comparison
            import copy as _copy2
            resp_original_for_recording: dict | None = None
            if unscrubbed_dict is not None:
                # R68-3 sibling fix: same json roundtrip applied here
                # so deeply-nested non-streaming responses don't
                # crash the recording snapshot via RecursionError.
                try:
                    resp_original_for_recording = _json_mod.loads(_json_mod.dumps(unscrubbed_dict))
                except (TypeError, ValueError):
                    resp_original_for_recording = _copy2.deepcopy(unscrubbed_dict)
                orig_serialized = _json_mod.dumps(resp_original_for_recording)
                if len(orig_serialized) > 8192:
                    resp_original_for_recording = {"_truncated": True, "size": len(orig_serialized)}
            if isinstance(body_for_recording, dict):
                serialized = _json_mod.dumps(body_for_recording)
                if len(serialized) > 8192:
                    body_for_recording = {"_truncated": True, "size": len(serialized)}
            await recorder.record_response(
                session_id=session_id,
                status=upstream_resp.status_code,
                streaming=False,
                body_scrubbed=body_for_recording,
                tokens_unscrubbed=tokens_unscrubbed,
                request_id=request_id,
                body_original=resp_original_for_recording,
                headers=dict(upstream_resp.headers),
                network_ms=network_ms,
                unscrub_ms=_unscrub_ms,
                total_ms=_total_ms,
            )
        except Exception:
            logger.warning("Failed to record response", exc_info=True)

    # Notify UI that a recording pair is complete
    _emit_recording_complete(event_bus, session_id, provider.name)

    try:
        await upstream_resp.aclose()
    except Exception:
        pass

    return Response(
        content=body_bytes,
        status_code=upstream_resp.status_code,
        headers=resp_headers,
    )


# ---------------------------------------------------------------------------
# Upstream URL resolution
# ---------------------------------------------------------------------------

def _resolve_upstream_url(provider: Any, proxy_req: ProxyRequest) -> str:
    """Determine the full upstream URL for a matched request.

    If the provider exposes an ``upstream_url`` attribute, the request path
    (including query string) is appended to it.  Otherwise the original
    request URL is used as-is.
    """
    upstream_base: str | None = getattr(provider, "upstream_url", None)
    if upstream_base:
        from urllib.parse import urlparse, urlencode, urlunparse
        # Parse the original URL to get path + query
        parsed = urlparse(proxy_req.url)
        base = upstream_base.rstrip("/")
        path = proxy_req.path.lstrip("/") if proxy_req.path else ""
        full_path = f"{base}/{path}" if path else base
        # Append original query string if present
        if parsed.query:
            full_path = f"{full_path}?{parsed.query}"
        return full_path

    # Fall back to original URL (e.g. transparent proxy).
    return proxy_req.url
