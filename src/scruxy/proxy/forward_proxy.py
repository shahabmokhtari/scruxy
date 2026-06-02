"""Asyncio-based HTTP forward proxy with CONNECT MITM support.

Implements a standard HTTP proxy that clients can use via ``HTTP_PROXY`` /
``HTTPS_PROXY`` environment variables.  For HTTPS targets that match a
known LLM provider, the proxy performs TLS man-in-the-middle interception
so the scrubbing pipeline can inspect and modify the traffic.  Non-LLM
CONNECT targets are tunnelled through transparently.

Plain HTTP forward-proxy requests (absolute-form URLs) are also handled
with scrubbing applied.
"""
from __future__ import annotations

import asyncio
import copy
import datetime as dt
import inspect
import json
import logging
import os
import posixpath
import re
import ssl
import tempfile
import uuid
from typing import Any
from urllib.parse import quote, unquote, urlparse

import httpx
import http as _stdlib_http_module

from scruxy.cert.ca import CertificateAuthority
from scruxy.proxy.forwarder import HOP_BY_HOP_HEADERS, STRIP_RESPONSE_HEADERS
from scruxy.proxy.token_map_utils import resolve_response_token_map
from scruxy.recording.recorder import append_capped_text
from scruxy.scrubber.response_unscrubber import deanonymize_text

logger = logging.getLogger(__name__)

# Maximum size of an HTTP request line + headers block (64 KiB).
_MAX_HEADER_SIZE = 65_536


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
        host = parts.hostname or ""
        if ":" in host and not host.startswith("["):
            host_part = f"[{host}]"
        else:
            host_part = host
        netloc = host_part
        if parts.port is not None:
            netloc = f"{netloc}:{parts.port}"
        return urlunsplit((parts.scheme, netloc, parts.path, "", ""))
    except Exception:
        # R54-1 fix: best-effort fallback that mirrors the success
        # path's guarantees (drop userinfo + query + fragment) when
        # urlsplit raises on a malformed URL.  Pure string ops since
        # urlsplit is what failed.
        out = url.split("?", 1)[0].split("#", 1)[0]
        if "://" in out and "@" in out:
            scheme, _sep, rest = out.partition("://")
            netloc, slash, path = rest.partition("/")
            if "@" in netloc:
                netloc = netloc.rsplit("@", 1)[1]
            out = f"{scheme}://{netloc}{slash}{path}"
        return out
# Per-direction idle timeout for transparent CONNECT tunnels and MITM
# inner relays.  Without this cap a slowloris-style attacker can hold
# tunnels open indefinitely by dripping one byte every few minutes,
# pinning two asyncio tasks + sockets per tunnel.  5 minutes is
# generous for normal LLM SSE streams (keep-alive ~15s) but caps
# the resource impact of pathological clients.
_TUNNEL_IDLE_TIMEOUT_S = 300
# R62-1 fix: per-target TCP connect timeout for CONNECT passthrough.
# Without this, a SYN-blackhole upstream blocks the coroutine for
# the OS TCP timeout (75-120s on Linux, ~21s on Windows).  30s
# accommodates legitimately slow upstreams while bounding the
# worst-case blocking per resolved target so many concurrent
# CONNECT requests to blackhole IPs cannot exhaust fds or asyncio
# tasks.
_CONNECT_TIMEOUT_S = 30
# Per-request header read deadline (seconds).  A client that opens a
# connection but never finishes the request line + headers within this
# window has a slow-loris pattern; close the connection.
_HEADER_READ_TIMEOUT_S = 30
# Per-request body read deadline (seconds) for sized bodies.
_BODY_READ_TIMEOUT_S = 120
_TUNNEL_BUF_SIZE = 65_536

# Maximum body size the proxy will read into memory (50 MB).
# Requests exceeding this limit are rejected to prevent OOM/DoS.
_MAX_BODY_SIZE = 50 * 1024 * 1024
# Brotli has no streaming API with an output-size limit on a single
# call, so we cap the compressed *input* size for brotli decompression
# at max_size / _BROTLI_MAX_RATIO bytes to bound worst-case allocation.
# 200x is generous for typical text payloads (real-world ratios for JSON
# rarely exceed 50x) while still catching pathological compression bombs.
_BROTLI_MAX_RATIO = 200
_MAX_SSE_RECORD_TEXT_CHARS = 16_384
# R54-3 fix: hard cap on the per-line buffer used while parsing SSE
# from upstream.  A misbehaving or malicious provider that streams
# bytes without ever sending a newline would otherwise let `_sse_lines`
# grow `buf` until OOM (~1.5 GB at the 120 s read timeout per
# connection).  When the cap is exceeded we yield the partial buffer
# as a single line and reset, preserving forward progress.
_MAX_SSE_LINE_BUFFER_BYTES = 1 * 1024 * 1024
# R56-2 fix: hold back this many trailing bytes when flushing a cap
# overflow so a ``REDACTED_<TYPE>_<N>`` token literal split at the
# cap boundary still re-joins the next chunk for the unscrubber.
# R57-3 fix: bumped from 128 → 4096 bytes to cover script-replacement
# tokens (``tokenmap/replacer.py``) which can return arbitrary stdout,
# and any custom regex/plugin entity types whose token literal exceeds
# the default ``REDACTED_<TYPE>_<N>`` length.  The worst-case memory
# bound (cap + chunk + holdback) is still well-bounded.
_MAX_TOKEN_HOLDBACK_BYTES = 4096
_LOCAL_ADMIN_PATH_PREFIXES = ("/ui", "/docs", "/redoc")

# Module-level strict-parsing toggle.  ``ForwardProxyServer.__init__``
# updates this from ``config.interception.forward_proxy.strict_http_parsing``.
# When False (default), framing parsers downgrade their RFC-violation
# rejects to WARNING + tolerant pass-through so real-world lax clients
# (VS Code extensions, legacy SDKs) keep working.
_STRICT_HTTP_PARSING = False


def _set_strict_http_parsing(value: bool) -> None:
    global _STRICT_HTTP_PARSING
    _STRICT_HTTP_PARSING = bool(value)


def _strict_or_warn(violation: str) -> bool:
    """Helper for HTTP framing rejects.  Returns True iff the parser
    should hard-reject (raise/return 400); False iff it should log a
    warning and continue with best-effort parsing."""
    if _STRICT_HTTP_PARSING:
        return True
    logger.warning("HTTP framing tolerance: %s (strict mode disabled)", violation)
    return False


def _strip_hop_by_hop(headers: dict[str, str]) -> dict[str, str]:
    """Return *headers* with hop-by-hop entries removed."""
    return {
        k: v for k, v in headers.items()
        if k.lower() not in HOP_BY_HOP_HEADERS
    }


def _status_line(status_code: int, reason_phrase: str | None = None) -> str:
    """Build an RFC 9112-conformant HTTP status line.

    The ABNF requires ``HTTP-version SP status-code SP reason-phrase CRLF``.
    The reason-phrase may be empty *string* but the second SP is mandatory.
    Earlier versions of this proxy emitted ``HTTP/1.1 {code}\\r\\n`` (no
    SP, no reason-phrase) which strict parsers (mitmproxy in some
    modes, some CDNs in front of clients) reject as malformed.

    M1 fix: sanitize ``reason_phrase`` so an upstream-controlled
    string can't inject CR/LF (header injection) or other CTL chars
    into the response status line.
    """
    if not reason_phrase:
        try:
            reason_phrase = _stdlib_http_module.HTTPStatus(status_code).phrase
        except ValueError:
            reason_phrase = ""
    # Strip CR/LF + other CTL characters; also collapse to ASCII to
    # avoid a UnicodeEncodeError downstream on .encode("latin-1").
    safe_reason = "".join(
        c for c in reason_phrase
        if c == " " or c == "\t" or (32 < ord(c) < 127)
    )
    return f"HTTP/1.1 {status_code} {safe_reason}\r\n"


def _strip_response_headers(headers: dict[str, str]) -> dict[str, str]:
    """Strip response headers that shouldn't be relayed to the client."""
    exclude = HOP_BY_HOP_HEADERS | STRIP_RESPONSE_HEADERS
    return {k: v for k, v in headers.items() if k.lower() not in exclude}


class DecompressLimitExceeded(Exception):
    """Raised when a compressed body decompresses to more than ``_MAX_BODY_SIZE`` bytes."""


def _decompress_body(
    raw: bytes,
    encoding: str | None,
    *,
    max_size: int = _MAX_BODY_SIZE,
    strict: bool = False,
) -> bytes:
    """Best-effort, bounded decompression of *raw* based on Content-Encoding.

    Streams the decompressor in chunks and aborts via
    ``DecompressLimitExceeded`` once the cumulative output would exceed
    ``max_size``, protecting against compression-bomb DoS where a small
    compressed payload expands to gigabytes.

    When ``strict=False`` (the legacy passthrough/logging behaviour) any
    unrecognised encoding or transient decompressor error returns the
    original bytes unchanged.  When ``strict=True`` (the matched-provider
    request-scrubbing path) those same conditions raise
    :class:`DecompressLimitExceeded` instead, so the caller can fail
    closed with a 413 -- preventing PII smuggling through an encoding
    Scruxy doesn't decode (e.g. ``zstd``) or through a corrupted body
    that would otherwise be forwarded uninspected.
    """
    if not encoding or not raw:
        return raw
    enc = encoding.lower().strip()
    # ``identity`` is the no-transform encoding token (RFC 7231).
    if enc == "identity":
        return raw
    try:
        if enc in ("gzip", "x-gzip"):
            import zlib
            decomp = zlib.decompressobj(zlib.MAX_WBITS | 16)
        elif enc == "deflate":
            import zlib
            decomp = zlib.decompressobj()
        elif enc == "br":
            # Brotli's Python binding has no streaming output cap and can
            # achieve ratios well above any input-size heuristic for
            # repetitive payloads.  For the forward-proxy request-scrubbing
            # path we therefore *fail closed* on brotli: raising
            # DecompressLimitExceeded causes the matched-provider path to
            # return 413 (so PII cannot be smuggled through unscrubbed),
            # while unmatched passthrough still works because the caller
            # preserves the original raw_body.
            raise DecompressLimitExceeded(
                "Brotli request decompression is disabled for safety; "
                "matched providers will fail closed, passthrough preserves raw bytes"
            )
        else:
            if strict:
                # Unsupported encoding (zstd, compress, ...): we cannot
                # produce plaintext for the scrubber, so we MUST fail
                # closed rather than forward an opaque body to the LLM.
                raise DecompressLimitExceeded(
                    f"Unsupported Content-Encoding {enc!r} for matched provider"
                )
            return raw

        # Bounded incremental decompression for zlib-family codecs.
        # C8 fix: handle multi-member gzip streams (RFC 1952 section 2.2)
        # AND verify the decompressor reached EOF -- a truncated gzip
        # body would otherwise be silently accepted as plaintext.
        chunks: list[bytes] = []
        total = 0
        view = memoryview(raw)
        step = 64 * 1024
        i = 0
        n = len(view)
        is_gzip_family = enc in ("gzip", "x-gzip")
        while True:
            while i < n or decomp.unconsumed_tail:
                tail = decomp.unconsumed_tail
                if tail:
                    piece_in = tail
                else:
                    piece_in = bytes(view[i : i + step])
                    i += step
                if not piece_in:
                    break
                try:
                    out = decomp.decompress(piece_in, max_size - total + 1)
                except Exception as exc:
                    logger.debug("Failed to decompress %s body (%d bytes)", enc, len(raw))
                    if strict:
                        raise DecompressLimitExceeded(
                            f"Decompressor error for {enc} body: {exc}"
                        ) from exc
                    return raw
                if out:
                    total += len(out)
                    if total > max_size:
                        raise DecompressLimitExceeded(
                            f"Decompressed {enc} body exceeds {max_size} bytes"
                        )
                    chunks.append(out)
                if decomp.eof:
                    break
            try:
                tail_out = decomp.flush()
            except Exception as exc:
                logger.debug("Failed to flush %s decompressor", enc)
                if strict:
                    raise DecompressLimitExceeded(
                        f"Decompressor flush error for {enc} body: {exc}"
                    ) from exc
                return raw
            if tail_out:
                total += len(tail_out)
                if total > max_size:
                    raise DecompressLimitExceeded(
                        f"Decompressed {enc} body exceeds {max_size} bytes"
                    )
                chunks.append(tail_out)
            # In strict mode, refuse any stream that didn't reach EOF
            # (e.g. truncated-footer gzip).
            if strict and not decomp.eof:
                raise DecompressLimitExceeded(
                    f"{enc} stream truncated (decompressor did not reach EOF)"
                )
            # In LENIENT mode, returning a truncated plaintext to the
            # caller would silently mask a corrupted body — the
            # matched-provider gate uses ``decompressed is not body``
            # to decide whether decompression succeeded.  If we let a
            # truncated stream pass that check, the proxy would treat
            # the partial JSON as authoritative, scrub it, and
            # forward.  Return raw bytes instead so the caller's
            # "encoding present but result unchanged" path sets
            # ``_decompress_failed = True`` and matched providers
            # fail closed (GPT-5.5 forward-proxy residual).
            if not decomp.eof:
                return raw
            # Multi-member gzip: drain remaining input through a fresh
            # decompressor.  ``unused_data`` is the bytes after the
            # current member's trailer.
            unused = decomp.unused_data or b""
            if is_gzip_family and (unused or i < n):
                view = memoryview(unused + bytes(view[i:]))
                i = 0
                n = len(view)
                if not view:
                    break
                decomp = zlib.decompressobj(zlib.MAX_WBITS | 16)
                continue
            break
        return b"".join(chunks)
    except DecompressLimitExceeded:
        raise
    except Exception:
        logger.debug("Failed to decompress %s body (%d bytes)", enc, len(raw))
    return raw


def _bounded_brotli_decompress(raw: bytes, max_size: int) -> bytes:
    """Bounded brotli decompression.

    brotli's Python binding lacks a streaming API with an output-size
    limit on a single call, so a maliciously crafted single chunk can
    expand to an arbitrarily large buffer before our post-call size
    check runs.  To bound worst-case memory, we cap the *compressed
    input* size at ``max_size / _BROTLI_MAX_RATIO`` (default 200×).
    Inputs above that cap are rejected outright with
    ``DecompressLimitExceeded`` so that the decompressor cannot
    allocate more than ~``max_size * something_small`` bytes between
    our checks.  We also feed the input in chunks and check the
    cumulative output after each call.
    """
    import brotli  # type: ignore[import-untyped]

    if len(raw) > max_size // _BROTLI_MAX_RATIO + 1:
        raise DecompressLimitExceeded(
            f"Brotli input {len(raw)} bytes exceeds safe input cap "
            f"({max_size // _BROTLI_MAX_RATIO} bytes)"
        )

    decomp = brotli.Decompressor()
    chunks: list[bytes] = []
    total = 0
    step = 64 * 1024
    view = memoryview(raw)
    for i in range(0, len(view), step):
        piece = bytes(view[i : i + step])
        try:
            out = decomp.process(piece)
        except Exception:
            logger.debug("Failed to decompress brotli body (%d bytes)", len(raw))
            return raw
        if out:
            total += len(out)
            if total > max_size:
                raise DecompressLimitExceeded(
                    f"Decompressed brotli body exceeds {max_size} bytes"
                )
            chunks.append(out)
    return b"".join(chunks)


def _is_forbidden_proxy_ip(ip: Any) -> bool:
    """Return whether *ip* is not safe to proxy to."""
    if not ip.is_global or ip.is_reserved:
        return True
    # Block NAT64 well-known prefix (64:ff9b::/96) which can embed
    # private/loopback IPv4 addresses that appear globally-routable.
    import ipaddress
    if isinstance(ip, ipaddress.IPv6Address):
        nat64_prefix = ipaddress.IPv6Network("64:ff9b::/96")
        if ip in nat64_prefix:
            embedded_v4 = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
            if not embedded_v4.is_global or embedded_v4.is_reserved:
                return True
    return False


def _build_host_header(parsed: Any) -> str:
    """Build the Host header for a parsed URL, preserving non-default ports."""
    hostname = parsed.hostname or ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    port = parsed.port
    default_port = 443 if parsed.scheme == "https" else 80
    if port and port != default_port:
        return f"{hostname}:{port}"
    return hostname


def _is_blocked_local_admin_path(path: str) -> bool:
    """Return whether *path* targets the local app's UI/admin surface.

    R63-3 fix: iterate ``unquote`` until idempotent (matches R62-3
    in the traversal guards).  A double-encoded path like
    ``/%252fui%252fapi%252fevents`` would otherwise pass the admin
    block while a fronting infra/upstream that decodes again would
    route to the actual admin endpoint.

    R64-1 fix: FAIL CLOSED if the unquote loop doesn't converge
    in the bounded number of rounds (mirrors R63-6 in the traversal
    guards).  Returning ``True`` (i.e. "this IS an admin path,
    block it") on non-convergence is the safe default — better to
    reject a possibly-pathological 9+ encoding-layer path than to
    risk admin-surface bypass via a fronting decoder.
    """
    normalized = path or "/"
    _converged = False
    for _ in range(8):
        decoded = unquote(normalized)
        if decoded == normalized:
            _converged = True
            break
        normalized = decoded
    if not _converged:
        return True
    normalized = normalized.replace("\\", "/")
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    while "//" in normalized:
        normalized = normalized.replace("//", "/")
    normalized = posixpath.normpath(normalized)
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    normalized = "/".join(part.split(";", 1)[0] for part in normalized.split("/"))
    while "//" in normalized:
        normalized = normalized.replace("//", "/")
    normalized = normalized.lower()
    if normalized in {"/", "/openapi.json"}:
        return True
    return any(
        normalized == prefix or normalized.startswith(prefix + "/")
        for prefix in _LOCAL_ADMIN_PATH_PREFIXES
    )


def _replace_url_host(parsed: Any, host: str, port: int) -> str:
    """Return *parsed* rebuilt with *host* and *port* in the netloc."""
    host_part = host
    if ":" in host and not host.startswith("["):
        host_part = f"[{host}]"
    # Reuse the raw userinfo from the original netloc to avoid
    # double-encoding already-percent-encoded values.  ``parsed.username``
    # and ``parsed.password`` preserve percent-encoding verbatim, so
    # re-applying ``quote`` would turn ``%40`` into ``%2540``.
    userinfo = ""
    raw_netloc = parsed.netloc or ""
    if "@" in raw_netloc:
        userinfo = raw_netloc.rsplit("@", 1)[0] + "@"
    default_port = 443 if parsed.scheme == "https" else 80
    authority = host_part if port == default_port else f"{host_part}:{port}"
    netloc = f"{userinfo}{authority}"
    return parsed._replace(netloc=netloc).geturl()


def _split_head_from_buffer(buf: bytes) -> tuple[str, bytes] | None:
    """Return a decoded header block and leftover body bytes when complete."""
    if b"\r\n\r\n" in buf:
        head, _, rest = buf.partition(b"\r\n\r\n")
        return head.decode("latin-1"), rest
    if b"\n\n" in buf:
        head, _, rest = buf.partition(b"\n\n")
        return head.decode("latin-1"), rest
    return None


async def _resolve_public_endpoints(hostname: str, port: int) -> list[tuple[str, int]]:
    """Resolve *hostname* and return all safe public endpoints in resolver order."""
    import ipaddress as _ipa
    import socket

    addrs = await asyncio.to_thread(
        socket.getaddrinfo,
        hostname,
        port,
        proto=socket.IPPROTO_TCP,
    )
    resolved_addrs: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    for _, _, _, _, addr in addrs:
        ip = _ipa.ip_address(addr[0])
        if _is_forbidden_proxy_ip(ip):
            raise PermissionError(f"private/reserved IP {ip}")
        candidate = (addr[0], addr[1])
        if candidate not in seen:
            resolved_addrs.append(candidate)
            seen.add(candidate)
    if not resolved_addrs:
        raise OSError(f"No DNS answers for {hostname}:{port}")
    return resolved_addrs


async def _read_chunked_body(
    reader: asyncio.StreamReader,
    leftover: bytes,
    *,
    deadline: float | None = None,
) -> tuple[bytes, bytes]:
    """Read an HTTP chunked transfer-encoded body.

    Returns ``(body, carry)`` -- *carry* is bytes left in the buffer
    AFTER the terminal trailers (the start of the NEXT pipelined
    request on a keep-alive tunnel).  C4 fix: previously the helper
    returned only the body and silently discarded these trailing
    bytes, corrupting pipelined requests in the MITM keep-alive loop.

    *leftover* contains any bytes already read past the header terminator.
    Raises ``ValueError`` if the total body exceeds ``_MAX_BODY_SIZE`` or
    if a malformed chunk-size line is encountered.

    *deadline* is an absolute event-loop time (``loop.time() + N``) that
    bounds the *total* read; without it a slow-loris client can hold a
    forward-proxy worker indefinitely by dripping one byte per chunk.
    Raises :class:`asyncio.TimeoutError` if exceeded.
    """
    buf = leftover
    body_parts: list[bytes] = []
    total_size = 0

    async def _read(n: int) -> bytes:
        if deadline is None:
            return await reader.read(n)
        time_left = deadline - asyncio.get_event_loop().time()
        if time_left <= 0:
            raise asyncio.TimeoutError("chunked body read exceeded deadline")
        return await asyncio.wait_for(reader.read(n), timeout=time_left)

    while True:
        # Find the next chunk-size line.
        while b"\r\n" not in buf:
            if len(buf) > _MAX_HEADER_SIZE:
                raise ValueError(f"Chunk-size line exceeds {_MAX_HEADER_SIZE} bytes")
            chunk = await _read(_TUNNEL_BUF_SIZE)
            if not chunk:
                return b"".join(body_parts), buf
            buf += chunk
            if len(buf) > _MAX_HEADER_SIZE:
                raise ValueError(f"Chunk-size line exceeds {_MAX_HEADER_SIZE} bytes")

        line, buf = buf.split(b"\r\n", 1)
        size_str = line.split(b";", 1)[0].strip()
        # R71-1 fix: ``int(size_str, 16)`` accepts ``+5``, leading
        # whitespace (already stripped), Python's ``5_000`` literal
        # syntax in some versions, and Unicode digits.  Per RFC 9112
        # §7.1 chunk-size = 1*HEXDIG → ASCII hex only.  Strict regex
        # avoids parser disagreement with the upstream → smuggling.
        if not re.fullmatch(rb"[0-9A-Fa-f]+", size_str):
            raise ValueError(f"Malformed chunk size: {size_str!r}")
        try:
            chunk_size = int(size_str, 16)
        except ValueError:
            raise ValueError(f"Malformed chunk size: {size_str!r}")
        if chunk_size == 0:
            # Terminal chunk -- consume optional trailers (header lines
            # ending with an empty \r\n) so they don't leak into the
            # next request on a keep-alive connection.
            while True:
                while b"\r\n" not in buf:
                    if len(buf) > _MAX_HEADER_SIZE:
                        raise ValueError(f"Chunked trailer exceeds {_MAX_HEADER_SIZE} bytes")
                    data = await _read(_TUNNEL_BUF_SIZE)
                    if not data:
                        return b"".join(body_parts), buf
                    buf += data
                    if len(buf) > _MAX_HEADER_SIZE:
                        raise ValueError(f"Chunked trailer exceeds {_MAX_HEADER_SIZE} bytes")
                trailer_line, buf = buf.split(b"\r\n", 1)
                if not trailer_line:
                    break  # empty line = end of trailers
            return b"".join(body_parts), buf

        total_size += chunk_size
        if total_size > _MAX_BODY_SIZE:
            raise ValueError(f"Chunked body exceeds maximum size ({_MAX_BODY_SIZE} bytes)")

        # Read exactly chunk_size bytes of data + trailing \r\n.
        while len(buf) < chunk_size + 2:
            data = await _read(_TUNNEL_BUF_SIZE)
            if not data:
                raise ValueError(
                    f"Connection closed mid-chunk (expected {chunk_size} bytes, got {min(len(buf), chunk_size)})"
                )
            buf += data
        body_parts.append(buf[:chunk_size])
        buf = buf[chunk_size + 2:]

    return b"".join(body_parts), buf


def _append_passthrough_entry(storage_file: str, entry_json: str) -> None:
    """Append a single passthrough log entry to disk (fire-and-forget)."""
    try:
        from pathlib import Path as _P
        p = _P(storage_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(entry_json + "\n")
    except Exception:
        logger.debug("Failed to persist passthrough entry to %s", storage_file)


_METHOD_TOKEN_RE = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_HTTP_VERSION_RE = re.compile(r"HTTP/[0-9]\.[0-9]")
_HEADER_NAME_TOKEN_RE = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_HEADER_VALUE_CTL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _parse_request_line(line: str) -> tuple[str, str, str]:
    """Parse an HTTP request line into (method, target, version).

    R71-Op47-NEW-A fix: enforce strict ASCII-SP separators and
    validate method/version per RFC 9112 §3.  ``str.split(None, 2)``
    accepts tabs, multiple spaces, and Unicode whitespace as
    separators — a parser disagreement primitive in the same class
    as R71-1 (lax CL/chunk-size int parsing).

    When ``_STRICT_HTTP_PARSING`` is False (default), violations log
    a WARNING and the parser falls back to the legacy lax form so
    real-world clients keep working.
    """
    s = line.strip("\r\n")
    if not s:
        raise ValueError(f"Malformed request line: {line!r}")
    # Strict path: exactly one ASCII SP between fields.
    if _STRICT_HTTP_PARSING:
        parts = s.split(" ")
        if len(parts) < 3:
            raise ValueError(f"Malformed request line: {line!r}")
        method = parts[0]
        version = parts[-1]
        target = " ".join(parts[1:-1])
        if not _METHOD_TOKEN_RE.fullmatch(method):
            raise ValueError(f"Malformed request line: invalid method {method!r}")
        if not _HTTP_VERSION_RE.fullmatch(version):
            raise ValueError(f"Malformed request line: invalid HTTP version {version!r}")
        if not target or " " in target or "\t" in target:
            raise ValueError(f"Malformed request line: invalid target {target!r}")
        return method.upper(), target, version
    # Tolerant path: legacy split-on-whitespace; warn but accept.
    parts = s.split(None, 2)
    if len(parts) < 3:
        raise ValueError(f"Malformed request line: {line!r}")
    method, target, version = parts[0], parts[1], parts[2]
    if not _METHOD_TOKEN_RE.fullmatch(method) or not _HTTP_VERSION_RE.fullmatch(version):
        logger.warning("HTTP framing tolerance: lax request line %r (strict mode disabled)", line)
    return method.upper(), target, version


def _parse_headers(raw: str) -> dict[str, str]:
    """Parse raw header lines into a dict.

    Raises ``ValueError`` if duplicate ``Content-Length`` or
    ``Transfer-Encoding`` headers are found, OR if both headers are
    present simultaneously (request smuggling defence -- RFC 9112 section 6.1
    requires rejecting any message that supplies both framing signals).
    """
    headers: dict[str, str] = {}
    _SENSITIVE = {"content-length", "transfer-encoding"}
    seen_sensitive: set[str] = set()
    # R70-3 fix: split ONLY on \r\n / \n (and tolerate bare \r at line
    # boundaries from clients that emit malformed line endings).
    # ``str.splitlines()`` also splits on \v, \f, \x1c-\x1e, \x85,
    # \u2028, \u2029 — a header value containing one of those is
    # silently split into two header entries → cookie injection,
    # auth swap, X-Forwarded-* spoofing.  Use a regex that ONLY
    # accepts standard HTTP line terminators.
    for line in re.split(r"\r\n|\n", raw):
        # Reject any header line containing a bare CR / LF in the
        # value (post-split).  Standard line terminators were already
        # consumed; what's left is a smuggling primitive.
        if "\r" in line or "\n" in line:
            if _strict_or_warn(f"bare CR/LF in header line: {line!r}"):
                raise ValueError(
                    "Header line contains bare CR/LF; rejecting to prevent "
                    "header injection (RFC 9112 section 5)."
                )
            line = line.replace("\r", "").replace("\n", "")
        # R71-2 fix: RFC 7230 §3.2.4 deprecated "obsolete line folding"
        # (a continuation line that begins with SP/HTAB) and RFC 9112
        # §5.2 requires senders to NOT send it; recipients SHOULD
        # reject it.  If we silently treat such a line as a NEW
        # header, an attacker can smuggle ``Host`` / ``Authorization``
        # past the sensitive-header guard by emitting them as
        # continuation lines after a benign header.
        if line and line[0] in " \t":
            if _strict_or_warn("obs-fold continuation line"):
                raise ValueError(
                    "Obsolete line folding rejected (RFC 9112 section 5.2); "
                    "header continuation lines are forbidden."
                )
            # Tolerant mode: skip the continuation entirely (we can't
            # safely fold it into the prior header without a smuggling
            # primitive on either side; skipping it is the most
            # conservative compromise).
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            key_stripped = key.strip(" \t")
            key_lower = key_stripped.lower()
            # R71-Op47-NEW-B fix: validate field-name as RFC 9110 §5.1
            # token.  Without this, ``"X-Foo bar: v"`` becomes
            # ``"X-Foo bar"`` lowercased — an attacker can place
            # ``\x7f`` or other CTLs in a header name to bypass case-
            # folded sensitive-name guards while a strict upstream
            # still parses the header.  Same parser-disagreement
            # smuggling class as R71-1 / R71-2.
            if not _HEADER_NAME_TOKEN_RE.fullmatch(key_stripped):
                if _strict_or_warn(f"non-token header name {key_stripped!r}"):
                    raise ValueError(
                        f"Invalid header name {key_stripped!r} (RFC 9110 "
                        f"section 5.1: token chars only)"
                    )
                # Tolerant mode: drop the malformed header entirely.
                # Folding it in would expose case-folded sensitive-
                # name guards to spoofing.
                continue
            if key_lower in _SENSITIVE:
                if key_lower in seen_sensitive:
                    raise ValueError(f"Duplicate header rejected: {key_stripped}")
                seen_sensitive.add(key_lower)
            # R71-Op47-NEW-B fix: tighten OWS strip to ASCII SP/HTAB only
            # so a value-trailing ``\v``/``\f``/``\x7f`` is *visible*
            # rather than silently removed.  Then reject any CTL chars
            # in the post-strip value per RFC 9110 §5.5.
            value_stripped = value.strip(" \t")
            if _HEADER_VALUE_CTL_RE.search(value_stripped):
                if _strict_or_warn(f"CTL char in header value for {key_stripped!r}"):
                    raise ValueError(
                        f"Invalid header value for {key_stripped!r} "
                        f"(contains CTL chars; RFC 9110 section 5.5)"
                    )
                # Tolerant mode: strip CTL chars and continue.
                value_stripped = _HEADER_VALUE_CTL_RE.sub("", value_stripped)
            # R58-5 fix: a request that sends multiple values for the
            # same header (legitimately allowed by RFC 7230, e.g.
            # multiple ``Cookie`` lines) was silently overwritten by
            # plain dict assignment.
            # R59-1 fix: store keys LOWERCASED so case-variant
            # duplicates are detected (``Cookie`` vs ``cookie``) AND
            # so the downstream body-reader's ``.get("transfer-encoding")``
            # path always finds the value, closing a request-smuggling
            # vector where ``TRANSFER-ENCODING: chunked`` would pass
            # the smuggling guard but be invisible to the body reader.
            # R59-3 fix: ``Cookie`` MUST be joined with ``; `` per
            # RFC 6265 §5.4 (cookie-string is a semicolon-separated
            # list of name=value pairs); other list-valued headers
            # use ``, `` per RFC 7230 §3.2.2.
            if key_lower in headers:
                joiner = "; " if key_lower == "cookie" else ", "
                headers[key_lower] = headers[key_lower] + joiner + value_stripped
            else:
                headers[key_lower] = value_stripped
    # CL+TE coexistence is a classic request-smuggling vector: the proxy
    # may pick one framing while the upstream picks the other.  Reject.
    if len(seen_sensitive) > 1:
        raise ValueError(
            "Request supplies both Content-Length and Transfer-Encoding; "
            "rejecting to prevent request smuggling (RFC 9112 section 6.1)."
        )
    return headers


def _canonicalize_hostname(hostname: str) -> str:
    """R70-14 + R71-5 fix: canonicalize a DNS / IP literal hostname for
    provider matching.

    Strips one or more trailing dots (absolute-FQDN form), strips
    surrounding brackets from IPv6 literals (so ``[::1]`` and ``::1``
    compare equal — and so the value matches what
    ``urlparse(...).hostname`` returns), strips any userinfo prefix
    (``user:pass@host``) which CONNECT MUST NOT carry but defensive
    parsers should still drop, lowercases, IDNA-encodes/decodes to
    ASCII (so unicode equivalents are caught).  Returns ``""`` for
    invalid input — callers must treat empty as "no match"
    (fail-closed).

    Without this, ``api.openai.com.``, ``[::1]``, or
    ``user:pass@api.openai.com`` (DNS-equivalent variants) bypass
    the MITM scrubbing path → CONNECT goes passthrough → PII
    forwarded raw to the real upstream.
    """
    if not hostname:
        return ""
    h = hostname.strip()
    # R71-5 fix: strip userinfo prefix (defensive — CONNECT MUST NOT
    # carry it per RFC 9112 §3.2.3, but parsers may receive it).
    if "@" in h:
        h = h.rsplit("@", 1)[1]
    # R71-5 fix: strip IPv6 brackets if both ends are bracketed.
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    # Strip ALL trailing dots (RFC 1034 §3.1 — multiple is invalid but tolerant).
    while h.endswith("."):
        h = h[:-1]
    if not h:
        return ""
    h = h.lower()
    # IPv6 literals contain colons and don't IDNA-encode; only attempt
    # IDNA on names without colons.
    if ":" not in h:
        try:
            h = h.encode("idna").decode("ascii").lower()
        except (UnicodeError, UnicodeDecodeError):
            # Invalid IDNA → fall back to lowercase string; callers
            # already handle non-matches as fail-closed (passthrough),
            # which is the safer side here (worst case: a malformed name
            # bypasses MITM, which is the same as today).
            pass
    return h


def _parse_connect_authority(target: str) -> tuple[str, int]:
    """R71-5 fix: parse a CONNECT target ``host:port`` correctly,
    handling IPv6 bracket notation (``[::1]:443``) and userinfo
    (``user:pass@host:443``).  Returns ``(hostname, port)`` with
    hostname canonicalized via ``_canonicalize_hostname``.

    Default port is 443 (HTTPS, the only thing CONNECT is meant for).
    Raises ``ValueError`` on parse failure or invalid port.
    """
    from urllib.parse import urlsplit
    # Prefix with "//" so urlsplit treats it as authority-only.
    parts = urlsplit("//" + target)
    host = parts.hostname or ""
    port = parts.port if parts.port is not None else 443
    if not host:
        raise ValueError(f"Cannot parse CONNECT authority: {target!r}")
    if not (1 <= port <= 65535):
        raise ValueError(f"Invalid CONNECT port: {port}")
    return _canonicalize_hostname(host), port


def _host_matches_provider(hostname: str, registry: Any) -> bool:
    """Return True if *hostname* matches any registered LLM provider."""
    if registry is None:
        return False
    canon_host = _canonicalize_hostname(hostname)
    if not canon_host:
        return False
    for provider in registry.providers:
        if not getattr(provider, "enabled", True):
            continue
        upstream_url = getattr(provider, "upstream_url", "")
        if upstream_url:
            parsed = urlparse(upstream_url)
            if parsed.hostname and _canonicalize_hostname(parsed.hostname) == canon_host:
                return True
        url_patterns = getattr(provider, "url_patterns", None)
        if not isinstance(url_patterns, (list, tuple)):
            url_patterns = getattr(provider, "_url_patterns", [])
        for pattern in url_patterns:
            # Extract hostname from URL pattern for proper domain matching
            from urllib.parse import urlparse as _urlparse_pat
            try:
                parsed_pat = _urlparse_pat(pattern)
                pat_host = parsed_pat.hostname
                if pat_host and _canonicalize_hostname(pat_host) == canon_host:
                    return True
            except Exception:
                pass
            # Fallback: wildcard patterns like "*githubcopilot.com*" or
            # "*githubcopilot.com/v1/chat/completions"
            clean = pattern.strip("*").lstrip(".").lower()
            # Strip any path component to get just the hostname
            if "/" in clean:
                clean = clean.split("/", 1)[0]
            clean = _canonicalize_hostname(clean) if clean else ""
            if clean and (canon_host == clean or canon_host.endswith("." + clean)):
                return True
    return False


class ForwardProxyServer:
    """Asyncio-based HTTP forward proxy with optional TLS MITM.

    Parameters
    ----------
    host : str
        Interface to bind to.
    port : int
        Port to listen on.
    ca : CertificateAuthority
        CA for generating per-host TLS certificates (MITM).
    registry : Any
        ``ProviderRegistry`` used to match requests to LLM providers.
    pipeline : Any
        ``PipelineEngine`` for PII detection.
    session_store : Any
        ``ConcurrentSessionStore`` for per-session token maps.
    request_scrubber : Any
        ``RequestScrubber`` for scrubbing request bodies.
    response_unscrubber : Any
        ``ResponseUnscrubber`` for unscrubbing response bodies.
    stats : Any
        ``StatsCollector`` (optional).
    event_bus : Any
        Event bus for SSE push to UI (optional).
    recorder : Any
        ``SessionRecorder`` (optional).
    """

    def __init__(
        self,
        *,
        host: str,
        port: int,
        ca: CertificateAuthority,
        registry: Any,
        pipeline: Any,
        session_store: Any,
        request_scrubber: Any,
        response_unscrubber: Any,
        stats: Any = None,
        event_bus: Any = None,
        recorder: Any = None,
        passthrough_log: Any = None,
        passthrough_enabled_ref: Any = None,
        passthrough_storage_file: str | None = None,
        passthrough_capture_bodies_ref: Any = None,
        main_listen_port: int = 8080,
    ) -> None:
        self._host = host
        self._port = port
        self._main_listen_port = main_listen_port
        self._ca = ca
        self._registry = registry
        self._pipeline = pipeline
        self._session_store = session_store
        self._request_scrubber = request_scrubber
        self._response_unscrubber = response_unscrubber
        self._stats = stats
        self._event_bus = event_bus
        self._recorder = recorder
        self._passthrough_log = passthrough_log
        self._passthrough_enabled_ref = passthrough_enabled_ref
        self._passthrough_storage_file = passthrough_storage_file
        # Body-capture is opt-in.  When False (default) the passthrough
        # log records request metadata but NEVER persists raw request /
        # response bodies -- those may contain real PII for unmatched
        # non-LLM traffic, which the design contract says must not be
        # written to disk.
        self._passthrough_capture_bodies_ref = passthrough_capture_bodies_ref

        self._server: asyncio.AbstractServer | None = None
        # Persistent httpx client for upstream requests.
        self._client = httpx.AsyncClient(
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            timeout=httpx.Timeout(120.0),
            follow_redirects=False,
            trust_env=False,  # Don't follow HTTP_PROXY env vars -- would loop back
        )
        # Cache SSLContext per hostname to avoid temp files on every CONNECT.
        # Bounded to prevent unbounded memory growth from many unique hostnames.
        self._ssl_ctx_cache: dict[str, ssl.SSLContext] = {}
        _SSL_CTX_CACHE_MAX = 256
        self._ssl_ctx_cache_max = _SSL_CTX_CACHE_MAX
        # Lock to prevent concurrent cert generation for the same hostname.
        self._ssl_ctx_locks: dict[str, asyncio.Lock] = {}
        self._ssl_ctx_meta_lock = asyncio.Lock()
        # Track active connection tasks for clean shutdown.
        self._connection_tasks: set[asyncio.Task] = set()

    def set_recorder(self, recorder: Any = None) -> None:
        """Swap the live recorder used for future forward-proxy requests."""
        self._recorder = recorder

    def _emit_recording_complete(self, session_id: str, provider_name: str) -> None:
        """Push a recording_complete event to SSE subscribers."""
        if self._event_bus is None:
            return
        import time as _t
        subscribers = getattr(self._event_bus, "subscribers", [])
        event = {
            "type": "recording_complete",
            "session_id": session_id,
            "provider": provider_name,
            "timestamp": _t.time(),
        }
        # R62-2 fix: snapshot subscribers before iterating to avoid
        # silent event drops when SSE handler removes a queue mid-iter.
        for queue in list(subscribers):
            try:
                queue.put_nowait(event)
            except Exception:
                pass

    _PT_BODY_MAX = 64_000

    def _log_passthrough(
        self, *, method: str, path: str, url: str, status: int = 0,
        request_content_type: str = "", response_content_type: str = "",
        request_body: bytes | None = None, response_body: bytes | None = None,
        request_encoding: str | None = None, response_encoding: str | None = None,
        disabled_provider: str | None = None, tunnel: bool = False,
    ) -> None:
        """Append an entry to the in-memory passthrough log and persist to disk."""
        ref = self._passthrough_enabled_ref
        enabled = ref() if callable(ref) else bool(ref) if ref is not None else False
        if not enabled or self._passthrough_log is None:
            return

        entry: dict = {
            "ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds"),
            "method": method,
            "path": path,
            "url": _redact_url_for_log(url),
            "status": status,
            "request_content_type": request_content_type,
            "response_content_type": response_content_type,
        }
        if tunnel:
            entry["tunnel"] = True
        if disabled_provider:
            entry["matched_provider"] = disabled_provider
            entry["provider_disabled"] = True

        # Decompress bodies so the UI shows readable text -- but only
        # when body capture is explicitly enabled.  Defaulting to OFF
        # honours the "real PII never stored on disk" contract for
        # passthrough (unmatched, unscrubbed) traffic.
        capture_ref = self._passthrough_capture_bodies_ref
        capture_bodies = (
            capture_ref() if callable(capture_ref)
            else bool(capture_ref) if capture_ref is not None else False
        )
        if capture_bodies and request_body:
            try:
                decoded = _decompress_body(request_body, request_encoding)
                entry["request_body"] = decoded[:self._PT_BODY_MAX].decode("utf-8", errors="replace")
            except Exception:
                pass
        if capture_bodies and response_body:
            try:
                decoded = _decompress_body(response_body, response_encoding)
                entry["response_body"] = decoded[:self._PT_BODY_MAX].decode("utf-8", errors="replace")
            except Exception:
                pass

        self._passthrough_log.append(entry)

        # Persist to disk so entries survive page refresh / restart.
        if self._passthrough_storage_file:
            try:
                entry_json = json.dumps(entry, separators=(",", ":"))
                asyncio.get_running_loop().call_soon_threadsafe(
                    asyncio.get_running_loop().create_task,
                    asyncio.to_thread(
                        _append_passthrough_entry, self._passthrough_storage_file, entry_json
                    ),
                )
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start accepting connections."""
        self._server = await asyncio.start_server(
            self._on_connection,
            host=self._host,
            port=self._port,
        )
        logger.info("Forward proxy listening on %s:%d", self._host, self._port)

    async def stop(self) -> None:
        """Gracefully shut down the server and httpx client."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        # Cancel all active connection tasks.
        for task in self._connection_tasks:
            task.cancel()
        if self._connection_tasks:
            await asyncio.gather(*self._connection_tasks, return_exceptions=True)
        self._connection_tasks.clear()

        await self._client.aclose()
        logger.info("Forward proxy stopped")

    # ------------------------------------------------------------------
    # Connection handler
    # ------------------------------------------------------------------

    def _on_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Callback for asyncio.start_server -- wraps handler in a tracked task."""
        task = asyncio.create_task(self._handle_connection(reader, writer))
        self._connection_tasks.add(task)
        task.add_done_callback(self._connection_tasks.discard)

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Dispatch an incoming connection based on the HTTP method."""
        peer = writer.get_extra_info("peername")
        try:
            # Read the first request line + headers.
            raw_head, _leftover = await self._read_head(reader)
            if not raw_head:
                logger.debug("Forward proxy: empty request from %s (client disconnected before sending)", peer)
                return

            first_line, _, header_block = raw_head.partition("\r\n")
            if not first_line:
                first_line, _, header_block = raw_head.partition("\n")

            method, target, _version = _parse_request_line(first_line)
            try:
                headers = _parse_headers(header_block)
            except ValueError as exc:
                logger.warning("Forward proxy: bad headers from %s: %s", peer, exc)
                writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return

            logger.info("Forward proxy: %s %s from %s", method, _redact_url_for_log(target), peer)

            if method == "CONNECT":
                # R69-3 + R70-9 fix: in passthrough mode we forward
                # any pre-CONNECT leftover bytes back into the relay
                # via ``reader.feed_data``.  In MITM mode we MUST
                # reject leftover bytes — they can't be valid TLS
                # handshake (TLS starts AFTER our 200 reply) and
                # ``feed_data`` would route them into the post-TLS
                # buffer, where ``_read_head`` would parse them as
                # plaintext HTTP — bypassing the very TLS termination
                # that gives us the request body to scrub.
                # HTTP/1.1 §9.3.6 says clients MUST NOT send body
                # before the 2xx CONNECT response, so rejection is
                # spec-correct.
                # R71-5 fix: parse with the shared helper so IPv6
                # bracket notation and userinfo are normalized
                # consistently with ``_handle_connect`` below.  Falling
                # back to plain target on parse error lets the inner
                # handler emit a proper 400.
                try:
                    hostname_for_dispatch, _port_for_dispatch = _parse_connect_authority(target)
                except Exception:
                    hostname_for_dispatch = ""
                will_mitm = bool(hostname_for_dispatch) and _host_matches_provider(
                    hostname_for_dispatch, self._registry,
                )
                if _leftover:
                    if will_mitm:
                        logger.warning(
                            "Forward proxy CONNECT (MITM): rejecting %d "
                            "leftover bytes sent before 200 response from %s "
                            "(RFC 9112 §9.3.6 violation; would bypass TLS).",
                            len(_leftover), peer,
                        )
                        writer.write(
                            b"HTTP/1.1 400 Bad Request\r\n"
                            b"Connection: close\r\nContent-Length: 0\r\n\r\n"
                        )
                        await writer.drain()
                        return
                    reader.feed_data(_leftover)
                await self._handle_connect(target, headers, reader, writer)
            else:
                await self._handle_http(method, target, headers, reader, writer, _leftover)
        except asyncio.CancelledError:
            logger.debug("Forward proxy: connection cancelled from %s", peer)
        except (ConnectionError, asyncio.IncompleteReadError):
            logger.debug("Forward proxy: client disconnected: %s", peer)
        except Exception:
            logger.exception("Forward proxy: error handling connection from %s", peer)
        finally:
            try:
                # Give the TLS/TCP stack time to transmit any remaining
                # data before tearing down the connection.
                await asyncio.sleep(0.05)
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _read_head(self, reader: asyncio.StreamReader, initial_buf: bytes | None = None) -> tuple[str, bytes]:
        """Read HTTP headers until the blank-line terminator.

        Returns ``(head_str, leftover_bytes)`` where *leftover_bytes* are any
        body bytes that were read past the header terminator.  The caller
        **must** consume leftover before doing further reads on *reader*.

        The total time spent reading the request line + headers is
        capped at :data:`_HEADER_READ_TIMEOUT_S` so a slow-loris client
        cannot keep a connection task alive indefinitely by dripping
        bytes below the size cap.
        """
        buf = initial_buf or b""
        parsed = _split_head_from_buffer(buf)
        if parsed is not None:
            return parsed
        deadline = asyncio.get_event_loop().time() + _HEADER_READ_TIMEOUT_S
        while True:
            remaining = _MAX_HEADER_SIZE - len(buf)
            if remaining <= 0:
                return "", b""
            time_left = deadline - asyncio.get_event_loop().time()
            if time_left <= 0:
                logger.debug(
                    "Forward proxy: header read timed out after %ds (slow-loris guard)",
                    _HEADER_READ_TIMEOUT_S,
                )
                return "", b""
            try:
                chunk = await asyncio.wait_for(reader.read(remaining), timeout=time_left)
            except asyncio.TimeoutError:
                logger.debug(
                    "Forward proxy: header read timed out after %ds (slow-loris guard)",
                    _HEADER_READ_TIMEOUT_S,
                )
                return "", b""
            if not chunk:
                return "", b""
            buf += chunk
            parsed = _split_head_from_buffer(buf)
            if parsed is not None:
                return parsed

    # ------------------------------------------------------------------
    # CONNECT handler (HTTPS proxy)
    # ------------------------------------------------------------------

    async def _handle_connect(
        self,
        target: str,
        headers: dict[str, str],
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        """Handle an HTTP CONNECT request.

        If the destination matches a known LLM provider, perform TLS MITM
        to enable scrubbing.  Otherwise tunnel bytes transparently.
        """
        # Parse host:port from CONNECT target via shared helper that
        # handles IPv6 brackets and userinfo (R71-5).  On parse
        # failure, send 400 and bail.
        try:
            hostname, port = _parse_connect_authority(target)
        except ValueError as exc:
            logger.warning("Forward proxy CONNECT: bad target %r: %s", _redact_url_for_log(target), exc)
            client_writer.write(
                b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            )
            await client_writer.drain()
            return

        # Send 200 only after we know we can reach the upstream for passthrough,
        # or immediately for MITM (which handles its own connection).
        if _host_matches_provider(hostname, self._registry):
            # MITM path: send 200 immediately, then start TLS handshake
            client_writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await client_writer.drain()
            logger.info("Forward proxy CONNECT: MITM tunnel to %s:%d", hostname, port)
            await self._mitm_tunnel(hostname, port, client_reader, client_writer)
        else:
            # Passthrough path: connect upstream first, then send 200
            logger.info("Forward proxy CONNECT: transparent tunnel to %s:%d (no provider match)", hostname, port)
            await self._passthrough_tunnel(hostname, port, client_reader, client_writer)

    async def _passthrough_tunnel(
        self,
        hostname: str,
        port: int,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        """Relay bytes bidirectionally without inspection."""
        try:
            connect_targets = await _resolve_public_endpoints(hostname, port)
        except PermissionError as exc:
            logger.warning(
                "Forward proxy passthrough: blocked connection to %s:%d (%s)",
                hostname,
                port,
                exc,
            )
            client_writer.write(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            await client_writer.drain()
            return
        except OSError:
            logger.warning("Forward proxy passthrough: DNS resolution failed for %s:%d", hostname, port)
            client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            await client_writer.drain()
            return

        upstream_reader = upstream_writer = None
        last_exc: Exception | None = None
        for connect_host, connect_port in connect_targets:
            try:
                # Connect to a validated IP directly to prevent TOCTOU DNS rebinding.
                # R62-1/R62-7 fix: bound the TCP connect phase with
                # ``asyncio.wait_for`` so a SYN-blackhole target can't
                # block the coroutine for the full OS TCP timeout
                # (75-120s on Linux, ~21s on Windows).  Many concurrent
                # CONNECTs to blackhole IPs would otherwise exhaust
                # asyncio tasks and file descriptors.  30s covers
                # legitimate slow upstreams while bounding worst-case
                # blocking per resolved target.
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    asyncio.open_connection(connect_host, connect_port),
                    timeout=_CONNECT_TIMEOUT_S,
                )
                break
            except (Exception, asyncio.TimeoutError) as exc:
                last_exc = exc

        if upstream_reader is None or upstream_writer is None:
            if last_exc is not None:
                logger.warning(
                    "Forward proxy passthrough: cannot connect to %s:%d (%s)",
                    hostname,
                    port,
                    last_exc,
                )
            else:
                logger.warning("Forward proxy passthrough: cannot connect to %s:%d", hostname, port)
            client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            await client_writer.drain()
            return

        # Send 200 only after upstream connection succeeded
        client_writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await client_writer.drain()

        logger.info("Forward proxy passthrough: connected to %s:%d -- relaying", hostname, port)
        self._log_passthrough(
            method="CONNECT", path=f"{hostname}:{port}", url=f"https://{hostname}:{port}",
            tunnel=True,
        )

        async def _relay(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
            try:
                while True:
                    try:
                        data = await asyncio.wait_for(
                            src.read(_TUNNEL_BUF_SIZE),
                            timeout=_TUNNEL_IDLE_TIMEOUT_S,
                        )
                    except asyncio.TimeoutError:
                        # Idle tunnel: a slowloris-style attacker can hold
                        # many CONNECT tunnels open by sending one byte
                        # every few minutes.  Close the idle side so the
                        # other relay task also exits.
                        logger.debug(
                            "CONNECT tunnel idle for %ds -- closing",
                            _TUNNEL_IDLE_TIMEOUT_S,
                        )
                        break
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except (ConnectionError, asyncio.CancelledError):
                pass

        t1 = asyncio.create_task(_relay(client_reader, upstream_writer))
        t2 = asyncio.create_task(_relay(upstream_reader, client_writer))
        try:
            # Wait for EITHER direction to close, then cancel the other.
            done, pending = await asyncio.wait(
                {t1, t2}, return_when=asyncio.FIRST_COMPLETED,
            )
            for t in pending:
                t.cancel()
            # Await pending tasks so they can clean up.
            if pending:
                await asyncio.wait(pending)
        except asyncio.CancelledError:
            t1.cancel()
            t2.cancel()
            await asyncio.gather(t1, t2, return_exceptions=True)
            raise
        finally:
            try:
                upstream_writer.close()
                await upstream_writer.wait_closed()
            except Exception:
                pass

    def _build_ssl_ctx(self, hostname: str) -> ssl.SSLContext:
        """Build an SSLContext for *hostname* (CPU-intensive, runs in thread)."""
        host_pair = self._ca.get_host_cert(hostname)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        cert_fd, cert_path = tempfile.mkstemp(suffix=".pem")
        key_fd, key_path = tempfile.mkstemp(suffix=".pem")
        # Track whether fdopen consumed each FD
        cert_fd_owned = True
        key_fd_owned = True
        try:
            with os.fdopen(cert_fd, "wb") as cert_f:
                cert_fd_owned = False  # fdopen takes ownership
                cert_f.write(host_pair.cert_pem)
            with os.fdopen(key_fd, "wb") as key_f:
                key_fd_owned = False
                key_f.write(host_pair.key_pem)
            try:
                os.chmod(key_path, 0o600)
            except OSError:
                pass
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        finally:
            # Close any FDs not consumed by fdopen
            if cert_fd_owned:
                try:
                    os.close(cert_fd)
                except OSError:
                    pass
            if key_fd_owned:
                try:
                    os.close(key_fd)
                except OSError:
                    pass
            try:
                os.unlink(cert_path)
            except OSError:
                pass
            try:
                os.unlink(key_path)
            except OSError:
                pass

        return ctx

    async def _get_or_create_ssl_ctx(self, hostname: str) -> ssl.SSLContext:
        """Return a cached SSLContext for *hostname*, creating one if needed.

        Cert generation (RSA key + signing) is offloaded to a thread so
        the event loop is never blocked.  Uses per-hostname locking to
        prevent duplicate cert generation and an LRU eviction policy.

        R71-6 fix: canonicalize ``hostname`` (lowercase, strip
        trailing dot, IDNA, strip brackets) before cache + lock
        lookup so case/dot/bracket variants share one entry — both
        avoiding cache fragmentation and preventing an adversary from
        DoS-ing the cert builder via N case permutations of the same
        hostname.  Also keeps R70-10's "skip held lock" dedup
        effective.
        """
        hostname = _canonicalize_hostname(hostname) or hostname
        if hostname in self._ssl_ctx_cache:
            return self._ssl_ctx_cache[hostname]

        # Get or create a per-hostname lock to serialize cert generation
        async with self._ssl_ctx_meta_lock:
            if hostname not in self._ssl_ctx_locks:
                self._ssl_ctx_locks[hostname] = asyncio.Lock()
            lock = self._ssl_ctx_locks[hostname]

        async with lock:
            # Double-check after acquiring lock
            if hostname in self._ssl_ctx_cache:
                return self._ssl_ctx_cache[hostname]

            ctx = await asyncio.to_thread(self._build_ssl_ctx, hostname)

            # Evict oldest entries if cache is full.
            # R54-2 fix: pop the per-host lock BEFORE deleting from
            # the cache (mirrors R53-6 in cert/ca.py).  Otherwise a
            # concurrent ``_get_or_create_ssl_ctx(oldest)`` could see
            # cache-miss + lock-still-present and acquire the
            # about-to-be-orphaned lock; once we then pop it, a third
            # task creates a NEW lock and both end up building the
            # same hostname's SSL context concurrently.
            # R70-10 fix: skip eviction of any oldest entry whose
            # per-host lock is currently held by another task.  If we
            # popped a held lock, a fresh request for the same
            # hostname would create a NEW lock and run a duplicate
            # cert build concurrent with the in-flight one.
            attempts = 0
            while len(self._ssl_ctx_cache) >= self._ssl_ctx_cache_max:
                attempts += 1
                if attempts > self._ssl_ctx_cache_max:
                    # All entries are held — break to avoid an
                    # infinite loop.  Cache may transiently exceed
                    # capacity by 1 until a holder releases.
                    break
                oldest = next(iter(self._ssl_ctx_cache))
                oldest_lock = self._ssl_ctx_locks.get(oldest)
                if oldest_lock is not None and oldest_lock.locked():
                    # Bump it to most-recent so we try a different
                    # entry next iteration.  Plain ``dict`` doesn't
                    # have ``move_to_end``; pop + re-insert achieves
                    # the same insertion-order shuffle.
                    self._ssl_ctx_cache[oldest] = self._ssl_ctx_cache.pop(oldest)
                    continue
                self._ssl_ctx_locks.pop(oldest, None)
                del self._ssl_ctx_cache[oldest]

            self._ssl_ctx_cache[hostname] = ctx
            return ctx

    async def _mitm_tunnel(
        self,
        hostname: str,
        port: int,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        """Perform TLS MITM: present a fake cert to the client, decrypt,
        scrub, and forward to the real upstream over TLS."""
        logger.info("Forward proxy MITM: intercepting TLS for %s:%d", hostname, port)

        server_ctx = await self._get_or_create_ssl_ctx(hostname)

        # Upgrade the client connection to TLS.
        transport = client_writer.transport
        protocol = transport.get_protocol()

        loop = asyncio.get_running_loop()
        try:
            # R63-2 fix: bound the TLS handshake with the same
            # timeout used for TCP connect (R62-1).  Without this a
            # slowloris client that opens CONNECT but never sends
            # TLS ClientHello holds the asyncio task indefinitely.
            new_transport = await asyncio.wait_for(
                loop.start_tls(
                    transport, protocol, server_ctx, server_side=True,
                ),
                timeout=_CONNECT_TIMEOUT_S,
            )
        except (ssl.SSLError, ConnectionError, asyncio.TimeoutError) as exc:
            logger.warning(
                "TLS handshake failed for MITM with %s: %s %s -- "
                "client may not trust the Scruxy CA cert at %s "
                "(for VS Code / Node.js clients, set "
                "NODE_EXTRA_CA_CERTS=%s)",
                hostname,
                type(exc).__name__,
                exc,
                self._ca.ca_cert_path,
                self._ca.ca_cert_path,
            )
            self._log_passthrough(
                method="CONNECT", path=f"{hostname}:{port}",
                url=f"https://{hostname}:{port}",
                tunnel=True,
            )
            return
        except Exception as exc:
            # WinError 64 ("network name no longer available") and timeout
            # errors are common on Windows when clients open parallel CONNECT
            # tunnels and drop some before the TLS handshake completes.
            # Log at debug to avoid noise.
            exc_str = str(exc)
            if "WinError 64" in exc_str or "taking longer than" in exc_str:
                logger.debug("TLS handshake dropped for %s: %s", hostname, exc)
            else:
                logger.warning(
                    "TLS handshake failed for MITM with %s: %s(%s)",
                    hostname,
                    type(exc).__name__,
                    exc,
                )
            self._log_passthrough(
                method="CONNECT", path=f"{hostname}:{port}",
                url=f"https://{hostname}:{port}",
                tunnel=True,
            )
            return

        # Rewire reader/writer to use the TLS transport.
        client_writer._transport = new_transport  # type: ignore[attr-defined]

        # Now handle HTTP requests over the decrypted connection.
        # We loop to support HTTP keep-alive within the tunnel.
        # Carry forward unread bytes across loop iterations.
        _carry_buf: bytes = b""
        try:
            while True:
                raw_head, leftover = await self._read_head(client_reader, _carry_buf or None)
                _carry_buf = b""  # Reset -- consumed by _read_head
                if not raw_head:
                    break

                first_line, _, header_block = raw_head.partition("\r\n")
                if not first_line:
                    first_line, _, header_block = raw_head.partition("\n")

                method, path, _version = _parse_request_line(first_line)
                try:
                    req_headers = _parse_headers(header_block)
                except ValueError as exc:
                    logger.warning("MITM: bad headers: %s", exc)
                    client_writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                    await client_writer.drain()
                    return

                # Reconstruct the full URL.
                url = f"https://{hostname}:{port}{path}" if port != 443 else f"https://{hostname}{path}"

                # Read body via Content-Length or chunked TE.
                body: bytes | None = None
                te = (req_headers.get("transfer-encoding") or "").lower()
                content_length = req_headers.get("content-length")

                # R70-2 fix: token-equality on the LAST coding only.
                # ``"chunked" in te`` previously matched ``"not-chunked"``,
                # ``"xchunked"``, ``"chunked-foo"`` etc.  Per RFC 9112
                # §6.1 chunked MUST be the outermost (final) coding
                # when present; differential parsing between Scruxy
                # and the upstream is the classic CL/TE smuggling
                # primitive.
                te_codings = [c.strip().lower() for c in te.split(",") if c.strip()]
                if te_codings and te_codings[-1] == "chunked":
                    try:
                        _deadline = asyncio.get_event_loop().time() + _BODY_READ_TIMEOUT_S
                        body, _carry_buf = await _read_chunked_body(
                            client_reader, leftover, deadline=_deadline,
                        )
                    except asyncio.TimeoutError:
                        logger.warning(
                            "MITM: chunked body read timed out after %ds; closing",
                            _BODY_READ_TIMEOUT_S,
                        )
                        client_writer.write(
                            b"HTTP/1.1 408 Request Timeout\r\n"
                            b"Connection: close\r\nContent-Length: 0\r\n\r\n"
                        )
                        await client_writer.drain()
                        return
                    except ValueError as exc:
                        logger.warning("MITM: chunked body error: %s", exc)
                        client_writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                        await client_writer.drain()
                        return
                elif content_length:
                    # R71-1 fix: ``int(content_length)`` accepts ``+5``,
                    # ``  5  ``, ``5_000`` (Python 3.6+) and Unicode
                    # digits.  Per RFC 9112 §8.6 Content-Length =
                    # 1*DIGIT (ASCII 0-9 only).  Strict regex first.
                    try:
                        if not re.fullmatch(r"[0-9]+", content_length):
                            raise ValueError("Content-Length must be ASCII digits")
                        cl = int(content_length)
                    except ValueError:
                        logger.warning("Invalid Content-Length: %r; sending 400", content_length)
                        client_writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                        await client_writer.drain()
                        return
                    if cl < 0:
                        logger.warning("Negative Content-Length: %d; sending 400", cl)
                        client_writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                        await client_writer.drain()
                        return
                    if cl > _MAX_BODY_SIZE:
                        logger.warning("Content-Length %d exceeds max body size; sending 413", cl)
                        client_writer.write(b"HTTP/1.1 413 Payload Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                        await client_writer.drain()
                        return
                    elif cl > 0:
                        if len(leftover) >= cl:
                            body = leftover[:cl]
                            _carry_buf = leftover[cl:]  # Carry forward for next request
                        else:
                            remaining = cl - len(leftover)
                            try:
                                body = leftover + await asyncio.wait_for(
                                    client_reader.readexactly(remaining),
                                    timeout=_BODY_READ_TIMEOUT_S,
                                )
                            except asyncio.TimeoutError:
                                logger.warning(
                                    "Forward proxy MITM: body read timed out after %ds; closing",
                                    _BODY_READ_TIMEOUT_S,
                                )
                                client_writer.write(
                                    b"HTTP/1.1 408 Request Timeout\r\n"
                                    b"Connection: close\r\nContent-Length: 0\r\n\r\n"
                                )
                                await client_writer.drain()
                                return
                            _carry_buf = b""
                    else:
                        # R63-1 fix: Content-Length: 0 — no body, but the
                        # leftover may still contain bytes from a pipelined
                        # next request that must be carried forward.
                        _carry_buf = leftover
                else:
                    # R63-1 fix: no Content-Length AND no Transfer-Encoding
                    # = bodiless request (e.g. GET).  Same carry-forward
                    # requirement as the CL=0 case above — leftover may
                    # be the start of the next pipelined request.
                    _carry_buf = leftover

                # Decompress request body so JSON parsing / scrubbing works,
                # but keep the ORIGINAL raw_body / raw_headers so any
                # passthrough (no provider match) preserves the wire-level
                # bytes (e.g. HMAC signatures over compressed payloads).
                # On a compression-bomb (DecompressLimitExceeded), we
                # *intentionally* skip decompression rather than 413: a
                # non-provider passthrough request with a huge expanded
                # body should still flow through transparently.  For
                # matched providers, scrubbing of compressed bytes will
                # simply not extract structured fields -- preferable to
                # blocking a legitimate request whose decompressed size
                # exceeds our scrub budget.
                req_content_encoding = (
                    req_headers.get("content-encoding")
                )
                raw_body_for_passthrough = body
                raw_headers_for_passthrough = req_headers
                _decompress_failed = False
                if body and req_content_encoding:
                    try:
                        decompressed = _decompress_body(body, req_content_encoding)
                    except DecompressLimitExceeded:
                        logger.warning(
                            "Forward proxy MITM: %s body would exceed decompress limit; "
                            "leaving compressed (passthrough) / fail-closed for matched providers",
                            req_content_encoding,
                        )
                        decompressed = body
                        _decompress_failed = True
                    if decompressed is not body:
                        # Decompression succeeded -- use decompressed body and
                        # remove Content-Encoding so downstream sees plain text.
                        body = decompressed
                        req_headers = {
                            k: v for k, v in req_headers.items()
                            if k.lower() != "content-encoding"
                        }
                    else:
                        # Lenient decompression returned the input unchanged.
                        # If the declared encoding isn't a known no-op, the
                        # body could not actually be decoded -- flag it so
                        # matched providers fail closed (rather than
                        # forwarding e.g. zstd-encoded PII unscrubbed).
                        enc_norm = (req_content_encoding or "").lower().strip()
                        if enc_norm and enc_norm != "identity" and not _decompress_failed:
                            logger.warning(
                                "Forward proxy MITM: unsupported Content-Encoding %r; "
                                "matched providers will fail closed",
                                req_content_encoding,
                            )
                            _decompress_failed = True

                logger.info("Forward proxy MITM inner: %s %s (body=%d bytes)",
                            method, _redact_url_for_log(url), len(body) if body else 0)

                # Process through scrubbing pipeline.
                resp_status, resp_headers, resp_body = await self._scrub_and_forward(
                    method=method,
                    url=url,
                    headers=req_headers,
                    body=body,
                    client_writer=client_writer,
                    raw_body=raw_body_for_passthrough,
                    raw_headers=raw_headers_for_passthrough,
                    decompress_failed=_decompress_failed,
                )

                if resp_status < 0:
                    # SSE was streamed directly via client_writer.
                    # Ensure all data is flushed before closing the connection.
                    await client_writer.drain()
                    break

                # Write HTTP response back to client over TLS.
                status_line = _status_line(resp_status)
                # Sanitize header values to prevent CRLF injection
                header_lines = "".join(
                    f"{k}: {v.replace(chr(13), '').replace(chr(10), '')}\r\n"
                    for k, v in resp_headers.items()
                )
                resp_bytes = resp_body or b""
                response_raw = (
                    f"{status_line}{header_lines}"
                    f"Content-Length: {len(resp_bytes)}\r\n"
                    f"\r\n"
                ).encode("latin-1") + resp_bytes

                client_writer.write(response_raw)
                await client_writer.drain()

        except (ConnectionError, asyncio.IncompleteReadError):
            logger.debug("MITM session closed for %s:%d (client disconnected)", hostname, port)
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.warning("MITM session error for %s:%d", hostname, port, exc_info=True)

    # ------------------------------------------------------------------
    # Plain HTTP forward-proxy handler
    # ------------------------------------------------------------------

    async def _handle_http(
        self,
        method: str,
        target: str,
        headers: dict[str, str],
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        leftover: bytes = b"",
    ) -> None:
        """Handle a plain HTTP forward-proxy request (absolute-form URL)."""
        # Reconstruct full URL if the client sent origin-form (relative path).
        # Some clients send "GET / HTTP/1.1" with a Host header instead of
        # the absolute-form "GET http://host/ HTTP/1.1" that proxies expect.
        url = target
        if not url.startswith("http://") and not url.startswith("https://"):
            # R71-Op47-7 fix: removed duplicate ``headers.get("host")``
            # — both branches were identical.  Headers are normalized to
            # lowercase keys at parse time, so a single lookup suffices.
            host = headers.get("host") or ""
            if host:
                url = f"http://{host}{target}"
            else:
                # No host header and relative URL -- cannot route this request
                logger.warning("Forward proxy: relative URL %r with no Host header -- rejecting", _redact_url_for_log(target))
                error_resp = (
                    b"HTTP/1.1 400 Bad Request\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: 44\r\n"
                    b"\r\n"
                    b"Bad Request: missing Host header for proxy\r\n"
                )
                writer.write(error_resp)
                await writer.drain()
                return

        logger.info("Forward proxy HTTP request: %s %s", method, _redact_url_for_log(url))
        # Read body via Content-Length or chunked TE.
        body: bytes | None = None
        te = (headers.get("transfer-encoding") or "").lower()
        content_length = headers.get("content-length")

        # R70-2 fix: token-equality on the LAST coding only.
        te_codings = [c.strip().lower() for c in te.split(",") if c.strip()]
        if te_codings and te_codings[-1] == "chunked":
            try:
                _deadline = asyncio.get_event_loop().time() + _BODY_READ_TIMEOUT_S
                body, _ = await _read_chunked_body(reader, leftover, deadline=_deadline)
            except asyncio.TimeoutError:
                logger.warning(
                    "Forward proxy HTTP: chunked body read timed out after %ds; closing",
                    _BODY_READ_TIMEOUT_S,
                )
                writer.write(
                    b"HTTP/1.1 408 Request Timeout\r\n"
                    b"Connection: close\r\nContent-Length: 0\r\n\r\n"
                )
                await writer.drain()
                return
            except ValueError as exc:
                logger.warning("Forward proxy HTTP: chunked body error: %s", exc)
                writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return
        elif content_length:
            # R71-1 fix: strict ASCII-digit validation per RFC 9112 §8.6.
            try:
                if not re.fullmatch(r"[0-9]+", content_length):
                    raise ValueError("Content-Length must be ASCII digits")
                cl = int(content_length)
            except ValueError:
                logger.warning("Invalid Content-Length: %r; sending 400", content_length)
                writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return
            if cl < 0:
                logger.warning("Negative Content-Length: %d; sending 400", cl)
                writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return
            if cl > _MAX_BODY_SIZE:
                logger.warning("Content-Length %d exceeds max body size; sending 413", cl)
                writer.write(b"HTTP/1.1 413 Payload Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return
            if cl > 0:
                if len(leftover) >= cl:
                    body = leftover[:cl]
                else:
                    remaining = cl - len(leftover)
                    try:
                        body = leftover + await asyncio.wait_for(
                            reader.readexactly(remaining),
                            timeout=_BODY_READ_TIMEOUT_S,
                        )
                    except asyncio.TimeoutError:
                        logger.warning(
                            "Forward proxy: body read timed out after %ds; closing",
                            _BODY_READ_TIMEOUT_S,
                        )
                        writer.write(
                            b"HTTP/1.1 408 Request Timeout\r\n"
                            b"Connection: close\r\nContent-Length: 0\r\n\r\n"
                        )
                        await writer.drain()
                        return

        # Decompress request body so JSON parsing / scrubbing works,
        # but keep the ORIGINAL raw_body / raw_headers so any
        # passthrough (no provider match) preserves the wire-level bytes.
        # On a compression-bomb, fall back to forwarding the still-compressed
        # bytes rather than 413: non-provider passthrough should work,
        # and matched providers will simply skip scrubbing the body.
        req_content_encoding = (
            headers.get("content-encoding")
        )
        raw_body_for_passthrough = body
        raw_headers_for_passthrough = headers
        _decompress_failed = False
        if body and req_content_encoding:
            try:
                decompressed = _decompress_body(body, req_content_encoding)
            except DecompressLimitExceeded:
                logger.warning(
                    "Forward proxy: %s body would exceed decompress limit; "
                    "leaving compressed (passthrough) / fail-closed for matched providers",
                    req_content_encoding,
                )
                decompressed = body
                _decompress_failed = True
            if decompressed is not body:
                body = decompressed
                headers = {k: v for k, v in headers.items() if k.lower() != "content-encoding"}
            else:
                # Lenient decompression returned the input unchanged.  If
                # the declared encoding isn't a no-op, fail closed for
                # matched providers -- see _mitm_inner for the rationale.
                enc_norm = (req_content_encoding or "").lower().strip()
                if enc_norm and enc_norm != "identity" and not _decompress_failed:
                    logger.warning(
                        "Forward proxy: unsupported Content-Encoding %r; "
                        "matched providers will fail closed",
                        req_content_encoding,
                    )
                    _decompress_failed = True

        resp_status, resp_headers, resp_body = await self._scrub_and_forward(
            method=method,
            url=url,
            headers=headers,
            body=body,
            client_writer=writer,
            raw_body=raw_body_for_passthrough,
            raw_headers=raw_headers_for_passthrough,
            decompress_failed=_decompress_failed,
        )

        if resp_status < 0:
            # SSE was streamed directly.
            await writer.drain()
            return

        # Write response back to client.
        status_line = _status_line(resp_status)
        # Sanitize header values to prevent CRLF injection
        header_lines = "".join(
            f"{k}: {v.replace(chr(13), '').replace(chr(10), '')}\r\n"
            for k, v in resp_headers.items()
        )
        resp_bytes = resp_body or b""
        response_raw = (
            f"{status_line}{header_lines}"
            f"Content-Length: {len(resp_bytes)}\r\n"
            f"\r\n"
        ).encode("latin-1") + resp_bytes

        writer.write(response_raw)
        await writer.drain()

    # ------------------------------------------------------------------
    # Core: scrub → forward → unscrub
    # ------------------------------------------------------------------

    async def _scrub_and_forward(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        client_writer: asyncio.StreamWriter | None = None,
        raw_body: bytes | None = None,
        raw_headers: dict[str, str] | None = None,
        decompress_failed: bool = False,
    ) -> tuple[int, dict[str, str], bytes]:
        """Run the scrubbing pipeline, forward to upstream, unscrub response.

        ``body`` and ``headers`` are the decoded (post-decompress) view used
        for provider matching and scrubbing.  ``raw_body`` and ``raw_headers``
        -- when provided -- preserve the original bytes / Content-Encoding so
        passthrough requests (no provider match, or local reverse-proxy
        target) are forwarded byte-identical, preserving HMAC signatures
        and other integrity guarantees on the original payload.

        Returns ``(status_code, response_headers, response_body)``.
        When SSE streaming is detected and *client_writer* is provided the
        response is written directly to *client_writer* and ``(-1, {}, b"")``
        is returned as a sentinel (caller should break the keep-alive loop).
        """
        from scruxy.providers.base import ProxyRequest as ProviderProxyRequest
        recorder = self._recorder

        # Default raw_* to the decoded body/headers for backwards compat.
        passthrough_body = raw_body if raw_body is not None else body
        passthrough_headers = raw_headers if raw_headers is not None else headers

        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        # R60-4 / R61-2 / R62-3 fix: reject paths containing ``..`` or
        # ``.`` segments BEFORE provider matching.  Iterate ``unquote``
        # until idempotent so multi-encoded variants are caught.
        # R63-6 fix: if the loop bound is reached without converging,
        # FAIL CLOSED — a path with >8 encoding layers is overwhelmingly
        # an attacker probing for traversal bypass.
        from urllib.parse import unquote as _unquote
        _decoded_path = parsed.path or "/"
        _converged = False
        for _ in range(8):
            _next = _unquote(_decoded_path)
            if _next == _decoded_path:
                _converged = True
                break
            _decoded_path = _next
        if not _converged:
            logger.warning(
                "Forward proxy: path encoding did not converge in 8 "
                "rounds (decoded_len=%d) -- 400 fail-closed",
                len(_decoded_path),
            )
            if client_writer is not None:
                client_writer.write(
                    b"HTTP/1.1 400 Bad Request\r\n"
                    b"Connection: close\r\nContent-Length: 0\r\n\r\n"
                )
                try:
                    await client_writer.drain()
                except Exception:
                    pass
                return (-1, {}, b"")
            return (400, {}, b"")
        # Re-split the decoded path on both ``/`` and ``\`` since
        # some clients/servers also normalize backslashes on Windows.
        _path_segments = _decoded_path.replace("\\", "/").split("/")
        if ".." in _path_segments or "." in _path_segments:
            logger.warning(
                "Forward proxy: rejecting path with traversal segments "
                "(decoded_len=%d) -- 400", len(_decoded_path),
            )
            if client_writer is not None:
                client_writer.write(
                    b"HTTP/1.1 400 Bad Request\r\n"
                    b"Connection: close\r\nContent-Length: 0\r\n\r\n"
                )
                try:
                    await client_writer.drain()
                except Exception:
                    pass
                return (-1, {}, b"")
            return (400, {}, b"")

        # Build a ProxyRequest compatible with the provider registry.
        body_json: dict | None = None
        if body:
            try:
                parsed_json = json.loads(body)
                if isinstance(parsed_json, dict):
                    body_json = parsed_json
            except (ValueError, TypeError):
                pass

        proxy_req = ProviderProxyRequest(
            method=method,
            url=url,
            headers=headers,
            body=body_json,
        )

        # If the target is the local reverse proxy, skip provider matching
        # and forward as-is.  The reverse proxy will handle scrubbing.
        _local_hosts = {"localhost", "127.0.0.1", "::1", "[::1]"}
        if (
            parsed.hostname
            and parsed.hostname.lower() in _local_hosts
            and (parsed.port or 80) == self._main_listen_port
        ):
            if _is_blocked_local_admin_path(parsed.path or "/"):
                logger.warning(
                    "Forward proxy: blocked local admin/UI path via passthrough: %s",
                    _redact_url_for_log(url),
                )
                return 403, {"Content-Type": "text/plain"}, b"Forbidden: local admin path"
            logger.debug(
                "Forward proxy: target is local reverse proxy (%s) -- passthrough",
                _redact_url_for_log(url),
            )
            return await self._plain_forward(
                method, url, passthrough_headers, passthrough_body,
                allow_private_target=True,
                client_writer=client_writer,
            )

        # Match provider.
        provider = self._registry.match(proxy_req) if self._registry else None

        if provider is None:
            # Check if a disabled provider would have matched.
            disabled_match = self._registry.match_disabled(proxy_req) if self._registry else None
            if disabled_match is not None:
                logger.info(
                    "Forward proxy: provider '%s' matched %s %s but is DISABLED -- passthrough",
                    disabled_match.name,
                    method,
                    _redact_url_for_log(url),
                )
            # No provider match -- forward without scrubbing using the
            # ORIGINAL raw bytes/headers so passthrough preserves
            # Content-Encoding, HMAC signatures, and any other integrity
            # guarantees on the wire format.
            return await self._plain_forward(
                method, url, passthrough_headers, passthrough_body,
                disabled_provider=disabled_match,
                client_writer=client_writer,
            )

        logger.info(
            "Forward proxy matched provider '%s' for %s %s",
            provider.name,
            method,
            _redact_url_for_log(url),
        )

        # Fail-closed: a matched provider whose request body could not be
        # safely decompressed must not be forwarded uninspected.  Otherwise
        # a client could bypass scrubbing by submitting a compression-bomb
        # request that the upstream still accepts.  Return 413 to the client.
        if decompress_failed and body:
            logger.warning(
                "Forward proxy: provider '%s' matched but request body could "
                "not be decompressed within budget -- failing closed (413).",
                provider.name,
            )
            if client_writer is not None:
                client_writer.write(
                    b"HTTP/1.1 413 Payload Too Large\r\n"
                    b"Connection: close\r\nContent-Length: 0\r\n\r\n"
                )
                try:
                    await client_writer.drain()
                except Exception:
                    pass
                return (-1, {}, b"")
            return (413, {}, b"")

        # Extract session ID and get token map.
        session_id = provider.extract_session_id(proxy_req)
        token_map = None
        token_map_error: Exception | None = None
        if self._session_store is not None:
            try:
                token_map = await self._session_store.get_or_create_session(session_id)
            except Exception as exc:
                token_map_error = exc
                logger.exception(
                    "Forward proxy: provider '%s' matched but session store "
                    "failed to provide a token map (session=%s)",
                    provider.name, session_id,
                )

        # Fail-closed: if a provider matched and we have a body OR a
        # query string that would normally be scrubbed but the session
        # store could not supply a token map (transient SQLite error,
        # disk full, corrupted DB, …), refuse to forward rather than
        # smuggling raw PII to the upstream LLM.  E1 r51 residual #3:
        # the original gate was body-only, so a bodyless GET with PII
        # in the query string would still forward unscrubbed.
        if (
            self._session_store is not None
            and token_map is None
            and self._request_scrubber is not None
            and self._pipeline is not None
            and (body_json is not None or "?" in url)
        ):
            logger.error(
                "Forward proxy: provider '%s' matched and request needs "
                "scrubbing but token map is unavailable (%s) -- failing "
                "closed (503).",
                provider.name,
                token_map_error if token_map_error else "no token map",
            )
            if client_writer is not None:
                client_writer.write(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Connection: close\r\nContent-Length: 0\r\n\r\n"
                )
                try:
                    await client_writer.drain()
                except Exception:
                    pass
                return (-1, {}, b"")
            return (503, {}, b"")

        response_token_map = await resolve_response_token_map(
            self._session_store,
            session_id,
            token_map,
        )

        # Scrub request body.
        import time as _time_mod
        # Fail-closed (B1): Round-47's A4/A5 only covered the
        # decompression-failure subcase.  Here we additionally cover
        # the case where decompression succeeded (or wasn't needed) but
        # the body could not be parsed as a JSON object -- without this
        # check, a non-JSON POST to a matched LLM endpoint would skip
        # scrubbing entirely and forward raw PII to the upstream.
        if (
            body
            and body_json is None
            and self._request_scrubber is not None
            and self._pipeline is not None
        ):
            logger.warning(
                "Forward proxy: provider '%s' matched but body is not valid JSON -- failing closed (415).",
                provider.name,
            )
            if client_writer is not None:
                client_writer.write(
                    b"HTTP/1.1 415 Unsupported Media Type\r\n"
                    b"Connection: close\r\nContent-Length: 0\r\n\r\n"
                )
                try:
                    await client_writer.drain()
                except Exception:
                    pass
                return (-1, {}, b"")
            return (415, {}, b"")

        _request_start = _time_mod.perf_counter()
        scrubbed_body = body
        scrubbed_dict_for_recording: dict | None = None
        pii_count = 0
        _scrub_ms = 0.0
        entities: list = []
        pipeline_breakdown: list[dict] | None = None
        request_id = str(uuid.uuid4())
        # E1 residual fix: scrub URL query string BEFORE the body
        # branch so bodyless or non-JSON matched requests still get
        # their query string scrubbed.  The query string is forwarded
        # upstream by `_resolve_upstream_url`, so leaving it raw on
        # a matched provider would leak PII regardless of body.
        # F2 fix: also tag/absorb any PII detected in the query so
        # the response unscrubber can reverse it.
        query_pii: set[str] = set()
        if (
            self._pipeline is not None
            and token_map is not None
            and "?" in url
        ):
            from scruxy.proxy.routes import _scrub_url_query
            scrubbed_url, query_pii = await _scrub_url_query(
                url, self._pipeline, token_map, request_id,
            )
            if scrubbed_url != url:
                url = scrubbed_url
                # R53-1 fix: `path` was computed from the unscrubbed URL
                # at the top of this function and is later passed to
                # `recorder.record_request(path=...)`.  Recompute it
                # from the scrubbed URL so raw query PII isn't
                # persisted to recordings via the `path` field.
                _scrubbed_parsed = urlparse(url)
                path = _scrubbed_parsed.path or "/"
                if _scrubbed_parsed.query:
                    path = f"{path}?{_scrubbed_parsed.query}"
            if (
                query_pii
                and self._session_store is not None
                and hasattr(self._session_store, "tag_session_pii")
            ):
                if inspect.iscoroutinefunction(self._session_store.tag_session_pii):
                    await self._session_store.tag_session_pii(session_id, query_pii)
                else:
                    await asyncio.to_thread(
                        self._session_store.tag_session_pii, session_id, query_pii,
                    )
                if response_token_map is not None and hasattr(response_token_map, "absorb_pii"):
                    response_token_map.absorb_pii(query_pii)
        if (
            self._request_scrubber is not None
            and body_json is not None
            and self._pipeline is not None
            and token_map is not None
        ):
            _scrub_start = _time_mod.perf_counter()
            scrubbed_dict, entities, _fwd_stage_timings, _fwd_prefilter_reused = await self._request_scrubber.scrub_request(
                body=body_json,
                provider=provider,
                pipeline=self._pipeline,
                token_map=token_map,
                request_id=request_id,
            )
            _scrub_ms = (_time_mod.perf_counter() - _scrub_start) * 1000
            scrubbed_body = json.dumps(scrubbed_dict).encode("utf-8")
            scrubbed_dict_for_recording = scrubbed_dict
            pii_count = len(entities)

            # Use actual per-stage timing from the pipeline.
            if _fwd_stage_timings:
                pipeline_breakdown = _fwd_stage_timings

            if entities and self._stats is not None:
                try:
                    await self._stats.record_scrub_event(
                        session_id=session_id,
                        provider=provider.name,
                        entities=entities,
                        latency_ms=_scrub_ms,
                    )
                except Exception:
                    pass

            # Tag PII for session tracking.
            if self._session_store is not None and hasattr(self._session_store, "tag_session_pii"):
                request_pii = set()
                for e in entities:
                    matched = getattr(e, "_matched_text", None)
                    if matched:
                        request_pii.add(matched)
                # Include PII reused via the second-pass prefilter -- those
                # entries don't produce new entities but must still be tagged
                # so response deanonymization works for this session.
                if _fwd_prefilter_reused:
                    request_pii.update(_fwd_prefilter_reused)
                if request_pii:
                    if inspect.iscoroutinefunction(self._session_store.tag_session_pii):
                        await self._session_store.tag_session_pii(session_id, request_pii)
                    else:
                        await asyncio.to_thread(
                            self._session_store.tag_session_pii, session_id, request_pii
                        )
                    # E4 r51 residual fix: seed the response view's
                    # snapshot with this request's PII so eviction
                    # between tag and the first deanonymize call
                    # cannot un-mask the tokens we just minted.
                    if response_token_map is not None and hasattr(
                        response_token_map, "absorb_pii"
                    ):
                        response_token_map.absorb_pii(request_pii)
                    maybe_dirty = self._session_store.mark_dirty(session_id)
                    if inspect.isawaitable(maybe_dirty):
                        await maybe_dirty

        # Forward-proxy mode: the request URL the client sent IS the
        # upstream URL.  Provider matching only verifies WHETHER the
        # request needs scrubbing; it does NOT rewrite the host.
        # Earlier code unconditionally substituted the provider's
        # configured ``upstream_url`` for the request host (e.g.
        # rewrote ``api.enterprise.githubcopilot.com`` →
        # ``api.anthropic.com``), which sent client auth tokens to
        # the wrong service and produced 401/404.  Reverse-proxy /
        # loopback rewriting belongs in the reverse-proxy router,
        # not here.
        upstream_url = url
        if upstream_url != url:
            logger.info("Forward proxy: resolved upstream %s → %s", _redact_url_for_log(url), _redact_url_for_log(upstream_url))
            url = upstream_url

        # Record request (after URL resolution so the recording shows the real upstream URL).
        if recorder is not None and scrubbed_dict_for_recording is not None:
            try:
                await recorder.record_request(
                    session_id=session_id,
                    provider=provider.name,
                    method=method,
                    path=path,
                    body_scrubbed=scrubbed_dict_for_recording,
                    pii_entities_found=pii_count,
                    latency_ms=_scrub_ms,
                    request_id=request_id,
                    body_original=body_json,
                    url=url,
                    headers=headers,
                    pipeline_breakdown=pipeline_breakdown,
                    proxy_type="forward",
                )
            except Exception:
                logger.warning("Failed to record fwd-proxy request", exc_info=True)
            # Update session metadata for fast listing
            try:
                harness = headers.get("user-agent", "unknown")
                await recorder.write_metadata(
                    session_id=session_id,
                    provider=provider.name,
                    harness=harness,
                )
            except Exception:
                logger.debug("Failed to write fwd-proxy session metadata", exc_info=True)

        # Forward to upstream.
        clean_headers = _strip_hop_by_hop(headers)

        # Detect SSE streaming request.
        # Check Accept header AND request body "stream": true (OpenAI format).
        wants_stream = "text/event-stream" in headers.get("accept", "").lower()
        if not wants_stream and isinstance(body_json, dict):
            wants_stream = body_json.get("stream") is True

        if wants_stream and client_writer is not None:
            # ----- SSE streaming path -----
            logger.info(
                "Forward proxy SSE detected for %s %s (session=%s, tokens=%d)",
                method, _redact_url_for_log(url), session_id,
                len(response_token_map.unscrub_map)
                if response_token_map and hasattr(response_token_map, "unscrub_map")
                else -1,
            )
            _network_start = _time_mod.perf_counter()
            try:
                request = self._client.build_request(
                    method=method,
                    url=url,
                    headers=clean_headers,
                    content=scrubbed_body,
                )
                upstream_resp = await self._client.send(request, stream=True)
            except Exception:
                logger.exception("Forward proxy upstream SSE error: %s %s", method, _redact_url_for_log(url))
                return 502, {"Content-Type": "application/json"}, b'{"error":"upstream request failed"}'
            _network_ms = (_time_mod.perf_counter() - _network_start) * 1000

            try:
                _raw_upstream_headers = dict(upstream_resp.headers)
                resp_headers = _strip_response_headers(_raw_upstream_headers)
                # Remove content-length (unknown for streams) and use Connection: close.
                resp_headers.pop("content-length", None)
                resp_headers.pop("Content-Length", None)
                resp_headers["Connection"] = "close"

                status_line = _status_line(upstream_resp.status_code, getattr(upstream_resp, "reason_phrase", None))
                header_lines = "".join(
                    f"{k}: {v.replace(chr(13), '').replace(chr(10), '')}\r\n"
                    for k, v in resp_headers.items()
                )
                head_bytes = f"{status_line}{header_lines}\r\n".encode("latin-1")
                client_writer.write(head_bytes)
                await client_writer.drain()

                logger.info(
                    "Forward proxy SSE stream: %s %s → %d (streaming)",
                    method, _redact_url_for_log(url), upstream_resp.status_code,
                )

                content_type = resp_headers.get("content-type", "").lower()

                # Accumulators for recording scrubbed/unscrubbed text.
                _SSE_PARTS_LIMIT = 200
                event_count = 0
                tokens_unscrubbed = 0
                scrubbed_text_parts: list[str] = []
                scrubbed_text_len = 0
                scrubbed_text_truncated = False
                scrubbed_text_event_count = 0
                scrubbed_sse_parts: list[dict] = []

                # Always unscrub when we have a token map.  The unscrubber
                # safely passes through non-"data:" lines, so running it on
                # non-SSE streams is harmless -- but skipping it on SSE
                # streams that lack a text/event-stream Content-Type causes
                # REDACTED tokens to leak to the client.
                if response_token_map is not None and provider is not None:
                    from scruxy.scrubber.sse_stream_unscrubber import SSEStreamUnscrubber

                    unscrub_map = (
                        response_token_map.unscrub_map
                        if hasattr(response_token_map, "unscrub_map")
                        else {}
                    )
                    logger.debug(
                        "Forward proxy SSE unscrub: session=%s, tokens in map=%d",
                        session_id,
                        len(unscrub_map),
                    )

                    unscrubber = SSEStreamUnscrubber(
                        provider=provider,
                        token_map=response_token_map,
                    )

                    async def _sse_lines():  # type: ignore[return]
                        nonlocal scrubbed_text_len, scrubbed_text_truncated, scrubbed_text_event_count
                        buf = b""
                        async for raw_chunk in upstream_resp.aiter_bytes():
                            buf += raw_chunk
                            while b"\n" in buf:
                                line, buf = buf.split(b"\n", 1)
                                # Capture scrubbed text for recording.
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
                                # immediately instead of waiting for the
                                # upstream to close the connection.
                                stripped = line.rstrip()
                                if stripped == b"data: [DONE]" or stripped == b"data:[DONE]":
                                    return
                            # R55-1 fix: apply the buffer cap ONLY to
                            # the residual after newlines have been
                            # drained.  R54-3 originally placed this
                            # check BEFORE the drain loop, which
                            # caused valid newline-bearing buffers >
                            # 1 MiB to be yielded as one opaque blob —
                            # SSEStreamUnscrubber treats that blob as
                            # one event, so REDACTED_* tokens past the
                            # first event leak unscrubbed.
                            # R56-2 fix: hold back the trailing
                            # ``_MAX_TOKEN_HOLDBACK_BYTES`` so a
                            # ``REDACTED_<TYPE>_<N>`` token bisected
                            # at the cap boundary still re-joins the
                            # next chunk and is matched by the
                            # unscrubber's trie.  Memory remains
                            # bounded (cap + chunk + holdback).
                            if len(buf) > _MAX_SSE_LINE_BUFFER_BYTES:
                                logger.warning(
                                    "SSE residual buffer exceeded %d bytes "
                                    "without newline -- flushing partial line",
                                    _MAX_SSE_LINE_BUFFER_BYTES,
                                )
                                # R58-7 fix: removed the dead ``else``
                                # branch.  The outer guard already
                                # ensures ``len(buf) > 1 MiB`` so the
                                # inner ``> 4 KiB`` was always true.
                                yield buf[:-_MAX_TOKEN_HOLDBACK_BYTES]
                                buf = buf[-_MAX_TOKEN_HOLDBACK_BYTES:]
                        if buf:
                            yield buf

                    async for unscrubbed_chunk in unscrubber.process_sse_stream(
                        _sse_lines()
                    ):
                        # B8: skip the synthesized blank-chunk separator
                        # from the unscrubber's flush path.  Emit just
                        # "\n" to terminate the preceding event with
                        # the spec-required "\n\n" framing, but don't
                        # bump event_count (it's not a distinct event).
                        if not unscrubbed_chunk:
                            client_writer.write(b"\n")
                            await client_writer.drain()
                            continue
                        client_writer.write(unscrubbed_chunk + b"\n")
                        await client_writer.drain()
                        event_count += 1
                else:
                    # Not actually SSE or no token map -- relay raw bytes.
                    async for chunk in upstream_resp.aiter_bytes():
                        client_writer.write(chunk)
                        await client_writer.drain()

                # Record SSE response with captured text.
                if recorder is not None and request_id:
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

                        original_record: dict | None = None
                        if scrubbed_text_parts and response_token_map is not None:
                            scrubbed_joined = "".join(scrubbed_text_parts)
                            orig_text = deanonymize_text(scrubbed_joined, response_token_map)
                            if orig_text != scrubbed_joined:
                                unscrub_map = (
                                    response_token_map.unscrub_map
                                    if hasattr(response_token_map, "unscrub_map")
                                    else {}
                                )
                                # NOTE: tokens_unscrubbed reflects only the
                                # captured text prefix (capped at
                                # _MAX_SSE_RECORD_TEXT_CHARS).  For streams
                                # exceeding that limit the count will
                                # underreport; the recording is already marked
                                # truncated=True in that case.
                                remaining_text = scrubbed_joined
                                for tok in sorted(unscrub_map, key=len, reverse=True):
                                    count = remaining_text.count(tok)
                                    if count > 0:
                                        tokens_unscrubbed += count
                                        remaining_text = remaining_text.replace(tok, "")
                                original_record = {
                                    "event_count": event_count,
                                    "streaming": True,
                                }
                                if scrubbed_text_truncated or len(orig_text) > 4096:
                                    original_record["text"] = orig_text[:4096]
                                    original_record["truncated"] = True
                                else:
                                    original_record["text"] = orig_text

                        _total_ms = (_time_mod.perf_counter() - _request_start) * 1000
                        _unscrub_ms_approx = max(0, _total_ms - _scrub_ms - _network_ms)
                        await recorder.record_response(
                            session_id=session_id,
                            status=upstream_resp.status_code,
                            streaming=True,
                            body_scrubbed=body_record,
                            tokens_unscrubbed=tokens_unscrubbed,
                            request_id=request_id,
                            body_original=original_record,
                            headers=_raw_upstream_headers,
                            network_ms=_network_ms,
                            unscrub_ms=_unscrub_ms_approx,
                            total_ms=_total_ms,
                        )
                    except Exception:
                        logger.warning("Failed to record fwd-proxy SSE response", exc_info=True)

                # Notify UI that a recording pair is complete.
                self._emit_recording_complete(session_id, provider.name)

                # Final drain after all recording/logging work to ensure the
                # client has had time to read all data before we return the
                # sentinel and the connection is closed.
                await client_writer.drain()
            finally:
                await upstream_resp.aclose()

            return -1, {}, b""  # sentinel: response already streamed

        # ----- Non-streaming path -----
        _network_start_ns = _time_mod.perf_counter()
        try:
            upstream_resp = await self._client.request(
                method=method,
                url=url,
                headers=clean_headers,
                content=scrubbed_body,
            )
        except Exception:
            logger.exception("Forward proxy upstream error: %s %s", method, _redact_url_for_log(url))
            return 502, {"Content-Type": "application/json"}, b'{"error":"upstream request failed"}'
        _network_ms_ns = (_time_mod.perf_counter() - _network_start_ns) * 1000

        # Unscrub response body.
        resp_body = upstream_resp.content
        scrubbed_resp_dict: dict | None = None
        unscrubbed_resp_dict: dict | None = None
        tokens_unscrubbed = 0
        _unscrub_ms = 0.0
        if self._response_unscrubber is not None and response_token_map is not None and resp_body:
            try:
                resp_dict = json.loads(resp_body)
                # R59-6 / R68-3 fix: use JSON round-trip instead of
                # recursive ``copy.deepcopy`` to avoid RecursionError
                # on deeply-nested upstream JSON responses.  Falls
                # back to deepcopy on non-JSON-safe values (rare for
                # parsed-from-JSON dicts).
                try:
                    scrubbed_resp_dict = json.loads(json.dumps(resp_dict))
                except (TypeError, ValueError):
                    scrubbed_resp_dict = copy.deepcopy(resp_dict)
                _unscrub_start = _time_mod.perf_counter()
                unscrubbed_dict = self._response_unscrubber.unscrub_response(
                    body=resp_dict,
                    provider=provider,
                    token_map=response_token_map,
                )
                _unscrub_ms = (_time_mod.perf_counter() - _unscrub_start) * 1000
                # R68-3 fix: same JSON round-trip for unscrubbed snapshot.
                try:
                    unscrubbed_resp_dict = json.loads(json.dumps(unscrubbed_dict))
                except (TypeError, ValueError):
                    unscrubbed_resp_dict = copy.deepcopy(unscrubbed_dict)
                resp_body = json.dumps(unscrubbed_dict).encode("utf-8")
                upstream_text = upstream_resp.content.decode("utf-8", errors="replace")
                unscrub_map = (
                    response_token_map.unscrub_map
                    if hasattr(response_token_map, "unscrub_map")
                    else {}
                )
                remaining_text = upstream_text
                tokens_unscrubbed = 0
                for tok in sorted(unscrub_map, key=len, reverse=True):
                    count = remaining_text.count(tok)
                    if count > 0:
                        tokens_unscrubbed += count
                        remaining_text = remaining_text.replace(tok, "")
            except (ValueError, TypeError):
                pass

        _total_ms = (_time_mod.perf_counter() - _request_start) * 1000

        # Record response.
        if recorder is not None and request_id:
            try:
                await recorder.record_response(
                    session_id=session_id,
                    status=upstream_resp.status_code,
                    streaming=False,
                    body_scrubbed=scrubbed_resp_dict or {},
                    tokens_unscrubbed=tokens_unscrubbed,
                    request_id=request_id,
                    body_original=unscrubbed_resp_dict,
                    headers=dict(upstream_resp.headers),
                    network_ms=_network_ms_ns,
                    unscrub_ms=_unscrub_ms,
                    total_ms=_total_ms,
                )
            except Exception:
                logger.warning("Failed to record fwd-proxy response", exc_info=True)

        # Notify UI that a recording pair is complete.
        self._emit_recording_complete(session_id, provider.name)

        resp_headers = _strip_response_headers(dict(upstream_resp.headers))

        # Provider-matched requests are already in recordings -- skip passthrough log.

        return upstream_resp.status_code, resp_headers, resp_body

    async def _plain_forward(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        disabled_provider: Any = None,
        allow_private_target: bool = False,
        client_writer: asyncio.StreamWriter | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        """Forward a request without scrubbing (no provider match)."""
        parsed = urlparse(url)
        if allow_private_target and _is_blocked_local_admin_path(parsed.path or "/"):
            logger.warning("Forward proxy plain: blocked local admin path %s", _redact_url_for_log(url))
            return 403, {"Content-Type": "text/plain"}, b"Forbidden: local admin path"

        hostname = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        resolved_targets: list[tuple[str, int]] = []
        # Note: HTTPS absolute-form passthrough is intentionally allowed.
        # ``httpx`` performs the TLS handshake to the upstream itself
        # (the URL still carries ``https://``), so the wire to the
        # upstream is encrypted as the client originally intended.
        # The earlier hard-fail here regressed the long-standing
        # "passthrough unmatched URLs" behavior — restored.
        if parsed.scheme.lower() == "https" and not allow_private_target:
            logger.debug(
                "Forward proxy plain: HTTPS passthrough (no provider match) %s",
                _redact_url_for_log(url),
            )
        if hostname and not allow_private_target:
            try:
                resolved_targets = await _resolve_public_endpoints(hostname, port)
            except PermissionError as exc:
                logger.warning("Forward proxy plain: blocked SSRF to %s (%s)", hostname, exc)
                return 403, {"Content-Type": "text/plain"}, b"Forbidden: non-public IP"
            except OSError:
                logger.warning("Forward proxy plain: DNS resolution failed for %s", _redact_url_for_log(url))
                return 502, {"Content-Type": "text/plain"}, b"Bad Gateway: hostname resolution failed"

        candidate_urls = [url]
        if not allow_private_target and parsed.scheme.lower() == "http" and resolved_targets:
            candidate_urls = [
                _replace_url_host(parsed, resolved_host, resolved_port)
                for resolved_host, resolved_port in resolved_targets
            ]

        logger.info("Forward proxy passthrough HTTP: %s %s (no provider match)", method, _redact_url_for_log(url))
        clean_headers = _strip_hop_by_hop(headers)
        host_header = _build_host_header(parsed)
        if host_header:
            clean_headers["Host"] = host_header

        # Check if client wants SSE streaming.
        wants_stream = "text/event-stream" in headers.get("accept", "").lower()
        if not wants_stream and body:
            try:
                body_obj = json.loads(body)
                if isinstance(body_obj, dict) and body_obj.get("stream") is True:
                    wants_stream = True
            except (ValueError, TypeError):
                pass

        if wants_stream and client_writer is not None:
            # Streaming passthrough: relay raw bytes without reading full response.
            upstream_resp = None
            last_exc: Exception | None = None
            for candidate_url in candidate_urls:
                try:
                    request = self._client.build_request(
                        method=method, url=candidate_url, headers=clean_headers, content=body,
                    )
                    upstream_resp = await self._client.send(request, stream=True)
                    break
                except Exception as exc:
                    last_exc = exc
            if upstream_resp is None:
                logger.warning(
                    "Forward proxy passthrough SSE error: %s %s (%s)",
                    method,
                    _redact_url_for_log(url),
                    last_exc,
                )
                return 502, {"Content-Type": "application/json"}, b'{"error":"upstream request failed"}'

            try:
                resp_headers = _strip_response_headers(dict(upstream_resp.headers))
                resp_headers.pop("content-length", None)
                resp_headers.pop("Content-Length", None)
                resp_headers["Connection"] = "close"

                status_line = _status_line(upstream_resp.status_code, getattr(upstream_resp, "reason_phrase", None))
                header_lines = "".join(
                    f"{k}: {v.replace(chr(13), '').replace(chr(10), '')}\r\n"
                    for k, v in resp_headers.items()
                )
                head_bytes = f"{status_line}{header_lines}\r\n".encode("latin-1")
                client_writer.write(head_bytes)
                await client_writer.drain()

                logger.info("Forward proxy passthrough SSE: %s %s → %d (streaming)", method, _redact_url_for_log(url), upstream_resp.status_code)

                async for chunk in upstream_resp.aiter_bytes():
                    client_writer.write(chunk)
                    await client_writer.drain()

                self._log_passthrough(
                    method=method, path=parsed.path or "/", url=url,
                    status=upstream_resp.status_code,
                    request_content_type=headers.get("content-type", ""),
                    response_content_type=resp_headers.get("content-type", ""),
                    request_body=body,
                    disabled_provider=getattr(disabled_provider, "name", None) if disabled_provider else None,
                )

                # Final drain to ensure client receives all data.
                await client_writer.drain()
            finally:
                await upstream_resp.aclose()

            return -1, {}, b""

        # Non-streaming passthrough.
        last_exc: Exception | None = None
        for candidate_url in candidate_urls:
            try:
                resp = await self._client.request(
                    method=method,
                    url=candidate_url,
                    headers=clean_headers,
                    content=body,
                )
                resp_headers = _strip_response_headers(dict(resp.headers))
                logger.info("Forward proxy passthrough HTTP: %s %s → %d", method, _redact_url_for_log(url), resp.status_code)
                self._log_passthrough(
                    method=method, path=parsed.path or "/", url=url,
                    status=resp.status_code,
                    request_content_type=headers.get("content-type", ""),
                    response_content_type=resp_headers.get("content-type", ""),
                    request_body=body,
                    response_body=resp.content,
                    disabled_provider=getattr(disabled_provider, "name", None) if disabled_provider else None,
                )
                return resp.status_code, resp_headers, resp.content
            except Exception as exc:
                last_exc = exc
                continue
        if last_exc is not None:
            logger.warning(
                "Forward proxy passthrough HTTP error: %s %s (%s)",
                method,
                _redact_url_for_log(url),
                last_exc,
            )
        return 502, {"Content-Type": "application/json"}, b'{"error":"upstream request failed"}'
