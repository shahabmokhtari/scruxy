"""httpx-based upstream forwarding with streaming support."""
from __future__ import annotations

import logging
from typing import AsyncIterator

import httpx

logger = logging.getLogger(__name__)

# Hop-by-hop headers that must not be forwarded to upstream.
# See RFC 2616 Section 13.5.1 and RFC 7230 Section 6.1.
HOP_BY_HOP_HEADERS: frozenset[str] = frozenset({
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",  # Recalculated by httpx from the actual body.
    "accept-encoding",  # Prevent compressed responses — we modify the body.
    # 72-6 fix: strip ``Expect: 100-continue`` because the proxy
    # always reads the full body before forwarding (no two-phase
    # POST).  Sending it upstream would make the upstream send
    # 100 Continue back to the proxy with no client to relay it
    # to, while the client would stall waiting for our (never-
    # sent) 100.  Strip cleanly per RFC 9110 §10.1.1.
    "expect",
})

# Headers to strip from upstream responses before relaying to the client.
# content-encoding is removed because httpx auto-decompresses gzip/br/deflate
# but the raw header stays on the response object, causing the client to try
# to decompress already-decompressed data (ZlibError).
# content-length is removed because we may modify the body (scrub/unscrub).
# R60-5 fix: ``set-cookie`` is removed from scrubbed responses because
# ``dict(upstream_resp.headers)`` joins multi-valued ``Set-Cookie``
# headers with ``", "`` which corrupts cookies whose ``Expires`` value
# contains commas.  LLM APIs do not legitimately use cookies; pass-
# through still preserves them byte-for-byte via the separate
# ``PASSTHROUGH_STRIP_RESPONSE_HEADERS`` set below.
STRIP_RESPONSE_HEADERS: frozenset[str] = frozenset({
    "content-encoding",
    "content-length",
    "transfer-encoding",
    "set-cookie",
})

# ---------------------------------------------------------------------------
# Passthrough-specific header sets — preserve compression end-to-end
# ---------------------------------------------------------------------------

# Request headers stripped for passthrough: true hop-by-hop only.
# accept-encoding is kept so upstream can compress the response.
PASSTHROUGH_STRIP_REQUEST_HEADERS: frozenset[str] = frozenset({
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",  # Recalculated by httpx from the actual body.
})

# Response headers stripped for passthrough: hop-by-hop + transfer-encoding.
# content-encoding is preserved (raw bytes forwarded without decompression).
# content-length is stripped — Starlette recomputes it for non-streaming.
PASSTHROUGH_STRIP_RESPONSE_HEADERS: frozenset[str] = frozenset({
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
})


def _strip_hop_by_hop(headers: dict[str, str]) -> dict[str, str]:
    """Return a copy of *headers* with hop-by-hop entries removed.

    Auth headers (e.g. ``authorization``, ``x-api-key``) are preserved because
    they must reach the upstream API.
    """
    return {
        key: value
        for key, value in headers.items()
        if key.lower() not in HOP_BY_HOP_HEADERS
    }


def _strip_passthrough_request(headers: dict[str, str]) -> dict[str, str]:
    """Strip headers for passthrough requests — preserves accept-encoding."""
    return {
        key: value
        for key, value in headers.items()
        if key.lower() not in PASSTHROUGH_STRIP_REQUEST_HEADERS
    }


class UpstreamForwarder:
    """Forward scrubbed requests to the real upstream LLM API.

    Uses a persistent ``httpx.AsyncClient`` connection pool for efficient
    keep-alive reuse across requests.
    """

    def __init__(
        self,
        max_connections: int = 100,
        max_keepalive: int = 20,
        timeout: float = 120.0,
    ) -> None:
        # Strip auth headers on cross-origin redirects to prevent credential leakage
        _AUTH_HEADERS = {"authorization", "x-api-key", "api-key", "proxy-authorization", "cookie"}

        self.client = httpx.AsyncClient(
            limits=httpx.Limits(
                max_connections=max_connections,
                max_keepalive_connections=max_keepalive,
            ),
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,  # Non-streaming: manual redirect loop with auth stripping
            trust_env=False,  # Don't follow HTTP_PROXY env vars — would loop back
        )
        # Streaming client also uses follow_redirects=False — streaming
        # responses can't be replayed after redirect, so 3xx responses are
        # returned to the caller which handles them at the proxy layer.
        self._stream_client = httpx.AsyncClient(
            limits=httpx.Limits(
                max_connections=max_connections,
                max_keepalive_connections=max_keepalive,
            ),
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
            trust_env=False,
        )
        self._auth_headers_to_strip = _AUTH_HEADERS
        self._max_redirects = 10

    async def forward(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None = None,
        stream: bool = False,
    ) -> httpx.Response:
        """Forward a request to the upstream API.

        Hop-by-hop headers are stripped automatically. Auth headers are
        forwarded untouched.

        Args:
            method: HTTP method (GET, POST, ...).
            url: Full upstream URL.
            headers: Request headers (will be filtered).
            body: Raw request body bytes.
            stream: When ``True`` the response is returned as an async
                stream that the caller must close via ``response.aclose()``.

        Returns:
            An ``httpx.Response``.  If *stream* is ``True`` the response body
            has not been read yet -- iterate ``response.aiter_bytes()`` or
            ``response.aiter_lines()`` to consume it.
        """
        clean_headers = _strip_hop_by_hop(headers)

        logger.debug(
            "Forwarding %s %s (stream=%s, body_len=%s)",
            method,
            url,
            stream,
            len(body) if body else 0,
        )

        from urllib.parse import urlparse as _urlparse_fwd

        def _origin(parsed_url) -> str:
            """Return scheme://host:port origin for cross-origin comparison."""
            scheme = (parsed_url.scheme or "https").lower()
            host = (parsed_url.hostname or "").lower()
            port = parsed_url.port
            # Use default ports when not explicit
            if port is None:
                port = 443 if scheme == "https" else 80
            return f"{scheme}://{host}:{port}"

        original_origin = _origin(_urlparse_fwd(url))

        if stream:
            # Streaming: follow redirects manually, stripping auth on cross-origin.
            current_url = url
            current_headers = dict(clean_headers)
            for _ in range(self._max_redirects):
                request = self._stream_client.build_request(
                    method=method,
                    url=current_url,
                    headers=current_headers,
                    content=body,
                )
                response = await self._stream_client.send(request, stream=True)
                if response.status_code not in (301, 302, 303, 307, 308):
                    return response
                location = response.headers.get("location")
                if not location:
                    # R67-5 fix: a 3xx WITHOUT Location is a server
                    # protocol violation (RFC 7231 §6.4 requires
                    # Location).  The body is not useful for the
                    # caller, so eagerly consume + close to avoid
                    # leaving a connection open in the pool if a
                    # caller forgets to ``aclose()`` this exceptional
                    # response.  The body is buffered into the
                    # response object so existing ``response.content``
                    # access still works.
                    try:
                        await response.aread()
                    finally:
                        await response.aclose()
                    return response
                # Close the redirect response before following
                await response.aclose()
                if not location.startswith("http"):
                    from urllib.parse import urljoin
                    location = urljoin(current_url, location)
                redirect_origin = _origin(_urlparse_fwd(location))
                if redirect_origin != original_origin:
                    current_headers = {
                        k: v for k, v in current_headers.items()
                        if k.lower() not in self._auth_headers_to_strip
                    }
                    logger.info("Stream cross-origin redirect: credentials stripped (%s → %s)", original_origin, redirect_origin)
                current_url = location
                # 301/302/303: convert to GET with no body (per HTTP spec)
                if response.status_code in (301, 302, 303) and method != "GET":
                    method = "GET"
                    body = None
            # Max redirects exhausted — send one final request
            request = self._stream_client.build_request(
                method=method, url=current_url,
                headers=current_headers, content=body,
            )
            return await self._stream_client.send(request, stream=True)

        # Non-streaming: follow redirects manually, stripping auth on cross-origin
        current_url = url
        current_headers = dict(clean_headers)
        current_body = body
        for _ in range(self._max_redirects):
            response = await self.client.request(
                method=method,
                url=current_url,
                headers=current_headers,
                content=current_body,
            )
            if response.status_code not in (301, 302, 303, 307, 308):
                return response
            location = response.headers.get("location")
            if not location:
                return response
            if not location.startswith("http"):
                from urllib.parse import urljoin
                location = urljoin(current_url, location)
            redirect_origin = _origin(_urlparse_fwd(location))
            if redirect_origin != original_origin:
                current_headers = {
                    k: v for k, v in current_headers.items()
                    if k.lower() not in self._auth_headers_to_strip
                }
                logger.info("Cross-origin redirect %s → %s: credentials stripped", original_origin, redirect_origin)
            current_url = location
            # 301/302/303: convert to GET with no body (per HTTP spec)
            if response.status_code in (301, 302, 303) and method != "GET":
                method = "GET"
                current_body = None
        # Max redirects exhausted — send one final request (same as streaming path)
        response = await self.client.request(
            method=method,
            url=current_url,
            headers=current_headers,
            content=current_body,
        )
        return response

    async def forward_raw(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None = None,
    ) -> httpx.Response:
        """Forward a request preserving compression (passthrough mode).

        Unlike :meth:`forward`, this preserves ``Accept-Encoding`` so the
        upstream may compress the response.  The returned response is always
        in streaming mode — callers **must** use ``aiter_raw()`` (not
        ``aiter_bytes()``) to obtain the original compressed bytes and then
        close the response via ``aclose()``.

        This prevents httpx from auto-decompressing the body, keeping the
        proxy fully transparent for passthrough traffic.
        """
        clean_headers = _strip_passthrough_request(headers)

        logger.debug(
            "Forwarding raw passthrough %s %s (body_len=%s)",
            method,
            url,
            len(body) if body else 0,
        )

        request = self._stream_client.build_request(
            method=method,
            url=url,
            headers=clean_headers,
            content=body,
        )
        response = await self._stream_client.send(request, stream=True)
        return response

    async def close(self) -> None:
        """Shut down the underlying connection pools."""
        await self.client.aclose()
        await self._stream_client.aclose()
