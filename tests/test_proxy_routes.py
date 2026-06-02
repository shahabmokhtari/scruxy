"""Tests for proxy routes and upstream forwarder."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, AsyncIterator
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import FastAPI

from scruxy.proxy.forwarder import (
    HOP_BY_HOP_HEADERS,
    PASSTHROUGH_STRIP_REQUEST_HEADERS,
    UpstreamForwarder,
    _strip_hop_by_hop,
    _strip_passthrough_request,
)
from scruxy.proxy.routes import (
    ProxyRequest,
    ScrubResult,
    UnscrubResult,
    _build_passthrough_headers,
    _build_transparent_passthrough_headers,
    _decompress_body,
    _is_sse_response,
    _resolve_upstream_url,
    router,
)


# ---------------------------------------------------------------------------
# Helpers: mock services
# ---------------------------------------------------------------------------


def _make_mock_provider(
    *,
    name: str = "test_provider",
    session_id: str = "session-abc-123",
    upstream_url: str = "https://api.example.com",
    matches: bool = True,
) -> MagicMock:
    """Create a mock LLM provider."""
    provider = MagicMock()
    provider.name = name
    provider.upstream_url = upstream_url
    provider.extract_session_id.return_value = session_id
    provider.matches.return_value = matches
    # SSE methods — return None so SSEStreamUnscrubber passes chunks through
    provider.parse_sse_event.return_value = None
    provider.rebuild_sse_event.side_effect = lambda event_data, text: text
    return provider


def _make_mock_registry(provider: MagicMock | None = None) -> MagicMock:
    """Create a mock ProviderRegistry."""
    registry = MagicMock()
    registry.match.return_value = provider
    return registry


def _make_mock_forwarder(
    status_code: int = 200,
    content: bytes = b'{"result": "ok"}',
    headers: dict[str, str] | None = None,
    stream_chunks: list[bytes] | None = None,
) -> AsyncMock:
    """Create a mock UpstreamForwarder.

    If *stream_chunks* is provided, the ``forward`` call with ``stream=True``
    returns a mock response whose ``aiter_bytes()`` yields those chunks.

    Also sets up ``forward_raw`` for passthrough tests — always returns a
    streaming response with ``aiter_raw()`` yielding the content bytes.
    """
    resp_headers = headers or {"content-type": "application/json"}

    forwarder = AsyncMock()

    if stream_chunks is not None:
        # Build a streaming mock response
        stream_resp = AsyncMock()
        stream_resp.status_code = status_code
        stream_resp.headers = httpx.Headers(resp_headers)
        stream_resp.aclose = AsyncMock()

        async def _aiter_bytes() -> AsyncIterator[bytes]:
            for chunk in stream_chunks:
                yield chunk

        stream_resp.aiter_bytes = _aiter_bytes

        async def _aiter_raw_stream() -> AsyncIterator[bytes]:
            for chunk in stream_chunks:
                yield chunk

        stream_resp.aiter_raw = _aiter_raw_stream

        # Non-streaming mock response (for cases where both may be tested)
        non_stream_resp = AsyncMock()
        non_stream_resp.status_code = status_code
        non_stream_resp.content = content
        non_stream_resp.headers = httpx.Headers(resp_headers)
        non_stream_resp.aclose = AsyncMock()

        async def _forward_side_effect(
            method: str,
            url: str,
            headers: dict,
            body: bytes | None = None,
            stream: bool = False,
        ) -> Any:
            if stream:
                return stream_resp
            return non_stream_resp

        forwarder.forward = AsyncMock(side_effect=_forward_side_effect)
        # forward_raw always returns the streaming response
        forwarder.forward_raw = AsyncMock(return_value=stream_resp)
    else:
        resp = AsyncMock()
        resp.status_code = status_code
        resp.content = content
        resp.headers = httpx.Headers(resp_headers)
        resp.aclose = AsyncMock()
        forwarder.forward.return_value = resp

        # forward_raw: build a streaming-compatible response from content
        raw_resp = AsyncMock()
        raw_resp.status_code = status_code
        raw_resp.headers = httpx.Headers(resp_headers)
        raw_resp.aclose = AsyncMock()

        async def _aiter_raw_content() -> AsyncIterator[bytes]:
            yield content

        raw_resp.aiter_raw = _aiter_raw_content
        forwarder.forward_raw = AsyncMock(return_value=raw_resp)

    return forwarder


def _make_mock_session_store(token_map: Any = None) -> AsyncMock:
    """Create a mock ConcurrentSessionStore."""
    store = AsyncMock()
    if token_map is None:
        token_map = MagicMock()
        # Provide a real unscrub dict so SSEStreamUnscrubber works
        token_map.unscrub = {}
        token_map.token_to_pii = {}
    store.get_or_create_session.return_value = token_map
    return store


def _make_mock_request_scrubber(
    scrubbed_body: bytes = b'{"message": "REDACTED_EMAIL_1"}',
    pii_count: int = 1,
) -> AsyncMock:
    """Create a mock RequestScrubber."""
    import json as _json
    scrubber = AsyncMock()
    # scrub_request returns (scrubbed_dict, entities_list, stage_timings)
    try:
        scrubbed_dict = _json.loads(scrubbed_body)
    except (ValueError, TypeError):
        scrubbed_dict = {}
    entities = [MagicMock() for _ in range(pii_count)]
    scrubber.scrub_request.return_value = (scrubbed_dict, entities, [], set())
    return scrubber


def _make_mock_response_unscrubber(
    unscrubbed_body: bytes = b'{"response": "john@example.com"}',
    token_count: int = 1,
) -> AsyncMock:
    """Create a mock ResponseUnscrubber."""
    import json as _json
    unscrubber = MagicMock()
    # unscrub_response returns a dict (sync method)
    try:
        unscrubbed_dict = _json.loads(unscrubbed_body)
    except (ValueError, TypeError):
        unscrubbed_dict = {}
    unscrubber.unscrub_response.return_value = unscrubbed_dict
    return unscrubber


def _make_mock_sse_unscrubber() -> AsyncMock:
    """Create a mock SSEStreamUnscrubber."""
    unscrubber = AsyncMock()

    async def _unscrub_chunk(
        provider: Any, chunk: bytes, token_map: Any
    ) -> tuple[bytes, int]:
        # Simple: just pass through chunks unchanged for most tests
        return chunk, 0

    unscrubber.unscrub_chunk = AsyncMock(side_effect=_unscrub_chunk)
    return unscrubber


def _make_mock_recorder() -> AsyncMock:
    """Create a mock SessionRecorder."""
    recorder = AsyncMock()
    recorder.record_request = AsyncMock()
    recorder.record_response = AsyncMock()
    return recorder


# ---------------------------------------------------------------------------
# Build a FastAPI test app with configurable mock services
# ---------------------------------------------------------------------------


def _create_test_app(
    *,
    registry: Any = None,
    pipeline: Any = None,
    session_store: Any = None,
    request_scrubber: Any = None,
    response_unscrubber: Any = None,
    sse_unscrubber: Any = None,
    forwarder: Any = None,
    recorder: Any = None,
) -> FastAPI:
    """Create a FastAPI application with the proxy router and mock state."""
    app = FastAPI()
    app.include_router(router)

    app.state.registry = registry
    app.state.pipeline = pipeline
    app.state.session_store = session_store
    app.state.request_scrubber = request_scrubber
    app.state.response_unscrubber = response_unscrubber
    app.state.sse_unscrubber = sse_unscrubber
    app.state.forwarder = forwarder
    app.state.recorder = recorder

    return app


# ===================================================================
# Tests: UpstreamForwarder (unit)
# ===================================================================


class TestStripHopByHop:
    """Test hop-by-hop header stripping."""

    def test_removes_hop_by_hop_headers(self):
        headers = {
            "connection": "keep-alive",
            "keep-alive": "timeout=5",
            "transfer-encoding": "chunked",
            "authorization": "Bearer sk-test",
            "content-type": "application/json",
        }
        result = _strip_hop_by_hop(headers)
        assert "connection" not in result
        assert "keep-alive" not in result
        assert "transfer-encoding" not in result
        assert result["authorization"] == "Bearer sk-test"
        assert result["content-type"] == "application/json"

    def test_case_insensitive_stripping(self):
        headers = {
            "Connection": "keep-alive",
            "Host": "api.example.com",
            "Authorization": "Bearer token",
        }
        result = _strip_hop_by_hop(headers)
        assert "Connection" not in result
        assert "Host" not in result
        assert result["Authorization"] == "Bearer token"

    def test_preserves_auth_headers(self):
        headers = {
            "authorization": "Bearer sk-test-key",
            "x-api-key": "key-123",
            "anthropic-version": "2024-01-01",
            "api-key": "azure-key",
        }
        result = _strip_hop_by_hop(headers)
        assert len(result) == 4
        assert result["authorization"] == "Bearer sk-test-key"

    def test_empty_headers(self):
        assert _strip_hop_by_hop({}) == {}

    def test_all_hop_by_hop_are_stripped(self):
        headers = {h: "value" for h in HOP_BY_HOP_HEADERS}
        result = _strip_hop_by_hop(headers)
        assert result == {}


class TestStripPassthroughRequest:
    """Test passthrough request header stripping — preserves accept-encoding."""

    def test_preserves_accept_encoding(self):
        headers = {
            "accept-encoding": "gzip, deflate, br",
            "authorization": "Bearer token",
            "content-type": "application/json",
        }
        result = _strip_passthrough_request(headers)
        assert result["accept-encoding"] == "gzip, deflate, br"
        assert result["authorization"] == "Bearer token"

    def test_strips_true_hop_by_hop(self):
        headers = {
            "connection": "keep-alive",
            "host": "api.example.com",
            "accept-encoding": "gzip",
            "content-type": "application/json",
        }
        result = _strip_passthrough_request(headers)
        assert "connection" not in result
        assert "host" not in result
        assert "accept-encoding" in result

    def test_accept_encoding_not_in_passthrough_strip_set(self):
        assert "accept-encoding" not in PASSTHROUGH_STRIP_REQUEST_HEADERS
        assert "accept-encoding" in HOP_BY_HOP_HEADERS


class TestUpstreamForwarder:
    """Test the UpstreamForwarder class."""

    def test_init_defaults(self):
        fwd = UpstreamForwarder()
        assert fwd.client is not None

    def test_init_custom_params(self):
        fwd = UpstreamForwarder(max_connections=50, max_keepalive=10, timeout=60.0)
        assert fwd.client is not None

    @pytest.mark.asyncio
    async def test_close(self):
        fwd = UpstreamForwarder()
        await fwd.close()
        # After close, the client should be closed
        assert fwd.client.is_closed


# ===================================================================
# Tests: Route helpers
# ===================================================================


class TestBuildPassthroughHeaders:
    """Test response header filtering."""

    def test_strips_hop_by_hop(self):
        headers = {"content-type": "application/json", "transfer-encoding": "chunked"}
        result = _build_passthrough_headers(headers)
        assert "transfer-encoding" not in result
        assert result["content-type"] == "application/json"


class TestBuildTransparentPassthroughHeaders:
    """Test transparent passthrough header filtering (preserves content-encoding)."""

    def test_preserves_content_encoding(self):
        headers = {
            "content-type": "application/json",
            "content-encoding": "gzip",
            "transfer-encoding": "chunked",
        }
        result = _build_transparent_passthrough_headers(headers)
        assert result.get("content-encoding") == "gzip"
        assert "transfer-encoding" not in result
        assert result["content-type"] == "application/json"

    def test_strips_hop_by_hop(self):
        headers = {
            "content-type": "text/plain",
            "connection": "keep-alive",
            "keep-alive": "timeout=5",
        }
        result = _build_transparent_passthrough_headers(headers)
        assert "connection" not in result
        assert "keep-alive" not in result
        assert result["content-type"] == "text/plain"


class TestDecompressBody:
    """Test best-effort body decompression for logging."""

    def test_gzip(self):
        import gzip
        original = b"hello world"
        compressed = gzip.compress(original)
        assert _decompress_body(compressed, "gzip") == original

    def test_deflate(self):
        import zlib
        original = b"hello world"
        compressed = zlib.compress(original)
        assert _decompress_body(compressed, "deflate") == original

    def test_no_encoding(self):
        data = b"plain text"
        assert _decompress_body(data, None) == data
        assert _decompress_body(data, "") == data

    def test_unknown_encoding_returns_raw(self):
        data = b"mystery bytes"
        assert _decompress_body(data, "zstd") == data

    def test_corrupt_data_returns_raw(self):
        data = b"not actually gzipped"
        assert _decompress_body(data, "gzip") == data

    def test_empty_body(self):
        assert _decompress_body(b"", "gzip") == b""


class TestDecompressBodyStrict:
    """Strict scrubbing-path decompression must fail closed on bombs/brotli."""

    def test_gzip_within_limit(self):
        import gzip
        from scruxy.proxy.routes import _decompress_body_strict
        original = b"hello world"
        compressed = gzip.compress(original)
        assert _decompress_body_strict(compressed, "gzip") == original

    def test_deflate_within_limit(self):
        import zlib
        from scruxy.proxy.routes import _decompress_body_strict
        original = b"hello world"
        compressed = zlib.compress(original)
        assert _decompress_body_strict(compressed, "deflate") == original

    def test_gzip_bomb_raises(self):
        import gzip
        from scruxy.proxy.routes import (
            _decompress_body_strict,
            DecompressFailed,
            _DECOMPRESS_LIMIT,
        )
        bomb = gzip.compress(b"A" * (_DECOMPRESS_LIMIT + 1024))
        with pytest.raises(DecompressFailed):
            _decompress_body_strict(bomb, "gzip")

    def test_brotli_rejected(self):
        from scruxy.proxy.routes import _decompress_body_strict, DecompressFailed
        with pytest.raises(DecompressFailed):
            _decompress_body_strict(b"\x8b\x00\x80anything", "br")

    def test_corrupt_gzip_raises(self):
        from scruxy.proxy.routes import _decompress_body_strict, DecompressFailed
        with pytest.raises(DecompressFailed):
            _decompress_body_strict(b"not actually gzipped, bytes here", "gzip")

    def test_no_encoding_passthrough(self):
        from scruxy.proxy.routes import _decompress_body_strict
        assert _decompress_body_strict(b"plain", None) == b"plain"
        assert _decompress_body_strict(b"plain", "") == b"plain"

    def test_unknown_encoding_fails_closed(self):
        # Unsupported encodings (zstd, compress, etc.) MUST fail closed:
        # we cannot produce plaintext for the scrubber, so the caller
        # has to 413/415 rather than forward an opaque body to the LLM.
        from scruxy.proxy.routes import _decompress_body_strict, DecompressFailed
        with pytest.raises(DecompressFailed):
            _decompress_body_strict(b"mystery", "zstd")
        with pytest.raises(DecompressFailed):
            _decompress_body_strict(b"mystery", "compress")

    def test_identity_encoding_passthrough(self):
        from scruxy.proxy.routes import _decompress_body_strict
        # RFC 7231: "identity" is the no-transformation token.
        assert _decompress_body_strict(b"plain", "identity") == b"plain"


class TestIsSSEResponse:
    """Test SSE response detection."""

    def test_sse_content_type(self):
        assert _is_sse_response({"content-type": "text/event-stream"}) is True

    def test_sse_content_type_with_charset(self):
        assert _is_sse_response({"content-type": "text/event-stream; charset=utf-8"}) is True

    def test_json_content_type(self):
        assert _is_sse_response({"content-type": "application/json"}) is False

    def test_empty_headers(self):
        assert _is_sse_response({}) is False

    def test_case_insensitive_header_key(self):
        assert _is_sse_response({"Content-Type": "text/event-stream"}) is True


class TestResolveUpstreamUrl:
    """Test upstream URL resolution."""

    def test_with_provider_upstream_url(self):
        provider = MagicMock()
        provider.upstream_url = "https://api.anthropic.com"
        req = ProxyRequest(
            method="POST", url="http://localhost:8080/v1/messages",
            path="v1/messages", headers={},
        )
        result = _resolve_upstream_url(provider, req)
        assert result == "https://api.anthropic.com/v1/messages"

    def test_with_trailing_slash_on_base(self):
        provider = MagicMock()
        provider.upstream_url = "https://api.anthropic.com/"
        req = ProxyRequest(
            method="POST", url="http://localhost:8080/v1/messages",
            path="v1/messages", headers={},
        )
        result = _resolve_upstream_url(provider, req)
        assert result == "https://api.anthropic.com/v1/messages"

    def test_without_provider_upstream_url(self):
        provider = MagicMock(spec=[])  # No upstream_url attribute
        req = ProxyRequest(
            method="POST", url="https://api.anthropic.com/v1/messages",
            path="v1/messages", headers={},
        )
        result = _resolve_upstream_url(provider, req)
        assert result == "https://api.anthropic.com/v1/messages"

    def test_empty_path(self):
        provider = MagicMock()
        provider.upstream_url = "https://api.anthropic.com"
        req = ProxyRequest(
            method="POST", url="http://localhost:8080/",
            path="", headers={},
        )
        result = _resolve_upstream_url(provider, req)
        assert result == "https://api.anthropic.com"


# ===================================================================
# Tests: Proxy route integration (via httpx.ASGITransport)
# ===================================================================


class TestUnmatchedRequestPassthrough:
    """Test that requests not matching any provider are passed through."""

    @pytest.mark.asyncio
    async def test_unmatched_passthrough(self):
        """Unmatched request is forwarded to upstream as-is."""
        forwarder = _make_mock_forwarder(content=b"ok")
        registry = _make_mock_registry(provider=None)  # No match

        app = _create_test_app(registry=registry, forwarder=forwarder)
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.get("/health")

        assert resp.status_code == 200
        forwarder.forward_raw.assert_called_once()

    @pytest.mark.asyncio
    async def test_unmatched_post_passthrough(self):
        """Unmatched POST request is forwarded to upstream."""
        forwarder = _make_mock_forwarder(content=b"ok")
        registry = _make_mock_registry(provider=None)

        app = _create_test_app(registry=registry, forwarder=forwarder)
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.post("/api/data", content=b'{"test": true}')

        assert resp.status_code == 200
        forwarder.forward_raw.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_registry_passthrough(self):
        """Request without a registry is forwarded as passthrough."""
        forwarder = _make_mock_forwarder(content=b"ok")
        app = _create_test_app(registry=None, forwarder=forwarder)
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.get("/anything")

        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_main_port_returns_404_for_unmatched(self):
        """Requests on the main dashboard port get 404 (not passthrough)."""
        forwarder = _make_mock_forwarder(content=b"ok")
        registry = _make_mock_registry(provider=None)

        app = _create_test_app(registry=registry, forwarder=forwarder)
        app.state.main_listen_port = 8080

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver:8080") as client:
            resp = await client.get("/health")

        assert resp.status_code == 404
        assert "no provider matched" in resp.json()["error"].lower()
        forwarder.forward_raw.assert_not_called()
        forwarder.forward.assert_not_called()

    @pytest.mark.asyncio
    async def test_non_main_port_does_passthrough(self):
        """Requests on non-main ports (e.g. 8081, 8443) get passthrough."""
        forwarder = _make_mock_forwarder(content=b"ok")
        registry = _make_mock_registry(provider=None)

        app = _create_test_app(registry=registry, forwarder=forwarder)
        app.state.main_listen_port = 8080

        transport = httpx.ASGITransport(app=app)
        # Port 8443 != 8080, so passthrough is allowed
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver:8443") as client:
            resp = await client.get("/health")

        assert resp.status_code == 200
        forwarder.forward_raw.assert_called_once()

    @pytest.mark.asyncio
    async def test_passthrough_uses_forward_raw(self):
        """Passthrough uses forward_raw (preserves accept-encoding)."""
        forwarder = _make_mock_forwarder(content=b"ok")
        registry = _make_mock_registry(provider=None)

        app = _create_test_app(registry=registry, forwarder=forwarder)
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.get("/test")

        assert resp.status_code == 200
        forwarder.forward_raw.assert_called_once()
        forwarder.forward.assert_not_called()

    @pytest.mark.asyncio
    async def test_passthrough_preserves_content_encoding(self):
        """Passthrough preserves content-encoding header from upstream."""
        import gzip as _gzip

        original = b'{"compressed": true}'
        compressed = _gzip.compress(original)

        forwarder = _make_mock_forwarder(
            content=compressed,
            headers={
                "content-type": "application/json",
                "content-encoding": "gzip",
            },
        )
        registry = _make_mock_registry(provider=None)

        app = _create_test_app(registry=registry, forwarder=forwarder)
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            resp = await client.get("/test")

        assert resp.status_code == 200
        # content-encoding is preserved in the response
        assert resp.headers.get("content-encoding") == "gzip"
        # httpx client auto-decompresses, proving the gzip bytes are valid
        assert resp.content == original

    @pytest.mark.asyncio
    async def test_passthrough_decompresses_body_for_log(self):
        """Passthrough decompresses response body for the logging tuple."""
        import gzip as _gzip

        original = b'{"logged": true}'
        compressed = _gzip.compress(original)

        forwarder = _make_mock_forwarder(
            content=compressed,
            headers={
                "content-type": "application/json",
                "content-encoding": "gzip",
            },
        )
        registry = _make_mock_registry(provider=None)

        app = _create_test_app(registry=registry, forwarder=forwarder)
        # Enable passthrough log AND opt in to body capture (default off
        # since the round-47 PII-on-disk hardening).
        app.state.passthrough_enabled = True
        app.state.passthrough_capture_bodies = True
        from collections import deque
        app.state.passthrough_log = deque(maxlen=100)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.get("/test")

        assert resp.status_code == 200
        # Log entry should contain the decompressed body
        assert len(app.state.passthrough_log) == 1
        entry = app.state.passthrough_log[0]
        assert "response_body" in entry
        assert "logged" in entry["response_body"]


class TestMatchedRequestScrubAndForward:
    """Test that matched requests are scrubbed, forwarded, and unscrubbed."""

    @pytest.mark.asyncio
    async def test_matched_json_request_scrub_and_unscrub(self):
        """A matched request is scrubbed, forwarded, and the response is unscrubbed."""
        provider = _make_mock_provider(upstream_url="https://api.anthropic.com")
        registry = _make_mock_registry(provider=provider)
        session_store = _make_mock_session_store()
        request_scrubber = _make_mock_request_scrubber(
            scrubbed_body=b'{"message": "Hello REDACTED_EMAIL_1"}',
        )
        # The upstream responds with scrubbed tokens
        forwarder = _make_mock_forwarder(
            content=b'{"response": "I see REDACTED_EMAIL_1"}',
            headers={"content-type": "application/json"},
        )
        response_unscrubber = _make_mock_response_unscrubber(
            unscrubbed_body=b'{"response": "I see john@example.com"}',
        )
        recorder = _make_mock_recorder()

        pipeline = MagicMock()
        app = _create_test_app(
            registry=registry,
            pipeline=pipeline,
            forwarder=forwarder,
            session_store=session_store,
            request_scrubber=request_scrubber,
            response_unscrubber=response_unscrubber,
            recorder=recorder,
        )
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.post(
                "/v1/messages",
                content=b'{"message": "Hello john@example.com"}',
                headers={"content-type": "application/json"},
            )

        assert resp.status_code == 200
        assert b"john@example.com" in resp.content
        # Scrubber was called
        request_scrubber.scrub_request.assert_called_once()
        # Unscrubber was called
        response_unscrubber.unscrub_response.assert_called_once()
        # Session store was called with the correct session ID
        session_store.get_or_create_session.assert_called_once_with("session-abc-123")
        # Recorder was called
        recorder.record_response.assert_called_once()

    @pytest.mark.asyncio
    async def test_matched_request_awaits_async_session_token_map(self):
        """Session-scoped deanonymization should await async session-map providers."""
        provider = _make_mock_provider(upstream_url="https://api.anthropic.com")
        registry = _make_mock_registry(provider=provider)
        shared_map = MagicMock()
        shared_map.unscrub_map = {"REDACTED_EMAIL_1": "shared@example.com"}
        session_view = MagicMock()
        session_view.unscrub_map = {"REDACTED_EMAIL_1": "scoped@example.com"}

        session_store = _make_mock_session_store(token_map=shared_map)
        session_store.get_session_token_map = AsyncMock(return_value=session_view)
        request_scrubber = _make_mock_request_scrubber(
            scrubbed_body=b'{"message": "Hello REDACTED_EMAIL_1"}',
        )
        forwarder = _make_mock_forwarder(
            content=b'{"response": "I see REDACTED_EMAIL_1"}',
            headers={"content-type": "application/json"},
        )
        response_unscrubber = _make_mock_response_unscrubber(
            unscrubbed_body=b'{"response": "I see scoped@example.com"}',
        )

        app = _create_test_app(
            registry=registry,
            pipeline=MagicMock(),
            forwarder=forwarder,
            session_store=session_store,
            request_scrubber=request_scrubber,
            response_unscrubber=response_unscrubber,
        )
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.post(
                "/v1/messages",
                content=b'{"message": "Hello john@example.com"}',
                headers={"content-type": "application/json"},
            )

        assert resp.status_code == 200
        session_store.get_session_token_map.assert_awaited_once_with("session-abc-123")
        assert response_unscrubber.unscrub_response.call_args.kwargs["token_map"] is session_view

    @pytest.mark.asyncio
    async def test_matched_request_uses_scrubbed_body_for_forwarding(self):
        """The forwarder receives the *scrubbed* body, not the original."""
        provider = _make_mock_provider(upstream_url="https://api.example.com")
        registry = _make_mock_registry(provider=provider)
        session_store = _make_mock_session_store()

        scrubbed = b'{"text": "REDACTED_PERSON_1"}'
        request_scrubber = _make_mock_request_scrubber(scrubbed_body=scrubbed)
        forwarder = _make_mock_forwarder(content=b'{"ok": true}')
        response_unscrubber = _make_mock_response_unscrubber(
            unscrubbed_body=b'{"ok": true}',
        )

        pipeline = MagicMock()
        app = _create_test_app(
            registry=registry,
            pipeline=pipeline,
            forwarder=forwarder,
            session_store=session_store,
            request_scrubber=request_scrubber,
            response_unscrubber=response_unscrubber,
        )
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            await client.post(
                "/v1/messages",
                content=b'{"text": "Jane Doe"}',
                headers={"content-type": "application/json"},
            )

        # Check that forwarder received the scrubbed body
        call_kwargs = forwarder.forward.call_args
        forwarded_body = call_kwargs.kwargs.get("body") or (
            call_kwargs.args[3] if len(call_kwargs.args) > 3 else None
        )
        assert forwarded_body == scrubbed

    @pytest.mark.asyncio
    async def test_matched_request_no_scrubber_passthrough_body(self):
        """When no request_scrubber is configured, the body is forwarded as-is."""
        provider = _make_mock_provider(upstream_url="https://api.example.com")
        registry = _make_mock_registry(provider=provider)
        session_store = _make_mock_session_store()
        original_body = b'{"text": "Jane Doe"}'
        forwarder = _make_mock_forwarder(content=b'{"ok": true}')

        app = _create_test_app(
            registry=registry,
            forwarder=forwarder,
            session_store=session_store,
            request_scrubber=None,  # No scrubber
            response_unscrubber=None,
        )
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            await client.post(
                "/v1/messages",
                content=original_body,
                headers={"content-type": "application/json"},
            )

        call_kwargs = forwarder.forward.call_args
        forwarded_body = call_kwargs.kwargs.get("body") or (
            call_kwargs.args[3] if len(call_kwargs.args) > 3 else None
        )
        assert forwarded_body == original_body


class TestJSONResponseUnscrub:
    """Test unscrubbing of non-streaming JSON responses."""

    @pytest.mark.asyncio
    async def test_json_response_unscrubbed(self):
        """A JSON response has its tokens replaced with real values."""
        provider = _make_mock_provider(upstream_url="https://api.example.com")
        registry = _make_mock_registry(provider=provider)
        session_store = _make_mock_session_store()
        request_scrubber = _make_mock_request_scrubber()

        upstream_content = b'{"content": "Hello REDACTED_PERSON_1"}'
        unscrubbed_content = b'{"content": "Hello Jane Smith"}'

        forwarder = _make_mock_forwarder(
            content=upstream_content,
            headers={"content-type": "application/json"},
        )
        response_unscrubber = _make_mock_response_unscrubber(
            unscrubbed_body=unscrubbed_content,
            token_count=1,
        )

        app = _create_test_app(
            registry=registry,
            forwarder=forwarder,
            session_store=session_store,
            request_scrubber=request_scrubber,
            response_unscrubber=response_unscrubber,
        )
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.post(
                "/v1/messages",
                content=b'{"message": "test"}',
                headers={"content-type": "application/json"},
            )

        assert resp.status_code == 200
        assert resp.content == unscrubbed_content

    @pytest.mark.asyncio
    async def test_stream_requested_but_json_upstream_stays_json(self):
        """A streamed JSON upstream response should be buffered and returned as JSON."""
        class _AsyncJSONStream(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield b'{"content": "plain json"}'

            async def aclose(self) -> None:
                return None

        provider = _make_mock_provider(upstream_url="https://api.example.com")
        registry = _make_mock_registry(provider=provider)
        session_store = _make_mock_session_store()
        request_scrubber = _make_mock_request_scrubber(
            scrubbed_body=b'{"stream": true, "message": "test"}',
        )
        forwarder = AsyncMock()
        forwarder.forward = AsyncMock(
            return_value=httpx.Response(
                200,
                headers={"content-type": "application/json"},
                stream=_AsyncJSONStream(),
                request=httpx.Request("POST", "https://api.example.com/v1/messages"),
            )
        )
        response_unscrubber = _make_mock_response_unscrubber(
            unscrubbed_body=b'{"content": "plain json"}',
        )

        app = _create_test_app(
            registry=registry,
            forwarder=forwarder,
            session_store=session_store,
            request_scrubber=request_scrubber,
            response_unscrubber=response_unscrubber,
        )
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.post(
                "/v1/messages",
                content=b'{"stream": true, "message": "test"}',
                headers={"content-type": "application/json"},
            )

        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("application/json")
        assert resp.content == b'{"content": "plain json"}'

    @pytest.mark.asyncio
    async def test_json_response_no_unscrubber_returns_raw(self):
        """Without an unscrubber, the raw upstream response is returned."""
        provider = _make_mock_provider(upstream_url="https://api.example.com")
        registry = _make_mock_registry(provider=provider)
        session_store = _make_mock_session_store()

        upstream_content = b'{"content": "REDACTED_PERSON_1"}'
        forwarder = _make_mock_forwarder(
            content=upstream_content,
            headers={"content-type": "application/json"},
        )

        app = _create_test_app(
            registry=registry,
            forwarder=forwarder,
            session_store=session_store,
            response_unscrubber=None,
        )
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.post(
                "/v1/messages",
                content=b'{"message": "test"}',
                headers={"content-type": "application/json"},
            )

        assert resp.content == upstream_content

    @pytest.mark.asyncio
    async def test_json_response_closes_upstream_on_unscrub_error(self):
        """Round-45 Goldeneye: if response unscrubber raises, the upstream
        streaming connection must still be closed (finally/except path)."""
        import time as _time
        from scruxy.proxy.routes import _handle_json_response, ProxyRequest

        aclose_calls = {"n": 0}

        class _FakeUpstream:
            status_code = 200
            headers = {"content-type": "application/json"}

            async def aread(self):
                return b'{"content": "Hello REDACTED_PERSON_1"}'

            async def aclose(self):
                aclose_calls["n"] += 1

        provider = _make_mock_provider(upstream_url="https://api.example.com")
        token_map = MagicMock()
        token_map.unscrub_map = {"REDACTED_PERSON_1": "Jane"}

        response_unscrubber = MagicMock()
        response_unscrubber.unscrub_response = MagicMock(
            side_effect=RuntimeError("boom")
        )

        proxy_req = ProxyRequest(
            method="POST",
            url="https://api.example.com/v1/messages",
            path="/v1/messages",
            headers={},
            body=b'{}',
        )

        with pytest.raises(RuntimeError, match="boom"):
            await _handle_json_response(
                upstream_resp=_FakeUpstream(),
                resp_headers={"content-type": "application/json"},
                provider=provider,
                token_map=token_map,
                response_unscrubber=response_unscrubber,
                recorder=None,
                session_id="s1",
                proxy_req=proxy_req,
                scrub_result=None,
                request_start=_time.monotonic(),
                request_id="r1",
                stats=None,
                scrub_ms=0.0,
                network_ms=0.0,
                event_bus=None,
            )

        assert aclose_calls["n"] >= 1, (
            "upstream_resp.aclose() was not called when unscrub raised"
        )


class TestSSEResponseStreaming:
    """Test SSE (streaming) response handling."""

    @pytest.mark.asyncio
    async def test_sse_response_streamed(self):
        """An SSE response is streamed back through the unscrubber."""
        provider = _make_mock_provider(upstream_url="https://api.example.com")
        registry = _make_mock_registry(provider=provider)
        session_store = _make_mock_session_store()
        request_scrubber = _make_mock_request_scrubber()
        sse_unscrubber = _make_mock_sse_unscrubber()
        recorder = _make_mock_recorder()

        sse_chunks = [
            b'data: {"type": "content_block_delta", "delta": {"text": "Hello "}}\n\n',
            b'data: {"type": "content_block_delta", "delta": {"text": "world"}}\n\n',
            b"data: [DONE]\n\n",
        ]

        forwarder = _make_mock_forwarder(
            stream_chunks=sse_chunks,
            headers={"content-type": "text/event-stream"},
        )

        app = _create_test_app(
            registry=registry,
            forwarder=forwarder,
            session_store=session_store,
            request_scrubber=request_scrubber,
            sse_unscrubber=sse_unscrubber,
            recorder=recorder,
        )
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.post(
                "/v1/messages",
                content=b'{"message": "test"}',
                headers={
                    "content-type": "application/json",
                    "accept": "text/event-stream",
                },
            )

        # The response should contain all streamed chunks (unscrubbed pass-through
        # since the mock token_map has no tokens to replace)
        assert resp.status_code == 200
        assert b"Hello " in resp.content
        assert b"world" in resp.content

    @pytest.mark.asyncio
    async def test_sse_response_without_unscrubber_streams_raw(self):
        """Without an SSE unscrubber, raw chunks are streamed as-is."""
        provider = _make_mock_provider(upstream_url="https://api.example.com")
        registry = _make_mock_registry(provider=provider)
        session_store = _make_mock_session_store()

        sse_chunks = [b"data: chunk1\n\n", b"data: chunk2\n\n"]

        forwarder = _make_mock_forwarder(
            stream_chunks=sse_chunks,
            headers={"content-type": "text/event-stream"},
        )

        app = _create_test_app(
            registry=registry,
            forwarder=forwarder,
            session_store=session_store,
            sse_unscrubber=None,
        )
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.post(
                "/v1/messages",
                content=b'{"message": "test"}',
                headers={
                    "content-type": "application/json",
                    "accept": "text/event-stream",
                },
            )

        assert b"chunk1" in resp.content
        assert b"chunk2" in resp.content

    @pytest.mark.asyncio
    async def test_sse_fallback_when_upstream_chunked_non_json(self):
        """Round-44 H1: when the client requests streaming and upstream
        returns a 2xx chunked response without a ``text/event-stream``
        content type, the proxy must still use the SSE streaming path
        instead of buffering the response as JSON.
        """
        provider = _make_mock_provider(upstream_url="https://api.example.com")
        registry = _make_mock_registry(provider=provider)
        session_store = _make_mock_session_store()
        request_scrubber = _make_mock_request_scrubber()
        sse_unscrubber = _make_mock_sse_unscrubber()
        recorder = _make_mock_recorder()

        sse_chunks = [
            b'data: {"delta": "streamed"}\n\n',
            b"data: [DONE]\n\n",
        ]

        # Upstream labels the content type incorrectly (text/plain or
        # application/octet-stream), but emits chunked SSE bytes.
        forwarder = _make_mock_forwarder(
            stream_chunks=sse_chunks,
            headers={
                "content-type": "text/plain",
                "transfer-encoding": "chunked",
            },
        )

        app = _create_test_app(
            registry=registry,
            forwarder=forwarder,
            session_store=session_store,
            request_scrubber=request_scrubber,
            sse_unscrubber=sse_unscrubber,
            recorder=recorder,
        )
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.post(
                "/v1/messages",
                content=b'{"message": "test", "stream": true}',
                headers={
                    "content-type": "application/json",
                    "accept": "text/event-stream",
                },
            )

        assert resp.status_code == 200
        # The streamed body must pass through — if the narrow fallback were
        # missing we'd hit the JSON handler and either buffer indefinitely
        # or fail to preserve the chunks.
        assert b"streamed" in resp.content

    @pytest.mark.asyncio
    async def test_no_sse_fallback_for_json_error_response(self):
        """Round-44 H1: streaming clients must still receive JSON errors as
        JSON — the narrow fallback must NOT kick in when content-type is
        application/json, even if transfer-encoding is chunked.
        """
        provider = _make_mock_provider(upstream_url="https://api.example.com")
        registry = _make_mock_registry(provider=provider)
        session_store = _make_mock_session_store()
        request_scrubber = _make_mock_request_scrubber()
        sse_unscrubber = _make_mock_sse_unscrubber()
        recorder = _make_mock_recorder()

        forwarder = _make_mock_forwarder(
            content=b'{"error": "bad request"}',
            status_code=400,
            headers={
                "content-type": "application/json",
                "transfer-encoding": "chunked",
            },
        )

        app = _create_test_app(
            registry=registry,
            forwarder=forwarder,
            session_store=session_store,
            request_scrubber=request_scrubber,
            sse_unscrubber=sse_unscrubber,
            recorder=recorder,
        )
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.post(
                "/v1/messages",
                content=b'{"message": "test", "stream": true}',
                headers={
                    "content-type": "application/json",
                    "accept": "text/event-stream",
                },
            )

        assert resp.status_code == 400
        assert b"bad request" in resp.content
        # Response must remain JSON, not SSE.
        assert "application/json" in resp.headers.get("content-type", "")


class TestErrorHandling:
    """Test error handling when upstream fails or services are unavailable."""

    @pytest.mark.asyncio
    async def test_no_forwarder_returns_503(self):
        """If no forwarder is configured, return 503."""
        app = _create_test_app(forwarder=None)
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.get("/anything")

        assert resp.status_code == 503
        assert "forwarder" in resp.json()["error"].lower()

    @pytest.mark.asyncio
    async def test_upstream_failure_returns_502(self):
        """If the upstream request raises an exception, return 502."""
        provider = _make_mock_provider(upstream_url="https://api.example.com")
        registry = _make_mock_registry(provider=provider)
        session_store = _make_mock_session_store()
        request_scrubber = _make_mock_request_scrubber()

        forwarder = AsyncMock()
        forwarder.forward = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))

        app = _create_test_app(
            registry=registry,
            forwarder=forwarder,
            session_store=session_store,
            request_scrubber=request_scrubber,
        )
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.post(
                "/v1/messages",
                content=b'{"message": "test"}',
                headers={"content-type": "application/json"},
            )

        assert resp.status_code == 502
        assert "upstream" in resp.json()["error"].lower()

    @pytest.mark.asyncio
    async def test_unmatched_request_passthrough(self):
        """If no provider matches, passthrough to upstream."""
        forwarder = _make_mock_forwarder(content=b"ok")
        registry = _make_mock_registry(provider=None)

        app = _create_test_app(registry=registry, forwarder=forwarder)
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.get("/health")

        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_provider_exception_returns_502(self):
        """If the provider's extract_session_id raises, return 502."""
        provider = _make_mock_provider()
        provider.extract_session_id.side_effect = RuntimeError("provider bug")
        registry = _make_mock_registry(provider=provider)
        forwarder = _make_mock_forwarder()

        app = _create_test_app(registry=registry, forwarder=forwarder)
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.post(
                "/v1/messages",
                content=b'{"test": true}',
                headers={"content-type": "application/json"},
            )

        assert resp.status_code == 502
        assert "error" in resp.json()

    @pytest.mark.asyncio
    async def test_upstream_timeout_returns_502(self):
        """If the upstream request times out, return 502."""
        provider = _make_mock_provider(upstream_url="https://api.example.com")
        registry = _make_mock_registry(provider=provider)
        session_store = _make_mock_session_store()
        request_scrubber = _make_mock_request_scrubber()

        forwarder = AsyncMock()
        forwarder.forward = AsyncMock(
            side_effect=httpx.ReadTimeout("Request timed out")
        )

        app = _create_test_app(
            registry=registry,
            forwarder=forwarder,
            session_store=session_store,
            request_scrubber=request_scrubber,
        )
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.post(
                "/v1/messages",
                content=b'{"message": "test"}',
                headers={"content-type": "application/json"},
            )

        assert resp.status_code == 502


class TestRecording:
    """Test that request/response recording is triggered."""

    @pytest.mark.asyncio
    async def test_json_response_is_recorded(self):
        """After a JSON response, the recorder is called."""
        provider = _make_mock_provider(session_id="sess-001")
        registry = _make_mock_registry(provider=provider)
        session_store = _make_mock_session_store()
        request_scrubber = _make_mock_request_scrubber()
        response_unscrubber = _make_mock_response_unscrubber()
        recorder = _make_mock_recorder()

        forwarder = _make_mock_forwarder(
            content=b'{"ok": true}',
            headers={"content-type": "application/json"},
        )

        app = _create_test_app(
            registry=registry,
            forwarder=forwarder,
            session_store=session_store,
            request_scrubber=request_scrubber,
            response_unscrubber=response_unscrubber,
            recorder=recorder,
        )
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            await client.post("/v1/messages", content=b'{"test": true}')

        recorder.record_response.assert_called_once()
        call_kwargs = recorder.record_response.call_args.kwargs
        assert call_kwargs["session_id"] == "sess-001"
        assert call_kwargs["streaming"] is False

    @pytest.mark.asyncio
    async def test_sse_response_is_recorded_after_stream_ends(self):
        """The recorder is called after the SSE stream is fully consumed."""
        provider = _make_mock_provider(session_id="sess-002")
        registry = _make_mock_registry(provider=provider)
        session_store = _make_mock_session_store()
        request_scrubber = _make_mock_request_scrubber()
        sse_unscrubber = _make_mock_sse_unscrubber()
        recorder = _make_mock_recorder()

        sse_chunks = [b"data: event1\n\n", b"data: event2\n\n"]
        forwarder = _make_mock_forwarder(
            stream_chunks=sse_chunks,
            headers={"content-type": "text/event-stream"},
        )

        app = _create_test_app(
            registry=registry,
            forwarder=forwarder,
            session_store=session_store,
            request_scrubber=request_scrubber,
            sse_unscrubber=sse_unscrubber,
            recorder=recorder,
        )
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.post(
                "/v1/messages",
                content=b'{"test": true}',
                headers={"accept": "text/event-stream"},
            )
            # Ensure we consume the response
            _ = resp.content

        recorder.record_response.assert_called_once()
        call_kwargs = recorder.record_response.call_args.kwargs
        assert call_kwargs["session_id"] == "sess-002"
        assert call_kwargs["streaming"] is True

    @pytest.mark.asyncio
    async def test_sse_original_record_marks_truncated_when_scrubbed_source_was_capped(self):
        """Original SSE recordings inherit truncation from the scrubbed source cap."""
        @dataclass
        class _SSEField:
            text_value: str

        token = "REDACTED_VERY_LONG_TOKEN_1234567890"
        restored = "x"
        repeated = token * 600  # > 16k scrubbed chars, but only 600 after deanonymizing

        provider = _make_mock_provider(session_id="sess-003")
        provider.parse_sse_event.side_effect = lambda data: _SSEField(
            text_value=json.loads(data)["delta"]["text"]
        )
        registry = _make_mock_registry(provider=provider)

        token_map = MagicMock()
        token_map.unscrub_map = {token: restored}
        session_store = _make_mock_session_store(token_map=token_map)
        request_scrubber = _make_mock_request_scrubber()
        sse_unscrubber = _make_mock_sse_unscrubber()
        recorder = _make_mock_recorder()

        sse_chunks = [
            f'data: {{"type": "content_block_delta", "delta": {{"text": "{repeated}"}}}}\n\n'.encode(),
            b"data: [DONE]\n\n",
        ]
        forwarder = _make_mock_forwarder(
            stream_chunks=sse_chunks,
            headers={"content-type": "text/event-stream"},
        )

        app = _create_test_app(
            registry=registry,
            forwarder=forwarder,
            session_store=session_store,
            request_scrubber=request_scrubber,
            sse_unscrubber=sse_unscrubber,
            recorder=recorder,
        )
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.post(
                "/v1/messages",
                content=b'{"test": true}',
                headers={"accept": "text/event-stream"},
            )
            _ = resp.content

        call_kwargs = recorder.record_response.call_args.kwargs
        original_record = call_kwargs["body_original"]
        assert original_record["truncated"] is True
        assert original_record["text"].startswith(restored * 100)
        assert len(original_record["text"]) < len(repeated)


class TestProxyRequestModel:
    """Test the ProxyRequest dataclass."""

    def test_creation_minimal(self):
        req = ProxyRequest(method="GET", url="http://localhost/test", path="test", headers={})
        assert req.method == "GET"
        assert req.body is None
        assert req.body_json is None

    def test_creation_with_body(self):
        req = ProxyRequest(
            method="POST",
            url="http://localhost/test",
            path="test",
            headers={"content-type": "application/json"},
            body=b'{"hello": "world"}',
            body_json={"hello": "world"},
        )
        assert req.body == b'{"hello": "world"}'
        assert req.body_json == {"hello": "world"}


class TestMultipleHTTPMethods:
    """Test that the catch-all route handles various HTTP methods."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("method", ["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def test_methods_unmatched_passthrough(self, method: str):
        """Various HTTP methods are passed through when no provider matches."""
        forwarder = _make_mock_forwarder(content=b'{"ok": true}')
        registry = _make_mock_registry(provider=None)

        app = _create_test_app(registry=registry, forwarder=forwarder)
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.request(method, "/test")

        assert resp.status_code == 200


class TestUpstreamStatusCodePreserved:
    """Test that upstream status codes are preserved in the proxy response."""

    @pytest.mark.asyncio
    async def test_unmatched_passthrough_preserves_status(self):
        """Unmatched requests passthrough and preserve upstream status code."""
        forwarder = _make_mock_forwarder(status_code=200, content=b'{"status": "test"}')
        registry = _make_mock_registry(provider=None)

        app = _create_test_app(registry=registry, forwarder=forwarder)
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.get("/test")

        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_status_code_preserved_matched(self):
        """Upstream status codes are preserved for matched requests."""
        provider = _make_mock_provider(upstream_url="https://api.example.com")
        registry = _make_mock_registry(provider=provider)
        session_store = _make_mock_session_store()
        request_scrubber = _make_mock_request_scrubber()
        response_unscrubber = _make_mock_response_unscrubber()

        forwarder = _make_mock_forwarder(
            status_code=429,
            content=b'{"error": "rate limited"}',
            headers={"content-type": "application/json"},
        )

        app = _create_test_app(
            registry=registry,
            forwarder=forwarder,
            session_store=session_store,
            request_scrubber=request_scrubber,
            response_unscrubber=response_unscrubber,
        )
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.post(
                "/v1/messages",
                content=b'{"message": "test"}',
            )

        assert resp.status_code == 429
