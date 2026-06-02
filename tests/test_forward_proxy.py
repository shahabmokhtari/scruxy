"""Tests for the forward proxy server and CA certificate generation."""
from __future__ import annotations

import asyncio
import httpx
import json
import ssl
import tempfile
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlparse
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from scruxy.cert.ca import CertificateAuthority, CertKeyPair
from scruxy.proxy.forward_proxy import (
    ForwardProxyServer,
    _build_host_header,
    _host_matches_provider,
    _parse_headers,
    _parse_request_line,
    _strip_hop_by_hop,
)


# -----------------------------------------------------------------------
# CA certificate tests
# -----------------------------------------------------------------------


class TestCertificateAuthority:
    """Tests for CA key+cert generation and per-host leaf certs."""

    def test_generate_ca_creates_files(self, tmp_path: Path) -> None:
        ca = CertificateAuthority(cert_dir=tmp_path)
        assert (tmp_path / "scruxy-ca.key").exists()
        assert (tmp_path / "scruxy-ca.pem").exists()

    def test_load_existing_ca(self, tmp_path: Path) -> None:
        ca1 = CertificateAuthority(cert_dir=tmp_path)
        pem1 = ca1.ca_cert_pem
        # Second instantiation should load, not regenerate.
        ca2 = CertificateAuthority(cert_dir=tmp_path)
        assert ca2.ca_cert_pem == pem1

    def test_get_host_cert_returns_pem(self, tmp_path: Path) -> None:
        ca = CertificateAuthority(cert_dir=tmp_path)
        pair = ca.get_host_cert("api.openai.com")
        assert isinstance(pair, CertKeyPair)
        assert b"BEGIN CERTIFICATE" in pair.cert_pem
        assert b"BEGIN RSA PRIVATE KEY" in pair.key_pem

    def test_host_cert_cached(self, tmp_path: Path) -> None:
        ca = CertificateAuthority(cert_dir=tmp_path)
        pair1 = ca.get_host_cert("example.com")
        pair2 = ca.get_host_cert("example.com")
        assert pair1 is pair2  # same object (cached)

    def test_different_hosts_different_certs(self, tmp_path: Path) -> None:
        ca = CertificateAuthority(cert_dir=tmp_path)
        a = ca.get_host_cert("a.example.com")
        b = ca.get_host_cert("b.example.com")
        assert a.cert_pem != b.cert_pem

    def test_ca_cert_path_property(self, tmp_path: Path) -> None:
        ca = CertificateAuthority(cert_dir=tmp_path)
        assert ca.ca_cert_path == tmp_path / "scruxy-ca.pem"

    def test_leaf_cert_has_san(self, tmp_path: Path) -> None:
        """Leaf cert should have the hostname as a SAN entry."""
        from cryptography import x509

        ca = CertificateAuthority(cert_dir=tmp_path)
        pair = ca.get_host_cert("api.anthropic.com")
        cert = x509.load_pem_x509_certificate(pair.cert_pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "api.anthropic.com" in dns_names


# -----------------------------------------------------------------------
# Helper function tests
# -----------------------------------------------------------------------


class TestHelpers:
    """Tests for forward proxy helper functions."""

    def test_parse_request_line_valid(self) -> None:
        method, target, version = _parse_request_line("CONNECT api.openai.com:443 HTTP/1.1")
        assert method == "CONNECT"
        assert target == "api.openai.com:443"
        assert version == "HTTP/1.1"

    def test_parse_request_line_post(self) -> None:
        method, target, version = _parse_request_line(
            "POST http://api.openai.com/v1/chat/completions HTTP/1.1"
        )
        assert method == "POST"
        assert target == "http://api.openai.com/v1/chat/completions"

    def test_parse_request_line_malformed(self) -> None:
        with pytest.raises(ValueError, match="Malformed"):
            _parse_request_line("BAD")

    def test_parse_headers(self) -> None:
        raw = "Host: example.com\r\nContent-Type: application/json\r\nX-Custom: value"
        headers = _parse_headers(raw)
        # R59-1: keys are stored lowercased so case-variant duplicates
        # are correctly detected and downstream lookups never miss
        # because of header casing.
        assert headers["host"] == "example.com"
        assert headers["content-type"] == "application/json"
        assert headers["x-custom"] == "value"

    def test_strip_hop_by_hop(self) -> None:
        headers = {
            "Authorization": "Bearer sk-test",
            "Connection": "keep-alive",
            "Host": "api.openai.com",
            "Content-Type": "application/json",
        }
        cleaned = _strip_hop_by_hop(headers)
        assert "Authorization" in cleaned
        assert "Content-Type" in cleaned
        assert "Connection" not in cleaned
        assert "Host" not in cleaned

    def test_build_host_header_brackets_ipv6_literals(self) -> None:
        parsed = urlparse("http://[2001:db8::1]:8080/hello")
        assert _build_host_header(parsed) == "[2001:db8::1]:8080"

    def test_replace_url_host_preserves_userinfo(self) -> None:
        parsed = urlparse("http://user:pass@example.com/path?x=1")
        from scruxy.proxy.forward_proxy import _replace_url_host

        result = _replace_url_host(parsed, "93.184.216.34", 80)
        assert result == "http://user:pass@93.184.216.34/path?x=1"

    def test_replace_url_host_preserves_encoded_userinfo(self) -> None:
        """Round-45 Goldeneye: percent-encoded passwords must not be
        double-encoded on rewrite (``%40`` must stay ``%40``, not become
        ``%2540``)."""
        from scruxy.proxy.forward_proxy import _replace_url_host

        parsed = urlparse("http://u%2Fs:p%40ss@example.com/path")
        result = _replace_url_host(parsed, "93.184.216.34", 80)
        assert result == "http://u%2Fs:p%40ss@93.184.216.34/path"

        # Password-only with special chars preserved verbatim
        parsed2 = urlparse("https://user:p%3Aass%23w%40rd@host.example/")
        result2 = _replace_url_host(parsed2, "198.51.100.7", 443)
        assert result2 == "https://user:p%3Aass%23w%40rd@198.51.100.7/"

    def test_is_forbidden_blocks_nat64_embedded_private_ipv4(self) -> None:
        import ipaddress
        from scruxy.proxy.forward_proxy import _is_forbidden_proxy_ip

        # NAT64 prefix embedding loopback
        assert _is_forbidden_proxy_ip(ipaddress.ip_address("64:ff9b::127.0.0.1")) is True
        # NAT64 prefix embedding link-local metadata
        assert _is_forbidden_proxy_ip(ipaddress.ip_address("64:ff9b::169.254.169.254")) is True
        # NAT64 prefix embedding RFC1918
        assert _is_forbidden_proxy_ip(ipaddress.ip_address("64:ff9b::10.0.0.1")) is True
        assert _is_forbidden_proxy_ip(ipaddress.ip_address("64:ff9b::192.168.1.1")) is True
        # Any NAT64 address is IETF-reserved and therefore blocked
        assert _is_forbidden_proxy_ip(ipaddress.ip_address("64:ff9b::93.184.216.34")) is True
        # Regular global IPv4 still allowed
        assert _is_forbidden_proxy_ip(ipaddress.ip_address("93.184.216.34")) is False
        # Regular private IPv4 still blocked
        assert _is_forbidden_proxy_ip(ipaddress.ip_address("10.0.0.1")) is True


class TestHostMatchesProvider:
    """Tests for _host_matches_provider."""

    def test_matches_by_upstream_url(self) -> None:
        provider = MagicMock()
        provider.enabled = True
        provider.upstream_url = "https://api.openai.com"
        provider._url_patterns = []
        registry = MagicMock()
        registry.providers = [provider]

        assert _host_matches_provider("api.openai.com", registry) is True
        assert _host_matches_provider("example.com", registry) is False

    def test_matches_by_url_pattern(self) -> None:
        provider = MagicMock()
        provider.enabled = True
        provider.upstream_url = ""
        provider._url_patterns = ["*api.anthropic.com*"]
        registry = MagicMock()
        registry.providers = [provider]

        assert _host_matches_provider("api.anthropic.com", registry) is True

    def test_no_registry(self) -> None:
        assert _host_matches_provider("api.openai.com", None) is False

    def test_disabled_provider_skipped(self) -> None:
        provider = MagicMock()
        provider.enabled = False
        provider.upstream_url = "https://api.openai.com"
        registry = MagicMock()
        registry.providers = [provider]

        assert _host_matches_provider("api.openai.com", registry) is False


# -----------------------------------------------------------------------
# ForwardProxyServer integration-style tests
# -----------------------------------------------------------------------


class TestForwardProxyServer:
    """Tests for the ForwardProxyServer class lifecycle."""

    @pytest.fixture
    def mock_deps(self, tmp_path: Path) -> dict:
        """Create mock dependencies for ForwardProxyServer."""
        ca = CertificateAuthority(cert_dir=tmp_path / "certs")
        return {
            "host": "127.0.0.1",
            "port": 0,  # Let OS assign a port
            "ca": ca,
            "registry": MagicMock(),
            "pipeline": MagicMock(),
            "session_store": MagicMock(),
            "request_scrubber": MagicMock(),
            "response_unscrubber": MagicMock(),
        }

    async def test_start_stop(self, mock_deps: dict) -> None:
        server = ForwardProxyServer(**mock_deps)
        await server.start()
        assert server._server is not None
        await server.stop()
        assert server._server is None

    async def test_plain_http_forward(self, mock_deps: dict) -> None:
        """Test that a plain HTTP forward request is handled."""
        mock_deps["registry"].providers = []
        mock_deps["registry"].match = MagicMock(return_value=None)
        server = ForwardProxyServer(**mock_deps)

        status, headers, body = await server._plain_forward(
            method="GET",
            url="http://httpbin.org/get",
            headers={"Accept": "application/json"},
            body=None,
        )
        # We can't actually reach httpbin in tests, so this will fail with 502
        # This test just verifies the method doesn't crash.
        assert isinstance(status, int)

    async def test_read_head_returns_complete_initial_buffer_without_waiting(self, mock_deps: dict) -> None:
        server = ForwardProxyServer(**mock_deps)
        reader = asyncio.StreamReader()
        reader.feed_eof()

        head, leftover = await server._read_head(
            reader,
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody-bytes",
        )

        assert head == "GET / HTTP/1.1\r\nHost: example.com"
        assert leftover == b"body-bytes"

    async def test_plain_forward_uses_validated_ip_and_preserves_host_header(self, mock_deps: dict) -> None:
        mock_deps["registry"].providers = []
        mock_deps["registry"].match = MagicMock(return_value=None)
        server = ForwardProxyServer(**mock_deps)
        server._client.request = AsyncMock(
            return_value=httpx.Response(
                200,
                headers={"content-type": "text/plain"},
                content=b"ok",
            )
        )

        with patch(
            "socket.getaddrinfo",
            return_value=[(None, None, None, None, ("93.184.216.34", 80))],
        ):
            status, headers, body = await server._plain_forward(
                method="GET",
                url="http://example.com/api",
                headers={"Accept": "application/json"},
                body=None,
            )

        assert status == 200
        assert body == b"ok"
        request_call = server._client.request.await_args.kwargs
        assert request_call["url"] == "http://93.184.216.34/api"
        assert request_call["headers"]["Host"] == "example.com"

    async def test_plain_forward_fails_closed_on_dns_error(self, mock_deps: dict) -> None:
        mock_deps["registry"].providers = []
        mock_deps["registry"].match = MagicMock(return_value=None)
        server = ForwardProxyServer(**mock_deps)
        server._client.request = AsyncMock()

        with patch("socket.getaddrinfo", side_effect=OSError("dns failure")):
            status, headers, body = await server._plain_forward(
                method="GET",
                url="http://example.com/api",
                headers={},
                body=None,
            )

        assert status == 502
        assert b"hostname resolution failed" in body
        server._client.request.assert_not_called()

    async def test_plain_forward_blocks_non_global_ip_ranges(self, mock_deps: dict) -> None:
        mock_deps["registry"].providers = []
        mock_deps["registry"].match = MagicMock(return_value=None)
        server = ForwardProxyServer(**mock_deps)
        server._client.request = AsyncMock()

        with patch(
            "socket.getaddrinfo",
            return_value=[(None, None, None, None, ("100.64.0.1", 80))],
        ):
            status, headers, body = await server._plain_forward(
                method="GET",
                url="http://example.com/api",
                headers={},
                body=None,
            )

        assert status == 403
        assert b"non-public IP" in body
        server._client.request.assert_not_called()

    async def test_plain_forward_preserves_url_embedded_credentials(self, mock_deps: dict) -> None:
        mock_deps["registry"].providers = []
        mock_deps["registry"].match = MagicMock(return_value=None)
        server = ForwardProxyServer(**mock_deps)
        server._client.request = AsyncMock(
            return_value=httpx.Response(
                200,
                headers={"content-type": "text/plain"},
                content=b"ok",
            )
        )

        with patch(
            "socket.getaddrinfo",
            return_value=[(None, None, None, None, ("93.184.216.34", 80))],
        ):
            status, headers, body = await server._plain_forward(
                method="GET",
                url="http://user:pass@example.com/api",
                headers={},
                body=None,
            )

        assert status == 200
        request_call = server._client.request.await_args.kwargs
        assert request_call["url"] == "http://user:pass@93.184.216.34/api"

    async def test_plain_forward_passes_remote_https_through(self, mock_deps: dict) -> None:
        """HTTPS absolute-form passthrough must be forwarded (httpx does
        TLS to the upstream so the original ``https://`` contract is
        preserved end-to-end).  Earlier behavior had a hard 400-reject
        here; that was a regression and is now restored to passthrough.
        """
        mock_deps["registry"].providers = []
        mock_deps["registry"].match = MagicMock(return_value=None)
        server = ForwardProxyServer(**mock_deps)

        # Stub the upstream call so we don't need a real network round-trip.
        upstream_resp = MagicMock()
        upstream_resp.status_code = 200
        upstream_resp.headers = {"Content-Type": "application/json"}
        upstream_resp.content = b'{"models":[]}'
        upstream_resp.reason_phrase = "OK"
        server._client.request = AsyncMock(return_value=upstream_resp)

        with patch(
            "socket.getaddrinfo",
            return_value=[(None, None, None, None, ("93.184.216.34", 443))],
        ):
            status, headers, body = await server._plain_forward(
                method="GET",
                url="https://example.com/api",
                headers={"Accept": "application/json"},
                body=None,
            )

        assert status == 200
        # The upstream was actually called (no 400 reject).
        server._client.request.assert_awaited()
        # And the URL kept its https:// scheme so httpx does TLS upstream.
        called_url = server._client.request.await_args.kwargs.get("url")
        assert called_url is not None and called_url.startswith("https://"), (
            f"upstream URL must remain https:// for end-to-end TLS, got {called_url!r}"
        )

    async def test_scrub_and_forward_awaits_async_session_token_map(self, mock_deps: dict) -> None:
        """Forward-proxy deanonymization should await async session-map providers."""
        provider = MagicMock()
        provider.name = "fake"
        provider.enabled = True
        provider.upstream_url = "https://api.example.com"
        provider.extract_session_id.return_value = "sess-1"

        mock_deps["registry"].providers = [provider]
        mock_deps["registry"].match = MagicMock(return_value=provider)
        shared_map = MagicMock()
        shared_map.unscrub_map = {"REDACTED_PERSON_1": "shared"}
        scoped_map = MagicMock()
        scoped_map.unscrub_map = {"REDACTED_PERSON_1": "Alice"}
        mock_deps["session_store"].get_or_create_session = AsyncMock(return_value=shared_map)
        mock_deps["session_store"].get_session_token_map = AsyncMock(return_value=scoped_map)
        mock_deps["request_scrubber"].scrub_request = AsyncMock(
            return_value=({"message": "hello"}, [], None, set())
        )
        mock_deps["response_unscrubber"].unscrub_response = MagicMock(
            return_value={"message": "Hello Alice"}
        )

        server = ForwardProxyServer(**mock_deps)
        server._client.request = AsyncMock(
            return_value=httpx.Response(
                200,
                headers={"content-type": "application/json"},
                content=b'{"message":"Hello REDACTED_PERSON_1"}',
            )
        )

        status, headers, body = await server._scrub_and_forward(
            method="POST",
            url="https://api.example.com/v1/messages",
            headers={"content-type": "application/json"},
            body=b'{"message":"hello"}',
        )

        assert status == 200
        mock_deps["session_store"].get_session_token_map.assert_awaited_once_with("sess-1")
        assert mock_deps["response_unscrubber"].unscrub_response.call_args.kwargs["token_map"] is scoped_map

    async def test_scrub_and_forward_snapshots_recorder_for_entire_request(self, mock_deps: dict) -> None:
        """A mid-request recorder swap should not split request/response recording."""
        provider = MagicMock()
        provider.name = "fake"
        provider.enabled = True
        provider.upstream_url = "https://api.example.com"
        provider.extract_session_id.return_value = "sess-1"

        token_map = MagicMock()
        token_map.unscrub_map = {}

        mock_deps["registry"].providers = [provider]
        mock_deps["registry"].match = MagicMock(return_value=provider)
        mock_deps["session_store"].get_or_create_session = AsyncMock(return_value=token_map)
        mock_deps["request_scrubber"].scrub_request = AsyncMock(
            return_value=({"message": "hello"}, [], None, set())
        )
        mock_deps["response_unscrubber"].unscrub_response = MagicMock(
            return_value={"message": "hello"}
        )

        server = ForwardProxyServer(**mock_deps)

        first_recorder = MagicMock()
        second_recorder = MagicMock()
        first_recorder.write_metadata = AsyncMock()
        second_recorder.write_metadata = AsyncMock()
        first_recorder.record_response = AsyncMock()
        second_recorder.record_response = AsyncMock()

        async def _swap_recorder(**kwargs):
            server.set_recorder(second_recorder)

        first_recorder.record_request = AsyncMock(side_effect=_swap_recorder)
        second_recorder.record_request = AsyncMock()
        server.set_recorder(first_recorder)

        server._client.request = AsyncMock(
            return_value=httpx.Response(
                200,
                headers={"content-type": "application/json"},
                content=b'{"message":"hello"}',
            )
        )

        status, _, _ = await server._scrub_and_forward(
            method="POST",
            url="https://api.example.com/v1/messages",
            headers={"content-type": "application/json"},
            body=b'{"message":"hello"}',
        )

        assert status == 200
        first_recorder.record_request.assert_awaited_once()
        first_recorder.record_response.assert_awaited_once()
        second_recorder.record_response.assert_not_called()

    async def test_plain_forward_retries_multiple_validated_addresses(self, mock_deps: dict) -> None:
        mock_deps["registry"].providers = []
        mock_deps["registry"].match = MagicMock(return_value=None)
        server = ForwardProxyServer(**mock_deps)

        called_urls: list[str] = []

        async def request_side_effect(method: str, url: str, headers: dict[str, str], content=None):
            called_urls.append(url)
            if len(called_urls) == 1:
                raise httpx.ConnectError("first address failed")
            return httpx.Response(
                200,
                headers={"content-type": "text/plain"},
                content=b"ok",
            )

        server._client.request = AsyncMock(side_effect=request_side_effect)

        with patch(
            "socket.getaddrinfo",
            return_value=[
                (None, None, None, None, ("93.184.216.34", 80)),
                (None, None, None, None, ("93.184.216.35", 80)),
            ],
        ):
            status, headers, body = await server._plain_forward(
                method="GET",
                url="http://example.com/api",
                headers={"Accept": "application/json"},
                body=None,
            )

        assert status == 200
        assert called_urls == [
            "http://93.184.216.34/api",
            "http://93.184.216.35/api",
        ]

    async def test_scrub_and_forward_allows_local_reverse_proxy_hop(self, mock_deps: dict) -> None:
        """Local reverse-proxy passthrough should not be blocked by the SSRF guard."""
        mock_deps["registry"].providers = []
        mock_deps["registry"].match = MagicMock(return_value=None)
        server = ForwardProxyServer(**mock_deps, main_listen_port=8080)
        server._client.request = AsyncMock(
            return_value=httpx.Response(
                200,
                headers={"content-type": "application/json"},
                content=b'{"ok": true}',
            )
        )

        status, headers, body = await server._scrub_and_forward(
            method="GET",
            url="http://localhost:8080/health",
            headers={},
            body=None,
        )

        assert status == 200
        request_call = server._client.request.await_args.kwargs
        assert request_call["url"] == "http://localhost:8080/health"

    async def test_scrub_and_forward_blocks_local_ui_admin_paths(self, mock_deps: dict) -> None:
        """The localhost bypass must not expose the app's UI/admin surface."""
        mock_deps["registry"].providers = []
        mock_deps["registry"].match = MagicMock(return_value=None)
        server = ForwardProxyServer(**mock_deps, main_listen_port=8080)
        server._client.request = AsyncMock()

        status, headers, body = await server._scrub_and_forward(
            method="GET",
            url="http://localhost:8080/ui/api/settings",
            headers={},
            body=None,
        )

        assert status == 403
        assert b"local admin path" in body
        server._client.request.assert_not_called()

    @pytest.mark.parametrize(
        "path",
        [
            "/%75i/api/settings",
            "/%64ocs",
            "/%72edoc",
            "/%6fpenapi.json",
            "//ui//api//settings",
            "/foo/../ui/api/settings",
            "/foo/../docs",
            "/ui;v=1/api/settings",
            "/docs;v=1",
        ],
    )
    async def test_scrub_and_forward_blocks_encoded_local_admin_paths(
        self,
        mock_deps: dict,
        path: str,
    ) -> None:
        """Encoded or normalized variants must not bypass the localhost admin block."""
        mock_deps["registry"].providers = []
        mock_deps["registry"].match = MagicMock(return_value=None)
        server = ForwardProxyServer(**mock_deps, main_listen_port=8080)
        server._client.request = AsyncMock()

        status, headers, body = await server._scrub_and_forward(
            method="GET",
            url=f"http://localhost:8080{path}",
            headers={},
            body=None,
        )

        # R60-4: paths with `..`/`.` traversal segments are now
        # rejected EARLIER with 400 (before the local-admin check).
        # Both 400 (traversal-rejected) and 403 (admin-blocked) are
        # acceptable defenses — the request must NOT reach the
        # upstream forwarder either way.
        assert status in (400, 403), (
            f"Expected 400 or 403, got {status} for path {path!r}"
        )
        if status == 403:
            assert b"local admin path" in body
        server._client.request.assert_not_called()

    async def test_passthrough_tunnel_tries_second_address(self, mock_deps: dict) -> None:
        """CONNECT passthrough should fall back to a later validated address."""
        mock_deps["registry"].providers = []
        mock_deps["registry"].match = MagicMock(return_value=None)
        server = ForwardProxyServer(**mock_deps)

        class Writer:
            def __init__(self) -> None:
                self.writes: list[bytes] = []

            def write(self, data: bytes) -> None:
                self.writes.append(data)

            async def drain(self) -> None:
                return None

        client_reader = asyncio.StreamReader()
        client_reader.feed_eof()
        client_writer = Writer()
        upstream_reader = asyncio.StreamReader()
        upstream_reader.feed_eof()
        upstream_writer = MagicMock()
        upstream_writer.write = MagicMock()
        upstream_writer.drain = AsyncMock()
        upstream_writer.close = MagicMock()
        upstream_writer.wait_closed = AsyncMock()

        connect_calls: list[tuple[str, int]] = []

        async def open_connection_side_effect(host: str, port: int):
            connect_calls.append((host, port))
            if len(connect_calls) == 1:
                raise OSError("first address failed")
            return upstream_reader, upstream_writer

        with patch(
            "socket.getaddrinfo",
            return_value=[
                (None, None, None, None, ("93.184.216.34", 443)),
                (None, None, None, None, ("93.184.216.35", 443)),
            ],
        ), patch(
            "scruxy.proxy.forward_proxy.asyncio.open_connection",
            side_effect=open_connection_side_effect,
        ):
            await server._passthrough_tunnel(
                "example.com",
                443,
                client_reader,
                client_writer,
            )

        assert connect_calls == [
            ("93.184.216.34", 443),
            ("93.184.216.35", 443),
        ]
        assert any(b"200 Connection established" in chunk for chunk in client_writer.writes)

    async def test_forward_proxy_sse_records_unscrubbed_token_count(self, mock_deps: dict) -> None:
        """Streaming recordings should keep diff data and token counts."""
        class Provider:
            name = "fake"
            enabled = True
            upstream_url = "https://api.example.com"

            def extract_session_id(self, proxy_req) -> str:
                return "sess-1"

            def parse_sse_event(self, event_data: str):
                try:
                    data = json.loads(event_data)
                except json.JSONDecodeError:
                    return None
                return SimpleNamespace(text_value=data.get("delta", ""))

            def rebuild_sse_event(self, event_data: str, unscrubbed_text: str) -> str:
                return json.dumps({"delta": unscrubbed_text})

        class Writer:
            def __init__(self) -> None:
                self.chunks: list[bytes] = []

            def write(self, data: bytes) -> None:
                self.chunks.append(data)

            async def drain(self) -> None:
                return None

        class UpstreamResponse:
            def __init__(self) -> None:
                self.status_code = 200
                self.headers = {"content-type": "text/event-stream"}

            async def aiter_bytes(self):
                yield b'data: {"delta":"Hello REDACTED_PERSON_1"}\n'
                yield b"data: [DONE]\n"

            async def aclose(self) -> None:
                return None

        provider = Provider()
        mock_deps["registry"].providers = [provider]
        mock_deps["registry"].match = MagicMock(return_value=provider)
        server = ForwardProxyServer(**mock_deps)

        token_map = MagicMock()
        token_map.unscrub_map = {"REDACTED_PERSON_1": "Alice"}
        token_map._token_version = 1
        mock_deps["session_store"].get_or_create_session = AsyncMock(return_value=token_map)
        mock_deps["session_store"].tag_session_pii = MagicMock()
        mock_deps["session_store"].mark_dirty = MagicMock()

        mock_deps["request_scrubber"].scrub_request = AsyncMock(
            return_value=({"stream": True}, [], None, set())
        )
        recorder = MagicMock()
        recorder.record_request = AsyncMock()
        recorder.record_response = AsyncMock()
        recorder.write_metadata = AsyncMock()
        server._recorder = recorder

        server._client.build_request = MagicMock(return_value=object())
        server._client.send = AsyncMock(return_value=UpstreamResponse())

        writer = Writer()
        status, headers, body = await server._scrub_and_forward(
            method="POST",
            url="https://api.example.com/v1/messages",
            headers={"Accept": "text/event-stream"},
            body=b'{"stream": true}',
            client_writer=writer,
        )

        assert status == -1
        assert headers == {}
        assert body == b""
        assert any(b"Alice" in chunk for chunk in writer.chunks)

        response_call = recorder.record_response.await_args.kwargs
        assert response_call["tokens_unscrubbed"] == 1
        assert response_call["body_original"]["text"].startswith("Hello Alice")


# -----------------------------------------------------------------------
# Round 46: bounded decompression (compression-bomb DoS protection)
# -----------------------------------------------------------------------


class TestBoundedDecompress:
    """Compression-bomb safety: _decompress_body must cap output."""

    def test_gzip_within_limit_decompresses(self) -> None:
        import gzip
        from scruxy.proxy.forward_proxy import _decompress_body

        plain = b"hello world " * 100
        compressed = gzip.compress(plain)
        out = _decompress_body(compressed, "gzip")
        assert out == plain

    def test_gzip_exceeding_limit_raises(self) -> None:
        import gzip
        from scruxy.proxy.forward_proxy import _decompress_body, DecompressLimitExceeded, _MAX_BODY_SIZE

        bomb_size = _MAX_BODY_SIZE + (4 * 1024 * 1024)
        plain = b"A" * bomb_size
        compressed = gzip.compress(plain)
        assert len(compressed) < 1_000_000  # tiny on the wire, huge expanded
        with pytest.raises(DecompressLimitExceeded):
            _decompress_body(compressed, "gzip")

    def test_deflate_exceeding_limit_raises(self) -> None:
        import zlib
        from scruxy.proxy.forward_proxy import _decompress_body, DecompressLimitExceeded, _MAX_BODY_SIZE

        bomb_size = _MAX_BODY_SIZE + (4 * 1024 * 1024)
        plain = b"B" * bomb_size
        compressed = zlib.compress(plain)
        with pytest.raises(DecompressLimitExceeded):
            _decompress_body(compressed, "deflate")

    def test_unknown_encoding_returns_original(self) -> None:
        from scruxy.proxy.forward_proxy import _decompress_body

        body = b"plain bytes"
        assert _decompress_body(body, "weird-codec") is body

    def test_brotli_decompression_fails_closed(self) -> None:
        """Brotli is intentionally rejected in forward-proxy ``_decompress_body``
        because there is no safe streaming output cap.  Matched-provider paths
        then return 413; passthrough preserves the original raw bytes."""
        from scruxy.proxy.forward_proxy import _decompress_body, DecompressLimitExceeded

        with pytest.raises(DecompressLimitExceeded):
            _decompress_body(b"\x8b\x00\x80anything", "br")

    def test_brotli_input_ratio_cap_enforced(self) -> None:
        """The standalone ``_bounded_brotli_decompress`` helper still
        rejects oversize compressed inputs by ratio (kept for any future
        call sites that may want to actually decompress brotli)."""
        try:
            import brotli  # type: ignore[import-untyped]  # noqa: F401
        except ImportError:
            pytest.skip("brotli not installed")

        from scruxy.proxy.forward_proxy import (
            _bounded_brotli_decompress,
            DecompressLimitExceeded,
            _MAX_BODY_SIZE,
            _BROTLI_MAX_RATIO,
        )
        oversize_input = b"\x00" * (_MAX_BODY_SIZE // _BROTLI_MAX_RATIO + 1024)
        with pytest.raises(DecompressLimitExceeded):
            _bounded_brotli_decompress(oversize_input, _MAX_BODY_SIZE)

    def test_brotli_within_ratio_cap_decompresses(self) -> None:
        try:
            import brotli  # type: ignore[import-untyped]
        except ImportError:
            pytest.skip("brotli not installed")

        from scruxy.proxy.forward_proxy import _bounded_brotli_decompress, _MAX_BODY_SIZE
        plain = b"hello world " * 1000
        compressed = brotli.compress(plain)
        out = _bounded_brotli_decompress(compressed, _MAX_BODY_SIZE)
        assert out == plain
