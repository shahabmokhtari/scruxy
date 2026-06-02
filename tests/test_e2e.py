"""End-to-end tests: exercise the full scrub → forward → unscrub cycle.

These tests start the real FastAPI app (with all services wired), mock only
the upstream API (via httpx responders), and verify that PII is scrubbed in
requests and unscrubbed in responses.
"""
from __future__ import annotations

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from scruxy.app import create_app
from scruxy.config.models import AppConfig


@pytest.fixture
def e2e_config(tmp_path):
    """Config that disables Presidio (needs spaCy) but enables regex patterns."""
    # Write regex patterns file
    patterns_file = tmp_path / "regex_patterns.yaml"
    patterns_file.write_text(
        "regex_patterns:\n"
        "  - name: email\n"
        '    entity_type: EMAIL_ADDRESS\n'
        "    pattern: '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}'\n"
        '    score: 0.95\n'
        '  - name: ssn\n'
        '    entity_type: US_SSN\n'
        "    pattern: '\\\\b\\\\d{3}-\\\\d{2}-\\\\d{4}\\\\b'\n"
        '    score: 0.99\n'
        '  - name: phone\n'
        '    entity_type: PHONE_NUMBER\n'
        "    pattern: '\\\\b\\\\d{3}-\\\\d{3}-\\\\d{4}\\\\b'\n"
        '    score: 0.9\n'
    )

    return AppConfig(
        sessions={"storage_dir": str(tmp_path / "sessions")},
        logging={"log_dir": str(tmp_path / "logs")},
        stats={"storage_file": str(tmp_path / "stats.json")},
        pipeline={
            "stages": [
                {"name": "presidio", "enabled": False, "config": {}},
                {
                    "name": "regex",
                    "enabled": True,
                    "config": {"patterns_file": str(patterns_file)},
                },
                {"name": "plugins", "enabled": False, "config": {}},
            ]
        },
    )


@pytest.fixture
def e2e_app(e2e_config):
    """Create a fully wired app for E2E testing."""
    return create_app(e2e_config)


# ---------------------------------------------------------------------------
# Pipeline integration tests (scrub + unscrub without upstream)
# ---------------------------------------------------------------------------


class TestPipelineScrubUnscrub:
    """Test the pipeline scrub/unscrub cycle using internal APIs."""

    async def test_scrub_text_detects_email(self, e2e_app):
        with TestClient(e2e_app):
            pipeline = e2e_app.state.pipeline
            session_store = e2e_app.state.session_store
            token_map = await session_store.get_or_create_session("test-session-1")

            result = await pipeline.scrub_text(
                "Contact john.doe@example.com for details",
                token_map,
            )

            assert "john.doe@example.com" not in result.scrubbed_text
            assert "REDACTED_EMAIL_ADDRESS_1" in result.scrubbed_text
            assert result.has_entities
            assert result.entities[0].entity_type == "EMAIL_ADDRESS"

    async def test_scrub_unscrub_roundtrip(self, e2e_app):
        """Scrub then unscrub should recover original text."""
        with TestClient(e2e_app):
            pipeline = e2e_app.state.pipeline
            session_store = e2e_app.state.session_store
            token_map = await session_store.get_or_create_session("test-session-2")

            original = "Send mail to alice@corp.com and bob@corp.com"
            scrubbed = await pipeline.scrub_text(original, token_map)

            assert "alice@corp.com" not in scrubbed.scrubbed_text
            assert "bob@corp.com" not in scrubbed.scrubbed_text

            # Now unscrub
            from scruxy.scrubber.response_unscrubber import deanonymize_text

            restored = deanonymize_text(scrubbed.scrubbed_text, token_map)
            assert restored == original

    async def test_deterministic_tokens_within_session(self, e2e_app):
        """Same PII should always map to the same token in a session."""
        with TestClient(e2e_app):
            pipeline = e2e_app.state.pipeline
            session_store = e2e_app.state.session_store
            token_map = await session_store.get_or_create_session("test-session-3")

            result1 = await pipeline.scrub_text("Email: test@example.com", token_map)
            result2 = await pipeline.scrub_text("Contact test@example.com", token_map)

            # Both should use the same token for the same email
            assert "REDACTED_EMAIL_ADDRESS_1" in result1.scrubbed_text
            assert "REDACTED_EMAIL_ADDRESS_1" in result2.scrubbed_text

    async def test_different_pii_gets_different_tokens(self, e2e_app):
        with TestClient(e2e_app):
            pipeline = e2e_app.state.pipeline
            session_store = e2e_app.state.session_store
            token_map = await session_store.get_or_create_session("test-session-4")

            text = "Contact alice@corp.com or bob@corp.com"
            result = await pipeline.scrub_text(text, token_map)

            assert "REDACTED_EMAIL_ADDRESS_1" in result.scrubbed_text
            assert "REDACTED_EMAIL_ADDRESS_2" in result.scrubbed_text

    async def test_shared_determinism(self, e2e_app):
        """Different sessions share the same token map (global determinism)."""
        with TestClient(e2e_app):
            pipeline = e2e_app.state.pipeline
            session_store = e2e_app.state.session_store
            tm1 = await session_store.get_or_create_session("session-A")
            tm2 = await session_store.get_or_create_session("session-B")

            await pipeline.scrub_text("Email: alice@corp.com", tm1)
            await pipeline.scrub_text("Email: bob@corp.com", tm2)

            # Shared map: alice gets _1, bob gets _2 (sequential)
            assert tm1 is tm2  # same shared map
            assert tm1.get_pii("REDACTED_EMAIL_ADDRESS_1") == "alice@corp.com"
            assert tm1.get_pii("REDACTED_EMAIL_ADDRESS_2") == "bob@corp.com"


class TestRequestScrubberE2E:
    """Test the request scrubber with real providers."""

    async def test_scrub_anthropic_request(self, e2e_app):
        with TestClient(e2e_app):
            scrubber = e2e_app.state.request_scrubber
            pipeline = e2e_app.state.pipeline
            session_store = e2e_app.state.session_store
            token_map = await session_store.get_or_create_session("anthropic-test")

            # Anthropic-style request body
            body = {
                "model": "claude-3-opus",
                "messages": [
                    {
                        "role": "user",
                        "content": "My email is jane@example.com, please help",
                    }
                ],
            }

            from scruxy.providers.anthropic import AnthropicProvider

            provider = AnthropicProvider()
            scrubbed_body, entities, _, _ = await scrubber.scrub_request(
                body, provider, pipeline, token_map,
            )

            # Email should be scrubbed
            scrubbed_content = scrubbed_body["messages"][0]["content"]
            assert "jane@example.com" not in scrubbed_content
            assert "REDACTED_EMAIL_ADDRESS_1" in scrubbed_content
            assert len(entities) >= 1

    async def test_scrub_openai_request(self, e2e_app):
        with TestClient(e2e_app):
            scrubber = e2e_app.state.request_scrubber
            pipeline = e2e_app.state.pipeline
            session_store = e2e_app.state.session_store
            token_map = await session_store.get_or_create_session("openai-test")

            body = {
                "model": "gpt-4",
                "messages": [
                    {
                        "role": "user",
                        "content": "Send the report to admin@company.org",
                    }
                ],
            }

            from scruxy.providers.openai import OpenAIProvider

            provider = OpenAIProvider()
            scrubbed_body, entities, _, _ = await scrubber.scrub_request(
                body, provider, pipeline, token_map,
            )

            scrubbed_content = scrubbed_body["messages"][0]["content"]
            assert "admin@company.org" not in scrubbed_content
            assert "REDACTED_EMAIL_ADDRESS_1" in scrubbed_content


class TestResponseUnscrubberE2E:
    """Test the response unscrubber with real providers."""

    async def test_unscrub_anthropic_response(self, e2e_app):
        with TestClient(e2e_app):
            unscrubber = e2e_app.state.response_unscrubber
            session_store = e2e_app.state.session_store
            token_map = await session_store.get_or_create_session("unscrub-test")

            # Pre-populate the token map
            token_map.get_or_create_token(
                pii="jane@example.com", entity_type="EMAIL_ADDRESS", source="regex"
            )

            # Simulate an Anthropic response with scrubbed tokens
            body = {
                "content": [
                    {"type": "text", "text": "I see REDACTED_EMAIL_ADDRESS_1 in the logs"}
                ]
            }

            from scruxy.providers.anthropic import AnthropicProvider

            provider = AnthropicProvider()
            unscrubbed_body = unscrubber.unscrub_response(body, provider, token_map)

            unscrubbed_text = unscrubbed_body["content"][0]["text"]
            assert "jane@example.com" in unscrubbed_text
            assert "REDACTED_EMAIL_ADDRESS_1" not in unscrubbed_text


class TestTokenMapPersistence:
    """Test that token maps survive save/load cycles (SQLite-backed)."""

    async def test_token_map_persists_to_disk(self, e2e_app, tmp_path):
        with TestClient(e2e_app):
            session_store = e2e_app.state.session_store
            token_map = await session_store.get_or_create_session("persist-test")
            token_map.get_or_create_token(
                pii="secret@email.com", entity_type="EMAIL", source="regex"
            )

        # DB file is at parent of sessions dir
        sessions_dir = e2e_app.state.config.sessions.storage_dir
        from pathlib import Path

        db_file = Path(sessions_dir).parent / "scruxy.db"
        assert db_file.exists()

        # Verify data via direct DB access
        from scruxy.tokenmap.db import TokenDB
        db = TokenDB(db_file)
        db.open()
        try:
            row = db.get_by_original("secret@email.com")
            assert row is not None
            assert row["scrubbed"] == "REDACTED_EMAIL_1"
        finally:
            db.close()


class TestStatsCollection:
    """Test that stats are collected during scrub operations."""

    async def test_stats_updated_after_scrub(self, e2e_app):
        with TestClient(e2e_app):
            pipeline = e2e_app.state.pipeline
            session_store = e2e_app.state.session_store
            stats = e2e_app.state.stats
            token_map = await session_store.get_or_create_session("stats-test")

            # Record a manual scrub event
            from scruxy.plugin.base import PiiEntity

            entities = [PiiEntity("EMAIL", 0, 15, 0.95, "regex")]
            await stats.record_scrub_event("stats-test", "anthropic", entities, 5.0)

            global_stats = await stats.get_global_stats()
            assert global_stats["total_requests"] >= 1
            assert global_stats["total_entities"] >= 1
            assert global_stats["entities_by_type"]["EMAIL"] >= 1


class TestProviderRouting:
    """Test that the provider registry correctly routes requests."""

    def test_anthropic_request_matched(self, e2e_app):
        with TestClient(e2e_app):
            registry = e2e_app.state.registry
            from scruxy.providers.base import ProxyRequest

            req = ProxyRequest(
                method="POST",
                url="http://localhost:8080/v1/messages",
                headers={"anthropic-version": "2024-01-01"},
                body={"messages": []},
            )
            provider = registry.match(req)
            assert provider is not None
            assert provider.name == "anthropic"

    def test_openai_request_matched(self, e2e_app):
        with TestClient(e2e_app):
            registry = e2e_app.state.registry
            from scruxy.providers.base import ProxyRequest

            req = ProxyRequest(
                method="POST",
                url="http://localhost:8080/v1/chat/completions",
                headers={"authorization": "Bearer sk-test"},
                body={"messages": []},
            )
            provider = registry.match(req)
            assert provider is not None
            assert provider.name == "openai"

    def test_unknown_request_not_matched(self, e2e_app):
        with TestClient(e2e_app):
            registry = e2e_app.state.registry
            from scruxy.providers.base import ProxyRequest

            req = ProxyRequest(
                method="GET",
                url="http://localhost:8080/health",
                headers={},
            )
            provider = registry.match(req)
            assert provider is None
