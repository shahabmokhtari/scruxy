"""Tests for custom replacement strategies (replacer.py) and TokenMap integration."""
from __future__ import annotations

import sys
import uuid
from pathlib import Path

import pytest

from scruxy.config.models import ReplacementConfig
from scruxy.tokenmap.replacer import (
    DefaultReplacement,
    ReplacementStrategy,
    ScriptReplacement,
    UuidReplacement,
    build_strategies,
)
from scruxy.tokenmap.token_map import TokenMap


# ---------------------------------------------------------------------------
# DefaultReplacement
# ---------------------------------------------------------------------------


class TestDefaultReplacement:
    def test_generates_standard_token(self) -> None:
        s = DefaultReplacement()
        assert s.generate("EMAIL", "a@b.com", 1) == "REDACTED_EMAIL_1"
        assert s.generate("PERSON", "Jane", 5) == "REDACTED_PERSON_5"


# ---------------------------------------------------------------------------
# UuidReplacement
# ---------------------------------------------------------------------------


class TestUuidReplacement:
    def test_generates_valid_uuid4(self) -> None:
        s = UuidReplacement()
        result = s.generate("GUID", "abc-123", 1)
        parsed = uuid.UUID(result, version=4)
        assert str(parsed) == result

    def test_each_call_unique(self) -> None:
        s = UuidReplacement()
        results = {s.generate("GUID", "abc", i) for i in range(10)}
        assert len(results) == 10


# ---------------------------------------------------------------------------
# ScriptReplacement
# ---------------------------------------------------------------------------


class TestScriptReplacement:
    def test_runs_command_and_returns_stdout(self, tmp_path: Path) -> None:
        # Script reads PII from stdin, args are entity_type and count.
        script = tmp_path / "fake.py"
        script.write_text(
            "import sys\n"
            "print(f'FAKE_{sys.argv[1]}_{sys.argv[2]}')\n"
        )
        s = ScriptReplacement(command=f"{sys.executable} {script}", timeout_ms=5000)
        result = s.generate("EMAIL", "a@b.com", 7)
        assert result == "FAKE_EMAIL_7"

    def test_pii_passed_via_stdin(self, tmp_path: Path) -> None:
        """PII is available on stdin, not as an argv argument."""
        script = tmp_path / "read_stdin.py"
        script.write_text(
            "import sys\n"
            "pii = sys.stdin.read().strip()\n"
            "print(f'GOT:{pii}')\n"
        )
        s = ScriptReplacement(command=f"{sys.executable} {script}", timeout_ms=5000)
        result = s.generate("EMAIL", "secret@co.com", 1)
        assert result == "GOT:secret@co.com"

    def test_empty_output_returns_none(self, tmp_path: Path) -> None:
        script = tmp_path / "empty.py"
        script.write_text("print('')\n")
        s = ScriptReplacement(command=f"{sys.executable} {script}", timeout_ms=5000)
        result = s.generate("EMAIL", "a@b.com", 1)
        assert result is None

    def test_output_matching_pii_returns_none(self, tmp_path: Path) -> None:
        script = tmp_path / "echo_pii.py"
        script.write_text("import sys; print(sys.stdin.read().strip())\n")
        s = ScriptReplacement(command=f"{sys.executable} {script}", timeout_ms=5000)
        result = s.generate("EMAIL", "a@b.com", 1)
        assert result is None

    def test_timeout_falls_back_to_default(self, tmp_path: Path) -> None:
        script = tmp_path / "slow.py"
        script.write_text("import time; time.sleep(10)\n")
        s = ScriptReplacement(command=f"{sys.executable} {script}", timeout_ms=100)
        result = s.generate("EMAIL", "a@b.com", 1)
        assert result == "REDACTED_EMAIL_1"

    def test_bad_command_falls_back_to_default(self) -> None:
        s = ScriptReplacement(command="/nonexistent/binary", timeout_ms=1000)
        result = s.generate("EMAIL", "a@b.com", 3)
        assert result == "REDACTED_EMAIL_3"

    def test_nonzero_exit_falls_back_to_default(self, tmp_path: Path) -> None:
        script = tmp_path / "fail.py"
        script.write_text("import sys; print('BAD_TOKEN'); sys.exit(1)\n")
        s = ScriptReplacement(command=f"{sys.executable} {script}", timeout_ms=5000)
        result = s.generate("EMAIL", "a@b.com", 2)
        assert result == "REDACTED_EMAIL_2"

    def test_error_logged_once_per_entity_type(self, tmp_path: Path) -> None:
        """Repeated failures for same entity type log only once."""
        s = ScriptReplacement(command="/nonexistent/binary", timeout_ms=100)
        s.generate("EMAIL", "a@b.com", 1)
        s.generate("EMAIL", "c@d.com", 2)
        # Second call should NOT add to _failure_logged again (already there)
        assert "EMAIL" in s._failure_logged

    def test_bare_python_resolved_to_venv(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """When inside a virtualenv, bare 'python' is resolved to the venv interpreter."""
        # Create a fake venv with a python executable
        if sys.platform == "win32":
            bin_dir = tmp_path / "Scripts"
            fake_python = bin_dir / "python.exe"
        else:
            bin_dir = tmp_path / "bin"
            fake_python = bin_dir / "python"
        bin_dir.mkdir()
        fake_python.write_text("")

        monkeypatch.setattr(sys, "prefix", str(tmp_path))
        monkeypatch.setattr(sys, "base_prefix", str(tmp_path / "base"))  # different → in venv

        s = ScriptReplacement(command="python ~/script.py", timeout_ms=1000)
        assert s._command_parts[0] == str(fake_python)

    def test_bare_python_unchanged_outside_venv(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Outside a virtualenv, bare 'python' is left as-is."""
        monkeypatch.setattr(sys, "prefix", "/usr/local")
        monkeypatch.setattr(sys, "base_prefix", "/usr/local")  # same → no venv

        s = ScriptReplacement(command="python ~/script.py", timeout_ms=1000)
        assert s._command_parts[0] == "python"


# ---------------------------------------------------------------------------
# ReplacementConfig validation
# ---------------------------------------------------------------------------


class TestReplacementConfigValidation:
    def test_literal_rejects_invalid_strategy(self) -> None:
        with pytest.raises(Exception):  # Pydantic ValidationError
            ReplacementConfig(strategy="banana")

    def test_script_requires_command(self) -> None:
        with pytest.raises(Exception):
            ReplacementConfig(strategy="script", command="")

    def test_script_with_command_succeeds(self) -> None:
        cfg = ReplacementConfig(strategy="script", command="echo hi")
        assert cfg.command == "echo hi"


# ---------------------------------------------------------------------------
# build_strategies factory
# ---------------------------------------------------------------------------


class TestBuildStrategies:
    def test_empty_config(self) -> None:
        assert build_strategies({}) == {}

    def test_default_strategy(self) -> None:
        cfg = {"EMAIL": ReplacementConfig(strategy="default")}
        strategies = build_strategies(cfg)
        assert isinstance(strategies["EMAIL"], DefaultReplacement)

    def test_uuid_strategy(self) -> None:
        cfg = {"GUID": ReplacementConfig(strategy="uuid")}
        strategies = build_strategies(cfg)
        assert isinstance(strategies["GUID"], UuidReplacement)

    def test_script_strategy(self) -> None:
        cfg = {"PERSON": ReplacementConfig(strategy="script", command="echo hi", timeout_ms=3000)}
        strategies = build_strategies(cfg)
        s = strategies["PERSON"]
        assert isinstance(s, ScriptReplacement)
        assert s._timeout == 3.0

    def test_multiple_strategies(self) -> None:
        cfg = {
            "GUID": ReplacementConfig(strategy="uuid"),
            "EMAIL": ReplacementConfig(strategy="default"),
        }
        strategies = build_strategies(cfg)
        assert isinstance(strategies["GUID"], UuidReplacement)
        assert isinstance(strategies["EMAIL"], DefaultReplacement)


# ---------------------------------------------------------------------------
# TokenMap integration with custom strategies
# ---------------------------------------------------------------------------


class TestTokenMapWithStrategies:
    def test_default_without_strategies(self) -> None:
        """No strategies configured — behaves exactly as before."""
        tm = TokenMap()
        token = tm.get_or_create_token("a@b.com", "EMAIL")
        assert token == "REDACTED_EMAIL_1"

    def test_uuid_strategy_produces_uuid(self) -> None:
        strategies = {"GUID": UuidReplacement()}
        tm = TokenMap(replacements=strategies)
        token = tm.get_or_create_token("abc-123-def", "GUID")
        assert token is not None
        uuid.UUID(token, version=4)  # validates format

    def test_uuid_deterministic_within_session(self) -> None:
        """Same PII always returns the same UUID token."""
        strategies = {"GUID": UuidReplacement()}
        tm = TokenMap(replacements=strategies)
        t1 = tm.get_or_create_token("abc-123", "GUID")
        t2 = tm.get_or_create_token("abc-123", "GUID")
        assert t1 == t2

    def test_unconfigured_type_uses_default(self) -> None:
        """Entity types without a configured strategy use REDACTED_TYPE_N."""
        strategies = {"GUID": UuidReplacement()}
        tm = TokenMap(replacements=strategies)
        token = tm.get_or_create_token("john@example.com", "EMAIL")
        assert token == "REDACTED_EMAIL_1"

    def test_strategy_returning_none_skips_redaction(self) -> None:
        class SkipStrategy(ReplacementStrategy):
            def generate(self, entity_type: str, pii: str, count: int) -> str | None:
                return None

        tm = TokenMap(replacements={"EMAIL": SkipStrategy()})
        result = tm.get_or_create_token("a@b.com", "EMAIL")
        assert result is None
        assert tm.size == 0

    def test_counter_not_incremented_on_skip(self) -> None:
        """When a strategy returns None, the counter should NOT advance."""
        class SkipStrategy(ReplacementStrategy):
            def generate(self, entity_type: str, pii: str, count: int) -> str | None:
                return None

        tm = TokenMap(replacements={"EMAIL": SkipStrategy()})
        tm.get_or_create_token("a@b.com", "EMAIL")
        assert tm.counters.get("EMAIL") is None  # counter never committed

    def test_counter_contiguous_after_skip_then_default(self) -> None:
        """After a skip, the next real token for a different type starts at 1."""
        class SkipStrategy(ReplacementStrategy):
            def generate(self, entity_type: str, pii: str, count: int) -> str | None:
                return None

        tm = TokenMap(replacements={"EMAIL": SkipStrategy()})
        tm.get_or_create_token("a@b.com", "EMAIL")  # skipped
        token = tm.get_or_create_token("John", "PERSON")  # default
        assert token == "REDACTED_PERSON_1"

    def test_bidirectional_mapping_with_uuid(self) -> None:
        strategies = {"GUID": UuidReplacement()}
        tm = TokenMap(replacements=strategies)
        token = tm.get_or_create_token("abc-123-def", "GUID")
        assert tm.get_pii(token) == "abc-123-def"
        assert tm.get_token("abc-123-def") == token

    def test_from_dict_preserves_strategies(self) -> None:
        strategies = {"GUID": UuidReplacement()}
        tm = TokenMap(replacements=strategies)
        tm.get_or_create_token("abc", "EMAIL")  # uses default
        data = tm.to_dict()

        restored = TokenMap.from_dict(data, replacements=strategies)
        # New GUID should get UUID token
        token = restored.get_or_create_token("some-guid", "GUID")
        assert token is not None
        uuid.UUID(token, version=4)

    def test_collision_falls_back_to_default(self) -> None:
        """If a strategy returns a token already mapped to different PII, fall back."""
        class ConstantStrategy(ReplacementStrategy):
            def generate(self, entity_type: str, pii: str, count: int) -> str:
                return "SAME_TOKEN"

        tm = TokenMap(replacements={"X": ConstantStrategy()})
        t1 = tm.get_or_create_token("pii_a", "X")
        assert t1 == "SAME_TOKEN"
        t2 = tm.get_or_create_token("pii_b", "X")
        # Second call should fall back to REDACTED_X_2 due to collision
        assert t2 == "REDACTED_X_2"


# ---------------------------------------------------------------------------
# Anonymizer integration with skip-redaction
# ---------------------------------------------------------------------------


class TestAnonymizerSkipRedaction:
    def test_skip_strategy_leaves_pii_in_text(self) -> None:
        from scruxy.tokenmap.anonymizer import PiiEntity, anonymize_text

        class SkipStrategy(ReplacementStrategy):
            def generate(self, entity_type: str, pii: str, count: int) -> str | None:
                return None

        tm = TokenMap(replacements={"EMAIL": SkipStrategy()})
        text = "Contact a@b.com for info."
        pii = "a@b.com"
        start = text.index(pii)
        entities = [PiiEntity("EMAIL", start, start + len(pii), 0.9, "test")]
        result = anonymize_text(text, entities, tm)
        assert result == "Contact a@b.com for info."

    def test_mixed_skip_and_replace(self) -> None:
        from scruxy.tokenmap.anonymizer import PiiEntity, anonymize_text

        class SkipStrategy(ReplacementStrategy):
            def generate(self, entity_type: str, pii: str, count: int) -> str | None:
                return None

        tm = TokenMap(replacements={"EMAIL": SkipStrategy()})
        text = "John (a@b.com)"
        entities = [
            PiiEntity("PERSON", 0, 4, 0.9, "test"),
            PiiEntity("EMAIL", 6, 13, 0.9, "test"),
        ]
        result = anonymize_text(text, entities, tm)
        assert "REDACTED_PERSON_1" in result
        assert "a@b.com" in result
