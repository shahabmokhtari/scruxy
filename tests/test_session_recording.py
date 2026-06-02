"""Tests for session recording (per-session JSONL recording of scrubbed data)."""
from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path

import pytest

from scruxy.recording.recorder import SessionRecorder, _append_text, append_capped_text


@pytest.fixture
def recorder(tmp_path: Path) -> SessionRecorder:
    """Create a SessionRecorder rooted in a temporary directory."""
    return SessionRecorder(storage_dir=str(tmp_path))


def test_append_text_without_lock_appends_content(tmp_path: Path) -> None:
    """_append_text should work correctly through the unlocked else-branch."""
    path = tmp_path / "recording.jsonl"
    _append_text(path, '{"n":1}\n')
    _append_text(path, '{"n":2}\n')
    assert path.read_text(encoding="utf-8") == '{"n":1}\n{"n":2}\n'


# ---------------------------------------------------------------------------
# record_request
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_record_request_writes_jsonl_line(recorder: SessionRecorder, tmp_path: Path) -> None:
    """record_request should append a single JSONL line with the expected fields."""
    await recorder.record_request(
        session_id="sess-1",
        provider="anthropic",
        method="POST",
        path="/v1/messages",
        body_scrubbed={"messages": [{"role": "user", "content": "Hello REDACTED_PERSON_1"}]},
        pii_entities_found=1,
        latency_ms=12.5,
    )

    recording_path = tmp_path / "sess-1" / "recording.jsonl"
    assert recording_path.exists()

    lines = recording_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1

    entry = json.loads(lines[0])
    assert entry["dir"] == "request"
    assert entry["provider"] == "anthropic"
    assert entry["method"] == "POST"
    assert entry["path"] == "/v1/messages"
    assert entry["body_scrubbed"]["messages"][0]["content"] == "Hello REDACTED_PERSON_1"
    assert entry["pii_entities_found"] == 1
    assert entry["latency_ms"] == 12.5
    assert "ts" in entry


@pytest.mark.asyncio
async def test_record_request_appends_multiple_lines(
    recorder: SessionRecorder, tmp_path: Path
) -> None:
    """Multiple record_request calls should append to the same JSONL file."""
    for i in range(3):
        await recorder.record_request(
            session_id="sess-multi",
            provider="openai",
            method="POST",
            path="/v1/chat/completions",
            body_scrubbed={"index": i},
            pii_entities_found=i,
            latency_ms=float(i),
        )

    recording_path = tmp_path / "sess-multi" / "recording.jsonl"
    lines = recording_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 3
    for i, line in enumerate(lines):
        entry = json.loads(line)
        assert entry["body_scrubbed"]["index"] == i


# ---------------------------------------------------------------------------
# record_response
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_record_response_writes_jsonl_line(
    recorder: SessionRecorder, tmp_path: Path
) -> None:
    """record_response should append a single JSONL line with the expected fields."""
    await recorder.record_response(
        session_id="sess-resp",
        status=200,
        streaming=True,
        body_scrubbed="[SSE stream - 47 events]",
        tokens_unscrubbed=3,
    )

    recording_path = tmp_path / "sess-resp" / "recording.jsonl"
    assert recording_path.exists()

    lines = recording_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1

    entry = json.loads(lines[0])
    assert entry["dir"] == "response"
    assert entry["status"] == 200
    assert entry["streaming"] is True
    assert entry["body_scrubbed"] == "[SSE stream - 47 events]"
    assert entry["tokens_unscrubbed"] == 3
    assert "ts" in entry


@pytest.mark.asyncio
async def test_record_response_with_dict_body(
    recorder: SessionRecorder, tmp_path: Path
) -> None:
    """record_response should handle dict bodies (non-streaming responses)."""
    await recorder.record_response(
        session_id="sess-dict-resp",
        status=200,
        streaming=False,
        body_scrubbed={"choices": [{"message": {"content": "Hi REDACTED_EMAIL_1"}}]},
        tokens_unscrubbed=1,
    )

    recording_path = tmp_path / "sess-dict-resp" / "recording.jsonl"
    lines = recording_path.read_text(encoding="utf-8").strip().splitlines()
    entry = json.loads(lines[0])
    assert entry["streaming"] is False
    assert isinstance(entry["body_scrubbed"], dict)
    assert entry["body_scrubbed"]["choices"][0]["message"]["content"] == "Hi REDACTED_EMAIL_1"


@pytest.mark.asyncio
async def test_recording_does_not_store_body_original_by_default(
    recorder: SessionRecorder, tmp_path: Path
) -> None:
    """Raw/original bodies should not be persisted unless explicitly enabled."""
    await recorder.record_request(
        session_id="sess-originals",
        provider="anthropic",
        method="POST",
        path="/v1/messages",
        body_scrubbed={"prompt": "Hello REDACTED_PERSON_1"},
        pii_entities_found=1,
        latency_ms=2.0,
        body_original={"prompt": "Hello Alice"},
    )
    await recorder.record_response(
        session_id="sess-originals",
        status=200,
        streaming=False,
        body_scrubbed={"reply": "Hello REDACTED_PERSON_1"},
        tokens_unscrubbed=1,
        body_original={"reply": "Hello Alice"},
    )

    lines = (tmp_path / "sess-originals" / "recording.jsonl").read_text(
        encoding="utf-8"
    ).strip().splitlines()
    request_entry = json.loads(lines[0])
    response_entry = json.loads(lines[1])
    assert "body_original" not in request_entry
    assert "body_original" not in response_entry


@pytest.mark.asyncio
async def test_recording_stores_body_original_when_enabled(tmp_path: Path) -> None:
    """Diff/original data is retained only when the recorder is explicitly opted in."""
    recorder = SessionRecorder(storage_dir=str(tmp_path), store_body_original=True)
    await recorder.record_request(
        session_id="sess-originals",
        provider="anthropic",
        method="POST",
        path="/v1/messages",
        body_scrubbed={"prompt": "Hello REDACTED_PERSON_1"},
        pii_entities_found=1,
        latency_ms=2.0,
        body_original={"prompt": "Hello Alice"},
    )
    await recorder.record_response(
        session_id="sess-originals",
        status=200,
        streaming=False,
        body_scrubbed={"reply": "Hello REDACTED_PERSON_1"},
        tokens_unscrubbed=1,
        body_original={"reply": "Hello Alice"},
    )

    lines = (tmp_path / "sess-originals" / "recording.jsonl").read_text(
        encoding="utf-8"
    ).strip().splitlines()
    request_entry = json.loads(lines[0])
    response_entry = json.loads(lines[1])
    assert request_entry["body_original"] == {"prompt": "Hello Alice"}
    assert response_entry["body_original"] == {"reply": "Hello Alice"}


def test_append_capped_text_limits_growth() -> None:
    """Large SSE streams should only retain a bounded preview in memory."""
    parts: list[str] = []
    current_len = 0

    current_len, truncated = append_capped_text(parts, "abcd", current_len, 6)
    assert current_len == 4
    assert truncated is False

    current_len, truncated = append_capped_text(parts, "efghijkl", current_len, 6)
    assert current_len == 6
    assert truncated is True
    assert "".join(parts) == "abcdef"


# ---------------------------------------------------------------------------
# write_metadata
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_write_metadata_creates_file(recorder: SessionRecorder, tmp_path: Path) -> None:
    """write_metadata should create metadata.json for a new session."""
    await recorder.write_metadata(
        session_id="sess-meta",
        provider="anthropic",
        harness="claude-code",
        agent_info={"model": "claude-opus-4-6", "version": "1.0.0"},
    )

    metadata_path = tmp_path / "sess-meta" / "metadata.json"
    assert metadata_path.exists()

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata["session_id"] == "sess-meta"
    assert metadata["provider"] == "anthropic"
    assert metadata["harness"] == "claude-code"
    assert metadata["request_count"] == 1
    assert metadata["agent_info"] == {"model": "claude-opus-4-6", "version": "1.0.0"}
    assert "started_at" in metadata
    assert "last_activity_at" in metadata


@pytest.mark.asyncio
async def test_write_metadata_updates_existing(recorder: SessionRecorder, tmp_path: Path) -> None:
    """write_metadata should update last_activity_at and increment request_count."""
    await recorder.write_metadata(
        session_id="sess-update",
        provider="anthropic",
        harness="claude-code",
    )

    metadata_path = tmp_path / "sess-update" / "metadata.json"
    first = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert first["request_count"] == 1

    await recorder.write_metadata(
        session_id="sess-update",
        provider="anthropic",
        harness="claude-code",
    )

    second = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert second["request_count"] == 2
    assert second["started_at"] == first["started_at"]


@pytest.mark.asyncio
async def test_write_metadata_shared_across_recorder_instances(tmp_path: Path) -> None:
    """Concurrent recorder swaps must still serialize metadata updates safely."""
    first = SessionRecorder(storage_dir=str(tmp_path))
    second = SessionRecorder(storage_dir=str(tmp_path))

    await asyncio.gather(
        first.write_metadata(
            session_id="sess-shared",
            provider="anthropic",
            harness="claude-code",
        ),
        second.write_metadata(
            session_id="sess-shared",
            provider="anthropic",
            harness="claude-code",
        ),
    )

    metadata = json.loads((tmp_path / "sess-shared" / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["request_count"] == 2


@pytest.mark.asyncio
async def test_write_metadata_without_agent_info(
    recorder: SessionRecorder, tmp_path: Path
) -> None:
    """write_metadata should allow agent_info to be None."""
    await recorder.write_metadata(
        session_id="sess-no-agent",
        provider="openai",
        harness="copilot",
    )

    metadata_path = tmp_path / "sess-no-agent" / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata["agent_info"] is None


@pytest.mark.asyncio
async def test_write_metadata_updates_agent_info(
    recorder: SessionRecorder, tmp_path: Path
) -> None:
    """write_metadata should update agent_info when provided on a subsequent call."""
    await recorder.write_metadata(
        session_id="sess-agent-update",
        provider="anthropic",
        harness="claude-code",
    )
    await recorder.write_metadata(
        session_id="sess-agent-update",
        provider="anthropic",
        harness="claude-code",
        agent_info={"model": "claude-sonnet-4", "version": "2.0.0"},
    )

    metadata_path = tmp_path / "sess-agent-update" / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata["agent_info"] == {"model": "claude-sonnet-4", "version": "2.0.0"}


def test_shared_file_locks_bounded_cleanup(tmp_path: Path) -> None:
    """Shared file locks should fall back to a global lock when the cap is exceeded."""
    original_cap = SessionRecorder._MAX_SHARED_LOCKS
    try:
        SessionRecorder._MAX_SHARED_LOCKS = 5
        recorder = SessionRecorder(storage_dir=str(tmp_path))
        locks = []
        for i in range(7):
            locks.append(recorder._get_file_lock(f"session-{i}"))
        # After exceeding the cap, excess locks should be the fallback
        assert locks[5] is SessionRecorder._fallback_file_lock
        assert locks[6] is SessionRecorder._fallback_file_lock
    finally:
        SessionRecorder._MAX_SHARED_LOCKS = original_cap


def test_shared_file_locks_gc_evicts_unreferenced_locks(tmp_path: Path) -> None:
    """Round-45 Goldeneye: file locks live in a WeakValueDictionary, so once
    no recorder holds a strong ref the entries are GC'd — preventing
    throughput collapse from unbounded growth at the ``_MAX_SHARED_LOCKS``
    cap.
    """
    import gc
    # Reset shared state so this test is independent of siblings.
    SessionRecorder._shared_file_locks.clear()
    recorder1 = SessionRecorder(storage_dir=str(tmp_path))
    recorder1._get_file_lock("s1")
    assert len(SessionRecorder._shared_file_locks) == 1
    # Drop the strong reference; entry should be collectable.
    del recorder1
    gc.collect()
    # After collection, the WeakValueDictionary has no live entries.
    assert len(SessionRecorder._shared_file_locks) == 0


@pytest.mark.asyncio
async def test_shared_index_locks_keyed_by_event_loop(tmp_path: Path) -> None:
    """Round-45 Goldeneye: asyncio.Lock is bound to the loop that created
    it.  Re-using a lock across a closed loop corrupts internals.  The
    index lock must be keyed by ``(storage_key, id(running_loop))`` so a
    second loop gets a fresh lock.
    """
    recorder_a = SessionRecorder(storage_dir=str(tmp_path))
    lock_a = recorder_a._index_lock
    loop_a_id = id(asyncio.get_running_loop())

    # Run a second recorder under a fresh event loop in another thread.
    collected: dict[str, object] = {}

    def _in_new_loop() -> None:
        async def _main() -> None:
            rec = SessionRecorder(storage_dir=str(tmp_path))
            collected["lock"] = rec._index_lock
            collected["loop_id"] = id(asyncio.get_running_loop())

        asyncio.run(_main())

    t = threading.Thread(target=_in_new_loop)
    t.start()
    t.join()

    assert collected["loop_id"] != loop_a_id
    # Different event loops must get different locks to avoid the
    # "lock attached to a different loop" RuntimeError.
    assert collected["lock"] is not lock_a


def test_token_map_utils_importable() -> None:
    """token_map_utils must be importable — guards against untracked file regressions."""
    from scruxy.proxy.token_map_utils import resolve_response_token_map
    assert callable(resolve_response_token_map)


# ---------------------------------------------------------------------------
# get_session_recordings
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_session_recordings_reads_all_entries(recorder: SessionRecorder) -> None:
    """get_session_recordings should return all entries from recording.jsonl."""
    await recorder.record_request(
        session_id="sess-read",
        provider="anthropic",
        method="POST",
        path="/v1/messages",
        body_scrubbed={"msg": "hello"},
        pii_entities_found=0,
        latency_ms=5.0,
    )
    await recorder.record_response(
        session_id="sess-read",
        status=200,
        streaming=False,
        body_scrubbed={"reply": "world"},
        tokens_unscrubbed=0,
    )

    entries = await recorder.get_session_recordings("sess-read")
    assert len(entries) == 2
    assert entries[0]["dir"] == "request"
    assert entries[1]["dir"] == "response"


@pytest.mark.asyncio
async def test_get_session_recordings_empty_when_no_file(recorder: SessionRecorder) -> None:
    """get_session_recordings should return an empty list when no recording exists."""
    entries = await recorder.get_session_recordings("nonexistent-session")
    assert entries == []


# ---------------------------------------------------------------------------
# list_sessions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_sessions_reads_index(recorder: SessionRecorder, tmp_path: Path) -> None:
    """list_sessions should return entries from _index.json."""
    await recorder.update_index(
        session_id="sess-idx-1",
        provider="anthropic",
        harness="claude-code",
        request_count=5,
    )
    await recorder.update_index(
        session_id="sess-idx-2",
        provider="openai",
        harness="copilot",
        request_count=10,
    )

    sessions = await recorder.list_sessions()
    assert len(sessions) == 2
    ids = {s["session_id"] for s in sessions}
    assert ids == {"sess-idx-1", "sess-idx-2"}


@pytest.mark.asyncio
async def test_list_sessions_empty_when_no_index(recorder: SessionRecorder) -> None:
    """list_sessions should return an empty list when _index.json doesn't exist."""
    sessions = await recorder.list_sessions()
    assert sessions == []


# ---------------------------------------------------------------------------
# update_index
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_index_creates_index(recorder: SessionRecorder, tmp_path: Path) -> None:
    """update_index should create _index.json when it does not exist."""
    await recorder.update_index(
        session_id="sess-new",
        provider="anthropic",
        harness="claude-code",
        request_count=1,
    )

    index_path = tmp_path / "_index.json"
    assert index_path.exists()

    entries = json.loads(index_path.read_text(encoding="utf-8"))
    assert len(entries) == 1
    assert entries[0]["session_id"] == "sess-new"
    assert entries[0]["provider"] == "anthropic"
    assert entries[0]["harness"] == "claude-code"
    assert entries[0]["request_count"] == 1
    assert "started_at" in entries[0]


@pytest.mark.asyncio
async def test_update_index_updates_existing_entry(
    recorder: SessionRecorder, tmp_path: Path
) -> None:
    """update_index should update an existing session entry in _index.json."""
    await recorder.update_index(
        session_id="sess-upd",
        provider="anthropic",
        harness="claude-code",
        request_count=1,
    )
    await recorder.update_index(
        session_id="sess-upd",
        provider="anthropic",
        harness="claude-code",
        request_count=5,
    )

    index_path = tmp_path / "_index.json"
    entries = json.loads(index_path.read_text(encoding="utf-8"))
    assert len(entries) == 1
    assert entries[0]["request_count"] == 5
    assert "last_activity_at" in entries[0]


@pytest.mark.asyncio
async def test_update_index_appends_new_session(
    recorder: SessionRecorder, tmp_path: Path
) -> None:
    """update_index should append a new session without overwriting existing ones."""
    await recorder.update_index("sess-a", "anthropic", "claude-code", 1)
    await recorder.update_index("sess-b", "openai", "copilot", 2)

    index_path = tmp_path / "_index.json"
    entries = json.loads(index_path.read_text(encoding="utf-8"))
    assert len(entries) == 2
    assert entries[0]["session_id"] == "sess-a"
    assert entries[1]["session_id"] == "sess-b"


# ---------------------------------------------------------------------------
# Multiple sessions isolation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_multiple_sessions_dont_interfere(
    recorder: SessionRecorder, tmp_path: Path
) -> None:
    """Recording to different sessions must be isolated -- each session gets
    its own directory and JSONL file."""
    await recorder.record_request(
        session_id="sess-alpha",
        provider="anthropic",
        method="POST",
        path="/v1/messages",
        body_scrubbed={"session": "alpha"},
        pii_entities_found=2,
        latency_ms=10.0,
    )
    await recorder.record_request(
        session_id="sess-beta",
        provider="openai",
        method="POST",
        path="/v1/chat/completions",
        body_scrubbed={"session": "beta"},
        pii_entities_found=0,
        latency_ms=8.0,
    )

    alpha_entries = await recorder.get_session_recordings("sess-alpha")
    beta_entries = await recorder.get_session_recordings("sess-beta")

    assert len(alpha_entries) == 1
    assert len(beta_entries) == 1
    assert alpha_entries[0]["body_scrubbed"]["session"] == "alpha"
    assert beta_entries[0]["body_scrubbed"]["session"] == "beta"

    # Check they live in separate directories
    assert (tmp_path / "sess-alpha" / "recording.jsonl").exists()
    assert (tmp_path / "sess-beta" / "recording.jsonl").exists()


@pytest.mark.asyncio
async def test_multiple_sessions_metadata_isolation(
    recorder: SessionRecorder, tmp_path: Path
) -> None:
    """Metadata files for different sessions should be independent."""
    await recorder.write_metadata("sess-x", "anthropic", "claude-code")
    await recorder.write_metadata("sess-y", "openai", "copilot")

    meta_x = json.loads((tmp_path / "sess-x" / "metadata.json").read_text(encoding="utf-8"))
    meta_y = json.loads((tmp_path / "sess-y" / "metadata.json").read_text(encoding="utf-8"))

    assert meta_x["session_id"] == "sess-x"
    assert meta_x["provider"] == "anthropic"
    assert meta_y["session_id"] == "sess-y"
    assert meta_y["provider"] == "openai"


# ---------------------------------------------------------------------------
# Interleaved request/response recording
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_interleaved_request_response(recorder: SessionRecorder) -> None:
    """Requests and responses should be interleaved correctly in the JSONL file."""
    await recorder.record_request(
        session_id="sess-interleave",
        provider="anthropic",
        method="POST",
        path="/v1/messages",
        body_scrubbed={"prompt": "first"},
        pii_entities_found=1,
        latency_ms=15.0,
    )
    await recorder.record_response(
        session_id="sess-interleave",
        status=200,
        streaming=True,
        body_scrubbed="[SSE stream - 10 events]",
        tokens_unscrubbed=2,
    )
    await recorder.record_request(
        session_id="sess-interleave",
        provider="anthropic",
        method="POST",
        path="/v1/messages",
        body_scrubbed={"prompt": "second"},
        pii_entities_found=0,
        latency_ms=8.0,
    )
    await recorder.record_response(
        session_id="sess-interleave",
        status=200,
        streaming=False,
        body_scrubbed={"reply": "done"},
        tokens_unscrubbed=0,
    )

    entries = await recorder.get_session_recordings("sess-interleave")
    assert len(entries) == 4
    assert [e["dir"] for e in entries] == ["request", "response", "request", "response"]


# ---------------------------------------------------------------------------
# Timestamp format validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_request_timestamp_format(recorder: SessionRecorder) -> None:
    """Request record timestamp should be in ISO 8601 format with Z suffix."""
    await recorder.record_request(
        session_id="sess-ts",
        provider="anthropic",
        method="GET",
        path="/health",
        body_scrubbed={},
        pii_entities_found=0,
        latency_ms=0.1,
    )
    entries = await recorder.get_session_recordings("sess-ts")
    ts = entries[0]["ts"]
    assert ts.endswith("Z")
    # Should contain date and time separated by T
    assert "T" in ts


@pytest.mark.asyncio
async def test_response_timestamp_format(recorder: SessionRecorder) -> None:
    """Response record timestamp should be in ISO 8601 format with Z suffix."""
    await recorder.record_response(
        session_id="sess-ts-resp",
        status=200,
        streaming=False,
        body_scrubbed="ok",
        tokens_unscrubbed=0,
    )
    entries = await recorder.get_session_recordings("sess-ts-resp")
    ts = entries[0]["ts"]
    assert ts.endswith("Z")
    assert "T" in ts


# ---------------------------------------------------------------------------
# Session directory creation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_session_directory_created_on_first_recording(
    recorder: SessionRecorder, tmp_path: Path
) -> None:
    """The session directory should be created automatically on the first recording."""
    session_dir = tmp_path / "new-session"
    assert not session_dir.exists()

    await recorder.record_request(
        session_id="new-session",
        provider="anthropic",
        method="POST",
        path="/v1/messages",
        body_scrubbed={},
        pii_entities_found=0,
        latency_ms=1.0,
    )

    assert session_dir.exists()
    assert session_dir.is_dir()


@pytest.mark.asyncio
async def test_session_directory_created_on_metadata_write(
    recorder: SessionRecorder, tmp_path: Path
) -> None:
    """The session directory should be created on metadata write too."""
    session_dir = tmp_path / "meta-session"
    assert not session_dir.exists()

    await recorder.write_metadata("meta-session", "anthropic", "claude-code")

    assert session_dir.exists()
    assert session_dir.is_dir()
