# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Scruxy** — a standalone, multi-provider, local Python proxy that intercepts LLM API traffic from AI coding assistants (Claude Code, GitHub Copilot), scrubs PII before it leaves the machine, forwards scrubbed requests to upstream APIs, and unscrubs responses so users see original values transparently.

**Status:** Core modules and regression tests are implemented. Use the current test run for counts rather than a fixed count in documentation.

**Design Spec:** `docs/plans/2026-03-03-scrubbing-proxy-design.md` is a historical design reference. For current setup, defaults, supported modes, and privacy limitations, use `README.md` and `docs/configuration.md`. The implementation includes SQLite token storage, built-in forward proxy MITM, incremental UI updates, pipeline profiling, Presidio caching, and cross-field second-pass scrub.

## Development Workflow

Always follow this flow for feature work and bug fixes:

1. **Pull latest** from remote before starting any work:
   ```bash
   git checkout main && git pull --ff-only origin main
   ```
2. **Create a feature branch** from `main` (or use `git worktree` for parallel work):
   ```bash
   git checkout -b feature/my-feature main
   ```
3. **Make changes** — write code, add/update tests, ensure all tests pass:
   ```bash
   pytest                    # Full suite must pass
   pytest tests/test_X.py    # Run targeted tests during development
   ```
4. **Review changes** before committing — check diffs, run linters:
   ```bash
   git diff                  # Review staged changes
   ```
5. **Commit** with descriptive messages and the Copilot co-author trailer:
   ```bash
   git commit -m "feat: short description of change

   Detailed explanation of what changed and why.

   Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
   ```
6. **Push the feature branch** and **create a PR** targeting `main` with a detailed description:
   - What changed and why
   - Testing done (test count, manual verification)
   - Breaking changes (if any)
7. **Review the PR** using 3-agent code review (Opus + GPT-5.4 + Sonnet/Gemini):
   - Run at least **3–5 rounds** of review
   - Fix all high, medium, and low issues found in each round before running the next
   - Only merge when reviewers report no significant issues
8. **Merge the PR** into `main` once all review rounds pass.
9. **Push** after merging:
   ```bash
   git push origin main
   ```

### Branch Strategy

- **`main`** — the public integration branch.
- **Feature branches** — `feature/my-feature`, created from `main`, merged via PR with review.
- Always `git pull` before starting work and `git push` after completing work.

## Tech Stack

- Python 3.11+, FastAPI + uvicorn (async), httpx for upstream forwarding
- Microsoft Presidio + spaCy for NER-based PII detection
- SQLite (via aiosqlite) for persistent token storage; optional in-memory-only mode
- Vanilla HTML/CSS/JS frontend (no build step, no CDN)
- YAML for config, JSONL for recordings
- Built-in CONNECT/TLS interception; legacy mitmproxy mode is retired
- Optional: OpenAI Privacy Filter (`opf`) for local ML detection

## Build & Run Commands

```bash
pip install -e .                              # Install in dev mode
uv sync --group dev                          # Install development dependency group
python -m spacy download en_core_web_lg       # Required NLP model

scruxy                               # Start proxy (default: localhost:8080)
scruxy --config path/to/config.yaml  # Custom config
scruxy --no-forward-proxy --no-https # HTTP reverse proxy only, no CA trust needed
scruxy --no-browser                 # Suppress automatic browser launch

pytest                                        # Run all tests
pytest tests/test_token_map.py                # Run a single test file
pytest tests/test_token_map.py::test_name -v  # Run a single test
```

## Architecture

### Request Flow

```
Harness (Claude Code/Copilot) → Provider Router → Scrubbing Pipeline → Token Map → Upstream Forwarder → Real API
```

### Response Flow (reverse)

```
Real API → Upstream Forwarder → Unscrubber (deanonymize tokens) → Harness
```

For SSE streaming, a rolling buffer with trie-based partial matching handles tokens split across chunk boundaries. Non-parsed SSE events (e.g. `response.completed`, `message_stop`) are deanonymized via recursive JSON-safe deep replacement to prevent token leakage.

### Key Entry Points (`src/scruxy/`)

- `__main__.py` — CLI entry point (`scruxy` command)
- `app.py` — FastAPI app setup, route mounting, lifespan management
- `proxy/routes.py` — catch-all route: identify provider → scrub → forward → unscrub (reverse proxy)
- `proxy/forward_proxy.py` — asyncio HTTP forward proxy with CONNECT MITM for `HTTP_PROXY` usage
- `pipeline/engine.py` — scrubbing orchestrator with per-stage timing (stateless)
- `scrubber/request_scrubber.py` — orchestrates field extraction, pipeline, and second-pass cross-field scrub
- `scrubber/sse_stream_unscrubber.py` — SSE stream deanonymization with rolling buffer + deep JSON fallback
- `tokenmap/service.py` — `ConcurrentSessionStore`: shared token map, SQLite persistence
- `tokenmap/db.py` — `TokenDB`: async SQLite storage for token mappings
- `recording/recorder.py` — JSONL recording with headers, latencies, pipeline breakdown, proxy type
- `ui/log_buffer.py` — in-memory ring-buffer logging handler for the UI logs tab

### Module Overview (`src/scruxy/`)

Core request path: `providers/` (parse) → `pipeline/` (detect PII) → `tokenmap/` (anonymize) → `scrubber/` (apply to request/response)

Supporting: `config/` (Pydantic + YAML), `plugin/` (DetectorPlugin ABC), `recording/` (JSONL per session), `ui/` (web dashboard + SSE + log buffer), `stats/`, `cert/` (CA management)

### Concurrency Model

- Shared token map across all sessions (single `TokenMap` instance)
- Per-session `asyncio.Lock` for token map write operations
- Pipeline stages are stateless and thread-safe
- Presidio `AnalyzerEngine` is thread-safe after initialization; results cached per-text (MD5-keyed, 256 entries)
- Per-session recording files avoid cross-session contention

### Provider System

Built-in providers (loaded automatically):
- **anthropic** — Anthropic Claude API (`/v1/messages`), Python class with content-block handling
- **openai** — OpenAI-compatible chat completions (`/v1/chat/completions`)
- **openai_responses** — OpenAI Responses API (`/v1/responses`)
- **copilot_chat** — GitHub Copilot chat completions (YAML-only; versioned and unversioned paths)
- **copilot_responses** — GitHub Copilot Responses API (YAML-only; versioned and unversioned paths)

Two extension mechanisms:
1. **YAML-only** (declarative) — drop a `.yaml` in `~/.scruxy/providers/` using JSONPath expressions
2. **Python class** — inherit from `LLMProvider` for complex APIs (e.g. Anthropic content blocks)

Provider matching gathers enabled candidates, uses configured matching-header names to disambiguate multiple matches, then falls back to registration order. Unmatched forward-proxy traffic can pass through unmodified; unknown routes on the main reverse-proxy port normally return 404.

### Scrubbing Pipeline

The pipeline processes text fields sequentially through stages: `pre_filter → whitelist → presidio → regex → file_path → plugins`. Each stage's detections are replaced with placeholders before the next stage runs (priority masking).

**Per-stage profiling:** Each stage is timed with `perf_counter`. Timings are logged at INFO level and stored in recordings as `pipeline_breakdown`.

**Second-pass scrub:** After all fields are processed, `RequestScrubber` re-applies the pre-filter across all fields using the now-complete token map. This catches PII discovered in later fields (e.g., a name found in a user message that also appears as a substring in the system prompt).

**Presidio optimizations:**
- Unused spaCy pipeline components disabled (parser, tagger, lemmatizer, attribute_ruler); measure performance on representative inputs
- MD5-keyed result cache (256 entries) — identical text skips NER entirely
- Recognizers filtered to configured entity types; inspect startup warnings for unavailable models or unsupported languages
- `reconfigure()` method detects config changes and reinitializes

### Token Map

Bidirectional PII ↔ token mapping, stored in a shared `TokenMap` backed by SQLite (`~/.scruxy/scruxy.db`). Default format: `REDACTED_{TYPE}_{N}`; an existing mapping is reused across sessions while it exists. Session usage is tracked in SQLite, with session-aware response restoration and cleanup. The in-memory cache writes through to SQLite. Set `tokens.persistent: false` for a memory-only token store; recordings, tester state, logs, and plugin data have separate persistence behavior.

### Forward Proxy Routing

When both `ANTHROPIC_BASE_URL` (reverse proxy) and `HTTP_PROXY` (forward proxy) are set:
- Allowed loopback traffic can be forwarded to local services without scrubbing; the app's own admin/UI surface is protected separately
- For matched providers, the forward proxy resolves the provider's `upstream_url` before forwarding (avoids loopback)
- Provider-matched requests are recorded with `proxy_type="forward"` and NOT logged to passthrough

## Platform Notes

- **Windows:** `n_process=1` set automatically for spaCy (uses `spawn`, not `fork`); `WinError 64` TLS failures from parallel CONNECT tunnels logged at DEBUG
- **Cross-platform:** Primary focus Windows, works on macOS/Linux
- Listener host defaults to `localhost`; IPv4/IPv6 resolution and binding depend on the listener and OS
- Forward proxy is enabled by default on 8081; HTTPS reverse proxy is disabled by default (port 8443 when enabled)
- `--mode mitmproxy` remains parseable for compatibility, but startup warns and migrates it to `primary` for that run

## Configuration

Main config: `~/.scruxy/config.yaml`. User-defined regex patterns in `~/.scruxy/regex_patterns.yaml`. Custom plugins in `~/.scruxy/plugins/`. Custom providers in `~/.scruxy/providers/`.

## Design Constraints

- **Latency target:** < 100ms excluding Presidio NER, not a guaranteed benchmark
- **Mapping reuse:** the same PII reuses its existing token globally until mappings are removed or expired
- **Per-custom-plugin timeout:** 50ms by default; failures/timeouts are logged and results skipped, not sandboxed
- **Local detection:** built-in detectors do not call an upstream LLM; optional OPF inference is local too
- **Recording privacy:** original bodies are off by default; `recording.store_body_original: true` stores original PII. Missed detections and metadata can remain sensitive even in scrubbed recordings
- **Local administration:** the UI exposes PII and edits executable plugins/scripts; keep it on loopback for a trusted single operator

## Web UI

Dashboard at `http://localhost:8080/ui/` with pages for:
- **Dashboard** — live stats, latency charts, entity counts, all registered providers
- **Tester** — locally test selected JSONPath fields and round-trip transformations; shares the token map and persists input
- **Plugins** — manage detection order, built-in/custom detectors, duplicate stages, file-backed configuration, and replacement rules/scripts
- **Providers** — view/configure LLM API providers (URL patterns, auth headers, text paths)
- **Tokens** — browse the token map (PII ↔ token mappings)
- **Recordings** — scrubbed request/response pairs with raw/chat/diff views, per-request latency breakdown (scrub → network → unscrub = total), per-stage pipeline timing, collapsible headers, scrubbed/unscrubbed body toggle, FWD/REV proxy badge, auto-refresh via SSE
- **Passthrough** — non-provider traffic logging (off by default), method filters (CONNECT hidden by default), persisted filter preferences; body capture is separate from the normal logging toggle
- **Logs** — application log viewer (ring buffer, 500 entries) with log level filter chips (WARNING+ by default), PII detection event table; all preferences persisted in localStorage
- **Settings** — edit application configuration sections; restart for listener/storage changes. Whitelist and regex file editors are available from Plugins

The compact stage-toggle page at `/ui/pipeline` is also available; Plugins is the main sidebar pipeline editor. README screenshots use isolated synthetic data; see `docs/screenshots.md`.
