# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Scruxy** — a standalone, multi-provider, local Python proxy that intercepts LLM API traffic from AI coding assistants (Claude Code, GitHub Copilot), scrubs PII before it leaves the machine, forwards scrubbed requests to upstream APIs, and unscrubs responses so users see original values transparently.

**Status:** Fully implemented and functional. All core modules are built and tested (1,190+ tests).

**Design Spec:** `docs/plans/2026-03-03-scrubbing-proxy-design.md` — the original design reference. The implementation is faithful to this spec with enhancements (SQLite token storage, forward proxy MITM, incremental UI updates, per-stage pipeline profiling, Presidio caching, cross-field second-pass scrub).

## Development Workflow

Always follow this flow for feature work and bug fixes:

1. **Pull latest** from remote before starting any work:
   ```bash
   git checkout development && git pull origin development
   ```
2. **Create a feature branch** from `development` (or use `git worktree` for parallel work):
   ```bash
   git checkout -b feature/my-feature development
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
6. **Push the feature branch** and **create a PR** targeting `development` with a detailed description:
   - What changed and why
   - Testing done (test count, manual verification)
   - Breaking changes (if any)
7. **Review the PR** using 3-agent code review (Opus + GPT-5.4 + Sonnet/Gemini):
   - Run at least **3–5 rounds** of review
   - Fix all high, medium, and low issues found in each round before running the next
   - Only merge when reviewers report no significant issues
8. **Merge the PR** into `development` once all review rounds pass.
9. **Push** after merging:
   ```bash
   git push origin development
   ```

### Branch Strategy

- **`development`** — the active integration branch. All feature branches branch from and merge back into `development`.
- **`main`** — stable release branch. `development` is merged into `main` less frequently (release cadence).
- **Feature branches** — `feature/my-feature`, created from `development`, merged via PR with review.
- Always `git pull` before starting work and `git push` after completing work.

## Tech Stack

- Python 3.11+, FastAPI + uvicorn (async), httpx for upstream forwarding
- Microsoft Presidio + spaCy for NER-based PII detection
- SQLite (via aiosqlite) for persistent token storage; optional in-memory-only mode
- Vanilla HTML/CSS/JS frontend (no build step, no CDN)
- YAML for config, JSONL for recordings
- Optional: mitmproxy for HTTPS interception fallback

## Build & Run Commands

```bash
pip install -e .                              # Install in dev mode
pip install -e ".[mitmproxy]"                 # With mitmproxy fallback
python -m spacy download en_core_web_lg       # Required NLP model

scruxy                               # Start proxy (default: localhost:8080)
scruxy --config path/to/config.yaml  # Custom config
scruxy --mode mitmproxy              # Use mitmproxy fallback

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
- **copilot_chat** — GitHub Copilot chat completions (YAML-only, `*githubcopilot.com/*/chat/completions`)
- **copilot_responses** — GitHub Copilot Responses API (YAML-only, `*githubcopilot.com/*/responses`)

Two extension mechanisms:
1. **YAML-only** (declarative) — drop a `.yaml` in `~/.scruxy/providers/` using JSONPath expressions
2. **Python class** — inherit from `LLMProvider` for complex APIs (e.g. Anthropic content blocks)

Provider router tries `matches()` in priority order (URL pattern → headers → body structure). First match wins; unmatched requests pass through unmodified.

### Scrubbing Pipeline

The pipeline processes text fields sequentially through stages: `pre_filter → whitelist → presidio → regex → file_path → plugins`. Each stage's detections are replaced with placeholders before the next stage runs (priority masking).

**Per-stage profiling:** Each stage is timed with `perf_counter`. Timings are logged at INFO level and stored in recordings as `pipeline_breakdown`.

**Second-pass scrub:** After all fields are processed, `RequestScrubber` re-applies the pre-filter across all fields using the now-complete token map. This catches PII discovered in later fields (e.g., a name found in a user message that also appears as a substring in the system prompt).

**Presidio optimizations:**
- Unused spaCy pipeline components disabled (parser, tagger, lemmatizer, attribute_ruler) — 30-50% faster
- MD5-keyed result cache (256 entries) — identical text skips NER entirely
- Recognizers filtered to configured entity types only — suppresses warnings
- `reconfigure()` method detects config changes and reinitializes

### Token Map

Bidirectional PII ↔ token mapping, stored in a shared `TokenMap` backed by SQLite (`~/.scruxy/scruxy.db`). Format: `REDACTED_{TYPE}_{N}` (deterministic — same PII always maps to same token). In-memory cache with write-through to SQLite. Set `tokens.persistent: false` in config for in-memory-only mode (no SQLite).

### Forward Proxy Routing

When both `ANTHROPIC_BASE_URL` (reverse proxy) and `HTTP_PROXY` (forward proxy) are set:
- Requests to `localhost:{main_port}` are detected and passed through without scrubbing — the reverse proxy handles them
- For matched providers, the forward proxy resolves the provider's `upstream_url` before forwarding (avoids loopback)
- Provider-matched requests are recorded with `proxy_type="forward"` and NOT logged to passthrough

## Platform Notes

- **Windows:** `n_process=1` set automatically for spaCy (uses `spawn`, not `fork`); `WinError 64` TLS failures from parallel CONNECT tunnels logged at DEBUG
- **Cross-platform:** Primary focus Windows, works on macOS/Linux
- All listeners bind to `localhost` by default (IPv4 + IPv6 dual-stack)

## Configuration

Main config: `~/.scruxy/config.yaml`. User-defined regex patterns in `~/.scruxy/regex_patterns.yaml`. Custom plugins in `~/.scruxy/plugins/`. Custom providers in `~/.scruxy/providers/`.

## Design Constraints

- **< 100ms latency overhead** for the scrubbing pipeline (excluding Presidio NER)
- **Deterministic tokens** — same PII → same token globally (shared map)
- **Per-plugin timeout** of 50ms to protect latency budget
- **No LLM calls** for PII detection (Presidio + regex + plugins only)
- Real PII is **never** stored in recordings — only in the token map

## Web UI

Dashboard at `http://localhost:8080/ui/` with pages for:
- **Dashboard** — live stats, latency charts, entity counts, all registered providers
- **Tester** — test the scrubbing pipeline interactively
- **Plugins** — manage detection plugins (built-in + custom)
- **Providers** — view/configure LLM API providers (URL patterns, auth headers, text paths)
- **Tokens** — browse the token map (PII ↔ token mappings)
- **Recordings** — scrubbed request/response pairs with raw/chat/diff views, per-request latency breakdown (scrub → network → unscrub = total), per-stage pipeline timing, collapsible headers, scrubbed/unscrubbed body toggle, FWD/REV proxy badge, auto-refresh via SSE
- **Passthrough** — all proxied requests with method filters (CONNECT hidden by default), expandable body details, persisted filter preferences
- **Logs** — application log viewer (ring buffer, 500 entries) with log level filter chips (WARNING+ by default), PII detection event table; all preferences persisted in localStorage
- **Settings** — edit all config sections + config files (whitelist, regex patterns)
