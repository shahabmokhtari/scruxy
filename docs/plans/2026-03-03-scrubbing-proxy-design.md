# Scruxy — Design

> **Implementation status (March 2026):** All core modules are fully implemented and tested (~980+ tests). Notable deviations from original design: token storage uses SQLite instead of JSON files, token map is shared globally (not per-session), forward proxy uses MITM for all CONNECT tunnels (cert is always installed), SSE streaming detection checks both `Accept` header and `stream: true` in request body, default listen host is `localhost` (IPv4+IPv6).

## Problem

AI coding assistants (Claude Code, GitHub Copilot) read files, receive user prompts, and generate code that may contain PII (names, emails, SSNs, phone numbers, etc.). In an enterprise environment, this PII should not reach the upstream LLM. We need a transparent proxy that scrubs PII before it leaves the machine and restores it in responses before the user sees them.

## Solution

**Scruxy** — a standalone, multi-provider, local Python proxy that:

1. **Intercepts** all LLM API traffic from any supported harness (Claude Code, Copilot, and extensible to others)
2. **Scrubs** PII using a configurable pipeline (Microsoft Presidio + regex + custom plugins)
3. **Forwards** scrubbed requests to the real API endpoint with auth pass-through
4. **Unscrubs** responses by reversing token substitutions before returning to the harness
5. **Records** sessions (scrubbed request/response pairs) for debugging and audit
6. **Handles** multiple concurrent agent sessions with isolated, disk-persisted token maps
7. **Provides** a web UI for monitoring, plugin management, pipeline configuration, and statistics

The LLM only ever sees redacted tokens. The user sees real values seamlessly restored.

## Constraints

- **Enterprise environment** — no direct API key access; auth passes through from the harness
- **< 100ms latency overhead** — Presidio + regex pipeline, no LLM calls for detection
- **Deterministic tokens** — same PII always maps to the same token within a session
- **Auto-unscrub** — user sees real PII in output transparently
- **Multi-agent concurrency** — multiple agents (Claude Code + Copilot, or parallel agentic sessions) using the proxy simultaneously with isolated state
- **Cross-platform** — Python-based, primary focus on Windows, works on macOS/Linux
- **Standalone** — no dependency on other projects; single `pip install` + run

---

## Architecture

```
┌────────────────────────────┐  ┌────────────────────────────┐  ┌──────────┐
│  Claude Code Agent 1       │  │  GitHub Copilot Agent       │  │  Agent N │
│  ANTHROPIC_BASE_URL=proxy  │  │  HTTPS_PROXY=proxy          │  │  ...     │
└─────────────┬──────────────┘  └─────────────┬──────────────┘  └────┬─────┘
              │                                │                      │
              └────────────────┬───────────────┘──────────────────────┘
                               │  concurrent HTTP requests
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  Scruxy (localhost:8080)                                        │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Provider Router                                                   │  │
│  │  Identifies provider (Anthropic/OpenAI/Azure/...) from URL + body │  │
│  │  Dispatches to correct request/response parser                    │  │
│  └──────────────────────────┬─────────────────────────────────────────┘  │
│                              │                                           │
│  ┌──────────────────────────▼─────────────────────────────────────────┐  │
│  │  Session Router                                                    │  │
│  │  Extracts harness session ID from headers                         │  │
│  │  Creates or retrieves per-session TokenMap (thread-safe)          │  │
│  └──────────────────────────┬─────────────────────────────────────────┘  │
│                              │                                           │
│  ┌──────────────────────────▼─────────────────────────────────────────┐  │
│  │  Scrubbing Pipeline (shared, stateless — session state in TokenMap)│  │
│  │  ┌──────────┐  ┌──────────┐  ┌────────────────┐                   │  │
│  │  │ Presidio │→ │  Regex   │→ │ Custom Plugins │                   │  │
│  │  └──────────┘  └──────────┘  └────────────────┘                   │  │
│  │            │          │              │                              │  │
│  │            └──────────┴──────────────┘                             │  │
│  │                       │                                            │  │
│  │               Merge & Deduplicate                                  │  │
│  │                       │                                            │  │
│  │               ┌───────▼───────┐                                    │  │
│  │               │ Token Map     │ (per-session, disk-persisted)      │  │
│  │               │ Anonymizer    │                                    │  │
│  │               └───────────────┘                                    │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                              │                                           │
│  ┌──────────────────────────▼─────────────────────────────────────────┐  │
│  │  Upstream Forwarder                                                │  │
│  │  Forward scrubbed request → real API (auth headers intact)        │  │
│  │  Stream SSE response back → unscrub tokens → return to harness    │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                              │                                           │
│  ┌──────────────────────────▼─────────────────────────────────────────┐  │
│  │  Session Recorder                                                  │  │
│  │  Log scrubbed request + response to JSONL per session             │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Web UI (localhost:8080/ui)                                        │  │
│  │  Dashboard · Pipeline · Plugins · Tokens · Sessions · Recordings  │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  Real API endpoints                                                      │
│  Anthropic (api.anthropic.com) · OpenAI (api.openai.com)                │
│  Azure OpenAI · Bedrock · Vertex · Custom                               │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Provider Abstraction

Providers are pluggable modules that define how to parse requests and responses for each LLM API format. Adding a new provider requires no core code changes — just a new provider config (YAML) or provider class (Python).

### Provider Interface

```python
class LLMProvider(ABC):
    """Abstraction for different LLM API providers."""

    name: str                          # e.g., "anthropic", "openai", "azure_openai"
    display_name: str                  # e.g., "Anthropic Claude", "GitHub Copilot"

    @abstractmethod
    def matches(self, request: ProxyRequest) -> bool:
        """Return True if this request belongs to this provider.
        Match by URL pattern, headers, or body structure."""

    @abstractmethod
    def extract_session_id(self, request: ProxyRequest) -> str:
        """Extract the harness session ID from request headers/body."""

    @abstractmethod
    def extract_text_fields(self, body: dict) -> list[TextField]:
        """Return all text fields in the request body that should be scrubbed.
        Each TextField has: json_path, text_value, field_type."""

    @abstractmethod
    def replace_text_fields(self, body: dict, replacements: dict[str, str]) -> dict:
        """Apply scrubbed text back into the request body."""

    @abstractmethod
    def extract_response_text_fields(self, body: dict) -> list[TextField]:
        """Return all text fields in a non-streaming response body."""

    @abstractmethod
    def parse_sse_event(self, event_data: str) -> SSETextField | None:
        """Extract the text field from a single SSE event, or None if no text."""

    @abstractmethod
    def rebuild_sse_event(self, event_data: str, new_text: str) -> str:
        """Replace the text in an SSE event with unscrubbed text."""

    @property
    @abstractmethod
    def default_url_patterns(self) -> list[str]:
        """Glob patterns for URLs this provider handles.
        Used for mitmproxy allow_hosts and request routing."""

    @property
    @abstractmethod
    def auth_headers(self) -> list[str]:
        """Headers that carry auth and must be forwarded untouched."""
```

### Built-in Providers

#### Anthropic (Claude Code)

```yaml
# providers/anthropic.yaml
name: anthropic
display_name: "Anthropic Claude"
url_patterns:
  - "*/v1/messages"
  - "*/v1/messages?*"
match_headers:
  - "anthropic-version"
auth_headers:
  - "authorization"
  - "x-api-key"
  - "anthropic-version"
  - "anthropic-beta"
session_id_headers:
  - "x-session-id"
  - "anthropic-beta"      # fallback: hash this to derive session

request_text_paths:
  - "$.system"                              # string or content block array
  - "$.messages[*].content"                 # string or content block array
  - "$.messages[*].content[*].text"         # text within content blocks
  - "$.messages[*].content[*].content"      # tool result content

response_text_paths:
  - "$.content[*].text"

sse_events:
  text_delta:
    type_match: "content_block_delta"
    delta_type_match: "text_delta"
    text_path: "delta.text"
  input_json_delta:
    type_match: "content_block_delta"
    delta_type_match: "input_json_delta"
    text_path: "delta.partial_json"
```

#### OpenAI-Compatible (GitHub Copilot, Azure OpenAI, OpenAI)

```yaml
# providers/openai.yaml
name: openai
display_name: "OpenAI-Compatible (Copilot, Azure, OpenAI)"
url_patterns:
  - "*/v1/chat/completions"
  - "*/chat/completions"
  - "*openai.azure.com/openai/deployments/*/chat/completions*"
match_headers:
  - "authorization"  # Bearer sk-... or Azure key
auth_headers:
  - "authorization"
  - "api-key"
  - "openai-organization"
session_id_headers:
  - "x-request-id"
  - "x-session-id"
  - "openai-conversation-id"

request_text_paths:
  - "$.messages[*].content"                 # string or content array
  - "$.messages[*].content[*].text"         # for multimodal content arrays

response_text_paths:
  - "$.choices[*].message.content"
  - "$.choices[*].message.tool_calls[*].function.arguments"

sse_events:
  text_delta:
    type_match: null                        # OpenAI SSE doesn't have a type field
    text_path: "choices[0].delta.content"
  tool_delta:
    type_match: null
    text_path: "choices[0].delta.tool_calls[0].function.arguments"
```

#### Adding a New Provider

Two options:

1. **YAML-only** (declarative) — drop a YAML file in `~/.scruxy/providers/`. The generic `YAMLProvider` class interprets it using JSONPath expressions. Works for standard REST + SSE APIs.

2. **Python class** (for complex APIs) — create a `.py` file in `~/.scruxy/providers/` with a class inheriting from `LLMProvider`. Full programmatic control.

### Provider Router

On each incoming request, the router tries each registered provider's `matches()` method in priority order:

1. URL pattern match (fastest)
2. Header presence check
3. Body structure sniffing (fallback)

First match wins. If no provider matches, the request is passed through unmodified (transparent proxy for non-LLM traffic).

---

## Multi-Agent Concurrency

Multiple AI agents can use the proxy simultaneously. Each agent has an isolated session with its own token map.

### How Concurrency Works

```
Claude Code Agent 1 ──┐
                       ├──► Proxy ──► Session "claude-abc-123" ──► Token Map 1
Claude Code Agent 2 ──┤              Session "claude-def-456" ──► Token Map 2
                       │              Session "copilot-xyz-789" ─► Token Map 3
GitHub Copilot ────────┘
```

### Thread Safety

- **FastAPI/uvicorn** handles concurrent requests via async I/O (single event loop + thread pool)
- **TokenMapService** uses a `ConcurrentSessionStore`:
  - Per-session `asyncio.Lock` for token map read/write operations
  - No global lock — sessions don't contend with each other
  - Lock granularity: per-session, not per-request (a session's scrub + unscrub don't race)
- **Pipeline stages** (Presidio, regex, plugins) are stateless — they take text in and return entities. Safe to call concurrently from different sessions.
- **Presidio AnalyzerEngine** is thread-safe after initialization (documented by Presidio team)
- **Session recorder** writes to per-session files — no cross-session file contention

### Session Isolation Guarantees

| Resource | Isolation | Mechanism |
|----------|-----------|-----------|
| Token map | Per-session | Separate `TokenMap` instance per session ID |
| Recording log | Per-session | Separate JSONL file per session |
| Statistics | Aggregated + per-session | Collector tracks both global and per-session stats |
| Pipeline | Shared | Stateless stages, session state passed as parameter |
| Config | Shared | Read-only after startup (except hot-reload via web UI with global lock) |

---

## Token Map — Disk Persistence by Harness Session ID

Token maps are **always persisted to disk**, keyed by the harness session ID. This ensures:
- Token maps survive proxy restarts
- Multiple concurrent sessions have isolated maps
- Sessions can be resumed after interruption
- Audit trail of all PII mappings is maintained

### Storage Layout

```
~/.scruxy/sessions/
├── claude-abc-123/                     # harness session ID
│   ├── token_map.json                  # bidirectional PII ↔ token mapping
│   ├── metadata.json                   # session metadata (provider, start time, agent info)
│   └── recording.jsonl                 # scrubbed request/response log
├── claude-def-456/
│   ├── token_map.json
│   ├── metadata.json
│   └── recording.jsonl
├── copilot-xyz-789/
│   ├── token_map.json
│   ├── metadata.json
│   └── recording.jsonl
└── _index.json                         # session index (for fast UI listing)
```

### token_map.json Format

```json
{
  "version": 1,
  "created_at": "2026-03-03T10:15:00Z",
  "updated_at": "2026-03-03T10:42:30Z",
  "scrub": {
    "john.doe@company.com": "REDACTED_EMAIL_1",
    "Jane Smith": "REDACTED_PERSON_1",
    "555-0123": "REDACTED_PHONE_1"
  },
  "unscrub": {
    "REDACTED_EMAIL_1": "john.doe@company.com",
    "REDACTED_PERSON_1": "Jane Smith",
    "REDACTED_PHONE_1": "555-0123"
  },
  "counters": {
    "EMAIL": 1,
    "PERSON": 1,
    "PHONE": 1
  },
  "stats": {
    "total_scrubbed": 47,
    "by_type": { "EMAIL": 12, "PERSON": 8, "PHONE": 5, "US_SSN": 2 },
    "by_source": { "presidio": 20, "regex": 5, "plugin:codename_detector": 2 }
  }
}
```

### metadata.json Format

```json
{
  "session_id": "claude-abc-123",
  "provider": "anthropic",
  "harness": "claude-code",
  "started_at": "2026-03-03T10:15:00Z",
  "last_activity_at": "2026-03-03T10:42:30Z",
  "request_count": 23,
  "agent_info": {
    "model": "claude-opus-4-6",
    "version": "1.0.0"
  }
}
```

### Write Strategy

- **In-memory cache** with periodic flush to disk (every 5 seconds or after every N operations, configurable)
- **Write-ahead**: new token mappings are appended to disk immediately (append-only log), full map rewritten on flush
- **On graceful shutdown**: flush all in-memory state to disk
- **On startup**: scan sessions directory and load active sessions (those with `last_activity_at` within `max_session_age_hours`)

### Session ID Extraction

The proxy extracts the harness session ID from each request using the provider's `extract_session_id()` method. Providers define which headers to inspect:

| Harness | Session ID Source | Format |
|---------|------------------|--------|
| Claude Code | `x-session-id` header | UUID or similar |
| Claude Code (fallback) | Hash of `authorization` + `anthropic-beta` headers | Derived stable ID |
| GitHub Copilot | `x-request-id` or `x-session-id` header | UUID |
| Copilot (fallback) | Hash of `authorization` header | Derived stable ID |
| Unknown | Auto-generated per unique source IP + auth combo | `auto-{hash}` |

---

## Session Recording

Every request/response pair is recorded (in scrubbed form) for debugging, audit, and replay.

### Recording Format

Per-session JSONL file (`recording.jsonl`), one JSON object per line:

```jsonl
{"ts":"2026-03-03T10:15:00.123Z","dir":"request","provider":"anthropic","method":"POST","path":"/v1/messages","body_scrubbed":{...},"pii_entities_found":5,"latency_ms":23}
{"ts":"2026-03-03T10:15:02.456Z","dir":"response","status":200,"streaming":true,"body_scrubbed":"[SSE stream - 47 events]","tokens_unscrubbed":3}
```

### What Is Recorded

| Field | Request | Response |
|-------|---------|----------|
| Timestamp | Yes | Yes |
| Provider | Yes | Yes |
| HTTP method/path/status | Yes | Yes |
| **Scrubbed** body | Full JSON body after scrubbing | Full response (or SSE event summary) after unscrubbing |
| PII entities found | Count + types | — |
| Tokens unscrubbed | — | Count + types |
| Pipeline latency | Scrub latency (ms) | Unscrub latency (ms) |

**Security**: Real PII values are **never** recorded. Only scrubbed content and token references appear in recording files. The token_map.json is the only file containing the real ↔ token mapping, and it can be encrypted at rest (optional).

### Recording in the Web UI

New UI page: **Session Recordings** (`/ui/recordings`):
- Browse sessions by date, provider, harness
- View individual request/response pairs in a timeline
- Filter by entity type, provider
- Replay: resend a scrubbed request to test pipeline changes
- Export session as HAR-like format or raw JSONL

---

## Interception Layer

Two interception modes. The proxy auto-detects which to use, with user override.

### Primary Mode: Reverse Proxy (via env vars)

A FastAPI HTTP server that acts as a transparent reverse proxy:

- Listens on `127.0.0.1:8080`
- All paths are proxied to the configured upstream URL
- The Provider Router identifies and processes LLM API calls; non-LLM calls pass through unchanged
- Auth headers forwarded untouched

**Setup per harness:**

| Harness | Environment Variable | Value |
|---------|---------------------|-------|
| Claude Code | `ANTHROPIC_BASE_URL` | `http://127.0.0.1:8080` |
| GitHub Copilot | `OPENAI_BASE_URL` or `HTTPS_PROXY` | `http://127.0.0.1:8080` |
| Custom | Per-provider env var | `http://127.0.0.1:8080` |

Can also be configured in `~/.claude/settings.json` (for Claude Code) or equivalent Copilot config.

**Advantage:** Zero OS-level changes, no cert needed, lowest latency (~1-5ms overhead).

### Fallback Mode: mitmproxy Transparent Interception

If the enterprise environment locks the base URL env vars, fall back to mitmproxy:

- Embedded mitmproxy runs as a regular HTTPS proxy on `127.0.0.1:8081`
- `allow_hosts` assembled from all registered providers' URL patterns — only LLM API traffic is decrypted
- All other HTTPS traffic passes through as opaque tunnels
- Traffic routed via `HTTPS_PROXY=http://127.0.0.1:8081` or Windows system proxy

**Auto Certificate Management:**

On startup (mitmproxy mode):
1. Check if mitmproxy CA cert exists (`~/.mitmproxy/mitmproxy-ca-cert.cer`)
2. If not, mitmproxy generates it on first run
3. Auto-install CA cert to system trust store:

| Platform | Install Command | Uninstall Command |
|----------|----------------|-------------------|
| Windows | `certutil -addstore root %USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer` | `certutil -delstore root "mitmproxy"` |
| macOS | `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem` | `security remove-trusted-cert -d ~/.mitmproxy/mitmproxy-ca-cert.pem` |
| Linux | Copy to `/usr/local/share/ca-certificates/mitmproxy-ca.crt` + `update-ca-certificates` | Remove + `update-ca-certificates` |

4. Prompt for admin elevation if needed (UAC on Windows, sudo on others)
5. Log cert fingerprint for audit trail
6. Set `NODE_EXTRA_CA_CERTS` env var for Node.js-based tools (Copilot)

On shutdown (or uninstall):
1. Auto-remove CA cert from system trust store (reverse of install)
2. Clean up env vars
3. Optionally delete `~/.mitmproxy/` directory

**Signal handling:** Register `atexit` and signal handlers (SIGINT, SIGTERM) to ensure cert cleanup runs even on unexpected exit. On Windows, also handle console close events via `SetConsoleCtrlHandler`.

**Latency:** ~5-15ms overhead (mitmproxy TLS + addon processing). Acceptable for fallback.

---

## Scrubbing Pipeline

The pipeline is a chain of detectors that run in sequence. Each detector produces a list of `PiiEntity` results. Results are merged, deduplicated (overlapping spans resolved by highest confidence), and then anonymized via the Token Map.

**The pipeline is stateless** — session state (token map) is passed as a parameter. This makes it safe to call from multiple concurrent sessions.

### Pipeline Flow

```
Input text
    │
    ▼
┌─────────────────┐
│ Presidio Analyzer│ → List[PiiEntity] (PERSON, EMAIL, SSN, PHONE, etc.)
└────────┬────────┘
         ▼
┌─────────────────┐
│ Regex Engine     │ → List[PiiEntity] (custom patterns: employee IDs, internal URLs, etc.)
└────────┬────────┘
         ▼
┌─────────────────┐
│ Custom Plugins   │ → List[PiiEntity] (user-provided detection logic)
└────────┬────────┘
         ▼
┌─────────────────┐
│ Merge & Dedup    │ → Resolve overlapping spans (highest confidence wins)
└────────┬────────┘
         ▼
┌─────────────────┐
│ Token Anonymizer │ → Replace PII spans with deterministic tokens (using session TokenMap)
└─────────────────┘
         ▼
    Scrubbed text
```

### Stage 1: Microsoft Presidio

Presidio is the primary PII detection engine. It provides high-quality NER-based detection for common PII types.

**Setup (one-time at startup):**

```python
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

provider = NlpEngineProvider(nlp_configuration={
    "nlp_engine_name": "spacy",
    "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}]
})
analyzer = AnalyzerEngine(
    nlp_engine=provider.create_engine(),
    supported_languages=["en"]
)
```

**Per-request:**

```python
results = analyzer.analyze(
    text=text,
    language="en",
    score_threshold=0.5,  # configurable via web UI
    entities=None  # detect all; or restrict to configured entity list
)
# → [RecognizerResult(entity_type='PERSON', start=5, end=15, score=0.85), ...]
```

**Presidio entities detected out of the box:**
- Global: `CREDIT_CARD`, `CRYPTO`, `DATE_TIME`, `EMAIL_ADDRESS`, `IBAN_CODE`, `IP_ADDRESS`, `LOCATION`, `PERSON`, `PHONE_NUMBER`, `URL`
- US: `US_BANK_NUMBER`, `US_DRIVER_LICENSE`, `US_ITIN`, `US_PASSPORT`, `US_SSN`
- Plus 20+ country-specific entities (UK, Spain, Italy, India, Australia, etc.)

**spaCy model choice** (configurable):

| Model | Size | Latency (~1000 words) | Accuracy | Use case |
|-------|------|----------------------|----------|----------|
| `en_core_web_sm` | 12 MB | ~5-15ms | Lower | Fast pipeline, regex-heavy detection |
| `en_core_web_lg` | 560 MB | ~20-50ms | Good | Default — best latency/accuracy balance |
| `en_core_web_trf` | 440 MB | ~100-300ms | Best | When accuracy is critical (may exceed 100ms budget) |

**Recommendation:** Default to `en_core_web_lg`. Allow override via config. Cold start loads the model (~2-5 seconds) once at startup.

**Windows note:** Set `n_process=1` for spaCy on Windows (multiprocessing uses `spawn`, not `fork`).

### Stage 2: Regex Engine

A configurable set of regex patterns for PII types that Presidio may miss or that are domain-specific.

**Built-in patterns:**

```yaml
regex_patterns:
  - name: employee_id
    entity_type: EMPLOYEE_ID
    pattern: '\bEMP-\d{6}\b'
    score: 0.95
    context_words: [employee, id, staff, worker]

  - name: internal_url
    entity_type: INTERNAL_URL
    pattern: 'https?://[\w.-]+\.corp\.company\.com[\w/.-]*'
    score: 0.9

  - name: windows_path_with_username
    entity_type: FILE_PATH_PII
    pattern: '[Cc]:\\Users\\[\w.]+\\'
    score: 0.7

  - name: azure_connection_string
    entity_type: CONNECTION_STRING
    pattern: '(?i)(?:AccountKey|SharedAccessKey|Password)=[A-Za-z0-9+/=]{20,}'
    score: 0.95
```

**User-defined patterns** are added via the web UI or config file. Each pattern specifies: name, entity_type, regex, confidence score, and optional context words (boost score when nearby).

Regex patterns are also registered as Presidio `PatternRecognizer` instances so they participate in Presidio's confidence scoring and context enhancement.

### Stage 3: Custom Plugins

Users can provide Python modules that implement a simple detection interface:

```python
# ~/.scruxy/plugins/my_detector.py

from scruxy.plugin import DetectorPlugin, PiiEntity

class MyDetector(DetectorPlugin):
    """Detect internal project codenames."""

    name = "project_codename_detector"
    version = "1.0"

    def setup(self, config: dict) -> None:
        """Called once at startup. Load lookup tables, models, etc."""
        self.codenames = {"Project Phoenix", "Project Titan", "Project Mercury"}

    def detect(self, text: str, language: str) -> list[PiiEntity]:
        """Return list of PII entities found in text."""
        results = []
        for name in self.codenames:
            start = 0
            while True:
                idx = text.find(name, start)
                if idx == -1:
                    break
                results.append(PiiEntity(
                    entity_type="PROJECT_CODENAME",
                    start=idx,
                    end=idx + len(name),
                    score=0.95,
                    source=self.name
                ))
                start = idx + 1
        return results

    def teardown(self) -> None:
        """Called on shutdown."""
        pass
```

**Plugin interface (`DetectorPlugin` base class):**

```python
class DetectorPlugin(ABC):
    name: str           # unique plugin identifier
    version: str        # plugin version

    @abstractmethod
    def setup(self, config: dict) -> None: ...

    @abstractmethod
    def detect(self, text: str, language: str) -> list[PiiEntity]: ...

    def teardown(self) -> None: ...
```

**Plugin discovery:** Scans `~/.scruxy/plugins/` for `.py` files. Each file must contain exactly one class that inherits from `DetectorPlugin`. Plugins are loaded dynamically at startup and can be enabled/disabled/reloaded via the web UI.

**Plugin sandboxing:** Plugins run in-process (for speed). A timeout guard (default 50ms) kills any plugin call that exceeds the deadline to protect the latency budget. Plugin errors are caught and logged — they never crash the proxy.

### Merge & Deduplication

After all three stages produce entity lists:

1. Collect all `PiiEntity` results into a single list
2. Sort by start position
3. Resolve overlapping spans: when two entities overlap, keep the one with the higher confidence score. If scores are equal, prefer the longer span.
4. Output: a non-overlapping list of PII spans with entity types and scores

### Token Anonymizer

Replaces each PII span with a deterministic token using the session's Token Map.

---

## Message Flow

### Request Path (Scrub)

1. Incoming HTTP request hits FastAPI (or mitmproxy addon)
2. **Provider Router** identifies the provider (Anthropic, OpenAI, etc.)
3. **Session Router** extracts harness session ID, acquires session lock
4. Provider's `extract_text_fields()` returns all text content from the request body
5. Each text field is run through the **Scrubbing Pipeline** → PII entities detected
6. **Token Anonymizer** replaces PII spans with deterministic tokens using the session's TokenMap
7. Provider's `replace_text_fields()` puts scrubbed text back into the request body
8. **Session Recorder** logs the scrubbed request
9. **Upstream Forwarder** sends the scrubbed request to the real API

### Response Path (Unscrub)

**Streaming (SSE):**

1. Upstream responds with `content-type: text/event-stream`
2. Proxy processes each SSE event as it arrives:
   a. Provider's `parse_sse_event()` extracts the text field
   b. **Deanonymizer** replaces tokens with real PII values from the session's TokenMap
   c. **Chunk buffer** handles token splits across SSE boundaries
   d. Provider's `rebuild_sse_event()` puts unscrubbed text back
3. Unscrubbed SSE event is streamed to the harness in real-time
4. Session Recorder logs a summary when the stream completes

**Non-streaming:**

1. Upstream responds with full JSON body
2. Provider's `extract_response_text_fields()` returns all text content
3. Deanonymizer replaces tokens
4. Provider's `replace_text_fields()` puts unscrubbed text back
5. Response returned to the harness

### SSE Chunk Boundary Handling

A token like `REDACTED_EMAIL_1` may be split across SSE chunks:

```
Chunk 1: "I see REDACTED_EM"       ← partial token match, buffer it
Chunk 2: "AIL_1 has a bug"         ← completes the token
Combined: "I see REDACTED_EMAIL_1 has a bug"
Unscrubbed: "I see john.doe@company.com has a bug"
```

**Strategy:** Maintain a rolling buffer of up to `max_token_length` characters (configurable, default 40) at chunk boundaries. Use a prefix tree (trie) built from all current unscrub tokens for efficient partial matching. If no token match completes within the buffer window, flush the buffered text as-is. Adds ~1-5ms latency.

---

## Web UI

A browser-based dashboard served at `http://127.0.0.1:8080/ui` (same port as the proxy, different path).

### Pages

#### 1. Dashboard (`/ui/`)

Real-time overview of proxy activity:

- **Status bar:** Proxy mode (primary/mitmproxy), registered providers, active sessions count
- **Per-provider cards:** Each registered provider shows: status (active/idle), active sessions, requests today
- **Live counters:** Total requests proxied, total PII entities scrubbed, entities by type (pie chart)
- **Latency chart:** Scrub pipeline latency per request (line chart, last 100 requests)
- **Recent activity feed:** Last 20 scrub events with timestamp, session, provider, entity type
- **Active sessions table:** Session ID, provider, harness, start time, entity count, last activity

#### 2. Pipeline Configuration (`/ui/pipeline`)

Configure the scrubbing pipeline stages:

- **Presidio settings:**
  - Enable/disable Presidio stage
  - spaCy model selection (sm/lg/trf)
  - Confidence threshold slider (0.0 - 1.0, default 0.5)
  - Entity type toggles (enable/disable individual PII types)
  - Language selection

- **Regex patterns:**
  - List of all regex patterns (built-in + user-defined) with name, pattern, entity type, score
  - Add/edit/delete patterns via inline form
  - Test patterns against sample text in real-time
  - Import/export patterns as YAML

- **Pipeline order:**
  - Drag-and-drop to reorder stages (Presidio, regex, plugins)
  - Per-stage enable/disable toggle

#### 3. Plugin Manager (`/ui/plugins`)

Manage custom detection plugins:

- **Installed plugins:** List with name, version, status (enabled/disabled/error), entity types detected
- **Enable/disable** toggle per plugin
- **Plugin config:** Per-plugin configuration editor (JSON)
- **Upload plugin:** File upload for new `.py` plugin files
- **Reload plugin:** Hot-reload a plugin without restarting the proxy
- **Plugin logs:** Recent log output per plugin (stdout/stderr capture)
- **Plugin template:** Download a starter template for writing new plugins

#### 4. Providers (`/ui/providers`)

Manage LLM provider configurations:

- **Registered providers:** List with name, URL patterns, active sessions, request count
- **Add provider:** Upload YAML config or Python class
- **Edit provider:** Modify URL patterns, auth headers, session ID extraction
- **Test provider:** Send a test request to verify routing and parsing
- **Provider status:** Health check showing if upstream is reachable

#### 5. Token Map Browser (`/ui/tokens`)

Inspect token mappings per session:

- **Session selector:** Dropdown of active and recent sessions, grouped by provider/harness
- **Token table:** Columns: token, real value (masked by default, reveal on click), entity type, first seen timestamp, hit count
- **Search/filter** by entity type or token
- **Export** session map as JSON

#### 6. Session Recordings (`/ui/recordings`)

Browse and analyze recorded sessions:

- **Session list:** Filterable by date, provider, harness, entity count
- **Timeline view:** Chronological request/response pairs with scrub/unscrub metadata
- **Detail view:** Expand any request/response to see scrubbed body, entities found, pipeline latency
- **Replay:** Resend a scrubbed request to test pipeline changes
- **Export:** Download session as JSONL or HAR-like format

#### 7. Logs & Statistics (`/ui/logs`)

Historical data and audit trail:

- **Event log:** Filterable table of all scrub/unscrub events with timestamp, session, provider, entity type, direction (request/response), confidence score
- **Statistics:**
  - Total PII entities detected over time (line chart)
  - Breakdown by entity type (bar chart)
  - Breakdown by provider and harness
  - Breakdown by detection source (Presidio vs regex vs plugin)
  - Average pipeline latency trend
  - Concurrent sessions over time
- **Export:** CSV/JSON export of logs and statistics
- **Retention:** Configurable log retention period (default 7 days)

#### 8. Settings (`/ui/settings`)

Global proxy configuration:

- **Interception mode:** Primary (env var) or Fallback (mitmproxy)
- **Per-provider upstream URLs**
- **Token format** (prefix, format string)
- **Session management** (max age, cleanup schedule)
- **Cert management** (mitmproxy mode): install/uninstall/view cert status, cert fingerprint
- **Logging** level and retention settings
- **About:** Version, loaded providers, plugin count, uptime

### Tech Stack (Web UI)

- **Backend:** FastAPI serves both the proxy API and the web UI API endpoints
- **Frontend:** Vanilla HTML/CSS/JS (no build step, no npm, no CDN dependencies)
- **Charts:** Lightweight inline SVG/Canvas charts (no external charting library)
- **Real-time updates:** Server-Sent Events (SSE) from FastAPI to dashboard for live counters and activity feed
- **Styling:** Dark mode by default, responsive layout

---

## Tech Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| **Language** | Python 3.11+ | Presidio and mitmproxy are Python-native; cross-platform |
| **Proxy/API server** | FastAPI + uvicorn | Async, handles concurrent connections, excellent streaming |
| **PII detection** | presidio-analyzer + spaCy | Industry-standard NER-based PII detection |
| **PII anonymization** | Custom TokenMap (not presidio-anonymizer) | Need deterministic per-session tokens with full bidirectional reversal |
| **Regex engine** | Python `re` module | Built-in, fast, sufficient for pattern matching |
| **HTTPS fallback** | mitmproxy (embedded via `DumpMaster`) | Proven HTTPS interception; Python-native |
| **HTTP client** | httpx (async) | Streaming support, connection pooling, proxy-aware |
| **Web UI backend** | FastAPI (same server) | Single process, shared state |
| **Web UI frontend** | Vanilla HTML/CSS/JS | Zero build dependencies, ships as static files |
| **Storage** | JSON files on disk | Simple, no database dependency |
| **Configuration** | YAML (main config + providers) + JSON (runtime state) | YAML for human editing, JSON for programmatic access |
| **Packaging** | pip + PyPI (or single-file exe via PyInstaller) | Easy install; optional standalone binary |

### Dependencies

```
# Core
fastapi>=0.109
uvicorn[standard]>=0.27
httpx>=0.27              # async HTTP client for upstream forwarding
pyyaml>=6.0
jsonpath-ng>=1.6         # JSONPath for provider field extraction

# PII detection
presidio-analyzer>=2.2
spacy>=3.7

# Fallback interception (optional extra)
mitmproxy>=12.0          # pip install scruxy[mitmproxy]

# spaCy model (installed separately)
# python -m spacy download en_core_web_lg
```

---

## Configuration

Main config file: `~/.scruxy/config.yaml`

```yaml
# Interception mode
interception:
  mode: primary  # "primary" (env var redirect) or "mitmproxy" (HTTPS interception)
  listen_host: "127.0.0.1"
  listen_port: 8080

  # mitmproxy fallback settings (only used when mode: mitmproxy)
  mitmproxy:
    listen_port: 8081
    auto_install_cert: true
    auto_uninstall_cert_on_exit: true
    cert_dir: "~/.mitmproxy"
    # allow_hosts auto-assembled from all registered providers

# Providers
providers:
  # Built-in providers (can be overridden)
  anthropic:
    enabled: true
    upstream_url: "https://api.anthropic.com"

  openai:
    enabled: true
    upstream_url: "https://api.openai.com"

  azure_openai:
    enabled: false
    upstream_url: "https://{resource}.openai.azure.com"

  # Custom providers loaded from:
  custom_providers_dir: "~/.scruxy/providers"

# Token format
tokens:
  prefix: "REDACTED"
  format: "{prefix}_{category}_{n}"  # e.g., REDACTED_EMAIL_1
  max_token_length: 40

# Scrubbing pipeline
pipeline:
  stages:
    - name: presidio
      enabled: true
      config:
        spacy_model: "en_core_web_lg"
        language: "en"
        score_threshold: 0.5
        entities: []  # empty = detect all

    - name: regex
      enabled: true
      config:
        patterns_file: "~/.scruxy/regex_patterns.yaml"

    - name: plugins
      enabled: true
      config:
        plugin_dir: "~/.scruxy/plugins"
        timeout_ms: 50  # per-plugin timeout

# Session management
sessions:
  storage_dir: "~/.scruxy/sessions"
  max_session_age_hours: 168  # 7 days; auto-cleanup
  flush_interval_seconds: 5   # token map disk flush frequency

# Session recording
recording:
  enabled: true
  # recordings stored inside each session directory

# Web UI
ui:
  enabled: true
  open_browser_on_start: true

# Logging
logging:
  level: "info"
  log_dir: "~/.scruxy/logs"
  log_scrub_events: true
  retention_days: 7

# Statistics
stats:
  enabled: true
  storage_file: "~/.scruxy/stats.json"
```

---

## Project Structure

```
scruxy/
├── pyproject.toml                       # Package definition, dependencies, entry points
├── README.md
├── LICENSE
├── docs/
│   └── plans/
│       └── 2026-03-03-scrubbing-proxy-design.md
│
├── src/scruxy/
│   ├── __init__.py
│   ├── __main__.py                      # CLI entry point (click or argparse)
│   ├── app.py                           # FastAPI app setup, route mounting, lifespan
│   │
│   ├── config/
│   │   ├── __init__.py
│   │   ├── models.py                    # Pydantic config models
│   │   └── loader.py                    # YAML config loading, defaults, validation
│   │
│   ├── providers/
│   │   ├── __init__.py
│   │   ├── base.py                      # LLMProvider ABC, TextField, SSETextField models
│   │   ├── registry.py                  # ProviderRegistry: registration, matching, routing
│   │   ├── yaml_provider.py             # Generic YAML-driven provider (JSONPath-based)
│   │   ├── anthropic.py                 # Anthropic Claude provider (built-in)
│   │   ├── openai.py                    # OpenAI-compatible provider (built-in)
│   │   └── loader.py                    # Discover + load custom providers from directory
│   │
│   ├── proxy/
│   │   ├── __init__.py
│   │   ├── routes.py                    # FastAPI catch-all route: identify provider, scrub, forward
│   │   ├── forwarder.py                 # httpx-based upstream forwarding with streaming
│   │   └── mitmproxy_backend.py         # mitmproxy DumpMaster embedding + ScrubAddon
│   │
│   ├── pipeline/
│   │   ├── __init__.py
│   │   ├── engine.py                    # Pipeline orchestrator (run stages, merge, anonymize)
│   │   ├── presidio_stage.py            # Presidio AnalyzerEngine wrapper
│   │   ├── regex_stage.py               # Regex pattern matching stage
│   │   ├── plugin_stage.py              # Plugin loader, executor, timeout guard
│   │   ├── merger.py                    # Span merging & deduplication
│   │   └── models.py                    # PiiEntity, PipelineResult dataclasses
│   │
│   ├── plugin/
│   │   ├── __init__.py
│   │   └── base.py                      # DetectorPlugin ABC, PiiEntity model
│   │
│   ├── tokenmap/
│   │   ├── __init__.py
│   │   ├── service.py                   # ConcurrentSessionStore: per-session maps, locks, disk flush
│   │   ├── token_map.py                 # Single session TokenMap: scrub/unscrub dicts, counters
│   │   ├── anonymizer.py                # Apply token replacements to text
│   │   └── deanonymizer.py              # Reverse token replacements (unscrub) + trie for SSE buffering
│   │
│   ├── scrubber/
│   │   ├── __init__.py
│   │   ├── request_scrubber.py          # Provider-aware request text extraction → pipeline → replacement
│   │   ├── response_unscrubber.py       # Provider-aware response text extraction → deanonymize
│   │   └── sse_stream_unscrubber.py     # SSE chunk processing with boundary buffering
│   │
│   ├── recording/
│   │   ├── __init__.py
│   │   └── recorder.py                  # Per-session JSONL writer, session metadata
│   │
│   ├── ui/
│   │   ├── __init__.py
│   │   ├── routes.py                    # FastAPI routes for UI API endpoints + SSE feed
│   │   └── static/
│   │       ├── index.html               # Dashboard
│   │       ├── pipeline.html            # Pipeline configuration
│   │       ├── plugins.html             # Plugin manager
│   │       ├── providers.html           # Provider management
│   │       ├── tokens.html              # Token map browser
│   │       ├── recordings.html          # Session recordings
│   │       ├── logs.html                # Logs & statistics
│   │       ├── settings.html            # Global settings
│   │       ├── css/
│   │       │   └── styles.css
│   │       └── js/
│   │           ├── dashboard.js
│   │           ├── pipeline.js
│   │           ├── plugins.js
│   │           ├── providers.js
│   │           ├── tokens.js
│   │           ├── recordings.js
│   │           ├── logs.js
│   │           ├── settings.js
│   │           └── shared.js            # Dark mode, SSE, toasts, common utils
│   │
│   ├── stats/
│   │   ├── __init__.py
│   │   └── collector.py                 # Statistics collection, per-session + global aggregation
│   │
│   └── cert/
│       ├── __init__.py
│       └── manager.py                   # Auto cert install/uninstall per platform + atexit cleanup
│
├── default_config/
│   ├── config.yaml                      # Default config template
│   ├── regex_patterns.yaml              # Default regex patterns
│   └── providers/                       # Default provider YAML configs
│       ├── anthropic.yaml
│       └── openai.yaml
│
├── example_plugins/
│   ├── project_codename_detector.py     # Example: detect internal project codenames
│   └── badge_number_detector.py         # Example: detect employee badge numbers
│
└── tests/
    ├── test_provider_anthropic.py
    ├── test_provider_openai.py
    ├── test_provider_registry.py
    ├── test_pipeline_engine.py
    ├── test_presidio_stage.py
    ├── test_regex_stage.py
    ├── test_plugin_stage.py
    ├── test_merger.py
    ├── test_token_map.py
    ├── test_concurrent_sessions.py
    ├── test_disk_persistence.py
    ├── test_request_scrubber.py
    ├── test_response_unscrubber.py
    ├── test_sse_stream.py
    ├── test_session_recording.py
    ├── test_proxy_routes.py
    ├── test_cert_manager.py
    └── test_config.py
```

---

## Startup Sequence

```
$ scruxy [--config path/to/config.yaml] [--mode primary|mitmproxy]

1.  Load config from ~/.scruxy/config.yaml (create defaults if missing)
2.  Initialize Presidio AnalyzerEngine (loads spaCy model, ~2-5s cold start)
3.  Load regex patterns from config
4.  Discover and load plugins from plugin directory
5.  Register built-in providers (Anthropic, OpenAI)
6.  Discover and load custom providers from providers directory
7.  Initialize ConcurrentSessionStore (scan sessions dir, restore active sessions from disk)
8.  Initialize statistics collector
9.  Initialize session recorder

If mode == "primary":
    10a. Start FastAPI server on configured host:port
    11a. Print provider setup instructions:
         "Set ANTHROPIC_BASE_URL=http://127.0.0.1:8080 for Claude Code"
         "Set OPENAI_BASE_URL=http://127.0.0.1:8080 for Copilot"

If mode == "mitmproxy":
    10b. Assemble allow_hosts from all registered providers' URL patterns
    11b. Check/install CA certificate (prompt for admin if needed)
    12b. Start mitmproxy DumpMaster in background thread with ScrubAddon
    13b. Start FastAPI server for web UI (same or separate port)
    14b. Print: "HTTPS proxy ready on 127.0.0.1:8081"
    15b. Register atexit + signal handlers for cert cleanup

16. Open web UI in browser (if configured)
17. Ready to proxy requests from multiple concurrent agents
```

---

## Prior Art & Inspiration

| Project | What it does | What we take from it |
|---------|-------------|---------------------|
| [llm-interceptor (LLI)](https://github.com/chouzz/llm-interceptor) | mitmproxy-based LLM traffic capture/analysis with session management | mitmproxy integration patterns, multi-provider URL patterns, session recording format. Lacks: real-time modification, PII detection, de-anonymization |
| [LLM-Sentinel](https://github.com/raaihank/llm-sentinel) | Go-based PII masking proxy for LLM APIs | Proxy architecture, multi-provider support. Lacks: de-anonymization, Presidio, plugins, web UI |
| [LiteLLM + Presidio](https://microsoft.github.io/presidio/samples/docker/litellm/) | Presidio PII masking via LiteLLM proxy | Presidio integration pattern. Lacks: standalone focus, custom plugins, deterministic tokens |
| [Scrubah.PII](https://github.com/Heyoub/scrubah.pii) | Triple-pipeline PII scrubber for medical docs | Multi-stage pipeline design (regex + BERT NER + rules). Lacks: proxy mode, LLM integration |
| [PII_Scrubbing_LLM](https://github.com/ParthaPRay/PII_Scrubbing_LLM) | FastAPI service: spaCy NER + regex → scrub → LLM | FastAPI + spaCy pattern. Lacks: proxy transparency, de-anonymization, plugins |
| [MCP Interceptors Proposal](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1763) | Proposed MCP event hooks for PII redaction | Future-facing; not yet implemented. Shows industry direction toward interception layers |

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Enterprise harness ignores base URL env vars | Primary mode unusable | mitmproxy fallback mode; test both during setup wizard |
| mitmproxy CA cert install requires admin | Blocks non-admin users | Clear error message with instructions; document IT approval process |
| Concurrent sessions race on shared state | Data corruption / cross-session leaks | Per-session async locks; stateless pipeline; no global mutable state |
| Presidio cold start (~2-5s) delays first request | First interaction slow | Pre-warm on startup; show "warming up" status in web UI |
| Presidio misses PII in code/structured data | PII leaks to model | Regex stage + plugins as defense-in-depth; audit log for all requests |
| Token collisions (token text appears naturally) | False unscrubbing | Distinctive prefix + category + number; configurable format |
| SSE chunk splitting garbles tokens | Broken output to user | Rolling buffer with trie-based partial matching; bounded max token length |
| Plugin crashes or hangs | Pipeline blocked | Per-plugin timeout (50ms); catch all exceptions; auto-disable misbehaving plugins |
| Disk I/O slows down with many sessions | Latency spike | In-memory cache with async background flush; periodic cleanup of old sessions |
| Provider API format changes | Scrubber breaks | Provider abstraction isolates changes; YAML-based providers easy to update |
| spaCy model download requires internet | Offline install fails | Document offline process; optional model bundling via PyInstaller |

---

## Out of Scope (v1)

- Multi-user / multi-tenant deployment (single-user localhost proxy)
- Image/PDF PII detection (Presidio has `presidio-image-redactor` — future enhancement)
- Non-English PII detection (can be added by configuring additional spaCy models)
- Encryption at rest for token maps (optional future enhancement)
- Integration with external secret managers or vaults
- Claude Code / Copilot UI modifications
