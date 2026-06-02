# Pipeline Tester Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a `/ui/tester` page that lets users run the full scrub/unscrub pipeline on sample or custom JSON payloads, with provider-aware defaults and per-stage toggles.

**Architecture:** Two new API endpoints (`GET /ui/api/tester/samples`, `POST /ui/api/tester/run`) that use the existing `PipelineEngine`, `TokenMap`, and `jsonpath_ng` library directly — no new abstractions. An ephemeral `TokenMap` is created per test run (not persisted). The UI is a new page with editable JSON panels and a results table.

**Tech Stack:** FastAPI endpoints, `jsonpath_ng` for JSONPath extraction, existing `PipelineEngine`/`TokenMap`/`Deanonymizer`, vanilla JS frontend.

**Design doc:** `docs/plans/2026-03-04-pipeline-tester-design.md`

---

## Task 1: Backend — Sample Data Endpoint

**Files:**
- Modify: `src/scruxy/ui/routes.py` (add endpoint + sample data + add "tester" to `_VALID_PAGES`)

**Step 1: Write the failing test**

Add to `tests/test_ui_routes.py`:

```python
class TestTesterSamplesAPI:
    """Tests for GET /ui/api/tester/samples."""

    async def test_returns_provider_list(self, client: AsyncClient) -> None:
        resp = await client.get("/ui/api/tester/samples")
        assert resp.status_code == 200
        data = resp.json()
        assert "providers" in data
        assert "anthropic" in data["providers"]
        assert "openai" in data["providers"]

    async def test_samples_have_required_keys(self, client: AsyncClient) -> None:
        data = (await client.get("/ui/api/tester/samples")).json()
        for provider in ["anthropic", "openai"]:
            sample = data["samples"][provider]
            assert "display_name" in sample
            assert "request_body" in sample
            assert "response_body" in sample
            assert "request_text_paths" in sample
            assert "response_text_paths" in sample
            assert isinstance(sample["request_text_paths"], list)
            assert len(sample["request_text_paths"]) > 0

    async def test_anthropic_sample_has_pii(self, client: AsyncClient) -> None:
        data = (await client.get("/ui/api/tester/samples")).json()
        req = data["samples"]["anthropic"]["request_body"]
        # The sample should contain PII-like text in messages
        assert "messages" in req
        content = req["messages"][0]["content"]
        assert isinstance(content, str)
        assert len(content) > 20

    async def test_openai_sample_has_system_message(self, client: AsyncClient) -> None:
        data = (await client.get("/ui/api/tester/samples")).json()
        req = data["samples"]["openai"]["request_body"]
        assert "messages" in req
        roles = [m["role"] for m in req["messages"]]
        assert "system" in roles

    async def test_response_samples_have_tokens(self, client: AsyncClient) -> None:
        """Response samples should contain REDACTED_ tokens for unscrub demo."""
        data = (await client.get("/ui/api/tester/samples")).json()
        for provider in ["anthropic", "openai"]:
            resp_body = data["samples"][provider]["response_body"]
            resp_str = json.dumps(resp_body)
            assert "REDACTED_" in resp_str
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_ui_routes.py::TestTesterSamplesAPI -v`
Expected: FAIL — endpoint doesn't exist yet

**Step 3: Implement the endpoint**

In `src/scruxy/ui/routes.py`, add "tester" to `_VALID_PAGES`, then add the sample data constant and endpoint before the `@router.get("/api/providers")` block:

```python
# --- Tester sample data ---------------------------------------------------

_TESTER_SAMPLES = {
    "anthropic": {
        "display_name": "Anthropic Claude",
        "request_body": {
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "system": "You are a helpful assistant for Acme Corp. The IT admin is John Smith (john.smith@acme.com, ext. 4521).",
            "messages": [
                {
                    "role": "user",
                    "content": "Hi, my name is Sarah Johnson. My email is sarah.j@example.com and my phone is 555-867-5309. Can you help me reset my password? My employee badge is BADGE-4872 and I work on Project Phoenix.",
                }
            ],
        },
        "response_body": {
            "id": "msg_test_001",
            "type": "message",
            "role": "assistant",
            "content": [
                {
                    "type": "text",
                    "text": "Hello REDACTED_PERSON_1! I can help you reset your password. I'll send the reset link to REDACTED_EMAIL_ADDRESS_1. For verification, I see your badge is REDACTED_BADGE_NUMBER_1 and you're part of REDACTED_PROJECT_CODENAME_1. Please check your email.",
                }
            ],
            "model": "claude-sonnet-4-20250514",
            "stop_reason": "end_turn",
        },
        "request_text_paths": [
            "$.system",
            "$.messages[*].content",
            "$.messages[*].content[*].text",
            "$.messages[*].content[*].content",
        ],
        "response_text_paths": ["$.content[*].text"],
    },
    "openai": {
        "display_name": "OpenAI / Copilot",
        "request_body": {
            "model": "gpt-4o",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a helpful assistant for Acme Corp. The IT admin is John Smith (john.smith@acme.com, ext. 4521).",
                },
                {
                    "role": "user",
                    "content": "Hi, my name is Sarah Johnson. My email is sarah.j@example.com and my phone is 555-867-5309. Can you help me reset my password? My employee badge is BADGE-4872 and I work on Project Phoenix.",
                },
            ],
        },
        "response_body": {
            "id": "chatcmpl-test001",
            "object": "chat.completion",
            "model": "gpt-4o",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "Hello REDACTED_PERSON_1! I can help you reset your password. I'll send the reset link to REDACTED_EMAIL_ADDRESS_1. For verification, I see your badge is REDACTED_BADGE_NUMBER_1 and you're part of REDACTED_PROJECT_CODENAME_1. Please check your email.",
                    },
                    "finish_reason": "stop",
                }
            ],
        },
        "request_text_paths": [
            "$.messages[*].content",
            "$.messages[*].content[*].text",
        ],
        "response_text_paths": [
            "$.choices[*].message.content",
            "$.choices[*].message.tool_calls[*].function.arguments",
        ],
    },
}


@router.get("/api/tester/samples", response_class=JSONResponse)
async def api_tester_samples() -> JSONResponse:
    """Return available provider samples with default JSON paths."""
    return JSONResponse(content={
        "providers": list(_TESTER_SAMPLES.keys()),
        "samples": _TESTER_SAMPLES,
    })
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_ui_routes.py::TestTesterSamplesAPI -v`
Expected: PASS

**Step 5: Commit**

```bash
git add src/scruxy/ui/routes.py tests/test_ui_routes.py
git commit -m "feat: add GET /ui/api/tester/samples endpoint with Anthropic/OpenAI sample data"
```

---

## Task 2: Backend — Test Run Endpoint

**Files:**
- Modify: `src/scruxy/ui/routes.py` (add `POST /ui/api/tester/run`)

**Step 1: Write the failing tests**

Add to `tests/test_ui_routes.py`:

```python
class TestTesterRunAPI:
    """Tests for POST /ui/api/tester/run."""

    async def test_run_returns_scrubbed_request(self, client: AsyncClient) -> None:
        """A valid test run returns scrubbed request JSON."""
        samples_resp = await client.get("/ui/api/tester/samples")
        sample = samples_resp.json()["samples"]["anthropic"]

        resp = await client.post("/ui/api/tester/run", json={
            "provider": "anthropic",
            "request_body": sample["request_body"],
            "response_body": sample["response_body"],
            "request_text_paths": sample["request_text_paths"],
            "response_text_paths": sample["response_text_paths"],
            "stages": {},
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "scrubbed_request" in data
        assert "unscrubbed_response" in data
        assert "entities" in data
        assert "token_map" in data
        assert "latency_ms" in data
        assert "stages_run" in data

    async def test_run_missing_request_body_returns_400(self, client: AsyncClient) -> None:
        resp = await client.post("/ui/api/tester/run", json={
            "provider": "anthropic",
            "response_body": {},
            "request_text_paths": [],
            "response_text_paths": [],
        })
        assert resp.status_code == 400

    async def test_run_invalid_json_returns_400(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/ui/api/tester/run",
            content=b"not json",
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 400

    async def test_run_no_pipeline_returns_500(self) -> None:
        app = _make_app()
        del app.state.pipeline
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post("/ui/api/tester/run", json={
                "provider": "anthropic",
                "request_body": {"messages": [{"role": "user", "content": "hello"}]},
                "response_body": {},
                "request_text_paths": ["$.messages[*].content"],
                "response_text_paths": [],
                "stages": {},
            })
            assert resp.status_code == 500

    async def test_run_stage_overrides(self, client: AsyncClient) -> None:
        """Stage overrides control which stages run."""
        resp = await client.post("/ui/api/tester/run", json={
            "provider": "anthropic",
            "request_body": {"messages": [{"role": "user", "content": "test"}]},
            "response_body": {},
            "request_text_paths": ["$.messages[*].content"],
            "response_text_paths": [],
            "stages": {"presidio": False, "regex": False, "plugins": False},
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["stages_run"] == []
        assert data["entities"] == []

    async def test_run_empty_text_paths(self, client: AsyncClient) -> None:
        """Empty text paths mean no scrubbing occurs."""
        resp = await client.post("/ui/api/tester/run", json={
            "provider": "anthropic",
            "request_body": {"messages": [{"role": "user", "content": "Sarah Johnson"}]},
            "response_body": {},
            "request_text_paths": [],
            "response_text_paths": [],
            "stages": {},
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["entities"] == []
        # Request unchanged
        assert data["scrubbed_request"]["messages"][0]["content"] == "Sarah Johnson"

    async def test_run_unscrubs_response_tokens(self, client: AsyncClient) -> None:
        """Response tokens are reversed using the scrub token map."""
        resp = await client.post("/ui/api/tester/run", json={
            "provider": "anthropic",
            "request_body": {"system": "Contact: test@example.com"},
            "response_body": {"content": [{"type": "text", "text": "Sent to REDACTED_EMAIL_ADDRESS_1"}]},
            "request_text_paths": ["$.system"],
            "response_text_paths": ["$.content[*].text"],
            "stages": {},
        })
        assert resp.status_code == 200
        data = resp.json()
        # If email was detected and mapped, the response should be unscrubbed
        # (depends on pipeline detecting the email)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_ui_routes.py::TestTesterRunAPI -v`
Expected: FAIL — endpoint doesn't exist

**Step 3: Implement the endpoint**

In `src/scruxy/ui/routes.py`, add the run endpoint. Key implementation details:
- Import `jsonpath_parse` from `jsonpath_ng`
- Import `TokenMap` from `scruxy.tokenmap.token_map`
- Import `Deanonymizer` from `scruxy.tokenmap.deanonymizer`
- Import `PipelineContext` from `scruxy.pipeline.models`
- Create ephemeral `TokenMap()` — not stored anywhere
- Temporarily override `stage.enabled` for the test, restoring after
- Use `jsonpath_parse` for text extraction and replacement
- Use `Deanonymizer.deanonymize_text()` for response unscrubbing
- Build entity list with `text`, `token`, `field_path` for each detection

```python
@router.post("/ui/api/tester/run", response_class=JSONResponse)
async def api_tester_run(request: Request) -> JSONResponse:
    """Run a full scrub/unscrub test on provided JSON payloads."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})

    if not isinstance(body, dict):
        return JSONResponse(status_code=400, content={"error": "Request body must be a JSON object"})

    request_body = body.get("request_body")
    if request_body is None:
        return JSONResponse(status_code=400, content={"error": "Missing 'request_body'"})

    response_body = body.get("response_body", {})
    request_text_paths = body.get("request_text_paths", [])
    response_text_paths = body.get("response_text_paths", [])
    stage_overrides = body.get("stages", {})

    pipeline = _get_pipeline(request)
    if pipeline is None:
        return JSONResponse(status_code=500, content={"error": "Pipeline not loaded"})

    import copy
    import time
    from jsonpath_ng import parse as jsonpath_parse
    from scruxy.tokenmap.token_map import TokenMap
    from scruxy.tokenmap.deanonymizer import Deanonymizer
    from scruxy.pipeline.models import PipelineContext

    start_time = time.perf_counter()

    # Create ephemeral token map (not persisted)
    token_map = TokenMap()
    context = PipelineContext(session_id="tester", provider_name=body.get("provider", "test"))

    # Save and apply stage overrides
    original_enabled = {}
    stages_run = []
    for stage in getattr(pipeline, "stages", []):
        stage_name = getattr(stage, "name", None)
        if stage_name is not None:
            original_enabled[stage_name] = getattr(stage, "enabled", True)
            if stage_name in stage_overrides:
                stage.enabled = bool(stage_overrides[stage_name])

    try:
        # 1. Extract text fields from request using JSONPath
        text_fields = []  # (full_path_str, text_value)
        for path_str in request_text_paths:
            try:
                compiled = jsonpath_parse(path_str)
                for match in compiled.find(request_body):
                    value = match.value
                    if isinstance(value, str) and value.strip():
                        text_fields.append((str(match.full_path), value))
            except Exception:
                pass  # Skip invalid JSONPath expressions

        # 2. Scrub each field through the pipeline
        all_entities = []
        replacements = {}
        for field_path, text_value in text_fields:
            result = await pipeline.scrub_text(text_value, token_map, context)
            replacements[field_path] = result.scrubbed_text
            # Build entity details with original text and token
            for entity in result.entities:
                pii_text = text_value[entity.start:entity.end]
                token = token_map.get_token(pii_text)
                all_entities.append({
                    "entity_type": entity.entity_type,
                    "text": pii_text,
                    "token": token or "",
                    "start": entity.start,
                    "end": entity.end,
                    "score": round(entity.score, 3),
                    "source": entity.source,
                    "field_path": field_path,
                })

        # 3. Build scrubbed request
        scrubbed_request = copy.deepcopy(request_body)
        for path_str, replacement_text in replacements.items():
            try:
                compiled = jsonpath_parse(path_str)
                compiled.update(scrubbed_request, replacement_text)
            except Exception:
                pass

        # 4. Unscrub response
        unscrubbed_response = copy.deepcopy(response_body) if response_body else {}
        for path_str in response_text_paths:
            try:
                compiled = jsonpath_parse(path_str)
                for match in compiled.find(unscrubbed_response):
                    if isinstance(match.value, str):
                        unscrubbed = Deanonymizer.deanonymize_text(match.value, token_map)
                        compiled.update(unscrubbed_response, unscrubbed)
            except Exception:
                pass

        # Determine which stages actually ran
        for stage in getattr(pipeline, "stages", []):
            stage_name = getattr(stage, "name", None)
            if stage_name and getattr(stage, "enabled", True):
                stages_run.append(stage_name)

        elapsed_ms = (time.perf_counter() - start_time) * 1000

    finally:
        # Restore original stage enabled states
        for stage in getattr(pipeline, "stages", []):
            stage_name = getattr(stage, "name", None)
            if stage_name in original_enabled:
                stage.enabled = original_enabled[stage_name]

    return JSONResponse(content={
        "scrubbed_request": scrubbed_request,
        "unscrubbed_response": unscrubbed_response,
        "entities": all_entities,
        "token_map": token_map.scrub_map,
        "latency_ms": round(elapsed_ms, 2),
        "stages_run": stages_run,
    })
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_ui_routes.py::TestTesterRunAPI -v`
Expected: PASS

**Step 5: Commit**

```bash
git add src/scruxy/ui/routes.py tests/test_ui_routes.py
git commit -m "feat: add POST /ui/api/tester/run endpoint for pipeline testing"
```

---

## Task 3: Frontend — Tester HTML Page

**Files:**
- Create: `src/scruxy/ui/static/tester.html`
- Modify: all 8 HTML pages to add "Tester" to sidebar nav
- Modify: `src/scruxy/ui/routes.py` — add "tester" to `_VALID_PAGES`

The tester.html page has: provider selector, stage checkboxes, JSON path inputs, 4 JSON panels (request, scrubbed request, response, unscrubbed response), results table, and token map display.

All other HTML pages get a new sidebar entry: `<li><a href="/ui/tester"><span class="nav-icon">&#9654;</span> Tester</a></li>` inserted after the Pipeline entry.

**Commit:**
```bash
git add src/scruxy/ui/static/tester.html src/scruxy/ui/static/*.html src/scruxy/ui/routes.py
git commit -m "feat: add tester page HTML and sidebar nav entry"
```

---

## Task 4: Frontend — Tester JavaScript

**Files:**
- Create: `src/scruxy/ui/static/js/tester.js`

The JS file handles:
1. Load samples from `GET /ui/api/tester/samples` on page load
2. Load pipeline stages from `GET /ui/api/pipeline/config` for stage checkboxes
3. Provider dropdown switches sample data + JSON paths
4. "Run Test" button sends `POST /ui/api/tester/run`
5. Render results: scrubbed JSON, unscrubbed JSON, entity table, token map

**Commit:**
```bash
git add src/scruxy/ui/static/js/tester.js
git commit -m "feat: add tester page JavaScript — load samples, run tests, render results"
```

---

## Task 5: Frontend — Tester CSS

**Files:**
- Modify: `src/scruxy/ui/static/css/styles.css`

Add styles for:
- `.tester-controls` — control bar layout
- `.tester-panels` — 2x2 grid of JSON panels
- `.tester-panel` — individual panel with header + textarea/pre
- `.tester-results` — results section
- `.entity-table` — detection results table
- `.token-map-list` — token map display

**Commit:**
```bash
git add src/scruxy/ui/static/css/styles.css
git commit -m "feat: add tester page CSS styles"
```

---

## Task 6: Example Plugin Updates

**Files:**
- Modify: `example_plugins/badge_number_detector.py`
- Modify: `example_plugins/project_codename_detector.py`

### badge_number_detector.py updates:
- Comprehensive module docstring with installation, config examples, testing guide
- Add `score` ConfigField (number, default=1.0, min=0.0, max=1.0, label="Detection Score")
- Add `context_words` ConfigField (list, default=["badge", "employee", "id"], label="Context Words")
- Use `label` and `details` on all fields
- Update `setup()` and `detect()` to use the new config fields
- Add inline comments showing different configuration patterns

### project_codename_detector.py updates:
- Comprehensive module docstring
- Add `case_sensitive` ConfigField (boolean, default=False, label="Case Sensitive")
- Add `score` ConfigField (number, default=0.95, min=0.0, max=1.0, label="Detection Score")
- Use `label` and `details` on all fields
- Update `setup()` and `detect()` to use the new config fields

**Commit:**
```bash
git add example_plugins/
git commit -m "feat: enhance example plugins with comprehensive config, docs, and best practices"
```

---

## Task 7: Tests for Example Plugins

**Files:**
- Modify: `tests/test_plugin_base.py`

Update existing `TestBadgeNumberDetector` and `TestProjectCodenameDetector` classes:
- Test new config fields (score, context_words, case_sensitive)
- Test label/details on all config_schema entries
- Test custom score value flows through to entities
- Test case sensitivity toggle

**Commit:**
```bash
git add tests/test_plugin_base.py
git commit -m "test: update example plugin tests for new config fields"
```

---

## Task 8: Full Test Suite Verification

Run full test suite to confirm nothing is broken:

```bash
pytest tests/ -q
```

Expected: All tests pass (current 741 + new tests).

**Commit (if any fixes needed):**
```bash
git commit -m "fix: resolve test failures from pipeline tester integration"
```

---

## Execution Order

```
Task 1 → Task 2 → Task 3 → Task 4 → Task 5 → Task 6 → Task 7 → Task 8
```

All tasks are sequential. Tasks 1-2 (backend) must come first since Tasks 3-5 (frontend) depend on the API. Task 6-7 (plugins) are independent but done after UI for verification. Task 8 is final validation.

---

## Verification Checklist

After all tasks complete:
- [ ] `pytest tests/ -q` — all tests pass
- [ ] `GET /ui/api/tester/samples` returns Anthropic + OpenAI samples
- [ ] `POST /ui/api/tester/run` scrubs request JSON and unscrubs response JSON
- [ ] `/ui/tester` page loads with provider dropdown and sample data
- [ ] Switching providers updates JSON panels and paths
- [ ] Stage checkboxes reflect live pipeline config
- [ ] "Run Test" shows scrubbed/unscrubbed output + entity table
- [ ] Example plugins have comprehensive docs and multiple config fields
- [ ] Sidebar nav on all pages includes "Tester" link
