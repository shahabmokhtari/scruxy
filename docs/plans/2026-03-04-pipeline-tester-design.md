# Pipeline Tester — Design Document

**Date:** 2026-03-04
**Status:** Approved

## Problem

Users have no way to validate that the scrubbing pipeline is correctly detecting and replacing PII before deploying in production. They need to test with sample or custom JSON payloads, see what gets scrubbed and unscrubbed, verify JSON path extraction works correctly for their provider, and confirm the round-trip (scrub → unscrub) preserves original values.

## Solution

A new `/ui/tester` page providing a full round-trip scrub/unscrub tester with:
- Provider-aware sample requests/responses with realistic PII
- Editable JSON input panels for request and response
- Configurable JSON paths per provider
- Per-stage enable/disable overrides (independent of live pipeline config)
- Side-by-side display of original → scrubbed → unscrubbed
- Entity detection details with source, confidence, and token mappings

## Architecture

### Page Layout

```
┌──────────────────────────────────────────────────────────────────┐
│ Provider: [Anthropic ▾]   Stages: [✓Presidio] [✓Regex] [✓Plug]  │
│ Request Paths: $.system, $.messages[*].content, ...              │
│ Response Paths: $.content[*].text                                │
│                                        [▶ Run Test]              │
├────────────────────────────┬─────────────────────────────────────┤
│ Request JSON (editable)    │ Scrubbed Request (read-only)        │
│                            │                                     │
├────────────────────────────┼─────────────────────────────────────┤
│ Response JSON (editable)   │ Unscrubbed Response (read-only)     │
│                            │                                     │
├──────────────────────────────────────────────────────────────────┤
│ Results: 3 entities found │ Latency: 12ms │ Stages: presidio,regex│
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ PERSON │ "John Doe" → REDACTED_PERSON_1 │ presidio │ 0.92   │ │
│ │ EMAIL  │ "john@ex.com" → REDACTED_EMAIL_1 │ regex  │ 0.85   │ │
│ │ PHONE  │ "555-1234" → REDACTED_PHONE_1 │ presidio │ 0.88   │ │
│ └──────────────────────────────────────────────────────────────┘ │
│ Token Map:                                                       │
│   John Doe → REDACTED_PERSON_1                                   │
│   john@ex.com → REDACTED_EMAIL_1                                 │
└──────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. User selects a provider → sample request/response JSON and provider-specific JSON paths load
2. User optionally edits the sample text, JSON paths, and stage toggles
3. On "Run Test":
   a. Backend extracts text fields from request JSON using configured JSONPath expressions
   b. Each text field runs through enabled pipeline stages (detect → merge → anonymize)
   c. Scrubbed text is written back to the request JSON at the same paths
   d. Response JSON tokens are deanonymized using the same ephemeral token map
4. Results returned: scrubbed request, unscrubbed response, entities, token map, latency

### Key Principle

The tester creates an **ephemeral TokenMap** instance (not stored to disk, no session ID in the session store). This avoids polluting real session data.

---

## API Design

### POST /ui/api/tester/run

Execute a full round-trip scrub/unscrub test.

**Request:**
```json
{
  "provider": "anthropic",
  "request_body": { "system": "You are helpful.", "messages": [...] },
  "response_body": { "content": [{"type": "text", "text": "Hello REDACTED_PERSON_1!"}] },
  "request_text_paths": ["$.system", "$.messages[*].content", "$.messages[*].content[*].text"],
  "response_text_paths": ["$.content[*].text"],
  "stages": {"presidio": true, "regex": true, "plugins": false}
}
```

**Response:**
```json
{
  "scrubbed_request": { ... },
  "unscrubbed_response": { ... },
  "entities": [
    {
      "entity_type": "PERSON",
      "text": "John Doe",
      "token": "REDACTED_PERSON_1",
      "start": 42,
      "end": 50,
      "score": 0.92,
      "source": "presidio",
      "field_path": "messages.[0].content"
    }
  ],
  "token_map": {
    "John Doe": "REDACTED_PERSON_1",
    "john@example.com": "REDACTED_EMAIL_1"
  },
  "latency_ms": 12.3,
  "stages_run": ["presidio", "regex"]
}
```

**Error responses:**
- 400: Invalid JSON body, missing required fields, invalid YAML paths
- 500: Pipeline not loaded

### GET /ui/api/tester/samples

Return available provider samples and their default JSON paths.

**Response:**
```json
{
  "providers": ["anthropic", "openai"],
  "samples": {
    "anthropic": {
      "display_name": "Anthropic Claude",
      "request_body": { ... },
      "response_body": { ... },
      "request_text_paths": ["$.system", "$.messages[*].content", "$.messages[*].content[*].text", "$.messages[*].content[*].content"],
      "response_text_paths": ["$.content[*].text"]
    },
    "openai": {
      "display_name": "OpenAI / Copilot",
      "request_body": { ... },
      "response_body": { ... },
      "request_text_paths": ["$.messages[*].content", "$.messages[*].content[*].text"],
      "response_text_paths": ["$.choices[*].message.content", "$.choices[*].message.tool_calls[*].function.arguments"]
    }
  }
}
```

---

## Default Sample Data

### Anthropic Sample Request

```json
{
  "model": "claude-sonnet-4-20250514",
  "max_tokens": 1024,
  "system": "You are a helpful assistant for Acme Corp. The IT admin is John Smith (john.smith@acme.com, ext. 4521).",
  "messages": [
    {
      "role": "user",
      "content": "Hi, my name is Sarah Johnson. My email is sarah.j@example.com and my phone is 555-867-5309. Can you help me reset my password? My employee badge is BADGE-4872 and I work on Project Phoenix."
    }
  ]
}
```

### Anthropic Sample Response

Contains `REDACTED_*` tokens that the unscrubber will reverse:

```json
{
  "id": "msg_test_001",
  "type": "message",
  "role": "assistant",
  "content": [
    {
      "type": "text",
      "text": "Hello REDACTED_PERSON_1! I can help you reset your password. I'll send the reset link to REDACTED_EMAIL_ADDRESS_1. For verification, I see your badge is REDACTED_BADGE_NUMBER_1 and you're part of REDACTED_PROJECT_CODENAME_1. Please check your email."
    }
  ],
  "model": "claude-sonnet-4-20250514",
  "stop_reason": "end_turn"
}
```

### OpenAI Sample Request

```json
{
  "model": "gpt-4o",
  "messages": [
    {
      "role": "system",
      "content": "You are a helpful assistant for Acme Corp. The IT admin is John Smith (john.smith@acme.com, ext. 4521)."
    },
    {
      "role": "user",
      "content": "Hi, my name is Sarah Johnson. My email is sarah.j@example.com and my phone is 555-867-5309. Can you help me reset my password? My employee badge is BADGE-4872 and I work on Project Phoenix."
    }
  ]
}
```

### OpenAI Sample Response

```json
{
  "id": "chatcmpl-test001",
  "object": "chat.completion",
  "model": "gpt-4o",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "Hello REDACTED_PERSON_1! I can help you reset your password. I'll send the reset link to REDACTED_EMAIL_ADDRESS_1. For verification, I see your badge is REDACTED_BADGE_NUMBER_1 and you're part of REDACTED_PROJECT_CODENAME_1. Please check your email."
      },
      "finish_reason": "stop"
    }
  ]
}
```

Note: The response samples use `REDACTED_*` tokens that match what the scrubber produces from the request samples. This allows the unscrub step to demonstrate token reversal.

---

## JSON Path Configuration

### Provider-Aware Defaults

Paths are loaded from the registered YAML provider configs:

| Provider | Request Paths | Response Paths |
|----------|--------------|----------------|
| Anthropic | `$.system`, `$.messages[*].content`, `$.messages[*].content[*].text`, `$.messages[*].content[*].content` | `$.content[*].text` |
| OpenAI | `$.messages[*].content`, `$.messages[*].content[*].text` | `$.choices[*].message.content`, `$.choices[*].message.tool_calls[*].function.arguments` |

### Editable in UI

Paths are shown as comma-separated text inputs. Users can add/remove paths for custom providers or testing specific fields.

---

## Stage Overrides

The tester reads the live pipeline's stage list and their current enabled state. Checkboxes let the user temporarily override which stages run for the test — this does NOT modify the live pipeline config.

Implementation: The `/run` endpoint receives a `stages` dict mapping stage name → bool. Stages not in the dict use their live enabled state. The engine temporarily overrides `stage.enabled` for the test run, restoring after.

---

## Pipeline Test Execution (Backend)

```python
async def run_test(request_body, response_body, request_paths, response_paths, stage_overrides, pipeline):
    # 1. Create ephemeral token map (not persisted)
    token_map = TokenMap()

    # 2. Compile JSONPath expressions
    compiled_paths = [(p, jsonpath_parse(p)) for p in request_paths]

    # 3. Extract text fields from request
    text_fields = []
    for path_str, compiled in compiled_paths:
        for match in compiled.find(request_body):
            if isinstance(match.value, str) and match.value.strip():
                text_fields.append((str(match.full_path), match.value))

    # 4. Scrub each field through the pipeline (with stage overrides)
    all_entities = []
    replacements = {}
    for field_path, text_value in text_fields:
        result = await pipeline.scrub_text(text_value, token_map, context)
        replacements[field_path] = result.scrubbed_text
        all_entities.extend(result.entities)

    # 5. Build scrubbed request
    scrubbed = deep_copy(request_body)
    for path, replacement in replacements.items():
        jsonpath_parse(path).update(scrubbed, replacement)

    # 6. Unscrub response using same token map
    unscrubbed = deep_copy(response_body)
    for path_str, compiled in compiled_response_paths:
        for match in compiled.find(unscrubbed):
            if isinstance(match.value, str):
                unscrubbed_text = deanonymize_text(match.value, token_map)
                compiled.update(unscrubbed, unscrubbed_text)

    return scrubbed, unscrubbed, all_entities, token_map
```

---

## Example Plugin Updates

Both example plugins will be updated to be comprehensive reference implementations:

### badge_number_detector.py

- Full docstring with usage instructions, config examples, and testing guide
- Multiple `config_schema` entries: `pattern` (string), `score` (number), `context_words` (list)
- `ConfigField` entries use `label`, `details`, `description`
- Comments showing different configuration patterns

### project_codename_detector.py

- Full docstring with usage instructions
- Multiple `config_schema` entries: `codenames` (list), `case_sensitive` (boolean), `score` (number with min/max)
- `ConfigField` entries use `label`, `details`, `description`
- Comments showing different configuration patterns

---

## Files Changed

| File | Change |
|------|--------|
| `src/scruxy/ui/routes.py` | Add `GET /ui/api/tester/samples`, `POST /ui/api/tester/run` |
| `src/scruxy/ui/static/tester.html` | New page with sidebar nav, controls, 4-panel layout |
| `src/scruxy/ui/static/js/tester.js` | Client-side logic: load samples, run tests, render results |
| `src/scruxy/ui/static/css/styles.css` | Tester-specific styles (panels, entity table, token map) |
| `src/scruxy/ui/static/pipeline.html` | Add "Tester" to sidebar nav |
| `src/scruxy/ui/static/*.html` | Add "Tester" to sidebar nav on all pages |
| `example_plugins/badge_number_detector.py` | Enhanced docs, multiple config fields |
| `example_plugins/project_codename_detector.py` | Enhanced docs, multiple config fields |
| `tests/test_ui_routes.py` | Tests for tester endpoints |
| `tests/test_tester.py` | Dedicated test file for tester logic |

---

## Testing Strategy

1. **Unit tests** for the tester endpoint: valid request, missing fields, invalid JSON paths, stage overrides
2. **Unit tests** for sample data endpoint: correct structure, provider paths
3. **Integration tests**: full round-trip with mock pipeline — verify entity detection, token mapping, unscrub reversal
4. **Edge cases**: empty request body, no text fields found, all stages disabled, invalid JSONPath expressions
