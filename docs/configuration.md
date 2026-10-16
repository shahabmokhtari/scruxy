# Configuration and operations

[Back to README](../README.md)

This guide describes the current implementation. Historical documents in `plans` may use retired modes or older persistence models.

## CLI and listeners

```text
scruxy [--config PATH] [--mode {primary,mitmproxy}]
       [--host HOST] [--port PORT]
       [--forward-proxy-port PORT] [--no-forward-proxy]
       [--https-port PORT] [--no-https] [--no-browser]
```

| Option | Effect |
|---|---|
| `--config PATH` | Read a YAML config instead of `~/.scruxy/config.yaml` |
| `--mode primary` | Normal operation: reverse proxy and configured additional listeners |
| `--mode mitmproxy` | Legacy input only; startup warns and changes it to `primary` for that run |
| `--host HOST` | Override bind host; default `localhost` |
| `--port PORT` | Override HTTP reverse-proxy/UI port; default `8080` |
| `--forward-proxy-port PORT` | Change forward-proxy port; default `8081`; does not enable a disabled listener |
| `--no-forward-proxy` | Disable the forward-proxy listener |
| `--https-port PORT` | Change HTTPS reverse-proxy port; default `8443`; does not enable it |
| `--no-https` | Disable the HTTPS reverse-proxy listener |
| `--no-browser` | Suppress the CLI's automatic browser launch |

There is no `--forward-proxy` enable flag. Use YAML to enable a listener that is disabled in your saved configuration. CLI overrides take precedence for the current invocation, not as an edit to the YAML file.

```yaml
interception:
  mode: primary
  listen_host: localhost
  listen_port: 8080
  forward_proxy:
    enabled: true
    listen_port: 8081
    auto_install_ca_cert: false
    ca_cert_dir: "~/.scruxy/certs"
  https:
    enabled: false
    listen_port: 8443
    ca_cert_dir: "~/.scruxy/certs"
```

This example opts out of automatic CA installation. Set `https.enabled: true` to use the HTTPS reverse proxy; a port override alone is insufficient.

Keep the UI on loopback. Binding to `0.0.0.0` is not a supported recipe for turning Scruxy into a secured shared service. `localhost` is the normal loopback default; OS IPv4/IPv6 resolution and binding behavior can vary.

## Certificate trust

The built-in forward proxy terminates matched HTTPS CONNECT traffic with certificates issued by Scruxy's local CA. The HTTPS reverse proxy uses that CA too. Certificate files normally live under `~/.scruxy/certs`; `scruxy-ca.pem` is the public CA certificate.

**Before starting the default forward proxy:** decide whether to allow `interception.forward_proxy.auto_install_ca_cert` (default `true`). The CLI attempts system trust installation when enabled. An HTTP-only reverse proxy needs neither the CA nor trust-store changes.

### Node-based clients

After the CA exists, set this in the shell that will launch the client:

```powershell
$env:HTTP_PROXY = "http://localhost:8081"
$env:HTTPS_PROXY = "http://localhost:8081"
$env:NODE_EXTRA_CA_CERTS = "$HOME\.scruxy\certs\scruxy-ca.pem"
```

```bash
export HTTP_PROXY="http://localhost:8081"
export HTTPS_PROXY="http://localhost:8081"
export NODE_EXTRA_CA_CERTS="$HOME/.scruxy/certs/scruxy-ca.pem"
```

Restart the client process. Trust-store behavior is runtime-specific: `NODE_EXTRA_CA_CERTS` does not configure Python, Java, or every editor.

### Manual trust

Only trust a CA you generated and verified on your own machine. System-wide changes may require administrator privileges and organizational approval.

| Platform | Procedure |
|---|---|
| Windows, current user | `certutil -user -addstore Root "$HOME\.scruxy\certs\scruxy-ca.pem"` in PowerShell |
| macOS, system keychain | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.scruxy/certs/scruxy-ca.pem` |
| Debian/Ubuntu-style Linux | Copy the public PEM to `/usr/local/share/ca-certificates/scruxy-ca.crt`, then run `sudo update-ca-certificates` |

Other Linux distributions use different trust tools. Do not use `NODE_TLS_REJECT_UNAUTHORIZED=0`, `verify=False`, or equivalent blanket verification bypasses.

### When finished

Remove the proxy/base-URL environment variables you set and restart the client. If you added system trust, locate the exact **Scruxy PII Proxy CA** certificate, verify its fingerprint against your local CA, and remove only that certificate from the same store. For Linux, remove only the CA file you added and rebuild the trust store. If you used only `NODE_EXTRA_CA_CERTS`, unset it and restart Node. Do not assume the built-in CA trust is automatically removed on exit.

Protect the CA private key. Never commit the certificate directory, token database, or real session recordings.

## Configure detection

Use **Plugins** to change individual stages without replacing the whole list. In YAML, `pipeline.stages` is a complete ordered list, **not** a name-based merge with defaults. If you supply only one entry, other default stages are omitted.

This explicit example keeps the usual detection layers:

```yaml
pipeline:
  stages:
    - name: whitelist
      enabled: true
      config:
        whitelist_file: "~/.scruxy/whitelist.yaml"
    - name: presidio
      enabled: true
      config:
        spacy_model: en_core_web_lg
        language: en
        score_threshold: 0.7
        entities:
          - PERSON
          - EMAIL_ADDRESS
          - PHONE_NUMBER
          - CREDIT_CARD
          - US_SSN
          - IP_ADDRESS
        post_filter_enabled: true
    - name: regex
      enabled: true
      config:
        patterns_file: "~/.scruxy/regex_patterns.yaml"
    - name: file_path
      enabled: true
      config:
        score: 0.95
    - name: plugins
      enabled: true
      config:
        plugin_dir: "~/.scruxy/plugins"
        timeout_ms: 50
    - name: openai_privacy_filter
      enabled: false
      config:
        device: cpu
        decode_mode: viterbi
        min_score: 0.5
        max_text_length: 64000
```

The known-PII pre-filter is managed by the engine, not an entry to add to this list. Whitelist stages are normalized ahead of other configured detectors. Reordering the rest changes which detector claims overlapping spans.

Presidio caches results (256 entries by default) and disables unused spaCy components. For a smaller model, install `en_core_web_sm` and change `spacy_model` in the Presidio stage. Evaluate accuracy on representative samples; a smaller download or faster run is not evidence of equivalent detection.

Watch startup warnings: if the configured model is missing, Scruxy attempts to obtain it; failed initialization can leave Presidio unavailable. A running server does not establish that every configured detector loaded.

## Extend detection

### Whitelist safe terms

In `~/.scruxy/whitelist.yaml`:

```yaml
whitelist:
  - Scruxy
  - ExampleWidget
```

Whitelist matching is case-insensitive. Use it narrowly to suppress false positives, not to bypass scrutiny of an entire sensitive category. Prefer editing through the Plugins file editor so the stage reloads; restart after external file edits.

### Add a regex rule

In `~/.scruxy/regex_patterns.yaml`:

```yaml
regex_patterns:
  - name: badge_number
    entity_type: BADGE_NUMBER
    pattern: '\bBADGE-\d{4}\b'
    score: 0.95
```

Test with `My badge is BADGE-1234.` and a negative example such as `BADGE-12`. Default sample patterns are commented out; enable rules deliberately. Avoid pathological regexes and test false positives as well as matches.

### Write a custom detector

Place one `DetectorPlugin` subclass in a `.py` file under `~/.scruxy/plugins`, or use the local plugin editor:

```python
import re

from scruxy.plugin.base import DetectorPlugin, PiiEntity


class BadgeNumberDetector(DetectorPlugin):
    name = "badge_number_detector"
    version = "1.0"

    def setup(self, config: dict) -> None:
        self._pattern = re.compile(config.get("pattern", r"\bBADGE-\d{4}\b"))

    def detect(self, text: str, language: str) -> list[PiiEntity]:
        return [
            PiiEntity(
                entity_type="BADGE_NUMBER",
                start=match.start(),
                end=match.end(),
                score=1.0,
                source=self.name,
            )
            for match in self._pattern.finditer(text)
        ]
```

Use either this detector or the equivalent regex example unless you intentionally want both. See [`example_plugins`](../example_plugins) and [`DetectorPlugin`](../src/scruxy/plugin/base.py) for more examples, configuration schema fields, and storage hooks.

The custom-plugin stage waits up to `timeout_ms` per plugin (50 ms by default). Exceptions and timeouts are logged and results skipped; repeated timeouts can auto-disable a plugin. A timed-out worker is not forcibly terminated, so plugin code must remain cooperative. This is a latency guard, not a sandbox. Only install code you trust.

### Choose replacement strategies

```yaml
tokens:
  persistent: true
  expiration_hours: 168
  replacements:
    EMAIL_ADDRESS:
      strategy: uuid
      enabled: true
```

Existing mappings remain reusable; a new strategy is not a retroactive rewrite of every token. The default token map uses `REDACTED_{TYPE}_{N}`. Configured default/UUID replacement strategies can preserve word counts using multiple replacement words. UUIDs are randomly generated once and then reused through the map.

For script rules, the command receives **entity type and count as arguments**, **original PII on stdin**, and returns the replacement on stdout. Errors/nonzero exits/timeouts log and fall back to default replacement. **Empty output or output identical to the input deliberately skips redaction.** Scripts receive sensitive material and execute locally with the process's privileges; review them before use. Manage rules and script files from Plugins.

## Custom providers

Start with an existing definition under [`default_config/providers`](../default_config/providers), then give your custom provider a unique name. A minimal non-streaming JSON API definition might look like:

```yaml
name: example_api
display_name: Example JSON API
upstream_url: "https://llm.example.com"
url_patterns:
  - "*/v1/generate"
auth_headers:
  - authorization
session_id_headers:
  - x-session-id
request_text_paths:
  - "$.prompt"
response_text_paths:
  - "$.answer"
```

Save this under `~/.scruxy/providers/example_api.yaml`, change the example upstream to your trusted endpoint, and restart. It describes only `prompt`/`answer`, not a full streaming protocol. Add the appropriate SSE configuration for a streaming API or implement `LLMProvider` in Python for richer extraction.

URL matching and registration order matter; the registry uses configured matching-header names to disambiguate multiple matches. Do not assume a newly added overlapping provider takes priority. Inspect a real synthetic request in Recordings to verify the selected provider and upstream.

Built-in Python providers handle structures that a short JSONPath list may miss. A custom request-path list overrides their default extraction behavior; test system/instruction text, content arrays, tool inputs/arguments, and responses separately.

## Optional OpenAI Privacy Filter

From the editable checkout and its Python environment:

```powershell
python -m pip install -e ".[opf]"
```

Or with uv:

```powershell
uv sync --extra opf
```

The extra installs `opf` from the upstream Git repository plus its dependencies. Expect substantial disk use from PyTorch and the model; sizes vary by platform and version. The checkpoint is downloaded on first inference, normally under `~/.opf/privacy_filter`. Use `checkpoint_path` in the stage configuration or `OPF_CHECKPOINT` for a pre-downloaded checkpoint.

On **Plugins**, enable `openai_privacy_filter` and disable Presidio for an initial comparison. Edit the existing OPF stage rather than replacing the entire pipeline list:

| Setting | Behavior |
|---|---|
| `device` | `cpu` or `cuda`; CUDA requires a compatible GPU/PyTorch installation |
| `decode_mode` | `viterbi` or `argmax` |
| `enabled_labels` | Selected OPF labels; empty means all eight |
| `min_score` | Fixed confidence attached to emitted spans, not a probability filter |
| `max_text_length` | Skip longer texts; default 64,000 characters, `0` removes this cap |
| `checkpoint_path` | Optional checkpoint directory |

The labels are `account_number`, `private_address`, `private_email`, `private_person`, `private_phone`, `private_url`, `private_date`, and `secret`. Missing optional dependencies produce warnings and no OPF detections. Avoid enabling it as your only detector until a local test succeeds.

The Plugins **Install** action invokes `POST /ui/api/plugins/openai_privacy_filter/install`. It installs into the server's Python environment; it does **not** hot-load the new package. Restart Scruxy after successful installation. Only use this trusted local administrative operation when you intend to install software.

Benchmark locally:

```powershell
python -m scruxy.bench_opf --text-size 4000 --repeat 5
python -m scruxy.bench_opf --text-size 64000 --repeat 3
```

The tool reports latency, entity counts, and throughput. `--no-presidio` and `--no-opf` skip a detector. Compare detection quality alongside speed; neither the README screenshots nor one payload establishes production latency.

## Storage and retention

| Default location | Contents |
|---|---|
| `~/.scruxy/config.yaml` | Saved application configuration |
| `~/.scruxy/scruxy.db` | Shared PII/token mappings and session usage in SQLite |
| `~/.scruxy/tester_state.json` | Tester inputs and field-selection state, potentially original PII |
| `~/.scruxy/sessions/<session>/recording.jsonl` | Request/response records |
| `~/.scruxy/sessions/<session>/metadata.json` and `_index.json` under `sessions` | Session metadata and index |
| `~/.scruxy/stats.json` | Persisted statistics |
| `~/.scruxy/passthrough_log.jsonl` | Passthrough log storage when used |
| `~/.scruxy/whitelist.yaml`, `regex_patterns.yaml` | Detection configuration |
| `~/.scruxy/plugins`, `plugins/data` | Custom detector code and plugin storage |
| `~/.scruxy/providers`, `scripts` | Custom provider definitions and replacement scripts |
| `~/.scruxy/logs`, `certs` | Application logs and local CA material |

The token database is stored next to the configured sessions directory. SQLite write-through replaces the old periodic JSON token-map flush; session usage is stored in the database, not new per-session `session_pii.json` files.

`tokens.expiration_hours` defaults to 168 (seven days); `0` disables token expiry. Do not treat token expiry as deletion of recordings, logs, tester input, plugin data, or older files.

To reduce persisted request data:

```yaml
tokens:
  persistent: false
recording:
  enabled: false
  store_body_original: false
interception:
  passthrough:
    enabled: false
```

This is **not** a no-disk-write mode and does not delete existing data. Tester state, configuration, logs, statistics, and plugin storage have separate behavior. Avoid entering sensitive text into Tester if you do not want it saved.

With recording enabled, original bodies remain off by default. Enabling `store_body_original` makes before/after views possible but stores original PII. Scrubbed recordings can still contain missed detections, unsupported fields, or sensitive metadata; review before sharing.

A custom `--config` file is not an isolated profile. Paths in the configuration and home-relative data such as tester state must all be considered when running a second instance.

## Troubleshooting

| Symptom | Check |
|---|---|
| Clone fails | Use `https://github.com/shahabmokhtari/scruxy.git` and check network/proxy settings. Public cloning does not require organization membership. |
| Provider defaults fail to load after installation | Use the editable source checkout and retain `default_config/providers`; current loaders resolve assets relative to the checkout. |
| No traffic in Recordings | Confirm the client inherited proxy/base-URL variables, recording is enabled, and the relevant listener actually started. |
| Main-port request returns 404 | Check path and provider matching. An OpenAI client may need `/v1` in its configured base URL. |
| HTTPS listener is missing | `--https-port` only changes its port; set `interception.https.enabled: true` and restart. |
| TLS verification fails | Confirm the CA file exists and that this runtime trusts it. Restart the client; do not disable verification. |
| Presidio unavailable / no name detections | Install the configured model into Scruxy's Python environment, check enabled categories and startup logs, then test a synthetic sample. |
| False positives | Inspect source/type in Tester; narrow regexes, adjust Presidio settings, or whitelist specific safe terms. File-path mappings can also match known segments later. |
| Text is unchanged | Verify extraction paths, enabled provider/stages, whitelists, detector caps/timeouts, and replacement scripts that may skip redaction. |
| Tokens remain in responses | Check whether mappings expired/were cleared, the response belongs to the expected session, or the model altered the token. Keep the original session context for debugging. |
| Scrub Diff says original not recorded | Expected with the default privacy setting. Enable original-body recording only deliberately, then generate a new synthetic request. |
| OPF is enabled but produces nothing | Check install status, restart after install, verify checkpoint availability, and check the input-length cap. |
| Settings look saved but listener behavior is unchanged | Restart for listener/storage changes and check CLI overrides. Use `--no-browser` rather than relying on the saved UI preference to suppress launch. |
| Legacy mitmproxy warning | Change saved `interception.mode` to `primary` and use the built-in forward proxy. |

## Implementation references

Defaults and parsing: [`config/models.py`](../src/scruxy/config/models.py), [`config/loader.py`](../src/scruxy/config/loader.py), [`__main__.py`](../src/scruxy/__main__.py).

Runtime behavior: [`app.py`](../src/scruxy/app.py), [`ui/routes.py`](../src/scruxy/ui/routes.py), [`recording/recorder.py`](../src/scruxy/recording/recorder.py), [`tokenmap/service.py`](../src/scruxy/tokenmap/service.py), [`tokenmap/replacer.py`](../src/scruxy/tokenmap/replacer.py).
