# Screenshot provenance

[Back to README](../README.md)

The images in [`images`](images) are captures of the actual Scruxy UI, not mockups. They were made on 2026-10-15 using headless Microsoft Edge, a 1440 x 1040 CSS-pixel viewport, and the application's default dark theme. The captured UI matches the public application's `2846b88` baseline.

## Demo conditions

- A separate application instance used `127.0.0.1:18943`, an isolated home/data directory, and an isolated browser profile. The user's running proxy and real session data were not used.
- Forward proxy and HTTPS listeners were disabled. No CA was installed or trusted.
- The installed Presidio/spaCy model ran locally. OPF stayed disabled; no OPF model was downloaded.
- Synthetic names, `example.com` email addresses, and fabricated paths were used. No request was sent to an upstream LLM.
- Dashboard and recording examples were populated through application services using locally scrubbed data. Network and response timing fields were supplied demo values, **not measured upstream performance**.
- Original-body recording was enabled **only in this isolated demo** to show the comparison view. The production default is `false`.
- The Tester was exercised through its UI, including checks that the email was replaced in the request and restored in the simulated response.

## Image inventory

| File | Demonstrates |
|---|---|
| `dashboard.png` | Provider inventory, counters, latency chart, time-window statistics |
| `tester.png` | Six-panel request/response transformation |
| `plugins.png` | Detection order, enabled states, and optional OPF |
| `providers.png` | Upstream and extraction configuration |
| `tokens.png` | Shared-map values filtered to a synthetic session |
| `recordings.png` | Paired request/response bodies and timing breakdown |
| `recordings-diff.png` | Original-versus-scrubbed comparison |
| `settings.png` | Application configuration controls |

## Refreshing the images

Use a disposable environment with the editable checkout and configured spaCy model. Do not simply point `--config` at another file: that alone does not redirect home-relative tester/script state or every storage path.

1. Isolate the process's home directory before importing Scruxy, or use a separate disposable OS account/container. Choose unused loopback ports and disable automatic CA installation and extra listeners.
2. Open the real UI in a fresh browser profile at the viewport above. Use only synthetic text and keep the production user's data out of that environment.
3. Populate Tester with a supported request and a response containing the generated token. For populated Recordings, use a local stub upstream or application-service fixtures; clearly label fixture timing values.
4. Capture the pages and inspect every image for real names, credentials, local usernames, notifications, and unrelated tabs. Do not modify the DOM to imply features that are not implemented.
5. Keep original-body recording off outside the disposable demonstration. Close the browser, stop the demo instance, and remove its profile, data, logs, and any task-only tooling.

Screenshots show a point in time. The text documentation is authoritative about defaults, privacy boundaries, and setup; values visible in the demo are not recommended production settings.
