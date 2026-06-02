/* ===================================================================
   Recordings page -- session selector + paired request/response view
   with optional chat-bubble display.
   =================================================================== */

"use strict";

(function () {
  var sessionSelect = document.getElementById("rec-session-select");
  var timeline      = document.getElementById("recordings-timeline");
  var btnRefresh    = document.getElementById("btn-refresh-recordings");
  var btnViewRaw    = document.getElementById("btn-view-raw");
  var btnViewChat   = document.getElementById("btn-view-chat");
  var btnViewDiff   = document.getElementById("btn-view-diff");
  var chkAutoRefresh = document.getElementById("chk-auto-refresh");
  var chkBeautifyJson = document.getElementById("chk-beautify-json");

  // Filter bar elements
  var filterProvider = document.getElementById("rec-filter-provider");
  var filterProxy = document.getElementById("rec-filter-proxy");
  var filterSearch = document.getElementById("rec-filter-search");
  var btnClearFilters = document.getElementById("btn-clear-filters");
  var filterCountEl = document.getElementById("rec-filter-count");

  // Parse URL query params for deep-linking from tokens page
  var _urlParams = new URLSearchParams(window.location.search);
  var _highlightRequestId = _urlParams.get("highlight") || "";
  var _urlSession = _urlParams.get("session") || "";

  var chkShowDiff = document.getElementById("chk-show-diff");
  var btnLayoutToggle = document.getElementById("btn-layout-toggle");

  var viewMode = "raw"; // "raw", "chat", or "diff"
  var columnLayout = "side"; // "side" = side-by-side (default), "stacked" = response below request
  var showDiffInRaw = false; // diff overlay in raw view
  var cachedData = null; // last loaded recording data
  var autoRefresh = true; // auto-refresh toggle state
  var beautifyJson = true; // beautify JSON bodies in raw/chat views

  // Diff toolbar state
  var diffLayout = "inline"; // "inline" | "side-by-side"
  var sortOrder = "desc"; // "desc" (newest first) | "asc" (oldest first)

  // ---- Persist user preferences in localStorage -------------------------

  var PREFS_KEY = "scruxy-recordings-prefs";

  function savePrefs() {
    try {
      localStorage.setItem(PREFS_KEY, JSON.stringify({
        viewMode: viewMode,
        session: sessionSelect.value,
        sortOrder: sortOrder,
        diffLayout: diffLayout,
        diffOnly: chkDiffOnly ? chkDiffOnly.checked : false,
        wordDiff: chkWordDiff ? chkWordDiff.checked : false,
        ignoreWS: chkIgnoreWS ? chkIgnoreWS.checked : false,
        wordWrap: chkWordWrap ? chkWordWrap.checked : true,
        autoRefresh: autoRefresh,
        beautifyJson: beautifyJson,
        showDiffInRaw: showDiffInRaw,
        columnLayout: columnLayout,
        filterProviderVal: filterProvider ? filterProvider.value : "",
        filterProxyVal: filterProxy ? filterProxy.value : "",
        filterSearchVal: filterSearch ? filterSearch.value : "",
      }));
    } catch (_) { /* ignore quota errors */ }
  }

  function loadPrefs() {
    try {
      var raw = localStorage.getItem(PREFS_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (_) { return null; }
  }

  // Known provider upstream URLs (populated from dashboard API)
  var providerUrls = {};
  (function () {
    try {
      apiFetch("/ui/api/dashboard").then(function (d) {
        var provs = d.providers || {};
        Object.keys(provs).forEach(function (name) {
          if (provs[name].upstream_url) providerUrls[name] = provs[name].upstream_url.replace(/\/+$/, "");
        });
      });
    } catch (_) { /* ignore */ }
  })();

  /** Build a display URL from a recording entry, falling back to provider base + path. */
  function getDisplayUrl(entry) {
    if (entry.url) return entry.url;
    var base = providerUrls[(entry.provider || "").toLowerCase()] || providerUrls[entry.provider || ""];
    if (base && entry.path) return base + "/" + entry.path.replace(/^\/+/, "");
    return entry.path || "--";
  }

  // Expanded-card state preserved across view switches / diff option changes
  var expandedPairIds = {};   // request_id → true
  var expandedSseParts = {};  // request_id → true

  // ---- Session loading ------------------------------------------------

  async function loadSessions() {
    var previousValue = sessionSelect.value;
    try {
      var data = await apiFetch("/ui/api/sessions");
      sessionSelect.innerHTML = '<option value="">-- Select a session --</option>';
      (data.sessions || []).forEach(function (s) {
        var opt = document.createElement("option");
        opt.value = s.session_id;
        opt.textContent = (s.title ? s.title.substring(0, 60) + " — " : "") + truncateId(s.session_id, 24) + " (" + (s.provider || "unknown") + ")";
        if (s.title) opt.title = s.title;
        sessionSelect.appendChild(opt);
      });
      if (previousValue && sessionSelect.querySelector('option[value="' + previousValue + '"]')) {
        sessionSelect.value = previousValue;
      }
    } catch (_) {
      /* ignore */
    }
  }

  // ---- Helpers --------------------------------------------------------

  function prettyJson(obj) {
    if (!obj || typeof obj !== "object") return String(obj || "");
    try {
      return beautifyJson
        ? JSON.stringify(obj, null, 2)
        : JSON.stringify(obj);
    } catch (_) { return String(obj); }
  }

  /** Detect provider from a pair or entry. */
  function detectProvider(pair) {
    if (pair && pair.request && pair.request.provider) return pair.request.provider;
    if (pair && pair.provider) return pair.provider;
    return "unknown";
  }

  // ====================================================================
  //  RAW JSON VIEW (original)
  // ====================================================================

  /** Build a collapsible headers section. */
  function buildHeadersSection(headers) {
    if (!headers || typeof headers !== "object" || Object.keys(headers).length === 0) return null;
    var toggle = el("button", { className: "rec-headers-toggle", textContent: "\u25B6 Headers (" + Object.keys(headers).length + ")" });
    var body = el("div", { className: "rec-headers-body" });
    Object.keys(headers).forEach(function (k) {
      body.appendChild(el("div", { className: "rec-header-row" }, [
        el("span", { className: "hdr-key", textContent: k }),
        el("span", { className: "hdr-val", textContent: headers[k] }),
      ]));
    });
    toggle.addEventListener("click", function (e) {
      e.stopPropagation();
      var open = body.classList.toggle("open");
      toggle.textContent = (open ? "\u25BC" : "\u25B6") + " Headers (" + Object.keys(headers).length + ")";
    });
    return el("div", {}, [toggle, body]);
  }

  /** Build a body block with scrubbed/unscrubbed toggle. */
  function buildBodyWithToggle(scrubbed, original) {
    var container = el("div", {});
    var preBlock = el("pre", { className: "rec-json-block", textContent: prettyJson(scrubbed) });
    var showingOriginal = false;

    if (original) {
      var label = el("label", { className: "rec-body-toggle-label" });
      var toggleSwitch = el("span", { className: "toggle-sm" });
      var labelText = el("span", { textContent: "scrubbed" });
      label.appendChild(toggleSwitch);
      label.appendChild(labelText);
      label.addEventListener("click", function (e) {
        e.stopPropagation();
        showingOriginal = !showingOriginal;
        toggleSwitch.classList.toggle("active", showingOriginal);
        labelText.textContent = showingOriginal ? "unscrubbed" : "scrubbed";
        preBlock.textContent = prettyJson(showingOriginal ? original : scrubbed);
      });
      container.appendChild(label);
    }

    container.appendChild(preBlock);
    return container;
  }

  /** Build a latency breakdown row showing the full request lifecycle. */
  function buildLatencyRow(req, resp) {
    var scrubMs = req && req.latency_ms;
    var networkMs = resp && resp.network_ms;
    var unscrubMs = resp && resp.unscrub_ms;
    var totalMs = resp && resp.total_ms;

    // Need at least one value to render
    if (scrubMs == null && networkMs == null && unscrubMs == null && totalMs == null) return null;

    var items = [];

    // Always show the full pipeline: scrub → network → unscrub = total
    items.push(latItem("scrub", scrubMs, "var(--warning)"));
    items.push(latArrow());
    items.push(latItem("network", networkMs, "var(--info)"));
    items.push(latArrow());
    items.push(latItem("unscrub", unscrubMs, "var(--success)"));
    if (totalMs != null) {
      items.push(latSep());
      items.push(latItem("total", totalMs, "var(--text-primary)"));
    }

    return el("div", { className: "rec-latency-row" }, items);
  }

  function latItem(label, ms, color) {
    var valueText = ms != null ? ms.toFixed(1) + "ms" : "--";
    var valueEl = el("span", { className: "lat-value", textContent: valueText });
    if (color) valueEl.style.color = color;
    return el("span", { className: "lat-item" }, [
      el("span", { className: "lat-label", textContent: label + ":" }),
      valueEl,
    ]);
  }

  function latArrow() {
    return el("span", { className: "lat-arrow", textContent: "\u2192" });
  }

  function latSep() {
    return el("span", { className: "lat-sep", textContent: "=" });
  }

  /** Build a pipeline breakdown row showing per-stage timing. */
  function buildPipelineRow(breakdown) {
    if (!breakdown || !Array.isArray(breakdown) || breakdown.length === 0) return null;
    var flow = el("span", { className: "rec-pipeline-flow" });
    flow.appendChild(el("span", { className: "pipe-stage", textContent: "req" }));
    breakdown.forEach(function (b) {
      flow.appendChild(el("span", { className: "pipe-arrow", textContent: "\u21D2" }));
      var stageEl = el("span", { className: "pipe-stage" });
      stageEl.appendChild(document.createTextNode(b.stage));
      // Show timing if available, otherwise entity count
      var detail = b.ms != null ? b.ms.toFixed(0) + "ms" : (b.count != null ? b.count : "");
      if (detail) {
        var detailSpan = el("span", { className: "pipe-count", textContent: " " + detail });
        stageEl.appendChild(detailSpan);
      }
      // Show entity count alongside timing if both present
      if (b.ms != null && b.count > 0) {
        var entSpan = el("span", { className: "pipe-count", textContent: " (" + b.count + ")" });
        stageEl.appendChild(entSpan);
      }
      flow.appendChild(stageEl);
    });
    flow.appendChild(el("span", { className: "pipe-arrow", textContent: "\u21D2" }));
    flow.appendChild(el("span", { className: "pipe-stage", textContent: "LLM API" }));
    return el("div", { className: "rec-pipeline-row" }, [flow]);
  }

  function buildPairCard(pair) {
    var req = pair.request;
    var resp = pair.response;
    var sessionId = pair.session_id || (req && req.session_id) || (resp && resp.session_id) || "";
    var pairId = (req && req.request_id) || (resp && resp.request_id) || "";

    var ts = (req && req.ts) || (resp && resp.ts) || "";
    var method = (req && req.method) || "--";
    var displayUrl = req ? getDisplayUrl(req) : "--";
    var provider = (req && req.provider) || "--";
    var entities = (req && req.pii_entities_found) || 0;
    var proxyType = (req && req.proxy_type) || "";
    var latency = (req && req.latency_ms) ? req.latency_ms.toFixed(1) + "ms" : "--";
    var status = (resp && resp.status) || "--";
    var streaming = resp && resp.streaming;

    // Header row
    var leftItems = [
      el("span", { className: "badge badge-info", textContent: method }),
      el("span", { className: "mono text-sm", textContent: displayUrl }),
      el("span", { className: "badge badge-neutral", textContent: provider }),
      proxyType ? el("span", { className: "badge badge-outline text-xs", textContent: proxyType === "forward" ? "FWD" : "REV" }) : null,
    ];
    if (sessionId) {
      leftItems.push(el("span", { className: "badge badge-outline text-xs", textContent: truncateId(sessionId, 12) }));
    }
    var headerLeft = el("div", { className: "flex items-center gap-2" }, leftItems);

    var headerRight = el("div", { className: "flex items-center gap-2" }, [
      el("span", { className: "text-xs text-muted", textContent: formatDate(ts) }),
      entities > 0
        ? el("span", { className: "badge badge-warning", textContent: entities + " entities" })
        : el("span", {}),
      el("span", {
        className: "badge " + (status >= 200 && status < 300 ? "badge-success" : status === "--" ? "badge-neutral" : "badge-danger"),
        textContent: String(status) + (streaming ? " SSE" : ""),
      }),
      el("span", { className: "text-xs text-muted", textContent: latency }),
    ]);

    var header = el("div", { className: "rec-pair-header" }, [headerLeft, headerRight]);

    var isExpanded = !!(pairId && expandedPairIds[pairId]);
    var bodyContent = el("div", { className: "rec-pair-body" + (isExpanded ? "" : " hidden") });
    if (isExpanded) header.classList.add("expanded");

    // Latency breakdown row
    var latRow = buildLatencyRow(req, resp);
    if (latRow) bodyContent.appendChild(latRow);

    // Pipeline breakdown row
    var pipeRow = req ? buildPipelineRow(req.pipeline_breakdown) : null;
    if (pipeRow) bodyContent.appendChild(pipeRow);

    var columnsClass = columnLayout === "stacked" ? "rec-pair-columns stacked" : "rec-pair-columns";
    var columns = el("div", { className: columnsClass });

    if (req && req.body_scrubbed) {
      var reqChildren = [
        el("div", { className: "rec-col-label" }, [el("span", { className: "badge badge-info", textContent: "REQUEST" })]),
      ];
      // Headers section
      var reqHeaders = buildHeadersSection(req.headers);
      if (reqHeaders) reqChildren.push(reqHeaders);
      // Body with scrubbed/unscrubbed toggle or diff overlay
      if (showDiffInRaw && req.body_original && typeof req.body_original === "object") {
        var reqOrigStr = prettyJson(req.body_original);
        var reqScrubStr = prettyJson(req.body_scrubbed);
        if (reqOrigStr !== reqScrubStr) {
          reqChildren.push(buildLineDiff(reqOrigStr, reqScrubStr, "Original", "Scrubbed", "badge-neutral", "badge-info"));
        } else {
          reqChildren.push(el("pre", { className: "rec-json-block", textContent: reqScrubStr }));
        }
      } else {
        reqChildren.push(buildBodyWithToggle(req.body_scrubbed, req.body_original));
      }
      columns.appendChild(el("div", { className: "rec-pair-col" }, reqChildren));
    }

    if (resp) {
      var respChildren = [
        el("div", { className: "rec-col-label" }, [el("span", { className: "badge badge-success", textContent: "RESPONSE" })]),
      ];
      // Headers section
      var respHeaders = buildHeadersSection(resp.headers);
      if (respHeaders) respChildren.push(respHeaders);

      // Body with scrubbed/unscrubbed toggle
      if (resp.body_scrubbed) {
        // Exclude sse_parts from the JSON preview — they have their own section
        var jsonBody = resp.body_scrubbed;
        if (jsonBody.sse_parts) {
          jsonBody = {};
          Object.keys(resp.body_scrubbed).forEach(function (k) {
            if (k !== "sse_parts") jsonBody[k] = resp.body_scrubbed[k];
          });
        }
        if (showDiffInRaw && resp.body_original && typeof resp.body_original === "object") {
          var respScrubStr2 = prettyJson(jsonBody);
          var respOrigStr2 = prettyJson(resp.body_original);
          if (respScrubStr2 !== respOrigStr2) {
            respChildren.push(buildLineDiff(respScrubStr2, respOrigStr2, "Scrubbed (from LLM)", "Unscrubbed (sent to client)", "badge-success", "badge-neutral"));
          } else {
            respChildren.push(el("pre", { className: "rec-json-block", textContent: respScrubStr2 }));
          }
        } else {
          respChildren.push(buildBodyWithToggle(jsonBody, resp.body_original));
        }

        // Show expandable SSE parts for streaming responses
        var sseParts = resp.body_scrubbed.sse_parts;
        if (sseParts && sseParts.length > 0) {
          var sseExpanded = !!(pairId && expandedSseParts[pairId]);
          var sseLabel = " SSE Events (" + sseParts.length + (resp.body_scrubbed.sse_parts_truncated ? "+" : "") + ")";
          var sseToggle = el("button", {
            className: "btn btn-xs btn-outline sse-parts-toggle",
            textContent: (sseExpanded ? "\u25BC" : "\u25B6") + sseLabel,
          });
          var sseBody = el("div", { className: "sse-parts-body" + (sseExpanded ? "" : " hidden") });

          var rows = sseParts.map(function (p) {
            var display = typeof p.t === "string" ? JSON.stringify(p.t) : String(p.t);
            return el("div", { className: "sse-part-row" }, [
              el("span", { className: "sse-part-idx", textContent: String(p.i) }),
              el("span", { className: "sse-part-text mono", textContent: display }),
            ]);
          });
          rows.forEach(function (r) { sseBody.appendChild(r); });
          if (resp.body_scrubbed.sse_parts_truncated) {
            sseBody.appendChild(el("div", { className: "text-xs text-muted", textContent: "\u2026 (remaining parts omitted)" }));
          }

          sseToggle.addEventListener("click", function (e) {
            e.stopPropagation();
            var hidden = sseBody.classList.toggle("hidden");
            sseToggle.textContent = (hidden ? "\u25B6" : "\u25BC") + sseLabel;
            if (pairId) {
              if (hidden) delete expandedSseParts[pairId];
              else expandedSseParts[pairId] = true;
            }
          });

          respChildren.push(sseToggle);
          respChildren.push(sseBody);
        }
      }

      columns.appendChild(el("div", { className: "rec-pair-col" }, respChildren));
    }

    bodyContent.appendChild(columns);

    header.addEventListener("click", function () {
      var nowHidden = bodyContent.classList.toggle("hidden");
      header.classList.toggle("expanded");
      if (pairId) {
        if (nowHidden) delete expandedPairIds[pairId];
        else expandedPairIds[pairId] = true;
      }
    });

    var card = el("div", { className: "rec-pair-card card" }, [header, bodyContent]);
    if (pairId) card.setAttribute("data-request-id", pairId);
    return card;
  }

  function buildUnpairedCard(entry) {
    var direction = entry.dir || "unknown";
    var ts = entry.ts || "";
    var content = prettyJson(entry.body_scrubbed || entry);

    return el("div", { className: "rec-pair-card card" }, [
      el("div", { className: "rec-pair-header" }, [
        el("div", { className: "flex items-center gap-2" }, [
          el("span", {
            className: "badge " + (direction === "request" ? "badge-info" : "badge-success"),
            textContent: direction,
          }),
          el("span", { className: "text-xs text-muted", textContent: formatDate(ts) }),
          entry.method ? el("span", { className: "mono text-sm", textContent: entry.method + " " + (entry.path || "") }) : el("span", {}),
        ]),
      ]),
      el("pre", { className: "rec-json-block text-sm", textContent: content }),
    ]);
  }

  // ---- Debounce utility -----------------------------------------------

  function debounce(fn, delay) {
    var timer;
    return function () {
      var ctx = this, args = arguments;
      clearTimeout(timer);
      timer = setTimeout(function () { fn.apply(ctx, args); }, delay);
    };
  }

  // ---- Filter functions -----------------------------------------------

  /** Populate the provider dropdown from the current pairs data. */
  function populateProviderFilter(pairs) {
    if (!filterProvider) return;
    var providers = {};
    pairs.forEach(function (pair) {
      var p = (pair.request && pair.request.provider) || "";
      if (p) providers[p] = true;
    });
    var current = filterProvider.value;
    filterProvider.innerHTML = '<option value="">All Providers</option>';
    Object.keys(providers).sort().forEach(function (p) {
      var opt = document.createElement("option");
      opt.value = p;
      opt.textContent = p;
      filterProvider.appendChild(opt);
    });
    if (current) filterProvider.value = current;
  }

  /** Filter pairs based on current filter control values. */
  function filterPairs(pairs) {
    var provFilter = filterProvider ? filterProvider.value : "";
    var proxyFilter = filterProxy ? filterProxy.value : "";
    var searchFilter = filterSearch ? filterSearch.value.toLowerCase().trim() : "";

    if (!provFilter && !proxyFilter && !searchFilter) return pairs;

    return pairs.filter(function (pair) {
      var req = pair.request;
      var resp = pair.response;

      // Provider filter
      if (provFilter) {
        var pairProvider = (req && req.provider) || "";
        if (pairProvider !== provFilter) return false;
      }

      // Proxy type filter
      if (proxyFilter) {
        var pairProxy = (req && req.proxy_type) || "";
        if (pairProxy !== proxyFilter) return false;
      }

      // Text search
      if (searchFilter) {
        var haystack = [
          req && req.method,
          req && req.path,
          req && req.url,
          req && req.provider,
          resp && resp.status,
          req ? JSON.stringify(req.body_scrubbed || "") : "",
          resp ? JSON.stringify(resp.body_scrubbed || "") : "",
        ].join(" ").toLowerCase();
        if (haystack.indexOf(searchFilter) === -1) return false;
      }

      return true;
    });
  }

  /** Update the "Showing X of Y" counter. */
  function updateFilterCount(filtered, total) {
    if (!filterCountEl) return;
    if (filtered === total) {
      filterCountEl.textContent = "";
    } else {
      filterCountEl.textContent = "Showing " + filtered + " of " + total + " recordings";
    }
  }

  /** Return pairs in the current sort order (desc = newest first). */
  function sortPairs(pairs) {
    var copy = pairs.slice();
    if (sortOrder === "desc") copy.reverse();
    return copy;
  }

  function renderRawView(data) {
    var pairs = data.pairs || [];
    var unpaired = data.unpaired || [];

    if (pairs.length === 0 && unpaired.length === 0) {
      var recordings = data.recordings || [];
      if (recordings.length === 0) {
        timeline.innerHTML = '<div class="empty-state text-sm">No recordings for this session</div>';
        return;
      }
      timeline.innerHTML = "";
      recordings.forEach(function (entry) { timeline.appendChild(buildUnpairedCard(entry)); });
      return;
    }

    timeline.innerHTML = "";
    sortPairs(pairs).forEach(function (pair) { timeline.appendChild(buildPairCard(pair)); });
    unpaired.forEach(function (entry) { timeline.appendChild(buildUnpairedCard(entry)); });
  }

  // ====================================================================
  //  CHAT VIEW
  // ====================================================================

  /** Extract human-readable messages from an Anthropic request body. */
  function extractAnthropicRequestMessages(body) {
    if (!body || typeof body !== "object") return [];
    var msgs = [];

    // System prompt
    var sys = body.system;
    if (typeof sys === "string" && sys.trim()) {
      msgs.push({ role: "system", text: sys });
    } else if (Array.isArray(sys)) {
      var sysText = sys.filter(function (b) { return b && b.type === "text"; })
                       .map(function (b) { return b.text || ""; }).join("\n");
      if (sysText.trim()) msgs.push({ role: "system", text: sysText });
    }

    // Messages array
    (body.messages || []).forEach(function (m) {
      if (!m || !m.role) return;
      var role = m.role; // "user" or "assistant"
      var content = m.content;

      if (typeof content === "string") {
        if (content.trim()) msgs.push({ role: role, text: content });
      } else if (Array.isArray(content)) {
        content.forEach(function (block) {
          if (!block) return;
          if (block.type === "text" && block.text) {
            msgs.push({ role: role, text: block.text });
          } else if (block.type === "tool_use") {
            msgs.push({ role: role, text: "Tool call: " + (block.name || "unknown"), kind: "tool_use", detail: block.input });
          } else if (block.type === "tool_result") {
            var resultText = "";
            if (typeof block.content === "string") resultText = block.content;
            else if (Array.isArray(block.content)) {
              resultText = block.content.filter(function (b) { return b && b.type === "text"; })
                                         .map(function (b) { return b.text || ""; }).join("\n");
            }
            msgs.push({ role: "tool", text: resultText || "(empty result)", kind: "tool_result", toolId: block.tool_use_id });
          }
        });
      }
    });

    return msgs;
  }

  /** Extract human-readable messages from an Anthropic response body. */
  function extractAnthropicResponseMessages(body) {
    if (!body || typeof body !== "object") return [];
    var msgs = [];
    var content = body.content;
    if (!Array.isArray(content)) return msgs;

    content.forEach(function (block) {
      if (!block) return;
      if (block.type === "text" && block.text) {
        msgs.push({ role: "assistant", text: block.text });
      } else if (block.type === "tool_use") {
        msgs.push({ role: "assistant", text: "Tool call: " + (block.name || "unknown"), kind: "tool_use", detail: block.input });
      }
    });
    return msgs;
  }

  /** Extract human-readable messages from an OpenAI request body. */
  function extractOpenAIRequestMessages(body) {
    if (!body || typeof body !== "object") return [];
    var msgs = [];

    (body.messages || []).forEach(function (m) {
      if (!m || !m.role) return;
      var role = m.role;
      var content = m.content;

      if (typeof content === "string") {
        if (content.trim()) msgs.push({ role: role, text: content });
      } else if (Array.isArray(content)) {
        content.forEach(function (part) {
          if (part && part.type === "text" && part.text) {
            msgs.push({ role: role, text: part.text });
          }
        });
      }

      // Tool calls
      if (Array.isArray(m.tool_calls)) {
        m.tool_calls.forEach(function (tc) {
          if (!tc || !tc.function) return;
          msgs.push({ role: role, text: "Tool call: " + (tc.function.name || "unknown"), kind: "tool_use", detail: tc.function.arguments });
        });
      }
    });

    return msgs;
  }

  /** Extract human-readable messages from an OpenAI response body. */
  function extractOpenAIResponseMessages(body) {
    if (!body || typeof body !== "object") return [];
    var msgs = [];

    (body.choices || []).forEach(function (choice) {
      if (!choice || !choice.message) return;
      var m = choice.message;
      if (m.content && typeof m.content === "string" && m.content.trim()) {
        msgs.push({ role: "assistant", text: m.content });
      }
      if (Array.isArray(m.tool_calls)) {
        m.tool_calls.forEach(function (tc) {
          if (!tc || !tc.function) return;
          msgs.push({ role: "assistant", text: "Tool call: " + (tc.function.name || "unknown"), kind: "tool_use", detail: tc.function.arguments });
        });
      }
    });
    return msgs;
  }

  /** Extract messages from an OpenAI Responses API request body ($.input). */
  function extractResponsesApiRequestMessages(body) {
    if (!body || typeof body !== "object") return [];
    var msgs = [];

    // Instructions (system prompt)
    var instructions = body.instructions;
    if (typeof instructions === "string" && instructions.trim()) {
      msgs.push({ role: "system", text: instructions });
    }

    // Input can be a string or array
    var input = body.input;
    if (typeof input === "string" && input.trim()) {
      msgs.push({ role: "user", text: input });
    } else if (Array.isArray(input)) {
      input.forEach(function (item) {
        if (!item) return;
        // String items
        if (typeof item === "string") {
          msgs.push({ role: "user", text: item });
          return;
        }
        var role = item.role || "user";
        var content = item.content;
        // Simple string content
        if (typeof content === "string" && content.trim()) {
          msgs.push({ role: role, text: content });
        }
        // Array of content blocks
        else if (Array.isArray(content)) {
          content.forEach(function (block) {
            if (!block) return;
            if (typeof block === "string") {
              msgs.push({ role: role, text: block });
            } else if (block.type === "input_text" || block.type === "text") {
              var t = block.text || block.input_text || "";
              if (t.trim()) msgs.push({ role: role, text: t });
            } else if (block.type === "function_call") {
              msgs.push({ role: role, text: block.name + "(" + (block.arguments || "") + ")", kind: "tool_use", detail: block.name });
            } else if (block.type === "function_call_output") {
              var out = block.output || "";
              msgs.push({ role: "tool", text: typeof out === "string" ? out : JSON.stringify(out), kind: "tool_result" });
            }
          });
        }
        // Tool output shorthand
        if (item.type === "function_call_output") {
          var outText = item.output || "";
          msgs.push({ role: "tool", text: typeof outText === "string" ? outText : JSON.stringify(outText), kind: "tool_result" });
        }
      });
    }

    return msgs;
  }

  /** Extract messages from an OpenAI Responses API response body ($.output). */
  function extractResponsesApiResponseMessages(body) {
    if (!body || typeof body !== "object") return [];
    var msgs = [];

    var output = body.output;
    if (!Array.isArray(output)) return msgs;

    output.forEach(function (item) {
      if (!item) return;
      var role = item.role || "assistant";
      // Content array
      if (Array.isArray(item.content)) {
        item.content.forEach(function (block) {
          if (!block) return;
          if (block.type === "output_text" || block.type === "text") {
            var t = block.text || "";
            if (t.trim()) msgs.push({ role: role, text: t });
          }
        });
      }
      // Function call
      if (item.type === "function_call") {
        msgs.push({ role: role, text: (item.name || "function") + "(" + (item.arguments || "") + ")", kind: "tool_use", detail: item.name });
      }
    });

    // Fallback: if output_text is at top level (some response formats)
    if (msgs.length === 0 && body.output_text) {
      msgs.push({ role: "assistant", text: body.output_text });
    }

    return msgs;
  }

  // ---- Chat message box helpers ----------------------------------------

  /**
   * Build a message box with 5-line clamp, [expand] toggle, and [meta] button.
   * @param {object} msg  - { role, text, detail?, meta? }
   *   meta is a flat object of key/value pairs shown in a table on [meta] click.
   */
  function buildMsgBox(msg) {
    var role = msg.role || "unknown";
    var cssRole = role === "user" ? "user"
               : role === "assistant" ? "assistant"
               : role === "system" ? "system"
               : "tool";

    var box = el("div", { className: "chat-msg-box chat-msg-" + cssRole });

    // Role label
    box.appendChild(el("div", { className: "chat-msg-role", textContent: role }));

    // Main text (clamped to 5 lines)
    var textEl = null;
    var textStr = msg.text || "";
    if (textStr) {
      textEl = el("div", { className: "chat-msg-text clamped", textContent: textStr });
      box.appendChild(textEl);
    }

    // Tool detail (inline, also clamped with the text)
    if (msg.detail) {
      var detailStr = typeof msg.detail === "string" ? msg.detail : prettyJson(msg.detail);
      var detailPre = el("pre", {
        className: "chat-msg-text clamped",
        textContent: detailStr,
        style: "margin-top:4px;font-size:0.78rem;opacity:0.85;",
      });
      box.appendChild(detailPre);
    }

    // Actions row: [expand] and [meta]
    var actions = el("div", { className: "chat-msg-actions" });
    var hasOverflow = false; // will check after render

    // [expand] button — only useful if text overflows 5 lines
    var expandBtn = el("button", { textContent: "expand" });
    var expanded = false;
    expandBtn.addEventListener("click", function () {
      expanded = !expanded;
      if (textEl) textEl.classList.toggle("clamped", !expanded);
      if (msg.detail) {
        var dp = box.querySelector("pre.chat-msg-text");
        if (dp) dp.classList.toggle("clamped", !expanded);
      }
      expandBtn.textContent = expanded ? "collapse" : "expand";
    });
    actions.appendChild(expandBtn);

    // [meta] button — show/hide metadata table
    if (msg.meta && Object.keys(msg.meta).length > 0) {
      var metaTable = buildMetaTable(msg.meta);
      metaTable.style.display = "none";
      var metaBtn = el("button", { textContent: "meta" });
      metaBtn.addEventListener("click", function () {
        var showing = metaTable.style.display !== "none";
        metaTable.style.display = showing ? "none" : "";
        metaBtn.textContent = showing ? "meta" : "hide meta";
      });
      actions.appendChild(metaBtn);
      box.appendChild(actions);
      box.appendChild(metaTable);
    } else {
      box.appendChild(actions);
    }

    // After render: check if expand button is needed (text exceeds 5 lines).
    // Use a microtask so the DOM has been laid out.
    requestAnimationFrame(function () {
      var needs = false;
      if (textEl && textEl.scrollHeight > textEl.clientHeight + 2) needs = true;
      if (msg.detail) {
        var dp = box.querySelector("pre.chat-msg-text");
        if (dp && dp.scrollHeight > dp.clientHeight + 2) needs = true;
      }
      if (!needs) expandBtn.style.display = "none";
    });

    return box;
  }

  /** Build a small metadata table from a flat object. */
  function buildMetaTable(meta) {
    var table = el("table", { className: "chat-meta-table" });
    Object.keys(meta).forEach(function (key) {
      var val = meta[key];
      if (val === null || val === undefined) return;
      var valStr = typeof val === "object" ? prettyJson(val) : String(val);
      table.appendChild(el("tr", {}, [
        el("th", { textContent: key }),
        el("td", { textContent: valStr }),
      ]));
    });
    return table;
  }

  /**
   * Collect non-message metadata from an API request body.
   * Returns a flat object suitable for the [meta] table.
   */
  function extractRequestMeta(body) {
    if (!body || typeof body !== "object") return {};
    var meta = {};
    var skip = new Set(["messages", "system"]);
    Object.keys(body).forEach(function (k) {
      if (skip.has(k)) return;
      meta[k] = body[k];
    });
    return meta;
  }

  /**
   * Collect non-content metadata from an API response body.
   */
  function extractResponseMeta(body) {
    if (!body || typeof body !== "object") return {};
    var meta = {};
    var skip = new Set(["content", "choices"]);
    Object.keys(body).forEach(function (k) {
      if (skip.has(k)) return;
      meta[k] = body[k];
    });
    return meta;
  }

  // ---- Build a chat pair (two-column row) --------------------------------

  /** Render a request/response pair as a two-column row. */
  /** Wrap a message box in an aligned bubble row. */
  function wrapBubble(msgBox, align) {
    return el("div", { className: "chat-bubble-row " + align }, [msgBox]);
  }

  /** Render a request/response pair as a phone-style chat turn. */
  function buildChatPair(pair, provider, isFirstTurn) {
    var req = pair.request;
    var resp = pair.response;
    var isAnthropic = provider === "anthropic";
    var isResponsesApi = provider === "openai_responses" || provider === "copilot_responses";
    var turn = el("div", { className: "chat-turn" });

    // -- Request metadata (right-aligned) --
    var ts = (req && req.ts) || (resp && resp.ts) || "";
    var model = (req && req.body_scrubbed) ? req.body_scrubbed.model || "" : "";
    var metaItems = [
      el("span", { className: "text-xs text-muted", textContent: formatDate(ts) }),
    ];
    if (model) metaItems.push(el("span", { className: "badge badge-neutral", textContent: model }));
    var entities = (req && req.pii_entities_found) || 0;
    if (entities > 0) metaItems.push(el("span", { className: "badge badge-warning", textContent: entities + " PII" }));
    turn.appendChild(el("div", { className: "chat-turn-meta meta-right" }, metaItems));

    // Extract request messages
    var reqMsgs = [];
    var reqMeta = {};
    if (req && req.body_scrubbed && typeof req.body_scrubbed === "object") {
      if (isAnthropic) {
        reqMsgs = extractAnthropicRequestMessages(req.body_scrubbed);
      } else if (isResponsesApi) {
        reqMsgs = extractResponsesApiRequestMessages(req.body_scrubbed);
      } else {
        reqMsgs = extractOpenAIRequestMessages(req.body_scrubbed);
      }
      reqMeta = extractRequestMeta(req.body_scrubbed);
    }

    // System prompt (center-aligned, first turn only)
    if (isFirstTurn) {
      reqMsgs.filter(function (m) { return m.role === "system"; }).forEach(function (m) {
        m.meta = reqMeta;
        reqMeta = {};
        turn.appendChild(wrapBubble(buildMsgBox(m), "align-center"));
      });
    }

    // Last user message (right-aligned)
    var lastUserMsg = null;
    for (var i = reqMsgs.length - 1; i >= 0; i--) {
      if (reqMsgs[i].role === "user") { lastUserMsg = reqMsgs[i]; break; }
    }
    if (lastUserMsg) {
      lastUserMsg.meta = Object.keys(reqMeta).length > 0 ? reqMeta : undefined;
      reqMeta = {};
      turn.appendChild(wrapBubble(buildMsgBox(lastUserMsg), "align-right"));
    }

    // Tool interactions after last user message (center-aligned)
    var afterLast = false;
    reqMsgs.forEach(function (m) {
      if (m === lastUserMsg) { afterLast = true; return; }
      if (afterLast && (m.kind === "tool_use" || m.kind === "tool_result" || m.role === "tool")) {
        turn.appendChild(wrapBubble(buildMsgBox(m), "align-center"));
      }
    });

    // Edge case: no messages but meta exists
    if (!lastUserMsg && reqMsgs.length === 0 && Object.keys(reqMeta).length > 0) {
      turn.appendChild(wrapBubble(buildMsgBox({ role: "user", text: "(no message body)", meta: reqMeta }), "align-right"));
    }

    // -- Response messages (left-aligned) --
    var status = resp ? resp.status : "--";
    var streaming = resp && resp.streaming;
    var respMetaItems = [];
    if (status !== "--") {
      respMetaItems.push(el("span", {
        className: "badge " + (status >= 200 && status < 300 ? "badge-success" : "badge-danger"),
        textContent: String(status) + (streaming ? " SSE" : ""),
      }));
    }
    if (respMetaItems.length > 0) {
      turn.appendChild(el("div", { className: "chat-turn-meta" }, respMetaItems));
    }

    var respMsgs = [];
    var respMeta = {};
    if (resp && resp.body_scrubbed && typeof resp.body_scrubbed === "object") {
      if (resp.streaming && resp.body_scrubbed.text) {
        respMsgs = [{ role: "assistant", text: resp.body_scrubbed.text }];
        var sm = {};
        Object.keys(resp.body_scrubbed).forEach(function (k) {
          if (k !== "text") sm[k] = resp.body_scrubbed[k];
        });
        respMeta = sm;
      } else {
        if (isAnthropic) {
          respMsgs = extractAnthropicResponseMessages(resp.body_scrubbed);
        } else if (isResponsesApi) {
          respMsgs = extractResponsesApiResponseMessages(resp.body_scrubbed);
        } else {
          respMsgs = extractOpenAIResponseMessages(resp.body_scrubbed);
        }
        respMeta = extractResponseMeta(resp.body_scrubbed);
      }
    } else if (resp && typeof resp.body_scrubbed === "string") {
      respMsgs = [{ role: "assistant", text: resp.body_scrubbed }];
    }

    if (respMsgs.length > 0) {
      respMsgs.forEach(function (m, idx) {
        if (idx === 0) m.meta = Object.keys(respMeta).length > 0 ? respMeta : undefined;
        turn.appendChild(wrapBubble(buildMsgBox(m), "align-left"));
      });
    } else {
      turn.appendChild(el("div", { className: "chat-bubble-row align-left" }, [
        el("div", { className: "chat-empty-col", textContent: "No response data" }),
      ]));
    }

    return turn;
  }

  function renderChatView(data) {
    var pairs = data.pairs || [];
    if (pairs.length === 0) {
      timeline.innerHTML = '<div class="empty-state text-sm">No conversation messages found</div>';
      return;
    }

    timeline.innerHTML = "";

    // Detect provider from first pair
    var provider = detectProvider(pairs[0]);

    var sorted = sortPairs(pairs);
    // The "first turn" (system prompt) is the chronologically earliest pair
    var firstTurnIdx = sortOrder === "desc" ? sorted.length - 1 : 0;
    sorted.forEach(function (pair, idx) {
      if (idx > 0) {
        timeline.appendChild(el("hr", { className: "chat-pair-separator" }));
      }
      timeline.appendChild(buildChatPair(pair, provider, idx === firstTurnIdx));
    });
  }

  // ====================================================================
  //  MYERS DIFF ENGINE
  // ====================================================================

  /**
   * Myers diff algorithm — computes the shortest edit script between two
   * arrays of lines.  Returns an array of operations:
   *   { op: "equal"|"delete"|"insert", oldLine, newLine, text }
   */
  function myersDiff(oldLines, newLines) {
    var N = oldLines.length, M = newLines.length;
    var MAX = N + M;
    if (MAX === 0) return [];

    // Shortcut: both identical
    if (N === M) {
      var same = true;
      for (var i = 0; i < N; i++) { if (oldLines[i] !== newLines[i]) { same = false; break; } }
      if (same) return oldLines.map(function (l, idx) { return { op: "equal", oldLine: idx, newLine: idx, text: l }; });
    }

    // V array indexed by k+MAX
    var V = new Int32Array(2 * MAX + 2);
    V.fill(-1);
    V[MAX + 1] = 0;

    // Store traces for backtracking
    var traces = [];

    outer:
    for (var d = 0; d <= MAX; d++) {
      var Vcopy = new Int32Array(V);
      traces.push(Vcopy);
      for (var k = -d; k <= d; k += 2) {
        var idx = k + MAX;
        var x;
        if (k === -d || (k !== d && V[idx - 1] < V[idx + 1])) {
          x = V[idx + 1]; // move down
        } else {
          x = V[idx - 1] + 1; // move right
        }
        var y = x - k;
        while (x < N && y < M && oldLines[x] === newLines[y]) { x++; y++; }
        V[idx] = x;
        if (x >= N && y >= M) break outer;
      }
    }

    // Backtrack to build edit script
    var ops = [];
    var cx = N, cy = M;
    for (var d2 = traces.length - 1; d2 >= 0; d2--) {
      var Vd = traces[d2];
      var ck = cx - cy;
      var prevK;
      if (ck === -d2 || (ck !== d2 && Vd[ck - 1 + MAX] < Vd[ck + 1 + MAX])) {
        prevK = ck + 1;
      } else {
        prevK = ck - 1;
      }
      var prevX = Vd[prevK + MAX];
      if (prevX === undefined || prevX < 0) prevX = 0;
      var prevY = prevX - prevK;

      // Diagonal (equal) lines
      while (cx > prevX && cy > prevY) {
        cx--; cy--;
        ops.push({ op: "equal", oldLine: cx, newLine: cy, text: oldLines[cx] });
      }
      if (d2 > 0) {
        if (cx === prevX && cy > prevY) {
          cy--;
          ops.push({ op: "insert", oldLine: -1, newLine: cy, text: newLines[cy] });
        } else if (cx > prevX) {
          cx--;
          ops.push({ op: "delete", oldLine: cx, newLine: -1, text: oldLines[cx] });
        }
      }
    }
    ops.reverse();
    return ops;
  }

  /**
   * Tokenize a string into alternating word / whitespace tokens.
   */
  function tokenizeWords(str) {
    return str.match(/\S+|\s+/g) || [];
  }

  /**
   * Word-level diff within a single changed line pair.
   * Reuses myersDiff on word tokens — works on any text size.
   * Returns {oldSpans: [{text, changed}], newSpans: [{text, changed}]}
   */
  function wordDiff(oldStr, newStr) {
    var oldWords = tokenizeWords(oldStr);
    var newWords = tokenizeWords(newStr);
    var ops = myersDiff(oldWords, newWords);

    function buildSpans(side) {
      var spans = [], run = "", runChanged = false;
      for (var i = 0; i < ops.length; i++) {
        var o = ops[i];
        if (side === "old" && o.op === "insert") continue;
        if (side === "new" && o.op === "delete") continue;
        var changed = o.op !== "equal";
        if (run && changed !== runChanged) {
          spans.push({ text: run, changed: runChanged });
          run = "";
        }
        runChanged = changed;
        run += o.text;
      }
      if (run) spans.push({ text: run, changed: runChanged });
      return spans;
    }

    return { oldSpans: buildSpans("old"), newSpans: buildSpans("new") };
  }

  // ====================================================================
  //  SCRUB DIFF VIEW
  // ====================================================================

  var chkDiffOnly = document.getElementById("chk-diff-only");
  var chkWordDiff = document.getElementById("chk-word-diff");
  var chkIgnoreWS = document.getElementById("chk-ignore-ws");
  var chkWordWrap = document.getElementById("chk-word-wrap");
  var diffToolbar = document.getElementById("diff-toolbar");
  var btnLayoutInline = document.getElementById("btn-layout-inline");
  var btnLayoutSide = document.getElementById("btn-layout-side");

  // Re-render when any diff option changes — collapse expanded cards
  function _onDiffOptionChange() {
    savePrefs();
    if (cachedData && showDiffInRaw) {
      var expanded = timeline.querySelectorAll(".rec-pair-header.expanded");
      expanded.forEach(function (h) { h.classList.remove("expanded"); });
      var visibleBodies = timeline.querySelectorAll(".rec-pair-body:not(.hidden)");
      visibleBodies.forEach(function (b) { b.classList.add("hidden"); });
      render(cachedData);
    }
  }
  if (chkDiffOnly) chkDiffOnly.addEventListener("change", _onDiffOptionChange);
  if (chkWordDiff) chkWordDiff.addEventListener("change", _onDiffOptionChange);
  if (chkIgnoreWS) chkIgnoreWS.addEventListener("change", _onDiffOptionChange);
  if (chkWordWrap) chkWordWrap.addEventListener("change", _onDiffOptionChange);

  if (btnLayoutInline) btnLayoutInline.addEventListener("click", function () {
    diffLayout = "inline";
    btnLayoutInline.classList.add("active");
    btnLayoutSide.classList.remove("active");
    _onDiffOptionChange();
  });
  if (btnLayoutSide) btnLayoutSide.addEventListener("click", function () {
    diffLayout = "side-by-side";
    btnLayoutSide.classList.add("active");
    btnLayoutInline.classList.remove("active");
    _onDiffOptionChange();
  });

  /**
   * Normalize a line for comparison when ignoring whitespace.
   */
  function normalizeLine(line) {
    return line.trim().replace(/\s+/g, " ");
  }

  /**
   * Render a unified-style inline diff block from two text strings.
   * Returns a DOM element.
   */
  function buildInlineDiff(leftStr, rightStr, leftLabel, rightLabel, leftBadgeClass, rightBadgeClass) {
    var leftLines = leftStr.split("\n");
    var rightLines = rightStr.split("\n");
    var ignoreWS = chkIgnoreWS && chkIgnoreWS.checked;
    var compareLeft = ignoreWS ? leftLines.map(normalizeLine) : leftLines;
    var compareRight = ignoreWS ? rightLines.map(normalizeLine) : rightLines;
    var ops = myersDiff(compareLeft, compareRight);
    // Map back to original text for display
    var leftIdx = 0, rightIdx = 0;
    ops.forEach(function (o) {
      if (o.op === "equal") { o.text = leftLines[leftIdx]; leftIdx++; rightIdx++; }
      else if (o.op === "delete") { o.text = leftLines[leftIdx]; leftIdx++; }
      else { o.text = rightLines[rightIdx]; rightIdx++; }
    });

    var identical = ops.every(function (o) { return o.op === "equal"; });
    var diffOnly = chkDiffOnly && chkDiffOnly.checked;
    var doWordDiff = chkWordDiff && chkWordDiff.checked;
    var wordWrap = chkWordWrap && chkWordWrap.checked;
    var wrapClass = wordWrap ? " word-wrap" : " no-wrap";

    var changeCount = ops.filter(function (o) { return o.op !== "equal"; }).length;

    var header = el("div", { className: "diff-line-header" }, [
      el("span", { className: "badge " + leftBadgeClass, textContent: leftLabel }),
      identical
        ? el("span", { className: "text-xs text-muted", textContent: "(identical)" })
        : el("span", { className: "badge badge-warning text-xs", textContent: changeCount + " line changes" }),
      el("span", { className: "badge " + rightBadgeClass, textContent: rightLabel }),
    ]);

    if (identical && diffOnly) {
      return el("div", { className: "diff-block" }, [header,
        el("div", { className: "text-xs text-muted p-2", textContent: "No differences" })
      ]);
    }

    var table = el("div", { className: "diff-table" });
    var CONTEXT = 3;

    var showMask = new Uint8Array(ops.length);
    if (diffOnly) {
      for (var i = 0; i < ops.length; i++) {
        if (ops[i].op !== "equal") {
          for (var j = Math.max(0, i - CONTEXT); j <= Math.min(ops.length - 1, i + CONTEXT); j++) {
            showMask[j] = 1;
          }
        }
      }
    } else {
      showMask.fill(1);
    }

    // Pair up deletes and inserts for word diff
    var wordPairs = {};
    if (doWordDiff && !identical) {
      var deleteRuns = [], insertRuns = [];
      for (var idx = 0; idx <= ops.length; idx++) {
        var op = idx < ops.length ? ops[idx] : null;
        if (op && op.op === "delete") { deleteRuns.push(idx); continue; }
        if (op && op.op === "insert") { insertRuns.push(idx); continue; }
        var pairCount = Math.min(deleteRuns.length, insertRuns.length);
        for (var p = 0; p < pairCount; p++) {
          var wd = wordDiff(ops[deleteRuns[p]].text, ops[insertRuns[p]].text);
          wordPairs[deleteRuns[p]] = wd.oldSpans;
          wordPairs[insertRuns[p]] = wd.newSpans;
        }
        deleteRuns = []; insertRuns = [];
      }
    }

    var lastShown = -2;
    var leftNum = 0, rightNum = 0;
    for (var idx2 = 0; idx2 < ops.length; idx2++) {
      var o = ops[idx2];
      if (o.op === "equal") { leftNum++; rightNum++; }
      else if (o.op === "delete") { leftNum++; }
      else { rightNum++; }

      if (!showMask[idx2]) continue;

      if (diffOnly && lastShown >= 0 && idx2 - lastShown > 1) {
        table.appendChild(el("div", { className: "diff-row diff-ellipsis", textContent: "···" }));
      }
      lastShown = idx2;

      var row = el("div", { className: "diff-row diff-" + o.op + wrapClass });
      var prefix = o.op === "equal" ? " " : o.op === "delete" ? "-" : "+";
      var ln = el("span", { className: "diff-ln" });
      ln.textContent = o.op === "insert" ? "" : String(leftNum);
      var rn = el("span", { className: "diff-rn" });
      rn.textContent = o.op === "delete" ? "" : String(rightNum);
      var pfx = el("span", { className: "diff-pfx", textContent: prefix });

      var content = el("span", { className: "diff-content" });
      if (wordPairs[idx2]) {
        wordPairs[idx2].forEach(function (sp) {
          var s = document.createElement("span");
          s.textContent = sp.text;
          if (sp.changed) s.className = o.op === "delete" ? "char-del" : "char-ins";
          content.appendChild(s);
        });
      } else {
        content.textContent = o.text;
      }

      row.appendChild(ln);
      row.appendChild(rn);
      row.appendChild(pfx);
      row.appendChild(content);
      table.appendChild(row);
    }

    return el("div", { className: "diff-block" }, [header, table]);
  }

  /**
   * Build a side-by-side diff view with synchronized line pairing.
   */
  function buildSideBySideDiff(leftStr, rightStr, leftLabel, rightLabel, leftBadgeClass, rightBadgeClass) {
    var leftLines = leftStr.split("\n");
    var rightLines = rightStr.split("\n");
    var ignoreWS = chkIgnoreWS && chkIgnoreWS.checked;
    var compareLeft = ignoreWS ? leftLines.map(normalizeLine) : leftLines;
    var compareRight = ignoreWS ? rightLines.map(normalizeLine) : rightLines;
    var ops = myersDiff(compareLeft, compareRight);
    // Map back to display text
    var li = 0, ri = 0;
    ops.forEach(function (o) {
      if (o.op === "equal") { o.leftText = leftLines[li]; o.rightText = rightLines[ri]; li++; ri++; }
      else if (o.op === "delete") { o.leftText = leftLines[li]; o.rightText = null; li++; }
      else { o.leftText = null; o.rightText = rightLines[ri]; ri++; }
    });

    var identical = ops.every(function (o) { return o.op === "equal"; });
    var diffOnly = chkDiffOnly && chkDiffOnly.checked;
    var doWordDiff = chkWordDiff && chkWordDiff.checked;
    var wordWrap = chkWordWrap && chkWordWrap.checked;
    var wrapClass = wordWrap ? " word-wrap" : " no-wrap";
    var changeCount = ops.filter(function (o) { return o.op !== "equal"; }).length;

    var header = el("div", { className: "diff-line-header" }, [
      el("span", { className: "badge " + leftBadgeClass, textContent: leftLabel }),
      identical
        ? el("span", { className: "text-xs text-muted", textContent: "(identical)" })
        : el("span", { className: "badge badge-warning text-xs", textContent: changeCount + " line changes" }),
      el("span", { className: "badge " + rightBadgeClass, textContent: rightLabel }),
    ]);

    if (identical && diffOnly) {
      return el("div", { className: "diff-block" }, [header,
        el("div", { className: "text-xs text-muted p-2", textContent: "No differences" })
      ]);
    }

    var CONTEXT = 3;
    var showMask = new Uint8Array(ops.length);
    if (diffOnly) {
      for (var i = 0; i < ops.length; i++) {
        if (ops[i].op !== "equal") {
          for (var j = Math.max(0, i - CONTEXT); j <= Math.min(ops.length - 1, i + CONTEXT); j++) {
            showMask[j] = 1;
          }
        }
      }
    } else {
      showMask.fill(1);
    }

    // Pair deletes/inserts into aligned rows
    var rows = [];
    var pendingDel = [], pendingIns = [];
    function flushPending() {
      var max = Math.max(pendingDel.length, pendingIns.length);
      for (var k = 0; k < max; k++) {
        rows.push({
          left: k < pendingDel.length ? pendingDel[k] : null,
          right: k < pendingIns.length ? pendingIns[k] : null,
          opIdx: k < pendingDel.length ? pendingDel[k]._idx : pendingIns[k]._idx,
        });
      }
      pendingDel = []; pendingIns = [];
    }
    for (var i2 = 0; i2 < ops.length; i2++) {
      var o2 = ops[i2];
      o2._idx = i2;
      if (o2.op === "delete") { pendingDel.push(o2); }
      else if (o2.op === "insert") { pendingIns.push(o2); }
      else { flushPending(); rows.push({ left: o2, right: o2, opIdx: i2 }); }
    }
    flushPending();

    // Compute word diff pairs for aligned change rows
    var wordPairsMap = {};
    if (doWordDiff && !identical) {
      rows.forEach(function (r, ri2) {
        if (r.left && r.right && r.left !== r.right && r.left.leftText !== null && r.right.rightText !== null) {
          var wd2 = wordDiff(r.left.leftText, r.right.rightText);
          wordPairsMap[ri2] = wd2;
        }
      });
    }

    // Build a single scrollable table with paired rows (avoids scroll sync issues)
    var table = el("div", { className: "diff-side-table" });
    var lastShown2 = -2;
    var leftNum2 = 0, rightNum2 = 0;

    rows.forEach(function (r, ri3) {
      if (r.left && r.left.op === "equal") leftNum2++;
      else if (r.left && r.left.op === "delete") leftNum2++;
      if (r.right && r.right.op === "equal") rightNum2++;
      else if (r.right && r.right.op === "insert") rightNum2++;

      if (!showMask[r.opIdx]) return;

      if (diffOnly && lastShown2 >= 0 && r.opIdx - lastShown2 > 1) {
        table.appendChild(el("div", { className: "diff-side-row" }, [
          el("div", { className: "diff-side-half diff-ellipsis" + wrapClass, textContent: "···" }),
          el("div", { className: "diff-side-half diff-ellipsis" + wrapClass, textContent: "···" }),
        ]));
      }
      lastShown2 = r.opIdx;

      // Left half
      var leftOp = (r.left && r.left.op !== "equal") ? "delete" : (r.left ? "equal" : "empty");
      var leftLn = el("span", { className: "diff-ln", textContent: r.left ? String(leftNum2) : "" });
      var leftContent = el("span", { className: "diff-content" });
      if (wordPairsMap[ri3] && r.left) {
        wordPairsMap[ri3].oldSpans.forEach(function (sp) {
          var s = document.createElement("span");
          s.textContent = sp.text;
          if (sp.changed) s.className = "char-del";
          leftContent.appendChild(s);
        });
      } else if (r.left && r.left.leftText !== null) {
        leftContent.textContent = r.left.leftText;
      }
      var leftHalf = el("div", { className: "diff-side-half diff-" + leftOp + wrapClass }, [leftLn, leftContent]);

      // Right half
      var rightOp = (r.right && r.right.op !== "equal") ? "insert" : (r.right ? "equal" : "empty");
      var rightLn = el("span", { className: "diff-ln", textContent: r.right ? String(rightNum2) : "" });
      var rightContent = el("span", { className: "diff-content" });
      if (wordPairsMap[ri3] && r.right) {
        wordPairsMap[ri3].newSpans.forEach(function (sp) {
          var s = document.createElement("span");
          s.textContent = sp.text;
          if (sp.changed) s.className = "char-ins";
          rightContent.appendChild(s);
        });
      } else if (r.right && r.right.rightText !== null) {
        rightContent.textContent = r.right.rightText;
      } else if (r.right && r.right.op === "equal" && r.right.leftText !== null) {
        rightContent.textContent = r.right.leftText;
      }
      var rightHalf = el("div", { className: "diff-side-half diff-" + rightOp + wrapClass }, [rightLn, rightContent]);

      table.appendChild(el("div", { className: "diff-side-row" }, [leftHalf, rightHalf]));
    });

    var leftLabel_el = el("div", { className: "diff-side-col-label" }, [
      el("span", { className: "badge " + leftBadgeClass, textContent: leftLabel }),
    ]);
    var rightLabel_el = el("div", { className: "diff-side-col-label" }, [
      el("span", { className: "badge " + rightBadgeClass, textContent: rightLabel }),
      !identical ? el("span", { className: "badge badge-warning text-xs", textContent: changeCount + " changes" }) : null,
    ].filter(Boolean));
    var labelRow = el("div", { className: "diff-side-labels" }, [leftLabel_el, rightLabel_el]);

    // Side-by-side: skip the duplicate summary header, column labels are sufficient
    return el("div", { className: "diff-block" }, [labelRow, table]);
  }

  /**
   * Dispatch to inline or side-by-side diff builder based on current layout setting.
   */
  function buildLineDiff(leftStr, rightStr, leftLabel, rightLabel, leftBadgeClass, rightBadgeClass) {
    if (diffLayout === "side-by-side") {
      return buildSideBySideDiff(leftStr, rightStr, leftLabel, rightLabel, leftBadgeClass, rightBadgeClass);
    }
    return buildInlineDiff(leftStr, rightStr, leftLabel, rightLabel, leftBadgeClass, rightBadgeClass);
  }

  /** Build a diff card for a request/response pair. */
  function buildDiffCard(pair) {
    var req = pair.request;
    var resp = pair.response;
    var pairId = (req && req.request_id) || (resp && resp.request_id) || "";

    var ts = (req && req.ts) || (resp && resp.ts) || "";
    var method = (req && req.method) || "--";
    var displayUrl = req ? getDisplayUrl(req) : "--";
    var provider = (req && req.provider) || "--";
    var entities = (req && req.pii_entities_found) || 0;
    var proxyType = (req && req.proxy_type) || "";
    var status = (resp && resp.status) || "--";

    // Header
    var headerItems = [
      el("span", { className: "badge badge-info", textContent: method }),
      el("span", { className: "mono text-sm", textContent: displayUrl }),
      el("span", { className: "badge badge-neutral", textContent: provider }),
      proxyType ? el("span", { className: "badge badge-outline text-xs", textContent: proxyType === "forward" ? "FWD" : "REV" }) : null,
      el("span", { className: "text-xs text-muted", textContent: formatDate(ts) }),
    ];
    if (entities > 0) {
      headerItems.push(el("span", { className: "badge badge-warning", textContent: entities + " PII entities scrubbed" }));
    }
    headerItems.push(el("span", {
      className: "badge " + (status >= 200 && status < 300 ? "badge-success" : status === "--" ? "badge-neutral" : "badge-danger"),
      textContent: String(status),
    }));

    var header = el("div", { className: "rec-pair-header" }, [
      el("div", { className: "flex items-center gap-2 flex-wrap" }, headerItems),
    ]);

    var isExpanded = !!(pairId && expandedPairIds[pairId]);
    var bodyContent = el("div", { className: "rec-pair-body" + (isExpanded ? "" : " hidden") });
    if (isExpanded) header.classList.add("expanded");

    // Helper: build a collapsible diff panel
    function buildCollapsibleDiffPanel(label, badgeClass, contentFn, startOpen) {
      var panel = el("div", { className: "diff-panel" });
      var panelBody = el("div", { className: startOpen ? "" : "hidden" });
      var chevron = el("span", { className: "diff-panel-chevron", textContent: startOpen ? "\u25BC" : "\u25B6" });
      var headerEl = el("div", { className: "diff-panel-header diff-panel-toggle" + (startOpen ? " expanded" : "") }, [
        chevron,
        el("span", { className: "badge " + badgeClass, textContent: label }),
      ]);
      headerEl.addEventListener("click", function (e) {
        e.stopPropagation();
        var nowHidden = panelBody.classList.toggle("hidden");
        headerEl.classList.toggle("expanded", !nowHidden);
        chevron.textContent = nowHidden ? "\u25B6" : "\u25BC";
      });
      panel.appendChild(headerEl);
      contentFn(panelBody, headerEl);
      panel.appendChild(panelBody);
      return panel;
    }

    // Request diff: Original (before scrub) → Scrubbed (after scrub, sent to LLM)
    if (req && req.body_scrubbed) {
      var reqOrigStr = prettyJson(req.body_original || null);
      var reqScrubStr = prettyJson(req.body_scrubbed);
      var hasReqOrig = req.body_original && typeof req.body_original === "object";

      bodyContent.appendChild(buildCollapsibleDiffPanel("REQUEST", "badge-info", function (panelBody, headerEl) {
        if (hasReqOrig) {
          var reqIdentical = reqOrigStr === reqScrubStr;
          if (reqIdentical) {
            headerEl.appendChild(el("span", { className: "text-xs text-muted", textContent: "(no changes)" }));
            panelBody.appendChild(el("pre", { className: "rec-json-block", textContent: reqScrubStr }));
          } else {
            panelBody.appendChild(buildLineDiff(reqOrigStr, reqScrubStr, "Original (before scrub)", "Scrubbed (sent to LLM)", "badge-neutral", "badge-info"));
          }
        } else {
          headerEl.appendChild(el("span", { className: "text-xs text-muted", textContent: "(original not recorded)" }));
          panelBody.appendChild(el("pre", { className: "rec-json-block", textContent: reqScrubStr }));
        }
      }, true));
    }

    // Response diff: Scrubbed (from LLM, with tokens) → Unscrubbed (tokens replaced, sent to client)
    if (resp && resp.body_scrubbed && typeof resp.body_scrubbed === "object") {
      var respScrubStr = prettyJson(resp.body_scrubbed);
      var respOrigStr = prettyJson(resp.body_original || null);
      var hasRespOrig = resp.body_original && typeof resp.body_original === "object";

      bodyContent.appendChild(buildCollapsibleDiffPanel("RESPONSE", "badge-success", function (panelBody, headerEl) {
        if (hasRespOrig) {
          var respIdentical = respScrubStr === respOrigStr;
          if (respIdentical) {
            headerEl.appendChild(el("span", { className: "text-xs text-muted", textContent: "(no changes)" }));
            panelBody.appendChild(el("pre", { className: "rec-json-block", textContent: respScrubStr }));
          } else {
            panelBody.appendChild(buildLineDiff(respScrubStr, respOrigStr, "Scrubbed (from LLM)", "Unscrubbed (sent to client)", "badge-success", "badge-neutral"));
          }
        } else {
          headerEl.appendChild(el("span", { className: "text-xs text-muted", textContent: "(original not recorded)" }));
          panelBody.appendChild(el("pre", { className: "rec-json-block", textContent: respScrubStr }));
        }
      }, false));
    }

    header.addEventListener("click", function () {
      var nowHidden = bodyContent.classList.toggle("hidden");
      header.classList.toggle("expanded");
      if (pairId) {
        if (nowHidden) delete expandedPairIds[pairId];
        else expandedPairIds[pairId] = true;
      }
    });

    return el("div", { className: "rec-pair-card card" }, [header, bodyContent]);
  }

  function renderDiffView(data) {
    var pairs = data.pairs || [];
    if (pairs.length === 0) {
      timeline.innerHTML = '<div class="empty-state text-sm">No recordings with scrub data found</div>';
      return;
    }

    timeline.innerHTML = "";

    // Show hint
    timeline.appendChild(el("div", { className: "text-xs text-muted mb-2", textContent:
      "Request: Original \u2192 Scrubbed (PII replaced)  |  Response: Scrubbed \u2192 Unscrubbed (tokens restored)"
    }));

    sortPairs(pairs).forEach(function (pair) {
      timeline.appendChild(buildDiffCard(pair));
    });
  }

  // ====================================================================
  //  View toggle + data loading
  // ====================================================================

  function setViewMode(mode) {
    viewMode = mode;
    btnViewRaw.classList.toggle("active", mode === "raw");
    btnViewChat.classList.toggle("active", mode === "chat");
    btnViewDiff.classList.toggle("active", mode === "raw" && showDiffInRaw);
    if (diffToolbar) diffToolbar.classList.toggle("hidden", !(mode === "raw" && showDiffInRaw));
    savePrefs();
    if (cachedData) render(cachedData);
  }

  function render(data) {
    var allPairs = data.pairs || [];
    populateProviderFilter(allPairs);
    var filtered = filterPairs(allPairs);
    updateFilterCount(filtered.length, allPairs.length);
    var filteredData = { pairs: filtered, unpaired: data.unpaired || [], recordings: data.recordings || [] };
    if (viewMode === "chat") {
      renderChatView(filteredData);
    } else {
      renderRawView(filteredData);
    }

    // Deep-link: scroll to highlighted recording
    if (_highlightRequestId) {
      requestAnimationFrame(function () {
        var card = timeline.querySelector('[data-request-id="' + CSS.escape(_highlightRequestId) + '"]');
        if (card) {
          // Auto-expand
          var hdr = card.querySelector(".rec-pair-header");
          var body = card.querySelector(".rec-pair-body");
          if (hdr && body && body.classList.contains("hidden")) {
            body.classList.remove("hidden");
            hdr.classList.add("expanded");
            expandedPairIds[_highlightRequestId] = true;
          }
          // Visual highlight
          card.style.outline = "2px solid var(--warning, #e5a100)";
          card.style.outlineOffset = "2px";
          card.scrollIntoView({ behavior: "smooth", block: "center" });
          // Remove highlight after 3s
          setTimeout(function () {
            card.style.outline = "";
            card.style.outlineOffset = "";
          }, 3000);
        }
        // Only highlight once
        _highlightRequestId = "";
        // Clean URL
        if (window.history.replaceState) {
          window.history.replaceState({}, "", window.location.pathname);
        }
      });
    }
  }

  async function loadRecordings() {
    var sid = sessionSelect.value;
    if (!sid) {
      cachedData = null;
      await loadRecentRecordings();
      return;
    }

    try {
      cachedData = await apiFetch("/ui/api/sessions/" + encodeURIComponent(sid) + "/recordings");
      collectKnownRequestIds(cachedData);
      render(cachedData);
    } catch (_) {
      timeline.innerHTML = '<div class="empty-state text-sm">Failed to load recordings</div>';
    }
  }

  async function loadRecentRecordings() {
    try {
      var data = await apiFetch("/ui/api/recordings/recent?limit=50");
      var pairs = data.pairs || [];
      var unpaired = data.unpaired || [];

      if (pairs.length === 0 && unpaired.length === 0) {
        timeline.innerHTML = '<div class="empty-state text-sm">No recordings yet. Proxy traffic will appear here.</div>';
        return;
      }

      // Store and render through the same path as session-specific recordings
      cachedData = data;
      collectKnownRequestIds(cachedData);
      render(cachedData);
    } catch (_) {
      timeline.innerHTML = '<div class="empty-state text-sm">Select a session to view recordings</div>';
    }
  }

  // ---- Live update via SSE --------------------------------------------

  var newBanner = document.getElementById("rec-new-banner");
  var pendingCount = 0;

  // Track known request_ids and whether they have a response
  var knownRequestIds = {};   // rid → true
  var knownHasResponse = {};  // rid → true if response exists

  function collectKnownRequestIds(data) {
    knownRequestIds = {};
    knownHasResponse = {};
    var pairs = data.pairs || [];
    for (var i = 0; i < pairs.length; i++) {
      var rid = (pairs[i].request && pairs[i].request.request_id) || (pairs[i].response && pairs[i].response.request_id) || "";
      if (rid) {
        knownRequestIds[rid] = true;
        if (pairs[i].response) knownHasResponse[rid] = true;
      }
    }
  }

  function showBanner() {
    if (!newBanner || pendingCount === 0) return;
    newBanner.textContent = pendingCount + " new message" + (pendingCount > 1 ? "s" : "") + " — click to load";
    newBanner.classList.remove("hidden");
  }

  function hideBanner() {
    if (!newBanner) return;
    newBanner.classList.add("hidden");
    pendingCount = 0;
  }

  if (newBanner) {
    newBanner.addEventListener("click", function () {
      hideBanner();
      loadRecordings();
    });
  }

  /** Append new pairs and update pairs that gained a response. */
  function appendNewPairs(newData) {
    var pairs = newData.pairs || [];
    var newPairs = [];
    var updatedPairs = [];
    for (var i = 0; i < pairs.length; i++) {
      var rid = (pairs[i].request && pairs[i].request.request_id) || (pairs[i].response && pairs[i].response.request_id) || "";
      if (!rid) continue;
      if (!knownRequestIds[rid]) {
        newPairs.push(pairs[i]);
        knownRequestIds[rid] = true;
        if (pairs[i].response) knownHasResponse[rid] = true;
      } else if (pairs[i].response && !knownHasResponse[rid]) {
        // Pair existed (request only) but now has a response — update it
        updatedPairs.push(pairs[i]);
        knownHasResponse[rid] = true;
      }
    }

    if (newPairs.length === 0 && updatedPairs.length === 0) return;

    // Update cachedData
    if (!cachedData) cachedData = { pairs: [], unpaired: [] };
    cachedData.pairs = pairs;
    cachedData.unpaired = newData.unpaired || [];

    // For updated pairs (gained response) or non-raw views, do a full re-render
    if (updatedPairs.length > 0 || viewMode !== "raw") {
      render(cachedData);
      return;
    }

    // Remove the empty-state placeholder if present
    var emptyState = timeline.querySelector(".empty-state");
    if (emptyState) emptyState.remove();

    // Build DOM nodes for new pairs and insert them
    var sorted = sortOrder === "desc" ? newPairs.slice().reverse() : newPairs;
    sorted.forEach(function (pair) {
      var card = buildPairCard(pair);
      if (sortOrder === "desc") {
        timeline.insertBefore(card, timeline.firstChild);
      } else {
        timeline.appendChild(card);
      }
    });
  }

  SSE.on("recording_complete", function () {
    if (!autoRefresh) return; // auto-refresh disabled, ignore SSE events

    // Fetch new data and append incrementally
    var sid = sessionSelect.value;
    var url = sid
      ? "/ui/api/sessions/" + encodeURIComponent(sid) + "/recordings"
      : "/ui/api/recordings/recent?limit=50";

    apiFetch(url).then(function (data) {
      appendNewPairs(data);
    }).catch(function () {
      // silently ignore
    });
  });

  // ---- Event bindings -------------------------------------------------

  sessionSelect.addEventListener("change", function () {
    hideBanner();
    savePrefs();
    loadRecordings();
  });
  btnRefresh.addEventListener("click", function () {
    hideBanner();
    loadSessions().then(loadRecordings);
  });
  btnViewRaw.addEventListener("click", function () { setViewMode("raw"); });
  btnViewChat.addEventListener("click", function () { setViewMode("chat"); });
  if (btnLayoutToggle) btnLayoutToggle.addEventListener("click", function () {
    columnLayout = columnLayout === "side" ? "stacked" : "side";
    btnLayoutToggle.innerHTML = columnLayout === "side" ? "&#9638; Side by Side" : "&#9636; Stacked";
    savePrefs();
    if (cachedData) render(cachedData);
  });
  btnViewDiff.addEventListener("click", function () {
    showDiffInRaw = !showDiffInRaw;
    if (chkShowDiff) chkShowDiff.checked = showDiffInRaw;
    if (diffToolbar) diffToolbar.classList.toggle("hidden", !showDiffInRaw);
    btnViewDiff.classList.toggle("active", showDiffInRaw);
    savePrefs();
    if (cachedData) render(cachedData);
  });

  // Auto-refresh toggle
  if (chkAutoRefresh) {
    chkAutoRefresh.addEventListener("change", function () {
      autoRefresh = chkAutoRefresh.checked;
      savePrefs();
    });
  }

  // Beautify JSON toggle
  if (chkBeautifyJson) {
    chkBeautifyJson.addEventListener("change", function () {
      beautifyJson = chkBeautifyJson.checked;
      savePrefs();
      if (cachedData) render(cachedData);
    });
  }

  // Show Diff in raw view toggle
  if (chkShowDiff) chkShowDiff.addEventListener("change", function () {
    showDiffInRaw = chkShowDiff.checked;
    if (diffToolbar) diffToolbar.classList.toggle("hidden", !showDiffInRaw);
    btnViewDiff.classList.toggle("active", showDiffInRaw);
    savePrefs();
    if (cachedData) render(cachedData);
  });

  // Filter bar events
  if (filterProvider) filterProvider.addEventListener("change", function () { savePrefs(); if (cachedData) render(cachedData); });
  if (filterProxy) filterProxy.addEventListener("change", function () { savePrefs(); if (cachedData) render(cachedData); });
  if (filterSearch) filterSearch.addEventListener("input", debounce(function () { savePrefs(); if (cachedData) render(cachedData); }, 300));
  if (btnClearFilters) btnClearFilters.addEventListener("click", function () {
    if (filterProvider) filterProvider.value = "";
    if (filterProxy) filterProxy.value = "";
    if (filterSearch) filterSearch.value = "";
    savePrefs();
    if (cachedData) render(cachedData);
  });

  // Sort order toggle
  var btnSortOrder = document.getElementById("btn-sort-order");
  function updateSortButton() {
    if (!btnSortOrder) return;
    btnSortOrder.innerHTML = sortOrder === "desc"
      ? "&#8595; Newest First"
      : "&#8593; Oldest First";
  }
  if (btnSortOrder) {
    btnSortOrder.addEventListener("click", function () {
      sortOrder = sortOrder === "desc" ? "asc" : "desc";
      updateSortButton();
      savePrefs();
      if (cachedData) render(cachedData);
    });
  }

  // Clear all sessions button
  var btnClearAll = document.getElementById("btn-clear-all-sessions");
  if (btnClearAll) {
    btnClearAll.addEventListener("click", async function () {
      if (!confirm("Clear ALL sessions, recordings, tokens, and stats? This cannot be undone.")) return;
      try {
        var resp = await fetch("/ui/api/sessions", { method: "DELETE" });
        var data = await resp.json();
        if (resp.ok) {
          Toast.show("All sessions cleared (" + (data.sessions_cleared || 0) + " sessions)", "success");
          sessionSelect.innerHTML = '<option value="">-- Select a session --</option>';
          timeline.innerHTML = '<div class="empty-state text-sm">Select a session to view recordings</div>';
          hideBanner();
        } else {
          Toast.show(data.error || "Failed", "error");
        }
      } catch (err) {
        Toast.show("Failed: " + err.message, "error");
      }
    });
  }

  // ---- Restore saved preferences on load --------------------------------
  var _prefs = loadPrefs();
  if (_prefs) {
    // Restore diff options before loading data (so first render uses them)
    if (chkDiffOnly) chkDiffOnly.checked = !!_prefs.diffOnly;
    if (chkWordDiff) chkWordDiff.checked = !!_prefs.wordDiff;
    if (chkIgnoreWS) chkIgnoreWS.checked = !!_prefs.ignoreWS;
    if (chkWordWrap) chkWordWrap.checked = _prefs.wordWrap !== false;
    if (_prefs.diffLayout === "side-by-side") {
      diffLayout = "side-by-side";
      if (btnLayoutSide) btnLayoutSide.classList.add("active");
      if (btnLayoutInline) btnLayoutInline.classList.remove("active");
    }
    if (_prefs.sortOrder === "asc") {
      sortOrder = "asc";
      updateSortButton();
    }
    if (_prefs.autoRefresh === false) {
      autoRefresh = false;
      if (chkAutoRefresh) chkAutoRefresh.checked = false;
    }
    if (_prefs.beautifyJson === false) {
      beautifyJson = false;
      if (chkBeautifyJson) chkBeautifyJson.checked = false;
    }
    if (_prefs.showDiffInRaw) {
      showDiffInRaw = true;
      if (chkShowDiff) chkShowDiff.checked = true;
      if (btnViewDiff) btnViewDiff.classList.add("active");
    }
    if (_prefs.columnLayout) {
      columnLayout = _prefs.columnLayout;
      if (btnLayoutToggle) btnLayoutToggle.innerHTML = columnLayout === "side" ? "&#9638; Side by Side" : "&#9636; Stacked";
    }
    // Restore filter bar state
    if (_prefs.filterProviderVal && filterProvider) filterProvider.value = _prefs.filterProviderVal;
    if (_prefs.filterProxyVal && filterProxy) filterProxy.value = _prefs.filterProxyVal;
    if (_prefs.filterSearchVal && filterSearch) filterSearch.value = _prefs.filterSearchVal;
  }

  loadSessions().then(function () {
    // Deep-link: if URL has ?session=X, select that session
    if (_urlSession) {
      var opt = sessionSelect.querySelector('option[value="' + CSS.escape(_urlSession) + '"]');
      if (opt) sessionSelect.value = _urlSession;
    } else if (_prefs && _prefs.session) {
      var opt = sessionSelect.querySelector('option[value="' + _prefs.session + '"]');
      if (opt) sessionSelect.value = _prefs.session;
    }
    // Restore view mode (triggers render)
    if (_prefs && _prefs.viewMode === "chat") {
      setViewMode("chat");
    }
    // Show diff toolbar if showDiffInRaw was restored
    if (showDiffInRaw && diffToolbar) diffToolbar.classList.remove("hidden");
    return loadRecordings();
  });
})();
