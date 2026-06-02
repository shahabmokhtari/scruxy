/* ===================================================================
   Settings page -- editable forms for application configuration.
   Each card section has Save and Discard buttons.
   =================================================================== */

"use strict";

(function () {
  // Stores the last-loaded config from the server for Discard.
  var originalConfig = {};

  // ---- Form control rendering helpers --------------------------------

  function renderTextInput(container, key, value, label) {
    var group = el("div", { className: "form-group" }, [
      el("label", { textContent: label, for: "setting-" + key }),
      el("input", {
        type: "text",
        id: "setting-" + key,
        "data-key": key,
        value: value != null ? String(value) : "",
        className: "w-full",
      }),
    ]);
    container.appendChild(group);
  }

  function renderNumberInput(container, key, value, label) {
    var group = el("div", { className: "form-group" }, [
      el("label", { textContent: label, for: "setting-" + key }),
      el("input", {
        type: "number",
        id: "setting-" + key,
        "data-key": key,
        value: value != null ? String(value) : "0",
        className: "w-full",
      }),
    ]);
    container.appendChild(group);
  }

  function renderSelect(container, key, value, label, options) {
    var selectNode = el("select", {
      id: "setting-" + key,
      "data-key": key,
      className: "w-full",
    });
    options.forEach(function (opt) {
      var optValue = typeof opt === "string" ? opt : opt.value;
      var optLabel = typeof opt === "string" ? opt : opt.label || opt.value;
      var optEl = el("option", { value: optValue, textContent: optLabel });
      if (optValue === value) {
        optEl.selected = true;
      }
      if (typeof opt === "object" && opt.disabled) {
        optEl.disabled = true;
      }
      selectNode.appendChild(optEl);
    });

    var group = el("div", { className: "form-group" }, [
      el("label", { textContent: label, for: "setting-" + key }),
      selectNode,
    ]);
    container.appendChild(group);
  }

  function renderToggle(container, key, value, label) {
    var checkbox = el("input", {
      type: "checkbox",
      id: "setting-" + key,
      "data-key": key,
    });
    checkbox.checked = !!value;

    var toggleLabel = el("label", { className: "toggle" }, [
      checkbox,
      el("span", { className: "toggle-slider" }),
    ]);

    var group = el("div", { className: "form-group flex items-center gap-3" }, [
      toggleLabel,
      el("label", {
        textContent: label,
        for: "setting-" + key,
        style: "display:inline; cursor:pointer;",
      }),
    ]);
    container.appendChild(group);
  }

  function renderFormActions(container, sectionKey) {
    var actions = el("div", { className: "form-actions" }, [
      el("button", {
        className: "btn btn-primary btn-sm",
        textContent: "Save",
        onClick: function () {
          saveSection(sectionKey);
        },
      }),
      el("button", {
        className: "btn btn-outline btn-sm",
        textContent: "Discard",
        onClick: function () {
          discardSection(sectionKey);
        },
      }),
    ]);
    container.appendChild(actions);
  }

  // ---- Section rendering ---------------------------------------------

  function renderInterception(data) {
    var container = document.getElementById("settings-interception");
    if (!container) return;
    container.innerHTML = "";

    var modeOptions = ["primary"];
    if (data.mode && modeOptions.indexOf(data.mode) === -1) {
      modeOptions.unshift({
        value: data.mode,
        label: data.mode + " (unsupported legacy value)",
      });
    }
    renderSelect(container, "interception-mode", data.mode || "primary", "Mode", modeOptions);
    if (data.mode && data.mode !== "primary") {
      container.appendChild(
        el("p", {
          className: "text-muted",
          textContent:
            "This legacy interception mode is no longer supported. Choose 'primary' before saving interception settings.",
        })
      );
    }
    renderTextInput(container, "interception-listen_host", data.listen_host || "localhost", "Listen Host");
    renderNumberInput(container, "interception-listen_port", data.listen_port || 8080, "Listen Port");
    renderFormActions(container, "interception");
  }

  function renderPassthrough(data) {
    var container = document.getElementById("settings-passthrough");
    if (!container) return;
    container.innerHTML = "";

    renderToggle(container, "passthrough-enabled", !!data.enabled, "Enable Logging");
    renderNumberInput(container, "passthrough-max_entries", data.max_entries || 500, "Max Log Entries");
    renderFormActions(container, "passthrough");
  }

  function renderTokens(data) {
    var container = document.getElementById("settings-tokens");
    if (!container) return;
    container.innerHTML = "";

    renderTextInput(container, "tokens-prefix", data.prefix || "REDACTED", "Prefix");
    renderTextInput(container, "tokens-format", data.format || "{prefix}_{category}_{n}", "Format");
    renderNumberInput(container, "tokens-max_token_length", data.max_token_length || 40, "Max Token Length");
    renderNumberInput(container, "tokens-expiration_hours", data.expiration_hours != null ? data.expiration_hours : 168, "Mapping Expiration (hours, 0=never)");
    renderToggle(container, "tokens-persistent", data.persistent !== false, "Persistent Token Store (SQLite)");
    renderFormActions(container, "tokens");
  }

  function renderSessions(data) {
    var container = document.getElementById("settings-sessions");
    if (!container) return;
    container.innerHTML = "";

    renderTextInput(container, "sessions-storage_dir", data.storage_dir || "~/.scruxy/sessions", "Storage Directory");
    renderNumberInput(container, "sessions-max_session_age_hours", data.max_session_age_hours || 168, "Max Session Age (hours)");
    renderNumberInput(container, "sessions-flush_interval_seconds", data.flush_interval_seconds || 5, "Flush Interval (seconds)");
    renderFormActions(container, "sessions");
  }

  function renderLogging(data) {
    var container = document.getElementById("settings-logging");
    if (!container) return;
    container.innerHTML = "";

    renderSelect(container, "logging-level", data.level || "info", "Level", [
      "debug",
      "info",
      "warning",
      "error",
    ]);
    renderTextInput(container, "logging-log_dir", data.log_dir || "~/.scruxy/logs", "Log Directory");
    renderToggle(container, "logging-log_scrub_events", data.log_scrub_events !== false, "Log Scrub Events");
    renderNumberInput(container, "logging-retention_days", data.retention_days || 7, "Retention (days)");
    renderFormActions(container, "logging");
  }

  function renderUI(data) {
    var container = document.getElementById("settings-ui");
    if (!container) return;
    container.innerHTML = "";

    renderToggle(container, "ui-enabled", data.enabled !== false, "Enabled");
    renderToggle(container, "ui-open_browser_on_start", data.open_browser_on_start !== false, "Open Browser on Start");
    renderFormActions(container, "ui");
  }

  function renderRecording(data) {
    var container = document.getElementById("settings-recording");
    if (!container) return;
    container.innerHTML = "";

    renderToggle(container, "recording-enabled", data.enabled !== false, "Enabled");
    renderToggle(
      container,
      "recording-store_body_original",
      !!data.store_body_original,
      "Store Original Bodies (contains raw PII)"
    );
    renderFormActions(container, "recording");
  }

  function renderStats(data) {
    var container = document.getElementById("settings-stats");
    if (!container) return;
    container.innerHTML = "";

    renderToggle(container, "stats-enabled", data.enabled !== false, "Enabled");
    renderTextInput(container, "stats-storage_file", data.storage_file || "~/.scruxy/stats.json", "Storage File");
    renderFormActions(container, "stats");
  }

  function renderForwardProxy(data) {
    var container = document.getElementById("settings-forward-proxy");
    if (!container) return;
    container.innerHTML = "";

    renderToggle(container, "forward_proxy-enabled", data.enabled !== false, "Enabled");
    renderNumberInput(container, "forward_proxy-listen_port", data.listen_port || 8081, "Listen Port");
    renderTextInput(container, "forward_proxy-ca_cert_dir", data.ca_cert_dir || "~/.scruxy/certs", "CA Cert Directory");
    renderToggle(container, "forward_proxy-auto_install_ca_cert", data.auto_install_ca_cert !== false, "Auto-install CA Cert");
    renderFormActions(container, "forward_proxy");
  }

  function renderHttps(data) {
    var container = document.getElementById("settings-https");
    if (!container) return;
    container.innerHTML = "";

    renderToggle(container, "https-enabled", !!data.enabled, "Enabled");
    renderNumberInput(container, "https-listen_port", data.listen_port || 8443, "Listen Port");
    renderTextInput(container, "https-ca_cert_dir", data.ca_cert_dir || "~/.scruxy/certs", "CA Cert Directory");
    renderFormActions(container, "https");
  }

  // ---- Collect form data from a section ------------------------------

  // Map of section key -> list of { key, type } descriptors.
  var sectionFields = {
    interception: [
      { key: "mode", type: "select" },
      { key: "listen_host", type: "text" },
      { key: "listen_port", type: "number" },
    ],
    forward_proxy: [
      { key: "enabled", type: "toggle" },
      { key: "listen_port", type: "number" },
      { key: "ca_cert_dir", type: "text" },
      { key: "auto_install_ca_cert", type: "toggle" },
    ],
    https: [
      { key: "enabled", type: "toggle" },
      { key: "listen_port", type: "number" },
      { key: "ca_cert_dir", type: "text" },
    ],
    passthrough: [
      { key: "enabled", type: "toggle" },
      { key: "max_entries", type: "number" },
    ],
    tokens: [
      { key: "prefix", type: "text" },
      { key: "format", type: "text" },
      { key: "max_token_length", type: "number" },
      { key: "expiration_hours", type: "number" },
      { key: "persistent", type: "toggle" },
    ],
    sessions: [
      { key: "storage_dir", type: "text" },
      { key: "max_session_age_hours", type: "number" },
      { key: "flush_interval_seconds", type: "number" },
    ],
    recording: [
      { key: "enabled", type: "toggle" },
      { key: "store_body_original", type: "toggle" },
    ],
    logging: [
      { key: "level", type: "select" },
      { key: "log_dir", type: "text" },
      { key: "log_scrub_events", type: "toggle" },
      { key: "retention_days", type: "number" },
    ],
    stats: [
      { key: "enabled", type: "toggle" },
      { key: "storage_file", type: "text" },
    ],
    ui: [
      { key: "enabled", type: "toggle" },
      { key: "open_browser_on_start", type: "toggle" },
    ],
  };

  function collectSectionData(sectionKey) {
    var fields = sectionFields[sectionKey];
    if (!fields) return {};
    var result = {};
    fields.forEach(function (field) {
      var inputId = "setting-" + sectionKey + "-" + field.key;
      var inputEl = document.getElementById(inputId);
      if (!inputEl) return;

      if (field.type === "number") {
        result[field.key] = parseInt(inputEl.value, 10) || 0;
      } else if (field.type === "toggle") {
        result[field.key] = inputEl.checked;
      } else {
        result[field.key] = inputEl.value;
      }
    });
    return result;
  }

  // ---- Save and Discard ----------------------------------------------

  // Map nested section keys to their correct config path
  var sectionToConfigPath = {
    forward_proxy: { parent: "interception", child: "forward_proxy" },
    https: { parent: "interception", child: "https" },
    passthrough: { parent: "interception", child: "passthrough" },
  };

  async function saveSection(sectionKey) {
    var data = collectSectionData(sectionKey);
    var body = {};

    var pathInfo = sectionToConfigPath[sectionKey];
    if (pathInfo) {
      // Nested config like interception.forward_proxy
      body[pathInfo.parent] = {};
      body[pathInfo.parent][pathInfo.child] = data;
    } else {
      body[sectionKey] = data;
    }

    try {
      var result = await apiFetch("/ui/api/config", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      // Update originalConfig with the response.
      originalConfig = result;
      Toast.show("Settings saved.", "success");
    } catch (_) {
      /* apiFetch shows a toast on error */
    }
  }

  function discardSection(sectionKey) {
    var pathInfo = sectionToConfigPath[sectionKey];
    var data;
    if (pathInfo) {
      var parent = originalConfig[pathInfo.parent] || {};
      data = parent[pathInfo.child] || {};
    } else {
      data = originalConfig[sectionKey] || {};
    }

    var renderMap = {
      interception: renderInterception,
      forward_proxy: renderForwardProxy,
      https: renderHttps,
      passthrough: renderPassthrough,
      tokens: renderTokens,
      sessions: renderSessions,
      recording: renderRecording,
      logging: renderLogging,
      stats: renderStats,
      ui: renderUI,
    };

    var fn = renderMap[sectionKey];
    if (fn) fn(data);
    Toast.show("Changes discarded.", "info");
  }

  // ---- Load config and render ----------------------------------------

  async function load() {
    try {
      var data = await apiFetch("/ui/api/config");
      originalConfig = data;

      var ic = data.interception || {};
      renderInterception(ic);
      renderForwardProxy(ic.forward_proxy || {});
      renderHttps(ic.https || {});
      renderPassthrough(ic.passthrough || {});
      renderTokens(data.tokens || {});
      renderSessions(data.sessions || {});
      renderRecording(data.recording || {});
      renderLogging(data.logging || {});
      renderStats(data.stats || {});
      renderUI(data.ui || {});
    } catch (_) {
      /* toast shown by apiFetch */
    }
  }

  load();
})();
