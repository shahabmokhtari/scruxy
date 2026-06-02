/* ===================================================================
   Providers page -- manage LLM providers: toggle, edit upstream URL,
   URL patterns, match headers, and text paths. Add/delete custom
   providers.
   =================================================================== */

"use strict";

(function () {
  var container = document.getElementById("providers-list");

  function providerClass(name) {
    var n = (name || "").toLowerCase();
    if (n.includes("anthropic")) return "anthropic";
    if (n.includes("openai")) return "openai";
    return "default";
  }

  function updateProvider(name, payload) {
    return fetch("/ui/api/providers/" + encodeURIComponent(name), {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }).then(function (resp) {
      if (!resp.ok) {
        return resp.json().then(function (data) {
          throw new Error(data.error || "HTTP " + resp.status);
        });
      }
      return resp.json();
    });
  }

  function createProvider(payload) {
    return fetch("/ui/api/providers", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }).then(function (resp) {
      if (!resp.ok) {
        return resp.json().then(function (data) {
          throw new Error(data.error || "HTTP " + resp.status);
        });
      }
      return resp.json();
    });
  }

  function deleteProvider(name) {
    return fetch("/ui/api/providers/" + encodeURIComponent(name), {
      method: "DELETE",
    }).then(function (resp) {
      if (!resp.ok) {
        return resp.json().then(function (data) {
          throw new Error(data.error || "HTTP " + resp.status);
        });
      }
      return resp.json();
    });
  }

  /** Convert a list of paths (or null) to newline-separated text for display. */
  function pathsToText(paths, defaults) {
    if (paths !== null && paths !== undefined) return paths.join("\n");
    return (defaults || []).join("\n");
  }

  /** Convert list to newline-separated text. */
  function listToText(arr) {
    return (arr || []).join("\n");
  }

  /** Parse newline-separated textarea value into a list of non-empty strings. */
  function textToList(text) {
    return text
      .split("\n")
      .map(function (l) { return l.trim(); })
      .filter(function (l) { return l.length > 0; });
  }

  // -------------------------------------------------------------------
  // Collapsible section builder
  // -------------------------------------------------------------------
  function buildCollapsible(title, indicator, bodyChildren) {
    var body = el("div", { className: "config-collapse-body hidden" });
    bodyChildren.forEach(function (c) { body.appendChild(c); });

    var header = el("div", { className: "config-collapse-header" });
    header.textContent = title;
    if (indicator) header.appendChild(indicator);
    header.addEventListener("click", function () {
      body.classList.toggle("hidden");
    });

    return el("div", { className: "plugin-config-collapsible mt-2" }, [header, body]);
  }

  // -------------------------------------------------------------------
  // Render provider cards
  // -------------------------------------------------------------------
  function renderProviders(providers) {
    container.innerHTML = "";

    // "Add Provider" button at top
    var addBtn = el("button", {
      className: "btn btn-primary mb-3",
      textContent: "+ Add Provider",
    });
    addBtn.addEventListener("click", function () {
      showAddForm();
    });
    container.appendChild(addBtn);

    if (!providers || providers.length === 0) {
      container.appendChild(
        el("div", { className: "empty-state" }, [
          el("div", { className: "empty-state-icon", textContent: "\u2601" }),
          el("p", { textContent: "No providers registered." }),
        ])
      );
      return;
    }

    providers.forEach(function (prov) {
      container.appendChild(buildProviderCard(prov));
    });
  }

  function buildProviderCard(prov) {
    var hasCustomPaths =
      prov.request_text_paths !== null || prov.response_text_paths !== null;

    // ---- Toggle switch ----
    var checkbox = el("input", { type: "checkbox" });
    checkbox.checked = !!prov.enabled;
    var slider = el("span", { className: "toggle-slider" });
    var toggle = el("label", { className: "toggle" }, [checkbox, slider]);

    checkbox.addEventListener("change", function () {
      var newEnabled = checkbox.checked;
      updateProvider(prov.name, { enabled: newEnabled })
        .then(function () {
          Toast.show(prov.name + " " + (newEnabled ? "enabled" : "disabled"), "success");
        })
        .catch(function (err) {
          Toast.show("Failed: " + err.message, "error");
          checkbox.checked = !newEnabled;
        });
    });

    // ---- Delete button (custom only) ----
    var deleteBtn = null;
    if (!prov.builtin) {
      deleteBtn = el("button", {
        className: "btn btn-sm",
        textContent: "\u2716 Delete",
        title: "Delete this provider",
      });
      deleteBtn.style.color = "#f85149";
      deleteBtn.style.borderColor = "#f85149";
      deleteBtn.addEventListener("click", function () {
        if (!confirm("Delete provider '" + prov.name + "'? This cannot be undone.")) return;
        deleteProvider(prov.name)
          .then(function () {
            Toast.show("Deleted " + prov.name, "success");
            load();
          })
          .catch(function (err) {
            Toast.show("Failed: " + err.message, "error");
          });
      });
    }

    // ---- Upstream URL input ----
    var urlInput = el("input", {
      type: "text",
      className: "input",
      value: prov.upstream_url || "",
      placeholder: "https://api.example.com",
    });
    urlInput.style.flex = "1";
    urlInput.style.minWidth = "0";

    var saveUrlBtn = el("button", {
      className: "btn btn-sm btn-primary",
      textContent: "Save",
    });
    saveUrlBtn.addEventListener("click", function () {
      updateProvider(prov.name, { upstream_url: urlInput.value.trim() })
        .then(function () { Toast.show(prov.name + " URL updated", "success"); })
        .catch(function (err) { Toast.show("Failed: " + err.message, "error"); });
    });

    var urlRow = el("div", { className: "flex items-center gap-2 mt-2" }, [
      el("span", { className: "text-xs text-muted", textContent: "Upstream URL:" }),
      urlInput,
      saveUrlBtn,
    ]);

    // ==== Section 1: URL Patterns & Headers ====
    var patternsTextarea = el("textarea", { className: "config-textarea" });
    patternsTextarea.value = listToText(prov.url_patterns);
    patternsTextarea.rows = 3;
    patternsTextarea.placeholder = "*/v1/chat/completions\n*/v1/messages";

    // match_headers removed from UI — matching is done by URL patterns only

    var authHdrTextarea = el("textarea", { className: "config-textarea" });
    authHdrTextarea.value = listToText(prov.auth_headers);
    authHdrTextarea.rows = 2;
    authHdrTextarea.placeholder = "authorization\nx-api-key";

    var sessHdrTextarea = el("textarea", { className: "config-textarea" });
    sessHdrTextarea.value = listToText(prov.session_id_headers);
    sessHdrTextarea.rows = 2;
    sessHdrTextarea.placeholder = "x-session-id\nx-request-id";

    // Session ID body extraction fields
    var sessBodyPathInput = el("input", { type: "text", className: "config-textarea", style: "height:auto;padding:6px 8px;" });
    sessBodyPathInput.value = prov.session_id_body_path || "";
    sessBodyPathInput.placeholder = "e.g. metadata.user_id";

    var sessBodyRegexInput = el("input", { type: "text", className: "config-textarea", style: "height:auto;padding:6px 8px;" });
    sessBodyRegexInput.value = prov.session_id_body_regex || "";
    sessBodyRegexInput.placeholder = "e.g. session_([0-9a-f-]+)";

    var sessBodyPrefixInput = el("input", { type: "text", className: "config-textarea", style: "height:auto;padding:6px 8px;" });
    sessBodyPrefixInput.value = prov.session_id_body_prefix || "";
    sessBodyPrefixInput.placeholder = "e.g. claude-";

    var savePatternsBtn = el("button", {
      className: "btn btn-sm btn-primary",
      textContent: "Save Patterns & Headers",
    });
    savePatternsBtn.addEventListener("click", function () {
      var patterns = textToList(patternsTextarea.value);
      if (patterns.length === 0) {
        Toast.show("At least one URL pattern is required", "error");
        return;
      }
      updateProvider(prov.name, {
        url_patterns: patterns,
        auth_headers: textToList(authHdrTextarea.value),
        session_id_headers: textToList(sessHdrTextarea.value),
        session_id_body_path: sessBodyPathInput.value.trim(),
        session_id_body_regex: sessBodyRegexInput.value.trim(),
        session_id_body_prefix: sessBodyPrefixInput.value.trim(),
      })
        .then(function () { Toast.show(prov.name + " patterns updated", "success"); })
        .catch(function (err) { Toast.show("Failed: " + err.message, "error"); });
    });

    var patternsSection = buildCollapsible(
      "URL Patterns & Headers",
      null,
      [
        el("label", { className: "text-xs text-muted", textContent: "URL patterns (glob, one per line):" }),
        patternsTextarea,
        el("div", { style: "height:8px" }),
        el("label", { className: "text-xs text-muted", textContent: "Auth headers (forwarded, used for session ID hash):" }),
        authHdrTextarea,
        el("div", { style: "height:8px" }),
        el("label", { className: "text-xs text-muted", textContent: "Session ID headers (checked in order):" }),
        sessHdrTextarea,
        el("div", { style: "height:12px" }),
        el("label", { className: "text-xs text-muted", textContent: "Session ID from body — dotted path (e.g. metadata.user_id):" }),
        sessBodyPathInput,
        el("div", { style: "height:4px" }),
        el("label", { className: "text-xs text-muted", textContent: "Session ID body regex — capture group extracts session (e.g. session_([0-9a-f-]+)):" }),
        sessBodyRegexInput,
        el("div", { style: "height:4px" }),
        el("label", { className: "text-xs text-muted", textContent: "Session ID body prefix (prepended to extracted value, e.g. claude-):" }),
        sessBodyPrefixInput,
        el("div", { className: "flex items-center gap-2 mt-2" }, [savePatternsBtn]),
      ]
    );

    // ==== Section 2: Text Paths ====
    var customIndicator = el("span", {
      className: "text-xs",
      textContent: hasCustomPaths ? " (custom)" : "",
    });
    if (hasCustomPaths) customIndicator.style.color = "var(--warning, #e5a100)";

    var reqTextarea = el("textarea", { className: "config-textarea" });
    reqTextarea.value = pathsToText(prov.request_text_paths, prov.default_request_text_paths);
    reqTextarea.rows = 4;
    reqTextarea.placeholder = "$.messages[*].content";

    var respTextarea = el("textarea", { className: "config-textarea" });
    respTextarea.value = pathsToText(prov.response_text_paths, prov.default_response_text_paths);
    respTextarea.rows = 3;
    respTextarea.placeholder = "$.content[*].text";

    var savePathsBtn = el("button", {
      className: "btn btn-sm btn-primary",
      textContent: "Save Paths",
    });
    savePathsBtn.addEventListener("click", function () {
      updateProvider(prov.name, {
        request_text_paths: textToList(reqTextarea.value),
        response_text_paths: textToList(respTextarea.value),
      })
        .then(function () {
          Toast.show(prov.name + " text paths updated", "success");
          customIndicator.textContent = " (custom)";
          customIndicator.style.color = "var(--warning, #e5a100)";
        })
        .catch(function (err) { Toast.show("Failed: " + err.message, "error"); });
    });

    var resetBtn = el("button", {
      className: "btn btn-sm",
      textContent: "Reset to Defaults",
    });
    resetBtn.addEventListener("click", function () {
      updateProvider(prov.name, {
        request_text_paths: null,
        response_text_paths: null,
      })
        .then(function () {
          reqTextarea.value = (prov.default_request_text_paths || []).join("\n");
          respTextarea.value = (prov.default_response_text_paths || []).join("\n");
          customIndicator.textContent = "";
          Toast.show(prov.name + " paths reset to defaults", "success");
        })
        .catch(function (err) { Toast.show("Failed: " + err.message, "error"); });
    });

    var pathsSection = buildCollapsible(
      "Request / Response Text Paths",
      customIndicator,
      [
        el("label", { className: "text-xs text-muted", textContent: "Request text paths (one JSONPath per line):" }),
        reqTextarea,
        el("div", { style: "height:8px" }),
        el("label", { className: "text-xs text-muted", textContent: "Response text paths (one JSONPath per line):" }),
        respTextarea,
        el("div", { className: "flex items-center gap-2 mt-2" }, [savePathsBtn, resetBtn]),
      ]
    );

    // ---- Card assembly ----
    var patterns = (prov.url_patterns || []).join(", ") || "No URL patterns";
    var card = el("div", { className: "card mb-3" });

    var rightControls = [
      el("span", {
        className: "text-xs text-muted",
        textContent: prov.enabled ? "Enabled" : "Disabled",
      }),
      toggle,
    ];
    if (deleteBtn) rightControls.push(deleteBtn);

    var headerRow = el("div", { className: "flex items-center justify-between" }, [
      el("div", { className: "flex items-center gap-3" }, [
        el("div", {
          className: "provider-icon " + providerClass(prov.name),
          textContent: (prov.name || "?")[0].toUpperCase(),
        }),
        el("div", {}, [
          el("div", { className: "provider-name", textContent: prov.name }),
          el("div", { className: "text-xs text-muted", textContent: patterns }),
        ]),
      ]),
      el("div", { className: "flex items-center gap-2" }, rightControls),
    ]);

    card.appendChild(headerRow);
    card.appendChild(urlRow);
    card.appendChild(patternsSection);
    card.appendChild(pathsSection);
    return card;
  }

  // -------------------------------------------------------------------
  // Add Provider form
  // -------------------------------------------------------------------
  function showAddForm() {
    // Remove existing form if present
    var existing = document.getElementById("add-provider-form");
    if (existing) { existing.remove(); return; }

    var form = el("div", { className: "card mb-3", id: "add-provider-form" });
    form.style.borderColor = "var(--accent)";

    var title = el("div", {
      className: "provider-name mb-2",
      textContent: "New Provider",
    });

    var nameInput = el("input", {
      type: "text",
      className: "input",
      placeholder: "Provider name (e.g. my-llm)",
    });
    nameInput.style.width = "100%";

    var urlInput = el("input", {
      type: "text",
      className: "input mt-2",
      placeholder: "Upstream URL (e.g. https://api.example.com)",
    });
    urlInput.style.width = "100%";

    var patternsLabel = el("label", {
      className: "text-xs text-muted mt-2",
      textContent: "URL patterns (glob, one per line — required):",
    });
    patternsLabel.style.display = "block";
    patternsLabel.style.marginTop = "8px";
    var patternsInput = el("textarea", { className: "config-textarea" });
    patternsInput.rows = 3;
    patternsInput.placeholder = "*/v1/chat/completions\n*/v1/messages";

    var reqPathsLabel = el("label", {
      className: "text-xs text-muted",
      textContent: "Request text paths (JSONPath, one per line):",
    });
    reqPathsLabel.style.display = "block";
    reqPathsLabel.style.marginTop = "8px";
    var reqPathsInput = el("textarea", { className: "config-textarea" });
    reqPathsInput.rows = 3;
    reqPathsInput.placeholder = "$.messages[*].content";

    var respPathsLabel = el("label", {
      className: "text-xs text-muted",
      textContent: "Response text paths (JSONPath, one per line):",
    });
    respPathsLabel.style.display = "block";
    respPathsLabel.style.marginTop = "8px";
    var respPathsInput = el("textarea", { className: "config-textarea" });
    respPathsInput.rows = 3;
    respPathsInput.placeholder = "$.choices[*].message.content";

    var createBtn = el("button", {
      className: "btn btn-primary mt-2",
      textContent: "Create Provider",
    });
    var cancelBtn = el("button", {
      className: "btn mt-2",
      textContent: "Cancel",
    });
    cancelBtn.style.marginLeft = "8px";

    cancelBtn.addEventListener("click", function () { form.remove(); });

    createBtn.addEventListener("click", function () {
      var name = nameInput.value.trim();
      var patterns = textToList(patternsInput.value);
      if (!name) { Toast.show("Name is required", "error"); return; }
      if (patterns.length === 0) { Toast.show("At least one URL pattern is required", "error"); return; }

      createBtn.disabled = true;
      createBtn.textContent = "Creating...";

      createProvider({
        name: name,
        upstream_url: urlInput.value.trim(),
        url_patterns: patterns,
        request_text_paths: textToList(reqPathsInput.value),
        response_text_paths: textToList(respPathsInput.value),
      })
        .then(function () {
          Toast.show("Provider '" + name + "' created", "success");
          form.remove();
          load();
        })
        .catch(function (err) {
          Toast.show("Failed: " + err.message, "error");
          createBtn.disabled = false;
          createBtn.textContent = "Create Provider";
        });
    });

    form.appendChild(title);
    form.appendChild(nameInput);
    form.appendChild(urlInput);
    form.appendChild(patternsLabel);
    form.appendChild(patternsInput);
    // match_headers removed from UI
    form.appendChild(reqPathsLabel);
    form.appendChild(reqPathsInput);
    form.appendChild(respPathsLabel);
    form.appendChild(respPathsInput);
    form.appendChild(el("div", { className: "flex items-center mt-2" }, [createBtn, cancelBtn]));

    // Insert after the Add button (first child of container)
    if (container.children.length > 1) {
      container.insertBefore(form, container.children[1]);
    } else {
      container.appendChild(form);
    }
  }

  // -------------------------------------------------------------------
  // Load
  // -------------------------------------------------------------------
  async function load() {
    try {
      var data = await apiFetch("/ui/api/providers");
      renderProviders(data.providers);
    } catch (_) {
      container.innerHTML = '<div class="empty-state text-sm">Failed to load providers</div>';
    }
  }

  load();
})();
