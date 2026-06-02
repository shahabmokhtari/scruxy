/* ===================================================================
   Tester page -- full round-trip scrub/unscrub pipeline tester
   with provider-aware samples, JSON path config, and stage overrides.
   Persists user edits to disk so they survive page reloads.
   Uses the persistent shared TokenMap (session_id="test").
   =================================================================== */

"use strict";

(function () {
  var providerSelect = document.getElementById("tester-provider");
  var stagesContainer = document.getElementById("tester-stages");
  var reqPathsInput = document.getElementById("tester-req-paths");
  var respPathsInput = document.getElementById("tester-resp-paths");
  var requestArea = document.getElementById("tester-request");
  var responseArea = document.getElementById("tester-response");
  var scrubbedPre = document.getElementById("tester-scrubbed");
  var unscrubbedReqPre = document.getElementById("tester-unscrubbed-request");
  var unscrubbedPre = document.getElementById("tester-unscrubbed");
  var rescrubbedPre = document.getElementById("tester-rescrubbed");
  var runBtn = document.getElementById("tester-run-btn");
  var resultsDiv = document.getElementById("tester-results");
  var summarySpan = document.getElementById("tester-summary");
  var entitiesTbody = document.getElementById("tester-entities");
  var tokenMapDiv = document.getElementById("tester-token-map");
  var clearTestBtn = document.getElementById("tester-clear-test");
  var clearAllBtn = document.getElementById("tester-clear-all");
  var mappingCountSpan = document.getElementById("tester-mapping-count");

  var samplesData = null;
  var stageStates = {}; // name -> checkbox element

  /** Stretch a textarea to match its grid-row panel height. */
  function _syncTextareaHeight(textarea) {
    var panel = textarea.closest(".tester-panel");
    if (!panel) return;
    var header = panel.querySelector(".tester-panel-header");
    var available = panel.offsetHeight - (header ? header.offsetHeight : 0);
    if (available > textarea.offsetHeight) {
      textarea.style.height = available + "px";
    }
  }

  // -- State persistence --------------------------------------------------

  var _saveTimer = null;

  function saveState() {
    var state = {
      provider: providerSelect.value,
      request_body: requestArea.value,
      response_body: responseArea.value,
      request_text_paths: reqPathsInput.value,
      response_text_paths: respPathsInput.value,
    };
    fetch("/ui/api/tester/state", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(state),
    }).catch(function () { /* best-effort save */ });
  }

  function debouncedSave() {
    if (_saveTimer) clearTimeout(_saveTimer);
    _saveTimer = setTimeout(saveState, 1000);
  }

  function attachAutoSave() {
    requestArea.addEventListener("input", debouncedSave);
    responseArea.addEventListener("input", debouncedSave);
    reqPathsInput.addEventListener("input", debouncedSave);
    respPathsInput.addEventListener("input", debouncedSave);
  }

  // -- Load samples and pipeline config ------------------------------------

  async function init() {
    try {
      var [samplesResp, pipelineResp] = await Promise.all([
        apiFetch("/ui/api/tester/samples"),
        apiFetch("/ui/api/pipeline/config"),
      ]);

      samplesData = samplesResp;

      // Populate provider dropdown
      providerSelect.innerHTML = "";
      (samplesResp.providers || []).forEach(function (name) {
        var opt = document.createElement("option");
        opt.value = name;
        opt.textContent = samplesResp.samples[name].display_name || name;
        providerSelect.appendChild(opt);
      });

      // Populate stage checkboxes
      stagesContainer.innerHTML = "";
      (pipelineResp.stages || []).forEach(function (stage) {
        var label = el("label", { className: "flex items-center gap-2", style: "cursor:pointer" });
        var cb = document.createElement("input");
        cb.type = "checkbox";
        cb.checked = stage.enabled;
        cb.dataset.stage = stage.name;
        label.appendChild(cb);
        label.appendChild(document.createTextNode(stage.name));
        stagesContainer.appendChild(label);
        stageStates[stage.name] = cb;
      });

      // Try to restore saved state; fall back to first sample
      var savedState = null;
      try {
        savedState = await apiFetch("/ui/api/tester/state");
      } catch (_) { /* no saved state */ }

      if (savedState && savedState.request_body) {
        // Restore saved state
        if (savedState.provider && providerSelect.querySelector('option[value="' + savedState.provider + '"]')) {
          providerSelect.value = savedState.provider;
        }
        requestArea.value = savedState.request_body;
        responseArea.value = savedState.response_body || "";
        reqPathsInput.value = savedState.request_text_paths || "";
        respPathsInput.value = savedState.response_text_paths || "";
      } else if (samplesResp.providers && samplesResp.providers.length > 0) {
        loadSample(samplesResp.providers[0]);
      }

      attachAutoSave();
    } catch (err) {
      Toast.show("Failed to load tester data", "error");
    }
  }

  function loadSample(provider) {
    if (!samplesData || !samplesData.samples[provider]) return;
    var sample = samplesData.samples[provider];

    requestArea.value = JSON.stringify(sample.request_body, null, 2);
    responseArea.value = JSON.stringify(sample.response_body, null, 2);
    reqPathsInput.value = (sample.request_text_paths || []).join(", ");
    respPathsInput.value = (sample.response_text_paths || []).join(", ");

    // Clear results
    scrubbedPre.textContent = "";
    unscrubbedReqPre.textContent = "";
    unscrubbedPre.textContent = "";
    if (rescrubbedPre) rescrubbedPre.textContent = "";
    resultsDiv.classList.add("hidden");

    // Save after loading sample
    saveState();
  }

  providerSelect.addEventListener("change", function () {
    loadSample(providerSelect.value);
  });

  // -- Run test ------------------------------------------------------------

  runBtn.addEventListener("click", async function () {
    var requestBody, responseBody;
    try {
      requestBody = JSON.parse(requestArea.value);
    } catch (e) {
      Toast.show("Invalid request JSON: " + e.message, "error");
      return;
    }
    try {
      responseBody = JSON.parse(responseArea.value);
    } catch (e) {
      Toast.show("Invalid response JSON: " + e.message, "error");
      return;
    }

    var reqPaths = reqPathsInput.value.split(",").map(function (s) { return s.trim(); }).filter(Boolean);
    var respPaths = respPathsInput.value.split(",").map(function (s) { return s.trim(); }).filter(Boolean);

    var stages = {};
    Object.keys(stageStates).forEach(function (name) {
      stages[name] = stageStates[name].checked;
    });

    runBtn.disabled = true;
    runBtn.textContent = "Running...";
    scrubbedPre.textContent = "Running pipeline...";
    unscrubbedReqPre.textContent = "";
    unscrubbedPre.textContent = "";
    if (rescrubbedPre) rescrubbedPre.textContent = "";

    try {
      var resp = await fetch("/ui/api/tester/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          provider: providerSelect.value,
          request_body: requestBody,
          response_body: responseBody,
          request_text_paths: reqPaths,
          response_text_paths: respPaths,
          stages: stages,
        }),
      });
      var data = await resp.json();

      if (!resp.ok) {
        Toast.show(data.error || "Test run failed", "error");
        scrubbedPre.textContent = "Error: " + (data.error || "unknown");
        return;
      }

      // Display scrubbed request
      scrubbedPre.textContent = JSON.stringify(data.scrubbed_request, null, 2);

      // Display unscrubbed request (round-trip)
      var unscrubbedReqStr = JSON.stringify(data.unscrubbed_request, null, 2);
      unscrubbedReqPre.textContent = unscrubbedReqStr;

      // Display unscrubbed response
      unscrubbedPre.textContent = JSON.stringify(data.unscrubbed_response, null, 2);

      // Display re-scrubbed response (round-trip)
      var rescrubbedStr = JSON.stringify(data.rescrubbed_response, null, 2);
      if (rescrubbedPre) rescrubbedPre.textContent = rescrubbedStr;

      // Sync textarea heights to match their row siblings
      requestAnimationFrame(function () {
        _syncTextareaHeight(requestArea);
        _syncTextareaHeight(responseArea);
      });

      // --- Request row validation: original vs unscrubbed request ---
      var originalStr = JSON.stringify(requestBody, null, 2);
      var requestPanel = requestArea.closest(".tester-panel");
      var unscrubbedReqPanel = unscrubbedReqPre.closest(".tester-panel");
      if (originalStr === unscrubbedReqStr) {
        if (requestPanel) requestPanel.style.borderColor = "var(--color-success, #22c55e)";
        if (unscrubbedReqPanel) unscrubbedReqPanel.style.borderColor = "var(--color-success, #22c55e)";
      } else {
        if (requestPanel) requestPanel.style.borderColor = "var(--color-danger, #ef4444)";
        if (unscrubbedReqPanel) unscrubbedReqPanel.style.borderColor = "var(--color-danger, #ef4444)";
      }

      // --- Response row validation: original response vs re-scrubbed response ---
      var originalRespStr = JSON.stringify(responseBody, null, 2);
      var responsePanel = responseArea.closest(".tester-panel");
      var rescrubbedPanel = rescrubbedPre ? rescrubbedPre.closest(".tester-panel") : null;
      if (originalRespStr === rescrubbedStr) {
        // Re-scrubbed matches original scrubbed response: green
        if (responsePanel) responsePanel.style.borderColor = "var(--color-success, #22c55e)";
        if (rescrubbedPanel) rescrubbedPanel.style.borderColor = "var(--color-success, #22c55e)";
      } else if (rescrubbedStr && rescrubbedStr !== "{}") {
        // Mismatch: red
        if (responsePanel) responsePanel.style.borderColor = "var(--color-danger, #ef4444)";
        if (rescrubbedPanel) rescrubbedPanel.style.borderColor = "var(--color-danger, #ef4444)";
      } else {
        // Empty: neutral
        if (responsePanel) responsePanel.style.borderColor = "";
        if (rescrubbedPanel) rescrubbedPanel.style.borderColor = "";
      }

      // Update mapping count
      updateMappingCount(data.mapping_count);

      // Show results
      renderResults(data);
      Toast.show("Test completed: " + data.entities.length + " entities detected", "success");

      // Save state after successful run
      saveState();
    } catch (err) {
      Toast.show("Test run failed: " + err.message, "error");
      scrubbedPre.textContent = "Network error";
    } finally {
      runBtn.disabled = false;
      runBtn.textContent = "\u25B6 Run Test";
    }
  });

  // -- Mapping controls ----------------------------------------------------

  function updateMappingCount(count) {
    if (mappingCountSpan) {
      mappingCountSpan.textContent = count != null ? count + " global mappings" : "";
    }
  }

  if (clearTestBtn) {
    clearTestBtn.addEventListener("click", async function () {
      try {
        var resp = await fetch("/ui/api/sessions/test/mappings", { method: "DELETE" });
        var data = await resp.json();
        if (resp.ok) {
          Toast.show("Cleared " + data.removed + " test-exclusive mappings", "success");
          updateMappingCount(data.remaining);
        } else {
          Toast.show(data.error || "Failed to clear", "error");
        }
      } catch (err) {
        Toast.show("Failed: " + err.message, "error");
      }
    });
  }

  if (clearAllBtn) {
    clearAllBtn.addEventListener("click", async function () {
      if (!confirm("Clear ALL token mappings across all sessions? This cannot be undone.")) return;
      try {
        var resp = await fetch("/ui/api/token-map", { method: "DELETE" });
        var data = await resp.json();
        if (resp.ok) {
          Toast.show("All mappings cleared", "success");
          updateMappingCount(0);
        } else {
          Toast.show(data.error || "Failed to clear", "error");
        }
      } catch (err) {
        Toast.show("Failed: " + err.message, "error");
      }
    });
  }

  // -- Render results ------------------------------------------------------

  function renderResults(data) {
    resultsDiv.classList.remove("hidden");

    // Summary
    var stagesStr = data.stages_run.length > 0 ? data.stages_run.join(", ") : "none";
    summarySpan.textContent = data.entities.length + " entities | " +
      data.latency_ms.toFixed(1) + "ms | Stages: " + stagesStr;

    // Entity table
    entitiesTbody.innerHTML = "";
    if (data.entities.length === 0) {
      var row = document.createElement("tr");
      var td = document.createElement("td");
      td.colSpan = 6;
      td.className = "text-muted";
      td.style.textAlign = "center";
      td.textContent = "No entities detected";
      row.appendChild(td);
      entitiesTbody.appendChild(row);
    } else {
      data.entities.forEach(function (entity) {
        var row = document.createElement("tr");
        row.innerHTML =
          "<td><span class='badge badge-info'>" + escapeHtml(entity.entity_type) + "</span></td>" +
          "<td class='mono'>" + escapeHtml(entity.text) + "</td>" +
          "<td class='mono text-accent'>" + escapeHtml(entity.token) + "</td>" +
          "<td>" + escapeHtml(entity.source) + "</td>" +
          "<td>" + entity.score.toFixed(3) + "</td>" +
          "<td class='text-xs text-muted'>" + escapeHtml(entity.field_path) + "</td>";
        entitiesTbody.appendChild(row);
      });
    }

    // Token map
    tokenMapDiv.innerHTML = "";
    var mapEntries = Object.entries(data.token_map || {});
    if (mapEntries.length === 0) {
      tokenMapDiv.innerHTML = '<div class="text-sm text-muted" style="padding:8px">No tokens generated</div>';
    } else {
      mapEntries.forEach(function (entry) {
        var item = el("div", { className: "config-item" }, [
          el("span", { className: "config-key mono", textContent: entry[0] }),
          el("span", { className: "config-value text-accent", textContent: entry[1] }),
        ]);
        tokenMapDiv.appendChild(item);
      });
    }
  }

  init();
})();
