/* ===================================================================
   Tokens page -- session selector + unmasked token table + management.
   =================================================================== */

"use strict";

(function () {
  var sessionSelect = document.getElementById("session-select");
  var tokenTable    = document.getElementById("token-table");
  var btnRefresh    = document.getElementById("btn-refresh-tokens");
  var btnClearSession = document.getElementById("btn-clear-session-tokens");
  var btnClearAll     = document.getElementById("btn-clear-all-tokens");
  var filterBar       = document.getElementById("token-type-filters");

  // Whitelist instances (fetched on load, used for per-instance buttons)
  var whitelistInstances = [];

  // Pill filter state: set of active entity types (empty = show all)
  var activeFilters = new Set();
  var PREFS_KEY = "scruxy-tokens-prefs";

  function savePrefs() {
    try {
      localStorage.setItem(PREFS_KEY, JSON.stringify({
        filters: Array.from(activeFilters),
      }));
    } catch (_) {}
  }

  function loadPrefs() {
    try {
      var raw = localStorage.getItem(PREFS_KEY);
      if (raw) {
        var p = JSON.parse(raw);
        if (Array.isArray(p.filters)) activeFilters = new Set(p.filters);
      }
    } catch (_) {}
  }

  loadPrefs();

  // Populate session dropdown, preserving current selection
  async function loadSessions() {
    var previousValue = sessionSelect.value;
    try {
      var data = await apiFetch("/ui/api/sessions");
      sessionSelect.innerHTML = '<option value="">All Sessions (Shared Map)</option>';
      (data.sessions || []).forEach(function (s) {
        var opt = document.createElement("option");
        opt.value = s.session_id;
        opt.textContent = (s.title ? s.title.substring(0, 50) + " — " : "") + truncateId(s.session_id, 16) + " (" + (s.provider || "unknown") + ")";
        if (s.title) opt.title = s.title;
        sessionSelect.appendChild(opt);
      });
      // Restore previous selection if it still exists
      if (previousValue && sessionSelect.querySelector('option[value="' + previousValue + '"]')) {
        sessionSelect.value = previousValue;
      }
    } catch (_) {
      /* ignore */
    }
  }

  // Load tokens for selected session (or all tokens if no session)
  async function loadTokens() {
    var sid = sessionSelect.value;

    try {
      var data;
      if (sid) {
        data = await apiFetch("/ui/api/sessions/" + encodeURIComponent(sid) + "/tokens");
      } else {
        data = await apiFetch("/ui/api/sessions/_shared/tokens");
      }
      var tokens = data.tokens || {};
      var entityTypes = data.entity_types || {};
      var tokenMeta = data.token_meta || {};
      var sessionId = data.session_id || "";
      var entries = Object.entries(tokens);

      // Build type → count map for pill filters
      var typeCounts = {};
      entries.forEach(function (pair) {
        var pii = pair[0];
        var token = pair[1];
        var et = entityTypes[pii];
        if (!et) {
          var parts = (typeof token === "string" ? token : "").split("_");
          et = parts.length >= 3 && parts[0] === "REDACTED" ? parts.slice(1, -1).join("_") : "UNKNOWN";
        }
        typeCounts[et] = (typeCounts[et] || 0) + 1;
      });
      buildFilterPills(typeCounts);

      // Apply type filter
      var filteredEntries = entries;
      if (activeFilters.size > 0) {
        filteredEntries = entries.filter(function (pair) {
          var pii = pair[0];
          var token = pair[1];
          var et = entityTypes[pii];
          if (!et) {
            var parts = (typeof token === "string" ? token : "").split("_");
            et = parts.length >= 3 && parts[0] === "REDACTED" ? parts.slice(1, -1).join("_") : "UNKNOWN";
          }
          return activeFilters.has(et);
        });
      }

      if (filteredEntries.length === 0) {
        tokenTable.innerHTML =
          '<tr><td colspan="5" class="empty-state text-sm">' +
          (activeFilters.size > 0 ? "No tokens match the selected filters" : (sid ? "No tokens in this session" : "No tokens in shared map")) +
          '</td></tr>';
        updateClearButtons(sid, entries.length);
        return;
      }

      tokenTable.innerHTML = "";
      filteredEntries.forEach(function (pair) {
        var pii = pair[0];
        var token = pair[1];
        var entityType = entityTypes[pii];
        if (!entityType) {
          var parts = (typeof token === "string" ? token : "").split("_");
          entityType = parts.length >= 3 && parts[0] === "REDACTED" ? parts.slice(1, -1).join("_") : "UNKNOWN";
        }

        var tr = el("tr", {}, [
          el("td", { className: "mono", textContent: token }),
          el("td", {}, [
            el("span", { className: "badge badge-info", textContent: entityType }),
          ]),
          el("td", { className: "mono", textContent: pii }),
        ]);

        // "First Seen" column — link to originating recording
        var requestId = (tokenMeta && tokenMeta[pii]) || "";
        var linkCell = document.createElement("td");
        if (requestId) {
          var link = document.createElement("a");
          link.href = "/ui/recordings?session=" + encodeURIComponent(sessionId) + "&highlight=" + encodeURIComponent(requestId);
          link.textContent = requestId.substring(0, 8) + "\u2026";
          link.title = requestId;
          link.className = "mono text-xs";
          linkCell.appendChild(link);
        }
        tr.appendChild(linkCell);

        // "Actions" column — whitelist button(s) for non-WHITELIST tokens
        var actionsCell = document.createElement("td");
        if (entityType !== "WHITELIST") {
          if (whitelistInstances.length <= 1) {
            // Single whitelist — simple button (backward compatible)
            var wlBtn = el("button", {
              className: "btn btn-xs btn-outline",
              textContent: "Whitelist",
              title: "Add \u201c" + pii + "\u201d to the whitelist so it is never scrubbed",
            });
            wlBtn.addEventListener("click", function () {
              addToWhitelist(pii, wlBtn, whitelistInstances.length === 1 ? whitelistInstances[0].name : "");
            });
            actionsCell.appendChild(wlBtn);
          } else {
            // Multiple whitelists — show a button per instance
            whitelistInstances.forEach(function (inst) {
              var wlBtn = el("button", {
                className: "btn btn-xs btn-outline",
                textContent: inst.display_name,
                title: "Add \u201c" + pii + "\u201d to " + inst.display_name,
              });
              wlBtn.style.marginRight = "4px";
              wlBtn.addEventListener("click", function () {
                addToWhitelist(pii, wlBtn, inst.name);
              });
              actionsCell.appendChild(wlBtn);
            });
          }
        } else {
          actionsCell.appendChild(el("span", { className: "text-xs text-muted", textContent: "whitelisted" }));
        }
        tr.appendChild(actionsCell);
        tokenTable.appendChild(tr);
      });
      updateClearButtons(sid, entries.length);
    } catch (_) {
      tokenTable.innerHTML =
        '<tr><td colspan="5" class="empty-state text-sm">Failed to load tokens</td></tr>';
    }
  }

  function buildFilterPills(typeCounts) {
    if (!filterBar) return;
    var types = Object.keys(typeCounts).sort();
    if (types.length <= 1) {
      filterBar.style.display = "none";
      return;
    }
    filterBar.style.display = "";
    // Keep the label, remove old pills
    while (filterBar.children.length > 1) filterBar.removeChild(filterBar.lastChild);
    // "All" pill
    var allPill = el("button", {
      className: "btn btn-xs " + (activeFilters.size === 0 ? "btn-primary" : "btn-outline"),
      textContent: "All (" + Object.values(typeCounts).reduce(function (a, b) { return a + b; }, 0) + ")",
    });
    allPill.addEventListener("click", function () {
      activeFilters.clear();
      savePrefs();
      loadTokens();
    });
    filterBar.appendChild(allPill);
    // Per-type pills
    types.forEach(function (t) {
      // All types shown including WHITELIST
      var isActive = activeFilters.has(t);
      var pill = el("button", {
        className: "btn btn-xs " + (isActive ? "btn-primary" : "btn-outline"),
        textContent: t + " (" + typeCounts[t] + ")",
      });
      pill.addEventListener("click", function () {
        if (activeFilters.has(t)) {
          activeFilters.delete(t);
        } else {
          activeFilters.add(t);
        }
        savePrefs();
        loadTokens();
      });
      filterBar.appendChild(pill);
    });
  }

  function updateClearButtons(sid, count) {
    if (btnClearSession) {
      btnClearSession.disabled = !sid;
      btnClearSession.textContent = sid
        ? "Clear " + truncateId(sid, 12) + " Tokens"
        : "Clear Session Tokens";
    }
    if (btnClearAll) {
      btnClearAll.disabled = count === 0;
    }
  }

  // Add a term to the whitelist via API
  async function addToWhitelist(term, btn, stageName) {
    btn.disabled = true;
    btn.textContent = "Adding\u2026";
    try {
      var payload = { term: term };
      if (stageName) payload.stage_name = stageName;
      var resp = await fetch("/ui/api/whitelist/add", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      var data = await resp.json();
      if (resp.ok) {
        Toast.show(data.added ? "Added \u201c" + term + "\u201d to whitelist" : "Already in whitelist", "success");
        loadTokens();
      } else {
        Toast.show(data.error || "Failed to add to whitelist", "error");
        btn.disabled = false;
        btn.textContent = "Whitelist";
      }
    } catch (err) {
      Toast.show("Failed: " + err.message, "error");
      btn.disabled = false;
      btn.textContent = "Whitelist";
    }
  }

  // Clear selected session's exclusive tokens
  if (btnClearSession) {
    btnClearSession.addEventListener("click", async function () {
      var sid = sessionSelect.value;
      if (!sid) { Toast.show("Select a session first", "info"); return; }
      if (!confirm("Delete exclusive token mappings for session " + truncateId(sid, 16) + "?")) return;
      try {
        var resp = await fetch("/ui/api/sessions/" + encodeURIComponent(sid) + "/mappings", { method: "DELETE" });
        var data = await resp.json();
        if (resp.ok) {
          Toast.show("Removed " + data.removed + " exclusive mappings", "success");
          loadTokens();
        } else {
          Toast.show(data.error || "Failed", "error");
        }
      } catch (err) {
        Toast.show("Failed: " + err.message, "error");
      }
    });
  }

  // Clear all tokens
  if (btnClearAll) {
    btnClearAll.addEventListener("click", async function () {
      if (!confirm("Clear ALL token mappings across all sessions? This cannot be undone.")) return;
      try {
        var resp = await fetch("/ui/api/token-map", { method: "DELETE" });
        var data = await resp.json();
        if (resp.ok) {
          Toast.show("All mappings cleared", "success");
          loadTokens();
        } else {
          Toast.show(data.error || "Failed", "error");
        }
      } catch (err) {
        Toast.show("Failed: " + err.message, "error");
      }
    });
  }

  sessionSelect.addEventListener("change", loadTokens);
  btnRefresh.addEventListener("click", function () {
    loadSessions().then(loadTokens);
  });

  // Auto-refresh session list and tokens when new recordings arrive
  SSE.on("recording_complete", function () {
    loadWhitelistInstances().then(function () {
      loadSessions().then(loadTokens);
    });
  });

  // Fetch whitelist instances then load sessions and tokens
  async function loadWhitelistInstances() {
    try {
      var data = await apiFetch("/ui/api/whitelist/instances");
      whitelistInstances = data.instances || [];
    } catch (_) {
      whitelistInstances = [];
    }
  }

  loadWhitelistInstances().then(function () {
    loadSessions().then(loadTokens);
  });
})();
