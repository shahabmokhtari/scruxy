/* ===================================================================
   Logs & Statistics page -- stats counters, bar charts, event log.
   =================================================================== */

"use strict";

(function () {
  var totalRequests = document.getElementById("log-total-requests");
  var totalEntities = document.getElementById("log-total-entities");
  var uptimeEl      = document.getElementById("log-uptime");
  var byTypeChart   = document.getElementById("entities-by-type-chart");
  var byProvChart   = document.getElementById("requests-by-provider-chart");
  var eventLogTable = document.getElementById("event-log-table");

  function formatUptime(seconds) {
    if (!seconds || seconds <= 0) return "--";
    var h = Math.floor(seconds / 3600);
    var m = Math.floor((seconds % 3600) / 60);
    var s = Math.floor(seconds % 60);
    if (h > 0) return h + "h " + m + "m";
    if (m > 0) return m + "m " + s + "s";
    return s + "s";
  }

  // Simple horizontal bar chart using plain HTML
  function renderBarChart(container, data) {
    var entries = Object.entries(data || {});
    if (entries.length === 0) {
      container.innerHTML = '<div class="empty-state text-sm">No data yet</div>';
      return;
    }

    var maxVal = Math.max.apply(null, entries.map(function (e) { return e[1]; })) || 1;
    container.innerHTML = "";

    var colors = ["#4a6cf7", "#22c55e", "#eab308", "#ef4444", "#38bdf8", "#a855f7", "#f97316"];
    entries.forEach(function (pair, i) {
      var name = pair[0];
      var count = pair[1];
      var pct = Math.round((count / maxVal) * 100);
      var color = colors[i % colors.length];

      var row = el("div", { className: "flex items-center gap-3 mb-2" }, [
        el("span", {
          className: "text-sm",
          style: "min-width:100px;",
          textContent: name,
        }),
        (function () {
          var bar = el("div", {
            style:
              "flex:1;height:20px;background:var(--bg-input);border-radius:4px;overflow:hidden;",
          });
          var fill = el("div", {
            style:
              "height:100%;width:" + pct + "%;background:" + color +
              ";border-radius:4px;transition:width 0.4s ease;",
          });
          bar.appendChild(fill);
          return bar;
        })(),
        el("span", {
          className: "text-sm mono",
          style: "min-width:40px;text-align:right;",
          textContent: String(count),
        }),
      ]);
      container.appendChild(row);
    });
  }

  function renderEvent(ev) {
    var tr = el("tr", {}, [
      el("td", { textContent: formatTime(ev.timestamp) }),
      el("td", { className: "mono", textContent: truncateId(ev.session_id, 10) }),
      el("td", { textContent: ev.provider || "--" }),
      el("td", {}, [
        el("span", { className: "badge badge-info", textContent: ev.entity_type || "--" }),
      ]),
      el("td", { textContent: ev.direction || "--" }),
      el("td", { textContent: ev.confidence != null ? ev.confidence.toFixed(2) : "--" }),
    ]);
    return tr;
  }

  async function load() {
    try {
      var data = await apiFetch("/ui/api/stats");
      totalRequests.textContent = String(data.total_requests || 0);
      totalEntities.textContent = String(data.total_entities || 0);
      uptimeEl.textContent = formatUptime(data.uptime_seconds);

      renderBarChart(byTypeChart, data.entities_by_type);
      renderBarChart(byProvChart, data.requests_by_provider);

      // Backfill event log from persisted recent_events
      var events = data.recent_events || [];
      if (events.length > 0) {
        eventLogTable.innerHTML = "";
        // Show newest first (events are stored oldest-first)
        for (var i = events.length - 1; i >= 0 && i >= events.length - 100; i--) {
          eventLogTable.appendChild(renderEvent(events[i]));
        }
      }
    } catch (_) {
      /* toast shown by apiFetch */
    }
  }

  // SSE: append events to the log table
  SSE.on("scrub_event", function (ev) {
    if (eventLogTable.querySelector(".empty-state")) {
      eventLogTable.innerHTML = "";
    }
    var tr = renderEvent(ev);
    // Prepend so newest appears first
    eventLogTable.insertBefore(tr, eventLogTable.firstChild);
    // Keep at most 100 rows
    while (eventLogTable.children.length > 100) {
      eventLogTable.removeChild(eventLogTable.lastChild);
    }
  });

  // ---- Application logs (real Python logger output) ----------------------

  var appLogContainer = document.getElementById("app-log-container");
  var chkAutoScroll   = document.getElementById("chk-log-autoscroll");
  var levelFiltersEl  = document.getElementById("log-level-filters");
  var _lastLogId = 0;
  // Buffer all received entries so we can re-filter without re-fetching
  var _allLogEntries = [];

  var LOG_PREFS_KEY = "scruxy-logs-prefs";
  var ALL_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"];
  // Default: show WARNING + ERROR + CRITICAL only
  var DEFAULT_LEVEL_FILTER = { "DEBUG": false, "INFO": false, "WARNING": true, "ERROR": true, "CRITICAL": true };
  var levelFilter = {};

  var LOG_COLORS = {
    "DEBUG":    "var(--text-muted)",
    "INFO":     "var(--text-secondary)",
    "WARNING":  "var(--warning)",
    "ERROR":    "var(--danger)",
    "CRITICAL": "var(--danger)",
  };

  // Persist / load prefs
  function saveLogPrefs() {
    try {
      localStorage.setItem(LOG_PREFS_KEY, JSON.stringify({ levelFilter: levelFilter }));
    } catch (_) {}
  }
  (function loadLogPrefs() {
    try {
      var raw = localStorage.getItem(LOG_PREFS_KEY);
      var p = raw ? JSON.parse(raw) : null;
      if (p && p.levelFilter) { levelFilter = p.levelFilter; return; }
    } catch (_) {}
    ALL_LEVELS.forEach(function (l) { levelFilter[l] = DEFAULT_LEVEL_FILTER[l]; });
  })();

  function renderLevelFilters() {
    levelFiltersEl.innerHTML = "";
    ALL_LEVELS.forEach(function (l) {
      var active = levelFilter[l] !== false;
      var chip = document.createElement("button");
      chip.className = "btn btn-xs " + (active ? "btn-primary" : "btn-outline");
      chip.textContent = l;
      chip.style.fontSize = "0.7rem";
      chip.style.padding = "2px 7px";
      chip.addEventListener("click", function () {
        levelFilter[l] = !active;
        saveLogPrefs();
        renderLevelFilters();
        rerenderLogs();
      });
      levelFiltersEl.appendChild(chip);
    });
  }
  renderLevelFilters();

  function isLevelVisible(level) { return levelFilter[level] !== false; }

  function renderLogLine(entry) {
    var line = el("div", { className: "app-log-line" });
    line.style.color = LOG_COLORS[entry.level] || "var(--text-primary)";
    line.textContent = entry.message;
    line.setAttribute("data-level", entry.level);
    return line;
  }

  function rerenderLogs() {
    appLogContainer.innerHTML = "";
    var count = 0;
    for (var i = 0; i < _allLogEntries.length; i++) {
      if (!isLevelVisible(_allLogEntries[i].level)) continue;
      appLogContainer.appendChild(renderLogLine(_allLogEntries[i]));
      count++;
    }
    if (count === 0) {
      appLogContainer.innerHTML = '<div class="empty-state text-sm">No matching logs</div>';
    }
    if (chkAutoScroll && chkAutoScroll.checked) {
      appLogContainer.scrollTop = appLogContainer.scrollHeight;
    }
  }

  async function pollAppLogs() {
    try {
      var data = await apiFetch("/ui/api/logs?after=" + _lastLogId + "&limit=100");
      var entries = data.entries || [];
      if (entries.length === 0) return;

      // Clear placeholder on first data
      if (_allLogEntries.length === 0 && appLogContainer.querySelector(".empty-state")) {
        appLogContainer.innerHTML = "";
      }

      var appended = false;
      entries.forEach(function (e) {
        _allLogEntries.push(e);
        if (e.id > _lastLogId) _lastLogId = e.id;
        if (isLevelVisible(e.level)) {
          appLogContainer.appendChild(renderLogLine(e));
          appended = true;
        }
      });

      // Trim buffer
      while (_allLogEntries.length > 500) _allLogEntries.shift();
      // Trim DOM
      while (appLogContainer.children.length > 500) {
        appLogContainer.removeChild(appLogContainer.firstChild);
      }

      if (appended && chkAutoScroll && chkAutoScroll.checked) {
        appLogContainer.scrollTop = appLogContainer.scrollHeight;
      }
    } catch (_) { /* ignore */ }
  }

  // Clear logs button
  var btnClearLogs = document.getElementById("btn-clear-logs");
  if (btnClearLogs) {
    btnClearLogs.addEventListener("click", function () {
      _allLogEntries = [];
      appLogContainer.innerHTML = '<div class="empty-state text-sm">Logs cleared</div>';
    });
  }

  // Initial load + poll every 2 seconds
  pollAppLogs();
  setInterval(pollAppLogs, 2000);

  load();
})();
