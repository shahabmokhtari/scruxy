/* ===================================================================
   Dashboard page logic -- fetches data from /ui/api/dashboard and
   renders stat cards, provider cards, latency chart, and setup guide.
   =================================================================== */

"use strict";

(function () {
  // -- DOM refs -------------------------------------------------------
  const statMode      = document.getElementById("stat-mode");
  const statProviders = document.getElementById("stat-providers");
  const statRequests  = document.getElementById("stat-requests");
  const statEntities  = document.getElementById("stat-entities");
  const providerCards = document.getElementById("provider-cards");

  // -- Chart toggle state ---------------------------------------------
  var hiddenSeries = new Set();

  // Provider color palette for per-provider lines
  var providerColors = [
    "#c084fc", "#38bdf8", "#fb923c", "#a3e635",
    "#f472b6", "#22d3ee", "#facc15", "#4ade80",
  ];
  var providerColorIdx = 0;
  var providerColorMap = {};
  function getProviderColor(name) {
    if (!providerColorMap[name]) {
      providerColorMap[name] = providerColors[providerColorIdx % providerColors.length];
      providerColorIdx++;
    }
    return providerColorMap[name];
  }

  // -- Provider icon letter -------------------------------------------
  function providerLetter(name) {
    return (name || "?")[0].toUpperCase();
  }

  function providerClass(name) {
    const n = (name || "").toLowerCase();
    if (n.includes("anthropic")) return "anthropic";
    if (n.includes("openai")) return "openai";
    return "default";
  }

  // -- Render providers -----------------------------------------------
  function renderProviders(providers) {
    providerCards.innerHTML = "";
    const names = Object.keys(providers || {});
    if (names.length === 0) {
      providerCards.innerHTML = '<div class="empty-state text-sm">No providers</div>';
      return;
    }
    names.forEach((name) => {
      const p = providers[name];
      const card = el("div", { className: "provider-card" }, [
        el("div", { className: "provider-icon " + providerClass(name), textContent: providerLetter(name) }),
        el("div", { className: "provider-info" }, [
          el("div", { className: "provider-name", textContent: name }),
          el("div", { className: "provider-url text-xs text-muted", textContent: p.upstream_url || "--" }),
        ]),
        el("span", { className: "badge " + (p.enabled ? "badge-success" : "badge-neutral"), textContent: p.enabled ? "Active" : "Disabled" }),
      ]);
      providerCards.appendChild(card);
    });
  }

  // -- Build chart series from data -----------------------------------
  function buildChartSeries(data) {
    var series = [
      { label: "Scrub", color: "#4a6cf7", data: data.latency_history || [], description: "Time to anonymize the request (PII detection + token replacement)" },
      { label: "Unscrub", color: "#f7a94a", data: data.unscrub_latency_history || [], description: "Time to deanonymize the response (token restoration)" },
      { label: "Network", color: "#e74a6c", data: data.network_latency_history || [], description: "Round-trip time for the upstream API call" },
      { label: "Total", color: "#4af7a0", data: data.total_latency_history || [], description: "End-to-end pipeline time (scrub + network + unscrub)" },
    ];
    // Per-provider series
    var pl = data.provider_latency || {};
    Object.keys(pl).forEach(function (pname) {
      var pdata = pl[pname];
      var color = getProviderColor(pname);
      if (pdata.total_history && pdata.total_history.length > 0) {
        series.push({ label: pname + " Total", color: color, data: pdata.total_history, description: "Total pipeline latency for " + pname });
      }
      if (pdata.network_history && pdata.network_history.length > 0) {
        series.push({ label: pname + " Network", color: color, data: pdata.network_history, dash: [5, 3], description: "Network latency for " + pname });
      }
    });
    return series;
  }

  // -- Render chart legend (clickable) --------------------------------
  function renderLegend(series) {
    var container = document.getElementById("latency-legend");
    if (!container) return;
    container.innerHTML = "";
    series.forEach(function (s) {
      var item = el("div", {
        className: "chart-legend-item" + (hiddenSeries.has(s.label) ? " hidden" : ""),
        title: s.description || s.label,
      }, [
        el("span", {
          className: "chart-legend-swatch" + (s.dash ? " dashed" : ""),
          style: s.dash
            ? "border-color:" + s.color
            : "background:" + s.color,
        }),
        el("span", { textContent: s.label }),
      ]);
      item.addEventListener("click", function () {
        if (hiddenSeries.has(s.label)) {
          hiddenSeries.delete(s.label);
          item.classList.remove("hidden");
        } else {
          hiddenSeries.add(s.label);
          item.classList.add("hidden");
        }
        drawMultiLineChart("latency-chart", series, { height: 200, hiddenLabels: hiddenSeries });
      });
      container.appendChild(item);
    });
  }

  // -- Render latency stats table -------------------------------------
  var activeStatsTab = "scrub";

  function renderLatencyStats(latencyStats) {
    var tabBar = document.getElementById("latency-stats-tabs");
    var body = document.getElementById("latency-stats-body");
    if (!tabBar || !body) return;

    var metrics = ["scrub", "unscrub", "network", "total"];
    var windows = ["5m", "15m", "30m", "1h"];
    var cols = ["avg", "min", "max", "p95", "p99"];

    // Has any data at all?
    var hasData = false;
    windows.forEach(function (w) {
      var ws = latencyStats[w];
      if (ws) {
        metrics.forEach(function (m) {
          if (ws[m] && ws[m].avg > 0) hasData = true;
        });
      }
    });
    if (!hasData) {
      tabBar.innerHTML = "";
      body.innerHTML = '<div class="empty-state text-sm" style="padding:16px">No latency data yet</div>';
      return;
    }

    // Render tabs
    tabBar.innerHTML = "";
    metrics.forEach(function (m) {
      var btn = el("button", {
        textContent: m.charAt(0).toUpperCase() + m.slice(1),
        className: m === activeStatsTab ? "active" : "",
      });
      btn.addEventListener("click", function () {
        activeStatsTab = m;
        renderLatencyStats(latencyStats);
      });
      tabBar.appendChild(btn);
    });

    // Render table for activeStatsTab
    var table = el("table", { className: "latency-stats-table" });
    var thead = el("thead", {}, [
      el("tr", {}, [
        el("th", { textContent: "Window" }),
      ].concat(cols.map(function (c) {
        return el("th", { textContent: c.toUpperCase() });
      }))),
    ]);
    table.appendChild(thead);

    var tbody = el("tbody");
    windows.forEach(function (w) {
      var ws = latencyStats[w];
      var row = ws && ws[activeStatsTab] ? ws[activeStatsTab] : {};
      var tr = el("tr", {}, [
        el("td", { textContent: w }),
      ].concat(cols.map(function (c) {
        var val = row[c];
        return el("td", { textContent: val != null && val > 0 ? val.toFixed(2) : "--" });
      })));
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);

    body.innerHTML = "";
    body.appendChild(table);
  }

  // -- Render setup guide -----------------------------------------------
  function renderSetupGuide(data) {
    var container = document.getElementById("setup-guide-content");
    if (!container) return;
    container.innerHTML = "";

    var host = data.listen_host || "localhost";
    var port = data.listen_port || 8080;
    var base = "http://" + host + ":" + port;
    var fwdEnabled = data.forward_proxy_enabled;
    var fwdPort = data.forward_proxy_port || 8081;
    var fwdBase = "http://" + host + ":" + fwdPort;
    var httpsEnabled = data.https_enabled;
    var httpsPort = data.https_port || 8443;
    var httpsBase = "https://" + host + ":" + httpsPort;
    var caCertPath = data.ca_cert_path || "~/.scruxy/certs/scruxy-ca.pem";

    var isWindows = navigator.platform.indexOf("Win") > -1 || navigator.userAgent.indexOf("Windows") > -1;

    // ------------------------------------------------------------------
    // Method 1: Base URL (reverse proxy)
    // ------------------------------------------------------------------
    var method1Header = el("div", { className: "setup-method-header" }, [
      el("div", { className: "setup-method-number", textContent: "1" }),
      el("div", {}, [
        el("div", { className: "setup-method-title", textContent: "Base URL (Reverse Proxy)" }),
        el("div", { className: "text-xs text-muted", textContent: "Set the API base URL to route traffic through Scruxy. Works with Claude Code and tools that support custom endpoints." }),
      ]),
    ]);

    var method1Tabs = [
      {
        id: "m1-unix",
        label: "macOS / Linux",
        commands: [
          { label: "Set environment variables for current shell", items: [
            "export ANTHROPIC_BASE_URL=" + base,
            "export OPENAI_BASE_URL=" + base + "/v1",
          ]},
          { label: "Run Claude Code through the proxy", items: [
            "ANTHROPIC_BASE_URL=" + base + " claude",
          ]},
          { label: "Run VS Code (Copilot) through the proxy", items: [
            "OPENAI_BASE_URL=" + base + "/v1 code",
          ]},
        ],
      },
      {
        id: "m1-windows",
        label: "Windows (PowerShell)",
        commands: [
          { label: "Set environment variables for current shell", items: [
            '$env:ANTHROPIC_BASE_URL="' + base + '"',
            '$env:OPENAI_BASE_URL="' + base + '/v1"',
          ]},
          { label: "Run Claude Code through the proxy", items: [
            '$env:ANTHROPIC_BASE_URL="' + base + '"; claude',
          ]},
          { label: "Run VS Code (Copilot) through the proxy", items: [
            '$env:OPENAI_BASE_URL="' + base + '/v1"; code',
          ]},
        ],
      },
    ];

    // ------------------------------------------------------------------
    // Method 2: HTTP Proxy (forward proxy)
    // ------------------------------------------------------------------
    var method2Header = el("div", { className: "setup-method-header" }, [
      el("div", { className: "setup-method-number", textContent: "2" }),
      el("div", {}, [
        el("div", { className: "setup-method-title", textContent: "HTTP Proxy (Forward Proxy)" + (fwdEnabled ? "" : " — Disabled") }),
        el("div", { className: "text-xs text-muted", textContent: fwdEnabled
          ? "Use HTTP_PROXY/HTTPS_PROXY for tools that support standard proxy settings (e.g. GitHub Copilot CLI). Both should point to the forward proxy. Requires trusting the Scruxy CA certificate."
          : "Forward proxy is disabled. Enable it in config.yaml or start with --forward-proxy to use HTTP_PROXY mode."
        }),
      ]),
    ]);

    var httpsProxyUrl = fwdBase;

    var caCertPathWin = caCertPath.replace(/\//g, "\\");

    var method2Tabs = [
      {
        id: "m2-unix",
        label: "macOS / Linux",
        commands: [
          { label: "1. Trust the Scruxy CA certificate (one-time setup)", items: [
            "# macOS:",
            "sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain " + caCertPath,
            "# Linux (Debian/Ubuntu):",
            "sudo cp " + caCertPath + " /usr/local/share/ca-certificates/scruxy-ca.crt && sudo update-ca-certificates",
          ]},
          { label: "2. Trust the CA for VS Code / Node.js clients", items: [
            "# Node.js (used by VS Code & Copilot) ignores the OS trust store.",
            "# Set this before launching VS Code so it trusts the Scruxy CA:",
            "export NODE_EXTRA_CA_CERTS=" + caCertPath,
          ]},
          { label: "3. Set proxy environment variables", items: [
            "export HTTP_PROXY=" + fwdBase,
            "export HTTPS_PROXY=" + httpsProxyUrl,
          ]},
          { label: "4. Run GitHub Copilot through the proxy", items: [
            "HTTP_PROXY=" + fwdBase + " HTTPS_PROXY=" + httpsProxyUrl + " NODE_EXTRA_CA_CERTS=" + caCertPath + " copilot",
          ]},
        ],
      },
      {
        id: "m2-windows",
        label: "Windows (PowerShell)",
        commands: [
          { label: "1. Trust the Scruxy CA certificate (one-time, run as Admin)", items: [
            "certutil -addstore Root " + caCertPathWin,
          ]},
          { label: "2. Trust the CA for VS Code / Node.js clients", items: [
            "# Node.js (used by VS Code & Copilot) ignores the OS trust store.",
            "# Set this before launching VS Code so it trusts the Scruxy CA:",
            '$env:NODE_EXTRA_CA_CERTS="' + caCertPathWin + '"',
          ]},
          { label: "3. Set proxy environment variables", items: [
            '$env:HTTP_PROXY="' + fwdBase + '"',
            '$env:HTTPS_PROXY="' + httpsProxyUrl + '"',
          ]},
          { label: "4. Run GitHub Copilot through the proxy", items: [
            '$env:HTTP_PROXY="' + fwdBase + '"; $env:HTTPS_PROXY="' + httpsProxyUrl + '"; $env:NODE_EXTRA_CA_CERTS="' + caCertPathWin + '"; copilot',
          ]},
        ],
      },
    ];

    // ------------------------------------------------------------------
    // Render helper
    // ------------------------------------------------------------------
    function buildTabSection(tabDefs, defaultIdx) {
      var tabBar = el("div", { className: "tab-bar" });
      var panels = {};
      tabDefs.forEach(function (tab, idx) {
        var btn = el("button", { textContent: tab.label });
        if (idx === defaultIdx) btn.className = "active";
        tabBar.appendChild(btn);

        var panel = el("div", { className: idx === defaultIdx ? "" : "hidden" });
        tab.commands.forEach(function (group) {
          var section = el("div", { className: "setup-tool" });
          section.appendChild(el("div", { className: "setup-tool-label", textContent: group.label }));
          group.items.forEach(function (cmd) {
            if (cmd.startsWith("#")) {
              // Render comments as plain text, no copy button
              section.appendChild(el("div", { className: "code-comment text-xs text-muted", textContent: cmd, style: "padding: 2px 12px;" }));
              return;
            }
            var copyBtn = el("button", {
              className: "copy-btn",
              textContent: "Copy",
              onClick: function () {
                copyToClipboard(cmd);
                copyBtn.textContent = "Copied!";
                setTimeout(function () { copyBtn.textContent = "Copy"; }, 1500);
              },
            });
            section.appendChild(el("div", { className: "code-block" }, [
              el("code", { textContent: cmd }),
              copyBtn,
            ]));
          });
          panel.appendChild(section);
        });
        panels[tab.id] = panel;

        btn.onclick = function () {
          tabBar.querySelectorAll("button").forEach(function (b) { b.className = ""; });
          btn.className = "active";
          Object.values(panels).forEach(function (p) { p.classList.add("hidden"); });
          panel.classList.remove("hidden");
        };
      });

      var wrapper = el("div");
      wrapper.appendChild(tabBar);
      Object.keys(panels).forEach(function (id) { wrapper.appendChild(panels[id]); });
      return wrapper;
    }

    var defaultTab = isWindows ? 1 : 0;

    // Method 1
    container.appendChild(method1Header);
    container.appendChild(buildTabSection(method1Tabs, defaultTab));

    // Divider
    container.appendChild(el("hr", { style: "margin: 24px 0; border-color: var(--border-color, #e2e8f0);" }));

    // Method 2
    container.appendChild(method2Header);

    // Cert status overlay for Method 2
    var certStatus = data.cert_status;
    if (fwdEnabled && certStatus) {
      if (certStatus.expired) {
        var expiredBanner = el("div", { className: "cert-expired-error" }, [
          el("div", { className: "cert-banner-icon", textContent: "\u26D4" }),
          el("div", {}, [
            el("strong", { textContent: "CA Certificate Expired" }),
            el("div", { className: "text-xs", textContent: "The Scruxy CA certificate expired on " + (certStatus.expiry_date || "unknown") + ". HTTPS interception will not work. Delete the cert files in " + certStatus.cert_path.replace(/[/\\][^/\\]+$/, "") + " and restart Scruxy to regenerate." }),
          ]),
          el("button", {
            className: "cert-recheck-btn",
            textContent: "Re-check",
            onClick: function () { recheckCert(); },
          }),
        ]);
        container.appendChild(expiredBanner);
      } else if (certStatus.expiry_warning) {
        var warningBanner = el("div", { className: "cert-expiry-warning" }, [
          el("div", { className: "cert-banner-icon", textContent: "\u26A0\uFE0F" }),
          el("div", {}, [
            el("strong", { textContent: "CA Certificate Expiring Soon" }),
            el("div", { className: "text-xs", textContent: "Expires in " + certStatus.days_until_expiry + " days (" + certStatus.expiry_date + "). Consider regenerating before it expires." }),
          ]),
          el("button", {
            className: "cert-recheck-btn",
            textContent: "Re-check",
            onClick: function () { recheckCert(); },
          }),
        ]);
        container.appendChild(warningBanner);
      }

      if (!certStatus.installed && !certStatus.expired) {
        var overlay = el("div", { className: "cert-warning-overlay" }, [
          el("div", { className: "cert-banner-icon", textContent: "\uD83D\uDD12" }),
          el("div", {}, [
            el("strong", { textContent: "CA Certificate Not Installed" }),
            el("div", { className: "text-xs", textContent: "The Scruxy CA certificate exists at " + certStatus.cert_path + " but is not installed in the OS trust store. HTTPS interception requires the cert to be trusted." }),
            el("div", { className: "text-xs", style: "margin-top: 6px;" }, [
              el("span", { textContent: "Install it manually using the commands below, or set " }),
              el("code", { textContent: "auto_install_ca_cert: true" }),
              el("span", { textContent: " in config.yaml and restart." }),
            ]),
          ]),
          el("button", {
            className: "cert-recheck-btn",
            textContent: "Re-check",
            onClick: function () { recheckCert(); },
          }),
        ]);
        container.appendChild(overlay);
      }
    }

    if (fwdEnabled) {
      container.appendChild(buildTabSection(method2Tabs, defaultTab));
    }

    // Divider
    container.appendChild(el("hr", { style: "margin: 24px 0; border-color: var(--border-color, #e2e8f0);" }));

    // ------------------------------------------------------------------
    // Reset: Unset all proxy environment variables
    // ------------------------------------------------------------------
    var resetHeader = el("div", { className: "setup-method-header" }, [
      el("div", { className: "setup-method-number", textContent: "\u21BA" }),
      el("div", {}, [
        el("div", { className: "setup-method-title", textContent: "Reset Environment Variables" }),
        el("div", { className: "text-xs text-muted", textContent: "Remove all Scruxy proxy environment variables from the current shell. Run these commands to restore direct API access." }),
      ]),
    ]);

    var resetTabs = [
      {
        id: "reset-unix",
        label: "macOS / Linux",
        commands: [
          { label: "Unset all proxy variables (current shell)", items: [
            "unset ANTHROPIC_BASE_URL OPENAI_BASE_URL HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NODE_EXTRA_CA_CERTS",
          ]},
          { label: "Or unset individually", items: [
            "unset ANTHROPIC_BASE_URL",
            "unset OPENAI_BASE_URL",
            "unset HTTP_PROXY",
            "unset HTTPS_PROXY",
            "unset NODE_EXTRA_CA_CERTS",
          ]},
        ],
      },
      {
        id: "reset-windows",
        label: "Windows (PowerShell)",
        commands: [
          { label: "Remove all proxy variables (current shell)", items: [
            'Remove-Item Env:ANTHROPIC_BASE_URL, Env:OPENAI_BASE_URL, Env:HTTP_PROXY, Env:HTTPS_PROXY, Env:NODE_EXTRA_CA_CERTS -ErrorAction SilentlyContinue',
          ]},
          { label: "Or remove individually", items: [
            '$env:ANTHROPIC_BASE_URL=""',
            '$env:OPENAI_BASE_URL=""',
            '$env:HTTP_PROXY=""',
            '$env:HTTPS_PROXY=""',
            '$env:NODE_EXTRA_CA_CERTS=""',
          ]},
        ],
      },
    ];

    container.appendChild(resetHeader);
    container.appendChild(buildTabSection(resetTabs, defaultTab));

    // Web UI link
    var uiSection = el("div", { className: "setup-tool", style: "margin-top: 16px;" });
    uiSection.appendChild(el("div", { className: "setup-tool-label", textContent: "Web UI" }));
    var link = el("a", { href: base + "/ui", textContent: base + "/ui" });
    uiSection.appendChild(el("div", { className: "code-block" }, [
      el("code", {}, [link]),
    ]));
    container.appendChild(uiSection);
  }

  async function recheckCert() {
    try {
      await apiFetch("/ui/api/cert/check", { method: "POST" });
      await loadDashboard();
    } catch (_) {
      /* toast already shown by apiFetch */
    }
  }

  function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text);
    } else {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
    }
  }

  // -- Last known data for SSE redraws --------------------------------
  var lastSeries = [];

  // -- Load data from API ---------------------------------------------
  async function loadDashboard() {
    try {
      const data = await apiFetch("/ui/api/dashboard");

      statMode.textContent = (data.mode || "primary").toUpperCase();
      const provCount = Object.keys(data.providers || {}).length;
      statProviders.textContent = String(provCount);
      statRequests.textContent = String(data.total_requests || 0);
      statEntities.textContent = String(data.total_entities || 0);

      renderProviders(data.providers);
      renderSetupGuide(data);

      // Build chart series including per-provider
      lastSeries = buildChartSeries(data);
      renderLegend(lastSeries);
      drawMultiLineChart("latency-chart", lastSeries, { height: 200, hiddenLabels: hiddenSeries });

      // Latency stats table
      renderLatencyStats(data.latency_stats || {});

    } catch (_) {
      /* toast already shown by apiFetch */
    }
  }

  // -- SSE live updates -----------------------------------------------
  SSE.on("scrub_event", (data) => {
    // Increment counters in place
    const cur = parseInt(statEntities.textContent, 10) || 0;
    statEntities.textContent = String(cur + (data.entity_count || 1));

    const curReq = parseInt(statRequests.textContent, 10) || 0;
    statRequests.textContent = String(curReq + 1);
  });

  SSE.on("latency", (data) => {
    // Refresh the multi-line chart with latest data
    if (data.value !== undefined) {
      var series = [
        { label: "Scrub", color: "#4a6cf7", data: data.scrub_history || data.history || [data.value], description: "Time to anonymize the request (PII detection + token replacement)" },
        { label: "Unscrub", color: "#f7a94a", data: data.unscrub_history || [], description: "Time to deanonymize the response (token restoration)" },
        { label: "Network", color: "#e74a6c", data: data.network_history || [], description: "Round-trip time for the upstream API call" },
        { label: "Total", color: "#4af7a0", data: data.total_history || [], description: "End-to-end pipeline time (scrub + network + unscrub)" },
      ];
      lastSeries = series;
      renderLegend(series);
      drawMultiLineChart("latency-chart", series, { height: 200, hiddenLabels: hiddenSeries });
    }
  });

  // -- Init -----------------------------------------------------------
  loadDashboard();
  // Refresh every 30s
  setInterval(loadDashboard, 30000);
})();
