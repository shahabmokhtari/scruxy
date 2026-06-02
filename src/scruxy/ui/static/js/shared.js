/* ===================================================================
   Scruxy -- Shared JavaScript Utilities
   Dark-mode toggle, SSE manager, toast system, fetch helpers, nav.
   No external dependencies.
   =================================================================== */

"use strict";

// ---- Theme management -----------------------------------------------

const Theme = (() => {
  const KEY = "scruxy-theme";

  function current() {
    return localStorage.getItem(KEY) || "dark";
  }

  function apply(theme) {
    if (theme === "light") {
      document.documentElement.classList.add("light");
    } else {
      document.documentElement.classList.remove("light");
    }
    localStorage.setItem(KEY, theme);
    const btn = document.getElementById("theme-toggle");
    if (btn) btn.textContent = theme === "light" ? "\u263E" : "\u2600";
  }

  function toggle() {
    apply(current() === "dark" ? "light" : "dark");
  }

  function init() {
    apply(current());
    const btn = document.getElementById("theme-toggle");
    if (btn) btn.addEventListener("click", toggle);
  }

  return { init, toggle, current };
})();

// ---- SSE connection manager -----------------------------------------

const SSE = (() => {
  let source = null;
  const handlers = {};

  function connect(url) {
    if (source) source.close();
    url = url || "/ui/api/events";
    source = new EventSource(url);

    source.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        const type = data.type || "unknown";
        if (handlers[type]) {
          handlers[type].forEach((fn) => fn(data));
        }
        if (handlers["*"]) {
          handlers["*"].forEach((fn) => fn(data));
        }
      } catch (_) {
        /* ignore parse errors */
      }
    };

    source.onerror = () => {
      Toast.show("SSE connection lost. Reconnecting...", "warning");
    };
  }

  function on(type, fn) {
    if (!handlers[type]) handlers[type] = [];
    handlers[type].push(fn);
  }

  function close() {
    if (source) {
      source.close();
      source = null;
    }
  }

  return { connect, on, close };
})();

// ---- Toast notifications --------------------------------------------

const Toast = (() => {
  let container = null;

  function ensureContainer() {
    if (!container) {
      container = document.createElement("div");
      container.className = "toast-container";
      document.body.appendChild(container);
    }
  }

  function show(message, type, duration) {
    type = type || "info";
    duration = duration || 4000;
    ensureContainer();

    const el = document.createElement("div");
    el.className = "toast " + type;
    el.innerHTML =
      '<span class="toast-icon">' + _icon(type) + "</span>" +
      '<span class="toast-msg">' + escapeHtml(message) + "</span>";
    container.appendChild(el);

    setTimeout(() => {
      el.classList.add("fade-out");
      setTimeout(() => el.remove(), 350);
    }, duration);
  }

  function _icon(type) {
    switch (type) {
      case "success": return "\u2713";
      case "error":   return "\u2717";
      case "warning": return "\u26A0";
      default:        return "\u2139";
    }
  }

  return { show };
})();

// ---- Fetch helpers --------------------------------------------------

async function apiFetch(path, options) {
  options = options || {};
  const url = path.startsWith("http") ? path : path;
  try {
    const resp = await fetch(url, options);
    if (!resp.ok) {
      throw new Error("HTTP " + resp.status);
    }
    return await resp.json();
  } catch (err) {
    Toast.show("API error: " + err.message, "error");
    throw err;
  }
}

// ---- Navigation highlighting ----------------------------------------

function highlightNav() {
  const path = window.location.pathname.replace(/\/$/, "") || "/ui";
  const links = document.querySelectorAll(".sidebar-nav a");
  links.forEach((link) => {
    const href = link.getAttribute("href").replace(/\/$/, "") || "/ui";
    link.classList.toggle("active", href === path);
  });
}

// ---- HTML helpers ---------------------------------------------------

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

function el(tag, attrs, children) {
  const node = document.createElement(tag);
  if (attrs) {
    Object.entries(attrs).forEach(([k, v]) => {
      if (k === "className") node.className = v;
      else if (k === "textContent") node.textContent = v;
      else if (k === "innerHTML") node.innerHTML = v;
      else if (k.startsWith("on")) node.addEventListener(k.slice(2).toLowerCase(), v);
      else node.setAttribute(k, v);
    });
  }
  if (children) {
    (Array.isArray(children) ? children : [children]).forEach((c) => {
      if (typeof c === "string") node.appendChild(document.createTextNode(c));
      else if (c) node.appendChild(c);
    });
  }
  return node;
}

function formatTime(ts) {
  if (!ts) return "--";
  const d = new Date(typeof ts === "number" ? ts * 1000 : ts);
  return d.toLocaleTimeString();
}

function formatDate(ts) {
  if (!ts) return "--";
  const d = new Date(typeof ts === "number" ? ts * 1000 : ts);
  return d.toLocaleDateString() + " " + d.toLocaleTimeString();
}

function truncateId(id, len) {
  len = len || 8;
  if (!id) return "--";
  return id.length > len ? id.slice(0, len) + "\u2026" : id;
}

// ---- Simple Canvas line chart ---------------------------------------

function drawLineChart(canvasId, data, options) {
  options = options || {};
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.parentElement.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = (options.height || 200) * dpr;
  canvas.style.width = rect.width + "px";
  canvas.style.height = (options.height || 200) + "px";
  ctx.scale(dpr, dpr);

  const W = rect.width;
  const H = options.height || 200;
  const pad = { top: 20, right: 16, bottom: 30, left: 50 };

  ctx.clearRect(0, 0, W, H);

  if (!data || data.length === 0) {
    ctx.fillStyle = "#5d6275";
    ctx.font = "13px sans-serif";
    ctx.textAlign = "center";
    ctx.fillText("No data yet", W / 2, H / 2);
    return;
  }

  const vals = data.map(Number);
  const minV = Math.min(...vals) * 0.9;
  const maxV = Math.max(...vals) * 1.1 || 1;
  const plotW = W - pad.left - pad.right;
  const plotH = H - pad.top - pad.bottom;

  // Grid lines
  ctx.strokeStyle = "#2d3142";
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad.top + (plotH / 4) * i;
    ctx.beginPath();
    ctx.moveTo(pad.left, y);
    ctx.lineTo(W - pad.right, y);
    ctx.stroke();
  }

  // Y axis labels
  ctx.fillStyle = "#5d6275";
  ctx.font = "11px sans-serif";
  ctx.textAlign = "right";
  for (let i = 0; i <= 4; i++) {
    const v = maxV - ((maxV - minV) / 4) * i;
    const y = pad.top + (plotH / 4) * i;
    ctx.fillText(v.toFixed(1), pad.left - 8, y + 4);
  }

  // X axis label
  ctx.textAlign = "center";
  ctx.fillText("Recent requests", W / 2, H - 4);

  // Line
  const color = options.color || "#4a6cf7";
  ctx.strokeStyle = color;
  ctx.lineWidth = 2;
  ctx.lineJoin = "round";
  ctx.beginPath();
  vals.forEach((v, i) => {
    const x = pad.left + (plotW / Math.max(vals.length - 1, 1)) * i;
    const y = pad.top + plotH - ((v - minV) / (maxV - minV || 1)) * plotH;
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();

  // Gradient fill
  const gradient = ctx.createLinearGradient(0, pad.top, 0, pad.top + plotH);
  gradient.addColorStop(0, color + "33");
  gradient.addColorStop(1, color + "00");
  ctx.lineTo(pad.left + plotW, pad.top + plotH);
  ctx.lineTo(pad.left, pad.top + plotH);
  ctx.closePath();
  ctx.fillStyle = gradient;
  ctx.fill();
}

/**
 * Draw a multi-series line chart on the given canvas.
 * @param {string} canvasId - Canvas element id
 * @param {Array<{label: string, color: string, data: number[], dash?: number[]}>} series
 * @param {object} [options] - height, hiddenLabels (Set of label strings to skip)
 */
function drawMultiLineChart(canvasId, series, options) {
  options = options || {};
  var hiddenLabels = options.hiddenLabels || new Set();
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.parentElement.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = (options.height || 200) * dpr;
  canvas.style.width = rect.width + "px";
  canvas.style.height = (options.height || 200) + "px";
  ctx.scale(dpr, dpr);

  const W = rect.width;
  const H = options.height || 200;
  const pad = { top: 20, right: 16, bottom: 30, left: 50 };

  ctx.clearRect(0, 0, W, H);

  // Filter to series that have data AND are not hidden
  const activeSeries = (series || []).filter(
    s => s.data && s.data.length > 0 && !hiddenLabels.has(s.label)
  );
  if (activeSeries.length === 0) {
    ctx.fillStyle = "#5d6275";
    ctx.font = "13px sans-serif";
    ctx.textAlign = "center";
    ctx.fillText("No data yet", W / 2, H / 2);
    return;
  }

  // Compute global min/max across all visible series
  let globalMin = Infinity, globalMax = -Infinity;
  activeSeries.forEach(s => {
    s.data.forEach(v => {
      const n = Number(v);
      if (n < globalMin) globalMin = n;
      if (n > globalMax) globalMax = n;
    });
  });
  globalMin = globalMin * 0.9;
  globalMax = globalMax * 1.1 || 1;

  const plotW = W - pad.left - pad.right;
  const plotH = H - pad.top - pad.bottom;

  // Grid lines
  ctx.strokeStyle = "#2d3142";
  ctx.lineWidth = 1;
  ctx.setLineDash([]);
  for (let i = 0; i <= 4; i++) {
    const y = pad.top + (plotH / 4) * i;
    ctx.beginPath();
    ctx.moveTo(pad.left, y);
    ctx.lineTo(W - pad.right, y);
    ctx.stroke();
  }

  // Y axis labels
  ctx.fillStyle = "#5d6275";
  ctx.font = "11px sans-serif";
  ctx.textAlign = "right";
  for (let i = 0; i <= 4; i++) {
    const v = globalMax - ((globalMax - globalMin) / 4) * i;
    const y = pad.top + (plotH / 4) * i;
    ctx.fillText(v.toFixed(1), pad.left - 8, y + 4);
  }

  // X axis label
  ctx.textAlign = "center";
  ctx.fillText("Recent requests", W / 2, H - 4);

  // Draw each series
  activeSeries.forEach(s => {
    const vals = s.data.map(Number);
    ctx.strokeStyle = s.color;
    ctx.lineWidth = 2;
    ctx.lineJoin = "round";
    ctx.setLineDash(s.dash || []);
    ctx.beginPath();
    vals.forEach((v, i) => {
      const x = pad.left + (plotW / Math.max(vals.length - 1, 1)) * i;
      const y = pad.top + plotH - ((v - globalMin) / (globalMax - globalMin || 1)) * plotH;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();
  });
  ctx.setLineDash([]);
}

// ---- Init -----------------------------------------------------------

document.addEventListener("DOMContentLoaded", () => {
  Theme.init();
  highlightNav();
  SSE.connect();
});
