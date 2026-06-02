/* ===================================================================
   Pipeline page -- fetches pipeline config and renders stage list
   with enable/disable toggle switches per stage.
   =================================================================== */

"use strict";

(function () {
  const stagesContainer = document.getElementById("pipeline-stages");

  function stageDescription(name) {
    switch (name) {
      case "presidio": return "NER-based PII detection using Microsoft Presidio + spaCy";
      case "regex":    return "Pattern-based detection using built-in and user-defined regex rules";
      case "plugins":  return "Custom detection plugins from ~/.scruxy/plugins/";
      default:         return "Pipeline stage";
    }
  }

  function createToggle(stage) {
    var label = el("label", { className: "toggle" });
    var input = document.createElement("input");
    input.type = "checkbox";
    input.checked = stage.enabled;
    var slider = el("span", { className: "toggle-slider" });
    label.appendChild(input);
    label.appendChild(slider);

    input.onchange = async function () {
      var newEnabled = input.checked;
      try {
        var resp = await fetch("/ui/api/pipeline/stages/" + encodeURIComponent(stage.name), {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ enabled: newEnabled }),
        });
        var data = await resp.json();
        if (resp.ok) {
          // Update the badge next to the toggle
          var item = input.closest(".stage-item");
          if (item) {
            var badge = item.querySelector(".badge");
            if (badge) {
              badge.className = "badge " + (newEnabled ? "badge-success" : "badge-neutral");
              badge.textContent = newEnabled ? "Enabled" : "Disabled";
            }
          }
          Toast.show("Stage '" + stage.name + "' " + (newEnabled ? "enabled" : "disabled"), "success");
        } else {
          // Revert toggle on failure
          input.checked = !newEnabled;
          Toast.show(data.error || "Failed to update stage", "error");
        }
      } catch (err) {
        input.checked = !newEnabled;
        Toast.show("Failed to update stage", "error");
      }
    };

    return label;
  }

  function renderStages(stages) {
    stagesContainer.innerHTML = "";

    if (!stages || stages.length === 0) {
      stagesContainer.innerHTML = '<div class="empty-state text-sm">No pipeline stages configured</div>';
      return;
    }

    stages.forEach(function (stage, idx) {
      var toggle = createToggle(stage);

      var item = el("div", { className: "stage-item" }, [
        el("span", { className: "stage-order", textContent: String(idx + 1) }),
        el("div", { className: "stage-info" }, [
          el("div", { className: "stage-name", textContent: stage.name }),
          el("div", { className: "stage-detail", textContent: stageDescription(stage.name) }),
        ]),
        toggle,
        el("span", {
          className: "badge " + (stage.enabled ? "badge-success" : "badge-neutral"),
          textContent: stage.enabled ? "Enabled" : "Disabled",
        }),
        el("a", {
          href: "/ui/plugins",
          className: "btn btn-outline btn-sm",
          textContent: "Configure",
        }),
      ]);
      stagesContainer.appendChild(item);
    });
  }

  async function load() {
    try {
      var data = await apiFetch("/ui/api/pipeline/config");
      renderStages(data.stages);
    } catch (_) {
      stagesContainer.innerHTML = '<div class="empty-state text-sm">Failed to load pipeline config</div>';
    }
  }

  load();
})();
