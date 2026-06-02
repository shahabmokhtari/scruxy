/* ===================================================================
   Plugins page -- unified list of all detection plugins (builtin + user)
   with enable/disable toggles, collapsible config forms, and file editor.
   =================================================================== */

"use strict";

(function () {
  var container = document.getElementById("plugins-list");

  // -- Helpers -----------------------------------------------------------

  function formatFieldName(name) {
    return name.replace(/_/g, " ").replace(/\b\w/g, function (c) { return c.toUpperCase(); });
  }

  function getFieldLabel(field) {
    return field.label || formatFieldName(field.name);
  }

  // -- Toggle switch (same pattern as pipeline.js) -----------------------

  function createToggle(plugin) {
    var label = el("label", { className: "toggle" });
    var input = document.createElement("input");
    input.type = "checkbox";
    input.checked = plugin.enabled;
    var slider = el("span", { className: "toggle-slider" });
    label.appendChild(input);
    label.appendChild(slider);

    input.onchange = async function () {
      var newEnabled = input.checked;
      try {
        var resp = await fetch("/ui/api/plugins/" + encodeURIComponent(plugin.name) + "/toggle", {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ enabled: newEnabled }),
        });
        var data = await resp.json();
        if (resp.ok) {
          // Update badge
          var card = input.closest(".card");
          if (card) {
            var badge = card.querySelector(".badge");
            if (badge) {
              badge.textContent = newEnabled ? "Enabled" : "Disabled";
              badge.className = "badge " + (newEnabled ? "badge-success" : "badge-neutral");
            }
          }
          Toast.show("Plugin '" + plugin.name + "' " + (newEnabled ? "enabled" : "disabled"), "success");
          load();  // Refresh the full list to reflect the new state
        } else {
          input.checked = !newEnabled;
          Toast.show(data.error || "Failed to toggle plugin", "error");
        }
      } catch (err) {
        input.checked = !newEnabled;
        Toast.show("Failed to toggle plugin", "error");
      }
    };

    return label;
  }

  // -- Unified config form from config_schema ----------------------------

  function buildUnifiedForm(plugin) {
    var schema = plugin.config_schema || [];
    if (schema.length === 0) return null;

    var runtimeConfig = plugin.config || {};

    var form = el("div", { className: "plugin-config-form mt-3" });
    var fieldMap = {}; // name -> input element

    schema.forEach(function (field) {
      // Skip file fields in the form — they get an Edit File button instead
      if (field.field_type === "file") return;

      var group = el("div", { className: "config-field-group" });

      // Label
      var labelText = getFieldLabel(field);
      var label = el("label", { className: "config-field-label", textContent: labelText });
      if (field.description) {
        label.title = field.description;
      }
      group.appendChild(label);

      // Description under label
      if (field.description) {
        group.appendChild(el("div", { className: "config-field-description", textContent: field.description }));
      }

      // Determine current value: runtime config > default
      var currentValue = (field.name in runtimeConfig) ? runtimeConfig[field.name] : field.default;

      var input;
      if (field.field_type === "boolean") {
        var wrapper = el("div", { className: "flex items-center gap-2" });
        input = document.createElement("input");
        input.type = "checkbox";
        input.checked = currentValue === true;
        input._fieldType = "boolean";
        wrapper.appendChild(input);
        group.appendChild(wrapper);
      } else if (field.field_type === "number") {
        if (field.name === "score_threshold" || (field.min_value != null && field.max_value != null && field.max_value <= 1)) {
          var sliderWrapper = el("div", { className: "flex items-center gap-2" });
          input = document.createElement("input");
          input.type = "range";
          input.min = String(field.min_value != null ? field.min_value : 0);
          input.max = String(field.max_value != null ? field.max_value : 1);
          input.step = "0.05";
          input.value = currentValue != null ? String(currentValue) : "0.5";
          input.style.width = "180px";
          var valSpan = el("span", { className: "config-value mono", textContent: String(input.value) });
          input.oninput = function () { valSpan.textContent = input.value; };
          input._fieldType = "number";
          sliderWrapper.appendChild(input);
          sliderWrapper.appendChild(valSpan);
          group.appendChild(sliderWrapper);
        } else {
          input = document.createElement("input");
          input.type = "number";
          input.value = currentValue != null ? String(currentValue) : "";
          if (field.min_value != null) input.min = String(field.min_value);
          if (field.max_value != null) input.max = String(field.max_value);
          input.style.width = "160px";
          input._fieldType = "number";
          group.appendChild(input);
        }
      } else if (field.field_type === "select" && field.choices) {
        input = document.createElement("select");
        field.choices.forEach(function (opt) {
          var option = document.createElement("option");
          option.value = opt;
          option.textContent = opt;
          if (opt === currentValue) option.selected = true;
          input.appendChild(option);
        });
        input._fieldType = "select";
        group.appendChild(input);
      } else if (field.field_type === "list") {
        input = document.createElement("input");
        input.type = "text";
        input.value = Array.isArray(currentValue) ? currentValue.join(", ") : (currentValue || "");
        input.placeholder = "(comma-separated)";
        input.className = "w-full";
        input._fieldType = "list";
        group.appendChild(input);
      } else if (field.field_type === "text") {
        input = document.createElement("textarea");
        input.value = currentValue != null ? String(currentValue) : "";
        input.className = "config-textarea";
        input.rows = 8;
        input.spellcheck = false;
        input._fieldType = "text";
        group.appendChild(input);
      } else {
        // string (default)
        input = document.createElement("input");
        input.type = "text";
        input.value = currentValue != null ? String(currentValue) : "";
        input.className = "w-full";
        input._fieldType = "string";
        group.appendChild(input);
      }

      if (field.details) {
        group.appendChild(el("div", { className: "config-field-details", textContent: field.details }));
      }

      fieldMap[field.name] = input;
      form.appendChild(group);
    });

    // Save button (only if there are non-file fields)
    if (Object.keys(fieldMap).length > 0) {
      var saveBtn = el("button", { className: "btn btn-primary btn-sm mt-2", textContent: "Save Configuration" });
      saveBtn.onclick = async function () {
        var newConfig = {};
        Object.keys(fieldMap).forEach(function (name) {
          var inp = fieldMap[name];
          if (inp._fieldType === "boolean") {
            newConfig[name] = inp.checked;
          } else if (inp._fieldType === "number") {
            newConfig[name] = parseFloat(inp.value);
          } else if (inp._fieldType === "list") {
            newConfig[name] = inp.value.split(",").map(function (s) { return s.trim(); }).filter(Boolean);
          } else if (inp._fieldType === "select") {
            newConfig[name] = inp.value;
          } else if (inp._fieldType === "text") {
            newConfig[name] = inp.value;
          } else {
            newConfig[name] = inp.value;
          }
        });

        saveBtn.disabled = true;
        saveBtn.textContent = "Saving...";
        try {
          var resp = await fetch("/ui/api/plugins/" + encodeURIComponent(plugin.name) + "/config", {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(newConfig),
          });
          var data = await resp.json();
          if (resp.ok) {
            Toast.show("Configuration saved", "success");
          } else {
            Toast.show(data.error || "Failed to save", "error");
          }
        } catch (err) {
          Toast.show("Failed to save configuration", "error");
        }
        saveBtn.disabled = false;
        saveBtn.textContent = "Save Configuration";
      };
      form.appendChild(saveBtn);
    }

    // Add "Edit File" buttons for all file-type fields
    schema.forEach(function (field) {
      if (field.field_type !== "file") return;
      var currentPath = (field.name in runtimeConfig) ? runtimeConfig[field.name] : field.default;

      var fileRow = el("div", { className: "config-field-group" });
      var labelText = getFieldLabel(field);
      fileRow.appendChild(el("label", { className: "config-field-label", textContent: labelText }));
      if (field.description) {
        fileRow.appendChild(el("div", { className: "config-field-description", textContent: field.description }));
      }

      var pathRow = el("div", { className: "flex items-center gap-2" });
      var pathCode = el("code", { className: "text-xs mono", textContent: currentPath || "(not set)" });
      pathRow.appendChild(pathCode);

      var editBtn = el("button", { className: "btn btn-outline btn-sm", textContent: "Edit File" });
      editBtn.onclick = function () { openFileEditor(plugin.name, field.name); };
      pathRow.appendChild(editBtn);

      // Rename File button
      if (currentPath) {
        (function (pluginName, fieldName, pathCodeEl) {
          var renameBtn = el("button", { className: "btn btn-outline btn-sm", textContent: "Rename File" });
          renameBtn.onclick = function () {
            var currentName = currentPath.split("/").pop().split("\\").pop();
            var newName = prompt("Enter new file name:", currentName);
            if (!newName || newName === currentName) return;
            // Build new path: same directory, new filename
            var dir = currentPath.substring(0, currentPath.length - currentName.length);
            var newPath = dir + newName;
            renameBtn.disabled = true;
            renameBtn.textContent = "Renaming...";
            fetch("/ui/api/plugins/" + encodeURIComponent(pluginName) + "/file/" + encodeURIComponent(fieldName) + "/rename", {
              method: "PUT",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ new_path: newPath }),
            }).then(function (resp) {
              return resp.json().then(function (data) {
                if (resp.ok) {
                  Toast.show(data.message || "File renamed", "success");
                  pathCodeEl.textContent = newPath;
                  load();
                } else {
                  Toast.show(data.error || "Failed to rename file", "error");
                }
              });
            }).catch(function () {
              Toast.show("Failed to rename file", "error");
            }).finally(function () {
              renameBtn.disabled = false;
              renameBtn.textContent = "Rename File";
            });
          };
          pathRow.appendChild(renameBtn);
        })(plugin.name, field.name, pathCode);
      }
      fileRow.appendChild(pathRow);

      if (field.details) {
        fileRow.appendChild(el("div", { className: "config-field-details", textContent: field.details }));
      }

      form.appendChild(fileRow);
    });

    return form;
  }

  // -- Generic file editor modal -----------------------------------------

  function openFileEditor(pluginName, fieldName) {
    fetch("/ui/api/plugins/" + encodeURIComponent(pluginName) + "/file/" + encodeURIComponent(fieldName))
      .then(function (resp) { return resp.json(); })
      .then(function (data) {
        showFileEditorModal(pluginName, fieldName, data.path, data.content, data.exists);
      })
      .catch(function (err) {
        Toast.show("Failed to load file", "error");
      });
  }

  function showFileEditorModal(pluginName, fieldName, path, content, exists) {
    var overlay = el("div", { className: "modal-overlay" });
    var card = el("div", { className: "modal-card-wide" });

    var header = el("div", { className: "flex items-center justify-between mb-3" }, [
      el("h3", { textContent: "Edit: " + fieldName }),
      el("button", {
        className: "btn btn-outline btn-sm",
        textContent: "X",
        onClick: function () { close(); },
      }),
    ]);
    card.appendChild(header);

    if (path) {
      card.appendChild(el("div", { className: "text-xs text-muted mb-3", textContent: path }));
    }

    if (!path) {
      card.appendChild(el("div", { className: "text-sm text-secondary mb-3", textContent: "No file path is configured. Set a path in the plugin config first." }));
      var closeBtn = el("button", { className: "btn btn-outline", textContent: "Close" });
      closeBtn.onclick = function () { close(); };
      card.appendChild(closeBtn);
      overlay.appendChild(card);
      document.body.appendChild(overlay);
      function close() { document.body.removeChild(overlay); }
      overlay.onclick = function (e) { if (e.target === overlay) close(); };
      return;
    }

    var defaultContent = exists ? content : "# File: " + fieldName + "\n";

    var textarea = document.createElement("textarea");
    textarea.value = defaultContent;
    textarea.className = "config-textarea";
    textarea.rows = 16;
    textarea.style.width = "100%";
    textarea.spellcheck = false;
    card.appendChild(textarea);

    var footer = el("div", { className: "flex items-center justify-between mt-3" });
    var cancelBtn = el("button", { className: "btn btn-outline", textContent: "Cancel" });
    var saveBtn = el("button", { className: "btn btn-primary", textContent: "Save" });

    function close() { document.body.removeChild(overlay); }

    cancelBtn.onclick = function () { close(); };
    overlay.onclick = function (e) { if (e.target === overlay) close(); };

    textarea.addEventListener("keydown", function (e) {
      if (e.key === "Escape") close();
    });

    saveBtn.onclick = async function () {
      saveBtn.disabled = true;
      saveBtn.textContent = "Saving...";
      try {
        var resp = await fetch("/ui/api/plugins/" + encodeURIComponent(pluginName) + "/file/" + encodeURIComponent(fieldName), {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ content: textarea.value }),
        });
        var result = await resp.json();
        if (resp.ok) {
          Toast.show(result.message || "File saved", "success");
          close();
        } else {
          Toast.show(result.error || "Failed to save", "error");
        }
      } catch (err) {
        Toast.show("Failed to save file", "error");
      }
      saveBtn.disabled = false;
      saveBtn.textContent = "Save";
    };

    footer.appendChild(cancelBtn);
    footer.appendChild(saveBtn);
    card.appendChild(footer);

    overlay.appendChild(card);
    document.body.appendChild(overlay);

    textarea.focus();
  }

  // -- Render all plugins uniformly ---------------------------------------

  // -- Reorder helpers -----------------------------------------------------

  var _currentPlugins = [];

  async function saveOrder() {
    var order = _currentPlugins
      .filter(function (p) { return p.name !== "pre_filter"; })
      .map(function (p) { return p.name; });
    try {
      await fetch("/ui/api/plugins/reorder", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ order: order }),
      });
    } catch (_) { /* best effort */ }
  }

  function movePlugin(index, direction) {
    // pre_filter is always index 0 and cannot be moved
    if (_currentPlugins[index].name === "pre_filter") return;
    var target = index + direction;
    // Can't move before pre_filter (index 0) or past end
    if (target < 1 || target >= _currentPlugins.length) return;
    if (_currentPlugins[target].name === "pre_filter") return;

    var tmp = _currentPlugins[index];
    _currentPlugins[index] = _currentPlugins[target];
    _currentPlugins[target] = tmp;

    container.innerHTML = "";
    container.appendChild(renderPlugins(_currentPlugins));
    saveOrder();
  }

  // -- Render all plugins uniformly ----------------------------------------

  function renderPlugins(allPlugins) {
    _currentPlugins = allPlugins;
    var section = el("div", { className: "mb-4" });

    // Section header with "Plugin Repository" button
    var header = el("div", { className: "section-header mb-3" }, [
      el("div", {}, [
        el("div", { className: "section-title", textContent: "Detection Pipeline" }),
        el("div", { className: "section-subtitle", textContent: "Stages run top-to-bottom. Higher stages have priority — their detections are masked before later stages run." }),
      ]),
    ]);

    var repoBtn = el("button", { className: "btn btn-primary btn-sm", textContent: "\uD83D\uDCE6 Plugin Repository" });
    repoBtn.onclick = showRepositoryModal;
    header.appendChild(repoBtn);
    section.appendChild(header);

    if (!allPlugins || allPlugins.length === 0) {
      section.appendChild(el("div", { className: "empty-state text-sm", textContent: "No plugins loaded" }));
      return section;
    }

    allPlugins.forEach(function (plugin, idx) {
      var card = el("div", { className: "card mb-3" });
      var isUser = plugin.type === "user";
      var isPreFilter = plugin.name === "pre_filter";

      var iconClass = plugin.name === "presidio" ? "anthropic" : (plugin.name === "regex" ? "openai" : "default");

      // Right side: reorder arrows + toggle + badge + optional Edit/Delete
      var toggle = createToggle(plugin);
      var badge = el("span", {
        className: "badge " + (plugin.enabled ? "badge-success" : "badge-neutral"),
        textContent: plugin.enabled ? "Enabled" : "Disabled",
      });

      var rightItems = [];

      // Reorder arrows (not for pre_filter)
      if (!isPreFilter) {
        (function (i) {
          var upBtn = el("button", {
            className: "btn btn-outline btn-sm",
            textContent: "\u25B2",
            title: "Move up (higher priority)",
            style: "padding:2px 6px; font-size:0.7rem; line-height:1;",
          });
          upBtn.onclick = function () { movePlugin(i, -1); };
          if (i <= 1) upBtn.disabled = true; // can't move above pre_filter

          var downBtn = el("button", {
            className: "btn btn-outline btn-sm",
            textContent: "\u25BC",
            title: "Move down (lower priority)",
            style: "padding:2px 6px; font-size:0.7rem; line-height:1;",
          });
          downBtn.onclick = function () { movePlugin(i, 1); };
          if (i >= allPlugins.length - 1) downBtn.disabled = true;

          rightItems.push(upBtn);
          rightItems.push(downBtn);
        })(idx);
      }

      rightItems.push(toggle);
      rightItems.push(badge);

      // Duplicate button (builtin pipeline stages except pre_filter)
      if (!isPreFilter && !isUser) {
        (function (pluginName) {
          var dupBtn = el("button", {
            className: "btn btn-outline btn-sm",
            textContent: "\uD83D\uDCC4 Duplicate",
            title: "Create a copy of this plugin with independent config",
          });
          dupBtn.onclick = async function () {
            dupBtn.disabled = true;
            dupBtn.textContent = "Duplicating...";
            try {
              var resp = await fetch("/ui/api/pipeline/duplicate/" + encodeURIComponent(pluginName), { method: "POST" });
              var data = await resp.json();
              if (resp.ok) {
                Toast.show("Plugin duplicated as '" + data.plugin.name + "'", "success");
                load();
              } else {
                Toast.show(data.error || "Failed to duplicate", "error");
              }
            } catch (err) {
              Toast.show("Failed to duplicate plugin", "error");
            }
            dupBtn.disabled = false;
            dupBtn.textContent = "\uD83D\uDCC4 Duplicate";
          };
          rightItems.push(dupBtn);
        })(plugin.name);
      }

      // Edit Source for user plugins
      if (isUser) {
        (function (pluginName) {
          var editBtn = el("button", {
            className: "btn btn-outline btn-sm",
            textContent: "Edit Source",
          });
          editBtn.onclick = function () { openEditor(pluginName); };
          rightItems.push(editBtn);
        })(plugin.name);
      }

      // Remove from pipeline (all plugins except pre_filter)
      if (!isPreFilter) {
        (function (pluginName, pluginIsUser) {
          var removeBtn = el("button", {
            className: "btn btn-danger btn-sm",
            textContent: "\u2715 Remove",
            title: "Remove from pipeline" + (pluginIsUser ? "" : " (plugin stays in repository)"),
          });
          removeBtn.onclick = function () { confirmRemoveFromPipeline(pluginName); };
          rightItems.push(removeBtn);
        })(plugin.name, isUser);
      }

      // Build name row with inline rename support
      var nameText = el("div", { className: "provider-name", textContent: plugin.display_name || plugin.name });
      var nameContainer = el("div", { className: "flex items-center gap-2" }, [nameText]);

      // Add pencil icon for renaming (not for pre_filter)
      if (!isPreFilter) {
        (function (pluginName, currentDisplayName, nameEl, nameCtr) {
          var pencilBtn = el("button", {
            className: "btn-icon-inline",
            title: "Rename plugin",
            innerHTML: "&#9998;",  // pencil unicode
          });
          pencilBtn.style.cssText = "background:none;border:none;cursor:pointer;opacity:0.5;font-size:0.85rem;padding:2px 4px;";
          pencilBtn.onmouseenter = function () { pencilBtn.style.opacity = "1"; };
          pencilBtn.onmouseleave = function () { pencilBtn.style.opacity = "0.5"; };
          pencilBtn.onclick = function (e) {
            e.stopPropagation();
            // Replace name text with an input
            var input = document.createElement("input");
            input.type = "text";
            input.value = currentDisplayName;
            input.className = "inline-rename-input";
            input.style.cssText = "font-size:inherit;padding:2px 6px;border:1px solid var(--border);border-radius:4px;width:200px;";
            nameEl.replaceWith(input);
            pencilBtn.style.display = "none";
            input.focus();
            input.select();

            var saved = false;
            function saveRename() {
              if (saved) return;
              saved = true;
              var newName = input.value.trim();
              if (!newName || newName === currentDisplayName) {
                // Cancelled — restore original
                input.replaceWith(nameEl);
                pencilBtn.style.display = "";
                return;
              }
              fetch("/ui/api/plugins/" + encodeURIComponent(pluginName) + "/display_name", {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ display_name: newName }),
              }).then(function (resp) {
                return resp.json().then(function (data) {
                  if (resp.ok) {
                    Toast.show("Renamed to \u201c" + newName + "\u201d", "success");
                    loadPlugins();  // Refresh to show new name
                  } else {
                    Toast.show(data.error || "Failed to rename", "error");
                    input.replaceWith(nameEl);
                    pencilBtn.style.display = "";
                  }
                });
              }).catch(function () {
                Toast.show("Failed to rename", "error");
                input.replaceWith(nameEl);
                pencilBtn.style.display = "";
              });
            }

            input.addEventListener("keydown", function (ev) {
              if (ev.key === "Enter") saveRename();
              if (ev.key === "Escape") { saved = true; input.replaceWith(nameEl); pencilBtn.style.display = ""; }
            });
            input.addEventListener("blur", saveRename);
          };
          nameCtr.appendChild(pencilBtn);
        })(plugin.name, plugin.display_name || plugin.name, nameText, nameContainer);
      }

      var row = el("div", { className: "flex items-center justify-between" }, [
        el("div", { className: "flex items-center gap-3" }, [
          el("div", {
            className: "provider-icon " + iconClass,
            textContent: (plugin.display_name || plugin.name || "P")[0].toUpperCase(),
          }),
          el("div", {}, [
            nameContainer,
            el("div", {
              className: "text-xs text-muted",
              textContent: "v" + (plugin.version || "0.0.0") +
                (plugin.type === "builtin" ? " | Built-in" : "") +
                " | Types: " + ((plugin.entity_types || []).join(", ") || "none"),
            }),
          ]),
        ]),
        el("div", { className: "flex items-center gap-3" }, rightItems),
      ]);
      card.appendChild(row);

      if (plugin.description) {
        card.appendChild(el("div", {
          className: "text-sm text-secondary mt-2",
          textContent: plugin.description,
        }));
      }

      // Install-status banner for the OPF plugin (the only built-in
      // detector with an optional ML dependency).  When the 'opf'
      // package is missing, surface an Install button that calls the
      // dedicated install endpoint instead of asking the user to
      // shell out to pip.
      if (plugin.install_status) {
        var status = plugin.install_status;
        var banner = el("div", { className: "plugin-install-banner mt-3" });
        if (!status.package_installed) {
          banner.appendChild(el("div", {
            className: "text-sm",
            textContent:
              "The 'opf' package is not installed.  Click Install to " +
              "fetch ~2GB of torch dependencies; the 1.5GB model " +
              "checkpoint downloads on the first detection request " +
              "after restart.",
          }));
          var installBtn = el("button", {
            className: "btn btn-primary btn-sm mt-2",
            textContent: "Install",
            onClick: async function () {
              installBtn.disabled = true;
              installBtn.textContent = "Installing... (may take several minutes)";
              try {
                var resp = await fetch(status.install_endpoint, { method: "POST" });
                var body = await resp.json();
                if (resp.ok && body.installed) {
                  Toast.show(
                    body.already_installed
                      ? "Already installed."
                      : "Installed.  Restart Scruxy so the plugin loads.",
                    "success",
                  );
                } else {
                  Toast.show(
                    "Install failed: " + (body.error || "unknown error") +
                    "\n" + (body.hint || ""),
                    "error",
                  );
                }
              } catch (e) {
                Toast.show("Install request failed: " + e, "error");
              } finally {
                installBtn.disabled = false;
                installBtn.textContent = "Install";
              }
            },
          });
          banner.appendChild(installBtn);
        } else if (!status.runtime_loaded) {
          banner.appendChild(el("div", {
            className: "text-sm text-muted",
            textContent:
              "Package installed.  Model loads lazily on the first " +
              "detection request after the plugin is enabled (~1.5GB " +
              "checkpoint downloads to ~/.opf/privacy_filter/ on first use).",
          }));
        } else {
          banner.appendChild(el("div", {
            className: "text-sm text-muted",
            textContent: "Package installed and model loaded.",
          }));
        }
        card.appendChild(banner);
      }

      // Collapsible config section (Fix 4)
      if (plugin.config_schema && plugin.config_schema.length > 0) {
        var configContainer = el("div", { className: "plugin-config-collapsible mt-3" });
        var configHeader = el("div", { className: "config-collapse-header", textContent: "Configuration \u25b8" });
        var configBody = el("div", { className: "config-collapse-body hidden" });

        configHeader.onclick = function () {
          var isHidden = configBody.classList.contains("hidden");
          if (isHidden) {
            configBody.classList.remove("hidden");
            configHeader.textContent = "Configuration \u25be";
          } else {
            configBody.classList.add("hidden");
            configHeader.textContent = "Configuration \u25b8";
          }
        };

        var configForm = buildUnifiedForm(plugin);
        if (configForm) configBody.appendChild(configForm);

        configContainer.appendChild(configHeader);
        configContainer.appendChild(configBody);
        card.appendChild(configContainer);
      }

      section.appendChild(card);
    });

    return section;
  }

  // -- Code editor modal --------------------------------------------------

  function openEditor(name) {
    fetch("/ui/api/plugins/" + encodeURIComponent(name) + "/source")
      .then(function (resp) {
        if (!resp.ok) return resp.json().then(function (d) { throw new Error(d.error || "Failed to load source"); });
        return resp.json();
      })
      .then(function (data) {
        showEditorModal(name, data.source);
      })
      .catch(function (err) {
        Toast.show(err.message || "Failed to load plugin source", "error");
      });
  }

  function showEditorModal(name, source) {
    var overlay = el("div", { className: "modal-overlay" });
    var card = el("div", { className: "modal-card-wide" });

    var header = el("div", { className: "flex items-center justify-between mb-3" }, [
      el("h3", { textContent: "Edit Plugin: " + name }),
      el("button", {
        className: "btn btn-outline btn-sm",
        textContent: "X",
        onClick: function () { close(); },
      }),
    ]);
    card.appendChild(header);

    var editorContainer = el("div", { className: "code-editor-container" });

    var textarea = document.createElement("textarea");
    textarea.value = source;
    textarea.spellcheck = false;
    textarea.autocomplete = "off";
    textarea.autocapitalize = "off";

    var pre = document.createElement("pre");
    var code = document.createElement("code");
    code.className = "language-python";
    pre.appendChild(code);

    editorContainer.appendChild(pre);
    editorContainer.appendChild(textarea);
    card.appendChild(editorContainer);

    function syncHighlight() {
      var text = textarea.value;
      if (text[text.length - 1] === "\n") {
        text += " ";
      }
      code.innerHTML = (typeof highlightPython === "function") ? highlightPython(text) : escapeHtml(text);
    }

    syncHighlight();

    textarea.addEventListener("input", syncHighlight);
    textarea.addEventListener("scroll", function () {
      pre.scrollTop = textarea.scrollTop;
      pre.scrollLeft = textarea.scrollLeft;
    });

    textarea.addEventListener("keydown", function (e) {
      if (e.key === "Tab") {
        e.preventDefault();
        var start = textarea.selectionStart;
        var end = textarea.selectionEnd;
        textarea.value = textarea.value.substring(0, start) + "    " + textarea.value.substring(end);
        textarea.selectionStart = textarea.selectionEnd = start + 4;
        syncHighlight();
      }
      if (e.key === "Escape") {
        close();
      }
    });

    var footer = el("div", { className: "flex items-center justify-between mt-3" });
    var cancelBtn = el("button", { className: "btn btn-outline", textContent: "Cancel" });
    var saveBtn = el("button", { className: "btn btn-primary", textContent: "Save" });

    cancelBtn.onclick = function () { close(); };
    saveBtn.onclick = async function () {
      saveBtn.disabled = true;
      saveBtn.textContent = "Saving...";
      try {
        var resp = await fetch("/ui/api/plugins/" + encodeURIComponent(name) + "/source", {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ source: textarea.value }),
        });
        var result = await resp.json();
        if (resp.ok) {
          Toast.show(result.message || "Plugin saved", "success");
          close();
        } else {
          Toast.show(result.error || "Failed to save", "error");
        }
      } catch (err) {
        Toast.show("Failed to save plugin source", "error");
      }
      saveBtn.disabled = false;
      saveBtn.textContent = "Save";
    };

    footer.appendChild(cancelBtn);
    footer.appendChild(saveBtn);
    card.appendChild(footer);

    overlay.appendChild(card);
    document.body.appendChild(overlay);

    textarea.focus();

    function close() { document.body.removeChild(overlay); }
    overlay.onclick = function (e) { if (e.target === overlay) close(); };
  }

  // -- Delete confirmation modal -----------------------------------------

  function confirmDelete(name) {
    var overlay = el("div", { className: "modal-overlay" });
    var card = el("div", { className: "modal-card" }, [
      el("h3", { textContent: "Delete Plugin", style: "margin-bottom: 16px" }),
      el("p", { className: "text-sm text-secondary mb-3", textContent: "Are you sure you want to delete plugin '" + name + "'? This action cannot be undone." }),
    ]);

    var btnRow = el("div", { className: "flex items-center justify-between" });
    var cancelBtn = el("button", { className: "btn btn-outline", textContent: "Cancel" });
    var deleteBtn = el("button", { className: "btn btn-danger", textContent: "Delete" });

    function close() { document.body.removeChild(overlay); }

    cancelBtn.onclick = close;
    overlay.onclick = function (e) { if (e.target === overlay) close(); };

    deleteBtn.onclick = async function () {
      deleteBtn.disabled = true;
      deleteBtn.textContent = "Deleting...";
      try {
        var resp = await fetch("/ui/api/plugins/" + encodeURIComponent(name), {
          method: "DELETE",
        });
        var result = await resp.json();
        if (resp.ok) {
          close();
          Toast.show(result.message || "Plugin deleted", "success");
          load();
        } else {
          Toast.show(result.error || "Failed to delete", "error");
          deleteBtn.disabled = false;
          deleteBtn.textContent = "Delete";
        }
      } catch (err) {
        Toast.show("Failed to delete plugin", "error");
        deleteBtn.disabled = false;
        deleteBtn.textContent = "Delete";
      }
    };

    btnRow.appendChild(cancelBtn);
    btnRow.appendChild(deleteBtn);
    card.appendChild(btnRow);
    overlay.appendChild(card);
    document.body.appendChild(overlay);
  }

  // -- Remove from pipeline confirmation modal ----------------------------

  function confirmRemoveFromPipeline(name) {
    var overlay = el("div", { className: "modal-overlay" });
    var card = el("div", { className: "modal-card" }, [
      el("h3", { textContent: "Remove from Pipeline", style: "margin-bottom: 16px" }),
      el("p", {
        className: "text-sm text-secondary mb-3",
        textContent: "Remove '" + name + "' from the active pipeline? You can re-add it later from the Plugin Repository.",
      }),
    ]);

    var btnRow = el("div", { className: "flex items-center justify-between" });
    var cancelBtn = el("button", { className: "btn btn-outline", textContent: "Cancel" });
    var removeBtn = el("button", { className: "btn btn-danger", textContent: "Remove" });

    function close() { document.body.removeChild(overlay); }

    cancelBtn.onclick = close;
    overlay.onclick = function (e) { if (e.target === overlay) close(); };

    removeBtn.onclick = async function () {
      removeBtn.disabled = true;
      removeBtn.textContent = "Removing...";
      try {
        var resp = await fetch("/ui/api/pipeline/" + encodeURIComponent(name), { method: "DELETE" });
        var data = await resp.json();
        if (resp.ok) {
          close();
          Toast.show(data.message || "Plugin removed from pipeline", "success");
          load();
        } else {
          Toast.show(data.error || "Failed to remove", "error");
          removeBtn.disabled = false;
          removeBtn.textContent = "Remove";
        }
      } catch (err) {
        Toast.show("Failed to remove plugin", "error");
        removeBtn.disabled = false;
        removeBtn.textContent = "Remove";
      }
    };

    btnRow.appendChild(cancelBtn);
    btnRow.appendChild(removeBtn);
    card.appendChild(btnRow);
    overlay.appendChild(card);
    document.body.appendChild(overlay);
  }

  // -- Plugin Repository modal -------------------------------------------

  function showRepositoryModal() {
    var overlay = el("div", { className: "modal-overlay" });
    var card = el("div", { className: "modal-card-wide" });
    card.style.maxWidth = "700px";

    var header = el("div", { className: "flex items-center justify-between mb-3" }, [
      el("h3", { textContent: "\uD83D\uDCE6 Plugin Repository" }),
      el("button", {
        className: "btn btn-outline btn-sm",
        textContent: "\u2715",
        onclick: function () { close(); },
      }),
    ]);
    card.appendChild(header);
    card.appendChild(el("div", {
      className: "text-sm text-secondary mb-3",
      textContent: "Browse available plugin types and add them to your pipeline. Each plugin can have multiple independent instances.",
    }));

    var listContainer = el("div", { style: "max-height: 55vh; overflow-y: auto;" });
    var loading = el("div", { className: "text-sm text-muted", textContent: "Loading plugins..." });
    listContainer.appendChild(loading);
    card.appendChild(listContainer);

    // Footer with "Create New Plugin" button
    var footer = el("div", { className: "flex items-center justify-between mt-3", style: "border-top: 1px solid var(--border-color); padding-top: 12px;" });
    var newPluginBtn = el("button", { className: "btn btn-primary btn-sm", textContent: "+ Create New Plugin" });
    newPluginBtn.onclick = function () {
      close();
      showCreateModal();
    };
    footer.appendChild(el("div", { className: "text-xs text-muted", textContent: "Can't find what you need?" }));
    footer.appendChild(newPluginBtn);
    card.appendChild(footer);

    overlay.appendChild(card);
    document.body.appendChild(overlay);

    function close() { document.body.removeChild(overlay); }
    overlay.onclick = function (e) { if (e.target === overlay) close(); };

    // Fetch repository data
    fetchRepository();

    async function fetchRepository() {
      try {
        var resp = await fetch("/ui/api/plugin-repository");
        var data = await resp.json();
        if (!resp.ok) throw new Error(data.error || "Failed to load");
        renderRepositoryList(data.plugins || []);
      } catch (err) {
        listContainer.innerHTML = "";
        listContainer.appendChild(el("div", { className: "text-sm text-danger", textContent: "Failed to load repository: " + err.message }));
      }
    }

    function renderRepositoryList(plugins) {
      listContainer.innerHTML = "";
      if (plugins.length === 0) {
        listContainer.appendChild(el("div", { className: "empty-state text-sm", textContent: "No plugins available" }));
        return;
      }

      plugins.forEach(function (plugin) {
        var item = el("div", {
          className: "card mb-2",
          style: "padding: 12px;",
        });

        var iconLetter = (plugin.display_name || plugin.name || "P")[0].toUpperCase();
        var iconClass = plugin.name === "presidio" ? "anthropic" : (plugin.name === "regex" ? "openai" : "default");

        var inPipeline = plugin.instances_in_pipeline || 0;
        var countBadge = inPipeline > 0
          ? el("span", { className: "badge badge-success", textContent: inPipeline + " in pipeline", style: "font-size: 0.65rem;" })
          : el("span", { className: "badge badge-neutral", textContent: "Not in pipeline", style: "font-size: 0.65rem;" });

        var typeBadge = el("span", {
          className: "badge " + (plugin.type === "builtin" ? "badge-info" : "badge-neutral"),
          textContent: plugin.type === "builtin" ? "Built-in" : "User",
          style: "font-size: 0.65rem; margin-left: 4px;",
        });

        var addBtn = el("button", {
          className: "btn btn-primary btn-sm",
          textContent: plugin.type === "builtin" ? "+ Add to Pipeline" : "Available via Plugins stage",
        });
        if (plugin.type === "builtin") {
          addBtn.onclick = function () { promptAddToPipeline(plugin, addBtn); };
        } else {
          addBtn.disabled = true;
          addBtn.title = "User plugins are managed through the shared Plugins stage";
        }

        var row = el("div", { className: "flex items-center justify-between" }, [
          el("div", { className: "flex items-center gap-3" }, [
            el("div", { className: "provider-icon " + iconClass, textContent: iconLetter }),
            el("div", {}, [
              el("div", { className: "provider-name", style: "font-size: 0.9rem;", textContent: plugin.display_name || plugin.name }),
              el("div", { className: "flex items-center gap-2 mt-1" }, [countBadge, typeBadge]),
            ]),
          ]),
          addBtn,
        ]);
        item.appendChild(row);

        if (plugin.description) {
          item.appendChild(el("div", {
            className: "text-xs text-secondary mt-2",
            textContent: plugin.description,
          }));
        }

        listContainer.appendChild(item);
      });
    }

    function promptAddToPipeline(plugin, btn) {
      // Generate a default instance name
      var baseName = plugin.name;
      var existingNames = _currentPlugins.map(function (p) { return p.name; });
      var instanceName = baseName;
      var counter = 2;
      while (existingNames.indexOf(instanceName) !== -1) {
        instanceName = baseName + "_" + counter;
        counter++;
      }

      // Show inline name input
      var nameInput = document.createElement("input");
      nameInput.type = "text";
      nameInput.value = instanceName;
      nameInput.className = "w-full";
      nameInput.style.cssText = "font-size: 0.8rem; padding: 4px 8px; margin-top: 8px;";
      nameInput.placeholder = "Instance name";

      var confirmBtn = el("button", { className: "btn btn-primary btn-sm", textContent: "Confirm", style: "margin-top: 8px; margin-left: 8px;" });
      var cancelAddBtn = el("button", { className: "btn btn-outline btn-sm", textContent: "Cancel", style: "margin-top: 8px; margin-left: 4px;" });

      var addRow = el("div", { className: "flex items-center", style: "flex-wrap: wrap;" }, [nameInput, confirmBtn, cancelAddBtn]);

      btn.parentNode.appendChild(addRow);
      btn.style.display = "none";
      nameInput.focus();
      nameInput.select();

      function cancelAdd() {
        addRow.remove();
        btn.style.display = "";
      }

      cancelAddBtn.onclick = cancelAdd;
      nameInput.onkeydown = function (e) {
        if (e.key === "Enter") doAdd();
        if (e.key === "Escape") cancelAdd();
      };

      async function doAdd() {
        var name = nameInput.value.trim();
        if (!name) return;
        confirmBtn.disabled = true;
        confirmBtn.textContent = "Adding...";
        try {
          var resp = await fetch("/ui/api/pipeline/add", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ plugin_name: plugin.name, instance_name: name, config: {} }),
          });
          var data = await resp.json();
          if (resp.ok) {
            Toast.show("'" + name + "' added to pipeline", "success");
            close();
            load();
          } else {
            Toast.show(data.error || "Failed to add", "error");
            confirmBtn.disabled = false;
            confirmBtn.textContent = "Confirm";
          }
        } catch (err) {
          Toast.show("Failed to add plugin", "error");
          confirmBtn.disabled = false;
          confirmBtn.textContent = "Confirm";
        }
      }

      confirmBtn.onclick = doAdd;
    }
  }

  // -- Create new plugin modal -------------------------------------------

  function showCreateModal() {
    var overlay = el("div", { className: "modal-overlay" });
    var card = el("div", { className: "modal-card" }, [
      el("h3", { textContent: "Create New Plugin", style: "margin-bottom: 16px" }),
    ]);

    var input = document.createElement("input");
    input.type = "text";
    input.placeholder = "my_detector";
    input.className = "w-full";
    input.style.marginBottom = "16px";

    var hint = el("div", { className: "text-xs text-muted mb-3", textContent: "Name must start with a letter and contain only letters, digits, and underscores." });

    var errorMsg = el("div", { className: "text-sm text-danger mb-3", style: "display: none" });

    var btnRow = el("div", { className: "flex items-center justify-between" });
    var cancelBtn = el("button", { className: "btn btn-outline", textContent: "Cancel" });
    var createBtn = el("button", { className: "btn btn-primary", textContent: "Create" });
    btnRow.appendChild(cancelBtn);
    btnRow.appendChild(createBtn);

    card.appendChild(input);
    card.appendChild(hint);
    card.appendChild(errorMsg);
    card.appendChild(btnRow);
    overlay.appendChild(card);
    document.body.appendChild(overlay);

    input.focus();

    function close() { document.body.removeChild(overlay); }

    cancelBtn.onclick = close;
    overlay.onclick = function(e) { if (e.target === overlay) close(); };

    input.onkeydown = function(e) {
      if (e.key === "Enter") doCreate();
      if (e.key === "Escape") close();
    };

    function showError(msg) {
      errorMsg.textContent = msg;
      errorMsg.style.display = "block";
      createBtn.disabled = false;
      createBtn.textContent = "Create";
    }

    async function doCreate() {
      var name = input.value.trim();
      if (!name) return;

      errorMsg.style.display = "none";
      createBtn.disabled = true;
      createBtn.textContent = "Creating...";

      try {
        var resp = await fetch("/ui/api/plugins/create", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: name }),
        });
        var data = await resp.json();

        if (resp.ok) {
          close();
          Toast.show(data.message || "Plugin created!", "success");
          load();
        } else {
          showError(data.error || "Failed to create plugin");
        }
      } catch (err) {
        showError("Network error: " + err.message);
      }
    }

    createBtn.onclick = doCreate;
  }

  // -- Replacement Rules -------------------------------------------------

  function strategyBadgeClass(strategy) {
    switch (strategy) {
      case "uuid":    return "badge-info";
      case "script":  return "badge-warning";
      default:        return "badge-neutral";
    }
  }

  /** Create a toggle switch for a replacement rule. */
  function createReplacementToggle(entityType, rule) {
    var isEnabled = rule.enabled !== false; // default true
    var label = el("label", { className: "toggle" });
    var input = document.createElement("input");
    input.type = "checkbox";
    input.checked = isEnabled;
    var slider = el("span", { className: "toggle-slider" });
    label.appendChild(input);
    label.appendChild(slider);

    input.onchange = async function () {
      var newEnabled = input.checked;
      try {
        var resp = await fetch("/ui/api/replacements/" + encodeURIComponent(entityType) + "/toggle", {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ enabled: newEnabled }),
        });
        var data = await resp.json();
        if (resp.ok) {
          // Update the status badge in the same row
          var row = input.closest("tr");
          if (row) {
            var statusBadge = row.querySelector(".replacement-status-badge");
            if (statusBadge) {
              statusBadge.textContent = newEnabled ? "Enabled" : "Disabled";
              statusBadge.className = "badge replacement-status-badge " + (newEnabled ? "badge-success" : "badge-neutral");
            }
          }
          Toast.show("Replacement '" + entityType + "' " + (newEnabled ? "enabled" : "disabled"), "success");
        } else {
          input.checked = !newEnabled;
          Toast.show(data.error || "Failed to toggle replacement rule", "error");
        }
      } catch (err) {
        input.checked = !newEnabled;
        Toast.show("Failed to toggle replacement rule", "error");
      }
    };

    return label;
  }

  function renderReplacementRules(rules) {
    var section = document.getElementById("replacement-rules-section");
    if (!section) return;
    section.innerHTML = "";

    var header = el("div", { className: "section-header mb-3 mt-4" }, [
      el("div", {}, [
        el("div", { className: "section-title", textContent: "Replacement Rules" }),
        el("div", { className: "section-subtitle", textContent: "Per-entity-type token generation strategy (default, uuid, or script)" }),
      ]),
    ]);
    var addBtn = el("button", { className: "btn btn-primary btn-sm", textContent: "+ Add Rule" });
    addBtn.onclick = function () { showReplacementFormModal(null, null); };
    header.appendChild(addBtn);
    section.appendChild(header);

    var card = el("div", { className: "card" });
    var entries = Object.entries(rules || {});

    if (entries.length === 0) {
      card.appendChild(
        el("div", { className: "empty-state text-sm", textContent: "No replacement rules configured. Click \"+ Add Rule\" to create one." })
      );
      section.appendChild(card);
      return;
    }

    var table = el("table", { className: "data-table w-full" });
    var thead = el("thead", {}, [
      el("tr", {}, [
        el("th", { textContent: "Entity Type" }),
        el("th", { textContent: "Strategy" }),
        el("th", { textContent: "Command" }),
        el("th", { textContent: "Timeout" }),
        el("th", { textContent: "", style: "text-align: right" }),
      ]),
    ]);
    table.appendChild(thead);

    var tbody = el("tbody");
    entries.forEach(function (pair) {
      var entityType = pair[0];
      var rule = pair[1];
      var strategy = rule.strategy || "default";
      var isEnabled = rule.enabled !== false;

      var row = el("tr", {}, [
        el("td", {}, [el("code", { textContent: entityType })]),
        el("td", {}, [
          el("span", {
            className: "badge " + strategyBadgeClass(strategy),
            textContent: strategy,
          }),
        ]),
        el("td", {
          className: "text-xs mono",
          textContent: strategy === "script" ? (rule.command || "--") : "--",
        }),
        el("td", {
          className: "text-xs",
          textContent: strategy === "script" ? (rule.timeout_ms || 5000) + "ms" : "--",
        }),
        el("td", { style: "text-align: right" }, [
          el("button", {
            className: "btn btn-outline btn-sm",
            textContent: "Edit",
            onClick: function () { showReplacementFormModal(entityType, rule); },
          }),
          el("button", {
            className: "btn btn-danger btn-sm",
            textContent: "Delete",
            style: "margin-left: 6px",
            onClick: function () { deleteReplacement(entityType); },
          }),
          createReplacementToggle(entityType, rule),
          el("span", {
            className: "badge replacement-status-badge " + (isEnabled ? "badge-success" : "badge-neutral"),
            textContent: isEnabled ? "Enabled" : "Disabled",
            style: "margin-left: 6px",
          }),
        ]),
      ]);
      tbody.appendChild(row);
    });
    table.appendChild(tbody);
    card.appendChild(table);
    section.appendChild(card);
  }

  function showReplacementFormModal(entityType, rule) {
    var isNew = !entityType;
    var overlay = el("div", { className: "modal-overlay" });
    var card = el("div", { className: "modal-card" });

    card.appendChild(el("h3", {
      textContent: isNew ? "Add Replacement Rule" : "Edit Replacement Rule",
      style: "margin-bottom: 16px",
    }));

    var typeInput = document.createElement("input");
    typeInput.type = "text";
    typeInput.value = entityType || "";
    typeInput.placeholder = "e.g. PERSON, EMAIL_ADDRESS, GUID";
    typeInput.className = "w-full";
    if (!isNew) typeInput.disabled = true;

    card.appendChild(el("div", { className: "form-group" }, [
      el("label", { textContent: "Entity Type" }),
      typeInput,
    ]));

    var stratSelect = document.createElement("select");
    stratSelect.className = "w-full";
    ["default", "uuid", "script"].forEach(function (opt) {
      var o = document.createElement("option");
      o.value = opt;
      o.textContent = opt;
      if ((rule && rule.strategy) === opt || (!rule && opt === "default")) o.selected = true;
      stratSelect.appendChild(o);
    });
    card.appendChild(el("div", { className: "form-group" }, [
      el("label", { textContent: "Strategy" }),
      stratSelect,
    ]));

    var scriptSection = el("div", { className: "form-group" });
    var cmdInput = document.createElement("input");
    cmdInput.type = "text";
    cmdInput.value = (rule && rule.command) || "";
    cmdInput.placeholder = "python ~/.scruxy/scripts/simple_name.py";
    cmdInput.className = "w-full";

    var browseBtn = el("button", {
      className: "btn btn-outline btn-sm",
      textContent: "Browse Scripts",
      style: "margin-top: 6px",
      onClick: function () {
        showScriptPicker(function (selectedName) {
          cmdInput.value = "python ~/.scruxy/scripts/" + selectedName;
        });
      },
    });

    var timeoutInput = document.createElement("input");
    timeoutInput.type = "number";
    timeoutInput.value = (rule && rule.timeout_ms) || "5000";
    timeoutInput.style.width = "120px";

    scriptSection.appendChild(el("label", { textContent: "Script Command" }));
    scriptSection.appendChild(cmdInput);
    scriptSection.appendChild(browseBtn);
    scriptSection.appendChild(el("div", { className: "form-group", style: "margin-top: 12px" }, [
      el("label", { textContent: "Timeout (ms)" }),
      timeoutInput,
    ]));
    card.appendChild(scriptSection);

    function updateScriptVisibility() {
      scriptSection.style.display = stratSelect.value === "script" ? "block" : "none";
    }
    stratSelect.addEventListener("change", updateScriptVisibility);
    updateScriptVisibility();

    var btnRow = el("div", { className: "flex items-center justify-between", style: "margin-top: 16px" });
    var cancelBtn = el("button", { className: "btn btn-outline", textContent: "Cancel" });
    var saveBtn = el("button", { className: "btn btn-primary", textContent: "Save Rule" });

    function close() { document.body.removeChild(overlay); }
    cancelBtn.onclick = close;
    overlay.onclick = function (e) { if (e.target === overlay) close(); };

    saveBtn.onclick = async function () {
      var type = typeInput.value.trim().toUpperCase();
      if (!type) { Toast.show("Entity type is required", "warning"); return; }

      var strat = stratSelect.value;
      var ruleObj = { strategy: strat };
      if (strat === "script") {
        var cmd = cmdInput.value.trim();
        if (!cmd) { Toast.show("Script command is required", "warning"); return; }
        ruleObj.command = cmd;
        ruleObj.timeout_ms = parseInt(timeoutInput.value, 10) || 5000;
      }

      var replacements = {};
      replacements[type] = ruleObj;

      saveBtn.disabled = true;
      saveBtn.textContent = "Saving...";
      try {
        var result = await apiFetch("/ui/api/config", {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ tokens: { replacements: replacements } }),
        });
        renderReplacementRules((result.tokens || {}).replacements || {});
        Toast.show("Replacement rule saved.", "success");
        close();
      } catch (_) { /* apiFetch shows toast */ }
      saveBtn.disabled = false;
      saveBtn.textContent = "Save Rule";
    };

    btnRow.appendChild(cancelBtn);
    btnRow.appendChild(saveBtn);
    card.appendChild(btnRow);
    overlay.appendChild(card);
    document.body.appendChild(overlay);
    if (isNew) typeInput.focus();
  }

  async function deleteReplacement(entityType) {
    if (!confirm("Delete replacement rule for '" + entityType + "'?")) return;
    var replacements = {};
    replacements[entityType] = null;
    try {
      var result = await apiFetch("/ui/api/config", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tokens: { replacements: replacements } }),
      });
      renderReplacementRules((result.tokens || {}).replacements || {});
      Toast.show("Replacement rule deleted.", "success");
    } catch (_) { /* apiFetch shows toast */ }
  }

  function showScriptPicker(onSelect) {
    var overlay = el("div", { className: "modal-overlay" });
    var card = el("div", { className: "modal-card" });
    card.appendChild(el("h3", { textContent: "Select Script", style: "margin-bottom: 16px" }));

    var listContainer = el("div", { className: "mb-3", style: "max-height: 300px; overflow-y: auto" });
    listContainer.appendChild(el("div", { className: "empty-state text-sm", textContent: "Loading..." }));
    card.appendChild(listContainer);

    function close() { document.body.removeChild(overlay); }

    var btnRow = el("div", { className: "flex items-center justify-between" });
    var cancelBtn = el("button", { className: "btn btn-outline", textContent: "Cancel" });
    var createBtn = el("button", { className: "btn btn-primary btn-sm", textContent: "+ New Script" });
    cancelBtn.onclick = close;
    overlay.onclick = function (e) { if (e.target === overlay) close(); };
    createBtn.onclick = function () {
      showCreateScriptModal(function () { close(); showScriptPicker(onSelect); });
    };
    btnRow.appendChild(cancelBtn);
    btnRow.appendChild(createBtn);
    card.appendChild(btnRow);
    overlay.appendChild(card);
    document.body.appendChild(overlay);

    apiFetch("/ui/api/scripts").then(function (data) {
      var scripts = data.scripts || [];
      listContainer.innerHTML = "";
      if (scripts.length === 0) {
        listContainer.appendChild(el("div", { className: "empty-state text-sm", textContent: "No scripts found." }));
        return;
      }
      scripts.forEach(function (name) {
        listContainer.appendChild(el("div", { className: "flex items-center justify-between", style: "padding: 6px 0; border-bottom: 1px solid var(--border-color)" }, [
          el("code", { className: "text-sm", textContent: name }),
          el("div", { className: "flex items-center gap-2" }, [
            el("button", { className: "btn btn-outline btn-sm", textContent: "Edit", onClick: function () { showScriptEditorModal(name); } }),
            el("button", { className: "btn btn-primary btn-sm", textContent: "Select", onClick: function () { onSelect(name); close(); } }),
          ]),
        ]));
      });
    }).catch(function () {
      listContainer.innerHTML = '<div class="empty-state text-sm">Failed to load scripts</div>';
    });
  }

  function showScriptEditorModal(name) {
    apiFetch("/ui/api/scripts/" + encodeURIComponent(name)).then(function (data) {
      _openScriptEditor(name, data.content);
    }).catch(function () { Toast.show("Failed to load script", "error"); });
  }

  function _openScriptEditor(name, content) {
    var overlay = el("div", { className: "modal-overlay" });
    var card = el("div", { className: "modal-card-wide" });
    card.appendChild(el("div", { className: "flex items-center justify-between mb-3" }, [
      el("h3", { textContent: "Edit Script: " + name }),
      el("button", { className: "btn btn-outline btn-sm", textContent: "X", onClick: function () { close(); } }),
    ]));

    var textarea = document.createElement("textarea");
    textarea.value = content;
    textarea.className = "config-textarea";
    textarea.rows = 20;
    textarea.style.width = "100%";
    textarea.style.fontFamily = "monospace";
    textarea.spellcheck = false;
    card.appendChild(textarea);

    textarea.addEventListener("keydown", function (e) {
      if (e.key === "Tab") {
        e.preventDefault();
        var start = textarea.selectionStart;
        var end = textarea.selectionEnd;
        textarea.value = textarea.value.substring(0, start) + "    " + textarea.value.substring(end);
        textarea.selectionStart = textarea.selectionEnd = start + 4;
      }
      if (e.key === "Escape") close();
    });

    var footer = el("div", { className: "flex items-center justify-between mt-3" });
    var cancelBtn = el("button", { className: "btn btn-outline", textContent: "Cancel" });
    var saveBtn = el("button", { className: "btn btn-primary", textContent: "Save" });
    function close() { document.body.removeChild(overlay); }
    cancelBtn.onclick = close;
    overlay.onclick = function (e) { if (e.target === overlay) close(); };
    saveBtn.onclick = async function () {
      saveBtn.disabled = true;
      saveBtn.textContent = "Saving...";
      try {
        await apiFetch("/ui/api/scripts/" + encodeURIComponent(name), {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ content: textarea.value }),
        });
        Toast.show("Script saved.", "success");
        close();
      } catch (_) { /* apiFetch shows toast */ }
      saveBtn.disabled = false;
      saveBtn.textContent = "Save";
    };
    footer.appendChild(cancelBtn);
    footer.appendChild(saveBtn);
    card.appendChild(footer);
    overlay.appendChild(card);
    document.body.appendChild(overlay);
    textarea.focus();
  }

  function showCreateScriptModal(callback) {
    var overlay = el("div", { className: "modal-overlay" });
    var card = el("div", { className: "modal-card" }, [
      el("h3", { textContent: "Create New Script", style: "margin-bottom: 16px" }),
    ]);

    var nameInput = document.createElement("input");
    nameInput.type = "text";
    nameInput.placeholder = "my_replacement.py";
    nameInput.className = "w-full";
    nameInput.style.marginBottom = "16px";
    card.appendChild(nameInput);
    card.appendChild(el("div", { className: "text-xs text-muted mb-3", textContent: "Name must end with .py and contain only letters, digits, underscores, hyphens, and dots." }));

    var errorMsg = el("div", { className: "text-sm text-danger mb-3", style: "display: none" });
    card.appendChild(errorMsg);

    var btnRow = el("div", { className: "flex items-center justify-between" });
    var cancelBtn = el("button", { className: "btn btn-outline", textContent: "Cancel" });
    var createBtn = el("button", { className: "btn btn-primary", textContent: "Create" });
    function close() { document.body.removeChild(overlay); }
    cancelBtn.onclick = close;
    overlay.onclick = function (e) { if (e.target === overlay) close(); };
    nameInput.onkeydown = function (e) { if (e.key === "Enter") doCreate(); if (e.key === "Escape") close(); };

    async function doCreate() {
      var name = nameInput.value.trim();
      if (!name) return;
      errorMsg.style.display = "none";
      createBtn.disabled = true;
      createBtn.textContent = "Creating...";
      try {
        var resp = await fetch("/ui/api/scripts", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: name }),
        });
        var data = await resp.json();
        if (resp.ok) {
          Toast.show(data.message || "Script created!", "success");
          close();
          var finalName = data.name || name;
          if (!finalName.endsWith(".py")) finalName += ".py";
          showScriptEditorModal(finalName);
          if (callback) callback(finalName);
        } else {
          errorMsg.textContent = data.error || "Failed to create script";
          errorMsg.style.display = "block";
        }
      } catch (err) {
        errorMsg.textContent = "Network error: " + err.message;
        errorMsg.style.display = "block";
      }
      createBtn.disabled = false;
      createBtn.textContent = "Create";
    }

    createBtn.onclick = doCreate;
    btnRow.appendChild(cancelBtn);
    btnRow.appendChild(createBtn);
    card.appendChild(btnRow);
    overlay.appendChild(card);
    document.body.appendChild(overlay);
    nameInput.focus();
  }

  // -- Load data ---------------------------------------------------------

  async function load() {
    try {
      var [pluginData, configData] = await Promise.all([
        apiFetch("/ui/api/plugins"),
        apiFetch("/ui/api/config"),
      ]);

      var allPlugins = pluginData.plugins || [];
      container.innerHTML = "";
      container.appendChild(renderPlugins(allPlugins));

      renderReplacementRules((configData.tokens || {}).replacements || {});
    } catch (_) {
      container.innerHTML = '<div class="empty-state text-sm">Failed to load plugins</div>';
    }
  }

  load();
})();
