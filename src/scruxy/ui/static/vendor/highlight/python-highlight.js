/* ===================================================================
   Lightweight Python syntax highlighter for Scruxy plugin editor.
   No external dependencies. Returns HTML with span classes for styling.
   =================================================================== */

"use strict";

var highlightPython = (function () {
  // Python keywords
  var KEYWORDS = new Set([
    "False", "None", "True", "and", "as", "assert", "async", "await",
    "break", "class", "continue", "def", "del", "elif", "else", "except",
    "finally", "for", "from", "global", "if", "import", "in", "is",
    "lambda", "nonlocal", "not", "or", "pass", "raise", "return",
    "try", "while", "with", "yield",
  ]);

  // Python builtins
  var BUILTINS = new Set([
    "print", "len", "range", "int", "str", "float", "list", "dict",
    "set", "tuple", "bool", "type", "isinstance", "hasattr", "getattr",
    "setattr", "super", "property", "staticmethod", "classmethod",
    "enumerate", "zip", "map", "filter", "sorted", "reversed",
    "any", "all", "min", "max", "sum", "abs", "round", "open",
    "ValueError", "TypeError", "KeyError", "IndexError", "AttributeError",
    "RuntimeError", "Exception", "StopIteration", "NotImplementedError",
    "self",
  ]);

  function escapeHtml(text) {
    return text
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function highlight(code) {
    var result = [];
    var i = 0;
    var len = code.length;

    while (i < len) {
      var ch = code[i];

      // Triple-quoted strings (""" or ''')
      if ((code.slice(i, i + 3) === '"""' || code.slice(i, i + 3) === "'''")) {
        var quote = code.slice(i, i + 3);
        var end = code.indexOf(quote, i + 3);
        if (end === -1) end = len - 3;
        var s = code.slice(i, end + 3);
        result.push('<span class="py-str">' + escapeHtml(s) + "</span>");
        i = end + 3;
        continue;
      }

      // Single/double quoted strings
      if (ch === '"' || ch === "'") {
        var q = ch;
        var j = i + 1;
        while (j < len && code[j] !== q) {
          if (code[j] === "\\") j++; // skip escaped char
          j++;
        }
        var s = code.slice(i, j + 1);
        result.push('<span class="py-str">' + escapeHtml(s) + "</span>");
        i = j + 1;
        continue;
      }

      // Comments
      if (ch === "#") {
        var end = code.indexOf("\n", i);
        if (end === -1) end = len;
        var s = code.slice(i, end);
        result.push('<span class="py-cmt">' + escapeHtml(s) + "</span>");
        i = end;
        continue;
      }

      // Decorators
      if (ch === "@" && (i === 0 || code[i - 1] === "\n")) {
        var end = code.indexOf("\n", i);
        if (end === -1) end = len;
        // Find end of decorator name (stop at parenthesis or newline)
        var paren = code.indexOf("(", i);
        var decEnd = (paren !== -1 && paren < end) ? paren : end;
        var s = code.slice(i, decEnd);
        result.push('<span class="py-dec">' + escapeHtml(s) + "</span>");
        i = decEnd;
        continue;
      }

      // Numbers (int/float, including 0x, 0b, 0o prefixes)
      if (/[0-9]/.test(ch) || (ch === "." && i + 1 < len && /[0-9]/.test(code[i + 1]))) {
        var j = i;
        if (ch === "0" && i + 1 < len && /[xXbBoO]/.test(code[i + 1])) {
          j += 2;
          while (j < len && /[0-9a-fA-F_]/.test(code[j])) j++;
        } else {
          while (j < len && /[0-9_.]/.test(code[j])) j++;
          if (j < len && /[eE]/.test(code[j])) {
            j++;
            if (j < len && /[+-]/.test(code[j])) j++;
            while (j < len && /[0-9_]/.test(code[j])) j++;
          }
        }
        // Don't highlight if preceded by a letter (e.g. part of identifier)
        if (i > 0 && /[a-zA-Z_]/.test(code[i - 1])) {
          result.push(escapeHtml(code[i]));
          i++;
          continue;
        }
        result.push('<span class="py-num">' + escapeHtml(code.slice(i, j)) + "</span>");
        i = j;
        continue;
      }

      // Identifiers / keywords / builtins
      if (/[a-zA-Z_]/.test(ch)) {
        var j = i;
        while (j < len && /[a-zA-Z0-9_]/.test(code[j])) j++;
        var word = code.slice(i, j);
        if (KEYWORDS.has(word)) {
          result.push('<span class="py-kw">' + escapeHtml(word) + "</span>");
        } else if (BUILTINS.has(word)) {
          result.push('<span class="py-bi">' + escapeHtml(word) + "</span>");
        } else {
          result.push(escapeHtml(word));
        }
        i = j;
        continue;
      }

      // Default: output character as-is
      result.push(escapeHtml(ch));
      i++;
    }

    return result.join("");
  }

  return highlight;
})();
