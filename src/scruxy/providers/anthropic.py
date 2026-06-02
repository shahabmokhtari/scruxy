"""Anthropic Claude provider with format-specific content block handling."""
from __future__ import annotations

import copy
import logging
import re
from pathlib import Path
from typing import Any

import yaml

from scruxy.providers.base import ProxyRequest, SSETextField, TextField
from scruxy.providers.yaml_provider import YAMLProvider


logger = logging.getLogger(__name__)


_DEFAULT_CONFIG_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "default_config"
    / "providers"
    / "anthropic.yaml"
)


def _load_default_config() -> dict[str, Any]:
    """Load the default Anthropic YAML config from the package."""
    with open(_DEFAULT_CONFIG_PATH) as f:
        return yaml.safe_load(f)


class AnthropicProvider(YAMLProvider):
    """Provider for Anthropic Claude API.

    Extends YAMLProvider with Anthropic-specific handling for content blocks.
    Anthropic messages can contain:
    - Simple string content: {"role": "user", "content": "Hello"}
    - Content block arrays: {"role": "user", "content": [{"type": "text", "text": "Hello"}]}
    - Tool results with nested content
    """

    # Regex to extract session portion from Claude's compound metadata.user_id
    _SESSION_RE = re.compile(r"session_([0-9a-f-]+)")

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        if config is None:
            config = _load_default_config()
        super().__init__(config)

    def extract_session_id(self, request: ProxyRequest) -> str:
        """Extract session ID, preferring metadata.user_id from the request body.

        Claude Code sends a ``metadata`` dict in request bodies containing a
        compound ``user_id`` like::

            user_<hash>_account_<uuid>_session_<uuid>

        We extract the ``session_<uuid>`` portion for a stable, readable
        session identifier. Falls back to header-based extraction.
        """
        body = getattr(request, "body_json", None) or (
            request.body if isinstance(request.body, dict) else None
        )
        if body and isinstance(body, dict):
            metadata = body.get("metadata")
            if isinstance(metadata, dict):
                user_id = metadata.get("user_id", "")
                if isinstance(user_id, str) and user_id:
                    m = self._SESSION_RE.search(user_id)
                    if m:
                        return f"claude-{m.group(1)}"
                    return f"claude-{user_id[:32]}"

        return super().extract_session_id(request)

    def extract_text_fields(self, body: dict) -> list[TextField]:
        """Extract text fields, handling Anthropic content block structures.

        Handles both string content and content block arrays in messages,
        as well as system prompts (string or content block array).
        """
        if self._user_request_text_paths is not None:
            return self.extract_text_fields_by_jsonpath(
                body, self._user_request_text_paths, self._compiled_user_request_paths,
            )

        if body is None:
            return []

        fields: list[TextField] = []

        # Extract system prompt (can be string or content block array)
        system = body.get("system")
        if isinstance(system, str) and system.strip():
            fields.append(TextField(
                json_path="system",
                text_value=system,
                field_type="system",
            ))
        elif isinstance(system, list):
            for i, block in enumerate(system):
                if isinstance(block, dict):
                    btype = block.get("type", "")
                    if btype == "text":
                        text = block.get("text", "")
                        if isinstance(text, str) and text.strip():
                            fields.append(TextField(
                                json_path=f"system.[{i}].text",
                                text_value=text,
                                field_type="system",
                            ))
                    else:
                        # R70-6 fix: newer block types
                        # (web_search_tool_result, code_execution_output,
                        # etc.) carry a ``text`` field but a non-``text``
                        # ``type``.  Skipping them silently leaks PII.
                        text = block.get("text", "")
                        if isinstance(text, str) and text.strip():
                            fields.append(TextField(
                                json_path=f"system.[{i}].text",
                                text_value=text,
                                field_type="system",
                            ))

        # Extract message content
        messages = body.get("messages", [])
        if not isinstance(messages, list):
            return fields

        for msg_idx, message in enumerate(messages):
            if not isinstance(message, dict):
                continue

            content = message.get("content")

            # String content
            if isinstance(content, str) and content.strip():
                fields.append(TextField(
                    json_path=f"messages.[{msg_idx}].content",
                    text_value=content,
                    field_type="text",
                ))
            # Content block array
            elif isinstance(content, list):
                for block_idx, block in enumerate(content):
                    if not isinstance(block, dict):
                        continue

                    block_type = block.get("type", "")

                    if block_type == "text":
                        text = block.get("text", "")
                        if isinstance(text, str) and text.strip():
                            fields.append(TextField(
                                json_path=f"messages.[{msg_idx}].content.[{block_idx}].text",
                                text_value=text,
                                field_type="text",
                            ))
                    elif block_type == "tool_result":
                        # Tool results can have string or array content
                        tool_content = block.get("content")
                        if isinstance(tool_content, str) and tool_content.strip():
                            fields.append(TextField(
                                json_path=(
                                    f"messages.[{msg_idx}].content.[{block_idx}].content"
                                ),
                                text_value=tool_content,
                                field_type="tool_result",
                            ))
                        elif isinstance(tool_content, list):
                            for tc_idx, tc_block in enumerate(tool_content):
                                if isinstance(tc_block, dict):
                                    # R70-6 fix: accept text from any
                                    # block type that carries a ``text``
                                    # field — not just ``type=="text"``.
                                    text = tc_block.get("text", "")
                                    if isinstance(text, str) and text.strip():
                                        fields.append(TextField(
                                            json_path=(
                                                f"messages.[{msg_idx}].content"
                                                f".[{block_idx}].content"
                                                f".[{tc_idx}].text"
                                            ),
                                            text_value=text,
                                            field_type="tool_result",
                                        ))
                    elif block_type == "tool_use":
                        # R56-1, R60-1, R61-3 fix lineage; R62-4
                        # passes the REMAINING per-request budget so
                        # a single block can't overshoot the cap.
                        remaining = _MAX_TOOL_INPUT_LEAVES_PER_REQUEST - len(fields)
                        if remaining <= 0:
                            continue
                        tool_input = block.get("input")
                        if isinstance(tool_input, dict):
                            base = (
                                f"messages.[{msg_idx}].content"
                                f".[{block_idx}].input"
                            )
                            _walk_json_strings(
                                tool_input, base, fields, "tool_use",
                                max_leaves=min(_MAX_TOOL_INPUT_LEAVES, remaining),
                            )
                    elif block_type in ("thinking", "redacted_thinking"):
                        # 72-1 fix: Anthropic extended-thinking blocks
                        # carry text in the ``thinking`` field, NOT
                        # ``text``.  Without this branch the request
                        # side leaks PII through the proxy unscrubbed.
                        thinking_text = block.get("thinking", "")
                        if isinstance(thinking_text, str) and thinking_text.strip():
                            fields.append(TextField(
                                json_path=(
                                    f"messages.[{msg_idx}].content"
                                    f".[{block_idx}].thinking"
                                ),
                                text_value=thinking_text,
                                field_type="text",
                            ))

        return fields

    def replace_text_fields(self, body: dict, replacements: dict[str, str]) -> dict:
        """Apply replacements using the custom json_path format from extract_text_fields.

        Handles the Anthropic-specific path format that uses bracket notation
        for array indices (e.g. 'messages.[0].content.[1].text').

        When user-configured text paths are active, delegates to the parent
        YAMLProvider which uses jsonpath_ng for consistent path handling.
        """
        if self._user_request_text_paths is not None:
            return super().replace_text_fields(body, replacements)

        if body is None:
            return {}

        # R59-6 fix: ``copy.deepcopy`` is recursive and crashes on
        # deeply-nested ``tool_use.input``.  JSON round-trip is
        # iterative at the C level.  Falls back to deepcopy if the
        # body contains non-JSON-safe values (rare for HTTP request
        # bodies, but preserved for compatibility).
        try:
            import json as _json
            result = _json.loads(_json.dumps(body))
        except (TypeError, ValueError):
            result = copy.deepcopy(body)

        for path_str, replacement_text in replacements.items():
            _set_by_path(result, path_str, replacement_text)

        return result

    def extract_response_text_fields(self, body: dict) -> list[TextField]:
        """Extract text from Anthropic response content blocks."""
        if self._user_response_text_paths is not None:
            return self.extract_text_fields_by_jsonpath(
                body, self._user_response_text_paths, self._compiled_user_response_paths,
            )

        if body is None:
            return []

        fields: list[TextField] = []
        content = body.get("content", [])
        if isinstance(content, list):
            for i, block in enumerate(content):
                if not isinstance(block, dict):
                    continue
                btype = block.get("type", "")
                if btype == "text":
                    text = block.get("text", "")
                    if isinstance(text, str) and text.strip():
                        fields.append(TextField(
                            json_path=f"content.[{i}].text",
                            text_value=text,
                            field_type="text",
                        ))
                elif btype == "tool_use":
                    # R61-3 + R62-4: per-request remaining budget.
                    remaining = _MAX_TOOL_INPUT_LEAVES_PER_REQUEST - len(fields)
                    if remaining <= 0:
                        continue
                    tool_input = block.get("input")
                    if isinstance(tool_input, dict):
                        # R56-1 fix: recursively walk for nested string
                        # leaves (matches request-side behavior).
                        _walk_json_strings(
                            tool_input,
                            f"content.[{i}].input",
                            fields,
                            "tool_use",
                            max_leaves=min(_MAX_TOOL_INPUT_LEAVES, remaining),
                        )
                elif btype in ("thinking", "redacted_thinking"):
                    # 72-1 fix: extended-thinking blocks carry text in
                    # ``thinking``, NOT ``text``.  Same handling as
                    # request side.
                    thinking_text = block.get("thinking", "")
                    if isinstance(thinking_text, str) and thinking_text.strip():
                        fields.append(TextField(
                            json_path=f"content.[{i}].thinking",
                            text_value=thinking_text,
                            field_type="text",
                        ))
                else:
                    # R71-3 fix: mirror R70-6 — accept text from any
                    # block type that carries a ``text`` field
                    # (web_search_tool_result, code_execution_output,
                    # future block types).  Without this, the response
                    # side silently leaks PII that the request side
                    # would scrub.
                    text = block.get("text", "")
                    if isinstance(text, str) and text.strip():
                        fields.append(TextField(
                            json_path=f"content.[{i}].text",
                            text_value=text,
                            field_type="text",
                        ))

        return fields


# R58-2 fix: `_walk_json_strings` is now ITERATIVE (an explicit
# work stack instead of recursion), so there is no recursion-depth
# cap, no fail-open behavior, no log-leak of PII via `base_path`,
# and pathologically nested input is handled correctly without
# RecursionError.  Replaces R57-2's depth cap entirely (which traded
# a crash for a silent leak — see R58-2 review finding).
# Constant kept for backward-compat in case external code references it,
# but it is no longer consulted by the walker.
_MAX_TOOL_INPUT_DEPTH = 200
# R59-7 fix: hard cap on number of extracted leaves to prevent a
# pathological ``tool_use.input`` with millions of string leaves
# from OOM-ing the proxy via the ``fields`` list.  100k strings is
# generous for any legitimate Anthropic tool schema while bounding
# worst-case memory at ~10 MB of TextField objects.
_MAX_TOOL_INPUT_LEAVES = 100_000
# R61-3 fix: per-REQUEST total leaf ceiling shared across all
# ``tool_use`` blocks.  R60-1 fixed the cross-block bypass but the
# OUTER ``fields`` accumulator was unbounded across blocks.  500k
# is a generous upper bound for any legitimate Anthropic request
# while bounding worst-case total memory at ~50 MB of TextField
# objects across the entire request.
_MAX_TOOL_INPUT_LEAVES_PER_REQUEST = 500_000
# R60-8 fix: also bound the working stack.  The leaf-cap alone
# doesn't prevent a pathological flat container (millions of
# children pushed in one go) from allocating hundreds of MB of path
# strings BEFORE any leaf is processed.  500k stack entries ×
# ~200-byte path strings ≈ 100 MB worst-case.
_MAX_TOOL_INPUT_STACK = 500_000


def _escape_path_segment(k: str) -> str:
    """R57-1 fix: escape a dict key for safe inclusion in the
    ``.[N]``-style path used by ``_set_by_path``.

    Replaces ``~``/``.``/``[``/``]`` with ``~0``/``~1``/``~2``/``~3``
    sequences so the splitter can losslessly distinguish key from
    array marker.  Order matters: ``~`` is escaped first so subsequent
    escapes are not double-encoded.  Inverse: ``_unescape_path_segment``.
    """
    return (
        k.replace("~", "~0")
         .replace(".", "~1")
         .replace("[", "~2")
         .replace("]", "~3")
    )


def _unescape_path_segment(p: str) -> str:
    """Inverse of ``_escape_path_segment`` (apply in reverse order)."""
    return (
        p.replace("~3", "]")
         .replace("~2", "[")
         .replace("~1", ".")
         .replace("~0", "~")
    )


def _walk_json_strings(
    value: Any,
    base_path: str,
    fields: list,
    field_type: str,
    max_leaves: int | None = None,
) -> None:
    """Iteratively yield non-empty string leaves of an arbitrary JSON
    value as ``TextField`` entries appended to ``fields``.

    R56-1, R57-1, R58-2, R59-7, R60-1, R60-8, R61-1: prior fixes.

    R62-4 fix: ``max_leaves`` parameter overrides the default
    ``_MAX_TOOL_INPUT_LEAVES`` per-call cap so callers can enforce
    a TIGHTER per-call budget — e.g. ``min(per_call_cap,
    per_request_cap - len(fields))`` — to prevent a single block
    from overshooting the per-request total.  None falls back to
    the default constant (preserves the old single-call contract).
    """
    cap = _MAX_TOOL_INPUT_LEAVES if max_leaves is None else max_leaves
    leaves_added = 0
    # Stack of (value, path) work items.  LIFO traversal is fine
    # since order does not affect correctness — every leaf is visited.
    stack: list[tuple[Any, str]] = [(value, base_path)]
    while stack:
        if leaves_added >= cap:
            logger.warning(
                "tool_use.input leaf count exceeded %d at base=%r "
                "(stack=%d); truncating remaining subtree",
                cap, base_path, len(stack),
            )
            return
        val, path = stack.pop()
        if isinstance(val, str):
            if val.strip():
                fields.append(TextField(
                    json_path=path,
                    text_value=val,
                    field_type=field_type,
                ))
                leaves_added += 1
        elif isinstance(val, dict):
            # R61-1 fix: enforce stack cap PER-APPEND so processed
            # leaves are preserved instead of returning with zero.
            for k, v in val.items():
                if not isinstance(k, str):
                    # R62-5 fix: coerce non-string dict keys to ``str``
                    # rather than silently skipping them.
                    # R63-5 fix: use the json-compatible coercion so
                    # the path the walker emits MATCHES the path the
                    # ``replace_text_fields`` JSON round-trip
                    # produces.
                    # R64-5 / R65-7 fix: also handle non-finite
                    # floats.  ``json.dumps`` does NOT raise on
                    # NaN/Inf by default — it emits the non-standard
                    # ``NaN``/``Infinity`` tokens, then ``json.loads``
                    # round-trips them back to floats which become
                    # the dict KEY ``float('nan')`` again.  But our
                    # walker would have emitted ``"nan"`` as the
                    # path segment — which never matches the round-
                    # tripped float key in ``_set_by_path``, so the
                    # replacement silently no-ops.  Skip these keys
                    # to fail-safe: no extraction → original value
                    # is forwarded raw, but at least no silent path
                    # mismatch that drops a known replacement.
                    if isinstance(k, bool):
                        # bool is also int — check first.
                        k = "true" if k else "false"
                    elif k is None:
                        k = "null"
                    elif isinstance(k, float):
                        import math as _math
                        if not _math.isfinite(k):
                            # Non-finite float → can't round-trip via JSON.
                            continue
                        k = str(k)
                    else:
                        k = str(k)
                if len(stack) >= _MAX_TOOL_INPUT_STACK:
                    logger.warning(
                        "tool_use.input work-stack reached %d at base=%r "
                        "(leaves=%d); skipping remaining children",
                        _MAX_TOOL_INPUT_STACK, base_path, leaves_added,
                    )
                    break
                stack.append((v, f"{path}.{_escape_path_segment(k)}"))
        elif isinstance(val, list):
            for idx, item in enumerate(val):
                if len(stack) >= _MAX_TOOL_INPUT_STACK:
                    logger.warning(
                        "tool_use.input work-stack reached %d at base=%r "
                        "(leaves=%d); skipping remaining children",
                        _MAX_TOOL_INPUT_STACK, base_path, leaves_added,
                    )
                    break
                stack.append((item, f"{path}.[{idx}]"))


def _set_by_path(data: Any, path: str, value: Any) -> None:
    """Set a value in a nested dict/list using bracket-notation path.

    Handles paths like 'messages.[0].content.[1].text' or 'system'.

    R57-1 fix: dict-key segments are unescaped via
    ``_unescape_path_segment`` so paths produced by the
    R57-1-aware walker round-trip correctly.  Array-index segments
    ``[N]`` are recognised by the unescaped form starting with ``[``;
    a literal key like ``"[0]"`` would have been escaped to
    ``~20~3`` so it never aliases the array marker.
    """
    parts = path.split(".")
    current = data

    for i, part in enumerate(parts[:-1]):
        if part.startswith("[") and part.endswith("]"):
            idx = int(part[1:-1])
            if isinstance(current, list) and 0 <= idx < len(current):
                current = current[idx]
            else:
                return
        elif isinstance(current, dict):
            key = _unescape_path_segment(part)
            if key in current:
                current = current[key]
            else:
                return
        else:
            return

    last = parts[-1]
    if last.startswith("[") and last.endswith("]"):
        idx = int(last[1:-1])
        if isinstance(current, list) and 0 <= idx < len(current):
            current[idx] = value
    elif isinstance(current, dict):
        current[_unescape_path_segment(last)] = value
