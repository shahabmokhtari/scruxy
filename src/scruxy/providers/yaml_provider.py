"""Generic YAML-driven provider that interprets declarative config using JSONPath."""
from __future__ import annotations

import copy
import hashlib
import json
import logging
import re
from fnmatch import fnmatch
from typing import Any

from jsonpath_ng import parse as jsonpath_parse

from scruxy.providers.base import (
    LLMProvider,
    ProxyRequest,
    SSETextField,
    TextField,
)


def _resolve_dotted_path(data: dict, dotted_path: str) -> Any:
    """Resolve a dotted path like 'delta.text' into a nested dict value.

    Args:
        data: The dict to traverse.
        dotted_path: Dot-separated key path.

    Returns:
        The value at the path, or None if not found.
    """
    parts = dotted_path.split(".")
    current: Any = data
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list):
            # Handle list indexing like choices[0]
            try:
                idx = int(part)
                current = current[idx]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return current


def _resolve_bracket_path(data: dict, path: str) -> Any:
    """Resolve a path with bracket notation like 'choices[0].delta.content'.

    Handles both dotted and bracket-indexed access.

    Args:
        data: The dict to traverse.
        path: Path string with optional bracket notation.

    Returns:
        The value at the path, or None if not found.
    """
    # Expand bracket notation into dotted segments
    # e.g. "choices[0].delta.content" -> ["choices", "0", "delta", "content"]
    segments: list[str] = []
    for part in path.split("."):
        if "[" in part:
            # Split "choices[0]" into "choices" and "0"
            base, rest = part.split("[", 1)
            segments.append(base)
            idx_str = rest.rstrip("]")
            segments.append(idx_str)
        else:
            segments.append(part)

    current: Any = data
    for seg in segments:
        if isinstance(current, dict) and seg in current:
            current = current[seg]
        elif isinstance(current, list):
            try:
                idx = int(seg)
                current = current[idx]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return current


def _set_bracket_path(data: dict, path: str, value: Any) -> None:
    """Set a value at a bracket-notation path in a nested dict/list.

    Args:
        data: The dict to modify in place.
        path: Path string with optional bracket notation.
        value: The value to set.
    """
    segments: list[str] = []
    for part in path.split("."):
        if "[" in part:
            base, rest = part.split("[", 1)
            segments.append(base)
            idx_str = rest.rstrip("]")
            segments.append(idx_str)
        else:
            segments.append(part)

    current: Any = data
    for i, seg in enumerate(segments[:-1]):
        next_seg = segments[i + 1]
        if isinstance(current, dict) and seg in current:
            current = current[seg]
        elif isinstance(current, list):
            try:
                idx = int(seg)
                current = current[idx]
            except (ValueError, IndexError):
                return
        else:
            return

    last = segments[-1]
    if isinstance(current, dict):
        current[last] = value
    elif isinstance(current, list):
        try:
            idx = int(last)
            current[idx] = value
        except (ValueError, IndexError):
            pass


logger = logging.getLogger(__name__)


class YAMLProvider(LLMProvider):
    """A generic LLM provider driven by a YAML configuration.

    The YAML config defines URL patterns, header matching, JSONPath expressions
    for text extraction, and SSE event mappings. This allows adding new providers
    without writing Python code.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self.name: str = config["name"]
        self.display_name: str = config.get("display_name", self.name)
        self.upstream_url: str = config.get("upstream_url", "")
        self.enabled: bool = config.get("enabled", True)
        self._url_patterns: list[str] = config.get("url_patterns", [])
        self._match_headers: list[str] = config.get("match_headers", [])
        self._auth_headers: list[str] = config.get("auth_headers", [])
        self._session_id_headers: list[str] = config.get("session_id_headers", [])
        self._request_text_paths: list[str] = config.get("request_text_paths", [])
        self._response_text_paths: list[str] = config.get("response_text_paths", [])
        self._sse_events: dict[str, dict[str, Any]] = config.get("sse_events", {})

        # Body-based session ID extraction (JSONPath + optional regex)
        self._session_id_body_path: str = config.get("session_id_body_path", "")
        self._session_id_body_regex: str = config.get("session_id_body_regex", "")
        self._session_id_body_prefix: str = config.get("session_id_body_prefix", "")
        self._compiled_session_id_body_regex: Any = None
        if self._session_id_body_regex:
            # R71-7 fix: pre-screen with the same ReDoS heuristic the
            # PUT /api/providers handler uses (R70-7).  Without this,
            # POSTed providers, app-startup-loaded configs, and YAML
            # custom providers all accept arbitrary regex → a
            # malicious config can stall the proxy on every matching
            # request.
            try:
                from scruxy.plugin.regex import _looks_catastrophic
                _redos_reason = _looks_catastrophic(self._session_id_body_regex)
            except Exception:
                _redos_reason = None
            if _redos_reason:
                # Refuse to compile and clear the source so the
                # provider falls back to header-based extraction.
                self._session_id_body_regex = ""
                # Surface via logger so the operator sees why.
                logger.warning(
                    "YAMLProvider %r: session_id_body_regex looks "
                    "ReDoS-prone (%s); ignoring.",
                    config.get("name", "<unnamed>"), _redos_reason,
                )
            else:
                try:
                    self._compiled_session_id_body_regex = re.compile(self._session_id_body_regex)
                except re.error:
                    pass

        # User-configurable overrides (None = use provider defaults)
        self._user_url_patterns: list[str] | None = None
        self._user_request_text_paths: list[str] | None = None
        self._user_response_text_paths: list[str] | None = None
        self._compiled_user_request_paths: list[tuple[str, Any]] | None = None
        self._compiled_user_response_paths: list[tuple[str, Any]] | None = None

        # Pre-compile JSONPath expressions for performance
        self._compiled_request_paths = [
            (path_str, jsonpath_parse(path_str)) for path_str in self._request_text_paths
        ]
        self._compiled_response_paths = [
            (path_str, jsonpath_parse(path_str)) for path_str in self._response_text_paths
        ]

    def matches(self, request: ProxyRequest) -> bool:
        """Check if the request matches this provider by URL patterns.

        Note: ``match_headers`` are enforced at the registry level for
        disambiguation when multiple providers share URL patterns, not here.
        """
        # Use user-configured patterns if set, otherwise YAML defaults
        patterns = self._user_url_patterns if self._user_url_patterns is not None else self._url_patterns
        if not patterns:
            return False
        for pattern in patterns:
            if fnmatch(request.url, pattern):
                return True
        return False

    def extract_session_id(self, request: ProxyRequest) -> str:
        """Extract session ID from body, then headers, falling back to auth hash.

        Priority order:
        1. ``session_id_body_path`` — extract from request body using a dotted
           path (e.g. ``metadata.user_id``), then optionally apply
           ``session_id_body_regex`` to capture a portion of the value.
        2. ``session_id_headers`` — check configured header names in order.
        3. Auth hash fallback — derive a stable session ID from auth headers.
        """
        # 1. Try body-based extraction
        body_json = getattr(request, "body_json", None) or (
            request.body if isinstance(getattr(request, "body", None), dict) else None
        )
        if self._session_id_body_path and body_json:
            raw_value = _resolve_dotted_path(body_json, self._session_id_body_path)
            if isinstance(raw_value, str) and raw_value:
                session_val = raw_value
                if self._compiled_session_id_body_regex is not None:
                    m = self._compiled_session_id_body_regex.search(raw_value)
                    if m:
                        session_val = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                prefix = self._session_id_body_prefix
                if prefix:
                    return f"{prefix}{session_val}"
                return session_val

        # 2. Try header-based extraction
        lower_headers = {k.lower(): v for k, v in request.headers.items()}

        # Try configured session ID headers in order
        for header in self._session_id_headers:
            value = lower_headers.get(header.lower(), "")
            if value:
                return value

        # Fallback: hash auth headers for a stable derived session ID
        auth_parts: list[str] = []
        for header in self._auth_headers:
            value = lower_headers.get(header.lower(), "")
            if value:
                auth_parts.append(f"{header.lower()}={value}")

        if auth_parts:
            combined = "|".join(sorted(auth_parts))
            return f"auto-{hashlib.sha256(combined.encode()).hexdigest()[:16]}"

        # Ultimate fallback
        return "auto-unknown"

    @property
    def user_url_patterns(self) -> list[str] | None:
        """User-configured URL pattern override."""
        return self._user_url_patterns

    @user_url_patterns.setter
    def user_url_patterns(self, value: list[str] | None) -> None:
        self._user_url_patterns = value

    @property
    def url_patterns(self) -> list[str]:
        """Active URL patterns (user override or YAML defaults)."""
        if self._user_url_patterns is not None:
            return list(self._user_url_patterns)
        return list(self._url_patterns)

    @property
    def default_url_patterns_list(self) -> list[str]:
        """The provider's built-in default URL patterns from YAML config."""
        return list(self._url_patterns)

    @property
    def user_request_text_paths(self) -> list[str] | None:
        """User-configured request text paths override."""
        return self._user_request_text_paths

    @user_request_text_paths.setter
    def user_request_text_paths(self, value: list[str] | None) -> None:
        self._user_request_text_paths = value
        if value is not None:
            self._compiled_user_request_paths = [
                (p, jsonpath_parse(p)) for p in value
            ]
        else:
            self._compiled_user_request_paths = None

    @property
    def user_response_text_paths(self) -> list[str] | None:
        """User-configured response text paths override."""
        return self._user_response_text_paths

    @user_response_text_paths.setter
    def user_response_text_paths(self, value: list[str] | None) -> None:
        self._user_response_text_paths = value
        if value is not None:
            self._compiled_user_response_paths = [
                (p, jsonpath_parse(p)) for p in value
            ]
        else:
            self._compiled_user_response_paths = None

    @property
    def default_request_text_paths(self) -> list[str]:
        """The provider's built-in default request text paths from YAML config."""
        return list(self._request_text_paths)

    @property
    def default_response_text_paths(self) -> list[str]:
        """The provider's built-in default response text paths from YAML config."""
        return list(self._response_text_paths)

    def extract_text_fields_by_jsonpath(
        self, body: dict, path_strings: list[str],
        compiled_paths: list[tuple[str, Any]] | None = None,
    ) -> list[TextField]:
        """Extract text fields from a body using arbitrary JSONPath expressions.

        Used when user-configured path overrides are active. If ``compiled_paths``
        is provided, uses pre-compiled expressions for performance.
        """
        if body is None:
            return []

        fields: list[TextField] = []
        if compiled_paths is not None:
            pairs = compiled_paths
        else:
            pairs = []
            for path_str in path_strings:
                try:
                    pairs.append((path_str, jsonpath_parse(path_str)))
                except Exception:
                    continue

        for _path_str, compiled in pairs:
            matches = compiled.find(body)
            for match in matches:
                value = match.value
                if isinstance(value, str) and value.strip():
                    fields.append(TextField(
                        json_path=str(match.full_path),
                        text_value=value,
                        field_type="text",
                    ))
        return fields

    def extract_text_fields(self, body: dict) -> list[TextField]:
        """Extract text fields from a request body using configured JSONPath expressions."""
        if self._user_request_text_paths is not None:
            return self.extract_text_fields_by_jsonpath(
                body, self._user_request_text_paths, self._compiled_user_request_paths,
            )

        if body is None:
            return []

        fields: list[TextField] = []
        for path_str, compiled_path in self._compiled_request_paths:
            matches = compiled_path.find(body)
            for match in matches:
                value = match.value
                if isinstance(value, str) and value.strip():
                    fields.append(TextField(
                        json_path=str(match.full_path),
                        text_value=value,
                        field_type="text",
                    ))
        return fields

    def replace_text_fields(self, body: dict, replacements: dict[str, str]) -> dict:
        """Apply replacements to text fields identified by their JSONPath.

        Args:
            body: Original request body.
            replacements: Mapping from json_path (as returned by extract_text_fields)
                to the replacement text string.

        Returns:
            A deep copy of body with the specified fields replaced.
        """
        if body is None:
            return {}

        # R60-3 fix: ``copy.deepcopy`` is RECURSIVE and crashes on
        # deeply nested JSON; mirror the R59-6 fix.  JSON round-trip
        # is iterative at the C level.  Falls back to deepcopy for
        # non-JSON-safe values (rare for HTTP request bodies).
        try:
            import json as _json
            result = _json.loads(_json.dumps(body))
        except (TypeError, ValueError):
            result = copy.deepcopy(body)

        for path_str, replacement_text in replacements.items():
            # Parse the path and find matches in the result
            try:
                compiled = jsonpath_parse(path_str)
                compiled.update(result, replacement_text)
            except Exception:
                # If jsonpath update fails, skip this replacement
                pass

        return result

    def extract_response_text_fields(self, body: dict) -> list[TextField]:
        """Extract text fields from a non-streaming response body."""
        if self._user_response_text_paths is not None:
            return self.extract_text_fields_by_jsonpath(
                body, self._user_response_text_paths, self._compiled_user_response_paths,
            )

        if body is None:
            return []

        fields: list[TextField] = []
        for path_str, compiled_path in self._compiled_response_paths:
            matches = compiled_path.find(body)
            for match in matches:
                value = match.value
                if isinstance(value, str) and value.strip():
                    fields.append(TextField(
                        json_path=str(match.full_path),
                        text_value=value,
                        field_type="text",
                    ))
        return fields

    def parse_sse_event(self, event_data: str) -> SSETextField | None:
        """Parse a single SSE event and extract text content.

        Tries each configured SSE event mapping. Returns the first match.
        """
        try:
            data = json.loads(event_data)
        except (json.JSONDecodeError, TypeError):
            return None

        if not isinstance(data, dict):
            return None

        for event_name, event_config in self._sse_events.items():
            type_match = event_config.get("type_match")
            delta_type_match = event_config.get("delta_type_match")
            text_path = event_config.get("text_path", "")

            # Check type match (if configured)
            if type_match is not None:
                event_type = data.get("type", "")
                if event_type != type_match:
                    continue

            # Check delta type match (if configured, Anthropic-specific)
            if delta_type_match is not None:
                delta = data.get("delta", {})
                if isinstance(delta, dict) and delta.get("type") != delta_type_match:
                    continue

            # Extract text at the configured path
            text_value = _resolve_bracket_path(data, text_path)
            if text_value is not None and isinstance(text_value, str):
                return SSETextField(
                    text_value=text_value,
                    event_type=data.get("type", event_name),
                )

        return None

    def rebuild_sse_event(self, event_data: str, new_text: str) -> str:
        """Replace the text in an SSE event with new text.

        Finds which SSE event config matches, then sets the text at the
        configured path to new_text.
        """
        try:
            data = json.loads(event_data)
        except (json.JSONDecodeError, TypeError):
            return event_data

        if not isinstance(data, dict):
            return event_data

        for event_name, event_config in self._sse_events.items():
            type_match = event_config.get("type_match")
            delta_type_match = event_config.get("delta_type_match")
            text_path = event_config.get("text_path", "")

            # Check type match
            if type_match is not None:
                event_type = data.get("type", "")
                if event_type != type_match:
                    continue

            # Check delta type match
            if delta_type_match is not None:
                delta = data.get("delta", {})
                if isinstance(delta, dict) and delta.get("type") != delta_type_match:
                    continue

            # Verify text exists at this path
            current_value = _resolve_bracket_path(data, text_path)
            if current_value is not None and isinstance(current_value, str):
                _set_bracket_path(data, text_path, new_text)
                return json.dumps(data, ensure_ascii=False)

        return event_data

    @property
    def default_url_patterns(self) -> list[str]:
        """Return the configured URL patterns."""
        return list(self._url_patterns)

    @property
    def auth_headers(self) -> list[str]:
        """Return the configured auth headers."""
        return list(self._auth_headers)
