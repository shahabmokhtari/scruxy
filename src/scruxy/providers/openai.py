"""OpenAI-compatible provider with format-specific content handling."""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from typing import Any

import yaml

from scruxy.providers.base import ProxyRequest, SSETextField, TextField
from scruxy.providers.yaml_provider import YAMLProvider


_DEFAULT_CONFIG_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "default_config"
    / "providers"
    / "openai.yaml"
)


def _load_default_config() -> dict[str, Any]:
    """Load the default OpenAI YAML config from the package."""
    with open(_DEFAULT_CONFIG_PATH) as f:
        return yaml.safe_load(f)


class OpenAIProvider(YAMLProvider):
    """Provider for OpenAI-compatible APIs (OpenAI, Azure OpenAI, GitHub Copilot).

    Extends YAMLProvider with OpenAI-specific handling for content formats.
    OpenAI messages can contain:
    - Simple string content: {"role": "user", "content": "Hello"}
    - Content part arrays: {"role": "user", "content": [{"type": "text", "text": "Hello"}]}
    - Tool calls in assistant messages
    - Function arguments as JSON strings
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        if config is None:
            config = _load_default_config()
        super().__init__(config)

    def extract_session_id(self, request: ProxyRequest) -> str:
        """Extract session ID, checking body ``user`` field as fallback.

        GitHub Copilot and other OpenAI-compatible clients may include a
        ``user`` field in the request body with a stable identifier. We
        use it (hashed for brevity) when header-based extraction fails.
        """
        # Try header-based extraction first
        header_id = super().extract_session_id(request)
        if not header_id.startswith("auto-"):
            return header_id

        # Check body for a user field (Copilot sends machine/user hashes).
        # body is already a dict on providers.base.ProxyRequest; also check
        # body_json which exists on proxy.routes.ProxyRequest.
        body = request.body if isinstance(request.body, dict) else getattr(request, "body_json", None)
        if isinstance(body, dict):
            user = body.get("user", "")
            if isinstance(user, str) and user:
                short = hashlib.sha256(user.encode()).hexdigest()[:16]
                return f"copilot-{short}"

        return header_id

    def extract_text_fields(self, body: dict) -> list[TextField]:
        """Extract text fields, handling OpenAI content formats.

        Handles both string content and content part arrays in messages,
        as well as tool call arguments.
        """
        if self._user_request_text_paths is not None:
            return self.extract_text_fields_by_jsonpath(
                body, self._user_request_text_paths, self._compiled_user_request_paths,
            )

        if body is None:
            return []

        fields: list[TextField] = []

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
            # Content part array (multimodal format)
            elif isinstance(content, list):
                for part_idx, part in enumerate(content):
                    if not isinstance(part, dict):
                        continue
                    if part.get("type") == "text":
                        text = part.get("text", "")
                        if isinstance(text, str) and text.strip():
                            fields.append(TextField(
                                json_path=(
                                    f"messages.[{msg_idx}].content.[{part_idx}].text"
                                ),
                                text_value=text,
                                field_type="text",
                            ))

            # Tool calls in assistant messages
            tool_calls = message.get("tool_calls", [])
            if isinstance(tool_calls, list):
                for tc_idx, tool_call in enumerate(tool_calls):
                    if not isinstance(tool_call, dict):
                        continue
                    func = tool_call.get("function", {})
                    if isinstance(func, dict):
                        args = func.get("arguments", "")
                        if isinstance(args, str) and args.strip():
                            fields.append(TextField(
                                json_path=(
                                    f"messages.[{msg_idx}].tool_calls"
                                    f".[{tc_idx}].function.arguments"
                                ),
                                text_value=args,
                                field_type="tool_call",
                            ))

            # R70-4 fix: legacy ``function_call.arguments`` field
            # (pre-tools API).  When clients echo prior assistant
            # turns, PII can ride in here.
            func_call = message.get("function_call")
            if isinstance(func_call, dict):
                fc_args = func_call.get("arguments", "")
                if isinstance(fc_args, str) and fc_args.strip():
                    fields.append(TextField(
                        json_path=f"messages.[{msg_idx}].function_call.arguments",
                        text_value=fc_args,
                        field_type="tool_call",
                    ))

            # R70-4 fix: ``message.refusal`` text (moderation reply).
            refusal = message.get("refusal")
            if isinstance(refusal, str) and refusal.strip():
                fields.append(TextField(
                    json_path=f"messages.[{msg_idx}].refusal",
                    text_value=refusal,
                    field_type="text",
                ))

        return fields

    def replace_text_fields(self, body: dict, replacements: dict[str, str]) -> dict:
        """Apply replacements using the custom json_path format from extract_text_fields.

        When user-configured text paths are active, delegates to the parent
        YAMLProvider which uses jsonpath_ng for consistent path handling.
        """
        if self._user_request_text_paths is not None:
            return super().replace_text_fields(body, replacements)

        if body is None:
            return {}

        # R60-3 fix: ``copy.deepcopy`` is RECURSIVE and crashes on
        # deeply nested JSON; mirror the R59-6 fix that landed in
        # ``AnthropicProvider.replace_text_fields``.  JSON round-trip
        # is iterative at the C level.  Falls back to ``deepcopy``
        # for non-JSON-safe values.
        try:
            import json as _json
            result = _json.loads(_json.dumps(body))
        except (TypeError, ValueError):
            result = copy.deepcopy(body)

        for path_str, replacement_text in replacements.items():
            _set_by_path(result, path_str, replacement_text)

        return result

    def extract_response_text_fields(self, body: dict) -> list[TextField]:
        """Extract text from OpenAI response format."""
        if self._user_response_text_paths is not None:
            return self.extract_text_fields_by_jsonpath(
                body, self._user_response_text_paths, self._compiled_user_response_paths,
            )

        if body is None:
            return []

        fields: list[TextField] = []
        choices = body.get("choices", [])
        if not isinstance(choices, list):
            return fields

        for choice_idx, choice in enumerate(choices):
            if not isinstance(choice, dict):
                continue

            message = choice.get("message", {})
            if not isinstance(message, dict):
                continue

            # Message content
            content = message.get("content")
            if isinstance(content, str) and content.strip():
                fields.append(TextField(
                    json_path=f"choices.[{choice_idx}].message.content",
                    text_value=content,
                    field_type="text",
                ))
            # R71-4 fix: handle list (multimodal) content same as request
            # side does — OpenAI responses can carry content arrays in
            # multimodal / structured-output / vision flows.
            elif isinstance(content, list):
                for part_idx, part in enumerate(content):
                    if not isinstance(part, dict):
                        continue
                    if part.get("type") == "text":
                        text = part.get("text", "")
                        if isinstance(text, str) and text.strip():
                            fields.append(TextField(
                                json_path=(
                                    f"choices.[{choice_idx}].message"
                                    f".content.[{part_idx}].text"
                                ),
                                text_value=text,
                                field_type="text",
                            ))

            # Tool call arguments
            tool_calls = message.get("tool_calls", [])
            if isinstance(tool_calls, list):
                for tc_idx, tool_call in enumerate(tool_calls):
                    if not isinstance(tool_call, dict):
                        continue
                    func = tool_call.get("function", {})
                    if isinstance(func, dict):
                        args = func.get("arguments", "")
                        if isinstance(args, str) and args.strip():
                            fields.append(TextField(
                                json_path=(
                                    f"choices.[{choice_idx}].message.tool_calls"
                                    f".[{tc_idx}].function.arguments"
                                ),
                                text_value=args,
                                field_type="tool_call",
                            ))

            # R70-4 fix: legacy ``function_call.arguments`` in response.
            func_call = message.get("function_call")
            if isinstance(func_call, dict):
                fc_args = func_call.get("arguments", "")
                if isinstance(fc_args, str) and fc_args.strip():
                    fields.append(TextField(
                        json_path=f"choices.[{choice_idx}].message.function_call.arguments",
                        text_value=fc_args,
                        field_type="tool_call",
                    ))

            # R70-4 fix: ``message.refusal`` (moderation reply).
            refusal = message.get("refusal")
            if isinstance(refusal, str) and refusal.strip():
                fields.append(TextField(
                    json_path=f"choices.[{choice_idx}].message.refusal",
                    text_value=refusal,
                    field_type="text",
                ))

        return fields


def _set_by_path(data: Any, path: str, value: Any) -> None:
    """Set a value in a nested dict/list using bracket-notation path.

    Handles paths like 'messages.[0].content.[1].text'.
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
        elif isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return

    last = parts[-1]
    if last.startswith("[") and last.endswith("]"):
        idx = int(last[1:-1])
        if isinstance(current, list) and 0 <= idx < len(current):
            current[idx] = value
    elif isinstance(current, dict):
        current[last] = value
