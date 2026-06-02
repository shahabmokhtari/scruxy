"""OpenAI Responses API provider with format-specific content handling."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from scruxy.providers.base import ProxyRequest
from scruxy.providers.yaml_provider import YAMLProvider


_DEFAULT_CONFIG_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "default_config"
    / "providers"
    / "openai_responses.yaml"
)


def _load_default_config() -> dict[str, Any]:
    """Load the default OpenAI Responses YAML config from the package."""
    with open(_DEFAULT_CONFIG_PATH) as f:
        return yaml.safe_load(f)


class OpenAIResponsesProvider(YAMLProvider):
    """Provider for the OpenAI Responses API (/v1/responses).

    The Responses API uses a different JSON schema from Chat Completions:
    - Request: ``input`` (string or message array), ``instructions``
    - Response: ``output[*].content[*].text``
    - SSE: ``response.output_text.delta`` with ``delta`` field

    Uses the generic YAMLProvider JSONPath extraction, which handles
    both the simple string input and structured message formats.
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        if config is None:
            config = _load_default_config()
        super().__init__(config)

    def extract_session_id(self, request: ProxyRequest) -> str:
        """Extract session ID, checking body ``user`` field as fallback.

        Reuses the same session ID extraction logic as the OpenAI Chat
        Completions provider since both APIs hit the same hosts.
        """
        import hashlib

        header_id = super().extract_session_id(request)
        if not header_id.startswith("auto-"):
            return header_id

        body = request.body if isinstance(request.body, dict) else getattr(request, "body_json", None)
        if isinstance(body, dict):
            user = body.get("user", "")
            if isinstance(user, str) and user:
                short = hashlib.sha256(user.encode()).hexdigest()[:16]
                return f"copilot-{short}"

        return header_id
