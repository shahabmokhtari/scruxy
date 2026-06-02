"""Core dataclasses and ABC for the provider system."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ProxyRequest:
    """Represents an incoming HTTP request to the proxy."""

    method: str
    url: str
    headers: dict[str, str]
    body: dict | None = None


@dataclass
class TextField:
    """A text field extracted from a request or response body.

    Attributes:
        json_path: JSONPath expression that located this field.
        text_value: The actual text content.
        field_type: Type of field (e.g. "text", "system", "tool_result").
    """

    json_path: str
    text_value: str
    field_type: str = "text"


@dataclass
class SSETextField:
    """A text field extracted from a Server-Sent Events chunk.

    Attributes:
        text_value: The text content from the SSE event.
        event_type: The SSE event type identifier (e.g. "content_block_delta").
    """

    text_value: str
    event_type: str = ""


class LLMProvider(ABC):
    """Abstract base class for LLM API providers.

    Providers define how to parse requests and responses for each LLM API format.
    Both YAML-driven and Python-class providers implement this same interface.
    """

    name: str
    display_name: str

    @abstractmethod
    def matches(self, request: ProxyRequest) -> bool:
        """Return True if this request belongs to this provider.

        Match by URL pattern, headers, or body structure.
        """

    @abstractmethod
    def extract_session_id(self, request: ProxyRequest) -> str:
        """Extract the harness session ID from request headers/body.

        Checks configured session_id_headers first, then falls back to
        hashing auth headers for a stable derived session ID.
        """

    @abstractmethod
    def extract_text_fields(self, body: dict) -> list[TextField]:
        """Return all text fields in the request body that should be scrubbed.

        Each TextField has: json_path, text_value, field_type.
        """

    @abstractmethod
    def replace_text_fields(self, body: dict, replacements: dict[str, str]) -> dict:
        """Apply scrubbed text back into the request body.

        Args:
            body: The original request body dict.
            replacements: Mapping from original json_path to replacement text.

        Returns:
            A new body dict with replaced text fields.
        """

    @abstractmethod
    def extract_response_text_fields(self, body: dict) -> list[TextField]:
        """Return all text fields in a non-streaming response body."""

    @abstractmethod
    def parse_sse_event(self, event_data: str) -> SSETextField | None:
        """Extract the text field from a single SSE event, or None if no text."""

    @abstractmethod
    def rebuild_sse_event(self, event_data: str, new_text: str) -> str:
        """Replace the text in an SSE event with new (unscrubbed) text."""

    @property
    @abstractmethod
    def default_url_patterns(self) -> list[str]:
        """Glob patterns for URLs this provider handles.

        Used for mitmproxy allow_hosts and request routing.
        """

    @property
    @abstractmethod
    def auth_headers(self) -> list[str]:
        """Headers that carry auth and must be forwarded untouched."""
