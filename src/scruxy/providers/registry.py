"""Provider registry with priority-ordered matching."""
from __future__ import annotations

import logging

from scruxy.providers.base import LLMProvider, ProxyRequest


logger = logging.getLogger(__name__)


class ProviderRegistry:
    """Ordered registry of LLM providers.

    Providers are tried in registration order (priority order).
    First match wins. If no provider matches, None is returned
    (indicating the request should pass through unmodified).
    """

    def __init__(self) -> None:
        self._providers: list[LLMProvider] = []

    def register(self, provider: LLMProvider) -> None:
        """Register a provider. Later registrations have lower priority.

        Args:
            provider: An LLMProvider instance to add to the registry.
        """
        self._providers.append(provider)
        logger.info("Registered provider: %s (%s)", provider.name, provider.display_name)

    def unregister(self, name: str) -> bool:
        """Remove a provider by name. Returns True if found and removed."""
        before = len(self._providers)
        self._providers = [p for p in self._providers if p.name != name]
        removed = len(self._providers) < before
        if removed:
            logger.info("Unregistered provider: %s", name)
        return removed

    def match(self, request: ProxyRequest) -> LLMProvider | None:
        """Find the best provider that matches the given request.

        When multiple providers match by URL, prefers providers whose
        ``match_headers`` are present in the request for disambiguation.
        Returns None if no provider matches (transparent passthrough).

        Args:
            request: The incoming proxy request.

        Returns:
            The matching LLMProvider, or None if no match.
        """
        candidates: list[LLMProvider] = []
        for provider in self._providers:
            if not getattr(provider, "enabled", True):
                continue
            try:
                if provider.matches(request):
                    candidates.append(provider)
            except Exception:
                logger.exception(
                    "Error in provider %s matches() for %s %s",
                    provider.name,
                    request.method,
                    request.url,
                )
                continue

        if not candidates:
            logger.debug(
                "No provider matched for %s %s — passthrough",
                request.method,
                request.url,
            )
            return None

        if len(candidates) == 1:
            logger.debug(
                "Request %s %s matched provider: %s",
                request.method, request.url, candidates[0].name,
            )
            return candidates[0]

        # Multiple URL matches — disambiguate using match_headers
        lower_headers = {k.lower() for k in request.headers}
        for provider in candidates:
            match_headers = getattr(provider, "_match_headers", [])
            if match_headers and all(h.lower() in lower_headers for h in match_headers):
                logger.debug(
                    "Request %s %s disambiguated to provider '%s' via match_headers",
                    request.method, request.url, provider.name,
                )
                return provider

        # No header disambiguation — return first match (priority order)
        logger.debug(
            "Request %s %s matched provider: %s (first of %d candidates)",
            request.method, request.url, candidates[0].name, len(candidates),
        )
        return candidates[0]

    def find_passthrough_provider(self, request: ProxyRequest) -> LLMProvider | None:
        """Find a provider for passthrough routing (host or header match only).

        Used when no provider fully matches (URL pattern + headers) but we
        still need to determine the upstream for requests that target a known
        provider's host.  For example, ``GET /v1/models`` doesn't match
        OpenAI's scrub pattern ``*/v1/chat/completions`` but should still be
        forwarded to ``https://api.openai.com/v1/models``.

        Matching strategy (first match wins):
        1. Check if the request URL hostname matches a provider's upstream_url.
        2. Check if the request has a provider's match_headers.
        """
        from urllib.parse import urlparse

        # R71-Gpt-3 fix: canonicalize hostnames the same way CONNECT
        # routing does (R70-14, R71-5) so the trailing-dot / IDNA /
        # bracket bypasses can't reach the passthrough path either.
        try:
            from scruxy.proxy.forward_proxy import _canonicalize_hostname
        except Exception:
            _canonicalize_hostname = lambda h: (h or "").lower()  # noqa: E731

        req_hostname_raw = urlparse(request.url).hostname or ""
        req_hostname = _canonicalize_hostname(req_hostname_raw)

        for provider in self._providers:
            if not getattr(provider, "enabled", True):
                continue
            # Strategy 1: hostname match (forward proxy / direct URLs)
            upstream_url = getattr(provider, "upstream_url", "") or ""
            if upstream_url and req_hostname:
                upstream_host = urlparse(upstream_url).hostname or ""
                upstream_host_canon = _canonicalize_hostname(upstream_host)
                if upstream_host_canon and req_hostname == upstream_host_canon:
                    logger.debug(
                        "Passthrough host match: %s → provider '%s'",
                        req_hostname,
                        provider.name,
                    )
                    return provider

        # Strategy 2: header-only match (reverse proxy path).
        # This method is only called from the reverse proxy catch-all route,
        # so all requests here are already targeting the proxy itself.
        for provider in self._providers:
            if not getattr(provider, "enabled", True):
                continue
            match_headers = getattr(provider, "_match_headers", [])
            if not match_headers:
                continue
            lower_headers = {k.lower(): v for k, v in request.headers.items()}
            for header in match_headers:
                if header.lower() in lower_headers:
                    logger.debug(
                        "Passthrough header match: header '%s' → provider '%s'",
                        header,
                        provider.name,
                    )
                    return provider

        return None

    def match_disabled(self, request: ProxyRequest) -> LLMProvider | None:
        """Find a *disabled* provider that would match this request.

        Same matching logic as ``match()`` but only considers disabled
        providers.  Used to surface disabled-provider matches in the
        passthrough log so users can see traffic that *would* be scrubbed.
        """
        for provider in self._providers:
            if getattr(provider, "enabled", True):
                continue  # skip enabled — we only want disabled
            try:
                if provider.matches(request):
                    logger.debug(
                        "Request %s %s matches DISABLED provider: %s",
                        request.method,
                        request.url,
                        provider.name,
                    )
                    return provider
            except Exception:
                continue
        return None

    @property
    def providers(self) -> list[LLMProvider]:
        """Return the list of registered providers (read-only copy)."""
        return list(self._providers)

    def __len__(self) -> int:
        return len(self._providers)

    def __contains__(self, name: str) -> bool:
        return any(p.name == name for p in self._providers)
