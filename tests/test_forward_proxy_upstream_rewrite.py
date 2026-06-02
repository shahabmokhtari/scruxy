"""Regression: forward proxy must NOT rewrite the upstream host.

Bug surfaced when GitHub Copilot CLI POSTed to
``https://api.enterprise.githubcopilot.com/v1/messages`` (matched
``anthropic.yaml``'s ``*/v1/messages`` URL pattern).  The forward
proxy then unconditionally rewrote the upstream to
``https://api.anthropic.com/v1/messages`` (the provider's
``upstream_url``) and forwarded the Copilot-issued auth token to
Anthropic, which returned 401.  Same shape for OpenAI/Responses.

Provider matching may decide WHETHER to scrub but it must never
rewrite the host.  Reverse-proxy loopback rewriting belongs in the
reverse-proxy router, not in the forward proxy.
"""
from __future__ import annotations

import inspect


def test_forward_proxy_does_not_rewrite_upstream_host() -> None:
    from scruxy.proxy import forward_proxy as fp_mod

    src = inspect.getsource(fp_mod)
    # Old rewrite block must be removed.
    assert (
        'upstream_url = f"{upstream_parsed.scheme}://{upstream_parsed.netloc}'
        not in src
    ), "Forward proxy must not rewrite upstream host based on provider config"
    # Request URL passed through verbatim.
    assert "upstream_url = url" in src
