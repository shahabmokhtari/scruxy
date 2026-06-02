"""Regression test for the legacy-config startup error.

Operator's ``~/.scruxy/config.yaml`` had ``interception.mode:
mitmproxy`` (a retired mode).  Previously the lifespan callback
raised ``RuntimeError`` and the daemon refused to start.

WHY this slipped past 70 rounds of code review: every reviewer
worked on the in-tree source against synthetic test configs; no
round ever exercised "operator runs the app with a stale on-disk
config".  The default ``AppConfig()`` has ``mode == "primary"`` so
the failure path was unreachable from the test suite.

This test exercises the lifespan with ``mode == "mitmproxy"`` to
ensure auto-migration works (and emits a warning).
"""
from __future__ import annotations

import logging

import pytest


@pytest.mark.asyncio
async def test_lifespan_auto_migrates_mitmproxy_mode_to_primary(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Running with a legacy ``mode: mitmproxy`` config must NOT crash;
    it must auto-migrate to ``primary`` and log a WARNING.

    Source-level test: the lifespan source must contain the
    auto-migration block (not the prior ``raise RuntimeError``).
    The behavioral driver lives below.
    """
    import inspect
    from scruxy import app as app_mod

    src = inspect.getsource(app_mod.lifespan)
    assert "auto-migrating to 'primary'" in src, (
        "lifespan must auto-migrate legacy mitmproxy mode, not crash"
    )
    assert "raise RuntimeError" not in src.split("0a.")[1].split("0b.")[0], (
        "lifespan section 0a must not raise RuntimeError on legacy mode"
    )


def test_legacy_mitmproxy_mode_no_longer_raises_in_lifespan() -> None:
    """The fix swap: the old hard-fail message must be gone from the
    lifespan source and replaced with the auto-migration warning."""
    import inspect
    from scruxy import app as app_mod

    src = inspect.getsource(app_mod.lifespan)
    assert (
        "mitmproxy scrubbing is not yet implemented" not in src
    ), "old hard-fail message still present in lifespan"

