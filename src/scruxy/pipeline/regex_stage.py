"""Backward-compatibility shim — real implementation moved to scruxy.plugin.regex."""
from scruxy.plugin.regex import (  # noqa: F401
    PiiEntity,
    RegexPlugin,
    RegexStage,
)

__all__ = [
    "RegexPlugin",
    "RegexStage",
    "PiiEntity",
]
