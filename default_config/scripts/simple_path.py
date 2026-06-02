#!/usr/bin/env python3
"""Replacement script for PATH_SEGMENT entities.

Replaces each unique path segment with a simple, memorable English word.
Deterministic: the same count always produces the same word within a session.

Protocol: argv[1]=entity_type, argv[2]=count (1-based), stdin=original PII, stdout=replacement.
"""
import sys

WORDS = [
    "apple", "river", "castle", "breeze", "falcon", "marble", "garden",
    "silver", "beacon", "coral", "timber", "summit", "crystal", "velvet",
    "meadow", "orbit", "lagoon", "ridge", "ember", "atlas", "cedar",
    "frost", "pebble", "sage", "dune", "opal", "haven", "flint",
    "brook", "cliff", "maple", "storm", "pearl", "delta", "ivy",
    "blaze", "cove", "spark", "aspen", "reef", "grove", "shade",
    "lunar", "birch", "moss", "quartz", "drift", "raven", "fern",
    "echo", "pine", "lotus", "mist", "thorn", "slate", "jade",
    "plume", "wren", "dusk", "haze", "lark", "stone", "vale", "gale",
]


def main():
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    _original = sys.stdin.read().strip()
    word = WORDS[(count - 1) % len(WORDS)]
    print(word)


if __name__ == "__main__":
    main()
