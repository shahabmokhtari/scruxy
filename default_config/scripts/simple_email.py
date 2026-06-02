#!/usr/bin/env python3
"""Simple email replacement using stdlib only.

Protocol: argv[1]=entity_type, argv[2]=count (1-based), stdin=original PII, stdout=replacement.
"""
import sys

USERNAMES = [
    "alice", "bob", "carol", "dave", "eve", "frank", "grace", "hank",
    "iris", "jack", "karen", "leo", "mona", "nick", "olive", "pete",
]

DOMAINS = ["example.com", "test.org", "sample.net", "demo.io"]


def main():
    entity_type = sys.argv[1] if len(sys.argv) > 1 else "EMAIL_ADDRESS"
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    _original = sys.stdin.read().strip()

    user = USERNAMES[(count - 1) % len(USERNAMES)]
    domain = DOMAINS[(count - 1) % len(DOMAINS)]
    print(f"{user}@{domain}")


if __name__ == "__main__":
    main()
