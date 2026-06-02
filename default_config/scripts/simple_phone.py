#!/usr/bin/env python3
"""Simple phone number replacement using stdlib only.

Protocol: argv[1]=entity_type, argv[2]=count (1-based), stdin=original PII, stdout=replacement.
"""
import sys


def main():
    entity_type = sys.argv[1] if len(sys.argv) > 1 else "PHONE_NUMBER"
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    _original = sys.stdin.read().strip()

    # Generate deterministic fake phone numbers: (555) 000-0001, (555) 000-0002, ...
    suffix = str(count).zfill(4)
    print(f"(555) 000-{suffix}")


if __name__ == "__main__":
    main()
