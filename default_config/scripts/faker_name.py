#!/usr/bin/env python3
"""Realistic name replacement using Faker.

Requires: pip install faker

Protocol: argv[1]=entity_type, argv[2]=count (1-based), stdin=original PII, stdout=replacement.
"""
import sys

try:
    from faker import Faker
except ImportError:
    sys.stderr.write("Error: 'faker' package not installed. Run: pip install faker\n")
    sys.exit(1)


def main():
    entity_type = sys.argv[1] if len(sys.argv) > 1 else "PERSON"
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    _original = sys.stdin.read().strip()

    # Seed with count for deterministic output within a session
    Faker.seed(count)
    fake = Faker()
    print(fake.name())


if __name__ == "__main__":
    main()
