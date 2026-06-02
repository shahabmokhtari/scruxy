#!/usr/bin/env python3
"""Simple name replacement using stdlib only.

Protocol: argv[1]=entity_type, argv[2]=count (1-based), stdin=original PII, stdout=replacement.
"""
import sys

FIRST_NAMES = [
    "Alice", "Bob", "Carol", "Dave", "Eve", "Frank", "Grace", "Hank",
    "Iris", "Jack", "Karen", "Leo", "Mona", "Nick", "Olive", "Pete",
    "Quinn", "Rose", "Sam", "Tina", "Uma", "Vic", "Wendy", "Xander",
]

LAST_NAMES = [
    "Smith", "Jones", "Brown", "Davis", "Wilson", "Clark", "Lewis",
    "Walker", "Hall", "Young", "King", "Wright", "Scott", "Green",
]


def main():
    entity_type = sys.argv[1] if len(sys.argv) > 1 else "PERSON"
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    _original = sys.stdin.read().strip()

    first = FIRST_NAMES[(count - 1) % len(FIRST_NAMES)]
    last = LAST_NAMES[(count - 1) % len(LAST_NAMES)]
    print(f"{first} {last}")


if __name__ == "__main__":
    main()
