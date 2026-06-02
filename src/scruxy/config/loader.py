"""YAML configuration loading with defaults, path expansion, and validation."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import yaml

from scruxy.config.models import AppConfig


DEFAULT_CONFIG_DIR = Path.home() / ".scruxy"


def _expand_paths(data: dict) -> dict:
    """Recursively expand ~ in string values that look like paths."""
    result = {}
    for key, value in data.items():
        if isinstance(value, dict):
            result[key] = _expand_paths(value)
        elif isinstance(value, list):
            result[key] = [
                _expand_paths(item) if isinstance(item, dict) else item for item in value
            ]
        elif isinstance(value, str) and value.startswith("~"):
            result[key] = str(Path(value).expanduser())
        else:
            result[key] = value
    return result


def _collapse_paths(data: dict) -> dict:
    """Recursively collapse absolute paths under the user's home directory to ~/... form.

    This is the inverse of ``_expand_paths``: any string value whose resolved
    path starts with the user's home directory is shortened to a ``~/...`` form
    for cleaner YAML output.
    """
    home = str(Path.home())
    result = {}
    for key, value in data.items():
        if isinstance(value, dict):
            result[key] = _collapse_paths(value)
        elif isinstance(value, list):
            result[key] = [
                _collapse_paths(item) if isinstance(item, dict) else item
                for item in value
            ]
        elif isinstance(value, str) and os.path.isabs(value):
            # Normalise separators so comparison works on Windows too.
            norm_value = value.replace("\\", "/")
            norm_home = home.replace("\\", "/")
            if norm_value.startswith(norm_home + "/") or norm_value == norm_home:
                relative = norm_value[len(norm_home):]
                result[key] = "~" + relative
            else:
                result[key] = value
        else:
            result[key] = value
    return result


def save_config(config: AppConfig, path: Path | None = None) -> None:
    """Serialize *config* to YAML and write it atomically to *path*.

    The config dict is run through ``_collapse_paths`` so that absolute paths
    under the user's home directory are stored as ``~/...`` in the YAML file.

    The write is atomic: the data is first written to a temporary file in the
    same directory, then renamed over the target path.  This guarantees that
    readers never see a partially-written file.

    Args:
        config: The validated ``AppConfig`` to persist.
        path:   Destination YAML file.  Defaults to ``~/.scruxy/config.yaml``.
    """
    if path is None:
        path = DEFAULT_CONFIG_DIR / "config.yaml"

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = config.model_dump(mode="json")
    data = _collapse_paths(data)

    # Atomic write: temp file -> rename.
    fd, tmp_path = tempfile.mkstemp(
        dir=str(path.parent), suffix=".tmp", prefix=".scruxy_cfg_"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
        # On Windows, os.replace is atomic and handles cross-device.
        os.replace(tmp_path, str(path))
    except BaseException:
        # Clean up the temp file on any failure.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def load_config(path: Path | None = None) -> AppConfig:
    """Load configuration from a YAML file, merging with defaults.

    Args:
        path: Path to config YAML file. If None, uses default location.

    Returns:
        Validated AppConfig instance.
    """
    if path is None:
        path = DEFAULT_CONFIG_DIR / "config.yaml"

    if path.exists():
        with open(path) as f:
            raw = yaml.safe_load(f) or {}
        raw = _expand_paths(raw)
        return AppConfig.model_validate(raw)

    return AppConfig()


def ensure_directories(config: AppConfig) -> None:
    """Create missing directories and seed default files."""
    dirs_to_create = [
        Path(config.sessions.storage_dir).expanduser(),
        Path(config.logging.log_dir).expanduser(),
        Path(config.custom_providers_dir).expanduser(),
    ]

    for stage in config.pipeline.stages:
        if "plugin_dir" in stage.config:
            dirs_to_create.append(Path(stage.config["plugin_dir"]).expanduser())
        if "patterns_file" in stage.config:
            dirs_to_create.append(Path(stage.config["patterns_file"]).expanduser().parent)
        if "whitelist_file" in stage.config:
            dirs_to_create.append(Path(stage.config["whitelist_file"]).expanduser().parent)

    for d in dirs_to_create:
        d.mkdir(parents=True, exist_ok=True)

    # Seed default files for ALL file-backed stages (supports multiple instances)
    for stage in config.pipeline.stages:
        if "whitelist_file" in stage.config:
            whitelist_path = Path(stage.config["whitelist_file"]).expanduser()
            if not whitelist_path.exists():
                _seed_default_whitelist_file(whitelist_path)
        if "patterns_file" in stage.config:
            patterns_path = Path(stage.config["patterns_file"]).expanduser()
            if not patterns_path.exists():
                _seed_default_patterns_file(patterns_path)

    # Seed default replacement scripts
    scripts_dir = DEFAULT_CONFIG_DIR / "scripts"
    _seed_default_scripts(scripts_dir)


_DEFAULT_WHITELIST_YAML = """\
# Whitelist — terms listed here will never be scrubbed.
# Matching is case-insensitive (e.g. "Claude" also protects "claude", "CLAUDE").
# One term per line under the 'whitelist' key.

whitelist:
  - Claude
  - Anthropic
  - OpenAI
  - Copilot
  - GitHub
  - Scruxy
  - sonnet
  - opus
  - haiku
  - claude-sonnet
  - claude-opus
  - claude-haiku
  - claude-md-improver
  - bash
  - glob
  - skill
  - tool
  - subagent
  - subagents
"""


def _seed_default_whitelist_file(dest: Path) -> None:
    """Write the default whitelist.yaml template to *dest*."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(_DEFAULT_WHITELIST_YAML, encoding="utf-8")


_DEFAULT_PATTERNS_YAML = """\
# Regex patterns for PII detection
# Uncomment and customize patterns below, or add your own.
# Each pattern needs: name, entity_type, pattern (regex), score (0.0-1.0)
# Optional: context_words (list of words that boost score when found nearby)

# regex_patterns:

# --- Sample patterns (uncomment to enable) ---
# To activate, uncomment 'regex_patterns:' above and the patterns you want.

#  - name: guid
#    entity_type: GUID
#    pattern: '\\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\b'
#    score: 0.8
#    context_words: [id, uuid, guid, identifier, correlation]

#  - name: badge_number
#    entity_type: BADGE_NUMBER
#    pattern: '(?i)\\bBADGE[#_\\-]\\s*[0-9A-Za-z]{3,12}\\b'
#    score: 0.9
#    context_words: [badge, employee, access, card]

#  - name: phone_number
#    entity_type: PHONE_NUMBER
#    pattern: '\\b(?:\\+?1[-.\\s]?)?\\(?\\d{3}\\)?[-.\\s]?\\d{3}[-.\\s]?\\d{4}\\b'
#    score: 0.6
#    context_words: [phone, call, tel, mobile, cell, fax]

#  - name: email_address
#    entity_type: EMAIL_ADDRESS
#    pattern: '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b'
#    score: 0.9
#    context_words: [email, mail, contact, address]

#  - name: employee_id
#    entity_type: EMPLOYEE_ID
#    pattern: '\\bEMP-\\d{6}\\b'
#    score: 0.95
#    context_words: [employee, id, staff, worker]

#  - name: azure_connection_string
#    entity_type: CONNECTION_STRING
#    pattern: '(?i)(?:AccountKey|SharedAccessKey|Password)=[A-Za-z0-9+/=]{20,}'
#    score: 0.95
"""


def _seed_default_patterns_file(dest: Path) -> None:
    """Write the default regex_patterns.yaml template to *dest*."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(_DEFAULT_PATTERNS_YAML, encoding="utf-8")


# ---------------------------------------------------------------------------
# Default replacement scripts seeded into ~/.scruxy/scripts/
# ---------------------------------------------------------------------------

_DEFAULT_SCRIPTS: dict[str, str] = {
    "simple_name.py": '''\
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
''',
    "simple_email.py": '''\
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
''',
    "simple_phone.py": '''\
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
''',
    "faker_name.py": '''\
#!/usr/bin/env python3
"""Realistic name replacement using Faker.

Requires: pip install faker

Protocol: argv[1]=entity_type, argv[2]=count (1-based), stdin=original PII, stdout=replacement.
"""
import sys

try:
    from faker import Faker
except ImportError:
    sys.stderr.write("Error: 'faker' package not installed. Run: pip install faker\\n")
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
''',
    "faker_email.py": '''\
#!/usr/bin/env python3
"""Realistic email replacement using Faker.

Requires: pip install faker

Protocol: argv[1]=entity_type, argv[2]=count (1-based), stdin=original PII, stdout=replacement.
"""
import sys

try:
    from faker import Faker
except ImportError:
    sys.stderr.write("Error: 'faker' package not installed. Run: pip install faker\\n")
    sys.exit(1)


def main():
    entity_type = sys.argv[1] if len(sys.argv) > 1 else "EMAIL_ADDRESS"
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    _original = sys.stdin.read().strip()

    # Seed with count for deterministic output within a session
    Faker.seed(count)
    fake = Faker()
    print(fake.email())


if __name__ == "__main__":
    main()
''',
    "faker_phone.py": '''\
#!/usr/bin/env python3
"""Realistic phone number replacement using Faker.

Requires: pip install faker

Protocol: argv[1]=entity_type, argv[2]=count (1-based), stdin=original PII, stdout=replacement.
"""
import sys

try:
    from faker import Faker
except ImportError:
    sys.stderr.write("Error: 'faker' package not installed. Run: pip install faker\\n")
    sys.exit(1)


def main():
    entity_type = sys.argv[1] if len(sys.argv) > 1 else "PHONE_NUMBER"
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    _original = sys.stdin.read().strip()

    # Seed with count for deterministic output within a session
    Faker.seed(count)
    fake = Faker()
    print(fake.phone_number())


if __name__ == "__main__":
    main()
''',
}


def _seed_default_scripts(scripts_dir: Path) -> None:
    """Write default sample scripts to *scripts_dir*, skipping files that already exist.

    Failures are logged and swallowed — missing template scripts should never
    prevent the proxy from starting.
    """
    import logging

    _log = logging.getLogger(__name__)

    try:
        scripts_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        _log.warning("Could not create scripts directory '%s'; skipping default script seeding", scripts_dir)
        return

    for filename, content in _DEFAULT_SCRIPTS.items():
        dest = scripts_dir / filename
        if not dest.exists():
            try:
                dest.write_text(content, encoding="utf-8")
            except OSError:
                _log.warning("Could not seed default script '%s'", dest)
