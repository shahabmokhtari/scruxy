"""Benchmark OPF vs Presidio scrubbing on CPU.

Usage:
    python -m scruxy.bench_opf [--text-size 4000] [--repeat 5] [--no-presidio] [--no-opf]

Prints a side-by-side table of detect() latency, entities found, and
per-byte throughput.  Useful for deciding whether to enable OPF in
place of Presidio.

Both plugins must be installed (Presidio always, OPF via
``pip install 'scruxy[opf]'``).  The OPF model is ~1.5GB; the first
run downloads it to ``~/.opf/privacy_filter/``.
"""
from __future__ import annotations

import argparse
import statistics
import time


_SAMPLE_SENTENCES = [
    "Alice Johnson lives at 1234 Maple Street, Springfield IL 62704.",
    "Reach me at alice.johnson@example.com or 555-867-5309.",
    "Card 4111-1111-1111-1111 expires 09/27 (CVV 123).",
    "SSN 123-45-6789, DOB 1985-03-14.",
    "Server logs show access from 203.0.113.42 at 2026-05-12T15:00:00Z.",
    "Bob's GitHub is github.com/bobsmith and his phone is +1 (415) 555-2671.",
    "Charlie booked a flight under passport US123456789 on 2024-12-25.",
    "Database password: hunter2!  Slack token: xoxb-secret-token-123.",
    "Patient Diana Lee (MRN 7654321) was admitted on 2025-01-15.",
    "AWS access key AKIAIOSFODNN7EXAMPLE leaked in commit 5e3f1a.",
]


def _build_text(approx_bytes: int) -> str:
    """Build a text fragment of roughly *approx_bytes* by repeating the
    sample sentences."""
    out: list[str] = []
    while sum(len(s) for s in out) < approx_bytes:
        out.append(_SAMPLE_SENTENCES[len(out) % len(_SAMPLE_SENTENCES)])
    return " ".join(out)


def _bench(detector, text: str, repeat: int) -> tuple[float, float, int]:
    """Return ``(min_ms, mean_ms, last_entity_count)`` over *repeat* runs."""
    timings: list[float] = []
    entities = []
    for _ in range(repeat):
        t0 = time.perf_counter()
        entities = detector.detect(text, "en")
        elapsed_ms = (time.perf_counter() - t0) * 1000
        timings.append(elapsed_ms)
    return min(timings), statistics.fmean(timings), len(entities)


def _setup_presidio():
    from scruxy.plugin.presidio import PresidioPlugin

    p = PresidioPlugin()
    p.setup({
        "spacy_model": "en_core_web_lg",
        "language": "en",
        "score_threshold": 0.7,
        "entities": [
            "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER",
            "CREDIT_CARD", "US_SSN", "IP_ADDRESS",
        ],
        "post_filter_enabled": True,
    })
    return p


def _setup_opf():
    from scruxy.plugin.openai_privacy_filter import OpenAIPrivacyFilterPlugin

    p = OpenAIPrivacyFilterPlugin()
    p.setup({
        "device": "cpu",
        "decode_mode": "viterbi",
        "min_score": 0.5,
        "max_text_length": 0,  # disable cap for benchmarking
    })
    return p


def _format_row(label: str, min_ms: float, mean_ms: float, n_entities: int, n_bytes: int) -> str:
    """Format one result row with throughput in MB/s."""
    if mean_ms <= 0:
        throughput = float("inf")
    else:
        throughput = (n_bytes / 1024.0 / 1024.0) / (mean_ms / 1000.0)
    return (
        f"{label:>25}  {min_ms:>8.1f}  {mean_ms:>8.1f}  "
        f"{n_entities:>8}  {throughput:>10.3f}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--text-size", type=int, default=4000,
                        help="Approx target text size in bytes (default: 4000)")
    parser.add_argument("--repeat", type=int, default=5,
                        help="Number of runs per detector (default: 5)")
    parser.add_argument("--no-presidio", action="store_true",
                        help="Skip the Presidio benchmark")
    parser.add_argument("--no-opf", action="store_true",
                        help="Skip the OPF benchmark")
    args = parser.parse_args()

    text = _build_text(args.text_size)
    n_bytes = len(text.encode("utf-8"))
    print(f"Text size: {n_bytes:,} bytes ({len(text):,} chars), "
          f"runs per detector: {args.repeat}\n")
    header = (
        f"{'detector':>25}  {'min ms':>8}  {'mean ms':>8}  "
        f"{'entities':>8}  {'MB/s':>10}"
    )
    print(header)
    print("-" * len(header))

    if not args.no_presidio:
        try:
            p = _setup_presidio()
            min_ms, mean_ms, n_ent = _bench(p, text, args.repeat)
            print(_format_row("presidio", min_ms, mean_ms, n_ent, n_bytes))
        except Exception as exc:
            print(f"{'presidio':>25}  setup failed: {exc}")

    if not args.no_opf:
        try:
            p = _setup_opf()
            if getattr(p, "_import_failed", False):
                print(f"{'openai_privacy_filter':>25}  "
                      f"package not installed (pip install 'scruxy[opf]')")
            else:
                min_ms, mean_ms, n_ent = _bench(p, text, args.repeat)
                print(_format_row("openai_privacy_filter",
                                  min_ms, mean_ms, n_ent, n_bytes))
        except Exception as exc:
            print(f"{'openai_privacy_filter':>25}  setup failed: {exc}")

    print()


if __name__ == "__main__":
    main()
