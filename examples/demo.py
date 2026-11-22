"""Quick demo: run a handful of sample identifiers through the toolkit.

    python examples/demo.py

Runs fully offline (no network, no API key) using the heuristic summary.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from contact_identifier import identify  # noqa: E402

SAMPLES = [
    "newsletter@acme-corp.com",
    "throwaway@mailinator.com",
    "+1 650-253-0000",
    "xn--pple-43d.com",     # punycode "apple" lookalike
    "cool_handle",
]

for sample in SAMPLES:
    report = identify(sample)
    print("=" * 64)
    print(report.summary)
    print()
