"""Make `src/` importable and force a network-free, deterministic test run."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

# Never touch the network or an LLM during tests.
os.environ.pop("CONTACT_ID_ALLOW_NETWORK", None)
os.environ.pop("CONTACT_ID_USE_LLM", None)
