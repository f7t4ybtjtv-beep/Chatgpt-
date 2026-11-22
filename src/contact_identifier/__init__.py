"""contact_identifier — an open-source OSINT toolkit for vetting unknown contacts.

Give it an identifier someone used to reach you (email, phone number, username
or domain) and it gathers public-data signals and produces a plain-language
risk assessment, optionally written up by an LLM.

Intended for defensive / personal-safety use: deciding whether to trust an
unsolicited message or caller. Please read the ethics notice in the README.
"""

from .core import identify
from .models import Report, Signal, Risk

__version__ = "0.1.0"
__all__ = ["identify", "Report", "Signal", "Risk", "__version__"]
