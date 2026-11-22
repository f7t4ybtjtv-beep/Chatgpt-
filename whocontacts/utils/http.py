"""Minimal, dependency-free HTTP client used by the network collectors.

Design goals:
- **Standard library only.** Works everywhere Python 3.9+ runs, no install.
- **Privacy first.** Sends a *generic* User-Agent. It never leaks who is
  running the tool: no email, no hostname, no identity in headers or URLs.
- **Polite.** Short timeouts and a conservative default; callers add delays.
- **Proxy / custom-CA aware.** Honours ``HTTPS_PROXY``/``HTTP_PROXY`` and
  ``SSL_CERT_FILE`` from the environment (used in sandboxes behind a proxy),
  but needs none of them on an ordinary machine.

If the optional :mod:`requests` package is installed it is **not** required;
this module is intentionally self-contained.
"""

from __future__ import annotations

import json as _json
import os
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Optional

# A deliberately generic client name. Do not personalise this.
USER_AGENT = "WhoContacts/0.1 (+https://github.com/; OSINT contact-vetting; respectful)"

DEFAULT_TIMEOUT = 8.0


def _ssl_context() -> ssl.SSLContext:
    """Build an SSL context, trusting a custom CA bundle if one is configured."""
    cafile = os.environ.get("SSL_CERT_FILE")
    # Common sandbox CA bundle location; used only if present.
    if not cafile:
        for candidate in ("/root/.ccr/ca-bundle.crt", "/etc/ssl/certs/ca-certificates.crt"):
            if os.path.exists(candidate):
                cafile = candidate
                break
    try:
        if cafile and os.path.exists(cafile):
            return ssl.create_default_context(cafile=cafile)
    except Exception:
        pass
    return ssl.create_default_context()


@dataclass
class Response:
    status: int
    url: str
    text: str
    headers: dict

    def json(self) -> Any:
        return _json.loads(self.text)


class HttpError(Exception):
    """Raised for network-level failures (timeouts, DNS, TLS, proxy)."""


def get(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    headers: Optional[dict] = None,
    allow_redirects: bool = True,
    max_bytes: int = 512_000,
) -> Response:
    """Perform a GET request and return a :class:`Response`.

    Raises :class:`HttpError` on any transport failure. HTTP error status
    codes (404, 403, ...) are returned as a normal ``Response`` so callers can
    treat "profile not found" etc. as data, not exceptions.
    """
    req_headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        req_headers.update(headers)

    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=_ssl_context()),
        # ProxyHandler with no args reads *_PROXY from the environment.
        urllib.request.ProxyHandler(),
    )
    if not allow_redirects:
        opener.add_handler(_NoRedirect())

    request = urllib.request.Request(url, headers=req_headers, method="GET")
    try:
        with opener.open(request, timeout=timeout) as resp:
            raw = resp.read(max_bytes)
            return Response(
                status=getattr(resp, "status", 200) or 200,
                url=resp.geturl(),
                text=raw.decode("utf-8", errors="replace"),
                headers=dict(resp.headers.items()),
            )
    except urllib.error.HTTPError as exc:  # noqa: PERF203 - clarity over speed
        body = ""
        try:
            body = exc.read(max_bytes).decode("utf-8", errors="replace")
        except Exception:
            pass
        return Response(status=exc.code, url=url, text=body, headers=dict(exc.headers.items()) if exc.headers else {})
    except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as exc:
        raise HttpError(f"{type(exc).__name__}: {exc}") from exc


def get_json(url: str, **kwargs: Any) -> Any:
    """GET a URL and parse JSON, or raise :class:`HttpError`."""
    resp = get(url, **kwargs)
    if resp.status >= 400:
        raise HttpError(f"HTTP {resp.status} for {url}")
    try:
        return resp.json()
    except Exception as exc:  # pragma: no cover - defensive
        raise HttpError(f"invalid JSON from {url}: {exc}") from exc


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any):  # noqa: D401
        return None
