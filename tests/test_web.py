"""Tests de l'interface web locale (serveur stdlib, hors-ligne)."""

import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from whocontacts import web


@pytest.fixture()
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), web._Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def _get(url: str):
    with urllib.request.urlopen(url, timeout=5) as r:  # noqa: S310 (local only)
        return r.status, r.read().decode("utf-8")


def test_index_serves_html(server):
    status, body = _get(server + "/")
    assert status == 200
    assert "<title>WhoContacts" in body


def test_api_analyses_ip_offline(server):
    status, body = _get(server + "/api?target=192.168.0.1&offline=1&noai=1")
    assert status == 200
    data = json.loads(body)
    assert data["kind"] == "ip"
    assert data["target"] == "192.168.0.1"
    assert "score" in data and "verdict" in data and "emoji" in data
    assert any(s["key"] == "private" for s in data["signals"])


def test_api_empty_target_is_400(server):
    try:
        _get(server + "/api?target=")
        assert False, "attendu une erreur HTTP 400"
    except urllib.error.HTTPError as exc:
        assert exc.code == 400


def test_unknown_path_404(server):
    try:
        _get(server + "/nope")
        assert False, "attendu 404"
    except urllib.error.HTTPError as exc:
        assert exc.code == 404
