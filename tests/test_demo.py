"""Smoke tests for the demo app under plain Python.

They check that the catalogue and the routes agree, and that the flaws are
still there: under ordinary Python the injected request must succeed, because
that is what the demo exists to show. Only routes that touch nothing outside
the app's own fixtures are exercised here.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as demo  # noqa: E402


@pytest.fixture()
def client():
    return demo.app.test_client()


def test_every_catalogued_route_exists():
    rules = {(r.rule, m) for r in demo.app.url_map.iter_rules() for m in r.methods}
    for row in demo.ENDPOINTS:
        method, path = row[1], row[2]
        assert (path, method) in rules, f"{method} {path} is in ENDPOINTS but not routed"


def test_landing_page_lists_the_catalogue(client):
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    for row in demo.ENDPOINTS:
        assert row[2] in body, f"{row[2]} missing from the landing page"


def test_sqli_normal_request_returns_one_user(client):
    resp = client.get("/sqli", query_string={"name": "alice"})
    assert resp.status_code == 200
    assert [r[1] for r in resp.get_json()["rows"]] == ["alice"]


def test_sqli_injection_still_dumps_every_row(client):
    resp = client.get("/sqli", query_string={"name": "x' OR '1'='1"})
    assert resp.status_code == 200
    assert sorted(r[1] for r in resp.get_json()["rows"]) == ["admin", "alice", "bob"]


def test_path_traversal_still_escapes_the_sample_dir(client):
    assert client.get("/path", query_string={"file": "notes.txt"}).status_code == 200
    resp = client.get("/path", query_string={"file": "../flag.txt"})
    assert resp.status_code == 200
    assert "EYALSEC{path_traversal_escaped_the_sandbox}" in resp.get_data(as_text=True)


BROWSER = {"Accept": "text/html,application/xhtml+xml"}


def test_every_browser_page_says_open_source_and_links_to_the_code(client):
    home = client.get("/", headers=BROWSER).get_data(as_text=True)
    assert "This website is open source" in home
    assert "https://github.com/EyalSec/vulnerable-python" in home
    assert "/archive/refs/heads/main.zip" in home
    assert home.count("View the code") >= len(demo.ENDPOINTS)

    for path in ("/sqli?name=alice", "/no-such-page"):
        page = client.get(path, headers=BROWSER).get_data(as_text=True)
        assert "This website is open source" in page, path
    page = client.get("/sqli?name=alice", headers=BROWSER).get_data(as_text=True)
    assert "See the code behind this page" in page
    assert "/blob/main/app.py#L" in page


def test_non_browser_clients_get_the_plain_response(client):
    resp = client.get("/sqli?name=alice")
    assert resp.mimetype == "application/json"
    assert "open source" not in resp.get_data(as_text=True)


def test_browser_view_escapes_the_response(client):
    page = client.get("/sqli?name=<b>x</b>", headers=BROWSER).get_data(as_text=True)
    assert "<b>x</b>" not in page
