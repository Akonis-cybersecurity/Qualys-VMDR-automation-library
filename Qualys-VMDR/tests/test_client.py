import pytest
import requests_mock as rm

from qualys_modules.client import QualysClient


BASE_URL = "https://qualysapi.qualys.com"


def test_basic_auth_header():
    client = QualysClient(BASE_URL, "user", "pass")
    assert client._session.auth is not None
    from requests.auth import HTTPBasicAuth

    assert isinstance(client._session.auth, HTTPBasicAuth)
    assert client._session.auth.username == "user"
    assert client._session.auth.password == "pass"


def test_x_requested_with_header():
    client = QualysClient(BASE_URL, "user", "pass")
    assert client._session.headers.get("X-Requested-With") == "SekoiaConnector"


def test_get_request(requests_mock):
    client = QualysClient(BASE_URL, "user", "pass")
    requests_mock.get(f"{BASE_URL}/api/2.0/fo/test", text="<xml/>")
    result = client.get("/api/2.0/fo/test")
    assert result == "<xml/>"


def test_post_request(requests_mock):
    client = QualysClient(BASE_URL, "user", "pass")
    requests_mock.post(f"{BASE_URL}/api/2.0/fo/scan/", text="<response/>")
    result = client.post("/api/2.0/fo/scan/", data={"action": "launch"})
    assert result == "<response/>"


def test_get_with_full_url(requests_mock):
    client = QualysClient(BASE_URL, "user", "pass")
    full_url = f"{BASE_URL}/api/2.0/fo/test?action=list&id_min=100"
    requests_mock.get(full_url, text="<xml/>")
    result = client.get(full_url)
    assert result == "<xml/>"


def test_retry_on_429(requests_mock):
    client = QualysClient(BASE_URL, "user", "pass")
    responses = [
        {"status_code": 429, "text": "rate limited"},
        {"status_code": 429, "text": "rate limited"},
        {"status_code": 200, "text": "<xml/>"},
    ]
    requests_mock.get(f"{BASE_URL}/api/2.0/fo/test", responses)

    import unittest.mock as mock

    with mock.patch("time.sleep"):
        result = client.get("/api/2.0/fo/test")

    assert result == "<xml/>"


def test_raises_on_http_error(requests_mock):
    client = QualysClient(BASE_URL, "user", "pass")
    requests_mock.get(f"{BASE_URL}/api/2.0/fo/test", status_code=401)
    with pytest.raises(Exception):
        client.get("/api/2.0/fo/test")


def test_base_url_trailing_slash_stripped():
    client = QualysClient(BASE_URL + "/", "user", "pass")
    assert client.base_url == BASE_URL
