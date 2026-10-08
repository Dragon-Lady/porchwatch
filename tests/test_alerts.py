import json

import pytest

from porchwatch import alerts
from porchwatch.safety import SafeError


@pytest.mark.parametrize("url", ["https://example.invalid/topic", "http://localhost:8080/topic", "http://127.0.0.1/topic", "http://[::1]/topic"])
def test_allowed_alert_endpoints(url):
    assert alerts.endpoint(url) == url


@pytest.mark.parametrize("url", ["http://example.invalid/topic", "ftp://example.invalid/topic", "https://user:secret@example.invalid/", "https://example.invalid/#secret", "/topic"])
def test_refused_alert_endpoints(url):
    with pytest.raises(SafeError):
        alerts.endpoint(url)


def test_redirect_disabled():
    assert alerts.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.invalid/") is None


def test_https_posts_timeout_and_payload(monkeypatch):
    calls = []
    class Response:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, size): assert size == 1024
    class Opener:
        def open(self, req, timeout):
            calls.append((req, timeout))
            return Response()
    monkeypatch.setattr(alerts, "build_opener", lambda handler: Opener())
    monkeypatch.setenv("PW_WEBHOOK", "https://example.invalid/secret-endpoint")
    alerts.send_one("slack", {"alert_slack_webhook_env": "PW_WEBHOOK"}, "aggregate only")
    req, timeout = calls[0]
    assert timeout == 5 and json.loads(req.data) == {"text": "aggregate only"}


def test_missing_env_and_insecure_smtp_fail():
    with pytest.raises(SafeError):
        alerts.env_secret({"alert_slack_webhook_env": "PW_MISSING_VAR"}, "alert_slack_webhook_env")
    with pytest.raises(SafeError):
        alerts.send_one("email", {"alert_smtp_host": "example.invalid", "alert_smtp_security": "none"}, "aggregate")
