import os

import pytest

from porchwatch.safety import Redactor, SafeError, bounded_read, fingerprint, SECRET_NAME


@pytest.mark.parametrize("name", ["PATH", "NODE_PATH", "PYTHONPATH", "projectPath", "KEYBOARD", "KEYBOARDS"])
def test_noncredential_names_not_redacted(name):
    assert not SECRET_NAME.search(name)
    clean = Redactor(b"x" * 32)
    clean.discover({name: "ordinary-path-value"})
    assert clean.clean("ordinary-path-value") == "ordinary-path-value"


@pytest.mark.parametrize("name", ["PAT", "GH_PAT", "GITHUB_PAT", "API_KEY", "KEY", "APIKEY", "auth-token", "PASSWORD", "CLIENT_SECRET"])
def test_credential_names_are_keyed_redacted(name):
    assert SECRET_NAME.search(name)
    key = b"x" * 32
    clean = Redactor(key)
    clean.discover({name: "known-test-value"})
    assert clean.clean("known-test-value") == fingerprint(key, "known-test-value")


def test_fifo_not_read_or_blocked(tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(SafeError, match="regular"):
        bounded_read(fifo)


def test_oversize_source_not_read(tmp_path):
    source = tmp_path / "large"
    with source.open("wb") as stream:
        stream.truncate(5 * 1024 * 1024 + 1)
    with pytest.raises(SafeError, match="5 MB"):
        bounded_read(source)
